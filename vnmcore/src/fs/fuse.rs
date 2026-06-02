//! FUSE filesystem adapter for single-file Venom containers.
//!
//! Architecture: each FUSE op has a pure `op_*()` method (returns Result<T, errno>)
//! and a thin Filesystem wrapper. Tests call op_*() directly without mounting.
//!
//! File I/O model (in-memory cache per open file handle):
//!   open    → decrypt all slots → Vec<u8> in OpenFile.data   (zero disk I/O after)
//!   read    → slice from cache
//!   write   → patch cache, dirty = true                       (zero disk I/O)
//!   flush   → re-encrypt & persist slots if dirty
//!   release → flush + evict
//!   Drop    → flush_all() safety net

#[cfg(feature = "fuse")]
pub mod driver {
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use fuser::{
        FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate,
        ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
        ReplyWrite, Request, TimeOrNow,
    };
    use libc::{EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTEMPTY, ENOTDIR};

    use crate::fs::container::VnmContainer;
    use crate::storage::vault_fs::{DirectoryBlock, DirEntry, FileBlock};
    use crate::storage::{NodeKind, VaultNode};
    use crate::VnmError;

    const TTL: Duration = Duration::from_secs(1);
    pub const ROOT_INO: u64 = 1;

    /// Max bytes of file data stored inline per slot (conservative).
    const FILE_DATA_CHUNK: usize = 30_000;

    /// Bypass kernel page cache — prevents fh=0 writeback EIO.
    const FOPEN_DIRECT_IO: u32 = 1;

    // ── Inode ↔ slot mapping ──────────────────────────────────────────────────

    pub(crate) struct InodeMap {
        slot_to_ino: HashMap<u64, u64>,
        ino_to_slot: HashMap<u64, u64>,
        next_ino: u64,
    }

    impl InodeMap {
        fn new(root_slot: u64) -> Self {
            let mut m = Self {
                slot_to_ino: HashMap::new(),
                ino_to_slot: HashMap::new(),
                next_ino: 2,
            };
            m.slot_to_ino.insert(root_slot, ROOT_INO);
            m.ino_to_slot.insert(ROOT_INO, root_slot);
            m
        }

        fn get_or_alloc(&mut self, slot: u64) -> u64 {
            if let Some(&ino) = self.slot_to_ino.get(&slot) { return ino; }
            let ino = self.next_ino;
            self.next_ino += 1;
            self.slot_to_ino.insert(slot, ino);
            self.ino_to_slot.insert(ino, slot);
            ino
        }

        fn slot_of(&self, ino: u64) -> Option<u64> {
            self.ino_to_slot.get(&ino).copied()
        }

        fn remove_slot(&mut self, slot: u64) {
            if let Some(ino) = self.slot_to_ino.remove(&slot) {
                self.ino_to_slot.remove(&ino);
            }
        }
    }

    // ── Open-file cache ───────────────────────────────────────────────────────

    pub(crate) struct OpenFile {
        ino:   u64,
        slot:  u64,
        data:  Vec<u8>,
        dirty: bool,
    }

    // ── VenomFuse ─────────────────────────────────────────────────────────────

    pub struct VenomFuse {
        pub(crate) container: Arc<VnmContainer>,
        pub(crate) inodes:    RwLock<InodeMap>,
        pub(crate) open_files: HashMap<u64, OpenFile>,
        next_fh: u64,
    }

    impl VenomFuse {
        pub fn new(container: Arc<VnmContainer>) -> Self {
            let root_slot = container.root_slot();
            Self {
                container,
                inodes: RwLock::new(InodeMap::new(root_slot)),
                open_files: HashMap::new(),
                next_fh: 1,
            }
        }

        // ── Attr helpers ──────────────────────────────────────────────────────

        fn make_attr(&self, ino: u64, node: &VaultNode) -> FileAttr {
            match node {
                VaultNode::Directory(_) => self.make_dir_attr(ino),
                VaultNode::File(f)      => self.make_file_attr(ino, f.total_size),
            }
        }

        pub fn make_dir_attr(&self, ino: u64) -> FileAttr {
            let ts = UNIX_EPOCH;
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            FileAttr { ino, size: 0, blocks: 0, atime: ts, mtime: ts, ctime: ts, crtime: ts,
                kind: FileType::Directory, perm: 0o755, nlink: 2, uid, gid,
                rdev: 0, blksize: 512, flags: 0 }
        }

        pub fn make_file_attr(&self, ino: u64, size: u64) -> FileAttr {
            let ts = UNIX_EPOCH;
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            FileAttr { ino, size, blocks: (size + 511) / 512,
                atime: ts, mtime: ts, ctime: ts, crtime: ts,
                kind: FileType::RegularFile, perm: 0o644, nlink: 1, uid, gid,
                rdev: 0, blksize: 4096, flags: 0 }
        }

        // ── Internal helpers ──────────────────────────────────────────────────

        fn alloc_fh(&mut self) -> u64 {
            let fh = self.next_fh;
            self.next_fh = self.next_fh.wrapping_add(1).max(1);
            fh
        }

        pub fn slot_of_ino(&self, ino: u64) -> Option<u64> {
            self.inodes.read().unwrap().slot_of(ino)
        }

        fn read_dir_block(&self, slot: u64) -> Result<DirectoryBlock, i32> {
            match self.container.read_node(slot) {
                Ok(VaultNode::Directory(d)) => Ok(d),
                Ok(_)  => Err(ENOTDIR),
                Err(_) => Err(EIO),
            }
        }

        fn dir_add_entry(&self, parent_slot: u64, entry: DirEntry) -> Result<(), i32> {
            let mut dir = self.read_dir_block(parent_slot)?;
            if dir.entries.iter().any(|e| e.name == entry.name) { return Err(EEXIST); }
            dir.entries.push(entry);
            self.container.update_node(parent_slot, &VaultNode::Directory(dir)).map_err(|_| EIO)
        }

        fn dir_remove_entry(&self, parent_slot: u64, name: &str) -> Result<u64, i32> {
            let mut dir = self.read_dir_block(parent_slot)?;
            let pos = dir.entries.iter().position(|e| e.name == name).ok_or(ENOENT)?;
            let removed_slot = dir.entries.remove(pos).slot;
            self.container.update_node(parent_slot, &VaultNode::Directory(dir)).map_err(|_| EIO)?;
            Ok(removed_slot)
        }

        pub fn load_file_data(&self, f: &FileBlock) -> Result<Vec<u8>, i32> {
            let mut data = f.data.clone();
            let mut next = f.next_slot;
            while let Some(slot) = next {
                match self.container.read_node(slot) {
                    Ok(VaultNode::File(c)) => {
                        data.extend_from_slice(&c.data);
                        next = c.next_slot;
                    }
                    _ => return Err(EIO),
                }
            }
            data.truncate(f.total_size as usize);
            Ok(data)
        }

        fn persist_file_data(&self, first_slot: u64, existing: &FileBlock, new_data: Vec<u8>) -> Result<(), i32> {
            // Free the old continuation chain.
            let mut next = existing.next_slot;
            while let Some(slot) = next {
                next = match self.container.read_node(slot) {
                    Ok(VaultNode::File(c)) => {
                        let n = c.next_slot;
                        self.container.free_node(slot);
                        self.inodes.write().unwrap().remove_slot(slot);
                        n
                    }
                    _ => None,
                };
            }

            let total_size = new_data.len() as u64;
            let chunks: Vec<&[u8]> = new_data.chunks(FILE_DATA_CHUNK).collect();

            // Build the new chain back-to-front so each block already knows its
            // successor's slot before being written.
            let mut tail_slot: Option<u64> = None;
            for chunk in chunks.iter().skip(1).rev() {
                let node = VaultNode::File(FileBlock {
                    kind:       NodeKind::FileContinuation,
                    total_size: 0,
                    next_slot:  tail_slot,
                    data:       chunk.to_vec(),
                });
                tail_slot = Some(self.container.write_node(&node).map_err(|_| EIO)?);
            }

            let first_data = chunks.first().map(|c| c.to_vec()).unwrap_or_default();
            self.container.update_node(first_slot, &VaultNode::File(FileBlock {
                kind:       NodeKind::File,
                total_size,
                next_slot:  tail_slot,
                data:       first_data,
            })).map_err(|_| EIO)
        }

        // ── Cache helpers ─────────────────────────────────────────────────────

        fn cache_open(&mut self, ino: u64, slot: u64, data: Vec<u8>) -> u64 {
            let fh = self.alloc_fh();
            self.open_files.insert(fh, OpenFile { ino, slot, data, dirty: false });
            fh
        }

        fn flush_fh(&mut self, fh: u64) -> Result<(), i32> {
            let (slot, data, dirty) = match self.open_files.get(&fh) {
                Some(of) => (of.slot, of.data.clone(), of.dirty),
                None     => return Ok(()),
            };
            if !dirty { return Ok(()); }
            let fb = match self.container.read_node(slot) {
                Ok(VaultNode::File(f)) => f,
                _ => return Err(EIO),
            };
            self.persist_file_data(slot, &fb, data)?;
            if let Some(of) = self.open_files.get_mut(&fh) { of.dirty = false; }
            Ok(())
        }

        fn flush_all(&mut self) {
            let fhs: Vec<u64> = self.open_files.keys().copied().collect();
            for fh in fhs { let _ = self.flush_fh(fh); }
            let _ = self.container.flush();
        }

        fn cached_size_for_ino(&self, ino: u64) -> Option<u64> {
            self.open_files.values()
                .find(|of| of.ino == ino)
                .map(|of| of.data.len() as u64)
        }

        // ── Core operations (pub for integration tests) ───────────────────────

        pub fn op_lookup(&mut self, parent: u64, name: &str) -> Result<(u64, VaultNode), i32> {
            let p_slot = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let dir    = self.read_dir_block(p_slot)?;
            let entry  = dir.entries.iter().find(|e| e.name == name).ok_or(ENOENT)?;
            let slot   = entry.slot;
            let node   = self.container.read_node(slot).map_err(|_| EIO)?;
            let ino    = self.inodes.write().unwrap().get_or_alloc(slot);
            Ok((ino, node))
        }

        pub fn op_mkdir(&mut self, parent: u64, name: &str) -> Result<(u64, VaultNode), i32> {
            let p_slot = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let new_dir = VaultNode::Directory(DirectoryBlock { kind: NodeKind::Directory, entries: vec![] });
            let slot = self.container.write_node(&new_dir).map_err(|_| EIO)?;
            let entry = DirEntry { name: name.to_string(), slot, kind: NodeKind::Directory };
            if let Err(e) = self.dir_add_entry(p_slot, entry) {
                self.container.free_node(slot);
                return Err(e);
            }
            let ino = self.inodes.write().unwrap().get_or_alloc(slot);
            Ok((ino, new_dir))
        }

        pub fn op_rmdir(&mut self, parent: u64, name: &str) -> Result<(), i32> {
            let p_slot = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let dir    = self.read_dir_block(p_slot)?;
            let t_slot = dir.entries.iter().find(|e| e.name == name).ok_or(ENOENT)?.slot;
            if !self.read_dir_block(t_slot)?.entries.is_empty() { return Err(ENOTEMPTY); }
            let removed = self.dir_remove_entry(p_slot, name)?;
            self.container.free_node(removed);
            self.inodes.write().unwrap().remove_slot(removed);
            Ok(())
        }

        pub fn op_create(&mut self, parent: u64, name: &str) -> Result<(u64, u64), i32> {
            let p_slot = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let empty  = VaultNode::File(FileBlock { kind: NodeKind::File, total_size: 0, next_slot: None, data: vec![] });
            let slot   = self.container.write_node(&empty).map_err(|_| EIO)?;
            let entry  = DirEntry { name: name.to_string(), slot, kind: NodeKind::File };
            if let Err(e) = self.dir_add_entry(p_slot, entry) {
                self.container.free_node(slot);
                return Err(e);
            }
            let ino = self.inodes.write().unwrap().get_or_alloc(slot);
            let fh  = self.cache_open(ino, slot, vec![]);
            Ok((ino, fh))
        }

        pub fn op_unlink(&mut self, parent: u64, name: &str) -> Result<(), i32> {
            let p_slot  = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let removed = self.dir_remove_entry(p_slot, name)?;
            self.open_files.retain(|_, of| of.slot != removed);
            // Free the entire continuation chain.
            if let Ok(VaultNode::File(f)) = self.container.read_node(removed) {
                let mut next = f.next_slot;
                while let Some(slot) = next {
                    next = match self.container.read_node(slot) {
                        Ok(VaultNode::File(c)) => {
                            let n = c.next_slot;
                            self.container.free_node(slot);
                            self.inodes.write().unwrap().remove_slot(slot);
                            n
                        }
                        _ => None,
                    };
                }
            }
            self.container.free_node(removed);
            self.inodes.write().unwrap().remove_slot(removed);
            Ok(())
        }

        pub fn op_rename(&mut self, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<(), i32> {
            let p_slot  = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let np_slot = self.slot_of_ino(newparent).ok_or(ENOENT)?;
            let moved   = self.dir_remove_entry(p_slot, name)?;
            let kind = match self.container.read_node(moved).map_err(|_| EIO)? {
                VaultNode::Directory(_) => NodeKind::Directory,
                _ => NodeKind::File,
            };
            let mut dest = self.read_dir_block(np_slot)?;
            if let Some(pos) = dest.entries.iter().position(|e| e.name == newname) {
                let old = dest.entries.remove(pos).slot;
                self.container.free_node(old);
                self.inodes.write().unwrap().remove_slot(old);
            }
            dest.entries.push(DirEntry { name: newname.to_string(), slot: moved, kind });
            self.container.update_node(np_slot, &VaultNode::Directory(dest)).map_err(|_| EIO)
        }

        pub fn op_open(&mut self, ino: u64) -> Result<u64, i32> {
            let slot = self.slot_of_ino(ino).ok_or(ENOENT)?;
            let fb   = match self.container.read_node(slot).map_err(|_| EIO)? {
                VaultNode::File(f) => f,
                _ => return Err(EISDIR),
            };
            let data = self.load_file_data(&fb)?;
            Ok(self.cache_open(ino, slot, data))
        }

        pub fn op_flush(&mut self, fh: u64)            -> Result<(), i32> { self.flush_fh(fh) }
        pub fn op_release(&mut self, fh: u64)          -> Result<(), i32> { self.flush_fh(fh)?; self.open_files.remove(&fh); Ok(()) }

        pub fn op_read(&mut self, ino: u64, fh: u64, offset: i64, size: u32) -> Result<Vec<u8>, i32> {
            if let Some(of) = self.open_files.get(&fh) {
                let start = (offset as usize).min(of.data.len());
                let end   = (start + size as usize).min(of.data.len());
                return Ok(of.data[start..end].to_vec());
            }
            // Fallback (no open handle — shouldn't happen with FOPEN_DIRECT_IO)
            let slot = self.slot_of_ino(ino).ok_or(ENOENT)?;
            let fb = match self.container.read_node(slot).map_err(|_| EIO)? {
                VaultNode::File(f) => f,
                _ => return Err(EISDIR),
            };
            let data = self.load_file_data(&fb)?;
            let start = (offset as usize).min(data.len());
            let end   = (start + size as usize).min(data.len());
            Ok(data[start..end].to_vec())
        }

        pub fn op_write(&mut self, ino: u64, fh: u64, offset: i64, data: &[u8]) -> Result<u32, i32> {
            if let Some(of) = self.open_files.get_mut(&fh) {
                let start = offset as usize;
                let end   = start + data.len();
                if end > of.data.len() { of.data.resize(end, 0); }
                of.data[start..end].copy_from_slice(data);
                of.dirty = true;
                return Ok(data.len() as u32);
            }
            // Fallback
            let slot = self.slot_of_ino(ino).ok_or(ENOENT)?;
            let fb = match self.container.read_node(slot).map_err(|_| EIO)? {
                VaultNode::File(f) => f,
                _ => return Err(EISDIR),
            };
            let mut buf = self.load_file_data(&fb)?;
            let start = offset as usize;
            let end   = start + data.len();
            if end > buf.len() { buf.resize(end, 0); }
            buf[start..end].copy_from_slice(data);
            self.persist_file_data(slot, &fb, buf)?;
            Ok(data.len() as u32)
        }

        pub fn op_setattr_size(&mut self, ino: u64, fh_hint: Option<u64>, new_size: u64) -> Result<(), i32> {
            let fh = fh_hint.or_else(|| {
                self.open_files.iter().find(|(_, of)| of.ino == ino).map(|(&f, _)| f)
            });
            if let Some(fh) = fh {
                if let Some(of) = self.open_files.get_mut(&fh) {
                    of.data.resize(new_size as usize, 0);
                    of.dirty = true;
                    return Ok(());
                }
            }
            let slot = self.slot_of_ino(ino).ok_or(ENOENT)?;
            let fb = match self.container.read_node(slot).map_err(|_| EIO)? {
                VaultNode::File(f) => f,
                _ => return Err(EISDIR),
            };
            let mut data = self.load_file_data(&fb)?;
            data.resize(new_size as usize, 0);
            self.persist_file_data(slot, &fb, data)
        }
    }

    // ── Filesystem trait ──────────────────────────────────────────────────────

    impl Filesystem for VenomFuse {
        fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
            let name = match name.to_str() { Some(n) => n, None => { reply.error(ENOENT); return; } };
            match self.op_lookup(parent, name) {
                Ok((ino, node)) => {
                    let mut attr = self.make_attr(ino, &node);
                    if let VaultNode::File(_) = &node {
                        if let Some(sz) = self.cached_size_for_ino(ino) {
                            attr.size = sz; attr.blocks = (sz + 511) / 512;
                        }
                    }
                    reply.entry(&TTL, &attr, 0);
                }
                Err(e) => reply.error(e),
            }
        }

        fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
            let slot = match self.slot_of_ino(ino) { Some(s) => s, None => { reply.error(ENOENT); return; } };
            match self.container.read_node(slot) {
                Ok(node) => {
                    let mut attr = self.make_attr(ino, &node);
                    if let VaultNode::File(_) = &node {
                        if let Some(sz) = self.cached_size_for_ino(ino) {
                            attr.size = sz; attr.blocks = (sz + 511) / 512;
                        }
                    }
                    reply.attr(&TTL, &attr);
                }
                Err(_) => reply.error(EIO),
            }
        }

        fn setattr(&mut self, _req: &Request, ino: u64,
            _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>, size: Option<u64>,
            _atime: Option<TimeOrNow>, _mtime: Option<TimeOrNow>, _ctime: Option<SystemTime>,
            fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>, _flags: Option<u32>, reply: ReplyAttr,
        ) {
            if let Some(new_size) = size {
                if let Err(e) = self.op_setattr_size(ino, fh, new_size) { reply.error(e); return; }
            }
            let slot = match self.slot_of_ino(ino) { Some(s) => s, None => { reply.error(ENOENT); return; } };
            match self.container.read_node(slot) {
                Ok(node) => {
                    let mut attr = self.make_attr(ino, &node);
                    if let Some(sz) = self.cached_size_for_ino(ino) { attr.size = sz; attr.blocks = (sz + 511) / 512; }
                    reply.attr(&TTL, &attr);
                }
                Err(_) => reply.error(EIO),
            }
        }

        fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
            let slot = match self.slot_of_ino(ino) { Some(s) => s, None => { reply.error(ENOENT); return; } };
            let dir  = match self.read_dir_block(slot) { Ok(d) => d, Err(e) => { reply.error(e); return; } };
            let mut entries: Vec<(u64, FileType, String)> = vec![
                (ino, FileType::Directory, ".".into()),
                (ino, FileType::Directory, "..".into()),
            ];
            for e in &dir.entries {
                let child_ino = self.inodes.write().unwrap().get_or_alloc(e.slot);
                let ft = if e.kind == NodeKind::Directory { FileType::Directory } else { FileType::RegularFile };
                entries.push((child_ino, ft, e.name.clone()));
            }
            for (i, (child_ino, ft, name)) in entries.iter().enumerate().skip(offset as usize) {
                if reply.add(*child_ino, (i + 1) as i64, *ft, name.as_str()) { break; }
            }
            reply.ok();
        }

        fn mkdir(&mut self, _req: &Request, parent: u64, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
            let name = match name.to_str() { Some(n) => n, None => { reply.error(EINVAL); return; } };
            match self.op_mkdir(parent, name) {
                Ok((ino, node)) => reply.entry(&TTL, &self.make_attr(ino, &node), 0),
                Err(e)          => reply.error(e),
            }
        }

        fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let name = match name.to_str() { Some(n) => n, None => { reply.error(EINVAL); return; } };
            match self.op_rmdir(parent, name) { Ok(_) => reply.ok(), Err(e) => reply.error(e) }
        }

        fn create(&mut self, _req: &Request, parent: u64, name: &OsStr, _mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate) {
            let name = match name.to_str() { Some(n) => n, None => { reply.error(EINVAL); return; } };
            match self.op_create(parent, name) {
                Ok((ino, fh)) => reply.created(&TTL, &self.make_file_attr(ino, 0), 0, fh, FOPEN_DIRECT_IO),
                Err(e)        => reply.error(e),
            }
        }

        fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let name = match name.to_str() { Some(n) => n, None => { reply.error(EINVAL); return; } };
            match self.op_unlink(parent, name) { Ok(_) => reply.ok(), Err(e) => reply.error(e) }
        }

        fn rename(&mut self, _req: &Request, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, _flags: u32, reply: ReplyEmpty) {
            let name    = match name.to_str()    { Some(n) => n, None => { reply.error(EINVAL); return; } };
            let newname = match newname.to_str() { Some(n) => n, None => { reply.error(EINVAL); return; } };
            match self.op_rename(parent, name, newparent, newname) { Ok(_) => reply.ok(), Err(e) => reply.error(e) }
        }

        fn open(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
            match self.op_open(ino) { Ok(fh) => reply.opened(fh, FOPEN_DIRECT_IO), Err(e) => reply.error(e) }
        }

        fn release(&mut self, _req: &Request, _ino: u64, fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
            let _ = self.op_release(fh);
            reply.ok();
        }

        fn flush(&mut self, _req: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
            match self.op_flush(fh) { Ok(_) => reply.ok(), Err(e) => reply.error(e) }
        }

        fn fsync(&mut self, _req: &Request, _ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
            match self.op_flush(fh) { Ok(_) => reply.ok(), Err(e) => reply.error(e) }
        }

        fn read(&mut self, _req: &Request, ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyData) {
            match self.op_read(ino, fh, offset, size) { Ok(data) => reply.data(&data), Err(e) => reply.error(e) }
        }

        fn write(&mut self, _req: &Request, ino: u64, fh: u64, offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyWrite) {
            match self.op_write(ino, fh, offset, data) { Ok(n) => reply.written(n), Err(e) => reply.error(e) }
        }

        fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
            let free = self.container.store.free.lock().unwrap().len() as u64;
            let total = self.container.outer_limit;
            reply.statfs(total, free, free, 1 << 20, 1 << 20, 4096, 255, 4096);
        }
    }

    impl Drop for VenomFuse {
        fn drop(&mut self) { self.flush_all(); }
    }

    /// Mount `container` at `mountpoint` — blocks until unmounted.
    pub fn mount(container: Arc<VnmContainer>, mountpoint: &str) -> crate::Result<()> {
        let fs = VenomFuse::new(container);
        let options = vec![MountOption::FSName("venom".into())];
        fuser::mount2(fs, mountpoint, &options).map_err(VnmError::Io)
    }

    // ── Integration tests ─────────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;
        use crate::container::CipherAlgorithm;
        use crate::fs::container::VnmContainer;
        use crate::storage::vault_fs::{DirEntry, FileBlock};
        use crate::storage::{NodeKind, VaultNode};

        const MB: u64 = 1024 * 1024;

        fn tmp(label: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!("vnm_{label}_{}.vnm", std::process::id()))
        }

        fn setup(label: &str) -> (Arc<VnmContainer>, VenomFuse, std::path::PathBuf) {
            let path = tmp(label);
            let _ = std::fs::remove_file(&path);
            let c = Arc::new(
                VnmContainer::create(&path, b"pass", 16 * MB, CipherAlgorithm::ChaCha20Poly1305, "interactive", None, None).unwrap(),
            );
            let fuse = VenomFuse::new(c.clone());
            (c, fuse, path)
        }

        fn plant_file(c: &Arc<VnmContainer>, fuse: &mut VenomFuse, name: &str, content: &[u8]) -> (u64, u64) {
            let node = VaultNode::File(FileBlock {
                kind: NodeKind::File,
                total_size: content.len() as u64,
                next_slot: None,
                data: content.to_vec(),
            });
            let slot = c.write_node(&node).unwrap();
            let root_slot = c.root_slot();
            let mut root = match c.read_node(root_slot).unwrap() {
                VaultNode::Directory(d) => d,
                _ => panic!(),
            };
            root.entries.push(DirEntry { name: name.into(), slot, kind: NodeKind::File });
            c.update_node(root_slot, &VaultNode::Directory(root)).unwrap();
            let ino = fuse.inodes.write().unwrap().get_or_alloc(slot);
            (slot, ino)
        }

        fn disk_data(c: &Arc<VnmContainer>, slot: u64) -> Vec<u8> {
            match c.read_node(slot).unwrap() {
                VaultNode::File(f) => {
                    let mut data = f.data.clone();
                    let mut next = f.next_slot;
                    while let Some(s) = next {
                        if let Ok(VaultNode::File(c2)) = c.read_node(s) {
                            data.extend_from_slice(&c2.data);
                            next = c2.next_slot;
                        } else { break; }
                    }
                    data.truncate(f.total_size as usize);
                    data
                }
                _ => panic!(),
            }
        }

        #[test] fn cache_open_populates_entry() {
            let (c, mut fuse, path) = setup("open_entry");
            let (slot, ino) = plant_file(&c, &mut fuse, "f.txt", b"hello");
            let fh = fuse.cache_open(ino, slot, b"hello".to_vec());
            let of = fuse.open_files.get(&fh).unwrap();
            assert_eq!(of.data, b"hello");  assert_eq!(of.ino, ino);  assert!(!of.dirty);
            std::fs::remove_file(&path).ok();
        }

        #[test] fn write_marks_dirty_no_disk_change() {
            let (c, mut fuse, path) = setup("write_dirty");
            let (slot, ino) = plant_file(&c, &mut fuse, "f.txt", b"original");
            let fh = fuse.cache_open(ino, slot, b"original".to_vec());
            fuse.open_files.get_mut(&fh).unwrap().data = b"modified".to_vec();
            fuse.open_files.get_mut(&fh).unwrap().dirty = true;
            assert_eq!(disk_data(&c, slot), b"original");
            std::fs::remove_file(&path).ok();
        }

        #[test] fn flush_persists_and_clears_dirty() {
            let (c, mut fuse, path) = setup("flush_persist");
            let (slot, ino) = plant_file(&c, &mut fuse, "f.txt", b"v1");
            let fh = fuse.cache_open(ino, slot, b"v2".to_vec());
            fuse.open_files.get_mut(&fh).unwrap().dirty = true;
            fuse.flush_fh(fh).unwrap();
            assert!(!fuse.open_files[&fh].dirty);
            assert_eq!(disk_data(&c, slot), b"v2");
            std::fs::remove_file(&path).ok();
        }

        #[test] fn drop_flushes_dirty_files() {
            let path = tmp("drop_flush");
            let _ = std::fs::remove_file(&path);
            let c = Arc::new(VnmContainer::create(&path, b"pass", 16*MB, CipherAlgorithm::ChaCha20Poly1305, "interactive", None, None).unwrap());
            let slot = {
                let mut fuse = VenomFuse::new(c.clone());
                let (s, ino) = plant_file(&c, &mut fuse, "f.txt", b"init");
                let fh = fuse.cache_open(ino, s, b"by drop".to_vec());
                fuse.open_files.get_mut(&fh).unwrap().dirty = true;
                s
            };
            assert_eq!(disk_data(&c, slot), b"by drop");
            std::fs::remove_file(&path).ok();
        }

        #[test] fn op_mkdir_creates_directory() {
            let (_c, mut fuse, path) = setup("mkdir");
            fuse.op_mkdir(ROOT_INO, "docs").unwrap();
            let (_, node) = fuse.op_lookup(ROOT_INO, "docs").unwrap();
            assert!(matches!(node, VaultNode::Directory(_)));
            std::fs::remove_file(&path).ok();
        }

        #[test] fn op_create_write_release_open_read() {
            let (_c, mut fuse, path) = setup("create_cycle");
            let (ino, fh) = fuse.op_create(ROOT_INO, "note.txt").unwrap();
            fuse.op_write(ino, fh, 0, b"hello venom").unwrap();
            fuse.op_release(fh).unwrap();
            let fh2 = fuse.op_open(ino).unwrap();
            let data = fuse.op_read(ino, fh2, 0, 1024).unwrap();
            assert_eq!(data, b"hello venom");
            std::fs::remove_file(&path).ok();
        }

        #[test] fn op_unlink_removes_file() {
            let (_c, mut fuse, path) = setup("unlink");
            fuse.op_create(ROOT_INO, "bye.txt").unwrap();
            fuse.op_unlink(ROOT_INO, "bye.txt").unwrap();
            assert_eq!(fuse.op_lookup(ROOT_INO, "bye.txt").unwrap_err(), ENOENT);
            std::fs::remove_file(&path).ok();
        }

        #[test] fn large_file_linked_chain_roundtrip() {
            // 75 KB — spans 3 slots (30 KB each). Verifies the linked-list
            // implementation handles multi-slot files without "plaintext too large".
            let (_c, mut fuse, path) = setup("large_file");
            let payload: Vec<u8> = (0u32..75_000).map(|i| (i * 7 + 13) as u8).collect();
            let (ino, fh) = fuse.op_create(ROOT_INO, "big.bin").unwrap();
            fuse.op_write(ino, fh, 0, &payload).unwrap();
            fuse.op_release(fh).unwrap();
            let fh2 = fuse.op_open(ino).unwrap();
            let back = fuse.op_read(ino, fh2, 0, payload.len() as u32 + 1).unwrap();
            assert_eq!(back, payload);
            std::fs::remove_file(&path).ok();
        }

        #[test] fn op_rename_within_dir() {
            let (_c, mut fuse, path) = setup("rename");
            let (ino, fh) = fuse.op_create(ROOT_INO, "old.txt").unwrap();
            fuse.op_write(ino, fh, 0, b"data").unwrap();
            fuse.op_release(fh).unwrap();
            fuse.op_rename(ROOT_INO, "old.txt", ROOT_INO, "new.txt").unwrap();
            assert_eq!(fuse.op_lookup(ROOT_INO, "old.txt").unwrap_err(), ENOENT);
            let (new_ino, _) = fuse.op_lookup(ROOT_INO, "new.txt").unwrap();
            let fh2 = fuse.op_open(new_ino).unwrap();
            assert_eq!(fuse.op_read(new_ino, fh2, 0, 1024).unwrap(), b"data");
            std::fs::remove_file(&path).ok();
        }
    }
}
