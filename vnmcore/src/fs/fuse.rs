//! FUSE filesystem adapter — mounts a Vault as a read-write directory.
//!
//! Inode layout: root directory is always inode 1. Each block UUID maps to a
//! u64 inode allocated on first access and cached in memory for the lifetime
//! of the mount.
//!
//! File storage model: all file data is stored inline in a single FileBlock.
//! Files larger than ~32 KiB use continuation blocks (linked list of FileBlocks).

#[cfg(feature = "fuse")]
pub mod driver {
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use fuser::{
        FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate,
        ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyWrite, Request,
        TimeOrNow,
    };
    use libc::{EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTEMPTY, ENOTDIR};

    use crate::fs::vault::Vault;
    use crate::storage::vault_fs::{DirectoryBlock, DirEntry, FileBlock};
    use crate::storage::{NodeKind, VaultNode};
    use crate::VnmError;

    const TTL: Duration = Duration::from_secs(1);
    const ROOT_INO: u64 = 1;
    /// Payload bytes available per block for file data (conservative estimate).
    const BLOCK_DATA_CAPACITY: usize = 30_000;

    // ── Inode ↔ block-id mapping ─────────────────────────────────────────────

    struct InodeMap {
        id_to_ino: HashMap<String, u64>,
        ino_to_id: HashMap<u64, String>,
        next_ino: u64,
    }

    impl InodeMap {
        fn new(root_id: &str) -> Self {
            let mut m = Self {
                id_to_ino: HashMap::new(),
                ino_to_id: HashMap::new(),
                next_ino: 2,
            };
            m.id_to_ino.insert(root_id.to_string(), ROOT_INO);
            m.ino_to_id.insert(ROOT_INO, root_id.to_string());
            m
        }

        fn get_or_alloc(&mut self, id: &str) -> u64 {
            if let Some(&ino) = self.id_to_ino.get(id) {
                return ino;
            }
            let ino = self.next_ino;
            self.next_ino += 1;
            self.id_to_ino.insert(id.to_string(), ino);
            self.ino_to_id.insert(ino, id.to_string());
            ino
        }

        fn block_id(&self, ino: u64) -> Option<&str> {
            self.ino_to_id.get(&ino).map(String::as_str)
        }

        fn remove(&mut self, id: &str) {
            if let Some(ino) = self.id_to_ino.remove(id) {
                self.ino_to_id.remove(&ino);
            }
        }
    }

    // ── VenomFuse ────────────────────────────────────────────────────────────

    pub struct VenomFuse {
        vault: Arc<Vault>,
        inodes: RwLock<InodeMap>,
    }

    impl VenomFuse {
        pub fn new(vault: Arc<Vault>) -> Self {
            let root_id = vault.root_id().to_string();
            Self {
                vault,
                inodes: RwLock::new(InodeMap::new(&root_id)),
            }
        }

        fn make_attr(&self, ino: u64, node: &VaultNode) -> FileAttr {
            let ts = UNIX_EPOCH;
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            match node {
                VaultNode::Directory(_) => FileAttr {
                    ino,
                    size: 0,
                    blocks: 0,
                    atime: ts,
                    mtime: ts,
                    ctime: ts,
                    crtime: ts,
                    kind: FileType::Directory,
                    perm: 0o755,
                    nlink: 2,
                    uid,
                    gid,
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                },
                VaultNode::File(f) => FileAttr {
                    ino,
                    size: f.total_size,
                    blocks: (f.total_size + 511) / 512,
                    atime: ts,
                    mtime: ts,
                    ctime: ts,
                    crtime: ts,
                    kind: FileType::RegularFile,
                    perm: 0o644,
                    nlink: 1,
                    uid,
                    gid,
                    rdev: 0,
                    blksize: 4096,
                    flags: 0,
                },
            }
        }

        /// Resolve inode → block_id string.
        fn block_id_of(&self, ino: u64) -> Option<String> {
            self.inodes.read().unwrap().block_id(ino).map(str::to_string)
        }

        /// Read a directory block, return an error code on failure.
        fn read_dir(&self, id: &str) -> Result<DirectoryBlock, i32> {
            match self.vault.read_node(id) {
                Ok(VaultNode::Directory(d)) => Ok(d),
                Ok(_) => Err(ENOTDIR),
                Err(_) => Err(EIO),
            }
        }

        /// Assemble the full byte content of a file (inline + continuations).
        fn read_file_data(&self, f: &FileBlock) -> Result<Vec<u8>, i32> {
            let mut data = f.data.clone();
            for cont_id in &f.continuation_ids {
                match self.vault.read_node(cont_id) {
                    Ok(VaultNode::File(c)) => data.extend_from_slice(&c.data),
                    _ => return Err(EIO),
                }
            }
            data.truncate(f.total_size as usize);
            Ok(data)
        }

        /// Write a byte buffer back into a (possibly multi-block) file node.
        /// Deletes/creates continuation blocks as needed.
        fn write_file_data(&self, first_id: &str, existing: &FileBlock, new_data: Vec<u8>) -> Result<(), i32> {
            // Delete old continuation blocks
            for cont_id in &existing.continuation_ids {
                let _ = self.vault.store.delete(cont_id);
                self.inodes.write().unwrap().remove(cont_id);
            }

            let total_size = new_data.len() as u64;
            let mut chunks = new_data.chunks(BLOCK_DATA_CAPACITY);
            let first_chunk = chunks.next().unwrap_or(&[]).to_vec();

            let mut cont_ids: Vec<String> = vec![];
            for chunk in chunks {
                let cont = VaultNode::File(FileBlock {
                    kind: NodeKind::FileContinuation,
                    total_size: 0,
                    continuation_ids: vec![],
                    data: chunk.to_vec(),
                });
                let id = self.vault.write_node(&cont).map_err(|_| EIO)?;
                cont_ids.push(id);
            }

            let updated = VaultNode::File(FileBlock {
                kind: NodeKind::File,
                total_size,
                continuation_ids: cont_ids,
                data: first_chunk,
            });
            self.vault.update_node(first_id, &updated).map_err(|_| EIO)
        }

        /// Add a directory entry to a parent directory block.
        fn dir_add_entry(&self, parent_id: &str, entry: DirEntry) -> Result<(), i32> {
            let mut dir = self.read_dir(parent_id)?;
            if dir.entries.iter().any(|e| e.name == entry.name) {
                return Err(EEXIST);
            }
            dir.entries.push(entry);
            self.vault
                .update_node(parent_id, &VaultNode::Directory(dir))
                .map_err(|_| EIO)
        }

        /// Remove a named entry from a parent directory, returning its block_id.
        fn dir_remove_entry(&self, parent_id: &str, name: &str) -> Result<String, i32> {
            let mut dir = self.read_dir(parent_id)?;
            let pos = dir.entries.iter().position(|e| e.name == name).ok_or(ENOENT)?;
            let removed_id = dir.entries.remove(pos).block_id;
            self.vault
                .update_node(parent_id, &VaultNode::Directory(dir))
                .map_err(|_| EIO)?;
            Ok(removed_id)
        }
    }

    // ── Filesystem trait ─────────────────────────────────────────────────────

    impl Filesystem for VenomFuse {
        fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
            let name = match name.to_str() {
                Some(n) => n,
                None => { reply.error(ENOENT); return; }
            };
            let parent_id = match self.block_id_of(parent) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            let dir = match self.read_dir(&parent_id) {
                Ok(d) => d,
                Err(e) => { reply.error(e); return; }
            };
            match dir.entries.iter().find(|e| e.name == name) {
                Some(entry) => {
                    let child_id = entry.block_id.clone();
                    match self.vault.read_node(&child_id) {
                        Ok(node) => {
                            let ino = self.inodes.write().unwrap().get_or_alloc(&child_id);
                            reply.entry(&TTL, &self.make_attr(ino, &node), 0);
                        }
                        Err(_) => reply.error(EIO),
                    }
                }
                None => reply.error(ENOENT),
            }
        }

        fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
            let id = match self.block_id_of(ino) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            match self.vault.read_node(&id) {
                Ok(node) => reply.attr(&TTL, &self.make_attr(ino, &node)),
                Err(_) => reply.error(EIO),
            }
        }

        fn setattr(
            &mut self,
            _req: &Request,
            ino: u64,
            _mode: Option<u32>,
            _uid: Option<u32>,
            _gid: Option<u32>,
            size: Option<u64>,
            _atime: Option<TimeOrNow>,
            _mtime: Option<TimeOrNow>,
            _ctime: Option<SystemTime>,
            _fh: Option<u64>,
            _crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<u32>,
            reply: ReplyAttr,
        ) {
            // Only handle size (truncate / extend).
            if let Some(new_size) = size {
                let id = match self.block_id_of(ino) {
                    Some(id) => id,
                    None => { reply.error(ENOENT); return; }
                };
                let fb = match self.vault.read_node(&id) {
                    Ok(VaultNode::File(f)) => f,
                    Ok(_) => { reply.error(EISDIR); return; }
                    Err(_) => { reply.error(EIO); return; }
                };
                let mut data = match self.read_file_data(&fb) {
                    Ok(d) => d,
                    Err(e) => { reply.error(e); return; }
                };
                data.resize(new_size as usize, 0);
                if let Err(e) = self.write_file_data(&id, &fb, data) {
                    reply.error(e);
                    return;
                }
            }
            // Re-read and return updated attrs
            let id = match self.block_id_of(ino) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            match self.vault.read_node(&id) {
                Ok(node) => reply.attr(&TTL, &self.make_attr(ino, &node)),
                Err(_) => reply.error(EIO),
            }
        }

        fn readdir(
            &mut self,
            _req: &Request,
            ino: u64,
            _fh: u64,
            offset: i64,
            mut reply: ReplyDirectory,
        ) {
            let id = match self.block_id_of(ino) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            let dir = match self.read_dir(&id) {
                Ok(d) => d,
                Err(e) => { reply.error(e); return; }
            };

            let mut entries: Vec<(u64, FileType, String)> = vec![
                (ino, FileType::Directory, ".".into()),
                (ino, FileType::Directory, "..".into()),
            ];
            for e in &dir.entries {
                let child_ino = self.inodes.write().unwrap().get_or_alloc(&e.block_id);
                let ft = if e.kind == NodeKind::Directory {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                entries.push((child_ino, ft, e.name.clone()));
            }
            for (i, (child_ino, ft, name)) in entries.iter().enumerate().skip(offset as usize) {
                if reply.add(*child_ino, (i + 1) as i64, *ft, name.as_str()) {
                    break;
                }
            }
            reply.ok();
        }

        fn mkdir(
            &mut self,
            _req: &Request,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            reply: ReplyEntry,
        ) {
            let name = match name.to_str() {
                Some(n) => n,
                None => { reply.error(EINVAL); return; }
            };
            let parent_id = match self.block_id_of(parent) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            let new_dir = VaultNode::Directory(DirectoryBlock {
                kind: NodeKind::Directory,
                entries: vec![],
            });
            let new_id = match self.vault.write_node(&new_dir) {
                Ok(id) => id,
                Err(_) => { reply.error(EIO); return; }
            };
            let entry = DirEntry {
                name: name.to_string(),
                block_id: new_id.clone(),
                kind: NodeKind::Directory,
            };
            if let Err(e) = self.dir_add_entry(&parent_id, entry) {
                let _ = self.vault.store.delete(&new_id);
                reply.error(e);
                return;
            }
            let ino = self.inodes.write().unwrap().get_or_alloc(&new_id);
            reply.entry(&TTL, &self.make_attr(ino, &new_dir), 0);
        }

        fn create(
            &mut self,
            _req: &Request,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            _flags: i32,
            reply: ReplyCreate,
        ) {
            let name = match name.to_str() {
                Some(n) => n,
                None => { reply.error(EINVAL); return; }
            };
            let parent_id = match self.block_id_of(parent) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            let new_file = VaultNode::File(FileBlock {
                kind: NodeKind::File,
                total_size: 0,
                continuation_ids: vec![],
                data: vec![],
            });
            let new_id = match self.vault.write_node(&new_file) {
                Ok(id) => id,
                Err(_) => { reply.error(EIO); return; }
            };
            let entry = DirEntry {
                name: name.to_string(),
                block_id: new_id.clone(),
                kind: NodeKind::File,
            };
            if let Err(e) = self.dir_add_entry(&parent_id, entry) {
                let _ = self.vault.store.delete(&new_id);
                reply.error(e);
                return;
            }
            let ino = self.inodes.write().unwrap().get_or_alloc(&new_id);
            let attr = self.make_attr(ino, &new_file);
            reply.created(&TTL, &attr, 0, ino, 0);
        }

        fn write(
            &mut self,
            _req: &Request,
            ino: u64,
            _fh: u64,
            offset: i64,
            data: &[u8],
            _write_flags: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyWrite,
        ) {
            let id = match self.block_id_of(ino) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            let fb = match self.vault.read_node(&id) {
                Ok(VaultNode::File(f)) => f,
                Ok(_) => { reply.error(EISDIR); return; }
                Err(_) => { reply.error(EIO); return; }
            };
            let mut buf = match self.read_file_data(&fb) {
                Ok(d) => d,
                Err(e) => { reply.error(e); return; }
            };

            let start = offset as usize;
            let end = start + data.len();
            if end > buf.len() {
                buf.resize(end, 0);
            }
            buf[start..end].copy_from_slice(data);

            if let Err(e) = self.write_file_data(&id, &fb, buf) {
                reply.error(e);
                return;
            }
            reply.written(data.len() as u32);
        }

        fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let name = match name.to_str() {
                Some(n) => n,
                None => { reply.error(EINVAL); return; }
            };
            let parent_id = match self.block_id_of(parent) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            let removed_id = match self.dir_remove_entry(&parent_id, name) {
                Ok(id) => id,
                Err(e) => { reply.error(e); return; }
            };
            // Delete continuation blocks then the main block
            if let Ok(VaultNode::File(f)) = self.vault.read_node(&removed_id) {
                for cont_id in &f.continuation_ids {
                    let _ = self.vault.store.delete(cont_id);
                    self.inodes.write().unwrap().remove(cont_id);
                }
            }
            let _ = self.vault.store.delete(&removed_id);
            self.inodes.write().unwrap().remove(&removed_id);
            reply.ok();
        }

        fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let name = match name.to_str() {
                Some(n) => n,
                None => { reply.error(EINVAL); return; }
            };
            let parent_id = match self.block_id_of(parent) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };

            // Peek at the target to check it's an empty directory
            let dir = match self.read_dir(&parent_id) {
                Ok(d) => d,
                Err(e) => { reply.error(e); return; }
            };
            let target_id = match dir.entries.iter().find(|e| e.name == name) {
                Some(e) => e.block_id.clone(),
                None => { reply.error(ENOENT); return; }
            };
            let target_dir = match self.read_dir(&target_id) {
                Ok(d) => d,
                Err(e) => { reply.error(e); return; }
            };
            if !target_dir.entries.is_empty() {
                reply.error(ENOTEMPTY);
                return;
            }

            match self.dir_remove_entry(&parent_id, name) {
                Ok(removed_id) => {
                    let _ = self.vault.store.delete(&removed_id);
                    self.inodes.write().unwrap().remove(&removed_id);
                    reply.ok();
                }
                Err(e) => reply.error(e),
            }
        }

        fn rename(
            &mut self,
            _req: &Request,
            parent: u64,
            name: &OsStr,
            newparent: u64,
            newname: &OsStr,
            _flags: u32,
            reply: ReplyEmpty,
        ) {
            let name = match name.to_str() {
                Some(n) => n,
                None => { reply.error(EINVAL); return; }
            };
            let newname = match newname.to_str() {
                Some(n) => n,
                None => { reply.error(EINVAL); return; }
            };
            let parent_id = match self.block_id_of(parent) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            let newparent_id = match self.block_id_of(newparent) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };

            let moved_id = match self.dir_remove_entry(&parent_id, name) {
                Ok(id) => id,
                Err(e) => { reply.error(e); return; }
            };

            // Determine kind for the new entry
            let kind = match self.vault.read_node(&moved_id) {
                Ok(VaultNode::Directory(_)) => NodeKind::Directory,
                Ok(_) => NodeKind::File,
                Err(_) => { reply.error(EIO); return; }
            };

            // If destination already exists, remove it first
            let mut dest_dir = match self.read_dir(&newparent_id) {
                Ok(d) => d,
                Err(e) => { reply.error(e); return; }
            };
            if let Some(pos) = dest_dir.entries.iter().position(|e| e.name == newname) {
                let old_id = dest_dir.entries.remove(pos).block_id;
                let _ = self.vault.store.delete(&old_id);
                self.inodes.write().unwrap().remove(&old_id);
            }
            dest_dir.entries.push(DirEntry {
                name: newname.to_string(),
                block_id: moved_id,
                kind,
            });
            match self.vault.update_node(&newparent_id, &VaultNode::Directory(dest_dir)) {
                Ok(_) => reply.ok(),
                Err(_) => reply.error(EIO),
            }
        }

        fn read(
            &mut self,
            _req: &Request,
            ino: u64,
            _fh: u64,
            offset: i64,
            size: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyData,
        ) {
            let id = match self.block_id_of(ino) {
                Some(id) => id,
                None => { reply.error(ENOENT); return; }
            };
            let fb = match self.vault.read_node(&id) {
                Ok(VaultNode::File(f)) => f,
                Ok(_) => { reply.error(EISDIR); return; }
                Err(_) => { reply.error(EIO); return; }
            };
            let data = match self.read_file_data(&fb) {
                Ok(d) => d,
                Err(e) => { reply.error(e); return; }
            };
            let start = (offset as usize).min(data.len());
            let end = (start + size as usize).min(data.len());
            reply.data(&data[start..end]);
        }
    }

    /// Mount `vault` at `mountpoint` — blocks until unmounted.
    pub fn mount(vault: Arc<Vault>, mountpoint: &str) -> crate::Result<()> {
        let fs = VenomFuse::new(vault);
        let options = vec![
            MountOption::FSName("venom".into()),
            MountOption::AutoUnmount,
            MountOption::AllowOther,
        ];
        fuser::mount2(fs, mountpoint, &options).map_err(VnmError::Io)
    }
}
