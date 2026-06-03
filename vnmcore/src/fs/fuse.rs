//! FUSE filesystem adapter for single-file Venom containers.
//!
//! Architecture: each FUSE op has a pure `op_*()` method (returns Result<T, errno>)
//! and a thin Filesystem wrapper.  Tests call op_*() directly without mounting.
//!
//! ## File I/O model — chunk-level LRU cache
//!
//!   open    → read head slot + index chain → build slot_map  (O(index size))
//!   read    → slice from LRU chunk cache; cache miss → decrypt one 30 KB slot
//!   write   → patch LRU cache entry, mark chunk dirty         (zero disk I/O)
//!   flush   → re-encrypt & persist dirty chunks only
//!   release → flush + evict
//!   Drop    → flush_all() safety net
//!
//! Memory cost per open file: at most MAX_CACHE_CHUNKS × CHUNK_SIZE ≈ 7.7 MB
//! regardless of file size.  Opening a 10 GB file reads only the index slots
//! (a few hundred KB) instead of the whole file.

#[cfg(feature = "fuse")]
pub mod driver {
    use std::collections::{HashMap, HashSet};
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
    use crate::storage::vault_fs::{
        DirectoryBlock, DirEntry, FileBlock, FileDataBlock, FileIndexBlock,
        CHUNK_SIZE, MAX_DIRECT_SLOTS, MAX_INDEX_SLOTS,
    };
    use crate::storage::{NodeKind, VaultNode};
    use crate::VnmError;

    const TTL: Duration = Duration::from_secs(1);
    pub const ROOT_INO: u64 = 1;
    const FOPEN_DIRECT_IO: u32 = 1;

    /// Max number of decoded chunks kept in memory per open file handle.
    /// 256 × 30 KB ≈ 7.7 MB.
    const MAX_CACHE_CHUNKS: usize = 256;

    /// When dirty continuation chunks exceed this threshold, flush the excess
    /// to disk immediately (write-through) so RAM stays bounded during large
    /// sequential writes.  Chunk 0 is excluded — it shares the head slot and
    /// can only be written when the full head metadata is known at close time.
    const WRITE_THROUGH_THRESHOLD: usize = MAX_CACHE_CHUNKS / 2; // 128 × 30 KB ≈ 3.8 MB

    // ── Inode ↔ slot mapping ──────────────────────────────────────────────────

    pub(crate) struct InodeMap {
        slot_to_ino: HashMap<u64, u64>,
        ino_to_slot: HashMap<u64, u64>,
        next_ino:    u64,
    }

    impl InodeMap {
        fn new(root_slot: u64) -> Self {
            let mut m = Self { slot_to_ino: HashMap::new(), ino_to_slot: HashMap::new(), next_ino: 2 };
            m.slot_to_ino.insert(root_slot, ROOT_INO);
            m.ino_to_slot.insert(ROOT_INO, root_slot);
            m
        }
        fn get_or_alloc(&mut self, slot: u64) -> u64 {
            if let Some(&ino) = self.slot_to_ino.get(&slot) { return ino; }
            let ino = self.next_ino; self.next_ino += 1;
            self.slot_to_ino.insert(slot, ino); self.ino_to_slot.insert(ino, slot); ino
        }
        fn slot_of(&self, ino: u64) -> Option<u64> { self.ino_to_slot.get(&ino).copied() }
        fn remove_slot(&mut self, slot: u64) {
            if let Some(ino) = self.slot_to_ino.remove(&slot) { self.ino_to_slot.remove(&ino); }
        }
    }

    // ── Open-file handle ──────────────────────────────────────────────────────

    /// Per-file-handle state.
    ///
    /// `slot_map[0]` is always `None` — chunk 0 lives inside the head slot itself
    /// and is handled specially on flush.  `slot_map[i]` for i ≥ 1 holds the
    /// physical slot id for continuation chunk i (None = not yet allocated on disk).
    pub(crate) struct OpenFile {
        ino:         u64,
        head_slot:   u64,
        total_size:  u64,
        /// Current index_chain pointer (needed to free old chain on rebuild).
        index_chain: Option<u64>,
        /// slot_map[i]: physical slot id for chunk i (None = unallocated new chunk).
        /// slot_map[0] is always None (chunk 0 is inline in the head slot).
        slot_map:    Vec<Option<u64>>,
        /// Decoded chunk bytes.
        cache:       HashMap<usize, Vec<u8>>,
        /// Chunk indices that need to be written back.
        dirty:       HashSet<usize>,
        /// True when total_size, slot_map, or index_chain changed.
        meta_dirty:  bool,
    }

    // ── Helpers (free functions) ──────────────────────────────────────────────

    /// Read the head slot and follow all index-chain slots to build a complete
    /// ordered slot_map.  Returns (total_size, index_chain, slot_map).
    ///
    /// slot_map[0] = None  (chunk 0 is inline in head)
    /// slot_map[i] = Some(id) for i ≥ 1
    fn build_slot_map(
        container: &VnmContainer,
        head_slot:  u64,
    ) -> Result<(u64, Option<u64>, Vec<Option<u64>>), i32> {
        let fb = match container.read_node(head_slot).map_err(|_| EIO)? {
            VaultNode::File(f) => f,
            _ => return Err(EISDIR),
        };

        let mut slot_map: Vec<Option<u64>> = Vec::with_capacity(1 + fb.data_slots.len() + 4);
        slot_map.push(None); // chunk 0 — inline in head
        for &id in &fb.data_slots { slot_map.push(Some(id)); }

        let mut next_idx = fb.index_chain;
        while let Some(idx_slot) = next_idx {
            match container.read_node(idx_slot).map_err(|_| EIO)? {
                VaultNode::FileIndex(fi) => {
                    for &id in &fi.slot_ids { slot_map.push(Some(id)); }
                    next_idx = fi.next_index;
                }
                _ => return Err(EIO),
            }
        }

        Ok((fb.total_size, fb.index_chain, slot_map))
    }

    /// Ensure chunk `chunk_idx` is in `of.cache`.  Loads from disk if missing.
    /// For unallocated new chunks (slot_map[i] == None) inserts a zero buffer.
    fn ensure_cached(container: &VnmContainer, of: &mut OpenFile, chunk_idx: usize) -> Result<(), i32> {
        if of.cache.contains_key(&chunk_idx) { return Ok(()); }

        let data = match of.slot_map.get(chunk_idx) {
            Some(Some(slot_id)) => {
                match container.read_node(*slot_id).map_err(|_| EIO)? {
                    VaultNode::File(fb) if chunk_idx == 0 => fb.data,
                    VaultNode::FileData(d)                => d.data,
                    _ => return Err(EIO),
                }
            }
            Some(None) if chunk_idx == 0 => {
                // Head slot not loaded yet (shouldn't happen — op_open pre-loads it)
                match container.read_node(of.head_slot).map_err(|_| EIO)? {
                    VaultNode::File(fb) => fb.data,
                    _ => return Err(EIO),
                }
            }
            Some(None) => vec![0u8; 0], // new unallocated chunk — zero on demand
            None       => return Err(EIO),
        };

        // LRU eviction: drop a clean chunk when cache is full
        if of.cache.len() >= MAX_CACHE_CHUNKS {
            if let Some(&evict) = of.cache.keys().find(|&&k| !of.dirty.contains(&k)) {
                of.cache.remove(&evict);
            }
            // If all are dirty, evict nothing — user wrote a lot without flushing
        }

        of.cache.insert(chunk_idx, data);
        Ok(())
    }

    /// Free all slots in an index_chain linked list.
    fn free_index_chain(container: &VnmContainer, first: Option<u64>) {
        let mut cur = first;
        while let Some(slot) = cur {
            cur = match container.read_node(slot) {
                Ok(VaultNode::FileIndex(fi)) => { container.free_node(slot); fi.next_index }
                _ => { container.free_node(slot); None }
            };
        }
    }

    /// Write a chain of FileIndexBlock slots for the given slice of slot ids.
    /// Returns the head of the chain (or None if slice is empty).
    fn write_index_chain(container: &VnmContainer, ids: &[u64]) -> Result<Option<u64>, i32> {
        if ids.is_empty() { return Ok(None); }
        let mut next: Option<u64> = None;
        for chunk in ids.rchunks(MAX_INDEX_SLOTS) {
            let node = VaultNode::FileIndex(FileIndexBlock {
                kind: NodeKind::FileIndex, slot_ids: chunk.to_vec(), next_index: next,
            });
            next = Some(container.write_node(&node).map_err(|_| EIO)?);
        }
        Ok(next)
    }

    // ── VenomFuse ─────────────────────────────────────────────────────────────

    pub struct VenomFuse {
        pub(crate) container:   Arc<VnmContainer>,
        pub(crate) inodes:      RwLock<InodeMap>,
        pub(crate) open_files:  HashMap<u64, OpenFile>,
        next_fh: u64,
    }

    impl VenomFuse {
        pub fn new(container: Arc<VnmContainer>) -> Self {
            let root_slot = container.root_slot();
            Self {
                container,
                inodes:     RwLock::new(InodeMap::new(root_slot)),
                open_files: HashMap::new(),
                next_fh:    1,
            }
        }

        fn alloc_fh(&mut self) -> u64 {
            let fh = self.next_fh;
            self.next_fh = self.next_fh.wrapping_add(1).max(1);
            fh
        }

        pub fn slot_of_ino(&self, ino: u64) -> Option<u64> {
            self.inodes.read().unwrap().slot_of(ino)
        }

        // ── Attr helpers ──────────────────────────────────────────────────────

        pub fn make_dir_attr(&self, ino: u64) -> FileAttr {
            let ts = UNIX_EPOCH;
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            FileAttr { ino, size: 0, blocks: 0, atime: ts, mtime: ts, ctime: ts, crtime: ts,
                kind: FileType::Directory, perm: 0o755, nlink: 2, uid, gid, rdev: 0, blksize: 512, flags: 0 }
        }

        pub fn make_file_attr(&self, ino: u64, size: u64) -> FileAttr {
            let ts = UNIX_EPOCH;
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            FileAttr { ino, size, blocks: (size + 511) / 512,
                atime: ts, mtime: ts, ctime: ts, crtime: ts,
                kind: FileType::RegularFile, perm: 0o644, nlink: 1, uid, gid,
                rdev: 0, blksize: 4096, flags: 0 }
        }

        fn make_attr(&self, ino: u64, node: &VaultNode) -> FileAttr {
            match node {
                VaultNode::Directory(_) => self.make_dir_attr(ino),
                VaultNode::File(f)      => self.make_file_attr(ino, f.total_size),
                _                       => self.make_file_attr(ino, 0),
            }
        }

        fn cached_size_for_ino(&self, ino: u64) -> Option<u64> {
            self.open_files.values().find(|of| of.ino == ino).map(|of| of.total_size)
        }

        // ── Directory helpers ─────────────────────────────────────────────────

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
            let removed = dir.entries.remove(pos).slot;
            self.container.update_node(parent_slot, &VaultNode::Directory(dir)).map_err(|_| EIO)?;
            Ok(removed)
        }

        // ── Flush helpers ─────────────────────────────────────────────────────

        /// Flush the `n` lowest-index dirty continuation chunks (ci ≥ 1) to disk.
        ///
        /// Called from `op_write` when dirty count exceeds WRITE_THROUGH_THRESHOLD.
        /// Continuation slots can be written independently of the head slot, so
        /// this keeps RAM bounded during large sequential copies without requiring
        /// a full flush (which would also update the head and index chain).
        fn write_through_flush(&mut self, fh: u64, n: usize) -> Result<(), i32> {
            let container = Arc::clone(&self.container);
            let of = match self.open_files.get_mut(&fh) { Some(o) => o, None => return Ok(()) };

            // Collect the n lowest dirty continuation chunk indices
            let mut to_flush: Vec<usize> = of.dirty.iter()
                .copied()
                .filter(|&ci| ci >= 1)
                .collect();
            to_flush.sort_unstable();
            to_flush.truncate(n);

            for ci in to_flush {
                let data = match of.cache.get(&ci) { Some(d) => d.clone(), None => continue };
                let node = VaultNode::FileData(FileDataBlock { kind: NodeKind::FileData, data });

                match of.slot_map.get(ci) {
                    Some(Some(slot_id)) => {
                        container.update_node(*slot_id, &node).map_err(|_| EIO)?;
                    }
                    Some(None) => {
                        let new_slot = container.write_node(&node).map_err(|_| EIO)?;
                        of.slot_map[ci] = Some(new_slot);
                        of.meta_dirty = true;
                    }
                    None => continue,
                }

                of.dirty.remove(&ci);
                of.cache.remove(&ci);
            }

            Ok(())
        }

        fn flush_fh(&mut self, fh: u64) -> Result<(), i32> {
            // Check if there's anything to do before taking ownership
            {
                let of = match self.open_files.get(&fh) { Some(o) => o, None => return Ok(()) };
                if of.dirty.is_empty() && !of.meta_dirty { return Ok(()); }
            }

            // Clone fields we need to avoid borrow conflicts with container calls
            let container = Arc::clone(&self.container);
            let of = self.open_files.get_mut(&fh).unwrap();

            let total_size  = of.total_size;
            let n_chunks    = if total_size == 0 { 0 } else { (total_size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE };

            // ── Step 1: write dirty continuation chunks (index ≥ 1) ──────────
            for &ci in of.dirty.iter().filter(|&&ci| ci >= 1) {
                let data = match of.cache.get(&ci) { Some(d) => d.clone(), None => continue };
                match of.slot_map.get(ci) {
                    Some(Some(slot_id)) => {
                        let node = VaultNode::FileData(FileDataBlock { kind: NodeKind::FileData, data });
                        container.update_node(*slot_id, &node).map_err(|_| EIO)?;
                    }
                    Some(None) => {
                        let node = VaultNode::FileData(FileDataBlock { kind: NodeKind::FileData, data });
                        let new_slot = container.write_node(&node).map_err(|_| EIO)?;
                        of.slot_map[ci] = Some(new_slot);
                        of.meta_dirty = true;
                    }
                    None => {} // beyond current slot_map — handled in resize below
                }
            }

            // ── Step 2: free excess slots if file was truncated ───────────────
            if of.slot_map.len() > n_chunks.max(1) {
                for opt in of.slot_map.drain(n_chunks.max(1)..) {
                    if let Some(slot_id) = opt {
                        container.free_node(slot_id);
                    }
                }
                of.meta_dirty = true;
            }

            // ── Step 3: rebuild head + index chain if metadata changed ────────
            let must_write_head = of.meta_dirty || of.dirty.contains(&0);
            if must_write_head {
                // Read old head to get current data if chunk 0 not in cache
                let chunk0 = if let Some(d) = of.cache.get(&0) {
                    let mut d = d.clone();
                    if let Some(sz) = chunk_actual_size(0, total_size) { d.truncate(sz); }
                    d
                } else {
                    match container.read_node(of.head_slot).map_err(|_| EIO)? {
                        VaultNode::File(fb) => fb.data,
                        _ => return Err(EIO),
                    }
                };

                // Continuation slot ids (index 1..n_chunks)
                let all_cont: Vec<u64> = of.slot_map[1..n_chunks.max(1).min(of.slot_map.len())]
                    .iter()
                    .filter_map(|&s| s)
                    .collect();

                // Free old index chain, build new one
                free_index_chain(&container, of.index_chain);
                let (data_slots, new_chain) = if all_cont.len() <= MAX_DIRECT_SLOTS {
                    (all_cont, None)
                } else {
                    let overflow = &all_cont[MAX_DIRECT_SLOTS..];
                    let chain = write_index_chain(&container, overflow)?;
                    (all_cont[..MAX_DIRECT_SLOTS].to_vec(), chain)
                };

                of.index_chain = new_chain;
                container.update_node(of.head_slot, &VaultNode::File(FileBlock {
                    kind:        NodeKind::File,
                    total_size,
                    data_slots,
                    index_chain: new_chain,
                    data:        chunk0,
                })).map_err(|_| EIO)?;
            }

            of.dirty.clear();
            of.meta_dirty = false;
            Ok(())
        }

        fn flush_all(&mut self) {
            let fhs: Vec<u64> = self.open_files.keys().copied().collect();
            for fh in fhs { let _ = self.flush_fh(fh); }
            let _ = self.container.flush();
        }

        // ── Core operations ───────────────────────────────────────────────────

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
            let p_slot  = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let new_dir = VaultNode::Directory(DirectoryBlock { kind: NodeKind::Directory, entries: vec![] });
            let slot    = self.container.write_node(&new_dir).map_err(|_| EIO)?;
            let entry   = DirEntry { name: name.to_string(), slot, kind: NodeKind::Directory };
            if let Err(e) = self.dir_add_entry(p_slot, entry) { self.container.free_node(slot); return Err(e); }
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
            let p_slot  = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let node    = VaultNode::File(FileBlock {
                kind: NodeKind::File, total_size: 0,
                data_slots: vec![], index_chain: None, data: vec![],
            });
            let head    = self.container.write_node(&node).map_err(|_| EIO)?;
            let entry   = DirEntry { name: name.to_string(), slot: head, kind: NodeKind::File };
            if let Err(e) = self.dir_add_entry(p_slot, entry) { self.container.free_node(head); return Err(e); }
            let ino = self.inodes.write().unwrap().get_or_alloc(head);
            let fh  = self.alloc_fh();
            self.open_files.insert(fh, OpenFile {
                ino, head_slot: head, total_size: 0, index_chain: None,
                slot_map: vec![None], cache: HashMap::new(),
                dirty: HashSet::new(), meta_dirty: false,
                            });
            Ok((ino, fh))
        }

        pub fn op_unlink(&mut self, parent: u64, name: &str) -> Result<(), i32> {
            let p_slot  = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let removed = self.dir_remove_entry(p_slot, name)?;
            // Evict any open handles for this head slot
            self.open_files.retain(|_, of| of.head_slot != removed);
            if let Ok(VaultNode::File(fb)) = self.container.read_node(removed) {
                // Free continuation slots
                for id in &fb.data_slots { self.container.free_node(*id); }
                free_index_chain(&self.container, fb.index_chain);
            }
            self.container.free_node(removed);
            self.inodes.write().unwrap().remove_slot(removed);
            Ok(())
        }

        pub fn op_rename(&mut self, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<(), i32> {
            let p_slot  = self.slot_of_ino(parent).ok_or(ENOENT)?;
            let np_slot = self.slot_of_ino(newparent).ok_or(ENOENT)?;
            let moved   = self.dir_remove_entry(p_slot, name)?;
            let kind    = match self.container.read_node(moved).map_err(|_| EIO)? {
                VaultNode::Directory(_) => NodeKind::Directory,
                _                       => NodeKind::File,
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
            let head_slot = self.slot_of_ino(ino).ok_or(ENOENT)?;
            let container = Arc::clone(&self.container);
            let (total_size, index_chain, mut slot_map) = build_slot_map(&container, head_slot)?;

            // Pre-load chunk 0 (inline in head) — always tiny, avoids a re-read on first access
            let chunk0 = match container.read_node(head_slot).map_err(|_| EIO)? {
                VaultNode::File(fb) => fb.data,
                _ => return Err(EISDIR),
            };
            let mut cache = HashMap::new();
            if !chunk0.is_empty() { cache.insert(0usize, chunk0); }

            // slot_map[0] stays None (chunk 0 is inline in head)
            if slot_map.is_empty() { slot_map.push(None); }

            let fh = self.alloc_fh();
            self.open_files.insert(fh, OpenFile {
                ino, head_slot, total_size, index_chain, slot_map, cache,
                dirty: HashSet::new(), meta_dirty: false,             });
            Ok(fh)
        }

        pub fn op_flush(&mut self, fh: u64)   -> Result<(), i32> { self.flush_fh(fh) }
        pub fn op_release(&mut self, fh: u64) -> Result<(), i32> {
            self.flush_fh(fh)?;
            self.open_files.remove(&fh);
            Ok(())
        }

        pub fn op_read(&mut self, _ino: u64, fh: u64, offset: i64, size: u32) -> Result<Vec<u8>, i32> {
            let total = {
                let of = self.open_files.get(&fh).ok_or(ENOENT)?;
                of.total_size as usize
            };
            let offset = offset as usize;
            if offset >= total { return Ok(vec![]); }
            let end = (offset + size as usize).min(total);

            let mut result = Vec::with_capacity(end - offset);
            let mut pos = offset;
            while pos < end {
                let ci  = pos / CHUNK_SIZE;
                let off = pos % CHUNK_SIZE;
                let container = Arc::clone(&self.container);
                let of = self.open_files.get_mut(&fh).ok_or(ENOENT)?;
                ensure_cached(&container, of, ci)?;
                let data = of.cache.get(&ci).ok_or(EIO)?;
                let take = (data.len().saturating_sub(off)).min(end - pos);
                if take == 0 { break; }
                result.extend_from_slice(&data[off..off + take]);
                pos += take;
            }
            Ok(result)
        }

        pub fn op_write(&mut self, _ino: u64, fh: u64, offset: i64, data: &[u8]) -> Result<u32, i32> {
            let offset = offset as usize;
            let end    = offset + data.len();
            let mut pos = offset;

            while pos < end {
                let ci      = pos / CHUNK_SIZE;
                let coff    = pos % CHUNK_SIZE;
                let take    = (CHUNK_SIZE - coff).min(end - pos);

                let container = Arc::clone(&self.container);
                let of = self.open_files.get_mut(&fh).ok_or(ENOENT)?;

                // Extend slot_map if writing beyond current end
                while of.slot_map.len() <= ci {
                    of.slot_map.push(None);
                    of.meta_dirty = true;
                }

                // Load chunk into cache if not present
                if !of.cache.contains_key(&ci) {
                    if of.slot_map[ci].is_some() || ci == 0 {
                        ensure_cached(&container, of, ci)?;
                    } else {
                        // Brand-new chunk: start with zeros
                        of.cache.insert(ci, vec![0u8; CHUNK_SIZE]);
                    }
                }

                let chunk = of.cache.get_mut(&ci).ok_or(EIO)?;
                let write_end = coff + take;
                if chunk.len() < write_end { chunk.resize(write_end, 0); }
                chunk[coff..write_end].copy_from_slice(&data[pos - offset..pos - offset + take]);
                of.dirty.insert(ci);

                // Update total_size
                let new_total = (end as u64).max(of.total_size);
                if new_total != of.total_size { of.total_size = new_total; of.meta_dirty = true; }

                pos += take;
            }

            // Write-through: flush oldest dirty continuation chunks when threshold
            // is exceeded so that large sequential copies don't accumulate GBs in RAM.
            let dirty_cont = self.open_files.get(&fh)
                .map(|of| of.dirty.iter().filter(|&&ci| ci >= 1).count())
                .unwrap_or(0);
            if dirty_cont > WRITE_THROUGH_THRESHOLD {
                self.write_through_flush(fh, dirty_cont - WRITE_THROUGH_THRESHOLD / 2)?;
            }

            Ok(data.len() as u32)
        }

        pub fn op_setattr_size(&mut self, ino: u64, fh_hint: Option<u64>, new_size: u64) -> Result<(), i32> {
            let fh = fh_hint.or_else(|| {
                self.open_files.iter().find(|(_, of)| of.ino == ino).map(|(&f, _)| f)
            });

            if let Some(fh) = fh {
                let of = self.open_files.get_mut(&fh).ok_or(ENOENT)?;
                if new_size == of.total_size { return Ok(()); }

                if new_size < of.total_size {
                    // Truncate: evict excess chunks from cache, clamp last chunk
                    let last_ci = if new_size == 0 { 0 } else { (new_size as usize - 1) / CHUNK_SIZE };
                    let last_sz = if new_size == 0 { 0 } else { chunk_actual_size(last_ci, new_size).unwrap_or(0) };
                    of.cache.retain(|&k, _| k <= last_ci);
                    of.dirty.retain(|&k| k <= last_ci);
                    if let Some(v) = of.cache.get_mut(&last_ci) { v.truncate(last_sz); }
                    if new_size > 0 { of.dirty.insert(last_ci); }
                }
                // For extension (new_size > total_size): just update total_size;
                // the new bytes are zero-filled on demand when written/read.

                of.total_size = new_size;
                of.meta_dirty = true;
                return Ok(());
            }

            // No open handle — do it on disk directly
            let head_slot = self.slot_of_ino(ino).ok_or(ENOENT)?;
            let fb = match self.container.read_node(head_slot).map_err(|_| EIO)? {
                VaultNode::File(f) => f,
                _ => return Err(EIO),
            };
            if new_size < fb.total_size {
                let n_chunks = if new_size == 0 { 0 } else { (new_size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE };
                // Free excess continuation slots
                if fb.data_slots.len() > n_chunks.saturating_sub(1) {
                    for &id in &fb.data_slots[n_chunks.saturating_sub(1)..] {
                        self.container.free_node(id);
                    }
                }
                free_index_chain(&self.container, fb.index_chain);
                let new_cont: Vec<u64> = fb.data_slots[..n_chunks.saturating_sub(1).min(fb.data_slots.len())].to_vec();
                let mut data = fb.data;
                if n_chunks == 0 { data.clear(); } else { data.truncate(new_size as usize); }
                self.container.update_node(head_slot, &VaultNode::File(FileBlock {
                    kind: NodeKind::File, total_size: new_size,
                    data_slots: new_cont, index_chain: None, data,
                })).map_err(|_| EIO)?;
            } else {
                self.container.update_node(head_slot, &VaultNode::File(FileBlock {
                    total_size: new_size, ..fb
                })).map_err(|_| EIO)?;
            }
            Ok(())
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
                        if let Some(sz) = self.cached_size_for_ino(ino) { attr.size = sz; attr.blocks = (sz + 511) / 512; }
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
                    if let Some(sz) = self.cached_size_for_ino(ino) { attr.size = sz; attr.blocks = (sz + 511) / 512; }
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
            let mut entries = vec![
                (ino, FileType::Directory, ".".to_string()),
                (ino, FileType::Directory, "..".to_string()),
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
            let _ = self.op_release(fh); reply.ok();
        }

        fn flush(&mut self, _req: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
            match self.op_flush(fh) { Ok(_) => reply.ok(), Err(e) => reply.error(e) }
        }

        fn fsync(&mut self, _req: &Request, _ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
            match self.op_flush(fh) { Ok(_) => reply.ok(), Err(e) => reply.error(e) }
        }

        fn read(&mut self, _req: &Request, ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyData) {
            match self.op_read(ino, fh, offset, size) { Ok(d) => reply.data(&d), Err(e) => reply.error(e) }
        }

        fn write(&mut self, _req: &Request, ino: u64, fh: u64, offset: i64, data: &[u8], _write_flags: u32, _flags: i32, _lock_owner: Option<u64>, reply: ReplyWrite) {
            match self.op_write(ino, fh, offset, data) { Ok(n) => reply.written(n), Err(e) => reply.error(e) }
        }

        fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
            let free  = self.container.store.free.lock().unwrap().len() as u64;
            let total = self.container.outer_limit;
            reply.statfs(total, free, free, 1 << 20, 1 << 20, 4096, 255, 4096);
        }
    }

    impl Drop for VenomFuse { fn drop(&mut self) { self.flush_all(); } }

    pub fn mount(container: Arc<VnmContainer>, mountpoint: &str) -> crate::Result<()> {
        let fs = VenomFuse::new(container);
        let options = vec![MountOption::FSName("venom".into())];
        fuser::mount2(fs, mountpoint, &options).map_err(VnmError::Io)
    }

    // ── Pure helper ───────────────────────────────────────────────────────────

    /// Expected byte count for chunk `ci` given `total_size`.
    fn chunk_actual_size(ci: usize, total_size: u64) -> Option<usize> {
        let start = ci * CHUNK_SIZE;
        let ts    = total_size as usize;
        if start >= ts { return None; }
        Some((ts - start).min(CHUNK_SIZE))
    }

    // ── Integration tests ─────────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;
        use crate::container::CipherAlgorithm;
        use crate::fs::container::VnmContainer;
        use crate::storage::{NodeKind, VaultNode};
        use crate::storage::vault_fs::{DirEntry, FileBlock};

        const MB: u64 = 1024 * 1024;

        fn tmp(label: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!("vnm_{label}_{}.vnm", std::process::id()))
        }

        fn setup(label: &str) -> (Arc<VnmContainer>, VenomFuse, std::path::PathBuf) {
            let path = tmp(label);
            let _ = std::fs::remove_file(&path);
            let c = Arc::new(VnmContainer::create(
                &path, b"pass", 32 * MB, CipherAlgorithm::XChaCha20Poly1305, "interactive", None, None,
            ).unwrap());
            let fuse = VenomFuse::new(c.clone());
            (c, fuse, path)
        }

        /// Plant a file directly via the container (bypasses FUSE) and register its inode.
        fn plant_file(c: &Arc<VnmContainer>, fuse: &mut VenomFuse, name: &str, content: &[u8]) -> (u64, u64) {
            let node = VaultNode::File(FileBlock {
                kind: NodeKind::File, total_size: content.len() as u64,
                data_slots: vec![], index_chain: None, data: content.to_vec(),
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

        /// Read file data from disk by following head + index (for test assertions).
        fn disk_data(c: &Arc<VnmContainer>, head_slot: u64) -> Vec<u8> {
            let fb = match c.read_node(head_slot).unwrap() {
                VaultNode::File(f) => f,
                _ => panic!("expected File node"),
            };
            let mut data = fb.data.clone();
            for &id in &fb.data_slots {
                if let Ok(VaultNode::FileData(d)) = c.read_node(id) {
                    data.extend_from_slice(&d.data);
                }
            }
            data.truncate(fb.total_size as usize);
            data
        }

        #[test]
        fn cache_open_populates_entry() {
            let (c, mut fuse, path) = setup("open_entry");
            let (slot, ino) = plant_file(&c, &mut fuse, "f.txt", b"hello");
            let fh = fuse.op_open(ino).unwrap();
            let of = fuse.open_files.get(&fh).unwrap();
            assert_eq!(of.cache.get(&0).unwrap(), b"hello");
            assert_eq!(of.head_slot, slot);
            assert!(!of.dirty.contains(&0));
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn write_marks_dirty_no_disk_change() {
            let (c, mut fuse, path) = setup("write_dirty");
            let (slot, ino) = plant_file(&c, &mut fuse, "f.txt", b"original");
            let fh = fuse.op_open(ino).unwrap();
            fuse.op_write(ino, fh, 0, b"modified").unwrap();
            assert!(fuse.open_files[&fh].dirty.contains(&0));
            // Disk still has original
            assert_eq!(disk_data(&c, slot), b"original");
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn flush_persists_and_clears_dirty() {
            let (c, mut fuse, path) = setup("flush_persist");
            let (slot, ino) = plant_file(&c, &mut fuse, "f.txt", b"v1");
            let fh = fuse.op_open(ino).unwrap();
            fuse.op_write(ino, fh, 0, b"version-2").unwrap();
            fuse.flush_fh(fh).unwrap();
            assert!(fuse.open_files[&fh].dirty.is_empty());
            assert_eq!(disk_data(&c, slot), b"version-2");
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn drop_flushes_dirty_files() {
            let path = tmp("drop_flush");
            let _ = std::fs::remove_file(&path);
            let c = Arc::new(VnmContainer::create(
                &path, b"pass", 16 * MB, CipherAlgorithm::XChaCha20Poly1305, "interactive", None, None,
            ).unwrap());
            let slot = {
                let mut fuse = VenomFuse::new(c.clone());
                let (s, ino) = plant_file(&c, &mut fuse, "f.txt", b"init");
                let fh = fuse.op_open(ino).unwrap();
                fuse.op_write(ino, fh, 0, b"by drop").unwrap();
                s
            }; // VenomFuse dropped here → flush_all
            assert_eq!(disk_data(&c, slot), b"by drop");
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn op_mkdir_creates_directory() {
            let (_c, mut fuse, path) = setup("mkdir");
            fuse.op_mkdir(ROOT_INO, "docs").unwrap();
            let (_, node) = fuse.op_lookup(ROOT_INO, "docs").unwrap();
            assert!(matches!(node, VaultNode::Directory(_)));
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn op_create_write_release_open_read() {
            let (_c, mut fuse, path) = setup("create_cycle");
            let (ino, fh) = fuse.op_create(ROOT_INO, "note.txt").unwrap();
            fuse.op_write(ino, fh, 0, b"hello venom").unwrap();
            fuse.op_release(fh).unwrap();
            let fh2 = fuse.op_open(ino).unwrap();
            let data = fuse.op_read(ino, fh2, 0, 1024).unwrap();
            assert_eq!(data, b"hello venom");
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn op_unlink_removes_file() {
            let (_c, mut fuse, path) = setup("unlink");
            fuse.op_create(ROOT_INO, "bye.txt").unwrap();
            fuse.op_unlink(ROOT_INO, "bye.txt").unwrap();
            assert_eq!(fuse.op_lookup(ROOT_INO, "bye.txt").unwrap_err(), ENOENT);
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn large_file_multi_chunk_roundtrip() {
            // 75 KB — spans 3 chunks (30 KB each) across 3 slots.
            let (_c, mut fuse, path) = setup("large_file");
            let payload: Vec<u8> = (0u32..75_000).map(|i| (i * 7 + 13) as u8).collect();
            let (ino, fh) = fuse.op_create(ROOT_INO, "big.bin").unwrap();
            fuse.op_write(ino, fh, 0, &payload).unwrap();
            fuse.op_release(fh).unwrap();
            let fh2  = fuse.op_open(ino).unwrap();
            let back = fuse.op_read(ino, fh2, 0, payload.len() as u32 + 1).unwrap();
            assert_eq!(back, payload);
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn write_through_keeps_cache_bounded() {
            // Write WRITE_THROUGH_THRESHOLD * 3 chunks and verify that
            // the in-memory dirty count never exceeds the threshold + 1.
            let (_c, mut fuse, path) = setup("write_through");
            let (ino, fh) = fuse.op_create(ROOT_INO, "large.bin").unwrap();

            let chunk = vec![0xABu8; CHUNK_SIZE];
            let limit = WRITE_THROUGH_THRESHOLD * 3 + 1;
            for i in 0..limit {
                fuse.op_write(ino, fh, (i * CHUNK_SIZE) as i64, &chunk).unwrap();
                let dirty_cont = fuse.open_files[&fh].dirty.iter().filter(|&&ci| ci >= 1).count();
                assert!(
                    dirty_cont <= WRITE_THROUGH_THRESHOLD + 1,
                    "dirty continuation chunks = {dirty_cont} at chunk {i}, expected ≤ {}",
                    WRITE_THROUGH_THRESHOLD + 1
                );
            }

            // Data must be fully readable after release
            fuse.op_release(fh).unwrap();
            let fh2 = fuse.op_open(ino).unwrap();
            let back = fuse.op_read(ino, fh2, 0, CHUNK_SIZE as u32).unwrap();
            assert_eq!(back, chunk);
            let tail_off = ((limit - 1) * CHUNK_SIZE) as i64;
            let back_tail = fuse.op_read(ino, fh2, tail_off, CHUNK_SIZE as u32).unwrap();
            assert_eq!(back_tail, chunk);
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn seek_read_does_not_load_entire_file() {
            // Write 3 chunks then seek directly to chunk 2 — only chunk 2 should be in cache.
            let (_c, mut fuse, path) = setup("seek");
            let payload: Vec<u8> = (0u32..75_000).map(|i| i as u8).collect();
            let (ino, fh) = fuse.op_create(ROOT_INO, "seek.bin").unwrap();
            fuse.op_write(ino, fh, 0, &payload).unwrap();
            fuse.op_release(fh).unwrap();

            let fh2 = fuse.op_open(ino).unwrap();
            // After open, cache has chunk 0 (pre-loaded from head). Evict it.
            fuse.open_files.get_mut(&fh2).unwrap().cache.remove(&0);

            // Read only from chunk 2 (offset 60 000)
            let chunk2_start = 2 * CHUNK_SIZE;
            let _ = fuse.op_read(ino, fh2, chunk2_start as i64, 100).unwrap();

            let of = &fuse.open_files[&fh2];
            assert!(of.cache.contains_key(&2), "chunk 2 must be cached");
            assert!(!of.cache.contains_key(&0), "chunk 0 must not be loaded");
            assert!(!of.cache.contains_key(&1), "chunk 1 must not be loaded");
            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn op_rename_within_dir() {
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
