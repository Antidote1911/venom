//! Windows filesystem backend using WinFSP.
//!
//! Mirrors the FUSE driver but uses the WinFSP user-mode filesystem API.
//! Requires WinFSP to be installed on the system (https://winfsp.dev/).
//!
//! Mount point can be a drive letter (`V:`) or a directory path.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use widestring::U16CStr;
use winfsp::filesystem::{
    DirInfo, FileInfo, FileSecurity, FileSystem, FileSystemContext, FileSystemParams,
    IoResult, OpenFileInfo, VolumeInfo,
};
use winfsp::error::FspError;

use crate::fs::container::VnmContainer;
use crate::storage::vault_fs::{DirectoryBlock, DirEntry, FileBlock};
use crate::storage::{NodeKind, VaultNode};
use crate::VnmError;

// ── Windows constants ─────────────────────────────────────────────────────────

const FILE_ATTRIBUTE_DIRECTORY: u32  = 0x10;
const FILE_ATTRIBUTE_NORMAL:    u32  = 0x80;
const FILE_ATTRIBUTE_ARCHIVE:   u32  = 0x20;

const DELETE:                   u32  = 0x0001_0000;
const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;

/// Seconds between Windows epoch (1601-01-01) and Unix epoch (1970-01-01).
const WIN_EPOCH_DIFF: u64 = 11_644_473_600;

fn unix_to_win_time(secs: u64) -> u64 {
    (secs + WIN_EPOCH_DIFF) * 10_000_000
}

fn now_win_time() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_win_time(secs)
}

const FILE_DATA_CHUNK: usize = 30_000;

// ── Open-file cache ───────────────────────────────────────────────────────────

struct OpenFile {
    slot:   u64,
    ino:    u64,
    data:   Vec<u8>,
    dirty:  bool,
    is_dir: bool,
}

// ── InodeMap ──────────────────────────────────────────────────────────────────

struct InodeMap {
    slot_to_ino: HashMap<u64, u64>,
    ino_to_slot: HashMap<u64, u64>,
    next_ino:    u64,
}

impl InodeMap {
    fn new(root_slot: u64) -> Self {
        let mut m = Self { slot_to_ino: HashMap::new(), ino_to_slot: HashMap::new(), next_ino: 2 };
        m.slot_to_ino.insert(root_slot, 1);
        m.ino_to_slot.insert(1, root_slot);
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
    fn slot_of(&self, ino: u64) -> Option<u64> { self.ino_to_slot.get(&ino).copied() }
    fn remove(&mut self, slot: u64) {
        if let Some(ino) = self.slot_to_ino.remove(&slot) { self.ino_to_slot.remove(&ino); }
    }
}

// ── Inner mutable state ───────────────────────────────────────────────────────

struct Inner {
    container:      Arc<VnmContainer>,
    inodes:         InodeMap,
    open_files:     HashMap<u64, OpenFile>,
    next_fh:        u64,
    pending_delete: HashSet<u64>, // slots marked delete-on-close
}

impl Inner {
    fn alloc_fh(&mut self) -> u64 {
        let fh = self.next_fh;
        self.next_fh = self.next_fh.wrapping_add(1).max(1);
        fh
    }

    fn slot_of_ino(&self, ino: u64) -> Option<u64> { self.inodes.slot_of(ino) }

    fn read_dir_block(&self, slot: u64) -> Option<DirectoryBlock> {
        match self.container.read_node(slot) {
            Ok(VaultNode::Directory(d)) => Some(d),
            _ => None,
        }
    }

    fn load_file_data(&self, f: &FileBlock) -> Vec<u8> {
        let mut data = f.data.clone();
        let mut next = f.next_slot;
        while let Some(s) = next {
            if let Ok(VaultNode::File(c)) = self.container.read_node(s) {
                data.extend_from_slice(&c.data);
                next = c.next_slot;
            } else { break; }
        }
        data.truncate(f.total_size as usize);
        data
    }

    fn persist_file_data(&self, first_slot: u64, existing: &FileBlock, new_data: Vec<u8>) {
        // Free old chain
        let mut next = existing.next_slot;
        while let Some(slot) = next {
            next = match self.container.read_node(slot) {
                Ok(VaultNode::File(c)) => { let n = c.next_slot; self.container.free_node(slot); n }
                _ => None,
            };
        }
        let total_size = new_data.len() as u64;
        let chunks: Vec<&[u8]> = new_data.chunks(FILE_DATA_CHUNK).collect();
        let mut tail: Option<u64> = None;
        for chunk in chunks.iter().skip(1).rev() {
            let node = VaultNode::File(FileBlock {
                kind: NodeKind::FileContinuation, total_size: 0, next_slot: tail, data: chunk.to_vec(),
            });
            if let Ok(s) = self.container.write_node(&node) { tail = Some(s); }
        }
        let first_data = chunks.first().map(|c| c.to_vec()).unwrap_or_default();
        let _ = self.container.update_node(first_slot, &VaultNode::File(FileBlock {
            kind: NodeKind::File, total_size, next_slot: tail, data: first_data,
        }));
    }

    fn flush_fh(&mut self, fh: u64) {
        let (slot, data, dirty) = match self.open_files.get(&fh) {
            Some(of) if of.dirty => (of.slot, of.data.clone(), true),
            _ => return,
        };
        if !dirty { return; }
        if let Ok(VaultNode::File(fb)) = self.container.read_node(slot) {
            self.persist_file_data(slot, &fb, data);
        }
        if let Some(of) = self.open_files.get_mut(&fh) { of.dirty = false; }
    }

    fn flush_all(&mut self) {
        let fhs: Vec<u64> = self.open_files.keys().copied().collect();
        for fh in fhs { self.flush_fh(fh); }
        let _ = self.container.flush();
    }

    /// Resolve a Windows path like `\subdir\file.txt` → (slot, node).
    /// Empty path or `\` → root.
    fn resolve(&mut self, path: &U16CStr) -> Result<(u64, VaultNode), FspError> {
        let path_str = path.to_string_lossy();
        let trimmed = path_str.trim_matches(|c| c == '\\' || c == '/');

        if trimmed.is_empty() {
            let root_slot = self.container.root_slot();
            let node = self.container.read_node(root_slot)
                .map_err(|_| FspError::ENOENT)?;
            self.inodes.get_or_alloc(root_slot);
            return Ok((root_slot, node));
        }

        let components: Vec<&str> = trimmed.split(|c| c == '\\' || c == '/').collect();
        let mut current = self.container.root_slot();

        for component in &components {
            let dir = self.container.read_node(current)
                .map_err(|_| FspError::ENOENT)?;
            let dir = match dir {
                VaultNode::Directory(d) => d,
                _ => return Err(FspError::from_win32(87)), // ERROR_INVALID_PARAMETER
            };
            let entry = dir.entries.iter()
                .find(|e| e.name.eq_ignore_ascii_case(component))
                .ok_or(FspError::ENOENT)?;
            current = entry.slot;
        }

        let node = self.container.read_node(current)
            .map_err(|_| FspError::ENOENT)?;
        self.inodes.get_or_alloc(current);
        Ok((current, node))
    }

    fn node_to_file_info(&self, slot: u64, node: &VaultNode, created_at: u64) -> FileInfo {
        let ts = unix_to_win_time(created_at);
        match node {
            VaultNode::Directory(_) => FileInfo {
                file_attributes: FILE_ATTRIBUTE_DIRECTORY,
                reparse_tag: 0,
                allocation_size: 0,
                file_size: 0,
                creation_time: ts,
                last_access_time: ts,
                last_write_time: ts,
                change_time: ts,
                index_number: slot,
                hard_links: 0,
                ea_size: 0,
            },
            VaultNode::File(f) => {
                let size = f.total_size;
                let alloc = (size + 4095) & !4095; // round up to 4 KB
                FileInfo {
                    file_attributes: FILE_ATTRIBUTE_ARCHIVE,
                    reparse_tag: 0,
                    allocation_size: alloc,
                    file_size: size,
                    creation_time: ts,
                    last_access_time: ts,
                    last_write_time: ts,
                    change_time: ts,
                    index_number: slot,
                    hard_links: 0,
                    ea_size: 0,
                }
            }
        }
    }
}

// ── VenomWinfsp ───────────────────────────────────────────────────────────────

pub struct VenomWinfsp {
    inner:      Mutex<Inner>,
    created_at: u64,
}

impl VenomWinfsp {
    pub fn new(container: Arc<VnmContainer>) -> Self {
        let root_slot  = container.root_slot();
        let created_at = container.created_at;
        Self {
            inner: Mutex::new(Inner {
                inodes:         InodeMap::new(root_slot),
                open_files:     HashMap::new(),
                next_fh:        1,
                pending_delete: HashSet::new(),
                container,
            }),
            created_at,
        }
    }
}

impl Drop for VenomWinfsp {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.flush_all();
        }
    }
}

// ── FileSystemContext implementation ──────────────────────────────────────────

impl FileSystemContext for VenomWinfsp {
    /// Per-open-handle context — we use our u64 fh.
    type FileContext = u64;

    // ── Required ─────────────────────────────────────────────────────────────

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity, FspError> {
        let mut inner = self.inner.lock().unwrap();
        let (slot, node) = inner.resolve(file_name)?;
        let attrs = match &node {
            VaultNode::Directory(_) => FILE_ATTRIBUTE_DIRECTORY,
            VaultNode::File(_)      => FILE_ATTRIBUTE_ARCHIVE,
        };
        Ok(FileSecurity {
            attributes: attrs,
            reparse: false,
            sz_security_descriptor: 0,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext, FspError> {
        let mut inner = self.inner.lock().unwrap();
        let (slot, node) = inner.resolve(file_name)?;
        let is_dir = matches!(node, VaultNode::Directory(_));

        let data = if is_dir {
            vec![]
        } else {
            if let VaultNode::File(ref f) = node { inner.load_file_data(f) } else { vec![] }
        };

        let ino = inner.inodes.get_or_alloc(slot);
        let fh = inner.alloc_fh();
        inner.open_files.insert(fh, OpenFile { slot, ino, data, dirty: false, is_dir });

        let fi = inner.node_to_file_info(slot, &node, self.created_at);
        file_info.set_file_info(fi);
        Ok(fh)
    }

    fn close(&self, file_context: Self::FileContext) {
        let mut inner = self.inner.lock().unwrap();
        inner.flush_fh(file_context);

        // Handle delete-on-close
        let slot = inner.open_files.get(&file_context).map(|f| f.slot);
        inner.open_files.remove(&file_context);

        if let Some(slot) = slot {
            if inner.pending_delete.remove(&slot) {
                // Actually delete the node from its parent directory
                // We traverse from root to find and remove it
                let _ = delete_slot_from_tree(&mut inner, slot);
            }
        }

        let _ = inner.container.flush();
    }

    // ── Optional ─────────────────────────────────────────────────────────────

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_attributes: u32,
        _security_descriptor: *mut c_void,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext, FspError> {
        let mut inner = self.inner.lock().unwrap();

        let path_str = file_name.to_string_lossy();
        let trimmed  = path_str.trim_matches(|c| c == '\\' || c == '/');
        let (parent_path, name) = split_path(trimmed);
        let name = name.to_string();

        // Resolve parent
        let parent_slot = if parent_path.is_empty() {
            inner.container.root_slot()
        } else {
            let parent_wcstr = widestring::U16CString::from_str_truncate(
                format!("\\{parent_path}")
            );
            let (slot, _) = inner.resolve(parent_wcstr.as_ucstr())?;
            slot
        };

        let is_dir = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || (create_options & 0x0000_0001) != 0; // FILE_DIRECTORY_FILE

        let new_node = if is_dir {
            VaultNode::Directory(DirectoryBlock { kind: NodeKind::Directory, entries: vec![] })
        } else {
            VaultNode::File(FileBlock { kind: NodeKind::File, total_size: 0, next_slot: None, data: vec![] })
        };

        let new_slot = inner.container.write_node(&new_node).map_err(|_| FspError::EIO)?;

        // Add to parent directory
        let mut parent_dir = inner.read_dir_block(parent_slot).ok_or(FspError::ENOENT)?;
        if parent_dir.entries.iter().any(|e| e.name.eq_ignore_ascii_case(&name)) {
            inner.container.free_node(new_slot);
            return Err(FspError::EEXIST);
        }
        parent_dir.entries.push(DirEntry {
            name: name.clone(),
            slot: new_slot,
            kind: if is_dir { NodeKind::Directory } else { NodeKind::File },
        });
        inner.container.update_node(parent_slot, &VaultNode::Directory(parent_dir))
            .map_err(|_| FspError::EIO)?;

        let ino = inner.inodes.get_or_alloc(new_slot);
        let fh  = inner.alloc_fh();
        inner.open_files.insert(fh, OpenFile {
            slot: new_slot, ino, data: vec![], dirty: false, is_dir,
        });

        let fi = inner.node_to_file_info(new_slot, &new_node, self.created_at);
        file_info.set_file_info(fi);
        Ok(fh)
    }

    fn cleanup(&self, file_context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        // FspCleanupDelete = 0x01
        if flags & 0x01 != 0 {
            let mut inner = self.inner.lock().unwrap();
            if let Some(of) = inner.open_files.get(file_context) {
                inner.pending_delete.insert(of.slot);
            }
        }
    }

    fn read(
        &self,
        file_context: &Self::FileContext,
        buffer:        &mut [u8],
        offset:        u64,
    ) -> Result<IoResult, FspError> {
        let inner = self.inner.lock().unwrap();
        let of = inner.open_files.get(file_context).ok_or(FspError::ENOENT)?;
        let start = (offset as usize).min(of.data.len());
        let end   = (start + buffer.len()).min(of.data.len());
        let n     = end - start;
        buffer[..n].copy_from_slice(&of.data[start..end]);
        Ok(IoResult { bytes_transferred: n as u32, io_pending: false })
    }

    fn write(
        &self,
        file_context:        &Self::FileContext,
        buffer:              &[u8],
        offset:              u64,
        write_to_end_of_file: bool,
        constrained_io:      bool,
        file_info:           &mut FileInfo,
    ) -> Result<IoResult, FspError> {
        let mut inner = self.inner.lock().unwrap();
        let of = inner.open_files.get_mut(file_context).ok_or(FspError::ENOENT)?;

        let actual_offset = if write_to_end_of_file { of.data.len() as u64 } else { offset };

        if constrained_io && actual_offset >= of.data.len() as u64 {
            // constrained_io: don't extend the file
            return Ok(IoResult { bytes_transferred: 0, io_pending: false });
        }

        let start = actual_offset as usize;
        let end   = start + buffer.len();
        if end > of.data.len() { of.data.resize(end, 0); }
        of.data[start..end].copy_from_slice(buffer);
        of.dirty = true;

        let slot = of.slot;
        let size = of.data.len() as u64;
        drop(inner); // release lock before building file_info

        let inner = self.inner.lock().unwrap();
        *file_info = inner.node_to_file_info(slot, &VaultNode::File(FileBlock {
            kind: NodeKind::File, total_size: size, next_slot: None, data: vec![],
        }), self.created_at);

        Ok(IoResult { bytes_transferred: buffer.len() as u32, io_pending: false })
    }

    fn flush(
        &self,
        file_context: Option<&Self::FileContext>,
        file_info:    &mut FileInfo,
    ) -> Result<(), FspError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(fh) = file_context {
            inner.flush_fh(*fh);
            if let Some(of) = inner.open_files.get(fh) {
                let slot = of.slot;
                let size = of.data.len() as u64;
                *file_info = inner.node_to_file_info(slot, &VaultNode::File(FileBlock {
                    kind: NodeKind::File, total_size: size, next_slot: None, data: vec![],
                }), self.created_at);
            }
        } else {
            inner.flush_all();
        }
        Ok(())
    }

    fn get_file_info(
        &self,
        file_context: &Self::FileContext,
        file_info:    &mut FileInfo,
    ) -> Result<(), FspError> {
        let inner = self.inner.lock().unwrap();
        let of = inner.open_files.get(file_context).ok_or(FspError::ENOENT)?;
        let slot = of.slot;
        let size = if of.is_dir { 0 } else { of.data.len() as u64 };
        *file_info = if of.is_dir {
            inner.node_to_file_info(slot, &VaultNode::Directory(DirectoryBlock {
                kind: NodeKind::Directory, entries: vec![],
            }), self.created_at)
        } else {
            inner.node_to_file_info(slot, &VaultNode::File(FileBlock {
                kind: NodeKind::File, total_size: size, next_slot: None, data: vec![],
            }), self.created_at)
        };
        Ok(())
    }

    fn set_basic_info(
        &self,
        file_context:    &Self::FileContext,
        _file_attributes: u32,
        _creation_time:   u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _last_change_time: u64,
        file_info:        &mut FileInfo,
    ) -> Result<(), FspError> {
        // Timestamps not stored — just return current info
        self.get_file_info(file_context, file_info)
    }

    fn set_file_size(
        &self,
        file_context:       &Self::FileContext,
        new_size:           u64,
        set_allocation_size: bool,
        file_info:          &mut FileInfo,
    ) -> Result<(), FspError> {
        if set_allocation_size { return self.get_file_info(file_context, file_info); }
        let mut inner = self.inner.lock().unwrap();
        let of = inner.open_files.get_mut(file_context).ok_or(FspError::ENOENT)?;
        of.data.resize(new_size as usize, 0);
        of.dirty = true;
        let slot = of.slot;
        *file_info = inner.node_to_file_info(slot, &VaultNode::File(FileBlock {
            kind: NodeKind::File, total_size: new_size, next_slot: None, data: vec![],
        }), self.created_at);
        Ok(())
    }

    fn set_delete(
        &self,
        file_context: &Self::FileContext,
        _file_name:   &U16CStr,
        delete_file:  bool,
    ) -> Result<(), FspError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(of) = inner.open_files.get(file_context) {
            let slot = of.slot;
            if delete_file {
                inner.pending_delete.insert(slot);
            } else {
                inner.pending_delete.remove(&slot);
            }
        }
        Ok(())
    }

    fn rename(
        &self,
        _file_context:   &Self::FileContext,
        file_name:       &U16CStr,
        new_file_name:   &U16CStr,
        replace_if_exists: bool,
    ) -> Result<(), FspError> {
        let mut inner = self.inner.lock().unwrap();

        let (slot, node) = inner.resolve(file_name)?;
        let kind = match &node { VaultNode::Directory(_) => NodeKind::Directory, _ => NodeKind::File };

        // Remove from old parent
        let old_path = file_name.to_string_lossy();
        let old_trimmed = old_path.trim_matches(|c| c == '\\' || c == '/');
        let (old_parent_path, old_name) = split_path(old_trimmed);
        let old_parent_slot = resolve_slot(&mut inner, old_parent_path)?;
        let mut old_parent = inner.read_dir_block(old_parent_slot).ok_or(FspError::ENOENT)?;
        old_parent.entries.retain(|e| !e.name.eq_ignore_ascii_case(old_name));
        inner.container.update_node(old_parent_slot, &VaultNode::Directory(old_parent))
            .map_err(|_| FspError::EIO)?;

        // Add to new parent
        let new_path = new_file_name.to_string_lossy();
        let new_trimmed = new_path.trim_matches(|c| c == '\\' || c == '/');
        let (new_parent_path, new_name) = split_path(new_trimmed);
        let new_parent_slot = resolve_slot(&mut inner, new_parent_path)?;
        let mut new_parent = inner.read_dir_block(new_parent_slot).ok_or(FspError::ENOENT)?;

        if let Some(pos) = new_parent.entries.iter().position(|e| e.name.eq_ignore_ascii_case(new_name)) {
            if !replace_if_exists { return Err(FspError::EEXIST); }
            let old_slot = new_parent.entries.remove(pos).slot;
            inner.container.free_node(old_slot);
            inner.inodes.remove(old_slot);
        }
        new_parent.entries.push(DirEntry { name: new_name.to_string(), slot, kind });
        inner.container.update_node(new_parent_slot, &VaultNode::Directory(new_parent))
            .map_err(|_| FspError::EIO)?;

        Ok(())
    }

    fn get_volume_info(&self, volume_info: &mut VolumeInfo) -> Result<(), FspError> {
        let inner = self.inner.lock().unwrap();
        let free  = inner.container.store.free.lock().unwrap().len() as u64;
        let total = inner.container.outer_limit;
        let slot_size = crate::container::SLOT_SIZE as u64;

        volume_info.total_size      = total * slot_size;
        volume_info.free_size       = free  * slot_size;
        volume_info.volume_label    = "Venom".to_string();
        Ok(())
    }

    fn read_directory(
        &self,
        file_context: &Self::FileContext,
        pattern:      Option<&U16CStr>,
        marker:       Option<&U16CStr>,
        buffer:       &mut Vec<u8>,
    ) -> Result<u32, FspError> {
        let inner = self.inner.lock().unwrap();
        let of = inner.open_files.get(file_context).ok_or(FspError::ENOENT)?;
        if !of.is_dir { return Err(FspError::ENOTDIR); }

        let slot = of.slot;
        let dir  = inner.read_dir_block(slot).ok_or(FspError::ENOENT)?;

        let marker_str = marker.map(|m| m.to_string_lossy().to_string());
        let mut past_marker = marker_str.is_none();

        let mut added = 0u32;

        for entry in &dir.entries {
            if !past_marker {
                if let Some(ref m) = marker_str {
                    if entry.name.eq_ignore_ascii_case(m) { past_marker = true; }
                }
                continue;
            }

            if let Some(pat) = pattern {
                let pat_str = pat.to_string_lossy();
                if !pat_str.is_empty() && pat_str != "*"
                    && !entry.name.eq_ignore_ascii_case(&pat_str.trim_matches('*').to_string())
                {
                    continue;
                }
            }

            let child_node = match inner.container.read_node(entry.slot) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let fi = inner.node_to_file_info(entry.slot, &child_node, self.created_at);
            let dir_info = DirInfo::new(&entry.name, fi);
            if !dir_info.write_to_buffer(buffer) { break; }
            added += 1;
        }

        Ok(added)
    }

    fn get_security(
        &self,
        _file_context:        &Self::FileContext,
        security_descriptor:  Option<&mut [c_void]>,
    ) -> Result<u64, FspError> {
        // Return an empty security descriptor size (no custom ACLs)
        Ok(0)
    }
}

// ── Helper functions ──────────────────────────────────────────────────────────

/// Split a path like `"subdir\\file.txt"` into `("subdir", "file.txt")`.
fn split_path(path: &str) -> (&str, &str) {
    match path.rfind(|c| c == '\\' || c == '/') {
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None      => ("", path),
    }
}

/// Resolve a plain path string (no leading slash) to a slot.
fn resolve_slot(inner: &mut Inner, path: &str) -> Result<u64, FspError> {
    if path.is_empty() { return Ok(inner.container.root_slot()); }
    let wcstr = widestring::U16CString::from_str_truncate(format!("\\{path}"));
    let (slot, _) = inner.resolve(wcstr.as_ucstr())?;
    Ok(slot)
}

/// Walk the tree from root to find and remove `target_slot` from its parent.
fn delete_slot_from_tree(inner: &mut Inner, target_slot: u64) -> Result<(), ()> {
    fn walk(inner: &mut Inner, dir_slot: u64, target: u64) -> bool {
        let dir = match inner.container.read_node(dir_slot) {
            Ok(VaultNode::Directory(d)) => d,
            _ => return false,
        };
        if let Some(pos) = dir.entries.iter().position(|e| e.slot == target) {
            let mut updated = dir.clone();
            updated.entries.remove(pos);
            let _ = inner.container.update_node(dir_slot, &VaultNode::Directory(updated));
            // Free the deleted node + its file chain
            if let Ok(VaultNode::File(f)) = inner.container.read_node(target) {
                let mut next = f.next_slot;
                while let Some(s) = next {
                    next = match inner.container.read_node(s) {
                        Ok(VaultNode::File(c)) => { let n = c.next_slot; inner.container.free_node(s); n }
                        _ => None,
                    };
                }
            }
            inner.container.free_node(target);
            inner.inodes.remove(target);
            return true;
        }
        // Recurse into subdirectories
        for entry in &dir.entries.clone() {
            if matches!(entry.kind, NodeKind::Directory) {
                if walk(inner, entry.slot, target) { return true; }
            }
        }
        false
    }

    let root = inner.container.root_slot();
    if walk(inner, root, target_slot) { Ok(()) } else { Err(()) }
}

// ── Public mount function ─────────────────────────────────────────────────────

/// Mount `container` at `mountpoint` (drive letter like `V:` or empty directory).
/// Blocks until the filesystem is dismounted.
pub fn mount(container: Arc<VnmContainer>, mountpoint: &str) -> crate::Result<()> {
    let fs = VenomWinfsp::new(container);

    let mut params = FileSystemParams::default();
    params.sector_size             = 512;
    params.sectors_per_allocation  = 1;
    params.max_component_length    = 255;
    params.volume_creation_time    = now_win_time();
    params.volume_serial_number    = 0x56454E4D; // "VENM"
    params.file_info_timeout       = 1000;
    params.case_sensitive_search   = false;
    params.case_preserved_names    = true;
    params.unicode_on_disk         = true;
    params.persistent_acls         = false;
    params.post_cleanup_when_modified_only = true;
    params.volume_prefix           = String::new();
    params.file_system_name        = "Venom".to_string();

    let host = FileSystem::new(params, fs)
        .map_err(|e| VnmError::InvalidFormat(format!("WinFSP init: {e}")))?;

    host.mount(mountpoint)
        .map_err(|e| VnmError::Io(std::io::Error::other(format!("WinFSP mount: {e}"))))?;

    host.wait(); // blocks until dismounted
    Ok(())
}
