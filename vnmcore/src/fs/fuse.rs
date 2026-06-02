//! FUSE filesystem adapter — mounts a Vault as a standard directory.
//!
//! Inode layout: root directory is always inode 1. Each block UUID is hashed
//! to a u64 inode on first access and cached in memory.

#[cfg(feature = "fuse")]
pub mod driver {
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, UNIX_EPOCH};

    use fuser::{
        FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData,
        ReplyDirectory, ReplyEntry, Request,
    };
    use libc::{ENOENT, ENOTDIR, EISDIR, EIO};

    use crate::fs::vault::Vault;
    use crate::storage::{VaultNode, NodeKind};
    use crate::VnmError;

    const TTL: Duration = Duration::from_secs(1);
    const ROOT_INO: u64 = 1;

    struct InodeMap {
        /// block_id → inode
        id_to_ino: HashMap<String, u64>,
        /// inode → block_id
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
            self.ino_to_id.get(&ino).map(|s| s.as_str())
        }
    }

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

        fn node_attr(&self, ino: u64, node: &VaultNode) -> FileAttr {
            let ts = UNIX_EPOCH;
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
                    uid: unsafe { libc::getuid() },
                    gid: unsafe { libc::getgid() },
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
                    uid: unsafe { libc::getuid() },
                    gid: unsafe { libc::getgid() },
                    rdev: 0,
                    blksize: 4096,
                    flags: 0,
                },
            }
        }
    }

    impl Filesystem for VenomFuse {
        fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
            let name = match name.to_str() {
                Some(n) => n,
                None => { reply.error(ENOENT); return; }
            };

            let parent_id = {
                let map = self.inodes.read().unwrap();
                match map.block_id(parent) {
                    Some(id) => id.to_string(),
                    None => { reply.error(ENOENT); return; }
                }
            };

            let node = match self.vault.read_node(&parent_id) {
                Ok(n) => n,
                Err(_) => { reply.error(EIO); return; }
            };

            let dir = match &node {
                VaultNode::Directory(d) => d,
                _ => { reply.error(ENOTDIR); return; }
            };

            let entry = dir.entries.iter().find(|e| e.name == name);
            match entry {
                Some(e) => {
                    let child_id = e.block_id.clone();
                    let child_node = match self.vault.read_node(&child_id) {
                        Ok(n) => n,
                        Err(_) => { reply.error(EIO); return; }
                    };
                    let ino = self.inodes.write().unwrap().get_or_alloc(&child_id);
                    let attr = self.node_attr(ino, &child_node);
                    reply.entry(&TTL, &attr, 0);
                }
                None => reply.error(ENOENT),
            }
        }

        fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
            let block_id = {
                let map = self.inodes.read().unwrap();
                match map.block_id(ino) {
                    Some(id) => id.to_string(),
                    None => { reply.error(ENOENT); return; }
                }
            };

            match self.vault.read_node(&block_id) {
                Ok(node) => {
                    let attr = self.node_attr(ino, &node);
                    reply.attr(&TTL, &attr);
                }
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
            let block_id = {
                let map = self.inodes.read().unwrap();
                match map.block_id(ino) {
                    Some(id) => id.to_string(),
                    None => { reply.error(ENOENT); return; }
                }
            };

            let node = match self.vault.read_node(&block_id) {
                Ok(n) => n,
                Err(_) => { reply.error(EIO); return; }
            };

            let dir = match &node {
                VaultNode::Directory(d) => d.clone(),
                _ => { reply.error(ENOTDIR); return; }
            };

            let mut entries: Vec<(u64, FileType, String)> = vec![
                (ino, FileType::Directory, ".".into()),
                (ino, FileType::Directory, "..".into()),
            ];

            for e in &dir.entries {
                let child_ino = self.inodes.write().unwrap().get_or_alloc(&e.block_id);
                let ft = match e.kind {
                    NodeKind::Directory => FileType::Directory,
                    _ => FileType::RegularFile,
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

        fn read(
            &mut self,
            _req: &Request,
            ino: u64,
            _fh: u64,
            offset: i64,
            size: u32,
            _flags: i32,
            _lock: Option<u64>,
            reply: ReplyData,
        ) {
            let block_id = {
                let map = self.inodes.read().unwrap();
                match map.block_id(ino) {
                    Some(id) => id.to_string(),
                    None => { reply.error(ENOENT); return; }
                }
            };

            let node = match self.vault.read_node(&block_id) {
                Ok(n) => n,
                Err(_) => { reply.error(EIO); return; }
            };

            match node {
                VaultNode::File(f) => {
                    // Assemble full file data from inline + continuations
                    let mut data = f.data.clone();
                    for cont_id in &f.continuation_ids {
                        match self.vault.read_node(cont_id) {
                            Ok(VaultNode::File(c)) => data.extend_from_slice(&c.data),
                            _ => { reply.error(EIO); return; }
                        }
                    }
                    data.truncate(f.total_size as usize);

                    let start = (offset as usize).min(data.len());
                    let end = (start + size as usize).min(data.len());
                    reply.data(&data[start..end]);
                }
                _ => reply.error(EISDIR),
            }
        }
    }

    /// Mount `vault` at `mountpoint` in the foreground (blocks until unmounted).
    pub fn mount(vault: Arc<Vault>, mountpoint: &str) -> crate::Result<()> {
        let fs = VenomFuse::new(vault);
        let options = vec![
            MountOption::RO,
            MountOption::FSName("venom".into()),
            MountOption::AutoUnmount,
        ];
        fuser::mount2(fs, mountpoint, &options)
            .map_err(|e| VnmError::Io(e))
    }
}
