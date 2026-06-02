use std::path::{Path, PathBuf};
use uuid::Uuid;
use crate::{Result, VnmError};
use crate::container::CipherAlgorithm;
use crate::crypto::{encrypt_block, decrypt_block};

/// Manages encrypted block files on disk.
///
/// Blocks are stored as `<vault_root>/<xx>/<uuid_rest>.blk`
/// where `xx` is the first two hex chars of the UUID — limits
/// directory entry count in large vaults.
pub struct BlockStore {
    root: PathBuf,
    key: [u8; 32],
    cipher: CipherAlgorithm,
}

impl BlockStore {
    pub fn new(root: impl AsRef<Path>, key: [u8; 32], cipher: CipherAlgorithm) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            key,
            cipher,
        }
    }

    /// Read and decrypt a block by its UUID string.
    pub fn read(&self, id: &str) -> Result<Vec<u8>> {
        let path = self.block_path(id);
        let data = std::fs::read(&path)
            .map_err(|_| VnmError::BlockNotFound(id.to_string()))?;
        let id_bytes = id.as_bytes();
        decrypt_block(&self.key, self.cipher, id_bytes, &data)
    }

    /// Encrypt and write a block. Returns the UUID used.
    pub fn write(&self, id: &str, plaintext: &[u8]) -> Result<()> {
        let path = self.block_path(id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let id_bytes = id.as_bytes();
        let encrypted = encrypt_block(&self.key, self.cipher, id_bytes, plaintext)?;
        std::fs::write(&path, encrypted)?;
        Ok(())
    }

    /// Create a new block with a fresh UUID, encrypt and write it.
    pub fn create(&self, plaintext: &[u8]) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        self.write(&id, plaintext)?;
        Ok(id)
    }

    /// Delete a block file.
    pub fn delete(&self, id: &str) -> Result<()> {
        let path = self.block_path(id);
        std::fs::remove_file(&path)
            .map_err(|_| VnmError::BlockNotFound(id.to_string()))
    }

    /// Check whether a block exists on disk.
    pub fn exists(&self, id: &str) -> bool {
        self.block_path(id).exists()
    }

    fn block_path(&self, id: &str) -> PathBuf {
        // Use first two chars of UUID as bucket directory
        let prefix = &id[..2.min(id.len())];
        self.root.join("blocks").join(prefix).join(format!("{id}.blk"))
    }
}
