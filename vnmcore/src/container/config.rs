use serde::{Deserialize, Serialize};

/// Cipher algorithm for block encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherAlgorithm {
    /// ChaCha20-Poly1305 (256-bit key, 96-bit nonce)
    ChaCha20Poly1305,
    /// AES-256-GCM (256-bit key, 96-bit nonce)
    Aes256Gcm,
}

impl CipherAlgorithm {
    pub fn key_len(&self) -> usize {
        32 // both use 256-bit keys
    }

    pub fn nonce_len(&self) -> usize {
        12 // both use 96-bit nonces
    }

    pub fn tag_len(&self) -> usize {
        16 // both produce 128-bit auth tags
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CipherAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305",
            CipherAlgorithm::Aes256Gcm => "aes-256-gcm",
        }
    }
}

impl std::fmt::Display for CipherAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Argon2id KDF parameters stored in vault config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    /// 32-byte random salt (hex-encoded)
    pub salt: String,
}

impl KdfParams {
    /// Interactive profile — fast unlock, suitable for desktop use
    pub fn interactive() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB
            iterations: 3,
            parallelism: 4,
            salt: String::new(), // filled at creation
        }
    }

    /// Sensitive profile — slower, higher security
    pub fn sensitive() -> Self {
        Self {
            memory_kib: 262144, // 256 MiB
            iterations: 4,
            parallelism: 4,
            salt: String::new(),
        }
    }
}

/// Vault configuration stored in `<vault_dir>/vnm_config.json` (encrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Format version for future compatibility
    pub version: u32,
    pub cipher: CipherAlgorithm,
    pub kdf: KdfParams,
    /// Block size in bytes (default 32768 = 32 KiB)
    pub block_size: usize,
    /// UUID of the root directory block
    pub root_block_id: String,
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Optional human-readable vault label
    pub label: Option<String>,
}

impl VaultConfig {
    pub const FILE_NAME: &'static str = "vnm_config.json";
    pub const FORMAT_VERSION: u32 = 1;
    pub const DEFAULT_BLOCK_SIZE: usize = 32768;
}
