mod header;

pub use header::{
    HeaderPayload, HEADER_SIZE, HEADER_REGION_SIZE, SLOT_SIZE,
    encode_header_with_password, decode_header,
    kdf_params_for_profile, profile_id_for_str,
};

use serde::{Deserialize, Serialize};

/// Symmetric cipher for slot encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherAlgorithm {
    ChaCha20Poly1305 = 0,
    Aes256Gcm        = 1,
}

impl CipherAlgorithm {
    pub fn key_len(self)   -> usize { 32 }
    pub fn nonce_len(self) -> usize { 12 }
    pub fn tag_len(self)   -> usize { 16 }

    pub fn as_str(self) -> &'static str {
        match self {
            CipherAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305",
            CipherAlgorithm::Aes256Gcm        => "aes-256-gcm",
        }
    }
}

impl std::fmt::Display for CipherAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Argon2id parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib:  u32,
    pub iterations:  u32,
    pub parallelism: u32,
    /// 32-byte salt, hex-encoded.
    pub salt: String,
}

impl KdfParams {
    pub fn interactive() -> Self {
        Self { memory_kib: 65536, iterations: 3, parallelism: 4, salt: String::new() }
    }
    pub fn sensitive() -> Self {
        Self { memory_kib: 262144, iterations: 4, parallelism: 4, salt: String::new() }
    }
}
