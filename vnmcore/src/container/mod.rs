pub mod header;
pub mod recipient;

pub use header::{
    HeaderPayload, HEADER_SIZE, HEADER_REGION_SIZE, SLOT_SIZE, DATA_AREA_OFFSET,
    MAX_PASSWORD_SLOTS, MAX_KEY_SLOTS, PW_SLOT_SIZE, KEY_SLOT_SIZE, RECIPIENT_AREA_SIZE,
    encode_header, decode_header, read_header_plaintext, kdf_params_for_profile_id,
};
pub use recipient::{
    encode_password_slot, try_password_slot,
    encode_key_slot, try_key_slot,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherAlgorithm {
    XChaCha20Poly1305 = 0,
    /// Deoxys-II-256 standalone AEAD (256-bit key, 15-byte nonce)
    DeoxysII256       = 1,
    /// Serpent-256-EAX (CTR + OMAC, 16-byte nonce + 16-byte tag)
    Serpent256        = 2,
    /// XChaCha20-Poly1305 → Deoxys-II-256 → Serpent-256-CTR + HMAC-SHA256
    Triple            = 3,
}

impl CipherAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            CipherAlgorithm::XChaCha20Poly1305 => "xchacha20-poly1305",
            CipherAlgorithm::DeoxysII256       => "deoxys-ii-256",
            CipherAlgorithm::Serpent256        => "serpent-256-eax",
            CipherAlgorithm::Triple            => "triple-xchacha20-deoxys-serpent",
        }
    }
}

impl std::fmt::Display for CipherAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib:  u32,
    pub iterations:  u32,
    pub parallelism: u32,
    pub salt: String,
}

impl KdfParams {
    pub fn interactive() -> Self {
        Self { memory_kib: 65_536, iterations: 3, parallelism: 4, salt: String::new() }
    }
    pub fn sensitive() -> Self {
        Self { memory_kib: 262_144, iterations: 4, parallelism: 4, salt: String::new() }
    }
}

pub fn kdf_params_for_profile(profile: &str) -> KdfParams {
    if profile == "sensitive" { KdfParams::sensitive() } else { KdfParams::interactive() }
}

pub fn profile_id_for_str(profile: &str) -> u8 {
    if profile == "sensitive" { 1 } else { 0 }
}
