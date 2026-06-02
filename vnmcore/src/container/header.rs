//! On-disk container header — version 3.
//!
//! ## Layout (512 bytes)
//!
//!   [0..64]    salt (64 bytes, plaintext — for Argon2id / key derivation)
//!   [64]       cipher_id (0=ChaCha20-Poly1305, 1=AES-256-GCM)
//!   [65]       kdf_profile_id (0=interactive, 1=sensitive)
//!   [66]       num_password_slots (u8, plaintext — max MAX_PASSWORD_SLOTS)
//!   [67]       num_key_slots (u8, plaintext — max MAX_KEY_SLOTS)
//!   [68..80]   nonce (12 bytes, for AEAD below)
//!   [80..512]  encrypt_block(K_master, cipher, AAD, header_body)
//!              = 36 (VNMB) + 396 (body) + 16 (tag) = 448 bytes — fits in 432 bytes?
//!              Let's compute: 512 - 80 = 432 bytes available for encrypted block.
//!              encrypt_block output = 20 + plaintext + 16 tag = 36 + plaintext.
//!              max plaintext = 432 - 36 = 396 bytes.
//!              Header body = 396 bytes.
//!
//! ## Header body plaintext (396 bytes)
//!
//!   [0..4]    magic "VNM3"
//!   [4..8]    version u32 LE = 3
//!   [8..16]   data_area_offset u64 LE (fixed: HEADER_REGION + RECIPIENT_AREA_SIZE)
//!   [16..24]  outer_slots u64 LE
//!             outer: number of outer-only data slots (claimed as full capacity)
//!             hidden: number of hidden data slots
//!   [24..32]  hidden_start u64 LE (outer: 0; hidden: first slot index of hidden volume)
//!   [32..40]  root_slot u64 LE
//!   [40..48]  created_at u64 LE
//!   [48..112] label [u8; 64]
//!   [112..396] reserved [u8; 284]
//!
//! ## Header positions
//!
//!   Outer header:  byte 0
//!   Hidden header: file_end - 512 (or random bytes if no hidden volume)
//!
//! ## Recipient area (immediately after HEADER_REGION_SIZE = 1024)
//!
//!   [1024 .. 1024 + MAX_PASSWORD_SLOTS * PW_SLOT_SIZE]   password slots
//!   [... .. ... + MAX_KEY_SLOTS * KEY_SLOT_SIZE]          ML-KEM slots
//!   DATA_AREA_OFFSET = 1024 + RECIPIENT_AREA_SIZE         first data slot

use rand::RngCore;
use zeroize::Zeroize;

use crate::{Result, VnmError};
use crate::container::{CipherAlgorithm, kdf_params_for_profile};
use crate::crypto::{derive_key, encrypt_block, decrypt_block};

pub const HEADER_SIZE:        usize = 512;
pub const HEADER_REGION_SIZE: u64   = 1024;
pub const SLOT_SIZE:          usize = 32_768;

// Recipient area constants (fixed layout — no need to move data when adding/removing recipients)
pub const MAX_PASSWORD_SLOTS: usize = 8;
pub const MAX_KEY_SLOTS:      usize = 8;
pub const PW_SLOT_SIZE:       usize = super::recipient::PW_SLOT_SIZE;   // 101
pub const KEY_SLOT_SIZE:      usize = super::recipient::KEY_SLOT_SIZE;  // 1644
pub const RECIPIENT_AREA_SIZE: usize = MAX_PASSWORD_SLOTS * PW_SLOT_SIZE + MAX_KEY_SLOTS * KEY_SLOT_SIZE;
// = 8 * 101 + 8 * 1644 = 808 + 13152 = 13960

/// Byte offset where slot 0 starts.
pub const DATA_AREA_OFFSET: u64 = HEADER_REGION_SIZE + RECIPIENT_AREA_SIZE as u64;
// = 1024 + 13960 = 14984

pub const MAGIC:          &[u8; 4] = b"VNM3";
pub const FORMAT_VERSION: u32      = 3;

const SALT_LEN:     usize = 64;
const BODY_OFFSET:  usize = 68;   // after salt(64) + cipher(1) + profile(1) + n_pw(1) + n_key(1) = 68
const BODY_PLAINTEXT: usize = 396; // = 512 - 68 - 36 (VNMB) = 408? let me recount

// encrypt_block output = 4(magic)+4(ver)+12(nonce)+plaintext+16(tag) = 36+plaintext
// Available: 512 - 68 = 444 bytes for the encrypted block output
// → max plaintext = 444 - 36 = 408 bytes
// We use 396 bytes plaintext (body) → output = 432 bytes ✓ (fits in 444)
pub(crate) const BODY_LEN: usize = 396;
/// Size of the VNMB-encrypted header body on disk (36 VNMB header + 396 plaintext + 16 tag).
pub(crate) const ENC_BODY_SIZE: usize = 36 + BODY_LEN; // = 432

const AAD_OUTER:  &[u8] = b"vnm:header:outer:v3";
const AAD_HIDDEN: &[u8] = b"vnm:header:hidden:v3";

/// Decoded header metadata.
#[derive(Clone)]
pub struct HeaderPayload {
    pub cipher:            CipherAlgorithm,
    pub kdf_profile:       u8,
    pub num_password_slots: u8,
    pub num_key_slots:     u8,
    /// outer: outer-only slot count; hidden: hidden slot count.
    pub outer_slots:       u64,
    /// outer: 0; hidden: first slot index of the hidden volume.
    pub hidden_start:      u64,
    pub root_slot:         u64,
    pub created_at:        u64,
    pub label:             [u8; 64],
}

/// Encode + encrypt a container header with K_master.
pub fn encode_header(
    payload:   &HeaderPayload,
    k_master:  &[u8; 32],
    is_hidden: bool,
) -> Result<[u8; HEADER_SIZE]> {
    let mut buf = [0u8; HEADER_SIZE];

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    buf[0..SALT_LEN].copy_from_slice(&salt);

    buf[64] = payload.cipher as u8;
    buf[65] = payload.kdf_profile;
    buf[66] = payload.num_password_slots;
    buf[67] = payload.num_key_slots;

    let mut body = [0u8; BODY_LEN];
    body[0..4].copy_from_slice(MAGIC);
    body[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    body[8..16].copy_from_slice(&DATA_AREA_OFFSET.to_le_bytes());
    body[16..24].copy_from_slice(&payload.outer_slots.to_le_bytes());
    body[24..32].copy_from_slice(&payload.hidden_start.to_le_bytes());
    body[32..40].copy_from_slice(&payload.root_slot.to_le_bytes());
    body[40..48].copy_from_slice(&payload.created_at.to_le_bytes());
    body[48..112].copy_from_slice(&payload.label);
    // [112..396] reserved zeros

    // AAD includes the salt to bind the ciphertext to this specific container
    let aad = if is_hidden { AAD_HIDDEN } else { AAD_OUTER };
    let enc = encrypt_block(k_master, payload.cipher, aad, &body)?;
    buf[BODY_OFFSET..BODY_OFFSET + enc.len()].copy_from_slice(&enc);

    Ok(buf)
}

/// Decrypt a 512-byte header with K_master.
pub fn decode_header(
    raw:       &[u8; HEADER_SIZE],
    k_master:  &[u8; 32],
    is_hidden: bool,
) -> Result<HeaderPayload> {
    let cipher_id  = raw[64];
    let kdf_profile = raw[65];
    let num_pw     = raw[66];
    let num_key    = raw[67];

    let cipher = match cipher_id {
        0 => CipherAlgorithm::ChaCha20Poly1305,
        1 => CipherAlgorithm::Aes256Gcm,
        _ => return Err(VnmError::InvalidFormat(format!("unknown cipher {cipher_id}"))),
    };

    let aad  = if is_hidden { AAD_HIDDEN } else { AAD_OUTER };
    // Pass exactly the encrypted blob bytes — not the full tail — so the AEAD tag is at the right position.
    let body = decrypt_block(k_master, cipher, aad, &raw[BODY_OFFSET..BODY_OFFSET + ENC_BODY_SIZE])
        .map_err(|_| VnmError::AuthenticationFailed)?;

    if body.len() < 112 { return Err(VnmError::InvalidFormat("header body too short".into())); }
    if &body[0..4] != MAGIC { return Err(VnmError::AuthenticationFailed); }

    let outer_slots  = u64::from_le_bytes(body[16..24].try_into().unwrap());
    let hidden_start = u64::from_le_bytes(body[24..32].try_into().unwrap());
    let root_slot    = u64::from_le_bytes(body[32..40].try_into().unwrap());
    let created_at   = u64::from_le_bytes(body[40..48].try_into().unwrap());
    let mut label    = [0u8; 64];
    label.copy_from_slice(&body[48..112]);

    Ok(HeaderPayload { cipher, kdf_profile, num_password_slots: num_pw, num_key_slots: num_key,
        outer_slots, hidden_start, root_slot, created_at, label })
}

/// Read plaintext fields from a raw header (cipher, kdf_profile, slot counts).
/// Used to know how many recipient slots to read before we have K_master.
pub fn read_header_plaintext(raw: &[u8; HEADER_SIZE]) -> (CipherAlgorithm, u8, u8, u8) {
    let cipher = match raw[64] {
        1 => CipherAlgorithm::Aes256Gcm,
        _ => CipherAlgorithm::ChaCha20Poly1305,
    };
    (cipher, raw[65], raw[66], raw[67])
}

/// Hardcoded Argon2id parameters per profile ID.
pub fn kdf_params_for_profile_id(profile_id: u8) -> crate::container::KdfParams {
    kdf_params_for_profile(
        if profile_id == 1 { "sensitive" } else { "interactive" }
    )
}
