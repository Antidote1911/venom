//! On-disk header format for Venom containers — version 2.
//!
//! ## Layout (512 bytes per header)
//!
//!   [0..64]    Salt — 64 random bytes, stored in plaintext.
//!              Needed to derive the header decryption key before decryption.
//!   [64]       cipher_id — 0 = ChaCha20-Poly1305, 1 = AES-256-GCM
//!   [65]       kdf_profile — 0 = interactive, 1 = sensitive
//!              Stores only a profile ID; exact Argon2id parameters are
//!              hardcoded per profile and NOT exposed in plaintext.
//!   [66..78]   reserved (12 random bytes — padding, not interpreted)
//!   [78..90]   nonce — 12 bytes for the AEAD below
//!   [90..512]  encrypted body — 406 bytes plaintext + 16-byte AEAD tag
//!
//! ## Header positions in the file
//!
//!   Byte 0     : outer header (always present)
//!   file_end−512 : hidden header (or random bytes if no hidden volume)
//!
//! Keeping the hidden header at the END of the file (rather than at a fixed
//! offset like 512) means an attacker cannot prove a hidden volume exists
//! by inspecting a known offset.
//!
//! ## Encrypted body plaintext (406 bytes)
//!
//!   [0..4]    magic   b"VNM2"  (version 2)
//!   [4..8]    version u32 LE
//!   [8..40]   master_key [u8; 32]
//!   [40..48]  total_slots u64 LE
//!             outer: number of outer-only slots (does NOT include hidden slots)
//!             hidden: number of hidden slots
//!   [48..56]  hidden_start u64 LE
//!             outer: 0 (unused)
//!             hidden: first slot index belonging to hidden volume
//!   [56..64]  root_slot u64 LE
//!   [64..72]  created_at u64 LE (Unix seconds)
//!   [72..136] label [u8; 64] (UTF-8, null-padded)
//!   [136..406] reserved [u8; 270]
//!
//! ## AAD
//!   outer  header: b"vnm:outer:v2"
//!   hidden header: b"vnm:hidden:v2"

use rand::RngCore;
use zeroize::Zeroize;

use crate::{Result, VnmError};
use crate::container::{CipherAlgorithm, KdfParams};
use crate::crypto::{derive_key, encrypt_block, decrypt_block};

pub const HEADER_SIZE:        usize = 512;
pub const HEADER_REGION_SIZE: u64   = 1024; // offset 0-511 = outer; 512-1023 = random/reserved
pub const SLOT_SIZE:          usize = 32_768;

pub const MAGIC:          &[u8; 4] = b"VNM2";
pub const FORMAT_VERSION: u32      = 2;

const SALT_LEN:    usize = 64;  // was 32 — now 64 to match VeraCrypt
const NONCE_OFFSET:usize = 78;
const BODY_OFFSET: usize = 90;
const BODY_SIZE:   usize = 406; // plaintext bytes in body (= 512 - 90 - 16 tag)

const AAD_OUTER:  &[u8] = b"vnm:outer:v2";
const AAD_HIDDEN: &[u8] = b"vnm:hidden:v2";

/// Hardcoded Argon2id parameters per profile.
/// Stored as an opaque 1-byte profile ID in the header — exact values are
/// NOT exposed in plaintext, reducing an attacker's brute-force efficiency.
pub fn kdf_params_for_profile(profile_id: u8) -> KdfParams {
    match profile_id {
        1 => KdfParams { memory_kib: 262_144, iterations: 4, parallelism: 4, salt: String::new() },
        _ => KdfParams { memory_kib:  65_536, iterations: 3, parallelism: 4, salt: String::new() },
    }
}

pub fn profile_id_for_str(profile: &str) -> u8 {
    if profile == "sensitive" { 1 } else { 0 }
}

/// Decoded content of a container header.
#[derive(Clone)]
pub struct HeaderPayload {
    pub master_key:   [u8; 32],
    /// outer: outer-only slot count; hidden: hidden slot count.
    pub total_slots:  u64,
    /// outer: 0; hidden: first slot index of the hidden volume.
    pub hidden_start: u64,
    pub root_slot:    u64,
    pub created_at:   u64,
    pub label:        [u8; 64],
    pub cipher:       CipherAlgorithm,
    pub kdf_profile:  u8,
}

impl Drop for HeaderPayload {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

/// Encode + encrypt a header with the given password.
pub fn encode_header_with_password(
    payload: &HeaderPayload,
    password: &[u8],
    is_hidden: bool,
) -> Result<[u8; HEADER_SIZE]> {
    let mut buf = [0u8; HEADER_SIZE];

    // Random 64-byte salt
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    buf[0..SALT_LEN].copy_from_slice(&salt);

    // Cipher ID + KDF profile (plaintext)
    buf[64] = payload.cipher as u8;
    buf[65] = payload.kdf_profile;
    // buf[66..78] = reserved (zeros, filled by buf initialization)

    // Derive key from password + salt
    let mut kdf = kdf_params_for_profile(payload.kdf_profile);
    kdf.salt = hex::encode(&salt);
    let dk  = derive_key(password, &kdf)?;
    let key: [u8; 32] = dk.as_array_32().unwrap();

    // Build plaintext body
    let mut body = [0u8; BODY_SIZE];
    body[0..4].copy_from_slice(MAGIC);
    body[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    body[8..40].copy_from_slice(&payload.master_key);
    body[40..48].copy_from_slice(&payload.total_slots.to_le_bytes());
    body[48..56].copy_from_slice(&payload.hidden_start.to_le_bytes());
    body[56..64].copy_from_slice(&payload.root_slot.to_le_bytes());
    body[64..72].copy_from_slice(&payload.created_at.to_le_bytes());
    body[72..136].copy_from_slice(&payload.label);
    // [136..406] zero (reserved)

    // Encrypt body → VNMB block (magic+version+nonce+ciphertext+tag)
    let aad       = if is_hidden { AAD_HIDDEN } else { AAD_OUTER };
    let encrypted = encrypt_block(&key, payload.cipher, aad, &body)?;

    // Store nonce + ciphertext+tag in header
    // encrypted layout: VNMB(4) + version(4) + nonce(12) + ciphertext+tag
    let enc_payload = &encrypted[20..]; // skip 20-byte VNMB block header
    buf[NONCE_OFFSET..NONCE_OFFSET + 12].copy_from_slice(&encrypted[8..20]);
    buf[BODY_OFFSET..BODY_OFFSET + enc_payload.len()].copy_from_slice(enc_payload);

    Ok(buf)
}

/// Decrypt a 512-byte header blob with a candidate password.
pub fn decode_header(
    raw: &[u8; HEADER_SIZE],
    password: &[u8],
    is_hidden: bool,
) -> Result<HeaderPayload> {
    let salt       = &raw[0..SALT_LEN];
    let cipher_id  = raw[64];
    let kdf_profile = raw[65];

    let cipher = match cipher_id {
        0 => CipherAlgorithm::ChaCha20Poly1305,
        1 => CipherAlgorithm::Aes256Gcm,
        _ => return Err(VnmError::InvalidFormat(format!("unknown cipher {cipher_id}"))),
    };

    let mut kdf = kdf_params_for_profile(kdf_profile);
    kdf.salt = hex::encode(salt);

    let dk  = derive_key(password, &kdf)?;
    let key: [u8; 32] = dk.as_array_32().unwrap();

    // Rebuild VNMB block for decrypt_block
    let nonce       = &raw[NONCE_OFFSET..NONCE_OFFSET + 12];
    let enc_payload = &raw[BODY_OFFSET..];

    let mut fuser_block: Vec<u8> = Vec::with_capacity(20 + enc_payload.len());
    fuser_block.extend_from_slice(b"VNMB");
    fuser_block.extend_from_slice(&1u32.to_le_bytes());
    fuser_block.extend_from_slice(nonce);
    fuser_block.extend_from_slice(enc_payload);

    let aad  = if is_hidden { AAD_HIDDEN } else { AAD_OUTER };
    let body = decrypt_block(&key, cipher, aad, &fuser_block)
        .map_err(|_| VnmError::AuthenticationFailed)?;

    if body.len() < 136 { return Err(VnmError::InvalidFormat("body too short".into())); }
    if &body[0..4] != MAGIC { return Err(VnmError::AuthenticationFailed); }

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&body[8..40]);

    let total_slots  = u64::from_le_bytes(body[40..48].try_into().unwrap());
    let hidden_start = u64::from_le_bytes(body[48..56].try_into().unwrap());
    let root_slot    = u64::from_le_bytes(body[56..64].try_into().unwrap());
    let created_at   = u64::from_le_bytes(body[64..72].try_into().unwrap());

    let mut label = [0u8; 64];
    label.copy_from_slice(&body[72..136]);

    Ok(HeaderPayload { master_key, total_slots, hidden_start, root_slot, created_at, label, cipher, kdf_profile })
}
