//! On-disk header format for Venom single-file containers.
//!
//! Each container file starts with two 512-byte header slots:
//!
//!   [0..512]    Outer header  (decrypted by outer password)
//!   [512..1024] Hidden header (decrypted by hidden password, or random bytes)
//!
//! Both headers have the same binary layout:
//!
//!   [0..32]    salt (32 random bytes, for Argon2id)
//!   [32]       cipher_id  (0=ChaCha20-Poly1305, 1=AES-256-GCM)
//!   [33..37]   kdf_memory_kib  (u32 LE)
//!   [37..41]   kdf_iterations  (u32 LE)
//!   [41..45]   kdf_parallelism (u32 LE)
//!   [45..57]   nonce (12 bytes, for AEAD over the body)
//!   [57..512]  encrypted body  (439 plaintext + 16-byte AEAD tag = 455 bytes)
//!
//! Plaintext body layout (439 bytes):
//!   [0..4]     magic  b"VNM1"
//!   [4..8]     version u32 LE
//!   [8..40]    master_key [u8; 32]
//!   [40..48]   total_slots u64 LE  (true number of slots in the container file)
//!   [48..56]   outer_limit u64 LE  (outer: exclusive upper bound of usable slots;
//!                                   hidden: = hidden_start = outer_limit of outer hdr)
//!   [56..64]   root_slot u64 LE
//!   [64..72]   created_at u64 LE (Unix seconds)
//!   [72..136]  label [u8; 64]  (UTF-8, null-padded)
//!   [136..439] reserved zeros
//!
//! The KDF params and cipher are stored OUTSIDE the encrypted body so the key
//! can be derived before decryption — same principle as vnm_bootstrap.json was
//! in the multi-file format, but now inlined in the header itself.
//!
//! AAD for the AEAD:
//!   Outer header: b"vnm:outer:v1"
//!   Hidden header: b"vnm:hidden:v1"
//! This prevents using the outer key to forge a valid hidden header and vice versa.

use rand::RngCore;
use zeroize::Zeroize;

use crate::{Result, VnmError};
use crate::container::{CipherAlgorithm, KdfParams};
use crate::crypto::{derive_key, encrypt_block, decrypt_block};

pub const HEADER_SIZE: usize = 512;
pub const OUTER_HEADER_OFFSET: u64 = 0;
pub const HIDDEN_HEADER_OFFSET: u64 = 512;
pub const HEADER_REGION_SIZE: u64 = 1024;

pub const SLOT_SIZE: usize = 32_768;
pub const MAGIC: &[u8; 4] = b"VNM1";
pub const FORMAT_VERSION: u32 = 1;

const BODY_SIZE: usize = 439;  // plaintext body bytes
const SALT_LEN: usize  = 32;
const NONCE_OFFSET: usize = 45;   // within the 512-byte header
const BODY_OFFSET: usize  = 57;   // ciphertext starts here

const AAD_OUTER:  &[u8] = b"vnm:outer:v1";
const AAD_HIDDEN: &[u8] = b"vnm:hidden:v1";

/// Decoded content of a container header.
#[derive(Clone)]
pub struct HeaderPayload {
    pub master_key:  [u8; 32],
    pub total_slots: u64,
    pub outer_limit: u64,
    pub root_slot:   u64,
    pub created_at:  u64,
    pub label:       [u8; 64],
    pub cipher:      CipherAlgorithm,
    pub kdf:         KdfParams,
}

impl Drop for HeaderPayload {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

/// Encode a header into 512 bytes ready to write to disk.
pub fn encode_header(
    payload: &HeaderPayload,
    is_hidden: bool,
) -> Result<[u8; HEADER_SIZE]> {
    let mut buf = [0u8; HEADER_SIZE];

    // Salt
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    buf[0..SALT_LEN].copy_from_slice(&salt);

    // Plaintext KDF params + cipher (before encrypted region)
    buf[32] = payload.cipher as u8;
    buf[33..37].copy_from_slice(&payload.kdf.memory_kib.to_le_bytes());
    buf[37..41].copy_from_slice(&payload.kdf.iterations.to_le_bytes());
    buf[41..45].copy_from_slice(&payload.kdf.parallelism.to_le_bytes());

    // Derive the header encryption key from password+salt (kdf stores salt hex internally)
    let mut kdf_with_salt = payload.kdf.clone();
    kdf_with_salt.salt = hex::encode(&salt);
    let dk = derive_key(&[], &kdf_with_salt) // password placeholder, used externally
        .map_err(|e| VnmError::KdfError(e.to_string()))?;
    let _ = dk; // actual derive happens in encode_header_with_key

    // Body (plaintext)
    let mut body = [0u8; BODY_SIZE];
    body[0..4].copy_from_slice(MAGIC);
    body[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    body[8..40].copy_from_slice(&payload.master_key);
    body[40..48].copy_from_slice(&payload.total_slots.to_le_bytes());
    body[48..56].copy_from_slice(&payload.outer_limit.to_le_bytes());
    body[56..64].copy_from_slice(&payload.root_slot.to_le_bytes());
    body[64..72].copy_from_slice(&payload.created_at.to_le_bytes());
    body[72..136].copy_from_slice(&payload.label);
    // [136..439] stays zero (reserved)

    // We need the actual derived key from the password — caller provides it via
    // encode_header_with_password which is the real public API.
    // This internal version encodes the body but doesn't encrypt — use the
    // with_password variant below.
    let _ = body; // returned to caller for use in encode_header_with_password

    Err(VnmError::InvalidFormat("use encode_header_with_password".into()))
}

/// Encode + encrypt a header with the given password.
pub fn encode_header_with_password(
    payload: &HeaderPayload,
    password: &[u8],
    is_hidden: bool,
) -> Result<[u8; HEADER_SIZE]> {
    let mut buf = [0u8; HEADER_SIZE];

    // Random salt
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    buf[0..SALT_LEN].copy_from_slice(&salt);

    // Plaintext KDF params + cipher
    buf[32] = payload.cipher as u8;
    buf[33..37].copy_from_slice(&payload.kdf.memory_kib.to_le_bytes());
    buf[37..41].copy_from_slice(&payload.kdf.iterations.to_le_bytes());
    buf[41..45].copy_from_slice(&payload.kdf.parallelism.to_le_bytes());

    // Derive key from password + salt
    let mut kdf = payload.kdf.clone();
    kdf.salt = hex::encode(&salt);
    let dk = derive_key(password, &kdf)?;
    let key: [u8; 32] = dk.as_array_32().unwrap();

    // Build plaintext body
    let mut body = [0u8; BODY_SIZE];
    body[0..4].copy_from_slice(MAGIC);
    body[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    body[8..40].copy_from_slice(&payload.master_key);
    body[40..48].copy_from_slice(&payload.total_slots.to_le_bytes());
    body[48..56].copy_from_slice(&payload.outer_limit.to_le_bytes());
    body[56..64].copy_from_slice(&payload.root_slot.to_le_bytes());
    body[64..72].copy_from_slice(&payload.created_at.to_le_bytes());
    body[72..136].copy_from_slice(&payload.label);

    // Encrypt body (nonce embedded in ciphertext prefix via encrypt_block)
    let aad = if is_hidden { AAD_HIDDEN } else { AAD_OUTER };
    let encrypted = encrypt_block(&key, payload.cipher, aad, &body)?;
    // encrypted = VNMB magic(4) + version(4) + nonce(12) + ciphertext + tag
    // We strip the VNMB wrapper and store only nonce + ciphertext+tag
    let enc_payload = &encrypted[20..]; // skip 20-byte fuser block header
    let enc_len = enc_payload.len();
    if enc_len > HEADER_SIZE - BODY_OFFSET {
        return Err(VnmError::InvalidFormat("encrypted body too large".into()));
    }

    // Nonce is at encrypted[8..20] in the VNMB block format
    buf[NONCE_OFFSET..NONCE_OFFSET+12].copy_from_slice(&encrypted[8..20]);
    // Ciphertext+tag follows
    buf[BODY_OFFSET..BODY_OFFSET + enc_len].copy_from_slice(enc_payload);

    Ok(buf)
}

/// Decrypt a 512-byte header blob with a candidate password.
/// Returns the decoded payload on success, or AuthenticationFailed.
pub fn decode_header(
    raw: &[u8; HEADER_SIZE],
    password: &[u8],
    is_hidden: bool,
) -> Result<HeaderPayload> {
    let salt = &raw[0..SALT_LEN];
    let cipher_id = raw[32];
    let kdf_memory    = u32::from_le_bytes(raw[33..37].try_into().unwrap());
    let kdf_iterations = u32::from_le_bytes(raw[37..41].try_into().unwrap());
    let kdf_parallelism = u32::from_le_bytes(raw[41..45].try_into().unwrap());

    let cipher = match cipher_id {
        0 => CipherAlgorithm::ChaCha20Poly1305,
        1 => CipherAlgorithm::Aes256Gcm,
        _ => return Err(VnmError::InvalidFormat(format!("unknown cipher {cipher_id}"))),
    };

    let kdf = KdfParams {
        memory_kib: kdf_memory,
        iterations: kdf_iterations,
        parallelism: kdf_parallelism,
        salt: hex::encode(salt),
    };

    // Derive key
    let dk = derive_key(password, &kdf)?;
    let key: [u8; 32] = dk.as_array_32().unwrap();

    // Reconstruct the VNMB-style encrypted block (add back the wrapper)
    let nonce = &raw[NONCE_OFFSET..NONCE_OFFSET+12];
    let enc_payload = &raw[BODY_OFFSET..];

    // Build fake VNMB block: magic(4) + version(4) + nonce(12) + ciphertext
    let mut fuser_block: Vec<u8> = Vec::with_capacity(20 + enc_payload.len());
    fuser_block.extend_from_slice(b"VNMB");
    fuser_block.extend_from_slice(&1u32.to_le_bytes());
    fuser_block.extend_from_slice(nonce);
    fuser_block.extend_from_slice(enc_payload);

    let aad = if is_hidden { AAD_HIDDEN } else { AAD_OUTER };
    let body = decrypt_block(&key, cipher, aad, &fuser_block)
        .map_err(|_| VnmError::AuthenticationFailed)?;

    if body.len() < 136 {
        return Err(VnmError::InvalidFormat("body too short".into()));
    }
    if &body[0..4] != MAGIC {
        return Err(VnmError::AuthenticationFailed);
    }

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&body[8..40]);

    let total_slots = u64::from_le_bytes(body[40..48].try_into().unwrap());
    let outer_limit = u64::from_le_bytes(body[48..56].try_into().unwrap());
    let root_slot   = u64::from_le_bytes(body[56..64].try_into().unwrap());
    let created_at  = u64::from_le_bytes(body[64..72].try_into().unwrap());

    let mut label = [0u8; 64];
    label.copy_from_slice(&body[72..136]);

    Ok(HeaderPayload {
        master_key,
        total_slots,
        outer_limit,
        root_slot,
        created_at,
        label,
        cipher,
        kdf,
    })
}
