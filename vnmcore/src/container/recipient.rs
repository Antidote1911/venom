//! On-disk recipient slots — each stores K_master encrypted for one credential.
//!
//! ## Password slot
//!
//!   [0..32]   salt        — Argon2id salt, unique per slot
//!   [32]      kdf_profile — 0=interactive, 1=sensitive
//!   [33..33+E] VNMB encrypted K_master   AAD: b"vnm:pw:v1"
//!   [33+E..PW_SLOT_SIZE] zero padding
//!
//!   E = vnmb_enc_32(cipher):
//!     XChaCha20-Poly1305: 32 + 32 + 16 = 80  →  PW_SLOT_SIZE = 113
//!     AES-256-GCM:        20 + 32 + 16 = 68  →  (padded to 113)
//!
//! ## Hybrid key slot — X25519 + ML-KEM-1024
//!
//! No plaintext fingerprint: all slots tried blindly (recipient anonymity).
//!
//!   [0..32]      x25519_eph_pk [u8; 32]
//!   [32..1600]   mlkem_ct      [u8; 1568]
//!   [1600..1600+E] VNMB encrypted K_master   AAD: b"vnm:key:v1"
//!   [1600+E..KEY_SLOT_SIZE] zero padding
//!
//!   KEY_SLOT_SIZE = 32 + 1568 + 80 = 1680 (using XChaCha20 max)

use crate::Result;
use crate::container::CipherAlgorithm;
use crate::container::kdf_params_for_profile_id;
use crate::crypto::{derive_key, encrypt_block, decrypt_block, vnmb_header_len};
use crate::crypto::hybrid_kem::{HybridPublicKey, HybridPrivateKey, encapsulate, decapsulate};
use crate::crypto::hybrid_kem::X25519_PK_SIZE;
use crate::crypto::kem::CT_SIZE;

/// Byte size of a VNMB-encrypted 32-byte payload for the given cipher.
/// This is the maximum (XChaCha20) size used to size the fixed slot buffers.
const VNMB_ENCRYPTED_32_MAX: usize = 32 + 32 + 16; // 80 (XChaCha20: nonce24+payload32+tag16)

/// Runtime VNMB-encrypted-32 size for a specific cipher.
fn vnmb_enc_32(cipher: CipherAlgorithm) -> usize {
    vnmb_header_len(cipher) + 32 + 16
}

pub const PW_SLOT_SIZE:  usize = 32 + 1 + VNMB_ENCRYPTED_32_MAX; // 113
pub const KEY_SLOT_SIZE: usize = X25519_PK_SIZE + CT_SIZE + VNMB_ENCRYPTED_32_MAX; // 1680

const AAD_PW:  &[u8] = b"vnm:pw:v1";
const AAD_KEY: &[u8] = b"vnm:key:v1";

// ── Password slot ─────────────────────────────────────────────────────────────

pub fn encode_password_slot(
    k_master: &[u8; 32], password: &[u8], kdf_profile: u8, cipher: CipherAlgorithm,
) -> Result<[u8; PW_SLOT_SIZE]> {
    let mut buf = [0u8; PW_SLOT_SIZE];
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    buf[0..32].copy_from_slice(&salt);
    buf[32] = kdf_profile;
    let mut kdf = kdf_params_for_profile_id(kdf_profile);
    kdf.salt = hex::encode(&salt);
    let dk = derive_key(password, &kdf)?;
    let key: [u8; 32] = dk.as_array_32().unwrap();
    let enc = encrypt_block(&key, cipher, AAD_PW, k_master)?;
    buf[33..33 + enc.len()].copy_from_slice(&enc);
    // Remaining bytes stay as zero padding (buf was zero-initialised)
    Ok(buf)
}

pub fn try_password_slot(
    slot: &[u8; PW_SLOT_SIZE], password: &[u8], cipher: CipherAlgorithm,
) -> Option<[u8; 32]> {
    let salt       = &slot[0..32];
    let kdf_profile = slot[32];
    // Slice exactly the bytes written by encode_password_slot for this cipher.
    let enc_end    = 33 + vnmb_enc_32(cipher);
    let enc        = &slot[33..enc_end];
    let mut kdf = kdf_params_for_profile_id(kdf_profile);
    kdf.salt = hex::encode(salt);
    let dk = derive_key(password, &kdf).ok()?;
    let key: [u8; 32] = dk.as_array_32()?;
    decrypt_block(&key, cipher, AAD_PW, enc).ok()?.try_into().ok()
}

// ── Hybrid key slot (X25519 + ML-KEM-1024) ───────────────────────────────────

pub fn encode_key_slot(
    k_master: &[u8; 32], recipient: &HybridPublicKey, cipher: CipherAlgorithm,
) -> Result<[u8; KEY_SLOT_SIZE]> {
    let mut buf = [0u8; KEY_SLOT_SIZE];
    let ct = encapsulate(recipient)?;
    buf[0..X25519_PK_SIZE].copy_from_slice(&ct.x25519_eph_pk);
    buf[X25519_PK_SIZE..X25519_PK_SIZE + CT_SIZE].copy_from_slice(&ct.mlkem_ct);
    let enc = encrypt_block(&ct.shared_secret, cipher, AAD_KEY, k_master)?;
    let enc_start = X25519_PK_SIZE + CT_SIZE;
    buf[enc_start..enc_start + enc.len()].copy_from_slice(&enc);
    Ok(buf)
}

pub fn try_key_slot(
    slot: &[u8; KEY_SLOT_SIZE], private: &HybridPrivateKey, cipher: CipherAlgorithm,
) -> Option<[u8; 32]> {
    let x25519_eph_pk: &[u8; X25519_PK_SIZE] = slot[0..X25519_PK_SIZE].try_into().ok()?;
    let mlkem_ct:      &[u8; CT_SIZE]         = slot[X25519_PK_SIZE..X25519_PK_SIZE + CT_SIZE].try_into().ok()?;
    let enc_start = X25519_PK_SIZE + CT_SIZE;
    let enc_end   = enc_start + vnmb_enc_32(cipher);
    let enc       = &slot[enc_start..enc_end];
    let shared = decapsulate(private, x25519_eph_pk, mlkem_ct).ok()?;
    decrypt_block(&shared, cipher, AAD_KEY, enc).ok()?.try_into().ok()
}
