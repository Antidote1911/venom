//! On-disk recipient slots — each stores K_master encrypted for one credential.
//!
//! ## Password slot (101 bytes)
//!
//!   [0..32]   salt        — Argon2id salt, unique per slot
//!   [32]      kdf_profile — 0=interactive, 1=sensitive
//!   [33..101] VNMB encrypted K_master (68 bytes)
//!             AAD: b"vnm:pw:v1"
//!
//! ## Hybrid key slot (1676 bytes) — X25519 + ML-KEM-1024
//!
//!   [0..8]      fingerprint [u8; 8]        — SHA-256(x25519_pk || mlkem_ek)[0..8]
//!   [8..40]     x25519_eph_pk [u8; 32]     — ephemeral X25519 public key
//!   [40..1608]  mlkem_ct [u8; 1568]        — ML-KEM-1024 ciphertext
//!   [1608..1676] VNMB encrypted K_master   — AEAD(hybrid_key, K_master, 68 bytes)
//!               AAD: b"vnm:key:v1"

use crate::{Result, VnmError};
use crate::container::{CipherAlgorithm, kdf_params_for_profile_id};
use crate::crypto::{derive_key, encrypt_block, decrypt_block};
use crate::crypto::hybrid_kem::{HybridPublicKey, HybridPrivateKey, encapsulate, decapsulate};
use crate::crypto::hybrid_kem::X25519_PK_SIZE;
use crate::crypto::kem::CT_SIZE;

const VNMB_ENCRYPTED_32: usize = 68;

pub const PW_SLOT_SIZE:  usize = 32 + 1 + VNMB_ENCRYPTED_32;                        // 101
pub const KEY_SLOT_SIZE: usize = 8 + X25519_PK_SIZE + CT_SIZE + VNMB_ENCRYPTED_32;  // 1676

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
    Ok(buf)
}

pub fn try_password_slot(
    slot: &[u8; PW_SLOT_SIZE], password: &[u8], cipher: CipherAlgorithm,
) -> Option<[u8; 32]> {
    let salt = &slot[0..32];
    let kdf_profile = slot[32];
    let enc = &slot[33..];
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
    buf[0..8].copy_from_slice(&recipient.fingerprint());
    let ct = encapsulate(recipient)?;
    buf[8..40].copy_from_slice(&ct.x25519_eph_pk);
    buf[40..40 + CT_SIZE].copy_from_slice(&ct.mlkem_ct);
    let enc = encrypt_block(&ct.shared_secret, cipher, AAD_KEY, k_master)?;
    let enc_start = 8 + X25519_PK_SIZE + CT_SIZE;
    buf[enc_start..enc_start + enc.len()].copy_from_slice(&enc);
    Ok(buf)
}

pub fn try_key_slot(
    slot: &[u8; KEY_SLOT_SIZE], private: &HybridPrivateKey, cipher: CipherAlgorithm,
) -> Option<[u8; 32]> {
    // Fingerprint check before crypto
    if &slot[0..8] != private.fingerprint().as_ref() { return None; }
    let x25519_eph_pk: &[u8; X25519_PK_SIZE] = slot[8..8 + X25519_PK_SIZE].try_into().ok()?;
    let mlkem_ct:      &[u8; CT_SIZE]         = slot[8 + X25519_PK_SIZE..8 + X25519_PK_SIZE + CT_SIZE].try_into().ok()?;
    let enc                                    = &slot[8 + X25519_PK_SIZE + CT_SIZE..];
    let shared = decapsulate(private, x25519_eph_pk, mlkem_ct).ok()?;
    decrypt_block(&shared, cipher, AAD_KEY, enc).ok()?.try_into().ok()
}

pub fn read_slot_fingerprint(slot: &[u8; KEY_SLOT_SIZE]) -> [u8; 8] {
    slot[0..8].try_into().unwrap()
}
