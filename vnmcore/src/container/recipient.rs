//! On-disk recipient slots — each stores K_master encrypted for one credential.
//!
//! ## Slot types
//!
//! PasswordSlot (101 bytes):
//!   [0..32]   salt        — Argon2id salt unique to this slot
//!   [32]      kdf_profile — 0=interactive, 1=sensitive
//!   [33..101] VNMB encrypted K_master (68 bytes = 36 VNMB header + 32 K_master + 16 tag + 16 tag)
//!             Wait, let me recount: encrypt_block output = 4(magic)+4(ver)+12(nonce)+plaintext+16(tag)
//!             = 36 + 32 = 68 bytes total
//!             AAD: b"vnm:pw:v1"
//!
//! KeySlot (1644 bytes):
//!   [0..8]      fingerprint   — SHA256(ek)[0..8], for quick matching
//!   [8..1576]   ML-KEM-1024 ciphertext (1568 bytes)
//!   [1576..1644] VNMB encrypted K_master (68 bytes)
//!               AAD: b"vnm:key:v1"

use crate::{Result, VnmError};
use crate::container::{CipherAlgorithm, kdf_params_for_profile_id};
use crate::crypto::{derive_key, encrypt_block, decrypt_block};
use crate::crypto::kem::{self, EncapKey, KemCiphertext, Seed, SS_SIZE, EK_SIZE, CT_SIZE};

const VNMB_ENCRYPTED_32: usize = 68; // 4+4+12+32+16
pub const PW_SLOT_SIZE:  usize = 32 + 1 + VNMB_ENCRYPTED_32;  // = 101
pub const KEY_SLOT_SIZE: usize = 8 + CT_SIZE + VNMB_ENCRYPTED_32;  // = 1644

const AAD_PW:  &[u8] = b"vnm:pw:v1";
const AAD_KEY: &[u8] = b"vnm:key:v1";

// ── Password slot ─────────────────────────────────────────────────────────────

/// Encode a password recipient slot.
pub fn encode_password_slot(
    k_master:    &[u8; 32],
    password:    &[u8],
    kdf_profile: u8,
    cipher:      CipherAlgorithm,
) -> Result<[u8; PW_SLOT_SIZE]> {
    let mut buf = [0u8; PW_SLOT_SIZE];

    // Random per-slot salt
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    buf[0..32].copy_from_slice(&salt);
    buf[32] = kdf_profile;

    // Derive slot key
    let mut kdf = kdf_params_for_profile_id(kdf_profile);
    kdf.salt = hex::encode(&salt);
    let dk  = derive_key(password, &kdf)?;
    let key: [u8; 32] = dk.as_array_32().unwrap();

    // Wrap K_master
    let enc = encrypt_block(&key, cipher, AAD_PW, k_master)?;
    buf[33..33 + enc.len()].copy_from_slice(&enc);
    Ok(buf)
}

/// Try to decrypt a password slot.  Returns K_master on success.
pub fn try_password_slot(
    slot:     &[u8; PW_SLOT_SIZE],
    password: &[u8],
    cipher:   CipherAlgorithm,
) -> Option<[u8; 32]> {
    let salt        = &slot[0..32];
    let kdf_profile = slot[32];
    let enc         = &slot[33..];

    let mut kdf = kdf_params_for_profile_id(kdf_profile);
    kdf.salt = hex::encode(salt);
    let dk  = derive_key(password, &kdf).ok()?;
    let key: [u8; 32] = dk.as_array_32()?;

    let plain = decrypt_block(&key, cipher, AAD_PW, enc).ok()?;
    plain.try_into().ok()
}

// ── ML-KEM slot ───────────────────────────────────────────────────────────────

/// Encode an ML-KEM recipient slot using the recipient's public key.
pub fn encode_key_slot(
    k_master: &[u8; 32],
    ek:       &EncapKey,
    cipher:   CipherAlgorithm,
) -> Result<[u8; KEY_SLOT_SIZE]> {
    let mut buf = [0u8; KEY_SLOT_SIZE];

    // Fingerprint
    buf[0..8].copy_from_slice(&kem::fingerprint(ek));

    // Encapsulate — produces ciphertext + 32-byte shared secret
    let (ct, ss) = kem::encapsulate(ek)?;
    buf[8..8 + CT_SIZE].copy_from_slice(&ct);

    // Use shared secret as AEAD key to wrap K_master
    let enc = encrypt_block(&ss, cipher, AAD_KEY, k_master)?;
    buf[8 + CT_SIZE..8 + CT_SIZE + enc.len()].copy_from_slice(&enc);
    Ok(buf)
}

/// Try to decrypt an ML-KEM slot with the given seed (private key).
/// Returns `(k_master, fingerprint)` on success.
pub fn try_key_slot(
    slot:   &[u8; KEY_SLOT_SIZE],
    seed:   &Seed,
    cipher: CipherAlgorithm,
) -> Option<[u8; 32]> {
    let fingerprint = &slot[0..8];
    let ct_bytes: &[u8; CT_SIZE]   = slot[8..8 + CT_SIZE].try_into().ok()?;
    let enc                         = &slot[8 + CT_SIZE..];

    // Optional: check fingerprint against our EK to short-circuit
    let our_ek = kem::ek_from_seed(seed);
    let our_fp = kem::fingerprint(&our_ek);
    if fingerprint != our_fp.as_ref() { return None; }

    let ss = kem::decapsulate(seed, ct_bytes).ok()?;
    let plain = decrypt_block(&ss, cipher, AAD_KEY, enc).ok()?;
    plain.try_into().ok()
}

/// Fingerprint of an encapsulation key (8 bytes).
pub fn slot_fingerprint(ek: &EncapKey) -> [u8; 8] {
    kem::fingerprint(ek)
}

/// Read the fingerprint stored in a key slot (no decryption needed).
pub fn read_slot_fingerprint(slot: &[u8; KEY_SLOT_SIZE]) -> [u8; 8] {
    slot[0..8].try_into().unwrap()
}
