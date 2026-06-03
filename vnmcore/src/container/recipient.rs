//! On-disk recipient slots — each stores K_master encrypted for one credential.
//!
//! ## Password slot
//!
//! Password slots always use Triple encryption (strongest protection).
//!
//!   [0..32]   salt        — Argon2id salt, unique per slot
//!   [32]      kdf_profile — 0=interactive, 1=sensitive
//!   [33..33+E] VNMB encrypted K_master   AAD: b"vnm:pw:v1"
//!   [33+E..PW_SLOT_SIZE] zero padding
//!
//!   E = vnmb_enc_32(Triple) = 8+55+32+64 = 159  →  PW_SLOT_SIZE = 192
//!
//!   Other ciphers for reference:
//!     XChaCha20: 8+24+32+16 = 80
//!     DeoxysII:  8+15+32+16 = 71
//!     Serpent256-EAX: 8+16+32+16 = 72
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
//!   KEY_SLOT_SIZE = 32 + 1568 + 159 = 1759 (using Triple max)

use crate::Result;
use crate::container::CipherAlgorithm;
use crate::container::kdf_params_for_profile_id;
use crate::crypto::{derive_key, encrypt_block, decrypt_block_into_32};
use crate::crypto::hybrid_kem::{HybridPublicKey, HybridPrivateKey, encapsulate, decapsulate};
use crate::crypto::hybrid_kem::X25519_PK_SIZE;
use crate::crypto::kem::CT_SIZE;
use crate::locked_memory::LockedMemory;

/// Maximum VNMB-encrypted 32-byte payload across all supported ciphers.
/// Triple = 63 (VNMB header with 3 nonces) + 32 (plaintext) + 64 (3 tags) = 159
const VNMB_ENCRYPTED_32_MAX: usize = 159;

/// Runtime VNMB-encrypted-32 size for a specific cipher.
fn vnmb_enc_32(cipher: CipherAlgorithm) -> usize {
    use crate::crypto::vnmb_overhead;
    vnmb_overhead(cipher) + 32
}

pub const PW_SLOT_SIZE:  usize = 32 + 1 + VNMB_ENCRYPTED_32_MAX; // 113
pub const KEY_SLOT_SIZE: usize = X25519_PK_SIZE + CT_SIZE + VNMB_ENCRYPTED_32_MAX; // 1680

const AAD_PW:  &[u8] = b"vnm:pw:v1";
const AAD_KEY: &[u8] = b"vnm:key:v1";

// ── Password slot ─────────────────────────────────────────────────────────────

pub fn encode_password_slot(
    k_master: &[u8; 32], password: &[u8], kdf_profile: u8,
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
    let enc = encrypt_block(&key, CipherAlgorithm::Triple, AAD_PW, k_master)?;
    buf[33..33 + enc.len()].copy_from_slice(&enc);
    Ok(buf)
}

/// Ciphers tried in order during blind decryption of key slots.
const ALL_CIPHERS: &[CipherAlgorithm] = &[
    CipherAlgorithm::XChaCha20Poly1305,
    CipherAlgorithm::DeoxysII256,
    CipherAlgorithm::Serpent256,
    CipherAlgorithm::Triple,
];

/// Attempt to decrypt K_master from a password slot without knowing the cipher.
///
/// Argon2id runs **once**; then each supported cipher is tried with a cheap
/// AEAD verification until one succeeds.  Returns K_master in locked memory
/// alongside the discovered cipher.
pub fn try_password_slot(
    slot: &[u8; PW_SLOT_SIZE], password: &[u8],
) -> Option<(LockedMemory<[u8; 32]>, CipherAlgorithm)> {
    let salt        = &slot[0..32];
    let kdf_profile = slot[32];
    let mut kdf = kdf_params_for_profile_id(kdf_profile);
    kdf.salt = hex::encode(salt);
    let dk  = derive_key(password, &kdf).ok()?;
    let key: [u8; 32] = dk.as_array_32()?; // transient slot key

    for &cipher in ALL_CIPHERS {
        let enc_end = 33 + vnmb_enc_32(cipher);
        let enc     = &slot[33..enc_end];
        let mut lm  = LockedMemory::new([0u8; 32]);
        if decrypt_block_into_32(&key, cipher, AAD_PW, enc, &mut *lm).is_ok() {
            return Some((lm, cipher));
        }
    }
    None
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

/// Attempt to decrypt K_master from a hybrid key slot without knowing the cipher.
///
/// ML-KEM decapsulation runs **once**; then each supported cipher is tried
/// until the AEAD tag verifies.  Returns K_master in locked memory and the
/// discovered cipher.
pub fn try_key_slot(
    slot: &[u8; KEY_SLOT_SIZE], private: &HybridPrivateKey,
) -> Option<(LockedMemory<[u8; 32]>, CipherAlgorithm)> {
    let x25519_eph_pk: &[u8; X25519_PK_SIZE] = slot[0..X25519_PK_SIZE].try_into().ok()?;
    let mlkem_ct:      &[u8; CT_SIZE]         = slot[X25519_PK_SIZE..X25519_PK_SIZE + CT_SIZE].try_into().ok()?;
    let shared = decapsulate(private, x25519_eph_pk, mlkem_ct).ok()?; // transient
    let enc_base = X25519_PK_SIZE + CT_SIZE;

    for &cipher in ALL_CIPHERS {
        let enc_end = enc_base + vnmb_enc_32(cipher);
        let enc     = &slot[enc_base..enc_end];
        let mut lm  = LockedMemory::new([0u8; 32]);
        if decrypt_block_into_32(&shared, cipher, AAD_KEY, enc, &mut *lm).is_ok() {
            return Some((lm, cipher));
        }
    }
    None
}
