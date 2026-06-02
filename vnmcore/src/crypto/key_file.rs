//! On-disk format for Venom hybrid keypairs.
//!
//! ## .key file — complete keypair
//!
//! Public portions are always in plaintext so the fingerprint and public key
//! can be read without a passphrase (needed for recipient management).
//! Only the private scalars are optionally encrypted.
//!
//! ### Unprotected (1785 bytes, protected byte = 0)
//!
//!   [0..4]      b"VKEY"
//!   [4..8]      version u32 LE = 1
//!   [8..16]     created_at u64 LE
//!   [16..80]    label [u8; 64]
//!   [80..88]    fingerprint [u8; 8]
//!   [88..120]   x25519_pk [u8; 32]   ← public, always plaintext
//!   [120..1688] mlkem_ek [u8; 1568]  ← public, always plaintext
//!   [1688]      protected = 0
//!   [1689..1721] x25519_sk [u8; 32]
//!   [1721..1785] mlkem_seed [u8; 64]
//!
//! ### Passphrase-protected (1886 bytes, protected byte = 1)
//!
//!   [0..1688]   same public header + public keys + protected = 1
//!   [1689..1753] argon2_salt [u8; 64]
//!   [1753]      kdf_profile u8 (0=interactive, 1=sensitive)
//!   [1754..1886] encrypt_block(
//!                    derived_key,
//!                    ChaCha20-Poly1305,
//!                    aad = b"vnm:key:protect:v1",
//!                    x25519_sk(32) || mlkem_seed(64)
//!                ) = 20 (VNMB) + 96 (plaintext) + 16 (tag) = 132 bytes
//!
//! ## .pub file — public portion only (1688 bytes, safe to share)
//!
//!   [0..4]      b"VPUB"
//!   [4..8]      version u32 LE = 1
//!   [8..16]     created_at u64 LE
//!   [16..80]    label [u8; 64]
//!   [80..88]    fingerprint [u8; 8]
//!   [88..120]   x25519_pk [u8; 32]
//!   [120..1688] mlkem_ek [u8; 1568]

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Result, VnmError};
use crate::container::{CipherAlgorithm, kdf_params_for_profile};
use crate::crypto::{derive_key, encrypt_block, decrypt_block};
use crate::crypto::hybrid_kem::{HybridPrivateKey, HybridPublicKey};
use crate::crypto::kem::EK_SIZE;

const KEY_MAGIC:    &[u8; 4] = b"VKEY";
const PUB_MAGIC:    &[u8; 4] = b"VPUB";
const FILE_VERSION: u32       = 1;
const CIPHER:       CipherAlgorithm = CipherAlgorithm::ChaCha20Poly1305;
const PROTECT_AAD:  &[u8]    = b"vnm:key:protect:v1";

// Fixed offsets common to all .key files
const OFF_X25519_PK:  usize = 88;
const OFF_MLKEM_EK:   usize = 120;
const OFF_PROTECTED:  usize = 1688;  // = 88 + 32 + 1568
const OFF_PRIV_START: usize = 1689;

// VNMB-encrypted block size for 96 bytes of plaintext:
//   4 magic + 4 version + 12 nonce + 96 plaintext + 16 tag = 132
const ENC_PRIV_SIZE: usize = 132;

pub const KEY_FILE_SIZE:           usize = OFF_PRIV_START + 32 + 64;           // 1785
pub const KEY_FILE_PROTECTED_SIZE: usize = OFF_PRIV_START + 64 + 1 + ENC_PRIV_SIZE; // 1886
pub const PUB_FILE_SIZE:           usize = 88 + 32 + EK_SIZE;                  // 1688

// ── Shared header helpers ─────────────────────────────────────────────────────

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
fn label_bytes(s: &str) -> [u8; 64] {
    let mut b = [0u8; 64];
    let src = s.as_bytes();
    b[..src.len().min(64)].copy_from_slice(&src[..src.len().min(64)]);
    b
}
fn label_str(raw: &[u8; 64]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(64);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn write_public_header(buf: &mut Vec<u8>, magic: &[u8; 4], key: &HybridPublicKey, label: &str, created_at: u64) {
    buf.extend_from_slice(magic);
    buf.extend_from_slice(&FILE_VERSION.to_le_bytes());
    buf.extend_from_slice(&created_at.to_le_bytes());
    buf.extend_from_slice(&label_bytes(label));
    buf.extend_from_slice(&key.fingerprint());
    buf.extend_from_slice(&key.x25519_pk);
    buf.extend_from_slice(&key.mlkem_ek);
}

// ── Encode ────────────────────────────────────────────────────────────────────

/// Encode an unprotected keypair.
pub fn encode_key_file(key: &HybridPrivateKey, label: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(KEY_FILE_SIZE);
    write_public_header(&mut buf, KEY_MAGIC, &key.public, label, now());
    buf.push(0u8);                         // protected = false
    buf.extend_from_slice(&key.x25519_sk); // private scalar
    buf.extend_from_slice(&key.mlkem_seed);
    buf
}

/// Encode a passphrase-protected keypair.
pub fn encode_key_file_protected(
    key:        &HybridPrivateKey,
    label:      &str,
    passphrase: &[u8],
    kdf_profile: u8,
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(KEY_FILE_PROTECTED_SIZE);
    write_public_header(&mut buf, KEY_MAGIC, &key.public, label, now());
    buf.push(1u8); // protected = true

    // Argon2id salt
    let mut salt = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    buf.extend_from_slice(&salt);
    buf.push(kdf_profile);

    // Derive encryption key from passphrase
    let derived = {
        let mut kdf = kdf_params_for_profile(if kdf_profile == 1 { "sensitive" } else { "interactive" });
        kdf.salt = hex::encode(&salt);
        derive_key(passphrase, &kdf)?
    };
    let enc_key: [u8; 32] = derived.as_array_32().unwrap();

    // Encrypt private material: x25519_sk(32) || mlkem_seed(64) = 96 bytes
    let mut plaintext = Vec::with_capacity(96);
    plaintext.extend_from_slice(&key.x25519_sk);
    plaintext.extend_from_slice(&key.mlkem_seed);
    let enc = encrypt_block(&enc_key, CIPHER, PROTECT_AAD, &plaintext)?;
    buf.extend_from_slice(&enc);

    Ok(buf)
}

/// Encode the public portion only.
pub fn encode_pub_file(pub_key: &HybridPublicKey, label: &str, created_at: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PUB_FILE_SIZE);
    write_public_header(&mut buf, PUB_MAGIC, pub_key, label, created_at);
    buf
}

// ── Decode ────────────────────────────────────────────────────────────────────

pub struct KeyFileData {
    pub label:        String,
    pub created_at:   u64,
    pub key:          HybridPrivateKey,
    pub is_protected: bool,
}

/// Public-only data readable from a .key file without a passphrase.
pub struct KeyPublicData {
    pub label:        String,
    pub created_at:   u64,
    pub public:       HybridPublicKey,
    pub is_protected: bool,
}

pub struct PubFileData {
    pub label:      String,
    pub created_at: u64,
    pub public:     HybridPublicKey,
}

/// Read only the public portions of a .key file (no passphrase required).
pub fn read_public_from_key_bytes(data: &[u8]) -> Result<KeyPublicData> {
    if data.len() < OFF_PRIV_START {
        return Err(VnmError::InvalidFormat("key file too short".into()));
    }
    if &data[0..4] != KEY_MAGIC {
        return Err(VnmError::InvalidFormat("not a Venom .key file".into()));
    }
    let created_at = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let label_raw: &[u8; 64] = data[16..80].try_into().unwrap();
    let x25519_pk: [u8; 32]  = data[OFF_X25519_PK..OFF_X25519_PK + 32].try_into().unwrap();
    let mlkem_ek:  [u8; EK_SIZE] = data[OFF_MLKEM_EK..OFF_MLKEM_EK + EK_SIZE].try_into().unwrap();
    let is_protected = data[OFF_PROTECTED] != 0;

    Ok(KeyPublicData {
        label:        label_str(label_raw),
        created_at,
        public:       HybridPublicKey { x25519_pk, mlkem_ek },
        is_protected,
    })
}

/// Decode an unprotected .key file. Fails if the key is passphrase-protected
/// (use `decode_key_file_protected` for that case).
pub fn decode_key_file(data: &[u8]) -> Result<KeyFileData> {
    let pub_data = read_public_from_key_bytes(data)?;

    if pub_data.is_protected {
        return Err(VnmError::AuthenticationFailed);
        // Caller should use decode_key_file_protected
    }

    if data.len() < KEY_FILE_SIZE {
        return Err(VnmError::InvalidFormat(format!(
            ".key file too short for unprotected ({} B, expected {KEY_FILE_SIZE})", data.len()
        )));
    }

    let x25519_sk: [u8; 32] = data[OFF_PRIV_START..OFF_PRIV_START + 32].try_into().unwrap();
    let mlkem_seed: [u8; 64] = data[OFF_PRIV_START + 32..OFF_PRIV_START + 96].try_into().unwrap();

    Ok(KeyFileData {
        label:        pub_data.label,
        created_at:   pub_data.created_at,
        is_protected: false,
        key: HybridPrivateKey { x25519_sk, mlkem_seed, public: pub_data.public },
    })
}

/// Decode a passphrase-protected .key file. Works for both protected and
/// unprotected (passphrase is ignored if the key is unprotected).
pub fn decode_key_file_with_passphrase(data: &[u8], passphrase: &[u8]) -> Result<KeyFileData> {
    let pub_data = read_public_from_key_bytes(data)?;

    if !pub_data.is_protected {
        return decode_key_file(data);
    }

    if data.len() < KEY_FILE_PROTECTED_SIZE {
        return Err(VnmError::InvalidFormat(format!(
            ".key file too short for protected ({} B, expected {KEY_FILE_PROTECTED_SIZE})", data.len()
        )));
    }

    let salt: &[u8; 64]  = data[OFF_PRIV_START..OFF_PRIV_START + 64].try_into().unwrap();
    let kdf_profile       = data[OFF_PRIV_START + 64];
    let enc               = &data[OFF_PRIV_START + 65..];

    let derived = {
        let mut kdf = kdf_params_for_profile(if kdf_profile == 1 { "sensitive" } else { "interactive" });
        kdf.salt = hex::encode(salt);
        derive_key(passphrase, &kdf)?
    };
    let enc_key: [u8; 32] = derived.as_array_32().unwrap();

    let plain = decrypt_block(&enc_key, CIPHER, PROTECT_AAD, enc)
        .map_err(|_| VnmError::AuthenticationFailed)?;

    if plain.len() < 96 {
        return Err(VnmError::InvalidFormat("decrypted private key too short".into()));
    }

    let x25519_sk: [u8; 32]  = plain[0..32].try_into().unwrap();
    let mlkem_seed: [u8; 64] = plain[32..96].try_into().unwrap();

    Ok(KeyFileData {
        label:        pub_data.label,
        created_at:   pub_data.created_at,
        is_protected: true,
        key: HybridPrivateKey { x25519_sk, mlkem_seed, public: pub_data.public },
    })
}

pub fn decode_pub_file(data: &[u8]) -> Result<PubFileData> {
    if data.len() < PUB_FILE_SIZE {
        return Err(VnmError::InvalidFormat(
            format!(".pub file too short ({} B, expected {PUB_FILE_SIZE})", data.len())
        ));
    }
    if &data[0..4] != PUB_MAGIC {
        return Err(VnmError::InvalidFormat("not a Venom .pub file".into()));
    }
    let created_at = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let label_raw: &[u8; 64]    = data[16..80].try_into().unwrap();
    let x25519_pk: [u8; 32]     = data[88..120].try_into().unwrap();
    let mlkem_ek: [u8; EK_SIZE] = data[120..120 + EK_SIZE].try_into().unwrap();
    Ok(PubFileData { label: label_str(label_raw), created_at, public: HybridPublicKey { x25519_pk, mlkem_ek } })
}

// ── File I/O ──────────────────────────────────────────────────────────────────

pub fn write_key_file(path: &Path, key: &HybridPrivateKey, label: &str) -> Result<()> {
    std::fs::write(path, encode_key_file(key, label)).map_err(VnmError::Io)?;
    chmod600(path);
    Ok(())
}

pub fn write_key_file_protected(path: &Path, key: &HybridPrivateKey, label: &str, passphrase: &[u8], kdf_profile: u8) -> Result<()> {
    let data = encode_key_file_protected(key, label, passphrase, kdf_profile)?;
    std::fs::write(path, &data).map_err(VnmError::Io)?;
    chmod600(path);
    Ok(())
}

pub fn write_pub_file(path: &Path, pub_key: &HybridPublicKey, label: &str, created_at: u64) -> Result<()> {
    std::fs::write(path, encode_pub_file(pub_key, label, created_at)).map_err(VnmError::Io)
}

pub fn read_key_file(path: &Path) -> Result<KeyFileData> {
    let data = std::fs::read(path).map_err(VnmError::Io)?;
    decode_key_file(&data)
}

pub fn read_key_file_protected(path: &Path, passphrase: &[u8]) -> Result<KeyFileData> {
    let data = std::fs::read(path).map_err(VnmError::Io)?;
    decode_key_file_with_passphrase(&data, passphrase)
}

pub fn read_key_public(path: &Path) -> Result<KeyPublicData> {
    let data = std::fs::read(path).map_err(VnmError::Io)?;
    read_public_from_key_bytes(&data)
}

pub fn read_pub_file(path: &Path) -> Result<PubFileData> {
    let data = std::fs::read(path).map_err(VnmError::Io)?;
    decode_pub_file(&data)
}

/// Pretty fingerprint: colon-separated hex bytes.
pub fn fp_display(fp: &[u8; 8]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn chmod600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}
