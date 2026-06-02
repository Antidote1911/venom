//! On-disk format for Venom hybrid keypairs.
//!
//! ## .key file — complete keypair (private + public, 1784 bytes)
//!
//!   [0..4]      b"VKEY"
//!   [4..8]      version u32 LE = 1
//!   [8..16]     created_at u64 LE
//!   [16..80]    label [u8; 64]
//!   [80..88]    fingerprint [u8; 8] = SHA-256(x25519_pk || mlkem_ek)[0..8]
//!   [88..120]   x25519_sk [u8; 32]   (static X25519 private scalar)
//!   [120..152]  x25519_pk [u8; 32]   (corresponding X25519 public key)
//!   [152..216]  mlkem_seed [u8; 64]  (ML-KEM-1024 private seed)
//!   [216..1784] mlkem_ek [u8; 1568]  (ML-KEM-1024 encapsulation key)
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
//!
//! The .key file stores private material unencrypted — protect with filesystem
//! permissions (chmod 600). Passphrase protection is a future improvement.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Result, VnmError};
use crate::crypto::hybrid_kem::{HybridPrivateKey, HybridPublicKey};
use crate::crypto::kem::EK_SIZE;

const KEY_MAGIC:  &[u8; 4] = b"VKEY";
const PUB_MAGIC:  &[u8; 4] = b"VPUB";
const FILE_VERSION: u32     = 1;

pub const KEY_FILE_SIZE: usize = 4 + 4 + 8 + 64 + 8 + 32 + 32 + 64 + EK_SIZE; // 1784
pub const PUB_FILE_SIZE: usize = 4 + 4 + 8 + 64 + 8 + 32 + EK_SIZE;            // 1688

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

// ── Encode ────────────────────────────────────────────────────────────────────

/// Encode the full keypair to bytes ready to write as a `.key` file.
pub fn encode_key_file(key: &HybridPrivateKey, label: &str) -> [u8; KEY_FILE_SIZE] {
    let mut buf = [0u8; KEY_FILE_SIZE];
    buf[0..4].copy_from_slice(KEY_MAGIC);
    buf[4..8].copy_from_slice(&FILE_VERSION.to_le_bytes());
    buf[8..16].copy_from_slice(&now().to_le_bytes());
    buf[16..80].copy_from_slice(&label_bytes(label));
    buf[80..88].copy_from_slice(&key.fingerprint());
    buf[88..120].copy_from_slice(&key.x25519_sk);
    buf[120..152].copy_from_slice(&key.public.x25519_pk);
    buf[152..216].copy_from_slice(&key.mlkem_seed);
    buf[216..216 + EK_SIZE].copy_from_slice(&key.public.mlkem_ek);
    buf
}

/// Encode the public portion to bytes ready to write as a `.pub` file.
pub fn encode_pub_file(pub_key: &HybridPublicKey, label: &str, created_at: u64) -> [u8; PUB_FILE_SIZE] {
    let mut buf = [0u8; PUB_FILE_SIZE];
    buf[0..4].copy_from_slice(PUB_MAGIC);
    buf[4..8].copy_from_slice(&FILE_VERSION.to_le_bytes());
    buf[8..16].copy_from_slice(&created_at.to_le_bytes());
    buf[16..80].copy_from_slice(&label_bytes(label));
    buf[80..88].copy_from_slice(&pub_key.fingerprint());
    buf[88..120].copy_from_slice(&pub_key.x25519_pk);
    buf[120..120 + EK_SIZE].copy_from_slice(&pub_key.mlkem_ek);
    buf
}

// ── Decode ────────────────────────────────────────────────────────────────────

pub struct KeyFileData {
    pub label:      String,
    pub created_at: u64,
    pub key:        HybridPrivateKey,
}

pub struct PubFileData {
    pub label:      String,
    pub created_at: u64,
    pub public:     HybridPublicKey,
}

pub fn decode_key_file(data: &[u8]) -> Result<KeyFileData> {
    if data.len() < KEY_FILE_SIZE {
        return Err(VnmError::InvalidFormat(
            format!(".key file too short ({} B, expected {KEY_FILE_SIZE})", data.len())
        ));
    }
    if &data[0..4] != KEY_MAGIC {
        return Err(VnmError::InvalidFormat("not a Venom .key file".into()));
    }

    let created_at  = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let label_raw: &[u8; 64] = data[16..80].try_into().unwrap();
    let x25519_sk: [u8; 32]  = data[88..120].try_into().unwrap();
    let x25519_pk: [u8; 32]  = data[120..152].try_into().unwrap();
    let mlkem_seed: [u8; 64] = data[152..216].try_into().unwrap();
    let mlkem_ek: [u8; EK_SIZE] = data[216..216 + EK_SIZE].try_into().unwrap();

    let public = HybridPublicKey { x25519_pk, mlkem_ek };
    let key = HybridPrivateKey { x25519_sk, mlkem_seed, public };

    Ok(KeyFileData { label: label_str(label_raw), created_at, key })
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

    let created_at  = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let label_raw: &[u8; 64] = data[16..80].try_into().unwrap();
    let x25519_pk: [u8; 32]  = data[88..120].try_into().unwrap();
    let mlkem_ek: [u8; EK_SIZE] = data[120..120 + EK_SIZE].try_into().unwrap();

    Ok(PubFileData {
        label: label_str(label_raw),
        created_at,
        public: HybridPublicKey { x25519_pk, mlkem_ek },
    })
}

// ── File I/O ──────────────────────────────────────────────────────────────────

pub fn write_key_file(path: &Path, key: &HybridPrivateKey, label: &str) -> Result<()> {
    let data = encode_key_file(key, label);
    std::fs::write(path, &data).map_err(VnmError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn write_pub_file(path: &Path, pub_key: &HybridPublicKey, label: &str, created_at: u64) -> Result<()> {
    let data = encode_pub_file(pub_key, label, created_at);
    std::fs::write(path, &data).map_err(VnmError::Io)
}

pub fn read_key_file(path: &Path) -> Result<KeyFileData> {
    let data = std::fs::read(path).map_err(VnmError::Io)?;
    decode_key_file(&data)
}

pub fn read_pub_file(path: &Path) -> Result<PubFileData> {
    let data = std::fs::read(path).map_err(VnmError::Io)?;
    decode_pub_file(&data)
}

/// Pretty fingerprint: colon-separated hex bytes.
pub fn fp_display(fp: &[u8; 8]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}
