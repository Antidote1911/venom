//! On-disk format for Venom ML-KEM-1024 key files.
//!
//! ## Public key file (.vpub, 1656 bytes)
//!
//!   [0..4]      magic b"VKPB"
//!   [4..8]      version u32 LE = 1
//!   [8..16]     created_at u64 LE (Unix seconds)
//!   [16..80]    label [u8; 64] UTF-8, null-padded
//!   [80..88]    fingerprint [u8; 8] = SHA-256(ek)[0..8]
//!   [88..1656]  encapsulation key [u8; 1568]
//!
//! ## Private key file (.vpriv, 153 bytes — unprotected)
//!
//!   [0..4]      magic b"VKPR"
//!   [4..8]      version u32 LE = 1
//!   [8..16]     created_at u64 LE
//!   [16..80]    label [u8; 64]
//!   [80..88]    fingerprint [u8; 8]
//!   [88]        protected: u8 (0 = plaintext, 1 = Argon2id-AES-GCM — future)
//!   [89..153]   seed [u8; 64]
//!
//! The private key file deliberately stores the seed in plaintext (protected=0).
//! Security relies on filesystem permissions (chmod 600). Passphrase protection
//! (protected=1) is reserved for a future version.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Result, VnmError};
use crate::crypto::kem::{self, EncapKey, Seed, EK_SIZE, SEED_SIZE};

pub const PUB_MAGIC:  &[u8; 4] = b"VKPB";
pub const PRIV_MAGIC: &[u8; 4] = b"VKPR";
pub const KEY_VERSION: u32 = 1;

pub const PUB_FILE_SIZE:  usize = 4 + 4 + 8 + 64 + 8 + EK_SIZE; // 1656
pub const PRIV_FILE_SIZE: usize = 4 + 4 + 8 + 64 + 8 + 1 + SEED_SIZE; // 153

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn label_bytes(label: &str) -> [u8; 64] {
    let mut b = [0u8; 64];
    let s = label.as_bytes();
    b[..s.len().min(64)].copy_from_slice(&s[..s.len().min(64)]);
    b
}

fn label_from(raw: &[u8; 64]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(64);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

// ── Encode ────────────────────────────────────────────────────────────────────

/// Encode a public key into its on-disk format.
pub fn encode_pub(ek: &EncapKey, label: &str, created_at: Option<u64>) -> [u8; PUB_FILE_SIZE] {
    let mut buf = [0u8; PUB_FILE_SIZE];
    let ts = created_at.unwrap_or_else(now);
    buf[0..4].copy_from_slice(PUB_MAGIC);
    buf[4..8].copy_from_slice(&KEY_VERSION.to_le_bytes());
    buf[8..16].copy_from_slice(&ts.to_le_bytes());
    buf[16..80].copy_from_slice(&label_bytes(label));
    buf[80..88].copy_from_slice(&kem::fingerprint(ek));
    buf[88..88 + EK_SIZE].copy_from_slice(ek);
    buf
}

/// Encode a private key (seed) into its on-disk format.
pub fn encode_priv(seed: &Seed, ek: &EncapKey, label: &str, created_at: Option<u64>) -> [u8; PRIV_FILE_SIZE] {
    let mut buf = [0u8; PRIV_FILE_SIZE];
    let ts = created_at.unwrap_or_else(now);
    buf[0..4].copy_from_slice(PRIV_MAGIC);
    buf[4..8].copy_from_slice(&KEY_VERSION.to_le_bytes());
    buf[8..16].copy_from_slice(&ts.to_le_bytes());
    buf[16..80].copy_from_slice(&label_bytes(label));
    buf[80..88].copy_from_slice(&kem::fingerprint(ek));
    buf[88] = 0; // protected = false
    buf[89..89 + SEED_SIZE].copy_from_slice(seed);
    buf
}

// ── Decode ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PubKeyFile {
    pub fingerprint: [u8; 8],
    pub label:       String,
    pub created_at:  u64,
    pub ek:          EncapKey,
}

#[derive(Clone)]
pub struct PrivKeyFile {
    pub fingerprint: [u8; 8],
    pub label:       String,
    pub created_at:  u64,
    pub seed:        Seed,
}

pub fn decode_pub(data: &[u8]) -> Result<PubKeyFile> {
    if data.len() < PUB_FILE_SIZE {
        return Err(VnmError::InvalidFormat(
            format!("public key file too short ({} bytes, expected {PUB_FILE_SIZE})", data.len())
        ));
    }
    if &data[0..4] != PUB_MAGIC {
        return Err(VnmError::InvalidFormat("not a Venom public key file".into()));
    }
    let created_at = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let label_raw: &[u8; 64] = data[16..80].try_into().unwrap();
    let fingerprint: [u8; 8] = data[80..88].try_into().unwrap();
    let ek: EncapKey = data[88..88 + EK_SIZE].try_into().unwrap();
    Ok(PubKeyFile { fingerprint, label: label_from(label_raw), created_at, ek })
}

pub fn decode_priv(data: &[u8]) -> Result<PrivKeyFile> {
    if data.len() < PRIV_FILE_SIZE {
        return Err(VnmError::InvalidFormat(
            format!("private key file too short ({} bytes, expected {PRIV_FILE_SIZE})", data.len())
        ));
    }
    if &data[0..4] != PRIV_MAGIC {
        return Err(VnmError::InvalidFormat("not a Venom private key file".into()));
    }
    if data[88] != 0 {
        return Err(VnmError::InvalidFormat(
            "passphrase-protected private keys are not yet supported".into()
        ));
    }
    let created_at = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let label_raw: &[u8; 64] = data[16..80].try_into().unwrap();
    let fingerprint: [u8; 8] = data[80..88].try_into().unwrap();
    let seed: Seed = data[89..89 + SEED_SIZE].try_into().unwrap();
    Ok(PrivKeyFile { fingerprint, label: label_from(label_raw), created_at, seed })
}

// ── File I/O helpers ──────────────────────────────────────────────────────────

pub fn write_pub_file(path: &Path, ek: &EncapKey, label: &str) -> Result<()> {
    let data = encode_pub(ek, label, None);
    std::fs::write(path, &data).map_err(VnmError::Io)
}

pub fn write_priv_file(path: &Path, seed: &Seed, ek: &EncapKey, label: &str) -> Result<()> {
    let data = encode_priv(seed, ek, label, None);
    std::fs::write(path, &data).map_err(VnmError::Io)?;
    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn read_pub_file(path: &Path) -> Result<PubKeyFile> {
    let data = std::fs::read(path).map_err(VnmError::Io)?;
    decode_pub(&data)
}

pub fn read_priv_file(path: &Path) -> Result<PrivKeyFile> {
    let data = std::fs::read(path).map_err(VnmError::Io)?;
    decode_priv(&data)
}

/// Pretty-print a fingerprint as colon-separated hex bytes.
pub fn fp_display(fp: &[u8; 8]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Short display: first 4 bytes only.
pub fn fp_short(fp: &[u8; 8]) -> String {
    fp[..4].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}
