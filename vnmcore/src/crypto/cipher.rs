use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use rand::RngCore;
use crate::{Result, VnmError};
use crate::container::CipherAlgorithm;

// On-disk block format (wraps every encrypted payload):
//   [0..4]    magic  b"VNMB"
//   [4..8]    version u32 LE
//   [8..20]   nonce (12 bytes)
//   [20..]    ciphertext + 16-byte auth tag

const MAGIC: &[u8; 4] = b"VNMB";
const VERSION: u32 = 1;
const NONCE_OFFSET: usize = 8;
const HEADER_LEN: usize = 20;

/// Encrypt `plaintext` and return the full on-disk block bytes.
/// `aad` (additional authenticated data) binds the ciphertext to its location
/// — e.g., the slot index as LE bytes, or a header-type string.
pub fn encrypt_block(key: &[u8; 32], cipher: CipherAlgorithm, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let mut buf = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&nonce_bytes);
    buf.extend_from_slice(plaintext);

    match cipher {
        CipherAlgorithm::Aes256Gcm => {
            let c   = Aes256Gcm::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n   = AesNonce::from_slice(&nonce_bytes);
            let tag = c.encrypt_in_place_detached(n, aad, &mut buf[HEADER_LEN..]).map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
        CipherAlgorithm::ChaCha20Poly1305 => {
            let c   = ChaCha20Poly1305::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n   = ChaNonce::from_slice(&nonce_bytes);
            let tag = c.encrypt_in_place_detached(n, aad, &mut buf[HEADER_LEN..]).map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
    }
    Ok(buf)
}

/// Decrypt a block from its on-disk bytes. Returns plaintext.
pub fn decrypt_block(key: &[u8; 32], cipher: CipherAlgorithm, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN + 16 {
        return Err(VnmError::AuthenticationFailed);
    }
    if &data[0..4] != MAGIC {
        return Err(VnmError::AuthenticationFailed);
    }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != VERSION {
        return Err(VnmError::InvalidFormat(format!("unknown block version {version}")));
    }
    let nonce_bytes = &data[NONCE_OFFSET..NONCE_OFFSET + 12];
    let ct_with_tag = &data[HEADER_LEN..];
    let tag_start   = ct_with_tag.len() - 16;
    let mut plain   = ct_with_tag[..tag_start].to_vec();
    let tag_bytes   = &ct_with_tag[tag_start..];

    match cipher {
        CipherAlgorithm::Aes256Gcm => {
            use aes_gcm::Tag;
            let c = Aes256Gcm::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = AesNonce::from_slice(nonce_bytes);
            let t = Tag::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, &mut plain, t).map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::ChaCha20Poly1305 => {
            use chacha20poly1305::Tag;
            let c = ChaCha20Poly1305::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = ChaNonce::from_slice(nonce_bytes);
            let t = Tag::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, &mut plain, t).map_err(|_| VnmError::AuthenticationFailed)?;
        }
    }
    Ok(plain)
}
