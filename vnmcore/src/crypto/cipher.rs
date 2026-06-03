use aes_gcm::{AesGcm, KeyInit, AeadInPlace};
use aes_gcm::aes::Aes256;
use aes_gcm::aead::generic_array::{GenericArray, typenum::U16 as AesN16};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use crate::{Result, VnmError};
use crate::container::CipherAlgorithm;

// AES-256-GCM with a 16-byte (128-bit) random nonce.
//
// The standard GCM IV derivation maps any nonce length != 12 bytes through
// GHASH, effectively hashing the nonce before use.  A 16-byte random nonce
// raises the birthday collision bound from 2^48 (12-byte nonce) to 2^64,
// matching the approach used by CryFS 2.0 for the same reason.
type Aes256GcmN16 = AesGcm<Aes256, AesN16>;

// On-disk VNMB block format (wraps every encrypted payload):
//   [0..4]       magic  b"VNMB"
//   [4..8]       version u32 LE = 1
//   [8..8+N]     nonce   N=24 bytes (XChaCha20-Poly1305) or 16 bytes (AES-256-GCM)
//   [8+N..]      ciphertext + 16-byte AEAD tag
//
// Total overhead: 48 B (XChaCha20) or 40 B (AES-256-GCM).

const MAGIC:        &[u8; 4] = b"VNMB";
const VERSION:      u32       = 1;
const NONCE_OFFSET: usize     = 8; // magic(4) + version(4)

fn nonce_len(cipher: CipherAlgorithm) -> usize {
    match cipher {
        CipherAlgorithm::XChaCha20Poly1305 => 24,
        CipherAlgorithm::Aes256Gcm         => 16,
    }
}

/// Byte length of the VNMB header (magic + version + nonce) for `cipher`.
pub fn vnmb_header_len(cipher: CipherAlgorithm) -> usize {
    NONCE_OFFSET + nonce_len(cipher)
}

/// Encrypt `plaintext` and return the full VNMB block bytes.
pub fn encrypt_block(key: &[u8; 32], cipher: CipherAlgorithm, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nlen = nonce_len(cipher);
    let hlen = NONCE_OFFSET + nlen;

    let mut nonce_bytes = vec![0u8; nlen];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let mut buf = Vec::with_capacity(hlen + plaintext.len() + 16);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&nonce_bytes);
    buf.extend_from_slice(plaintext);

    match cipher {
        CipherAlgorithm::XChaCha20Poly1305 => {
            use chacha20poly1305::KeyInit as _;
            use chacha20poly1305::aead::AeadInPlace as _;
            let c   = XChaCha20Poly1305::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n   = XNonce::from_slice(&nonce_bytes);
            let tag = c.encrypt_in_place_detached(n, aad, &mut buf[hlen..]).map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
        CipherAlgorithm::Aes256Gcm => {
            let c   = Aes256GcmN16::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n   = GenericArray::<u8, AesN16>::from_slice(&nonce_bytes);
            let tag = c.encrypt_in_place_detached(n, aad, &mut buf[hlen..]).map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
    }
    Ok(buf)
}

/// Decrypt a VNMB block whose plaintext is exactly 32 bytes, writing the
/// result directly into `out` without any intermediate heap allocation.
///
/// Used to decrypt K_master directly into a `LockedMemory<[u8; 32]>` buffer,
/// ensuring the key is never materialised as an unprotected stack or heap value.
pub fn decrypt_block_into_32(
    key:    &[u8; 32],
    cipher: CipherAlgorithm,
    aad:    &[u8],
    data:   &[u8],
    out:    &mut [u8; 32],
) -> crate::Result<()> {
    let nlen = nonce_len(cipher);
    let hlen = NONCE_OFFSET + nlen;
    let expected = hlen + 32 + 16;

    if data.len() != expected { return Err(crate::VnmError::AuthenticationFailed); }
    if &data[0..4] != MAGIC   { return Err(crate::VnmError::AuthenticationFailed); }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != VERSION {
        return Err(crate::VnmError::InvalidFormat(format!("unknown VNMB block version {version}")));
    }

    let nonce_bytes = &data[NONCE_OFFSET..NONCE_OFFSET + nlen];
    out.copy_from_slice(&data[hlen..hlen + 32]); // copy ciphertext into out
    let tag_bytes = &data[hlen + 32..];

    match cipher {
        CipherAlgorithm::XChaCha20Poly1305 => {
            use chacha20poly1305::{KeyInit as _, aead::AeadInPlace as _, Tag};
            let c = XChaCha20Poly1305::new_from_slice(key).map_err(|e| crate::VnmError::CipherError(e.to_string()))?;
            let n = XNonce::from_slice(nonce_bytes);
            let t = Tag::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, out.as_mut_slice(), t)
             .map_err(|_| crate::VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::Aes256Gcm => {
            use aes_gcm::aead::{AeadInPlace as _, Tag};
            let c = Aes256GcmN16::new_from_slice(key).map_err(|e| crate::VnmError::CipherError(e.to_string()))?;
            let n = GenericArray::<u8, AesN16>::from_slice(nonce_bytes);
            let t = Tag::<Aes256GcmN16>::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, out.as_mut_slice(), t)
             .map_err(|_| crate::VnmError::AuthenticationFailed)?;
        }
    }
    Ok(())
}

/// Decrypt a VNMB block. Returns plaintext.
pub fn decrypt_block(key: &[u8; 32], cipher: CipherAlgorithm, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let nlen = nonce_len(cipher);
    let hlen = NONCE_OFFSET + nlen;

    if data.len() < hlen + 16 {
        return Err(VnmError::AuthenticationFailed);
    }
    if &data[0..4] != MAGIC {
        return Err(VnmError::AuthenticationFailed);
    }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != VERSION {
        return Err(VnmError::InvalidFormat(format!("unknown VNMB block version {version}")));
    }

    let nonce_bytes = &data[NONCE_OFFSET..NONCE_OFFSET + nlen];
    let ct_with_tag = &data[hlen..];
    let tag_start   = ct_with_tag.len() - 16;
    let mut plain   = ct_with_tag[..tag_start].to_vec();
    let tag_bytes   = &ct_with_tag[tag_start..];

    match cipher {
        CipherAlgorithm::XChaCha20Poly1305 => {
            use chacha20poly1305::KeyInit as _;
            use chacha20poly1305::aead::AeadInPlace as _;
            use chacha20poly1305::Tag;
            let c = XChaCha20Poly1305::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = XNonce::from_slice(nonce_bytes);
            let t = Tag::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, &mut plain, t).map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::Aes256Gcm => {
            use aes_gcm::aead::Tag;
            let c = Aes256GcmN16::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = GenericArray::<u8, AesN16>::from_slice(nonce_bytes);
            let t = Tag::<Aes256GcmN16>::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, &mut plain, t).map_err(|_| VnmError::AuthenticationFailed)?;
        }
    }
    Ok(plain)
}
