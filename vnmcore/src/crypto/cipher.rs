use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use rand::RngCore;
use crate::{Result, VnmError};
use crate::container::{CipherAlgorithm, VaultHeader};

/// Encrypt `plaintext` and return the full on-disk block bytes (header + ciphertext).
/// `block_id` is used as AAD to bind ciphertext to its block identity.
pub fn encrypt_block(
    key: &[u8; 32],
    cipher: CipherAlgorithm,
    block_id: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let mut buf = Vec::with_capacity(VaultHeader::HEADER_LEN + plaintext.len() + 16);

    // Header: magic + version + nonce
    buf.extend_from_slice(VaultHeader::MAGIC);
    buf.extend_from_slice(&VaultHeader::VERSION.to_le_bytes());
    buf.extend_from_slice(&nonce_bytes);

    // Payload (will be encrypted in-place)
    buf.extend_from_slice(plaintext);

    let payload_start = VaultHeader::HEADER_LEN;

    match cipher {
        CipherAlgorithm::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let nonce = AesNonce::from_slice(&nonce_bytes);
            let tag = c
                .encrypt_in_place_detached(nonce, block_id, &mut buf[payload_start..])
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
        CipherAlgorithm::ChaCha20Poly1305 => {
            let c = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let nonce = ChaNonce::from_slice(&nonce_bytes);
            let tag = c
                .encrypt_in_place_detached(nonce, block_id, &mut buf[payload_start..])
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
    }

    Ok(buf)
}

/// Decrypt a block from its on-disk bytes. Returns plaintext.
pub fn decrypt_block(
    key: &[u8; 32],
    cipher: CipherAlgorithm,
    block_id: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    if data.len() < VaultHeader::HEADER_LEN + 16 {
        return Err(VnmError::CorruptedBlock("too short".into()));
    }

    if &data[0..4] != VaultHeader::MAGIC {
        return Err(VnmError::CorruptedBlock("bad magic".into()));
    }

    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != VaultHeader::VERSION {
        return Err(VnmError::CorruptedBlock(format!("unknown version {version}")));
    }

    let nonce_bytes = &data[VaultHeader::NONCE_OFFSET..VaultHeader::NONCE_OFFSET + 12];
    let ciphertext_with_tag = &data[VaultHeader::HEADER_LEN..];

    if ciphertext_with_tag.len() < 16 {
        return Err(VnmError::CorruptedBlock("missing tag".into()));
    }

    let tag_start = ciphertext_with_tag.len() - 16;
    let mut plaintext = ciphertext_with_tag[..tag_start].to_vec();
    let tag = &ciphertext_with_tag[tag_start..];

    match cipher {
        CipherAlgorithm::Aes256Gcm => {
            use aes_gcm::Tag;
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let nonce = AesNonce::from_slice(nonce_bytes);
            let tag = Tag::from_slice(tag);
            c.decrypt_in_place_detached(nonce, block_id, &mut plaintext, tag)
                .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::ChaCha20Poly1305 => {
            use chacha20poly1305::Tag;
            let c = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let nonce = ChaNonce::from_slice(nonce_bytes);
            let tag = Tag::from_slice(tag);
            c.decrypt_in_place_detached(nonce, block_id, &mut plaintext, tag)
                .map_err(|_| VnmError::AuthenticationFailed)?;
        }
    }

    Ok(plaintext)
}
