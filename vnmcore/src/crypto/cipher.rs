use aes_gcm::{AesGcm, KeyInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aes::Aes256;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use deoxys::DeoxysII256;
use serpent::Serpent;
use cipher::{BlockCipherEncrypt, KeyInit as SerpentInit};
use hybrid_array::{Array, typenum::U16 as HU16};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::RngCore;
use crate::{Result, VnmError};
use crate::container::CipherAlgorithm;

// On-disk VNMB block format:
//   [0..4]       magic  b"VNMB"
//   [4..8]       version u32 LE = 1
//   [8..8+N]     nonce(s) — N depends on cipher
//   [8+N..]      ciphertext + tag(s)
//
// Single-cipher nonce sizes:
//   XChaCha20-Poly1305 : N = 24  (192-bit random nonce)
//   AES-256-GCM-16B    : N = 16  (128-bit random nonce via GHASH)
//
// Triple-cipher nonce section (N = 55 = 24+15+16):
//   [8..32]   nonce1 — 24 B (XChaCha20-Poly1305)
//   [32..47]  nonce2 — 15 B (DeoxysII256)
//   [47..63]  nonce3 — 16 B (Serpent-256-CTR)
//
// Triple-cipher ciphertext layout (P = plaintext size):
//   encrypt(P) with XChaCha20 → P+16 (tag1 embedded)
//   encrypt(P+16) with DeoxysII → P+32 (tag2 embedded)
//   encrypt(P+32) with Serpent-CTR → P+32 bytes ciphertext
//   append HMAC-SHA256(K3_mac, nonce3||aad||ct) → P+64 bytes total

const MAGIC:        &[u8; 4] = b"VNMB";
const VERSION:      u32       = 1;
const NONCE_OFFSET: usize     = 8;

// Sizes of the three nonces in the Triple cascade
const N1: usize = 24; // XChaCha20
const N2: usize = 15; // DeoxysII256
const N3: usize = 16; // Serpent-CTR
const TRIPLE_NONCE_LEN: usize = N1 + N2 + N3; // 55

/// Number of extra bytes a VNMB block adds over its plaintext.
/// For single ciphers: nonce_len + 16 (one AEAD tag).
/// For Triple: TRIPLE_NONCE_LEN + 64 (three tags: 16+16+32).
pub fn vnmb_overhead(cipher: CipherAlgorithm) -> usize {
    NONCE_OFFSET + nonce_section_len(cipher) + tags_len(cipher)
}

fn nonce_section_len(cipher: CipherAlgorithm) -> usize {
    match cipher {
        CipherAlgorithm::XChaCha20Poly1305 => 24,
        CipherAlgorithm::Aes256Gcm         => 16,
        CipherAlgorithm::Triple            => TRIPLE_NONCE_LEN,
    }
}

fn tags_len(cipher: CipherAlgorithm) -> usize {
    match cipher {
        CipherAlgorithm::Triple => 64, // poly1305(16) + deoxys(16) + hmac-sha256(32)
        _                       => 16, // single AEAD tag
    }
}

/// Byte length of the VNMB header (magic + version + nonce section) for `cipher`.
pub fn vnmb_header_len(cipher: CipherAlgorithm) -> usize {
    NONCE_OFFSET + nonce_section_len(cipher)
}

// ── Key derivation for Triple cipher ─────────────────────────────────────────

/// Derive a 32-byte subkey from K_master using HMAC-SHA256 with a label.
fn derive_subkey_32(k_master: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(k_master).expect("HMAC accepts any key");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

fn derive_subkey_24(k_master: &[u8; 32], label: &[u8]) -> [u8; 24] {
    let full = derive_subkey_32(k_master, label);
    full[..24].try_into().unwrap()
}

fn derive_subkey_16(k_master: &[u8; 32], label: &[u8]) -> [u8; 16] {
    let full = derive_subkey_32(k_master, label);
    full[..16].try_into().unwrap()
}

struct TripleKeys {
    k1:     [u8; 32],  // XChaCha20-Poly1305  (256-bit)
    k2:     [u8; 32],  // DeoxysII256          (256-bit)
    k3_enc: [u8; 32],  // Serpent-256-CTR      (256-bit via new_from_slice, manual CTR)
    k3_mac: [u8; 32],  // HMAC-SHA256          (256-bit)
}

fn derive_triple_keys(k_master: &[u8; 32]) -> TripleKeys {
    TripleKeys {
        k1:     derive_subkey_32(k_master, b"\x01venom:triple:xchacha20"),
        k2:     derive_subkey_32(k_master, b"\x02venom:triple:deoxys"),
        k3_enc: derive_subkey_32(k_master, b"\x03venom:triple:serpent:enc"),
        k3_mac: derive_subkey_32(k_master, b"\x04venom:triple:serpent:mac"),
    }
}

// ── Serpent-CTR + HMAC-SHA256 helpers ────────────────────────────────────────

/// Apply Serpent-256 in CTR mode (in place) using a 32-byte key.
///
/// `Serpent::new_from_slice` accepts 16–32 bytes (variable key length).
/// `Ctr128BE::new_from_slices` rejects 32-byte keys because `KeySizeUser::KeySize = U16`.
/// We therefore construct the cipher directly and implement CTR manually using
/// `BlockEncrypt::encrypt_block_inplace` on each 16-byte counter block.
fn serpent_ctr_apply(key: &[u8; 32], nonce: &[u8; N3], data: &mut [u8]) -> Result<()> {
    let cipher = <Serpent as SerpentInit>::new_from_slice(key.as_ref())
        .map_err(|e| VnmError::CipherError(format!("Serpent-256 init: {e}")))?;
    let mut ctr = u128::from_be_bytes(*nonce);
    for chunk in data.chunks_mut(16) {
        let mut block: Array<u8, HU16> = ctr.to_be_bytes().into();
        cipher.encrypt_block(&mut block);
        let keystream: [u8; 16] = block.into();
        for (d, k) in chunk.iter_mut().zip(keystream.iter()) {
            *d ^= k;
        }
        ctr = ctr.wrapping_add(1);
    }
    Ok(())
}

/// Compute HMAC-SHA256(key, nonce3 || aad || ciphertext).
fn hmac_sha256(key: &[u8; 32], nonce3: &[u8], aad: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(nonce3);
    mac.update(aad);
    mac.update(ct);
    mac.finalize().into_bytes().into()
}

// ── AES-256-GCM type with 16-byte nonce ──────────────────────────────────────

type Aes256GcmN16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

// ── encrypt_block ─────────────────────────────────────────────────────────────

/// Encrypt `plaintext` and return a complete VNMB block.
pub fn encrypt_block(key: &[u8; 32], cipher: CipherAlgorithm, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    match cipher {
        CipherAlgorithm::Triple => encrypt_triple(key, aad, plaintext),
        _                       => encrypt_single(key, cipher, aad, plaintext),
    }
}

fn encrypt_single(key: &[u8; 32], cipher: CipherAlgorithm, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nlen = nonce_section_len(cipher);
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
            let c = XChaCha20Poly1305::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = XNonce::from_slice(&nonce_bytes);
            let tag = c.encrypt_in_place_detached(n, aad, &mut buf[hlen..])
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
        CipherAlgorithm::Aes256Gcm => {
            let c = Aes256GcmN16::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = aes_gcm::Nonce::<aes_gcm::aead::consts::U16>::from_slice(&nonce_bytes);
            let tag = c.encrypt_in_place_detached(n, aad, &mut buf[hlen..])
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
        CipherAlgorithm::Triple => unreachable!(),
    }
    Ok(buf)
}

fn encrypt_triple(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let keys = derive_triple_keys(key);

    let mut nonce1 = [0u8; N1];
    let mut nonce2 = [0u8; N2];
    let mut nonce3 = [0u8; N3];
    rand::thread_rng().fill_bytes(&mut nonce1);
    rand::thread_rng().fill_bytes(&mut nonce2);
    rand::thread_rng().fill_bytes(&mut nonce3);

    // Layer 1: XChaCha20-Poly1305
    let mut layer1 = Vec::with_capacity(plaintext.len() + 16);
    layer1.extend_from_slice(plaintext);
    {
        use chacha20poly1305::KeyInit as _;
        use chacha20poly1305::aead::AeadInPlace as _;
        let c = XChaCha20Poly1305::new_from_slice(&keys.k1)
            .map_err(|e| VnmError::CipherError(e.to_string()))?;
        let n = XNonce::from_slice(&nonce1);
        let tag = c.encrypt_in_place_detached(n, aad, &mut layer1)
            .map_err(|e| VnmError::CipherError(e.to_string()))?;
        layer1.extend_from_slice(tag.as_slice());
    } // layer1 = plaintext + tag1 (P+16)

    // Layer 2: DeoxysII256 (key 24 B, nonce 15 B)
    let mut layer2 = layer1; // move
    {
        use deoxys::aead::{KeyInit as _, AeadInPlace as _};
        let c = DeoxysII256::new_from_slice(&keys.k2)
            .map_err(|e| VnmError::CipherError(e.to_string()))?;
        let n = deoxys::aead::Nonce::<DeoxysII256>::from_slice(&nonce2);
        let tag = c.encrypt_in_place_detached(n, aad, &mut layer2)
            .map_err(|e| VnmError::CipherError(e.to_string()))?;
        layer2.extend_from_slice(tag.as_slice());
    } // layer2 = (P+16) + tag2 (P+32)

    // Layer 3: Serpent-256-CTR (encrypt in place) + HMAC-SHA256 (authenticate)
    let mut layer3 = layer2; // move
    serpent_ctr_apply(&keys.k3_enc, &nonce3, &mut layer3)?;
    let mac = hmac_sha256(&keys.k3_mac, &nonce3, aad, &layer3);
    // layer3 ends with: encrypted(P+32) || hmac(32) = P+64

    // Assemble VNMB block
    let mut buf = Vec::with_capacity(NONCE_OFFSET + TRIPLE_NONCE_LEN + layer3.len() + 32);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&nonce1);
    buf.extend_from_slice(&nonce2);
    buf.extend_from_slice(&nonce3);
    buf.extend_from_slice(&layer3);
    buf.extend_from_slice(&mac);
    Ok(buf)
}

// ── decrypt_block ─────────────────────────────────────────────────────────────

/// Decrypt a VNMB block. Returns plaintext.
pub fn decrypt_block(key: &[u8; 32], cipher: CipherAlgorithm, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match cipher {
        CipherAlgorithm::Triple => decrypt_triple(key, aad, data),
        _                       => decrypt_single(key, cipher, aad, data),
    }
}

fn decrypt_single(key: &[u8; 32], cipher: CipherAlgorithm, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let nlen = nonce_section_len(cipher);
    let hlen = NONCE_OFFSET + nlen;

    if data.len() < hlen + 16 { return Err(VnmError::AuthenticationFailed); }
    if &data[0..4] != MAGIC   { return Err(VnmError::AuthenticationFailed); }
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
            use chacha20poly1305::{KeyInit as _, aead::AeadInPlace as _, Tag};
            let c = XChaCha20Poly1305::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = XNonce::from_slice(nonce_bytes);
            let t = Tag::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, &mut plain, t)
             .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::Aes256Gcm => {
            use aes_gcm::aead::Tag;
            let c = Aes256GcmN16::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = aes_gcm::Nonce::<aes_gcm::aead::consts::U16>::from_slice(nonce_bytes);
            let t = Tag::<Aes256GcmN16>::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, &mut plain, t)
             .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::Triple => unreachable!(),
    }
    Ok(plain)
}

fn decrypt_triple(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let hlen = NONCE_OFFSET + TRIPLE_NONCE_LEN; // 63

    if data.len() < hlen + 64 + 1 { return Err(VnmError::AuthenticationFailed); }
    if &data[0..4] != MAGIC       { return Err(VnmError::AuthenticationFailed); }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != VERSION {
        return Err(VnmError::InvalidFormat(format!("unknown VNMB block version {version}")));
    }

    let nonce1: &[u8; N1] = data[8..8+N1].try_into().unwrap();
    let nonce2: &[u8; N2] = data[8+N1..8+N1+N2].try_into().unwrap();
    let nonce3: &[u8; N3] = data[8+N1+N2..hlen].try_into().unwrap();

    let keys = derive_triple_keys(key);

    // Layer 3 reverse: verify HMAC, then Serpent-CTR decrypt
    let mac_expected = &data[data.len() - 32..];
    let layer3_ct    = &data[hlen..data.len() - 32];

    let mac_actual = hmac_sha256(&keys.k3_mac, nonce3, aad, layer3_ct);
    // Constant-time comparison
    use subtle::ConstantTimeEq;
    if mac_actual.ct_eq(mac_expected).unwrap_u8() == 0 {
        return Err(VnmError::AuthenticationFailed);
    }
    let mut layer2 = layer3_ct.to_vec();
    serpent_ctr_apply(&keys.k3_enc, nonce3, &mut layer2)?;
    // layer2 = encrypted_deoxys(encrypted_xchacha20(plaintext)) P+32

    // Layer 2 reverse: DeoxysII256 decrypt
    {
        use deoxys::aead::{KeyInit as _, AeadInPlace as _, Tag};
        let c = DeoxysII256::new_from_slice(&keys.k2)
            .map_err(|e| VnmError::CipherError(e.to_string()))?;
        let n = deoxys::aead::Nonce::<DeoxysII256>::from_slice(nonce2);
        let tag_start = layer2.len() - 16;
        let tag_bytes = layer2[tag_start..].to_vec();
        layer2.truncate(tag_start);
        let t = Tag::<DeoxysII256>::from_slice(&tag_bytes);
        c.decrypt_in_place_detached(n, aad, &mut layer2, t)
         .map_err(|_| VnmError::AuthenticationFailed)?;
    }
    // layer2 = encrypted_xchacha20(plaintext) P+16

    // Layer 1 reverse: XChaCha20-Poly1305 decrypt
    {
        use chacha20poly1305::{KeyInit as _, aead::AeadInPlace as _, Tag};
        let c = XChaCha20Poly1305::new_from_slice(&keys.k1)
            .map_err(|e| VnmError::CipherError(e.to_string()))?;
        let n = XNonce::from_slice(nonce1);
        let tag_start = layer2.len() - 16;
        let tag_bytes = layer2[tag_start..].to_vec();
        layer2.truncate(tag_start);
        let t = Tag::from_slice(&tag_bytes);
        c.decrypt_in_place_detached(n, aad, &mut layer2, t)
         .map_err(|_| VnmError::AuthenticationFailed)?;
    }

    Ok(layer2) // = plaintext
}

// ── decrypt_block_into_32 ──────────────────────────────────────────────────────

/// Decrypt a VNMB block whose plaintext is exactly 32 bytes, writing the
/// result directly into `out` without any intermediate heap allocation.
pub fn decrypt_block_into_32(
    key:    &[u8; 32],
    cipher: CipherAlgorithm,
    aad:    &[u8],
    data:   &[u8],
    out:    &mut [u8; 32],
) -> crate::Result<()> {
    // For triple cipher, use the general decrypt path then copy
    if cipher == CipherAlgorithm::Triple {
        let plain = decrypt_triple(key, aad, data)?;
        if plain.len() != 32 { return Err(VnmError::AuthenticationFailed); }
        out.copy_from_slice(&plain);
        return Ok(());
    }

    let nlen     = nonce_section_len(cipher);
    let hlen     = NONCE_OFFSET + nlen;
    let expected = hlen + 32 + 16;

    if data.len() != expected { return Err(VnmError::AuthenticationFailed); }
    if &data[0..4] != MAGIC   { return Err(VnmError::AuthenticationFailed); }
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if version != VERSION {
        return Err(VnmError::InvalidFormat(format!("unknown VNMB block version {version}")));
    }

    let nonce_bytes = &data[NONCE_OFFSET..NONCE_OFFSET + nlen];
    out.copy_from_slice(&data[hlen..hlen + 32]);
    let tag_bytes = &data[hlen + 32..];

    match cipher {
        CipherAlgorithm::XChaCha20Poly1305 => {
            use chacha20poly1305::{KeyInit as _, aead::AeadInPlace as _, Tag};
            let c = XChaCha20Poly1305::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = XNonce::from_slice(nonce_bytes);
            let t = Tag::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, out.as_mut_slice(), t)
             .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::Aes256Gcm => {
            use aes_gcm::aead::Tag;
            let c = Aes256GcmN16::new_from_slice(key).map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = aes_gcm::Nonce::<aes_gcm::aead::consts::U16>::from_slice(nonce_bytes);
            let t = Tag::<Aes256GcmN16>::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, out.as_mut_slice(), t)
             .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::Triple => unreachable!(),
    }
    Ok(())
}
