// AeadInPlace and related items are deprecated in aead 0.6-rc.
// They remain functional. Migration to AeadInOut + InOutBuf is deferred until
// aead 0.6 reaches a stable release.
#![allow(deprecated)]

use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use deoxys::DeoxysII256;
use eax::Eax;
use serpent::Serpent;
use cipher::{BlockCipherEncrypt, BlockCipherEncClosure, KeyInit as SerpentInit, KeySizeUser, BlockSizeUser, ParBlocksSizeUser};
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
// Nonce sizes per cipher:
//   XChaCha20-Poly1305 : N = 24  (192-bit random nonce)
//   DeoxysII-256       : N = 15  (120-bit random nonce)
//   Serpent-256-EAX    : N = 16  (128-bit random nonce)
//
// Triple-cipher nonce section (N = 55 = 24+15+16):
//   [8..32]   nonce1 — 24 B (XChaCha20-Poly1305)
//   [32..47]  nonce2 — 15 B (DeoxysII256)
//   [47..63]  nonce3 — 16 B (Serpent-256-CTR, layer 3 of Triple)

const MAGIC:        &[u8; 4] = b"VNMB";
const VERSION:      u32       = 1;
const NONCE_OFFSET: usize     = 8;

const N1: usize = 24; // XChaCha20
const N2: usize = 15; // DeoxysII256
const N3: usize = 16; // Serpent-CTR (Triple layer 3) / Serpent-EAX
const TRIPLE_NONCE_LEN: usize = N1 + N2 + N3; // 55

/// Serpent newtype with a fixed 256-bit key, required because `Serpent::KeySize = U16`
/// while EAX uses the cipher's `KeySize` for the AEAD key.
#[derive(Clone)]
struct Serpent256(Serpent);

impl KeySizeUser for Serpent256 {
    type KeySize = hybrid_array::typenum::U32;
}
impl BlockSizeUser for Serpent256 {
    type BlockSize = HU16;
}
impl ParBlocksSizeUser for Serpent256 {
    type ParBlocksSize = hybrid_array::typenum::U1;
}
impl SerpentInit for Serpent256 {
    fn new(key: &hybrid_array::Array<u8, hybrid_array::typenum::U32>) -> Self {
        Self(Serpent::new_from_slice(key.as_slice()).expect("32-byte Serpent key"))
    }
}
impl BlockCipherEncrypt for Serpent256 {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = HU16>) {
        self.0.encrypt_with_backend(f)
    }
}

type SerpentEax = Eax<Serpent256>;

/// Number of extra bytes a VNMB block adds over its plaintext.
pub fn vnmb_overhead(cipher: CipherAlgorithm) -> usize {
    NONCE_OFFSET + nonce_section_len(cipher) + tags_len(cipher)
}

fn nonce_section_len(cipher: CipherAlgorithm) -> usize {
    match cipher {
        CipherAlgorithm::XChaCha20Poly1305 => N1,
        CipherAlgorithm::DeoxysII256       => N2,
        CipherAlgorithm::Serpent256        => N3,
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

// ── Serpent-CTR helpers (used only by Triple layer 3) ────────────────────────

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

fn hmac_sha256(key: &[u8; 32], nonce: &[u8], aad: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(nonce);
    mac.update(aad);
    mac.update(ct);
    mac.finalize().into_bytes().into()
}

// ── Triple cipher key schedule ────────────────────────────────────────────────

fn derive_subkey_32(k_master: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(k_master).expect("HMAC accepts any key");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

struct TripleKeys {
    k1:     [u8; 32],  // XChaCha20-Poly1305
    k2:     [u8; 32],  // DeoxysII256
    k3_enc: [u8; 32],  // Serpent-256-CTR
    k3_mac: [u8; 32],  // HMAC-SHA256
}

fn derive_triple_keys(k_master: &[u8; 32]) -> TripleKeys {
    TripleKeys {
        k1:     derive_subkey_32(k_master, b"\x01venom:triple:xchacha20"),
        k2:     derive_subkey_32(k_master, b"\x02venom:triple:deoxys"),
        k3_enc: derive_subkey_32(k_master, b"\x03venom:triple:serpent:enc"),
        k3_mac: derive_subkey_32(k_master, b"\x04venom:triple:serpent:mac"),
    }
}

// ── encrypt_block ─────────────────────────────────────────────────────────────

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
            let c = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = XNonce::from_slice(&nonce_bytes);
            let tag = c.encrypt_in_place_detached(n, aad, &mut buf[hlen..])
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
        CipherAlgorithm::DeoxysII256 => {
            use deoxys::aead::{KeyInit as _, AeadInPlace as _};
            let c = DeoxysII256::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = deoxys::aead::Nonce::<DeoxysII256>::from_slice(&nonce_bytes);
            let tag = c.encrypt_in_place_detached(n, aad, &mut buf[hlen..])
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            buf.extend_from_slice(tag.as_slice());
        }
        CipherAlgorithm::Serpent256 => {
            use eax::aead::{KeyInit as _, AeadInPlace as _};
            let c = SerpentEax::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = eax::aead::Nonce::<SerpentEax>::from_slice(&nonce_bytes);
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
    }

    // Layer 2: DeoxysII256
    let mut layer2 = layer1;
    {
        use deoxys::aead::{KeyInit as _, AeadInPlace as _};
        let c = DeoxysII256::new_from_slice(&keys.k2)
            .map_err(|e| VnmError::CipherError(e.to_string()))?;
        let n = deoxys::aead::Nonce::<DeoxysII256>::from_slice(&nonce2);
        let tag = c.encrypt_in_place_detached(n, aad, &mut layer2)
            .map_err(|e| VnmError::CipherError(e.to_string()))?;
        layer2.extend_from_slice(tag.as_slice());
    }

    // Layer 3: Serpent-256-CTR + HMAC-SHA256
    let mut layer3 = layer2;
    serpent_ctr_apply(&keys.k3_enc, &nonce3, &mut layer3)?;
    let mac = hmac_sha256(&keys.k3_mac, &nonce3, aad, &layer3);

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
            let c = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = XNonce::from_slice(nonce_bytes);
            let t = Tag::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, &mut plain, t)
             .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::DeoxysII256 => {
            use deoxys::aead::{KeyInit as _, AeadInPlace as _, Tag};
            let c = DeoxysII256::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = deoxys::aead::Nonce::<DeoxysII256>::from_slice(nonce_bytes);
            let t = Tag::<DeoxysII256>::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, &mut plain, t)
             .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::Serpent256 => {
            use eax::aead::{KeyInit as _, AeadInPlace as _, Tag};
            let c = SerpentEax::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = eax::aead::Nonce::<SerpentEax>::from_slice(nonce_bytes);
            let t = Tag::<SerpentEax>::from_slice(tag_bytes);
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
    use subtle::ConstantTimeEq;
    if mac_actual.ct_eq(mac_expected).unwrap_u8() == 0 {
        return Err(VnmError::AuthenticationFailed);
    }
    let mut layer2 = layer3_ct.to_vec();
    serpent_ctr_apply(&keys.k3_enc, nonce3, &mut layer2)?;

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

    Ok(layer2)
}

// ── decrypt_block_into_32 ──────────────────────────────────────────────────────

pub fn decrypt_block_into_32(
    key:    &[u8; 32],
    cipher: CipherAlgorithm,
    aad:    &[u8],
    data:   &[u8],
    out:    &mut [u8; 32],
) -> crate::Result<()> {
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
            let c = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = XNonce::from_slice(nonce_bytes);
            let t = Tag::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, out.as_mut_slice(), t)
             .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::DeoxysII256 => {
            use deoxys::aead::{KeyInit as _, AeadInPlace as _, Tag};
            let c = DeoxysII256::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = deoxys::aead::Nonce::<DeoxysII256>::from_slice(nonce_bytes);
            let t = Tag::<DeoxysII256>::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, out.as_mut_slice(), t)
             .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::Serpent256 => {
            use eax::aead::{KeyInit as _, AeadInPlace as _, Tag};
            let c = SerpentEax::new_from_slice(key)
                .map_err(|e| VnmError::CipherError(e.to_string()))?;
            let n = eax::aead::Nonce::<SerpentEax>::from_slice(nonce_bytes);
            let t = Tag::<SerpentEax>::from_slice(tag_bytes);
            c.decrypt_in_place_detached(n, aad, out.as_mut_slice(), t)
             .map_err(|_| VnmError::AuthenticationFailed)?;
        }
        CipherAlgorithm::Triple => unreachable!(),
    }
    Ok(())
}
