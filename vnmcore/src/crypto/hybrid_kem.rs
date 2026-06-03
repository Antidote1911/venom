//! Hybrid post-quantum key encapsulation: X25519 + ML-KEM-1024.
//!
//! Neither component is derived from the other — both are independently generated.
//! Security holds as long as at least ONE of the two algorithms is secure:
//!   • X25519 is broken by Shor's algorithm on a quantum computer → ML-KEM still holds
//!   • ML-KEM has a classical cryptanalysis flaw → X25519 still holds
//!
//! ## Shared-secret derivation
//!
//!   hybrid_key = BLAKE3_derive_key(
//!       context  = "venom:hybrid:v1"   ← BLAKE3 domain separator (hashed with distinct IV)
//!       material = x25519_shared    (32 B)
//!                || mlkem_ss         (32 B)
//!                || x25519_eph_pk    (32 B, binds ciphertext)
//!                || mlkem_ct         (1568 B, binds ciphertext)
//!   )
//!
//! The ciphertexts are included to prevent key-commitment attacks and ensure
//! the hybrid_key is bound to the specific encapsulation.
//! BLAKE3's derive_key() hashes the context string with a distinct IV, providing
//! stronger domain separation than prepending a label to a plain hash input.

use sha2::{Sha256, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub, StaticSecret};


use crate::Result;
use crate::crypto::kem::{Seed as MlKemSeed, EncapKey as MlKemEncapKey, CT_SIZE};

pub const X25519_SK_SIZE: usize = 32;
pub const X25519_PK_SIZE: usize = 32;

/// Public portion — safe to share in a .pub file.
#[derive(Clone)]
pub struct HybridPublicKey {
    pub x25519_pk: [u8; X25519_PK_SIZE],
    pub mlkem_ek:  MlKemEncapKey,
}

impl HybridPublicKey {
    /// Fingerprint = SHA-256(x25519_pk || mlkem_ek)[0..8].
    pub fn fingerprint(&self) -> [u8; 8] {
        let mut h = Sha256::new();
        h.update(&self.x25519_pk);
        h.update(&self.mlkem_ek);
        h.finalize()[..8].try_into().unwrap()
    }
}

/// Private portion — keep secret in a .key file.
#[derive(Clone)]
pub struct HybridPrivateKey {
    pub x25519_sk: [u8; X25519_SK_SIZE],
    pub mlkem_seed: MlKemSeed,
    /// Cached public key (stored alongside private for convenience; always rederivable).
    pub public: HybridPublicKey,
}

impl HybridPrivateKey {
    pub fn fingerprint(&self) -> [u8; 8] { self.public.fingerprint() }
}

/// Generate a new hybrid keypair. Both components are independently random.
pub fn generate() -> HybridPrivateKey {
    // X25519 keypair
    let x25519_sk_bytes = {
        let sk = StaticSecret::random_from_rng(rand::thread_rng());
        sk.to_bytes()
    };
    let x25519_pk: [u8; 32] = {
        let sk = StaticSecret::from(x25519_sk_bytes);
        X25519Pub::from(&sk).to_bytes()
    };

    // ML-KEM-1024 keypair (independent random seed)
    use crate::crypto::kem;
    let (mlkem_seed, mlkem_ek) = kem::generate();

    HybridPrivateKey {
        x25519_sk: x25519_sk_bytes,
        mlkem_seed,
        public: HybridPublicKey { x25519_pk, mlkem_ek },
    }
}

/// Encapsulation output — stored in the recipient slot.
pub struct HybridCiphertext {
    pub x25519_eph_pk: [u8; X25519_PK_SIZE],
    pub mlkem_ct:      [u8; CT_SIZE],
    /// 32-byte shared secret — used as AEAD key to wrap K_master.
    pub shared_secret: [u8; 32],
}

/// Encapsulate a shared secret for `recipient`.
/// The caller uses `shared_secret` to AEAD-wrap K_master.
pub fn encapsulate(recipient: &HybridPublicKey) -> Result<HybridCiphertext> {
    // X25519 ephemeral
    let eph_sk = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_pk = X25519Pub::from(&eph_sk);
    let recipient_x25519 = X25519Pub::from(recipient.x25519_pk);
    let x25519_shared: [u8; 32] = eph_sk.diffie_hellman(&recipient_x25519).to_bytes();
    let x25519_eph_pk_bytes = eph_pk.to_bytes();

    // ML-KEM-1024
    let (mlkem_ct, mlkem_ss) = crate::crypto::kem::encapsulate(&recipient.mlkem_ek)?;

    // Combine
    let shared_secret = combine(&x25519_shared, &mlkem_ss, &x25519_eph_pk_bytes, &mlkem_ct);

    Ok(HybridCiphertext {
        x25519_eph_pk: x25519_eph_pk_bytes,
        mlkem_ct,
        shared_secret,
    })
}

/// Decapsulate — recover the shared secret using the private key.
pub fn decapsulate(
    private:       &HybridPrivateKey,
    x25519_eph_pk: &[u8; X25519_PK_SIZE],
    mlkem_ct:      &[u8; CT_SIZE],
) -> Result<[u8; 32]> {
    // X25519
    let sk = StaticSecret::from(private.x25519_sk);
    let eph_pk = X25519Pub::from(*x25519_eph_pk);
    let x25519_shared: [u8; 32] = sk.diffie_hellman(&eph_pk).to_bytes();

    // ML-KEM-1024
    let mlkem_ss = crate::crypto::kem::decapsulate(&private.mlkem_seed, mlkem_ct)?;

    Ok(combine(&x25519_shared, &mlkem_ss, x25519_eph_pk, mlkem_ct))
}

/// BLAKE3 domain-separated combination of the two shared secrets.
fn combine(
    x25519_ss:  &[u8; 32],
    mlkem_ss:   &[u8; 32],
    eph_pk:     &[u8; 32],
    mlkem_ct:   &[u8; CT_SIZE],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + CT_SIZE);
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(eph_pk);
    ikm.extend_from_slice(mlkem_ct.as_ref());
    blake3::derive_key("venom:hybrid:v1", &ikm)
}
