//! ML-KEM-1024 wrapper (NIST FIPS 203 — post-quantum key encapsulation).
//! Security: NIST Category 5, ~256-bit post-quantum.
//!
//! Requires ml-kem feature "getrandom" (random source via OS).
//!
//! Key representations (plain byte arrays for easy serialisation):
//!   Seed  (private key): 64 B  — compact, regenerates the full key pair
//!   EncapKey (public):  1568 B — share with each recipient
//!   Ciphertext:         1568 B — included in the recipient slot on disk
//!   SharedSecret:         32 B — AEAD key used to wrap K_master

use ml_kem::{
    MlKem1024, Seed as MlSeed,
    kem::{Kem, Decapsulate, Encapsulate, KeyExport},
    DecapsulationKey1024, EncapsulationKey1024,
};

use crate::{Result, VnmError};

pub const SEED_SIZE: usize = 64;
pub const EK_SIZE:   usize = 1568;
pub const CT_SIZE:   usize = 1568;
pub const SS_SIZE:   usize = 32;

pub type Seed          = [u8; SEED_SIZE];
pub type EncapKey      = [u8; EK_SIZE];
pub type KemCiphertext = [u8; CT_SIZE];
pub type SharedSecret  = [u8; SS_SIZE];

/// Generate a new ML-KEM-1024 keypair.
/// Returns `(seed, encap_key)`.
pub fn generate() -> (Seed, EncapKey) {
    let (dk, ek) = MlKem1024::generate_keypair();
    let seed: Seed = dk.to_bytes().as_slice().try_into().expect("seed 64B");
    let ek_b: EncapKey = ek.to_bytes().as_slice().try_into().expect("ek 1568B");
    (seed, ek_b)
}

/// Reconstruct the public encapsulation key from a 64-byte seed.
pub fn ek_from_seed(seed: &Seed) -> EncapKey {
    let ml_seed = MlSeed::from(*seed);
    let dk = DecapsulationKey1024::from_seed(ml_seed);
    dk.encapsulation_key().to_bytes().as_slice().try_into().expect("ek 1568B")
}

/// Encapsulate: produce (ciphertext, shared_secret) for the recipient holding `ek`.
pub fn encapsulate(ek_bytes: &EncapKey) -> Result<(KemCiphertext, SharedSecret)> {
    let key_arr = (*ek_bytes).into();
    let ek = EncapsulationKey1024::new(&key_arr)
        .map_err(|_| VnmError::CipherError("invalid ML-KEM public key".into()))?;
    let (ct, ss) = ek.encapsulate();
    let ct_b: KemCiphertext = <[u8; CT_SIZE]>::try_from(ct.as_ref())
        .map_err(|_| VnmError::CipherError("CT size mismatch".into()))?;
    let ss_b: SharedSecret  = <[u8; SS_SIZE]>::try_from(ss.as_ref())
        .map_err(|_| VnmError::CipherError("SS size mismatch".into()))?;
    Ok((ct_b, ss_b))
}

/// Decapsulate: recover the shared secret from seed + ciphertext.
pub fn decapsulate(seed: &Seed, ct_bytes: &KemCiphertext) -> Result<SharedSecret> {
    let ml_seed = MlSeed::from(*seed);
    let dk = DecapsulationKey1024::from_seed(ml_seed);
    let ct_arr = ml_kem::kem::Ciphertext::<MlKem1024>::from(*ct_bytes);
    let ss = dk.decapsulate(&ct_arr);
    <[u8; SS_SIZE]>::try_from(ss.as_ref())
        .map_err(|_| VnmError::CipherError("SS size mismatch".into()))
}

/// First 8 bytes of BLAKE3(encap_key) — identifies which slot belongs to a given key.
pub fn fingerprint(ek: &EncapKey) -> [u8; 8] {
    blake3::hash(ek.as_ref()).as_bytes()[..8].try_into().unwrap()
}
