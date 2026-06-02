use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;
use crate::{Result, VnmError};
use crate::container::KdfParams;
use super::keys::DerivedKey;

/// Generate a cryptographically random 32-byte salt, hex-encoded.
pub fn generate_salt() -> String {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    hex::encode(salt)
}

/// Derive a 32-byte key from `password` using the vault's Argon2id parameters.
pub fn derive_key(password: &[u8], params: &KdfParams) -> Result<DerivedKey> {
    let salt_bytes = hex::decode(&params.salt)
        .map_err(|_| VnmError::KdfError("invalid salt hex".into()))?;

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| VnmError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password, &salt_bytes, &mut output)
        .map_err(|e| VnmError::KdfError(e.to_string()))?;

    Ok(DerivedKey::new(output))
}
