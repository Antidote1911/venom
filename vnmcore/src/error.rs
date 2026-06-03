use thiserror::Error;

#[derive(Debug, Error)]
pub enum VnmError {
    #[error("Wrong password or corrupted container")]
    AuthenticationFailed,

    #[error("Container not found: {0}")]
    ContainerNotFound(String),

    #[error("Container already exists: {0}")]
    ContainerAlreadyExists(String),

    #[error("Slot not found: {0}")]
    SlotNotFound(u64),

    #[error("Corrupted slot {0}: {1}")]
    CorruptedSlot(u64, String),

    #[error("Invalid container format: {0}")]
    InvalidFormat(String),

    #[error("No space left in container")]
    NoSpaceLeft,

    #[error("Cipher error: {0}")]
    CipherError(String),

    #[error("KDF error: {0}")]
    KdfError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Container is already mounted")]
    AlreadyMounted,

    #[error("Container is not mounted")]
    NotMounted,

    #[error("Requested size is too small (minimum {0} bytes)")]
    SizeTooSmall(u64),

    #[error("Rollback detected: container generation {current_gen} < last known {expected_gen} — the container may have been replaced with an older copy")]
    RollbackDetected { current_gen: u64, expected_gen: u64 },

    #[error("Merkle integrity check failed — one or more encrypted slots were modified or removed since last close")]
    MerkleIntegrityFailure,
}
