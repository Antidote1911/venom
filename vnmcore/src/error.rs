use thiserror::Error;

#[derive(Debug, Error)]
pub enum VnmError {
    #[error("Wrong password or corrupted vault")]
    AuthenticationFailed,

    #[error("Vault not found at path: {0}")]
    VaultNotFound(String),

    #[error("Vault already exists at path: {0}")]
    VaultAlreadyExists(String),

    #[error("Block not found: {0}")]
    BlockNotFound(String),

    #[error("Corrupted block: {0}")]
    CorruptedBlock(String),

    #[error("Invalid vault config: {0}")]
    InvalidConfig(String),

    #[error("Cipher error: {0}")]
    CipherError(String),

    #[error("KDF error: {0}")]
    KdfError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Vault is already mounted")]
    AlreadyMounted,

    #[error("Vault is not mounted")]
    NotMounted,

    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),
}
