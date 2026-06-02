pub mod container;
pub mod crypto;
pub mod storage;
pub mod fs;
pub mod error;

pub use container::{VaultConfig, VaultHeader, CipherAlgorithm};
pub use crypto::{MasterKey, DerivedKey};
pub use error::VnmError;

pub type Result<T> = std::result::Result<T, VnmError>;
