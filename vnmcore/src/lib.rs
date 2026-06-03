pub mod container;
pub mod crypto;
pub mod storage;
pub mod fs;
pub mod error;
pub mod rollback;
pub mod locked_memory;

pub use container::{CipherAlgorithm, KdfParams};
pub use fs::container::{VnmContainer, OpenCredential, RecipientInfo, HiddenVolumeOptions};
pub use crypto::kem::{Seed as KemSeed, EncapKey as KemEncapKey, generate as kem_generate, ek_from_seed as kem_ek_from_seed};
pub use crypto::key_file::{
    KeyFileData, KeyPublicData, PubFileData,
    write_key_file, write_key_file_protected, write_pub_file,
    read_key_file, read_key_file_protected, read_key_public, read_pub_file,
    decode_key_file, decode_key_file_with_passphrase, decode_pub_file,
    read_public_from_key_bytes,
    fp_display,
    KEY_FILE_SIZE, KEY_FILE_PROTECTED_SIZE, PUB_FILE_SIZE,
};
pub use crypto::hybrid_kem::{
    HybridPublicKey, HybridPrivateKey,
    generate as hybrid_generate,
    encapsulate as hybrid_encapsulate,
    decapsulate as hybrid_decapsulate,
};
pub use error::VnmError;

pub type Result<T> = std::result::Result<T, VnmError>;
