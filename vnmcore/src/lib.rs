pub mod container;
pub mod crypto;
pub mod storage;
pub mod fs;
pub mod error;

pub use container::{CipherAlgorithm, KdfParams};
pub use fs::container::{VnmContainer, OpenCredential, RecipientInfo, HiddenVolumeOptions};
pub use crypto::kem::{Seed as KemSeed, EncapKey as KemEncapKey, generate as kem_generate, ek_from_seed as kem_ek_from_seed};
pub use crypto::key_file::{
    KeyFileData, PubFileData,
    write_key_file, write_pub_file,
    read_key_file, read_pub_file,
    decode_key_file, decode_pub_file,
    fp_display,
    KEY_FILE_SIZE, PUB_FILE_SIZE,
};
pub use crypto::hybrid_kem::{
    HybridPublicKey, HybridPrivateKey,
    generate as hybrid_generate,
    encapsulate as hybrid_encapsulate,
    decapsulate as hybrid_decapsulate,
};
pub use error::VnmError;

pub type Result<T> = std::result::Result<T, VnmError>;
