pub mod container;
pub mod crypto;
pub mod storage;
pub mod fs;
pub mod error;

pub use container::{CipherAlgorithm, KdfParams};
pub use fs::container::{VnmContainer, OpenCredential, RecipientInfo, HiddenVolumeOptions};
pub use crypto::kem::{Seed as KemSeed, EncapKey as KemEncapKey, generate as kem_generate, ek_from_seed as kem_ek_from_seed};
pub use crypto::key_file::{
    PubKeyFile, PrivKeyFile,
    write_pub_file, write_priv_file,
    read_pub_file, read_priv_file,
    decode_pub, decode_priv,
    fp_display, fp_short,
    PUB_FILE_SIZE, PRIV_FILE_SIZE,
};
pub use error::VnmError;

pub type Result<T> = std::result::Result<T, VnmError>;
