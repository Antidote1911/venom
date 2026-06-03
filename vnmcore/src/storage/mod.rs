pub mod vault_fs;
pub mod slot_store;
pub mod merkle;

pub use vault_fs::{
    VaultNode, NodeKind, DirEntry, DirectoryBlock,
    FileBlock, FileDataBlock, FileIndexBlock,
    CHUNK_SIZE, MAX_DIRECT_SLOTS, MAX_INDEX_SLOTS,
};
pub use slot_store::{SlotStore, SLOT_PAYLOAD_CAPACITY};
