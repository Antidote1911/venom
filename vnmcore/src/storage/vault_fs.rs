use serde::{Deserialize, Serialize};

/// Bytes of user data per chunk (head inline or continuation slot).
pub const CHUNK_SIZE: usize = 30_000;

/// Max continuation-slot ids stored directly in the head FileBlock before
/// spilling into a FileIndexBlock chain (~4 000 × 30 KB ≈ 120 MB per head).
pub const MAX_DIRECT_SLOTS: usize = 4_000;

/// Max slot ids per FileIndexBlock (fills ~32 KB payload / 8 bytes each).
pub const MAX_INDEX_SLOTS: usize = 4_080;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Directory,
    File,      // head slot: metadata + chunk 0 inline
    FileData,  // continuation chunk
    FileIndex, // overflow slot-id index
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub slot: u64,
    pub kind: NodeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryBlock {
    pub kind:    NodeKind,
    pub entries: Vec<DirEntry>,
}

/// Head slot of a file.
///
/// Stores file metadata and the ordered index of continuation-slot ids.
/// Chunk 0 data is stored inline in `data`; chunks 1..N live in `data_slots`.
/// For files larger than MAX_DIRECT_SLOTS + 1 chunks the overflow index chains
/// through FileIndexBlock slots via `index_chain`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBlock {
    pub kind:        NodeKind,    // File
    pub total_size:  u64,
    /// Slot ids for continuation chunks 1, 2, … (chunk 0 is inline in `data`).
    pub data_slots:  Vec<u64>,
    /// First overflow FileIndexBlock slot, or None if all ids fit in data_slots.
    pub index_chain: Option<u64>,
    /// Inline payload for chunk 0 (≤ CHUNK_SIZE bytes).
    #[serde(with = "serde_bytes")]
    pub data:        Vec<u8>,
}

/// Continuation data chunk — stores bytes for one chunk of a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDataBlock {
    pub kind: NodeKind, // FileData
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Overflow index slot for files with more than MAX_DIRECT_SLOTS continuation chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndexBlock {
    pub kind:       NodeKind, // FileIndex
    pub slot_ids:   Vec<u64>,
    pub next_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultNode {
    Directory(DirectoryBlock),
    File(FileBlock),
    FileData(FileDataBlock),
    FileIndex(FileIndexBlock),
}
