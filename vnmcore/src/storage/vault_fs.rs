use serde::{Deserialize, Serialize};

/// Logical type of a filesystem node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Directory,
    File,
    FileContinuation,
}

/// A single directory entry: name → slot mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub slot: u64,
    pub kind: NodeKind,
}

/// Content stored inside a directory slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryBlock {
    pub kind:    NodeKind,
    pub entries: Vec<DirEntry>,
}

/// Content stored inside a file slot (first block of a file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBlock {
    pub kind: NodeKind,
    /// Total file size in bytes (used to trim padding on the last block).
    pub total_size: u64,
    /// Ordered list of continuation slot indices (empty if file fits in one slot).
    pub continuation_slots: Vec<u64>,
    /// Inline payload — first `SLOT_PAYLOAD_CAPACITY` bytes of the file.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Decoded representation of any slot's plaintext payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultNode {
    Directory(DirectoryBlock),
    File(FileBlock),
}
