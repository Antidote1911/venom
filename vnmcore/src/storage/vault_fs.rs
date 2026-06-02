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

/// Content stored inside a file slot.
///
/// Files are stored as a **singly-linked chain** of slots:
///
///   slot_0  { total_size, next_slot: Some(slot_1), data: chunk_0 }
///   slot_1  { total_size: 0, next_slot: Some(slot_2), data: chunk_1 }
///   …
///   slot_N  { total_size: 0, next_slot: None, data: chunk_N }
///
/// Using a linked list instead of a flat Vec<u64> of continuation indices
/// keeps every slot's payload bounded at ~30 KB regardless of file size,
/// so even multi-GB files work within the 32 KB slot limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBlock {
    pub kind: NodeKind,
    /// Total file size in bytes — meaningful only in the head block (kind = File).
    pub total_size: u64,
    /// Slot index of the next block in the chain, or None if this is the tail.
    pub next_slot: Option<u64>,
    /// Inline payload for this slot.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Decoded representation of any slot's plaintext payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultNode {
    Directory(DirectoryBlock),
    File(FileBlock),
}
