use serde::{Deserialize, Serialize};

/// Discriminant stored inside every encrypted block to know its role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Directory,
    File,
    /// A continuation block for files larger than one block
    FileContinuation,
}

/// A single directory entry (name → block UUID mapping).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub block_id: String,
    pub kind: NodeKind,
}

/// Content of a directory block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryBlock {
    pub kind: NodeKind, // always NodeKind::Directory
    pub entries: Vec<DirEntry>,
}

/// Content of a file block (first block of a file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBlock {
    pub kind: NodeKind, // NodeKind::File
    /// Total file size in bytes (used to trim padding on last block)
    pub total_size: u64,
    /// Ordered list of continuation block UUIDs (empty if file fits in one block)
    pub continuation_ids: Vec<String>,
    /// Inline payload — contains the first `block_size - overhead` bytes of the file
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Decoded representation of any block's plaintext payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VaultNode {
    Directory(DirectoryBlock),
    File(FileBlock),
}
