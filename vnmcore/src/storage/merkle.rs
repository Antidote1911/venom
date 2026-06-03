//! BLAKE3 Merkle tree over the raw encrypted slot bytes.
//!
//! ## Why raw encrypted bytes?
//!
//! Each slot's ciphertext already carries an AEAD tag — modifications are caught
//! individually by `SlotStore::read()`. The Merkle tree provides a **global**
//! integrity guarantee: the set of slots (identity + order + content) matches
//! the state at last close, detected in O(1) at mount time without reading
//! every slot individually.
//!
//! ## Tree construction
//!
//! Leaves cover the used data slots sorted ascending by index:
//!   `leaf = BLAKE3_derive_key("venom:merkle:leaf:v1", slot_index_le8 || raw_slot_32kb)`
//!
//! Pairs of adjacent nodes are combined bottom-up:
//!   `node = BLAKE3_derive_key("venom:merkle:node:v1", left[32] || right[32])`
//!
//! An odd node at any level is carried up unchanged (same as Bitcoin/RFC 6962).

use std::io::{Read, Seek, SeekFrom};
use crate::container::{DATA_AREA_OFFSET, SLOT_SIZE};

const LEAF_CTX: &str = "venom:merkle:leaf:v1";
const NODE_CTX: &str = "venom:merkle:node:v1";

/// Compute the BLAKE3 Merkle root over `used_slots` (sorted ascending).
///
/// Reads raw 32 KB slot bytes directly from the file — no decryption.
/// Returns `[0u8; 32]` if `used_slots` is empty.
pub fn compute_merkle_root<F: Read + Seek>(
    file: &mut F,
    used_slots: &[u64],
) -> std::io::Result<[u8; 32]> {
    if used_slots.is_empty() {
        return Ok([0u8; 32]);
    }

    let mut raw = vec![0u8; SLOT_SIZE];
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(used_slots.len());

    for &slot in used_slots {
        let offset = DATA_AREA_OFFSET + slot * SLOT_SIZE as u64;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut raw)?;

        let mut h = blake3::Hasher::new_derive_key(LEAF_CTX);
        h.update(&slot.to_le_bytes());
        h.update(&raw);
        leaves.push(*h.finalize().as_bytes());
    }

    // Build tree bottom-up; odd node at each level is carried up unchanged.
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        let mut i = 0;
        while i < leaves.len() {
            if i + 1 < leaves.len() {
                let mut h = blake3::Hasher::new_derive_key(NODE_CTX);
                h.update(&leaves[i]);
                h.update(&leaves[i + 1]);
                next.push(*h.finalize().as_bytes());
                i += 2;
            } else {
                next.push(leaves[i]); // carry up odd leaf
                i += 1;
            }
        }
        leaves = next;
    }

    Ok(leaves[0])
}
