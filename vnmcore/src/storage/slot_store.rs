//! Slot-based block store backed by a single container file.
//!
//! The file layout is:
//!
//!   [0..HEADER_REGION_SIZE]     Two 512-byte headers (outer + hidden)
//!   [HEADER_REGION_SIZE..]      Data area: slots 0..total_slots
//!
//! Slot addresses within a volume:
//!   Outer: slots [0..outer_limit)   — slot 0 = outer allocation block
//!   Hidden: slots [outer_limit..total_slots)  — last slot = hidden alloc block
//!
//! Free lists are kept in memory and persisted to the allocation block on flush.
//!
//! ## Allocation block format (has_generation = true)
//!
//!   [0..8]   n: u64 LE — total slot count
//!   [8..16]  generation: u64 LE — anti-rollback counter
//!   [16..48] merkle_root: [u8; 32] — BLAKE3 Merkle root over used slots
//!            All-zero root means "not yet computed"; verification is skipped.
//!   [48..]   bitmap: bit i = 1 → slot (slot_start + i) is FREE
//!
//! Legacy format (has_generation = false):
//!   [0..8]   n: u64 LE
//!   [8..]    bitmap

use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rand::RngCore;
use crate::locked_memory::LockedMemory;

use crate::{Result, VnmError};
use crate::container::{CipherAlgorithm, DATA_AREA_OFFSET, SLOT_SIZE};
use crate::crypto::{decrypt_block, encrypt_block};
use crate::storage::merkle::compute_merkle_root;

/// Maximum bytes available for user data in a slot (payload capacity).
/// SLOT_SIZE minus the VNMB block overhead (magic 4 + version 4 + nonce 12 + tag 16 = 36).
pub const SLOT_PAYLOAD_CAPACITY: usize = SLOT_SIZE - 36;

/// Byte size of the generation + merkle prefix in the alloc block (has_generation = true).
const ALLOC_HEADER_LEN: usize = 8 + 8 + 32; // n + gen + merkle_root

pub struct SlotStore {
    file:        Mutex<std::fs::File>,
    master_key:  LockedMemory<[u8; 32]>,
    cipher:      CipherAlgorithm,
    pub slot_start: u64,
    pub slot_limit: u64,
    alloc_slot:  u64,
    pub free:    Mutex<Vec<u64>>,
    generation:  AtomicU64,
    has_generation: bool,
    /// Cached Merkle root — updated by `update_merkle_root()`, included in alloc block by `save_free_list()`.
    cached_merkle_root: Mutex<[u8; 32]>,
    /// Set whenever a slot is written or wiped; cleared after `update_merkle_root()`.
    merkle_dirty: AtomicBool,
}

impl SlotStore {
    pub fn new(
        file: std::fs::File,
        master_key: LockedMemory<[u8; 32]>,
        cipher: CipherAlgorithm,
        slot_start: u64,
        slot_limit: u64,
        alloc_slot: u64,
        has_generation: bool,
    ) -> Self {
        Self {
            file: Mutex::new(file),
            master_key,
            cipher,
            slot_start,
            slot_limit,
            alloc_slot,
            free: Mutex::new(vec![]),
            generation: AtomicU64::new(0),
            has_generation,
            cached_merkle_root: Mutex::new([0u8; 32]),
            merkle_dirty: AtomicBool::new(false),
        }
    }

    // ── Slot I/O ─────────────────────────────────────────────────────────────

    fn slot_offset(slot: u64) -> u64 {
        DATA_AREA_OFFSET + slot * SLOT_SIZE as u64
    }

    /// Derive a slot-specific 32-byte key from K_master and the slot index.
    ///
    /// Using a per-slot key means that a cipher-level compromise of one slot's
    /// key does not expose K_master or any other slot's key.
    /// The slot index is also kept as AEAD AAD for an independent binding layer.
    fn derive_slot_key(&self, slot: u64) -> [u8; 32] {
        let mut ikm = [0u8; 40]; // K_master(32) || slot_index_le8(8)
        ikm[..32].copy_from_slice(&*self.master_key);
        ikm[32..].copy_from_slice(&slot.to_le_bytes());
        blake3::derive_key("venom:slot:v1", &ikm)
    }

    /// Encrypt `plaintext` and write it to `slot`.
    pub fn write(&self, slot: u64, plaintext: &[u8]) -> Result<()> {
        let slot_key = self.derive_slot_key(slot);
        let aad      = slot.to_le_bytes();
        let encrypted = encrypt_block(&slot_key, self.cipher, &aad, plaintext)?;

        if encrypted.len() + 4 > SLOT_SIZE {
            return Err(VnmError::Serialization("plaintext too large for one slot".into()));
        }

        let mut buf = vec![0u8; SLOT_SIZE];
        let len = encrypted.len() as u32;
        buf[0..4].copy_from_slice(&len.to_le_bytes());
        buf[4..4 + encrypted.len()].copy_from_slice(&encrypted);

        {
            let mut f = self.file.lock().unwrap();
            f.seek(SeekFrom::Start(Self::slot_offset(slot)))?;
            f.write_all(&buf)?;
        }
        self.merkle_dirty.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Read and decrypt `slot`. Returns decrypted plaintext.
    pub fn read(&self, slot: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; SLOT_SIZE];
        {
            let mut f = self.file.lock().unwrap();
            f.seek(SeekFrom::Start(Self::slot_offset(slot)))?;
            f.read_exact(&mut buf)?;
        }

        let len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        if len < 36 || 4 + len > SLOT_SIZE {
            return Err(VnmError::CorruptedSlot(slot, "invalid length prefix".into()));
        }

        let slot_key = self.derive_slot_key(slot);
        let aad      = slot.to_le_bytes();
        decrypt_block(&slot_key, self.cipher, &aad, &buf[4..4 + len])
            .map_err(|_| VnmError::CorruptedSlot(slot, "authentication failed".into()))
    }

    /// Overwrite `slot` with random bytes (called on free for forward secrecy).
    pub fn wipe(&self, slot: u64) -> Result<()> {
        let mut buf = vec![0u8; SLOT_SIZE];
        rand::thread_rng().fill_bytes(&mut buf);
        {
            let mut f = self.file.lock().unwrap();
            f.seek(SeekFrom::Start(Self::slot_offset(slot)))?;
            f.write_all(&buf)?;
        }
        self.merkle_dirty.store(true, Ordering::Relaxed);
        Ok(())
    }

    // ── Allocation ────────────────────────────────────────────────────────────

    pub fn alloc(&self) -> Result<u64> {
        let mut free = self.free.lock().unwrap();
        free.pop().ok_or(VnmError::NoSpaceLeft)
    }

    pub fn free_slot(&self, slot: u64) {
        let _ = self.wipe(slot);
        let mut free = self.free.lock().unwrap();
        let pos = free.partition_point(|&s| s > slot);
        free.insert(pos, slot);
    }

    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    // ── Merkle helpers ────────────────────────────────────────────────────────

    /// Return sorted ascending list of used data slots (excluding the alloc slot).
    fn used_slots(&self) -> Vec<u64> {
        let free_set: std::collections::HashSet<u64> = self.free.lock().unwrap().iter().copied().collect();
        (self.slot_start..self.slot_limit)
            .filter(|&s| s != self.alloc_slot && !free_set.contains(&s))
            .collect()
    }

    /// Read all used slots from disk, compute BLAKE3 Merkle root, cache it.
    /// Sets `merkle_dirty = false` on success.
    pub fn update_merkle_root(&self) -> Result<()> {
        let used = self.used_slots();
        let root = {
            let mut f = self.file.lock().unwrap();
            compute_merkle_root(&mut *f, &used)?
        };
        *self.cached_merkle_root.lock().unwrap() = root;
        self.merkle_dirty.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Returns true if `merkle_dirty` is set (a slot was written or wiped since last update).
    pub fn is_merkle_dirty(&self) -> bool {
        self.merkle_dirty.load(Ordering::Relaxed)
    }

    // ── Free list persistence ─────────────────────────────────────────────────

    /// Load the allocation state from disk into the in-memory free list.
    /// For containers with a stored non-zero Merkle root, verifies integrity.
    pub fn load_free_list(&self) -> Result<()> {
        let min_len = if self.has_generation { ALLOC_HEADER_LEN } else { 8 };
        match self.read(self.alloc_slot) {
            Ok(data) if data.len() >= min_len => {
                let n = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;

                let (gen, stored_root, bitmap) = if self.has_generation {
                    let g = u64::from_le_bytes(data[8..16].try_into().unwrap());
                    let root: [u8; 32] = data[16..48].try_into().unwrap();
                    (g, root, &data[48..])
                } else {
                    (0u64, [0u8; 32], &data[8..])
                };

                self.generation.store(gen, Ordering::Relaxed);
                *self.cached_merkle_root.lock().unwrap() = stored_root;

                // Rebuild free list from bitmap
                let mut list: Vec<u64> = Vec::new();
                for i in 0..n {
                    if bitmap.get(i / 8).map(|b| (b >> (i % 8)) & 1 == 1).unwrap_or(false) {
                        list.push(self.slot_start + i as u64);
                    }
                }
                list.sort_unstable_by(|a, b| b.cmp(a));
                *self.free.lock().unwrap() = list;

                // Verify Merkle root if it was stored (non-zero root = was computed at least once)
                if self.has_generation && stored_root != [0u8; 32] {
                    let used = self.used_slots();
                    let computed = {
                        let mut f = self.file.lock().unwrap();
                        compute_merkle_root(&mut *f, &used)?
                    };
                    if computed != stored_root {
                        return Err(VnmError::MerkleIntegrityFailure);
                    }
                }
            }
            _ => {
                self.rebuild_free_list();
            }
        }
        Ok(())
    }

    /// Persist the in-memory free list, generation counter, and cached Merkle root.
    pub fn save_free_list(&self) -> Result<()> {
        let free = self.free.lock().unwrap();
        let n    = (self.slot_limit - self.slot_start) as usize;
        let mut bitmap = vec![0u8; (n + 7) / 8];
        for &slot in free.iter() {
            let i = (slot - self.slot_start) as usize;
            bitmap[i / 8] |= 1 << (i % 8);
        }
        let new_gen = if self.has_generation {
            self.generation.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            0
        };

        let mut data = Vec::with_capacity(ALLOC_HEADER_LEN + bitmap.len());
        data.extend_from_slice(&(n as u64).to_le_bytes());
        if self.has_generation {
            data.extend_from_slice(&new_gen.to_le_bytes());
            data.extend_from_slice(self.cached_merkle_root.lock().unwrap().as_ref());
        }
        data.extend_from_slice(&bitmap);
        drop(free);
        self.write(self.alloc_slot, &data)
    }

    pub fn rebuild_free_list(&self) {
        let mut list: Vec<u64> = (self.slot_start..self.slot_limit)
            .filter(|&s| s != self.alloc_slot)
            .collect();
        list.sort_unstable_by(|a, b| b.cmp(a));
        *self.free.lock().unwrap() = list;
    }

    pub fn flush_file(&self) -> Result<()> {
        self.file.lock().unwrap().flush()?;
        Ok(())
    }
}
