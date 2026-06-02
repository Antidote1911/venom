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

use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Mutex;

use rand::RngCore;

use crate::{Result, VnmError};
use crate::container::{CipherAlgorithm, HEADER_REGION_SIZE, SLOT_SIZE};
use crate::crypto::{decrypt_block, encrypt_block};

/// Maximum bytes available for user data in a slot (payload capacity).
/// SLOT_SIZE minus the VNMB block overhead (magic 4 + version 4 + nonce 12 + tag 16 = 36).
pub const SLOT_PAYLOAD_CAPACITY: usize = SLOT_SIZE - 36;

pub struct SlotStore {
    file:        Mutex<std::fs::File>,
    master_key:  [u8; 32],
    cipher:      CipherAlgorithm,
    /// Inclusive lower bound of this volume's slots (0 for outer, outer_limit for hidden).
    pub slot_start: u64,
    /// Exclusive upper bound of this volume's slots.
    pub slot_limit: u64,
    /// The slot index used to persist the free list (slot 0 for outer, slot_limit-1 for hidden).
    alloc_slot:  u64,
    /// In-memory sorted free list (descending so pop() = lowest free slot).
    pub free:    Mutex<Vec<u64>>,
}

impl SlotStore {
    pub fn new(
        file: std::fs::File,
        master_key: [u8; 32],
        cipher: CipherAlgorithm,
        slot_start: u64,
        slot_limit: u64,
        alloc_slot: u64,
    ) -> Self {
        Self {
            file: Mutex::new(file),
            master_key,
            cipher,
            slot_start,
            slot_limit,
            alloc_slot,
            free: Mutex::new(vec![]),
        }
    }

    // ── Slot I/O ─────────────────────────────────────────────────────────────

    fn slot_offset(slot: u64) -> u64 {
        HEADER_REGION_SIZE + slot * SLOT_SIZE as u64
    }

    /// Encrypt `plaintext` and write it to `slot`.
    ///
    /// Layout on disk (SLOT_SIZE bytes):
    ///   [0..4]        u32 LE  — length of the encrypted blob
    ///   [4..4+len]    encrypted blob (VNMB header + ciphertext + AEAD tag)
    ///   [4+len..]     zero padding to fill SLOT_SIZE
    pub fn write(&self, slot: u64, plaintext: &[u8]) -> Result<()> {
        let aad = slot.to_le_bytes();
        let encrypted = encrypt_block(&self.master_key, self.cipher, &aad, plaintext)?;

        if encrypted.len() + 4 > SLOT_SIZE {
            return Err(VnmError::Serialization("plaintext too large for one slot".into()));
        }

        let mut buf = vec![0u8; SLOT_SIZE];
        let len = encrypted.len() as u32;
        buf[0..4].copy_from_slice(&len.to_le_bytes());
        buf[4..4 + encrypted.len()].copy_from_slice(&encrypted);

        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(Self::slot_offset(slot)))?;
        f.write_all(&buf)?;
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

        let aad = slot.to_le_bytes();
        decrypt_block(&self.master_key, self.cipher, &aad, &buf[4..4 + len])
            .map_err(|_| VnmError::CorruptedSlot(slot, "authentication failed".into()))
    }

    /// Overwrite `slot` with random bytes (called on free for forward secrecy).
    pub fn wipe(&self, slot: u64) -> Result<()> {
        let mut buf = vec![0u8; SLOT_SIZE];
        rand::thread_rng().fill_bytes(&mut buf);
        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(Self::slot_offset(slot)))?;
        f.write_all(&buf)?;
        Ok(())
    }

    // ── Allocation ────────────────────────────────────────────────────────────

    /// Allocate a free slot. Returns its index.
    pub fn alloc(&self) -> Result<u64> {
        let mut free = self.free.lock().unwrap();
        free.pop().ok_or(VnmError::NoSpaceLeft)
    }

    /// Return a slot to the free list (wipes it for forward secrecy).
    pub fn free_slot(&self, slot: u64) {
        let _ = self.wipe(slot);
        let mut free = self.free.lock().unwrap();
        // Keep sorted descending so pop() gives the lowest-numbered free slot.
        let pos = free.partition_point(|&s| s > slot);
        free.insert(pos, slot);
    }

    /// Load the allocation state from disk into the in-memory free list.
    ///
    /// On-disk format (inside the alloc slot's plaintext payload):
    ///   [0..8]  total_slots u64 LE  (number of bits in the bitmap)
    ///   [8..]   bitmap: bit `i` = 1 → slot (slot_start + i) is FREE
    ///
    /// A bitmap of N slots uses ceil(N/8) bytes. For 1 M slots that's 128 KB,
    /// which exceeds one slot (32 KB). Venom therefore caps usable volume size
    /// at (SLOT_SIZE − 4 prefix − 36 crypto − 8 header) × 8 × SLOT_SIZE ≈ 8 GB
    /// per volume. Larger containers are rejected at creation time.
    pub fn load_free_list(&self) -> Result<()> {
        match self.read(self.alloc_slot) {
            Ok(data) if data.len() >= 8 => {
                let n = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
                let bitmap = &data[8..];
                let mut list: Vec<u64> = Vec::new();
                for i in 0..n {
                    if (bitmap[i / 8] >> (i % 8)) & 1 == 1 {
                        list.push(self.slot_start + i as u64);
                    }
                }
                // Sort descending so pop() yields the lowest-numbered free slot.
                list.sort_unstable_by(|a, b| b.cmp(a));
                *self.free.lock().unwrap() = list;
            }
            _ => {
                // Fresh container — every slot except the alloc block is free.
                self.rebuild_free_list();
            }
        }
        Ok(())
    }

    /// Persist the in-memory free list as a compact bitmap.
    pub fn save_free_list(&self) -> Result<()> {
        let free = self.free.lock().unwrap();
        let n    = (self.slot_limit - self.slot_start) as usize;
        let mut bitmap = vec![0u8; (n + 7) / 8];
        for &slot in free.iter() {
            let i = (slot - self.slot_start) as usize;
            bitmap[i / 8] |= 1 << (i % 8);
        }
        let mut data = Vec::with_capacity(8 + bitmap.len());
        data.extend_from_slice(&(n as u64).to_le_bytes());
        data.extend_from_slice(&bitmap);
        drop(free); // release lock before writing to disk
        self.write(self.alloc_slot, &data)
    }

    /// Rebuild the in-memory free list assuming no slots are allocated
    /// (used for fresh containers, before root dir is written).
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
