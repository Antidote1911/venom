//! High-level container API.
//!
//! A VnmContainer wraps a SlotStore and exposes typed read/write operations
//! on VaultNodes (directory/file blocks). It handles both outer and hidden
//! volumes transparently — the caller just provides a password and gets the
//! correct volume.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::OpenOptions;

use rand::RngCore;

use crate::{Result, VnmError};
use crate::container::{
    CipherAlgorithm, HeaderPayload, KdfParams, HEADER_REGION_SIZE, SLOT_SIZE,
    encode_header_with_password, decode_header,
    OUTER_HEADER_OFFSET, HIDDEN_HEADER_OFFSET,
};
use crate::storage::{SlotStore, VaultNode, NodeKind};
use crate::storage::vault_fs::DirectoryBlock;

const OUTER_ALLOC_SLOT:  u64 = 0;  // slot 0 = outer allocation block

/// Minimum usable container size in bytes.
pub const MIN_SIZE: u64 = HEADER_REGION_SIZE + 16 * SLOT_SIZE as u64; // ≥ 16 slots

/// Options for creating the hidden volume.
pub struct HiddenVolumeOptions<'a> {
    pub password: &'a [u8],
    pub size_bytes: u64,
    pub label: Option<String>,
    pub kdf_profile: &'a str,
}

/// A mounted Venom container (outer or hidden volume).
pub struct VnmContainer {
    pub store: SlotStore,
    pub root_slot: u64,
    pub is_hidden: bool,
    pub cipher: CipherAlgorithm,
    pub total_slots: u64,
    pub outer_limit: u64,
    pub label: Option<String>,
    pub created_at: u64,
    path: PathBuf,
}

impl VnmContainer {
    // ── Create ────────────────────────────────────────────────────────────────

    /// Create a new container file.
    ///
    /// `outer_size_bytes` includes both the outer and hidden volumes.
    /// If `hidden` is provided, the hidden volume occupies the tail of the file
    /// and the outer volume is constrained to the remaining slots.
    pub fn create(
        path: impl AsRef<Path>,
        outer_password: &[u8],
        total_size_bytes: u64,
        cipher: CipherAlgorithm,
        kdf_profile: &str,
        label: Option<String>,
        hidden: Option<HiddenVolumeOptions<'_>>,
    ) -> Result<Self> {
        let path = path.as_ref();

        if path.exists() {
            return Err(VnmError::ContainerAlreadyExists(path.display().to_string()));
        }
        if total_size_bytes < MIN_SIZE {
            return Err(VnmError::SizeTooSmall(MIN_SIZE));
        }

        let total_slots = (total_size_bytes - HEADER_REGION_SIZE) / SLOT_SIZE as u64;

        // Determine outer and hidden slot boundaries.
        let (outer_limit, _hidden_slots) = match &hidden {
            None => (total_slots, 0u64),
            Some(h) => {
                let h_slots = ((h.size_bytes + SLOT_SIZE as u64 - 1) / SLOT_SIZE as u64)
                    .max(2); // at least 2 hidden slots (alloc + root)
                let o_limit = total_slots.saturating_sub(h_slots);
                if o_limit < 2 {
                    return Err(VnmError::SizeTooSmall(MIN_SIZE));
                }
                (o_limit, h_slots)
            }
        };

        // ── Create the file pre-filled with random bytes (required for deniability)
        {
            let f = std::fs::File::create(path)?;
            f.set_len(total_size_bytes)?;
        }
        // Fill with random bytes in chunks
        {
            let mut f = OpenOptions::new().write(true).open(path)?;
            let mut rng = rand::thread_rng();
            let mut chunk = vec![0u8; SLOT_SIZE];
            let total_fill = HEADER_REGION_SIZE + total_slots * SLOT_SIZE as u64;
            let mut written = 0u64;
            while written < total_fill {
                rng.fill_bytes(&mut chunk);
                let to_write = ((total_fill - written) as usize).min(chunk.len());
                use std::io::Write;
                f.write_all(&chunk[..to_write])?;
                written += to_write as u64;
            }
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        // ── Derive outer master key
        let outer_kdf = kdf_params(kdf_profile);
        let outer_master_key = new_master_key();

        // ── Write hidden header (if requested)
        if let Some(ref h) = hidden {
            let hidden_kdf = kdf_params(h.kdf_profile);
            let hidden_master_key = new_master_key();
            let hidden_start = outer_limit; // first hidden slot
            let hidden_alloc = total_slots - 1; // last slot = hidden alloc block

            let mut hidden_label = [0u8; 64];
            if let Some(ref lbl) = h.label {
                let b = lbl.as_bytes();
                hidden_label[..b.len().min(64)].copy_from_slice(&b[..b.len().min(64)]);
            }

            let hidden_payload = HeaderPayload {
                master_key:  hidden_master_key,
                total_slots,
                outer_limit: hidden_start,  // hidden: stores where hidden slots start
                root_slot:   hidden_start + 1, // root is second hidden slot (first = alloc)
                created_at:  now,
                label:       hidden_label,
                cipher,
                kdf:         hidden_kdf.clone(),
            };
            let hidden_hdr = encode_header_with_password(&hidden_payload, h.password, true)?;

            // Write hidden header to disk
            {
                use std::io::{Write, Seek, SeekFrom};
                let mut f = OpenOptions::new().write(true).open(path)?;
                f.seek(SeekFrom::Start(HIDDEN_HEADER_OFFSET))?;
                f.write_all(&hidden_hdr)?;
            }

            // Initialize hidden volume's alloc block and root directory
            let hidden_store = open_slot_store(
                path,
                hidden_master_key,
                cipher,
                hidden_start,
                total_slots,
                hidden_alloc,
            )?;
            hidden_store.rebuild_free_list();
            // Remove root slot from free list (it will be written next)
            {
                let mut free = hidden_store.free.lock().unwrap();
                free.retain(|&s| s != hidden_start + 1);
            }
            // Write empty root directory
            let root_dir = VaultNode::Directory(DirectoryBlock {
                kind: NodeKind::Directory,
                entries: vec![],
            });
            let payload = bincode::serialize(&root_dir)
                .map_err(|e| VnmError::Serialization(e.to_string()))?;
            hidden_store.write(hidden_start + 1, &payload)?;
            hidden_store.save_free_list()?;
        }

        // ── Write outer header
        let mut outer_label = [0u8; 64];
        if let Some(ref lbl) = label {
            let b = lbl.as_bytes();
            outer_label[..b.len().min(64)].copy_from_slice(&b[..b.len().min(64)]);
        }

        let outer_payload = HeaderPayload {
            master_key:  outer_master_key,
            total_slots,
            outer_limit,
            root_slot:   1, // slot 0 = alloc, slot 1 = root dir
            created_at:  now,
            label:       outer_label,
            cipher,
            kdf:         outer_kdf,
        };
        let outer_hdr = encode_header_with_password(&outer_payload, outer_password, false)?;
        {
            use std::io::{Write, Seek, SeekFrom};
            let mut f = OpenOptions::new().write(true).open(path)?;
            f.seek(SeekFrom::Start(OUTER_HEADER_OFFSET))?;
            f.write_all(&outer_hdr)?;
        }

        // ── Initialize outer slot store
        let outer_store = open_slot_store(
            path,
            outer_master_key,
            cipher,
            0,
            outer_limit,
            OUTER_ALLOC_SLOT,
        )?;
        // All slots free except alloc (0) and root (1).
        outer_store.rebuild_free_list();
        {
            let mut free = outer_store.free.lock().unwrap();
            free.retain(|&s| s != 1); // root will be written below
        }
        // Write empty root directory to slot 1
        let root_dir = VaultNode::Directory(DirectoryBlock {
            kind: NodeKind::Directory,
            entries: vec![],
        });
        let payload = bincode::serialize(&root_dir)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        outer_store.write(1, &payload)?;
        outer_store.save_free_list()?;

        Ok(VnmContainer {
            store:       outer_store,
            root_slot:   1,
            is_hidden:   false,
            cipher,
            total_slots,
            outer_limit,
            label,
            created_at:  now,
            path:        path.to_path_buf(),
        })
    }

    // ── Open ──────────────────────────────────────────────────────────────────

    /// Open an existing container. Automatically detects outer vs hidden volume
    /// by trying both headers in sequence.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(VnmError::ContainerNotFound(path.display().to_string()));
        }

        let file_size = std::fs::metadata(path)?.len();
        let total_slots = (file_size.saturating_sub(HEADER_REGION_SIZE)) / SLOT_SIZE as u64;

        // Read both 512-byte headers
        let (outer_raw, hidden_raw) = {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = std::fs::File::open(path)?;
            let mut outer_raw = [0u8; 512];
            let mut hidden_raw = [0u8; 512];
            f.seek(SeekFrom::Start(OUTER_HEADER_OFFSET))?;
            f.read_exact(&mut outer_raw)?;
            f.seek(SeekFrom::Start(HIDDEN_HEADER_OFFSET))?;
            f.read_exact(&mut hidden_raw)?;
            (outer_raw, hidden_raw)
        };

        // Try outer header first
        if let Ok(payload) = decode_header(&outer_raw, password, false) {
            let store = open_slot_store(
                path,
                payload.master_key,
                payload.cipher,
                0,
                payload.outer_limit,
                OUTER_ALLOC_SLOT,
            )?;
            store.load_free_list()?;
            let label = label_from_bytes(&payload.label);
            return Ok(VnmContainer {
                root_slot:   payload.root_slot,
                is_hidden:   false,
                cipher:      payload.cipher,
                total_slots: payload.total_slots,
                outer_limit: payload.outer_limit,
                label,
                created_at:  payload.created_at,
                store,
                path:        path.to_path_buf(),
            });
        }

        // Try hidden header
        if let Ok(payload) = decode_header(&hidden_raw, password, true) {
            let hidden_start = payload.outer_limit;
            let hidden_alloc = total_slots - 1;
            let store = open_slot_store(
                path,
                payload.master_key,
                payload.cipher,
                hidden_start,
                total_slots,
                hidden_alloc,
            )?;
            store.load_free_list()?;
            let label = label_from_bytes(&payload.label);
            return Ok(VnmContainer {
                root_slot:   payload.root_slot,
                is_hidden:   true,
                cipher:      payload.cipher,
                total_slots: payload.total_slots,
                outer_limit: payload.outer_limit,
                label,
                created_at:  payload.created_at,
                store,
                path:        path.to_path_buf(),
            });
        }

        Err(VnmError::AuthenticationFailed)
    }

    // ── Node I/O ──────────────────────────────────────────────────────────────

    pub fn read_node(&self, slot: u64) -> Result<VaultNode> {
        let data = self.store.read(slot)?;
        bincode::deserialize(&data)
            .map_err(|e| VnmError::Serialization(e.to_string()))
    }

    pub fn write_node(&self, node: &VaultNode) -> Result<u64> {
        let slot = self.store.alloc()?;
        let payload = bincode::serialize(node)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        self.store.write(slot, &payload)?;
        Ok(slot)
    }

    pub fn update_node(&self, slot: u64, node: &VaultNode) -> Result<()> {
        let payload = bincode::serialize(node)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        self.store.write(slot, &payload)
    }

    pub fn free_node(&self, slot: u64) {
        self.store.free_slot(slot);
    }

    pub fn root_slot(&self) -> u64 { self.root_slot }

    pub fn path(&self) -> &Path { &self.path }

    /// Flush the free list and file buffers to disk.
    pub fn flush(&self) -> Result<()> {
        self.store.save_free_list()?;
        self.store.flush_file()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn new_master_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn kdf_params(profile: &str) -> KdfParams {
    match profile {
        "sensitive" => KdfParams::sensitive(),
        _           => KdfParams::interactive(),
    }
}

fn open_slot_store(
    path: &Path,
    master_key: [u8; 32],
    cipher: CipherAlgorithm,
    slot_start: u64,
    slot_limit: u64,
    alloc_slot: u64,
) -> Result<SlotStore> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    Ok(SlotStore::new(file, master_key, cipher, slot_start, slot_limit, alloc_slot))
}

fn label_from_bytes(raw: &[u8; 64]) -> Option<String> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(64);
    if end == 0 {
        None
    } else {
        String::from_utf8(raw[..end].to_vec()).ok()
    }
}
