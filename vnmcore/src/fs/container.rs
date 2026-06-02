//! High-level container API.
//!
//! ## File layout (version 2)
//!
//!   [0..512]                      Outer header
//!   [512..1024]                   Random reserved bytes (no header here)
//!   [1024 .. 1024+outer*32768]    Outer slots  [0..outer_slots)
//!   [1024+outer*32768 .. end-512] Hidden slots [outer_slots..outer+hidden) — absent if no hidden
//!   [end-512 .. end]              Hidden header (or random bytes if no hidden volume)
//!
//! Key deniability property: the outer header claims `total_slots = outer_slots`
//! (the outer volume appears to own the full container).  The extra space at the
//! end (hidden volume + its header) is indistinguishable from slack space to an
//! attacker who only has the outer password.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::OpenOptions;

use rand::RngCore;

use crate::{Result, VnmError};
use crate::container::{
    CipherAlgorithm, HeaderPayload, HEADER_REGION_SIZE, SLOT_SIZE,
    encode_header_with_password, decode_header,
    kdf_params_for_profile, profile_id_for_str,
};
use crate::storage::{SlotStore, VaultNode, NodeKind};
use crate::storage::vault_fs::DirectoryBlock;

const OUTER_ALLOC_SLOT: u64 = 0;

/// Minimum container size: header region + at least 16 outer slots.
pub const MIN_SIZE: u64 = HEADER_REGION_SIZE + 16 * SLOT_SIZE as u64;

/// Byte offset of the outer header in the file.
const OUTER_HEADER_OFFSET: u64 = 0;

/// Options for the hidden volume.
pub struct HiddenVolumeOptions<'a> {
    pub password:    &'a [u8],
    pub size_bytes:  u64,
    pub label:       Option<String>,
    pub kdf_profile: &'a str,
}

/// A mounted Venom container (outer or hidden volume).
pub struct VnmContainer {
    pub store:      SlotStore,
    pub root_slot:  u64,
    pub is_hidden:  bool,
    pub cipher:     CipherAlgorithm,
    pub total_slots: u64,   // outer: outer-only count; hidden: hidden count
    pub outer_limit: u64,   // first slot index that belongs to the hidden area
    pub label:      Option<String>,
    pub created_at: u64,
    path:           PathBuf,
}

impl VnmContainer {
    // ── Create ────────────────────────────────────────────────────────────────

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

        // File layout:
        //   HEADER_REGION_SIZE bytes  (outer header + reserved)
        //   outer_slots * SLOT_SIZE   bytes
        //   [hidden_slots * SLOT_SIZE bytes] — only if hidden volume
        //   512 bytes                  — hidden header slot (random if no hidden)
        let usable = total_size_bytes.saturating_sub(HEADER_REGION_SIZE + 512);
        let total_data_slots = usable / SLOT_SIZE as u64;

        let (outer_slots, hidden_slots) = match &hidden {
            None => (total_data_slots, 0u64),
            Some(h) => {
                let h_slots = ((h.size_bytes + SLOT_SIZE as u64 - 1) / SLOT_SIZE as u64).max(2);
                let o_slots = total_data_slots.saturating_sub(h_slots);
                if o_slots < 2 { return Err(VnmError::SizeTooSmall(MIN_SIZE)); }
                (o_slots, h_slots)
            }
        };

        // Physical file size
        let file_size = HEADER_REGION_SIZE
            + (outer_slots + hidden_slots) * SLOT_SIZE as u64
            + 512; // hidden header / random tail

        // 1. Create file and fill entirely with random bytes (deniability requirement).
        {
            let f = std::fs::File::create(path)?;
            f.set_len(file_size)?;
        }
        {
            use std::io::Write;
            let mut f = OpenOptions::new().write(true).open(path)?;
            let mut rng  = rand::thread_rng();
            let mut chunk = vec![0u8; SLOT_SIZE];
            let mut written = 0u64;
            while written < file_size {
                rng.fill_bytes(&mut chunk);
                let n = ((file_size - written) as usize).min(chunk.len());
                f.write_all(&chunk[..n])?;
                written += n as u64;
            }
        }

        let now          = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let outer_kdf_id = profile_id_for_str(kdf_profile);
        let outer_key    = new_master_key();

        // 2. Write hidden header at end of file (before writing outer header).
        if let Some(ref h) = hidden {
            let hidden_kdf_id = profile_id_for_str(h.kdf_profile);
            let hidden_key    = new_master_key();
            let hidden_start  = outer_slots;
            let hidden_alloc  = hidden_start + hidden_slots - 1; // last hidden slot = alloc bitmap

            let mut lbl = [0u8; 64];
            if let Some(ref s) = h.label {
                let b = s.as_bytes(); lbl[..b.len().min(64)].copy_from_slice(&b[..b.len().min(64)]);
            }

            let hidden_payload = HeaderPayload {
                master_key:   hidden_key,
                total_slots:  hidden_slots,
                hidden_start,
                root_slot:    hidden_start + 1,
                created_at:   now,
                label:        lbl,
                cipher,
                kdf_profile:  hidden_kdf_id,
            };
            let hidden_hdr = encode_header_with_password(&hidden_payload, h.password, true)?;
            write_at(path, file_size - 512, &hidden_hdr)?;

            // Initialise hidden slot store
            let hidden_store = open_slot_store(path, hidden_key, cipher,
                hidden_start, hidden_start + hidden_slots, hidden_alloc)?;
            hidden_store.rebuild_free_list();
            {
                let mut free = hidden_store.free.lock().unwrap();
                free.retain(|&s| s != hidden_start + 1); // root slot reserved
            }
            write_empty_root_dir(&hidden_store, hidden_start + 1)?;
            hidden_store.save_free_list()?;
        }

        // 3. Write outer header at offset 0.
        let mut outer_lbl = [0u8; 64];
        if let Some(ref s) = label {
            let b = s.as_bytes(); outer_lbl[..b.len().min(64)].copy_from_slice(&b[..b.len().min(64)]);
        }
        let outer_payload = HeaderPayload {
            master_key:   outer_key,
            total_slots:  outer_slots,  // outer volume claims only its own slots
            hidden_start: 0,
            root_slot:    1,
            created_at:   now,
            label:        outer_lbl,
            cipher,
            kdf_profile:  outer_kdf_id,
        };
        let outer_hdr = encode_header_with_password(&outer_payload, outer_password, false)?;
        write_at(path, OUTER_HEADER_OFFSET, &outer_hdr)?;

        // 4. Initialise outer slot store.
        let outer_store = open_slot_store(path, outer_key, cipher,
            0, outer_slots, OUTER_ALLOC_SLOT)?;
        outer_store.rebuild_free_list();
        { outer_store.free.lock().unwrap().retain(|&s| s != 1); }
        write_empty_root_dir(&outer_store, 1)?;
        outer_store.save_free_list()?;

        Ok(VnmContainer {
            store:       outer_store,
            root_slot:   1,
            is_hidden:   false,
            cipher,
            total_slots: outer_slots,
            outer_limit: outer_slots,
            label,
            created_at:  now,
            path:        path.to_path_buf(),
        })
    }

    // ── Open ──────────────────────────────────────────────────────────────────

    /// Open an existing container.  Tries the outer header first (offset 0),
    /// then the hidden header (file_end − 512).  Returns whichever volume the
    /// password decrypts.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Self> {
        let path      = path.as_ref();
        if !path.exists() {
            return Err(VnmError::ContainerNotFound(path.display().to_string()));
        }
        let file_size = std::fs::metadata(path)?.len();

        // Read outer header (512 bytes at offset 0)
        let outer_raw = read_at(path, OUTER_HEADER_OFFSET)?;
        // Read hidden header (512 bytes at file_end - 512)
        let hidden_raw = if file_size >= 512 {
            read_at(path, file_size - 512).unwrap_or([0u8; 512])
        } else {
            [0u8; 512]
        };

        // Try outer header
        if let Ok(p) = decode_header(&outer_raw, password, false) {
            let outer_limit = p.total_slots;
            let store = open_slot_store(path, p.master_key, p.cipher,
                0, outer_limit, OUTER_ALLOC_SLOT)?;
            store.load_free_list()?;
            return Ok(VnmContainer {
                root_slot:   p.root_slot,
                is_hidden:   false,
                cipher:      p.cipher,
                total_slots: p.total_slots,
                outer_limit,
                label:       label_from(p.label),
                created_at:  p.created_at,
                store,
                path:        path.to_path_buf(),
            });
        }

        // Try hidden header
        if let Ok(p) = decode_header(&hidden_raw, password, true) {
            let hidden_start = p.hidden_start;
            let hidden_end   = hidden_start + p.total_slots;
            let hidden_alloc = hidden_end - 1; // last hidden slot = alloc bitmap
            let store = open_slot_store(path, p.master_key, p.cipher,
                hidden_start, hidden_end, hidden_alloc)?;
            store.load_free_list()?;
            // outer_limit = hidden_start (outer area boundary, used for statfs)
            return Ok(VnmContainer {
                root_slot:   p.root_slot,
                is_hidden:   true,
                cipher:      p.cipher,
                total_slots: p.total_slots,
                outer_limit: hidden_start,
                label:       label_from(p.label),
                created_at:  p.created_at,
                store,
                path:        path.to_path_buf(),
            });
        }

        Err(VnmError::AuthenticationFailed)
    }

    // ── Node I/O ──────────────────────────────────────────────────────────────

    pub fn read_node(&self, slot: u64) -> Result<VaultNode> {
        let data = self.store.read(slot)?;
        rmp_serde::from_slice(&data)
            .map_err(|e| VnmError::Serialization(e.to_string()))
    }

    pub fn write_node(&self, node: &VaultNode) -> Result<u64> {
        let slot    = self.store.alloc()?;
        let payload = rmp_serde::to_vec_named(node)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        self.store.write(slot, &payload)?;
        Ok(slot)
    }

    pub fn update_node(&self, slot: u64, node: &VaultNode) -> Result<()> {
        let payload = rmp_serde::to_vec_named(node)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        self.store.write(slot, &payload)
    }

    pub fn free_node(&self, slot: u64) {
        self.store.free_slot(slot);
    }

    pub fn root_slot(&self)  -> u64  { self.root_slot }
    pub fn path(&self)       -> &Path { &self.path }

    pub fn flush(&self) -> Result<()> {
        self.store.save_free_list()?;
        self.store.flush_file()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn new_master_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

fn open_slot_store(
    path: &Path, key: [u8; 32], cipher: CipherAlgorithm,
    slot_start: u64, slot_limit: u64, alloc_slot: u64,
) -> Result<SlotStore> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    Ok(SlotStore::new(file, key, cipher, slot_start, slot_limit, alloc_slot))
}

fn write_at(path: &Path, offset: u64, data: &[u8]) -> Result<()> {
    use std::io::{Write, Seek, SeekFrom};
    let mut f = OpenOptions::new().write(true).open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(data)?;
    Ok(())
}

fn read_at(path: &Path, offset: u64) -> Result<[u8; 512]> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; 512];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_empty_root_dir(store: &SlotStore, slot: u64) -> Result<()> {
    let root = VaultNode::Directory(DirectoryBlock { kind: NodeKind::Directory, entries: vec![] });
    let data = rmp_serde::to_vec_named(&root)
        .map_err(|e| VnmError::Serialization(e.to_string()))?;
    store.write(slot, &data)
}

fn label_from(raw: [u8; 64]) -> Option<String> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(64);
    if end == 0 { None } else { String::from_utf8(raw[..end].to_vec()).ok() }
}
