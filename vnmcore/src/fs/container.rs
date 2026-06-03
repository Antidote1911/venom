//! VnmContainer v1 — single-file encrypted container with multi-recipient support.
//!
//! ## Open flow
//!
//!   1. Read outer header (512 B at offset 0) → get cipher, kdf_profile, slot counts
//!   2. Read recipient area (at HEADER_REGION_SIZE): password slots then ML-KEM slots
//!   3. Try each slot with the provided credential → obtain K_master
//!   4. Decrypt header body with K_master → get metadata (outer_slots, root_slot, …)
//!   5. Access data via SlotStore
//!
//! ## File layout
//!
//!   [0..512]                   Outer header (VNM1)
//!   [512..1024]                Random reserved (no header here)
//!   [1024..1024+RECIPIENT_AREA] Recipient slots (fixed size, unused = random bytes)
//!   [DATA_AREA_OFFSET..]       Data slots (32 KB each)
//!   [end-512..end]             Hidden header (VNM1) or random bytes

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::OpenOptions;
use std::io::{Read, Write, Seek, SeekFrom};

use rand::RngCore;
use crate::locked_memory::LockedMemory;

use crate::{Result, VnmError};
use crate::rollback::RollbackState;
use crate::container::{
    CipherAlgorithm,
    HEADER_REGION_SIZE, SLOT_SIZE, DATA_AREA_OFFSET,
    MAX_PASSWORD_SLOTS, MAX_KEY_SLOTS, PW_SLOT_SIZE, KEY_SLOT_SIZE,
    encode_header, decode_header, read_header_plaintext, kdf_params_for_profile,
    encode_password_slot, try_password_slot,
    encode_key_slot, try_key_slot,
};
use crate::crypto::hybrid_kem::{HybridPublicKey, HybridPrivateKey};
use crate::storage::{SlotStore, VaultNode, NodeKind};
use crate::storage::vault_fs::DirectoryBlock;
use crate::container::header::HeaderPayload;

const OUTER_ALLOC_SLOT: u64 = 0;
const OUTER_ROOT_SLOT:  u64 = 1;

/// File must be at least this large.
pub const MIN_SIZE: u64 = DATA_AREA_OFFSET + 16 * SLOT_SIZE as u64 + 512;

/// Options for the hidden volume.
pub struct HiddenVolumeOptions<'a> {
    pub password:    &'a [u8],
    pub size_bytes:  u64,
    pub label:       Option<String>,
    pub kdf_profile: &'a str,
}

/// Credential used to open a container.
pub enum OpenCredential<'a> {
    /// Password (tries all password slots).
    Password(&'a [u8]),
    /// Hybrid private key (X25519 + ML-KEM-1024, tries all key slots).
    PrivateKey(&'a HybridPrivateKey),
}

/// Summary of one recipient slot (for display in the GUI).
pub struct RecipientInfo {
    pub is_key:     bool,
    pub slot_index: usize,
}

/// A mounted Venom container.
pub struct VnmContainer {
    pub store:       SlotStore,
    pub root_slot:   u64,
    pub is_hidden:   bool,
    pub cipher:      CipherAlgorithm,
    pub outer_slots: u64,
    pub outer_limit: u64,   // = outer_slots for outer vol; = hidden_start for hidden vol
    pub label:       Option<String>,
    pub created_at:  u64,
    k_master:        LockedMemory<[u8; 32]>,
    path:            PathBuf,
    /// Anti-rollback identifier (all-zeros for pre-rollback containers).
    pub container_id: [u8; 16],
}

impl VnmContainer {
    // ── Create ────────────────────────────────────────────────────────────────

    pub fn create(
        path:            impl AsRef<Path>,
        outer_password:  &[u8],
        total_size_bytes: u64,
        cipher:          CipherAlgorithm,
        kdf_profile:     &str,
        label:           Option<String>,
        hidden:          Option<HiddenVolumeOptions<'_>>,
    ) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            return Err(VnmError::ContainerAlreadyExists(path.display().to_string()));
        }
        if total_size_bytes < MIN_SIZE {
            return Err(VnmError::SizeTooSmall(MIN_SIZE));
        }

        // Tail size: outer-only = 512 (primary hidden header placeholder);
        //            with hidden = 1024 (hidden primary 512 + hidden backup 512).
        let tail_size: u64 = if hidden.is_some() { 1024 } else { 512 };

        // Compute slot counts
        let usable_for_data = total_size_bytes.saturating_sub(DATA_AREA_OFFSET + tail_size);
        let total_data_slots = usable_for_data / SLOT_SIZE as u64;

        let (outer_slots, hidden_slots) = match &hidden {
            None    => (total_data_slots, 0u64),
            Some(h) => {
                let h_slots = ((h.size_bytes + SLOT_SIZE as u64 - 1) / SLOT_SIZE as u64).max(2);
                let o_slots = total_data_slots.saturating_sub(h_slots);
                if o_slots < 2 { return Err(VnmError::SizeTooSmall(MIN_SIZE)); }
                (o_slots, h_slots)
            }
        };

        // Physical file size
        let file_size = DATA_AREA_OFFSET
            + (outer_slots + hidden_slots) * SLOT_SIZE as u64
            + tail_size;

        // 1. Create + fill with random bytes (deniability)
        { std::fs::File::create(path)?.set_len(file_size)?; }
        {
            let mut f   = OpenOptions::new().write(true).open(path)?;
            let mut rng = rand::thread_rng();
            let mut buf = vec![0u8; 65536];
            let mut done = 0u64;
            while done < file_size {
                rng.fill_bytes(&mut buf);
                let n = ((file_size - done) as usize).min(buf.len());
                f.write_all(&buf[..n])?;
                done += n as u64;
            }
        }

        let now          = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let k_outer      = new_k_master();
        let kdf_id       = if kdf_profile == "sensitive" { 1u8 } else { 0u8 };
        let mut outer_container_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut outer_container_id);

        // 2. Write hidden header at end (if requested)
        if let Some(ref h) = hidden {
            let k_hidden   = new_k_master();
            let hid_start  = outer_slots;
            let hid_kdf_id = if h.kdf_profile == "sensitive" { 1u8 } else { 0u8 };
            let mut hid_lbl = [0u8; 64];
            if let Some(ref s) = h.label {
                let b = s.as_bytes(); hid_lbl[..b.len().min(64)].copy_from_slice(&b[..b.len().min(64)]);
            }
            let mut hid_container_id = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut hid_container_id);

            // Password slot for hidden volume
            let pw_slot = encode_password_slot(&k_hidden, h.password, hid_kdf_id, cipher)?;

            let hid_payload = HeaderPayload {
                cipher, kdf_profile: hid_kdf_id,
                num_password_slots: 1, num_key_slots: 0,
                outer_slots: hidden_slots, hidden_start: hid_start,
                root_slot: hid_start + 1, created_at: now, label: hid_lbl,
                container_id: hid_container_id,
            };
            let hid_hdr = encode_header(&hid_payload, &k_hidden, true)?;
            write_bytes_at(path, file_size - 512, &hid_hdr)?;

            // Recipient area for hidden volume: write pw slot at offset 0 of hidden recipient area
            // (hidden volume's recipient area is within its header on disk — no separate area)
            // For simplicity, hidden volume uses a separate in-memory slot lookup:
            // the pw_slot is stored in the hidden header's reserved area? No, let's keep it simple:
            // The hidden volume's recipient slots are at the same HEADER_REGION_SIZE offset
            // but that's the outer volume's recipient area. For the hidden volume, we store
            // the password slot inline in the header body encrypted region.
            // Actually, let me re-architect: hidden volume uses the tail of the file as its
            // "recipient area" too. But to keep things simple, hidden volume supports
            // only 1 password slot for now, stored in its header (we'll pack it in reserved bytes).
            // Actually the cleanest: encode the pw_slot as part of the hidden header's payload.
            // Let me just store it in the file right after the hidden header.
            // File: [...][hid_header(512)][hid_pw_slot(101)][end]
            // But that changes the end. Let me instead make the hidden volume's slots
            // stored at file_size - 512 - RECIPIENT_AREA_SIZE ... nah this gets complex.

            // SIMPLE APPROACH: hidden volume password is derived differently.
            // The hidden header body is encrypted with K_hidden (derived from password).
            // No separate recipient area for hidden volume.
            // → We'll re-derive K_hidden from the password when opening.

            // So for the hidden header, K_hidden = Argon2id(h.password, salt_in_hidden_hdr).
            // The hidden header was already written above, but we need to re-think the design.
            // Let me use the V2 approach for the hidden header: derive K_master from password.
            let _ = pw_slot;

            // Re-derive the hidden master key from the password (standard approach for hidden)
            let _hkdf = kdf_params_for_profile(h.kdf_profile);
            // Use a random salt stored in the hidden header's first 64 bytes
            // → already done by encode_header (it generates a random salt internally)
            // We need to get K_hidden from the password when opening.
            // But encode_header encrypts with k_hidden (master key), not with password.
            // We need: encrypted_body = AEAD(K_from_password, body) OR AEAD(K_master, body)
            //
            // K_master to encrypt the header body.
            // For hidden volume: user provides password → we need K_master from a recipient slot.
            //
            // Solution: store a password recipient slot in the hidden header's tail bytes.
            // The hidden header is 512 bytes. Payload starts at byte 68. We have ~432 bytes.
            // Body takes 432 bytes (encrypted). We can't fit a pw slot (101 bytes) inside.
            //
            // REVISED APPROACH for hidden volume:
            // The hidden header is encrypted with a key derived directly from the hidden password.
            // This is simpler and avoids the recipient area complexity for the hidden volume.
            // K_hidden_hdr = Argon2id(hidden_password, salt_in_hidden_header)
            // Then K_master_hidden is INSIDE the hidden header body (like V2).
            // → Use a modified encode_header that takes a password directly (not K_master).
            //
            // Let's use the simplest approach:
            // Hidden header encrypted with Argon2id(password, salt) like V2.
            // Use password-derived key for the hidden header.

            let hid_hdr = encode_header_with_password(&hid_payload, h.password, true, &k_hidden)?;
            write_bytes_at(path, file_size - 512, &hid_hdr)?; // hidden primary  (EOF-512)
            write_bytes_at(path, 512,             &hid_hdr)?; // hidden backup   ([512..1024], near start)

            // Init hidden slot store (hidden volume has its own alloc in its first slot)
            let hid_alloc = hid_start + hidden_slots - 1;
            let hid_store = open_store(path, k_hidden, cipher, hid_start, hid_start + hidden_slots, hid_alloc, true)?;
            hid_store.rebuild_free_list();
            { hid_store.free.lock().unwrap().retain(|&s| s != hid_start + 1); }
            write_empty_dir(&hid_store, hid_start + 1)?;
            hid_store.save_free_list()?;
        }

        // 3. Write outer header
        let mut lbl = [0u8; 64];
        if let Some(ref s) = label {
            let b = s.as_bytes(); lbl[..b.len().min(64)].copy_from_slice(&b[..b.len().min(64)]);
        }
        // An empty outer_password means "key-only access" — no password slot is created.
        let has_password = !outer_password.is_empty();
        let outer_payload = HeaderPayload {
            cipher, kdf_profile: kdf_id,
            num_password_slots: u8::from(has_password), num_key_slots: 0,
            outer_slots, hidden_start: 0,
            root_slot: OUTER_ROOT_SLOT, created_at: now, label: lbl,
            container_id: outer_container_id,
        };
        let outer_hdr = encode_header(&outer_payload, &k_outer, false)?;
        write_bytes_at(path, 0, &outer_hdr)?;   // outer primary  (offset 0)
        // Outer backup at the far end of the file — maximum geographic separation.
        // outer-only: EOF-512  (replaces random placeholder)
        // with hidden: EOF-1024 (just before the hidden primary at EOF-512)
        let outer_backup_off = if hidden.is_some() { file_size - 1024 } else { file_size - 512 };
        write_bytes_at(path, outer_backup_off, &outer_hdr)?;

        // 4. Write password recipient slot (only when a password is provided)
        if has_password {
            let pw_slot = encode_password_slot(&k_outer, outer_password, kdf_id, cipher)?;
            write_recipient_slot(path, 0, &pw_slot)?;
        }
        // Remaining slots stay as random bytes (already filled in step 1)

        // 5. Init outer slot store (clone k_outer: one copy for the store, one for k_master)
        let outer_store = open_store(path, k_outer.clone(), cipher, 0, outer_slots, OUTER_ALLOC_SLOT, true)?;
        outer_store.rebuild_free_list();
        { outer_store.free.lock().unwrap().retain(|&s| s != OUTER_ROOT_SLOT); }
        write_empty_dir(&outer_store, OUTER_ROOT_SLOT)?;
        outer_store.save_free_list()?;

        // Establish rollback baseline for new container (generation = 0 after first save_free_list)
        RollbackState::load().update(&outer_container_id, outer_store.current_generation())?;

        Ok(VnmContainer {
            store:        outer_store,
            root_slot:    OUTER_ROOT_SLOT,
            is_hidden:    false,
            cipher,
            outer_slots,
            outer_limit:  outer_slots,
            label,
            created_at:   now,
            k_master:     k_outer,
            path:         path.to_path_buf(),
            container_id: outer_container_id,
        })
    }

    // ── Open ──────────────────────────────────────────────────────────────────

    pub fn open(path: impl AsRef<Path>, credential: OpenCredential<'_>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() { return Err(VnmError::ContainerNotFound(path.display().to_string())); }
        let file_size = std::fs::metadata(path)?.len();

        // ── Outer volume ──────────────────────────────────────────────────────
        //
        // Derive K_master once (expensive: Argon2id or ML-KEM decapsulation).
        // If the primary header's plaintext fields look corrupted (both counts
        // zero), fall back to a backup header's plaintext before running KDF.
        //
        // Read n_pw / n_key from plaintext (cipher byte 64 is always 0 — ignored).
        let raw_0 = read_512_at(path, 0).unwrap_or([0u8; 512]);
        let (_, n_pw0, n_key0) = read_header_plaintext(&raw_0);

        let (n_pw, n_key) = if n_pw0 == 0 && n_key0 == 0 {
            // Primary plaintext zeroed — try backup locations for valid counts
            [file_size.saturating_sub(512), file_size.saturating_sub(1024)]
                .iter()
                .find_map(|&off| {
                    read_512_at(path, off).ok().and_then(|raw| {
                        let (_, p, k) = read_header_plaintext(&raw);
                        if p > 0 || k > 0 { Some((p, k)) } else { None }
                    })
                })
                .unwrap_or((n_pw0, n_key0))
        } else {
            (n_pw0, n_key0)
        };

        // Cipher is discovered by trying all supported ciphers during slot decryption.
        // Argon2id (password) or ML-KEM decapsulation runs once per slot; only AEAD
        // verification is repeated for each cipher candidate.
        let k_outer = match &credential {
            OpenCredential::Password(pw)     => try_pw_slots(path, pw, n_pw),
            OpenCredential::PrivateKey(priv_) => try_key_slots(path, priv_, n_key),
        };

        // Try to authenticate against each header copy (cheap AEAD, no extra KDF).
        // Order: primary → EOF-512 backup → EOF-1024 backup.
        if let Some((k, cipher)) = k_outer {
            let offsets = [0u64, file_size.saturating_sub(512), file_size.saturating_sub(1024)];
            for &off in &offsets {
                if let Ok(raw) = read_512_at(path, off) {
                    if let Ok(meta) = decode_header(&raw, &k, cipher, false) {
                        let has_gen = meta.container_id != [0u8; 16];
                        let store = open_store(path, k.clone(), meta.cipher, 0, meta.outer_slots, OUTER_ALLOC_SLOT, has_gen)?;
                        store.load_free_list()?;
                        // Anti-rollback check
                        if has_gen {
                            RollbackState::load().check(&meta.container_id, store.current_generation())?;
                        }
                        return Ok(VnmContainer {
                            root_slot:    meta.root_slot,
                            is_hidden:    false,
                            cipher:       meta.cipher,
                            outer_slots:  meta.outer_slots,
                            outer_limit:  meta.outer_slots,
                            label:        label_from(meta.label),
                            created_at:   meta.created_at,
                            k_master:     k,
                            store,
                            path:         path.to_path_buf(),
                            container_id: meta.container_id,
                        });
                    }
                }
            }
        }

        // ── Hidden volume ─────────────────────────────────────────────────────
        // Primary at EOF-512, backup at [512..1024].
        if let OpenCredential::Password(pw) = &credential {
            let hidden = try_hidden_at(path, file_size.saturating_sub(512), pw)
                .or_else(|| try_hidden_at(path, 512, pw));

            if let Some((k, meta)) = hidden {
                let hid_start = meta.hidden_start;
                let hid_end   = hid_start + meta.outer_slots;
                let hid_alloc = hid_end - 1;
                let has_gen   = meta.container_id != [0u8; 16];
                let store = open_store(path, k.clone(), meta.cipher, hid_start, hid_end, hid_alloc, has_gen)?;
                store.load_free_list()?;
                // Anti-rollback check
                if has_gen {
                    RollbackState::load().check(&meta.container_id, store.current_generation())?;
                }
                return Ok(VnmContainer {
                    root_slot:    meta.root_slot,
                    is_hidden:    true,
                    cipher:       meta.cipher,
                    outer_slots:  meta.outer_slots,
                    outer_limit:  hid_start,
                    label:        label_from(meta.label),
                    created_at:   meta.created_at,
                    k_master:     k,
                    store,
                    path:         path.to_path_buf(),
                    container_id: meta.container_id,
                });
            }
        }

        Err(VnmError::AuthenticationFailed)
    }

    // ── Recipients ────────────────────────────────────────────────────────────

    /// List all recipient slots (password and ML-KEM).
    pub fn list_recipients(&self) -> Result<Vec<RecipientInfo>> {
        let raw = read_512_at(&self.path, 0)?;
        let (_, n_pw, n_key) = read_header_plaintext(&raw);
        let mut out = vec![];
        for i in 0..n_pw as usize {
            out.push(RecipientInfo { is_key: false, slot_index: i });
        }
        for j in 0..n_key as usize {
            out.push(RecipientInfo { is_key: true, slot_index: j });
        }
        Ok(out)
    }

    /// Add a new password recipient.
    pub fn add_password_recipient(&self, new_password: &[u8]) -> Result<()> {
        let raw = read_512_at(&self.path, 0)?;
        let (kdf_profile, n_pw, n_key) = read_header_plaintext(&raw);
        if n_pw as usize >= MAX_PASSWORD_SLOTS {
            return Err(VnmError::InvalidFormat("max password recipients reached".into()));
        }
        let slot = encode_password_slot(&self.k_master, new_password, kdf_profile, self.cipher)?;
        write_recipient_slot(&self.path, n_pw as usize, &slot)?;
        update_slot_counts(&self.path, n_pw + 1, n_key, &self.k_master, self.cipher, &raw)?;
        Ok(())
    }

    /// Add a new ML-KEM (post-quantum) recipient using their public key.
    pub fn add_key_recipient(&self, recipient: &HybridPublicKey) -> Result<()> {
        let raw = read_512_at(&self.path, 0)?;
        let (_, n_pw, n_key) = read_header_plaintext(&raw);
        if n_key as usize >= MAX_KEY_SLOTS {
            return Err(VnmError::InvalidFormat("max key recipients reached".into()));
        }
        let slot = encode_key_slot(&self.k_master, recipient, self.cipher)?;
        write_key_slot_raw(&self.path, n_key as usize, &slot)?;
        update_slot_counts(&self.path, n_pw, n_key + 1, &self.k_master, self.cipher, &raw)?;
        Ok(())
    }

    /// Remove the ML-KEM key slot at the given index.
    ///
    /// The caller must provide `slot_index` from `list_recipients()`.
    /// Remaining slots are compacted (shifted down) and the freed slot is wiped.
    pub fn remove_key_recipient(&self, slot_index: usize) -> Result<()> {
        let raw = read_512_at(&self.path, 0)?;
        let (_, n_pw, n_key) = read_header_plaintext(&raw);

        if slot_index >= n_key as usize {
            return Err(VnmError::InvalidFormat("key slot index out of range".into()));
        }

        let mut slots: Vec<[u8; KEY_SLOT_SIZE]> = (0..n_key as usize)
            .map(|i| read_key_slot_raw(&self.path, i))
            .collect::<Result<_>>()?;

        slots.remove(slot_index);

        for (i, s) in slots.iter().enumerate() {
            write_key_slot_raw(&self.path, i, s)?;
        }
        // Wipe the now-unused last slot with random bytes
        let mut rng = rand::thread_rng();
        let mut random_slot = vec![0u8; KEY_SLOT_SIZE];
        rng.fill_bytes(&mut random_slot);
        write_key_slot_raw(&self.path, slots.len(), random_slot.as_slice().try_into().unwrap())?;

        update_slot_counts(&self.path, n_pw, n_key - 1, &self.k_master, self.cipher, &raw)?;
        Ok(())
    }

    // ── Node I/O ──────────────────────────────────────────────────────────────

    pub fn read_node(&self, slot: u64) -> Result<VaultNode> {
        let data = self.store.read(slot)?;
        rmp_serde::from_slice(&data).map_err(|e| VnmError::Serialization(e.to_string()))
    }
    pub fn write_node(&self, node: &VaultNode) -> Result<u64> {
        let slot    = self.store.alloc()?;
        let payload = rmp_serde::to_vec_named(node).map_err(|e| VnmError::Serialization(e.to_string()))?;
        self.store.write(slot, &payload)?;
        Ok(slot)
    }
    pub fn update_node(&self, slot: u64, node: &VaultNode) -> Result<()> {
        let payload = rmp_serde::to_vec_named(node).map_err(|e| VnmError::Serialization(e.to_string()))?;
        self.store.write(slot, &payload)
    }
    pub fn free_node(&self, slot: u64) { self.store.free_slot(slot); }
    pub fn root_slot(&self) -> u64 { self.root_slot }
    pub fn path(&self) -> &Path { &self.path }

    pub fn flush(&self) -> Result<()> {
        self.store.save_free_list()?;
        self.store.flush_file()?;
        // Persist updated generation to anti-rollback state (no-op for legacy containers)
        if self.container_id != [0u8; 16] {
            RollbackState::load().update(&self.container_id, self.store.current_generation())?;
        }
        Ok(())
    }

    /// Reset the anti-rollback baseline for this container.
    ///
    /// Call this after a deliberate restore from backup, so the next mount
    /// accepts the restored (lower) generation without raising an error.
    pub fn reset_rollback_state(&self) -> Result<()> {
        if self.container_id == [0u8; 16] { return Ok(()); }
        RollbackState::load().reset(&self.container_id)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generate a fresh random K_master directly into a locked heap allocation.
/// The random bytes are never placed on the stack — zeros are initialised
/// first (not sensitive), then overwritten in place with random data.
fn new_k_master() -> LockedMemory<[u8; 32]> {
    let mut lm = LockedMemory::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut *lm);
    lm
}

fn open_store(path: &Path, k: LockedMemory<[u8; 32]>, c: CipherAlgorithm, s: u64, l: u64, a: u64, has_gen: bool) -> Result<SlotStore> {
    let f = OpenOptions::new().read(true).write(true).open(path)?;
    Ok(SlotStore::new(f, k, c, s, l, a, has_gen))
}

fn write_bytes_at(path: &Path, offset: u64, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(data)?;
    Ok(())
}

fn read_512_at(path: &Path, offset: u64) -> Result<[u8; 512]> {
    let mut f   = std::fs::File::open(path)?;
    let mut buf = [0u8; 512];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_empty_dir(store: &SlotStore, slot: u64) -> Result<()> {
    let node = VaultNode::Directory(DirectoryBlock { kind: NodeKind::Directory, entries: vec![] });
    let data = rmp_serde::to_vec_named(&node).map_err(|e| VnmError::Serialization(e.to_string()))?;
    store.write(slot, &data)
}

fn label_from(raw: [u8; 64]) -> Option<String> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(64);
    if end == 0 { None } else { String::from_utf8(raw[..end].to_vec()).ok() }
}

/// Byte offset of password slot `i` in the file.
fn pw_slot_offset(i: usize) -> u64 {
    HEADER_REGION_SIZE + (i * PW_SLOT_SIZE) as u64
}

/// Byte offset of ML-KEM key slot `j` in the file.
fn key_slot_offset(j: usize) -> u64 {
    HEADER_REGION_SIZE + (MAX_PASSWORD_SLOTS * PW_SLOT_SIZE + j * KEY_SLOT_SIZE) as u64
}

fn write_recipient_slot(path: &Path, i: usize, slot: &[u8; PW_SLOT_SIZE]) -> Result<()> {
    write_bytes_at(path, pw_slot_offset(i), slot)
}

fn read_key_slot_raw(path: &Path, j: usize) -> Result<[u8; KEY_SLOT_SIZE]> {
    let mut f   = std::fs::File::open(path)?;
    let mut buf = [0u8; KEY_SLOT_SIZE];
    f.seek(SeekFrom::Start(key_slot_offset(j)))?;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_key_slot_raw(path: &Path, j: usize, slot: &[u8; KEY_SLOT_SIZE]) -> Result<()> {
    write_bytes_at(path, key_slot_offset(j), slot)
}

/// Try all password slots.  Returns (K_master locked, cipher) on success.
fn try_pw_slots(path: &Path, pw: &[u8], n: u8) -> Option<(LockedMemory<[u8; 32]>, CipherAlgorithm)> {
    for i in 0..n as usize {
        let slot = read_pw_slot_raw(path, i).ok()?;
        if let Some(result) = try_password_slot(&slot, pw) { return Some(result); }
    }
    None
}

fn read_pw_slot_raw(path: &Path, i: usize) -> Result<[u8; PW_SLOT_SIZE]> {
    let mut f   = std::fs::File::open(path)?;
    let mut buf = [0u8; PW_SLOT_SIZE];
    f.seek(SeekFrom::Start(pw_slot_offset(i)))?;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Try all ML-KEM slots.  Returns (K_master locked, cipher) on success.
fn try_key_slots(path: &Path, private: &HybridPrivateKey, n: u8) -> Option<(LockedMemory<[u8; 32]>, CipherAlgorithm)> {
    for j in 0..n as usize {
        let slot = read_key_slot_raw(path, j).ok()?;
        if let Some(result) = try_key_slot(&slot, private) { return Some(result); }
    }
    None
}

/// Re-write the outer header (primary + backup) with updated slot counts.
///
/// The backup offset is inferred from the file tail size:
///   outer-only (tail = 512 B):  backup at EOF-512
///   with hidden (tail = 1024 B): backup at EOF-1024 (leaves EOF-512 for hidden primary)
fn update_slot_counts(
    path: &Path, n_pw: u8, n_key: u8, k_master: &[u8; 32],
    cipher: CipherAlgorithm, old_raw: &[u8; 512],
) -> Result<()> {
    let meta = decode_header(old_raw, k_master, cipher, false)?;
    let new_payload = HeaderPayload { num_password_slots: n_pw, num_key_slots: n_key, ..meta };
    let new_hdr = encode_header(&new_payload, k_master, false)?;

    let file_size  = std::fs::metadata(path)?.len();
    let tail       = (file_size.saturating_sub(DATA_AREA_OFFSET)) % SLOT_SIZE as u64;
    let backup_off = if tail == 1024 { file_size - 1024 } else { file_size - 512 };

    write_bytes_at(path, 0,          &new_hdr)?; // primary
    write_bytes_at(path, backup_off, &new_hdr)   // backup (EOF-512 or EOF-1024)
}

/// Try to open a hidden volume from a specific header offset.
/// Derives K_hidden once, then probes all cipher candidates via AEAD.
fn try_hidden_at(path: &Path, hdr_offset: u64, password: &[u8]) -> Option<(LockedMemory<[u8; 32]>, HeaderPayload)> {
    let raw = read_512_at(path, hdr_offset).ok()?;
    let k   = derive_hidden_key(&raw, password).ok()?;
    for &cipher in &[CipherAlgorithm::XChaCha20Poly1305, CipherAlgorithm::Aes256Gcm] {
        if let Ok(meta) = decode_header(&raw, &*k, cipher, true) {
            return Some((k, meta));
        }
    }
    None
}

/// Derive the hidden-header encryption key from the password.
///
/// The derived key is copied from the Argon2id output Vec directly into a
/// `LockedMemory<[u8; 32]>` allocation, so K_hidden never appears on the stack
/// as a plain array.  The source Vec is dropped (and zeroized via ZeroizeOnDrop
/// on DerivedKey) immediately after the copy.
/// Derive K_hidden from the password + salt embedded in the header.
/// Returns the key in locked memory (no cipher probing here).
fn derive_hidden_key(raw: &[u8; 512], password: &[u8]) -> Result<LockedMemory<[u8; 32]>> {
    use crate::crypto::derive_key;
    use crate::container::kdf_params_for_profile;
    let salt        = &raw[0..64];
    let kdf_profile = raw[65];
    let mut kdf = kdf_params_for_profile(if kdf_profile == 1 { "sensitive" } else { "interactive" });
    kdf.salt = hex::encode(salt);
    let dk  = derive_key(password, &kdf)?;
    let src = dk.as_bytes();
    if src.len() != 32 { return Err(VnmError::KdfError("unexpected key length".into())); }
    let mut lm = LockedMemory::new([0u8; 32]);
    lm.copy_from_slice(src);
    Ok(lm)
}

/// Encode a hidden header using a password-derived key (not K_master).
fn encode_header_with_password(
    payload: &HeaderPayload,
    password: &[u8],
    is_hidden: bool,
    _k_master_hint: &[u8; 32],
) -> Result<[u8; 512]> {
    use crate::crypto::derive_key;
    use crate::container::kdf_params_for_profile;
    // The "hidden key" IS derived directly from the password.
    // To store it in the header: we need a salt. encode_header generates a fresh salt
    // internally, so we can't predict the key. Instead, use a two-pass approach:
    // derive a temporary key from (password, random_salt), embed salt in header, use that key.
    let mut salt = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut kdf = kdf_params_for_profile(if payload.kdf_profile == 1 { "sensitive" } else { "interactive" });
    kdf.salt = hex::encode(&salt);
    let dk  = derive_key(password, &kdf)?;
    let key: [u8; 32] = dk.as_array_32().unwrap();

    // Build the header with this key
    let mut buf = [0u8; 512];
    buf[0..64].copy_from_slice(&salt);
    buf[64] = 0; // cipher hidden — always 0
    buf[65] = payload.kdf_profile;
    buf[66] = payload.num_password_slots;
    buf[67] = payload.num_key_slots;

    let mut body = [0u8; crate::container::header::BODY_LEN];
    body[0..4].copy_from_slice(b"VNM1");
    body[4..8].copy_from_slice(&3u32.to_le_bytes());
    body[8..16].copy_from_slice(&DATA_AREA_OFFSET.to_le_bytes());
    body[16..24].copy_from_slice(&payload.outer_slots.to_le_bytes());
    body[24..32].copy_from_slice(&payload.hidden_start.to_le_bytes());
    body[32..40].copy_from_slice(&payload.root_slot.to_le_bytes());
    body[40..48].copy_from_slice(&payload.created_at.to_le_bytes());
    body[48..112].copy_from_slice(&payload.label);
    body[112..128].copy_from_slice(&payload.container_id);

    let aad = if is_hidden { b"vnm:header:hidden:v1".as_ref() } else { b"vnm:header:outer:v1".as_ref() };
    let enc = crate::crypto::encrypt_block(&key, payload.cipher, aad, &body)?;
    buf[68..68 + enc.len()].copy_from_slice(&enc);
    Ok(buf)
}
