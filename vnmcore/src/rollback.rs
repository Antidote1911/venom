//! Anti-rollback state tracking.
//!
//! Each container has a `container_id` (16 random bytes, stored in the AEAD-
//! protected header body) and a monotonically increasing `generation` counter
//! embedded in its allocation block.
//!
//! On every `VnmContainer::flush()`, the generation is incremented on disk and
//! the new value is persisted to a local state file. On the next mount, the
//! current generation is compared to the last-seen value: if it regressed, the
//! container may have been replaced with an older copy (backup replay, cloud
//! sync going backwards, etc.) and the mount is refused.
//!
//! ## State file
//!
//! `~/.config/venom/rollback.json`  — JSON object mapping container_id (hex)
//! to the last-seen generation number.
//!
//! Deleting this file or a specific entry is the "force mount" escape hatch
//! for legitimate restore scenarios.
//!
//! ## Limitations
//!
//! - Per-device only: moving the container to another machine loses the baseline.
//! - First mount on a new device establishes a new baseline (no protection until then).
//! - Write failures to the state file are returned as errors; the container
//!   remains readable but the baseline is not updated.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::{Result, VnmError};

pub struct RollbackState {
    path:    PathBuf,
    entries: HashMap<String, u64>,
}

impl RollbackState {
    /// Load (or initialise) the local rollback state from disk.
    pub fn load() -> Self {
        let path = state_path();
        let entries = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { path, entries }
    }

    /// Check whether `current_gen` is consistent with the stored baseline.
    ///
    /// - No entry for this container → Ok (first mount, no baseline yet).
    /// - `current_gen >= stored` → Ok (normal operation or forward progress).
    /// - `current_gen < stored`  → `Err(VnmError::RollbackDetected)`.
    pub fn check(&self, container_id: &[u8; 16], current_gen: u64) -> Result<()> {
        let key = hex::encode(container_id);
        if let Some(&stored) = self.entries.get(&key) {
            if current_gen < stored {
                return Err(VnmError::RollbackDetected {
                    current_gen,
                    expected_gen: stored,
                });
            }
        }
        Ok(())
    }

    /// Update the stored generation and persist to disk.
    pub fn update(&mut self, container_id: &[u8; 16], gen: u64) -> Result<()> {
        let key = hex::encode(container_id);
        self.entries.insert(key, gen);
        self.persist()
    }

    /// Remove the baseline for this container.
    ///
    /// Use this to allow mounting a known-good backup or restore without
    /// triggering a rollback error on the next open.
    pub fn reset(&mut self, container_id: &[u8; 16]) -> Result<()> {
        let key = hex::encode(container_id);
        self.entries.remove(&key);
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(VnmError::Io)?;
        }
        let json = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        std::fs::write(&self.path, json).map_err(VnmError::Io)
    }
}

fn state_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".config")
        .join("venom")
        .join("rollback.json")
}
