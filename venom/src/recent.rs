use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ENTRIES: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentVault {
    /// Absolute path to the vault directory.
    pub path: String,
    /// Cached from config — populated after a successful open.
    pub label: Option<String>,
    /// e.g. "chacha20-poly1305"
    pub cipher: Option<String>,
    /// Unix seconds of last successful mount.
    pub last_used: u64,
}

impl RecentVault {
    pub fn display_name(&self) -> &str {
        self.label.as_deref().unwrap_or_else(|| {
            // Fall back to the last path component.
            std::path::Path::new(&self.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&self.path)
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecentList {
    pub entries: Vec<RecentVault>,
}

impl RecentList {
    /// Load from `~/.config/venom/recent.json` (returns empty list on any error).
    pub fn load() -> Self {
        std::fs::read(config_path())
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default()
    }

    /// Persist to disk. Silent on error (non-essential feature).
    pub fn save(&self) {
        let path = config_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_vec_pretty(self) {
            let _ = std::fs::write(&path, json);
        }
    }

    /// Add or bump `vault_path` to the front of the list, then persist.
    pub fn add(&mut self, vault_path: &str, label: Option<String>, cipher: Option<String>) {
        self.entries.retain(|e| e.path != vault_path);
        self.entries.insert(
            0,
            RecentVault {
                path: vault_path.to_string(),
                label,
                cipher,
                last_used: now_secs(),
            },
        );
        self.entries.truncate(MAX_ENTRIES);
        self.save();
    }

    /// Update label/cipher for an existing entry (called after a successful open).
    /// Returns true when the entry was found and the metadata changed.
    pub fn update_metadata(
        &mut self,
        vault_path: &str,
        label: Option<String>,
        cipher: Option<String>,
    ) -> bool {
        if let Some(e) = self.entries.iter_mut().find(|e| e.path == vault_path) {
            if e.label != label || e.cipher != cipher {
                e.label = label;
                e.cipher = cipher;
                e.last_used = now_secs();
                self.save();
                return true;
            }
        }
        false
    }

    pub fn remove(&mut self, vault_path: &str) {
        self.entries.retain(|e| e.path != vault_path);
        self.save();
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".config")
        .join("venom")
        .join("recent.json")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Read the cipher from `vnm_bootstrap.json` without decryption — used to
/// populate the recent list before the vault is fully opened.
pub fn read_cipher_from_bootstrap(vault_path: &str) -> Option<String> {
    let data = std::fs::read(
        std::path::Path::new(vault_path).join("vnm_bootstrap.json"),
    )
    .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&data).ok()?;
    v.get("cipher")?.as_str().map(|s| {
        // The serde name is snake_case; normalise for display.
        match s {
            "chacha20_poly1305" => "chacha20-poly1305".into(),
            "aes256_gcm"        => "aes-256-gcm".into(),
            other               => other.into(),
        }
    })
}
