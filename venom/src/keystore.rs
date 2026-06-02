//! Local key store — manages hybrid ML-KEM + X25519 keypairs on disk.
//!
//! Storage: ~/.config/venom/keys/<fingerprint_hex>.key
//!
//! The .key file stores public portions in plaintext (always accessible)
//! and optionally protects private portions with Argon2id + ChaCha20-Poly1305.

use std::path::PathBuf;
use vnmcore::{
    HybridPublicKey, HybridPrivateKey,
    hybrid_generate,
    KeyFileData, KeyPublicData,
    write_key_file, write_key_file_protected, write_pub_file,
    read_key_file, read_key_file_protected, read_key_public, read_pub_file,
    fp_display,
};

#[derive(Clone, Debug)]
pub struct KeyEntry {
    pub fingerprint:  [u8; 8],
    pub label:        String,
    pub created_at:   u64,
    pub is_protected: bool,
}

impl KeyEntry {
    pub fn fp_hex(&self) -> String { fp_display(&self.fingerprint) }
}

pub struct KeyStore {
    pub entries: Vec<KeyEntry>,
    dir:         PathBuf,
}

impl KeyStore {
    /// Load all keypairs from disk. Reads only public portions — no passphrase needed.
    pub fn load() -> Self {
        let dir = key_dir();
        let _ = std::fs::create_dir_all(&dir);
        let mut entries = vec![];

        if let Ok(rd) = std::fs::read_dir(&dir) {
            for item in rd.flatten() {
                let path = item.path();
                if path.extension().and_then(|e| e.to_str()) != Some("key") { continue; }
                if let Ok(pub_data) = read_key_public(&path) {
                    entries.push(KeyEntry {
                        fingerprint:  pub_data.public.fingerprint(),
                        label:        pub_data.label,
                        created_at:   pub_data.created_at,
                        is_protected: pub_data.is_protected,
                    });
                }
            }
        }
        entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Self { entries, dir }
    }

    // ── Generate ──────────────────────────────────────────────────────────────

    /// Generate a new keypair without passphrase protection.
    pub fn generate(&mut self, label: &str) -> Result<KeyEntry, String> {
        self.generate_inner(label, None, 0)
    }

    /// Generate a new keypair protected by `passphrase`.
    pub fn generate_protected(&mut self, label: &str, passphrase: &[u8], kdf_profile: u8) -> Result<KeyEntry, String> {
        self.generate_inner(label, Some(passphrase), kdf_profile)
    }

    fn generate_inner(&mut self, label: &str, passphrase: Option<&[u8]>, kdf_profile: u8) -> Result<KeyEntry, String> {
        let key = hybrid_generate();
        let fp     = key.fingerprint();
        let fp_hex = fp_display(&fp);
        let path   = self.dir.join(format!("{fp_hex}.key"));

        match passphrase {
            Some(pw) => write_key_file_protected(&path, &key, label, pw, kdf_profile)
                .map_err(|e| format!("write: {e}"))?,
            None     => write_key_file(&path, &key, label)
                .map_err(|e| format!("write: {e}"))?,
        }

        let entry = KeyEntry {
            fingerprint:  fp,
            label:        label.to_string(),
            created_at:   std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_protected: passphrase.is_some(),
        };
        self.entries.insert(0, entry.clone());
        Ok(entry)
    }

    // ── Import ────────────────────────────────────────────────────────────────

    /// Import a .key file from an arbitrary path (copies to the key store).
    pub fn import_key(&mut self, path: &std::path::Path) -> Result<KeyEntry, String> {
        let pub_data = read_key_public(path).map_err(|e| e.to_string())?;
        let fp       = pub_data.public.fingerprint();
        let fp_hex   = fp_display(&fp);

        if self.entries.iter().any(|e| e.fingerprint == fp) {
            return Err(format!("Key {fp_hex} is already in the store."));
        }

        let dest = self.dir.join(format!("{fp_hex}.key"));
        std::fs::copy(path, &dest).map_err(|e| format!("copy: {e}"))?;

        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
        }

        let entry = KeyEntry {
            fingerprint:  fp,
            label:        pub_data.label,
            created_at:   pub_data.created_at,
            is_protected: pub_data.is_protected,
        };
        self.entries.insert(0, entry.clone());
        Ok(entry)
    }

    // ── Export ────────────────────────────────────────────────────────────────

    /// Export the public key of a given fingerprint as a `.pub` file.
    pub fn export_pub(&self, fp: &[u8; 8], dest: &std::path::Path) -> Result<(), String> {
        let src = self.dir.join(format!("{}.key", fp_display(fp)));
        let pub_data = read_key_public(&src).map_err(|e| e.to_string())?;
        let entry = self.entries.iter().find(|e| e.fingerprint == *fp);
        let label = entry.map(|e| e.label.as_str()).unwrap_or("");
        write_pub_file(dest, &pub_data.public, label, pub_data.created_at)
            .map_err(|e| format!("export: {e}"))
    }

    // ── Passphrase management ─────────────────────────────────────────────────

    /// Add or change passphrase on an existing key.
    /// `old_passphrase`: None if key is currently unprotected.
    pub fn protect(&mut self, fp: &[u8; 8], old_passphrase: Option<&[u8]>, new_passphrase: &[u8], kdf_profile: u8) -> Result<(), String> {
        let path = self.dir.join(format!("{}.key", fp_display(fp)));
        let kf = match old_passphrase {
            Some(pw) => read_key_file_protected(&path, pw).map_err(|e| e.to_string())?,
            None     => read_key_file(&path).map_err(|e| e.to_string())?,
        };
        write_key_file_protected(&path, &kf.key, &kf.label, new_passphrase, kdf_profile)
            .map_err(|e| e.to_string())?;
        if let Some(e) = self.entries.iter_mut().find(|e| e.fingerprint == *fp) {
            e.is_protected = true;
        }
        Ok(())
    }

    /// Remove passphrase protection from a key.
    pub fn unprotect(&mut self, fp: &[u8; 8], passphrase: &[u8]) -> Result<(), String> {
        let path = self.dir.join(format!("{}.key", fp_display(fp)));
        let kf = read_key_file_protected(&path, passphrase).map_err(|e| e.to_string())?;
        write_key_file(&path, &kf.key, &kf.label).map_err(|e| e.to_string())?;
        if let Some(e) = self.entries.iter_mut().find(|e| e.fingerprint == *fp) {
            e.is_protected = false;
        }
        Ok(())
    }

    // ── Key access ────────────────────────────────────────────────────────────

    /// Get the public portion (no passphrase needed).
    pub fn get_public(&self, fp: &[u8; 8]) -> Option<HybridPublicKey> {
        let path = self.dir.join(format!("{}.key", fp_display(fp)));
        read_key_public(&path).ok().map(|d| d.public)
    }

    /// Get the full keypair. Fails if the key is protected (use `get_key_protected`).
    pub fn get_key(&self, fp: &[u8; 8]) -> Option<HybridPrivateKey> {
        let path = self.dir.join(format!("{}.key", fp_display(fp)));
        read_key_file(&path).ok().map(|kf| kf.key)
    }

    /// Get the full keypair, decrypting with passphrase if needed.
    pub fn get_key_with_passphrase(&self, fp: &[u8; 8], passphrase: &[u8]) -> Result<HybridPrivateKey, String> {
        let path = self.dir.join(format!("{}.key", fp_display(fp)));
        read_key_file_protected(&path, passphrase)
            .map(|kf| kf.key)
            .map_err(|e| e.to_string())
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    pub fn remove(&mut self, fp: &[u8; 8]) {
        let _ = std::fs::remove_file(self.dir.join(format!("{}.key", fp_display(fp))));
        self.entries.retain(|e| e.fingerprint != *fp);
    }

    pub fn key_dir(&self) -> &std::path::Path { &self.dir }
}

fn key_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("venom").join("keys")
}
