//! Local key store — manages hybrid ML-KEM + X25519 keypairs on disk.
//!
//! Storage: ~/.config/venom/keys/<fingerprint_hex>.key  (private + public)
//!          ~/.config/venom/keys/<fingerprint_hex>.pub  (public only, exported)
//!
//! Each entry is identified by its fingerprint = SHA-256(x25519_pk || mlkem_ek)[0..8].

use std::path::PathBuf;
use vnmcore::{
    HybridPublicKey, HybridPrivateKey,
    hybrid_generate,
    KeyFileData, PubFileData,
    write_key_file, write_pub_file,
    read_key_file, read_pub_file,
    fp_display,
};

#[derive(Clone, Debug)]
pub struct KeyEntry {
    pub fingerprint: [u8; 8],
    pub label:       String,
    pub created_at:  u64,
}

impl KeyEntry {
    pub fn fp_hex(&self) -> String { fp_display(&self.fingerprint) }
}

pub struct KeyStore {
    pub entries: Vec<KeyEntry>,
    dir:         PathBuf,
}

impl KeyStore {
    pub fn load() -> Self {
        let dir = key_dir();
        let _ = std::fs::create_dir_all(&dir);
        let mut entries = vec![];

        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("key") { continue; }
                if let Ok(kf) = read_key_file(&path) {
                    entries.push(KeyEntry {
                        fingerprint: kf.key.fingerprint(),
                        label:       kf.label,
                        created_at:  kf.created_at,
                    });
                }
            }
        }
        entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Self { entries, dir }
    }

    /// Generate a new hybrid keypair and save as .key file.
    pub fn generate(&mut self, label: &str) -> Result<KeyEntry, String> {
        let key = hybrid_generate();
        let fp = key.fingerprint();
        let fp_hex = fp_display(&fp);

        let key_path = self.dir.join(format!("{fp_hex}.key"));
        write_key_file(&key_path, &key, label)
            .map_err(|e| format!("write {fp_hex}.key: {e}"))?;

        let entry = KeyEntry {
            fingerprint: fp,
            label:       label.to_string(),
            created_at:  std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        self.entries.insert(0, entry.clone());
        Ok(entry)
    }

    /// Import a .key file from an arbitrary path.
    pub fn import_key(&mut self, path: &std::path::Path) -> Result<KeyEntry, String> {
        let kf = read_key_file(path).map_err(|e| e.to_string())?;
        let fp = kf.key.fingerprint();
        let fp_hex = fp_display(&fp);

        if self.entries.iter().any(|e| e.fingerprint == fp) {
            return Err(format!("Key {fp_hex} is already in the store."));
        }

        let dest = self.dir.join(format!("{fp_hex}.key"));
        write_key_file(&dest, &kf.key, &kf.label)
            .map_err(|e| format!("save: {e}"))?;

        let entry = KeyEntry { fingerprint: fp, label: kf.label, created_at: kf.created_at };
        self.entries.insert(0, entry.clone());
        Ok(entry)
    }

    /// Import a .pub file (adds a contact key without private access).
    /// Note: without the private key this can only be used for adding recipients,
    /// not for opening containers. Stored as .key file with zeroed private fields
    /// is not supported — only full keypairs are stored.
    /// For recipient-only keys, the .pub file is kept externally and passed directly.
    pub fn import_pub(&mut self, _path: &std::path::Path) -> Result<KeyEntry, String> {
        Err("Importing .pub-only contacts is not yet supported. \
             Use the .pub file directly when adding a recipient to a container.".into())
    }

    /// Export the public portion of a key as a .pub file at the chosen path.
    pub fn export_pub(&self, fp: &[u8; 8], dest: &std::path::Path) -> Result<(), String> {
        let kf = self.get_key(fp).ok_or_else(|| format!("Key {} not found", fp_display(fp)))?;
        write_pub_file(dest, &kf.public, &self.label_for(fp), kf_created_at(fp, &self.dir))
            .map_err(|e| format!("export: {e}"))
    }

    /// Remove a key from the store.
    pub fn remove(&mut self, fp: &[u8; 8]) {
        let fp_hex = fp_display(fp);
        let _ = std::fs::remove_file(self.dir.join(format!("{fp_hex}.key")));
        self.entries.retain(|e| e.fingerprint != *fp);
    }

    /// Get the full keypair (private + public) for a fingerprint.
    pub fn get_key(&self, fp: &[u8; 8]) -> Option<HybridPrivateKey> {
        let path = self.dir.join(format!("{}.key", fp_display(fp)));
        read_key_file(&path).ok().map(|kf| kf.key)
    }

    /// Get only the public portion for a fingerprint.
    pub fn get_public(&self, fp: &[u8; 8]) -> Option<HybridPublicKey> {
        self.get_key(fp).map(|k| k.public)
    }

    fn label_for(&self, fp: &[u8; 8]) -> String {
        self.entries.iter()
            .find(|e| e.fingerprint == *fp)
            .map(|e| e.label.clone())
            .unwrap_or_default()
    }

    pub fn key_dir(&self) -> &std::path::Path { &self.dir }
}

fn key_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("venom").join("keys")
}

fn kf_created_at(fp: &[u8; 8], dir: &PathBuf) -> u64 {
    let path = dir.join(format!("{}.key", fp_display(fp)));
    read_key_file(&path).ok().map(|kf| kf.created_at).unwrap_or(0)
}
