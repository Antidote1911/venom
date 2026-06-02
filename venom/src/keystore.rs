//! Local key store — manages ML-KEM key pairs on disk.
//!
//! Keys are stored in `~/.config/venom/keys/`:
//!   <fingerprint_hex>.vpub   — public key (always present)
//!   <fingerprint_hex>.vpriv  — private key (present only for own keys)
//!
//! A key pair is identified by its 8-byte fingerprint (SHA-256 of the public key).

use std::path::PathBuf;
use vnmcore::{
    KemEncapKey, KemSeed,
    PubKeyFile, PrivKeyFile,
    write_pub_file, write_priv_file,
    read_pub_file, read_priv_file,
    fp_display,
    kem_generate, kem_ek_from_seed,
};

/// Summary of one key in the local store.
#[derive(Clone, Debug)]
pub struct KeyEntry {
    pub fingerprint: [u8; 8],
    pub label:       String,
    pub created_at:  u64,
    /// True when we have the corresponding private key.
    pub has_private: bool,
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
                if path.extension().and_then(|e| e.to_str()) != Some("vpub") { continue; }

                if let Ok(pk) = read_pub_file(&path) {
                    let priv_path = dir.join(format!("{}.vpriv", fp_display(&pk.fingerprint)));
                    let has_private = priv_path.exists();
                    entries.push(KeyEntry {
                        fingerprint: pk.fingerprint,
                        label:       pk.label,
                        created_at:  pk.created_at,
                        has_private,
                    });
                }
            }
        }

        // Sort by creation date descending (newest first)
        entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Self { entries, dir }
    }

    /// Generate a new ML-KEM-1024 keypair, save both files, return the entry.
    pub fn generate(&mut self, label: &str) -> Result<KeyEntry, String> {
        let (seed, ek) = kem_generate();
        let fp = vnmcore::crypto::kem::fingerprint(&ek);
        let fp_hex = fp_display(&fp);

        let pub_path  = self.dir.join(format!("{fp_hex}.vpub"));
        let priv_path = self.dir.join(format!("{fp_hex}.vpriv"));

        write_pub_file(&pub_path, &ek, label)
            .map_err(|e| format!("write {fp_hex}.vpub: {e}"))?;
        write_priv_file(&priv_path, &seed, &ek, label)
            .map_err(|e| format!("write {fp_hex}.vpriv: {e}"))?;

        let entry = KeyEntry {
            fingerprint: fp,
            label:       label.to_string(),
            created_at:  std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            has_private: true,
        };
        self.entries.insert(0, entry.clone());
        Ok(entry)
    }

    /// Import a .vpub file from an arbitrary path.
    pub fn import_pub(&mut self, path: &std::path::Path) -> Result<KeyEntry, String> {
        let pk = read_pub_file(path).map_err(|e| e.to_string())?;
        let fp_hex = fp_display(&pk.fingerprint);

        // Don't duplicate
        if self.entries.iter().any(|e| e.fingerprint == pk.fingerprint) {
            return Err(format!("Key {fp_hex} already in the store."));
        }

        let dest = self.dir.join(format!("{fp_hex}.vpub"));
        write_pub_file(&dest, &pk.ek, &pk.label)
            .map_err(|e| format!("save: {e}"))?;

        let entry = KeyEntry {
            fingerprint: pk.fingerprint,
            label:       pk.label,
            created_at:  pk.created_at,
            has_private: false,
        };
        self.entries.insert(0, entry.clone());
        Ok(entry)
    }

    /// Import a .vpriv file. The matching .vpub is derived from the seed.
    pub fn import_priv(&mut self, path: &std::path::Path) -> Result<KeyEntry, String> {
        let sk = read_priv_file(path).map_err(|e| e.to_string())?;
        let ek = kem_ek_from_seed(&sk.seed);
        let fp = vnmcore::crypto::kem::fingerprint(&ek);
        let fp_hex = fp_display(&fp);

        // Save / update both files
        let pub_path  = self.dir.join(format!("{fp_hex}.vpub"));
        let priv_path = self.dir.join(format!("{fp_hex}.vpriv"));

        write_pub_file(&pub_path, &ek, &sk.label)
            .map_err(|e| format!("write {fp_hex}.vpub: {e}"))?;
        write_priv_file(&priv_path, &sk.seed, &ek, &sk.label)
            .map_err(|e| format!("write {fp_hex}.vpriv: {e}"))?;

        // Update or insert
        if let Some(e) = self.entries.iter_mut().find(|e| e.fingerprint == fp) {
            e.has_private = true;
        } else {
            self.entries.insert(0, KeyEntry {
                fingerprint: fp,
                label:       sk.label.clone(),
                created_at:  sk.created_at,
                has_private: true,
            });
        }
        Ok(self.entries.iter().find(|e| e.fingerprint == fp).unwrap().clone())
    }

    /// Export the public key of a given fingerprint to a user-chosen path.
    pub fn export_pub(&self, fp: &[u8; 8], dest: &std::path::Path) -> Result<(), String> {
        let src = self.dir.join(format!("{}.vpub", fp_display(fp)));
        std::fs::copy(&src, dest).map_err(|e| format!("copy: {e}"))?;
        Ok(())
    }

    /// Export the private key of a given fingerprint to a user-chosen path.
    pub fn export_priv(&self, fp: &[u8; 8], dest: &std::path::Path) -> Result<(), String> {
        let src = self.dir.join(format!("{}.vpriv", fp_display(fp)));
        if !src.exists() {
            return Err("Private key not available (public-key only entry).".into());
        }
        std::fs::copy(&src, dest).map_err(|e| format!("copy: {e}"))?;
        Ok(())
    }

    /// Remove a key from the store (both .vpub and .vpriv).
    pub fn remove(&mut self, fp: &[u8; 8]) {
        let fp_hex = fp_display(fp);
        let _ = std::fs::remove_file(self.dir.join(format!("{fp_hex}.vpub")));
        let _ = std::fs::remove_file(self.dir.join(format!("{fp_hex}.vpriv")));
        self.entries.retain(|e| e.fingerprint != *fp);
    }

    /// Retrieve the encapsulation key for a fingerprint.
    pub fn get_encap_key(&self, fp: &[u8; 8]) -> Option<KemEncapKey> {
        let path = self.dir.join(format!("{}.vpub", fp_display(fp)));
        read_pub_file(&path).ok().map(|pk| pk.ek)
    }

    /// Retrieve the seed (private key) for a fingerprint, if available.
    pub fn get_seed(&self, fp: &[u8; 8]) -> Option<KemSeed> {
        let path = self.dir.join(format!("{}.vpriv", fp_display(fp)));
        read_priv_file(&path).ok().map(|sk| sk.seed)
    }

    pub fn key_dir(&self) -> &std::path::Path { &self.dir }
}

fn key_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("venom").join("keys")
}
