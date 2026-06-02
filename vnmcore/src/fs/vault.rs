use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Result, VnmError};
use crate::container::{VaultConfig, CipherAlgorithm, KdfParams};
use crate::crypto::{derive_key, encrypt_block, decrypt_block};
use crate::crypto::kdf::generate_salt;
use crate::storage::{BlockStore, VaultNode, NodeKind};
use crate::storage::vault_fs::DirectoryBlock;

/// Unencrypted bootstrap metadata written alongside the vault.
/// Contains only what is needed to derive the decryption key and cipher.
/// Knowing these values does not help an attacker without the password.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Bootstrap {
    pub kdf: KdfParams,
    pub cipher: CipherAlgorithm,
}

/// High-level vault handle — owns the block store and config.
pub struct Vault {
    pub config: VaultConfig,
    pub store: BlockStore,
    root: PathBuf,
}

impl Vault {
    const CONFIG_ENC: &'static str = "vnm_config.enc";
    const BOOTSTRAP: &'static str = "vnm_bootstrap.json";

    /// Create a brand-new vault directory at `path`.
    pub fn create(
        path: impl AsRef<Path>,
        password: &[u8],
        cipher: CipherAlgorithm,
        kdf_profile: &str,
        label: Option<String>,
    ) -> Result<Self> {
        let root = path.as_ref().to_path_buf();

        if root.exists() {
            let mut entries = root.read_dir()?;
            if entries.next().is_some() {
                return Err(VnmError::VaultAlreadyExists(root.display().to_string()));
            }
        } else {
            std::fs::create_dir_all(&root)?;
        }

        let salt = generate_salt();
        let mut kdf = match kdf_profile {
            "sensitive" => KdfParams::sensitive(),
            _ => KdfParams::interactive(),
        };
        kdf.salt = salt;

        let derived = derive_key(password, &kdf)?;
        let key: [u8; 32] = derived.as_array_32().unwrap();
        let store = BlockStore::new(&root, key, cipher);

        // Empty root directory block
        let root_dir = DirectoryBlock { kind: NodeKind::Directory, entries: vec![] };
        let root_payload = bincode::serialize(&VaultNode::Directory(root_dir))
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        let root_id = store.create(&root_payload)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let config = VaultConfig {
            version: VaultConfig::FORMAT_VERSION,
            cipher,
            kdf: kdf.clone(),
            block_size: VaultConfig::DEFAULT_BLOCK_SIZE,
            root_block_id: root_id,
            created_at: now,
            label,
        };

        // Write unencrypted bootstrap (cipher + KDF params — no secrets)
        let bootstrap = Bootstrap { kdf, cipher };
        let boot_json = serde_json::to_vec_pretty(&bootstrap)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        std::fs::write(root.join(Self::BOOTSTRAP), boot_json)?;

        // Encrypt and write the full config
        let config_json = serde_json::to_vec(&config)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        let encrypted = encrypt_block(&key, cipher, b"vnm_config", &config_json)?;
        std::fs::write(root.join(Self::CONFIG_ENC), encrypted)?;

        Ok(Self { config, store, root })
    }

    /// Open an existing vault with the given password.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Self> {
        let root = path.as_ref().to_path_buf();

        if !root.exists() {
            return Err(VnmError::VaultNotFound(root.display().to_string()));
        }

        // Read unencrypted bootstrap to get KDF params + cipher
        let boot_data = std::fs::read(root.join(Self::BOOTSTRAP))
            .map_err(|_| VnmError::InvalidConfig("missing vnm_bootstrap.json".into()))?;
        let bootstrap: Bootstrap = serde_json::from_slice(&boot_data)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;

        let derived = derive_key(password, &bootstrap.kdf)?;
        let key: [u8; 32] = derived.as_array_32().unwrap();

        let enc_data = std::fs::read(root.join(Self::CONFIG_ENC))
            .map_err(|_| VnmError::InvalidConfig("missing vnm_config.enc".into()))?;
        let plain = decrypt_block(&key, bootstrap.cipher, b"vnm_config", &enc_data)?;

        let config: VaultConfig = serde_json::from_slice(&plain)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;

        let store = BlockStore::new(&root, key, config.cipher);
        Ok(Self { config, store, root })
    }

    /// Read and deserialize any block by UUID.
    pub fn read_node(&self, id: &str) -> Result<VaultNode> {
        let plain = self.store.read(id)?;
        bincode::deserialize(&plain)
            .map_err(|e| VnmError::Serialization(e.to_string()))
    }

    /// Serialize and store a new block, returning its UUID.
    pub fn write_node(&self, node: &VaultNode) -> Result<String> {
        let payload = bincode::serialize(node)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        self.store.create(&payload)
    }

    /// Overwrite an existing block in-place (new nonce, same UUID).
    pub fn update_node(&self, id: &str, node: &VaultNode) -> Result<()> {
        let payload = bincode::serialize(node)
            .map_err(|e| VnmError::Serialization(e.to_string()))?;
        self.store.write(id, &payload)
    }

    pub fn root_id(&self) -> &str {
        &self.config.root_block_id
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }
}
