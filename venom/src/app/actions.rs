use vnmcore::{
    container::CipherAlgorithm,
    fs::Vault,
};
use crate::app::state::{VenomApp, MountedVault};

impl VenomApp {
    pub fn action_create_vault(&mut self) {
        let v = &self.create_view;

        if v.vault_path.is_empty() {
            self.set_status("Vault path is required.", true);
            return;
        }
        if v.password.is_empty() {
            self.set_status("Password is required.", true);
            return;
        }
        if v.password != v.password_confirm {
            self.set_status("Passwords do not match.", true);
            return;
        }

        let cipher = match v.cipher_index {
            0 => CipherAlgorithm::ChaCha20Poly1305,
            _ => CipherAlgorithm::Aes256Gcm,
        };

        let profile = if v.high_security { "sensitive" } else { "interactive" };
        let label = if v.label.is_empty() { None } else { Some(v.label.clone()) };

        match Vault::create(&v.vault_path, v.password.as_bytes(), cipher, profile, label) {
            Ok(_) => {
                self.set_status(
                    format!("Vault created at {}", v.vault_path),
                    false,
                );
                self.create_view = Default::default();
                self.screen = crate::app::state::Screen::VaultList;
            }
            Err(e) => self.set_status(format!("Error: {e}"), true),
        }
    }

    pub fn action_mount_vault(&mut self) {
        let v = &self.mount_view;

        if v.vault_path.is_empty() || v.mountpoint.is_empty() {
            self.set_status("Vault path and mountpoint are required.", true);
            return;
        }
        if v.password.is_empty() {
            self.set_status("Password is required.", true);
            return;
        }

        match Vault::open(&v.vault_path, v.password.as_bytes()) {
            Ok(vault) => {
                let label = vault.config.label.clone();
                let cipher = vault.config.cipher.to_string();
                let vault_path = v.vault_path.clone();
                let mountpoint = v.mountpoint.clone();

                #[cfg(target_family = "unix")]
                {
                    use std::sync::Arc;
                    let vault_arc = Arc::new(vault);
                    let mp = mountpoint.clone();
                    std::thread::spawn(move || {
                        let _ = vnmcore::fs::fuse::driver::mount(vault_arc, &mp);
                    });
                }

                self.mounted.push(MountedVault {
                    vault_path,
                    mountpoint: mountpoint.clone(),
                    label,
                    cipher,
                });

                self.set_status(format!("Vault mounted at {mountpoint}"), false);
                self.mount_view = Default::default();
                self.screen = crate::app::state::Screen::VaultList;
            }
            Err(e) => self.set_status(format!("Error: {e}"), true),
        }
    }

    pub fn action_unmount(&mut self, index: usize) {
        if let Some(mv) = self.mounted.get(index) {
            let mp = mv.mountpoint.clone();

            #[cfg(target_family = "unix")]
            {
                let _ = std::process::Command::new("fusermount")
                    .args(["-u", &mp])
                    .status();
            }

            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("umount").arg(&mp).status();
            }

            self.mounted.remove(index);
            self.set_status(format!("Unmounted {mp}"), false);
        }
    }
}
