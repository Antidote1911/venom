use std::sync::{Arc, Mutex};
use vnmcore::container::CipherAlgorithm;
use vnmcore::fs::Vault;
use crate::app::state::{MountStatus, MountedVault, Screen, VenomApp};

impl VenomApp {
    // ── Create ────────────────────────────────────────────────────────────────

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
                self.set_status(format!("Vault created at {}", v.vault_path), false);
                self.create_view = Default::default();
                self.screen = Screen::VaultList;
            }
            Err(e) => self.set_status(format!("Error: {e}"), true),
        }
    }

    // ── Mount (async) ─────────────────────────────────────────────────────────

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

        // Reject duplicate mountpoints.
        if self.mounted.iter().any(|mv| mv.mountpoint == v.mountpoint) {
            self.set_status(
                format!("'{}' is already in use as a mountpoint.", v.mountpoint),
                true,
            );
            return;
        }

        let status = Arc::new(Mutex::new(MountStatus::Mounting));
        let status_thread = Arc::clone(&status);
        let vault_path = v.vault_path.clone();
        let mountpoint = v.mountpoint.clone();
        let password = v.password.as_bytes().to_vec();
        let ctx = self.egui_ctx.clone();

        // Spawn a dedicated thread so KDF + FUSE never block the UI thread.
        #[cfg(target_family = "unix")]
        std::thread::Builder::new()
            .name(format!("vnm-mount:{mountpoint}"))
            .spawn(move || {
                use vnmcore::fs::fuse::driver;

                match Vault::open(&vault_path, &password) {
                    Ok(vault) => {
                        // Vault opened → update status before blocking on FUSE mount.
                        *status_thread.lock().unwrap() = MountStatus::Mounted {
                            label: vault.config.label.clone(),
                            cipher: vault.config.cipher.to_string(),
                            created_at: vault.config.created_at,
                        };
                        ctx.request_repaint();

                        // Blocks until the filesystem is unmounted.
                        if let Err(e) = driver::mount(Arc::new(vault), &mountpoint) {
                            *status_thread.lock().unwrap() =
                                MountStatus::Error(format!("FUSE error: {e}"));
                            ctx.request_repaint();
                        }
                    }
                    Err(e) => {
                        *status_thread.lock().unwrap() = MountStatus::Error(e.to_string());
                        ctx.request_repaint();
                    }
                }
            })
            .expect("failed to spawn mount thread");

        #[cfg(not(target_family = "unix"))]
        {
            *status.lock().unwrap() =
                MountStatus::Error("FUSE is only supported on Linux / macOS.".into());
        }

        self.mounted.push(MountedVault {
            vault_path: v.vault_path.clone(),
            mountpoint: v.mountpoint.clone(),
            status,
        });

        self.mount_view = Default::default();
        self.screen = Screen::VaultList;
    }

    // ── Unmount ───────────────────────────────────────────────────────────────

    pub fn action_unmount(&mut self, index: usize) {
        if let Some(mv) = self.mounted.get(index) {
            let mp = mv.mountpoint.clone();
            unmount_platform(&mp);
            self.mounted.remove(index);
            self.set_status(format!("Unmounted {mp}"), false);
        }
    }

    /// Remove a vault card that is in an Error state.
    pub fn action_dismiss_error(&mut self, index: usize) {
        if index < self.mounted.len() {
            self.mounted.remove(index);
        }
    }

    // ── Open folder ───────────────────────────────────────────────────────────

    pub fn action_open_folder(&self, path: &str) {
        open_in_file_manager(path);
    }
}

// ── Platform helpers ──────────────────────────────────────────────────────────

fn unmount_platform(mountpoint: &str) {
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    {
        // Try fusermount3 first (libfuse3), then fusermount (libfuse2).
        let ok = std::process::Command::new("fusermount3")
            .args(["-u", mountpoint])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::process::Command::new("fusermount")
                .args(["-u", mountpoint])
                .status();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("umount").arg(mountpoint).status();
    }
    #[cfg(target_os = "windows")]
    {
        // WinFsp / Dokan: not yet implemented.
        let _ = mountpoint;
    }
}

fn open_in_file_manager(path: &str) {
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(path).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer").arg(path).spawn();
    }
}
