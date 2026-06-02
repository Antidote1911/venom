use std::sync::{Arc, Mutex};
use vnmcore::container::CipherAlgorithm;
use vnmcore::fs::Vault;
use crate::app::state::{MountStatus, MountedVault, Screen, VenomApp};
use crate::recent::read_cipher_from_bootstrap;

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

        let vault_path = v.vault_path.clone();
        let label_for_recent = label.clone();
        let cipher_str = match cipher {
            CipherAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305",
            CipherAlgorithm::Aes256Gcm        => "aes-256-gcm",
        };

        match Vault::create(&vault_path, v.password.as_bytes(), cipher, profile, label) {
            Ok(_) => {
                self.recent.add(&vault_path, label_for_recent, Some(cipher_str.into()));
                self.set_status(format!("Vault created at {vault_path}"), false);
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
                        // Vault opened — update status before blocking on FUSE mount.
                        *status_thread.lock().unwrap() = MountStatus::Mounted {
                            label: vault.config.label.clone(),
                            cipher: vault.config.cipher.to_string(),
                            created_at: vault.config.created_at,
                        };
                        ctx.request_repaint();

                        // Blocks until fusermount3 -u (or equivalent) tears down the mount.
                        match driver::mount(Arc::new(vault), &mountpoint) {
                            Ok(_) => {
                                // Clean unmount — transition to Gone so the GUI can remove the card.
                                *status_thread.lock().unwrap() = MountStatus::Gone;
                                ctx.request_repaint();
                            }
                            Err(e) => {
                                *status_thread.lock().unwrap() =
                                    MountStatus::Error(format!("FUSE error: {e}"));
                                ctx.request_repaint();
                            }
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

        // Add to recent immediately with cipher from bootstrap (no KDF needed).
        // Label will be enriched later by update() once the thread reports Mounted.
        let cipher_hint = read_cipher_from_bootstrap(&v.vault_path);
        self.recent.add(&v.vault_path, None, cipher_hint);

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
            match unmount_platform(&mp) {
                Ok(_) => {
                    // Card will be auto-removed when the mount thread sets status → Gone.
                    // If the thread is already dead (e.g. error state), remove immediately.
                    let already_gone = !matches!(
                        *mv.status.lock().unwrap(),
                        MountStatus::Mounted { .. } | MountStatus::Mounting
                    );
                    if already_gone {
                        self.mounted.remove(index);
                    }
                    self.set_status(format!("Unmounting {mp}…"), false);
                }
                Err(e) => {
                    self.set_status(format!("Unmount failed: {e}"), true);
                }
            }
        }
    }

    /// Called every frame by update() — removes cards whose mount thread has exited.
    pub fn gc_gone_mounts(&mut self) {
        self.mounted.retain(|mv| {
            !matches!(*mv.status.lock().unwrap(), MountStatus::Gone)
        });
    }

    /// Remove a vault card that is in an Error state.
    pub fn action_dismiss_error(&mut self, index: usize) {
        if index < self.mounted.len() {
            self.mounted.remove(index);
        }
    }

    // ── Open folder ───────────────────────────────────────────────────────────

    pub fn action_open_folder(&mut self, path: &str) {
        // Verify the path is reachable before trying to open it.
        if !std::path::Path::new(path).exists() {
            self.set_status(
                format!("Cannot open '{path}': directory not found or vault not mounted."),
                true,
            );
            return;
        }

        match open_in_file_manager(path) {
            Ok(bin) => self.set_status(format!("Opened {path} with {bin}"), false),
            Err(e)  => self.set_status(format!("Could not open folder: {e}"), true),
        }
    }
}

// ── Platform helpers ──────────────────────────────────────────────────────────

/// Send the unmount signal via the appropriate helper.
/// Returns Ok(()) only when the helper exited with status 0.
fn unmount_platform(mountpoint: &str) -> Result<(), String> {
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    {
        // Prefer fusermount3 (libfuse3); fall back to fusermount (libfuse2).
        for bin in &["fusermount3", "fusermount"] {
            match std::process::Command::new(bin).args(["-u", mountpoint]).status() {
                Ok(s) if s.success() => return Ok(()),
                Ok(s) => {
                    // Exited with non-zero — try the fallback before giving up.
                    let _ = s;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    continue; // binary not installed, try next
                }
                Err(e) => return Err(format!("{bin}: {e}")),
            }
        }
        Err(format!(
            "fusermount3/fusermount failed for '{mountpoint}'. \
             Is the vault still mounted?"
        ))
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("umount")
            .arg(mountpoint)
            .status()
            .map_err(|e| e.to_string())
            .and_then(|s| {
                if s.success() { Ok(()) }
                else { Err(format!("umount exited with {s}")) }
            })
    }
    #[cfg(target_os = "windows")]
    {
        let _ = mountpoint;
        Err("Unmount not yet implemented on Windows.".into())
    }
}

/// Try to open `path` in a file manager.
/// Returns the name of the binary used on success, or an error string.
fn open_in_file_manager(path: &str) -> Result<String, String> {
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    {
        // Ordered candidate list: generic portal first, then common DEs.
        // xdg-open delegates to the right app depending on XDG_CURRENT_DESKTOP.
        // If it's missing or broken we fall back to well-known file managers.
        let candidates = [
            "xdg-open",   // generic (GNOME, KDE, XFCE, …)
            "nautilus",   // GNOME
            "dolphin",    // KDE
            "thunar",     // XFCE
            "nemo",       // Cinnamon
            "pcmanfm",    // LXDE / LXQt
            "caja",       // MATE
        ];

        let mut last_err = String::from("no file manager found in PATH");

        for bin in &candidates {
            match std::process::Command::new(bin).arg(path).spawn() {
                Ok(_)  => return Ok(bin.to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Not installed — try the next candidate.
                    continue;
                }
                Err(e) => {
                    // Present but failed to launch (permissions, etc.).
                    last_err = format!("{bin}: {e}");
                    continue;
                }
            }
        }

        Err(last_err)
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path)
            .spawn()
            .map(|_| "open".to_string())
            .map_err(|e| format!("open: {e}"))
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(path)
            .spawn()
            .map(|_| "explorer".to_string())
            .map_err(|e| format!("explorer: {e}"))
    }
}
