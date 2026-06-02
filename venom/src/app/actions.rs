use std::sync::{Arc, Mutex};
use vnmcore::container::CipherAlgorithm;
use vnmcore::fs::container::{VnmContainer, HiddenVolumeOptions};
use crate::app::state::{MountStatus, MountedVault, Screen, VenomApp};
use crate::recent::read_cipher_from_bootstrap;

impl VenomApp {
    // ── Create ────────────────────────────────────────────────────────────────

    pub fn action_create_vault(&mut self) {
        let v = &self.create_view;

        if v.container_path.is_empty() {
            self.set_status("Container file path is required.", true);
            return;
        }
        if v.size_mb == 0 {
            self.set_status("Container size must be > 0 MB.", true);
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
        if v.hidden_enabled {
            if v.hidden_password.is_empty() {
                self.set_status("Hidden volume password is required.", true);
                return;
            }
            if v.hidden_password != v.hidden_password_confirm {
                self.set_status("Hidden volume passwords do not match.", true);
                return;
            }
            if v.hidden_size_mb == 0 {
                self.set_status("Hidden volume size must be > 0 MB.", true);
                return;
            }
            let min_outer = v.hidden_size_mb + 2;
            if v.size_mb <= min_outer {
                self.set_status(
                    format!("Total size must be > {} MB to fit the hidden volume.", min_outer),
                    true,
                );
                return;
            }
        }

        let cipher = match v.cipher_index {
            0 => CipherAlgorithm::ChaCha20Poly1305,
            _ => CipherAlgorithm::Aes256Gcm,
        };
        let profile = if v.high_security { "sensitive" } else { "interactive" };
        let label   = if v.label.is_empty() { None } else { Some(v.label.clone()) };
        let total_bytes = v.size_mb as u64 * 1024 * 1024;

        // Build hidden options if requested
        let hidden_bytes    = v.hidden_size_mb as u64 * 1024 * 1024;
        let hidden_password = v.hidden_password.as_bytes().to_vec();
        let hidden_label    = if v.hidden_label.is_empty() { None } else { Some(v.hidden_label.clone()) };
        let hidden_enabled  = v.hidden_enabled;
        let hidden_profile  = if v.high_security { "sensitive" } else { "interactive" };

        let container_path = v.container_path.clone();
        let password = v.password.as_bytes().to_vec();
        let cipher_str = cipher.as_str().to_string();

        // Create is synchronous for now (runs KDF + fills container with random bytes)
        // TODO: make async with progress indicator for large containers
        let hidden_opt = if hidden_enabled {
            Some(HiddenVolumeOptions {
                password: &hidden_password,
                size_bytes: hidden_bytes,
                label: hidden_label,
                kdf_profile: hidden_profile,
            })
        } else {
            None
        };

        match VnmContainer::create(&container_path, &password, total_bytes, cipher, profile, label, hidden_opt) {
            Ok(_) => {
                self.recent.add(&container_path, None, Some(cipher_str));
                self.set_status(format!("Container created: {container_path}"), false);
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
            self.set_status("Container path and mountpoint are required.", true);
            return;
        }
        if v.password.is_empty() {
            self.set_status("Password is required.", true);
            return;
        }
        if self.mounted.iter().any(|mv| mv.mountpoint == v.mountpoint) {
            self.set_status(format!("'{}' is already in use as a mountpoint.", v.mountpoint), true);
            return;
        }

        let status     = Arc::new(Mutex::new(MountStatus::Mounting));
        let st_thread  = Arc::clone(&status);
        let vault_path = v.vault_path.clone();
        let mountpoint = v.mountpoint.clone();
        let password   = v.password.as_bytes().to_vec();
        let ctx        = self.egui_ctx.clone();

        #[cfg(target_family = "unix")]
        std::thread::Builder::new()
            .name(format!("vnm-mount:{mountpoint}"))
            .spawn(move || {
                use vnmcore::fs::fuse::driver;
                match VnmContainer::open(&vault_path, &password) {
                    Ok(c) => {
                        *st_thread.lock().unwrap() = MountStatus::Mounted {
                            label:      c.label.clone(),
                            cipher:     c.cipher.to_string(),
                            created_at: c.created_at,
                            is_hidden:  c.is_hidden,
                        };
                        ctx.request_repaint();
                        if let Err(e) = driver::mount(Arc::new(c), &mountpoint) {
                            *st_thread.lock().unwrap() = MountStatus::Error(format!("FUSE: {e}"));
                            ctx.request_repaint();
                        } else {
                            *st_thread.lock().unwrap() = MountStatus::Gone;
                            ctx.request_repaint();
                        }
                    }
                    Err(e) => {
                        *st_thread.lock().unwrap() = MountStatus::Error(e.to_string());
                        ctx.request_repaint();
                    }
                }
            })
            .expect("failed to spawn mount thread");

        #[cfg(not(target_family = "unix"))]
        {
            *status.lock().unwrap() = MountStatus::Error("FUSE is only supported on Linux / macOS.".into());
        }

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
        if index >= self.mounted.len() { return; }
        let mp = self.mounted[index].mountpoint.clone();
        let already_gone = !matches!(
            *self.mounted[index].status.lock().unwrap(),
            MountStatus::Mounted { .. } | MountStatus::Mounting
        );
        match unmount_platform(&mp) {
            Ok(_)  => { self.set_status(format!("Unmounting {mp}…"), false); }
            Err(e) => { self.set_status(format!("Unmount failed: {e}"), true); return; }
        }
        if already_gone { self.mounted.remove(index); }
    }

    pub fn action_dismiss_error(&mut self, index: usize) {
        if index < self.mounted.len() { self.mounted.remove(index); }
    }

    pub fn gc_gone_mounts(&mut self) {
        // Enrich recent with label/cipher/is_hidden from newly-Mounted vaults
        for mv in &self.mounted {
            if self.recent_enriched.contains(&mv.vault_path) { continue; }
            if let MountStatus::Mounted { label, cipher, .. } = &*mv.status.lock().unwrap() {
                self.recent.update_metadata(&mv.vault_path, label.clone(), Some(cipher.clone()));
                self.recent_enriched.insert(mv.vault_path.clone());
            }
        }
        self.mounted.retain(|mv| !matches!(*mv.status.lock().unwrap(), MountStatus::Gone));
    }

    // ── Open folder ───────────────────────────────────────────────────────────

    pub fn action_open_folder(&mut self, path: &str) {
        if !std::path::Path::new(path).exists() {
            self.set_status(format!("Cannot open '{path}': not mounted or not found."), true);
            return;
        }
        match open_in_file_manager(path) {
            Ok(bin) => self.set_status(format!("Opened {path} with {bin}"), false),
            Err(e)  => self.set_status(format!("Could not open folder: {e}"), true),
        }
    }
}

// ── Platform helpers ──────────────────────────────────────────────────────────

fn unmount_platform(mountpoint: &str) -> Result<(), String> {
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    {
        for bin in &["fusermount3", "fusermount"] {
            match std::process::Command::new(bin).args(["-u", mountpoint]).status() {
                Ok(s) if s.success() => return Ok(()),
                Ok(_)  => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{bin}: {e}")),
            }
        }
        Err(format!("fusermount3/fusermount failed for '{mountpoint}'"))
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("umount").arg(mountpoint).status()
            .map_err(|e| e.to_string())
            .and_then(|s| if s.success() { Ok(()) } else { Err(format!("umount: {s}")) })
    }
    #[cfg(target_os = "windows")]
    { let _ = mountpoint; Err("Not implemented on Windows.".into()) }
}

fn open_in_file_manager(path: &str) -> Result<String, String> {
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    {
        for bin in &["xdg-open","nautilus","dolphin","thunar","nemo","pcmanfm","caja"] {
            match std::process::Command::new(bin).arg(path).spawn() {
                Ok(_)  => return Ok(bin.to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{bin}: {e}")),
            }
        }
        Err("no file manager found".into())
    }
    #[cfg(target_os = "macos")]
    { std::process::Command::new("open").arg(path).spawn().map(|_| "open".into()).map_err(|e| e.to_string()) }
    #[cfg(target_os = "windows")]
    { std::process::Command::new("explorer").arg(path).spawn().map(|_| "explorer".into()).map_err(|e| e.to_string()) }
}
