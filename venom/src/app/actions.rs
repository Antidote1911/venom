use std::sync::{Arc, Mutex};
use vnmcore::container::CipherAlgorithm;
use vnmcore::fs::container::{VnmContainer, HiddenVolumeOptions};
use crate::app::state::{MountStatus, MountedVault, Screen, VenomApp};
use crate::recent::read_cipher_from_bootstrap;

/// Background thread that opens the container, signals Mounted, then blocks on the
/// OS-level mount. Works on Linux/macOS (FUSE) and Windows (WinFSP).
fn mount_thread(
    status:     Arc<Mutex<MountStatus>>,
    vault_path: String,
    mountpoint: String,
    password:   Vec<u8>,
    ctx:        egui::Context,
) {
    use vnmcore::OpenCredential;
    match VnmContainer::open(&vault_path, OpenCredential::Password(&password)) {
        Ok(c) => {
            *status.lock().unwrap() = MountStatus::Mounted {
                label:      c.label.clone(),
                cipher:     c.cipher.to_string(),
                created_at: c.created_at,
                is_hidden:  c.is_hidden,
            };
            ctx.request_repaint();

            let result = platform_mount(Arc::new(c), &mountpoint);

            match result {
                Ok(_) => {
                    *status.lock().unwrap() = MountStatus::Gone;
                }
                Err(e) => {
                    *status.lock().unwrap() = MountStatus::Error(format!("{e}"));
                }
            }
            ctx.request_repaint();
        }
        Err(e) => {
            *status.lock().unwrap() = MountStatus::Error(e.to_string());
            ctx.request_repaint();
        }
    }
}

/// Dispatch to the right mount backend for this platform.
fn platform_mount(container: Arc<VnmContainer>, mountpoint: &str) -> vnmcore::Result<()> {
    // Linux / macOS → FUSE
    #[cfg(target_family = "unix")]
    return vnmcore::fs::fuse::driver::mount(container, mountpoint);

    // Windows → WinFSP
    #[cfg(target_os = "windows")]
    return vnmcore::fs::winfsp::mount(container, mountpoint);

    // Compile-time unreachable on all currently supported platforms
    #[allow(unreachable_code)]
    Err(vnmcore::VnmError::InvalidFormat("Unsupported platform".into()))
}

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

        let selected_recipients = self.create_view.selected_recipients.clone();

        match VnmContainer::create(&container_path, &password, total_bytes, cipher, profile, label, hidden_opt) {
            Ok(container) => {
                // Add selected key recipients
                let mut recipient_errors = vec![];
                for fp in &selected_recipients {
                    match self.keys.get_public(fp) {
                        Some(pub_key) => {
                            if let Err(e) = container.add_key_recipient(&pub_key) {
                                recipient_errors.push(format!("{}: {e}", vnmcore::fp_display(fp)));
                            }
                        }
                        None => recipient_errors.push(format!("{}: key not found", vnmcore::fp_display(fp))),
                    }
                }
                container.flush().ok();

                self.recent.add(&container_path, None, Some(cipher_str));

                if recipient_errors.is_empty() {
                    let n = selected_recipients.len();
                    let extra = if n > 0 { format!(" (+{n} recipient(s))") } else { String::new() };
                    self.set_status(format!("Container created{extra}: {container_path}"), false);
                } else {
                    self.set_status(
                        format!("Container created but some recipients failed: {}", recipient_errors.join("; ")),
                        true,
                    );
                }
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

        std::thread::Builder::new()
            .name(format!("vnm-mount:{mountpoint}"))
            .spawn(move || {
                mount_thread(st_thread, vault_path, mountpoint, password, ctx);
            })
            .expect("failed to spawn mount thread");

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
    {
        // WinFSP provides a command-line tool to unmount: `net use <drive> /delete`
        // or simply `winfsp.exe /unmount <mp>`. We try both.
        let result = std::process::Command::new("net")
            .args(["use", mountpoint, "/delete", "/y"])
            .status();
        match result {
            Ok(s) if s.success() => Ok(()),
            _ => {
                // Fallback: try WinFSP's own utility
                std::process::Command::new("winfsp.exe")
                    .args(["/unmount", mountpoint])
                    .status()
                    .map_err(|e| e.to_string())
                    .and_then(|s| if s.success() { Ok(()) } else { Err(format!("winfsp unmount failed")) })
            }
        }
    }
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

// ── Recipient management ──────────────────────────────────────────────────────

impl VenomApp {
    /// Open the recipient management screen for a mounted vault.
    pub fn action_open_recipients(&mut self, vault_path: String, mountpoint: String) {
        use vnmcore::{VnmContainer, OpenCredential};
        // List recipients (needs to open the container with known credentials)
        // For display we just read the plaintext slot counts without decrypting.
        // We can't add/remove without K_master, but we can show the list.
        self.recipient_view.container_path = vault_path.clone();
        self.recipient_view.mountpoint     = Some(mountpoint);
        self.recipient_view.recipients     = vec![];
        self.recipient_view.new_password   = String::new();
        self.recipient_view.new_pubkey_path = String::new();
        self.screen = crate::app::state::Screen::Recipients;
    }

    /// Load recipient list from a container opened with K_master (requires the container to be
    /// accessible). For now, we open with a stored credential (future: use K_master from mount).
    pub fn action_load_recipients(&mut self, password: Vec<u8>) {
        use vnmcore::{VnmContainer, OpenCredential};
        let path = self.recipient_view.container_path.clone();
        match VnmContainer::open(&path, OpenCredential::Password(&password)) {
            Ok(c) => match c.list_recipients() {
                Ok(list) => {
                    self.recipient_view.recipients = list;
                    self.set_status("Recipients loaded.", false);
                }
                Err(e) => self.set_status(format!("Error: {e}"), true),
            },
            Err(e) => self.set_status(format!("Could not open container: {e}"), true),
        }
    }

    /// Generate a new ML-KEM-1024 keypair and save to .vpub / .vpriv files.
    pub fn action_generate_keypair(&mut self) {
        use std::io::Write;
        let base = self.recipient_view.keygen_path.trim().to_string();
        if base.is_empty() { self.set_status("Choose a file path first.", true); return; }

        let (seed, ek) = vnmcore::kem_generate();
        let pub_path  = format!("{base}.vpub");
        let priv_path = format!("{base}.vpriv");

        match std::fs::write(&pub_path, ek) {
            Err(e) => { self.set_status(format!("Write {pub_path}: {e}"), true); return; }
            Ok(_)  => {}
        }
        match std::fs::write(&priv_path, seed) {
            Err(e) => { self.set_status(format!("Write {priv_path}: {e}"), true); return; }
            Ok(_)  => {}
        }

        let fp = vnmcore::crypto::kem::fingerprint(&ek);
        let fp_hex: String = fp.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
        self.set_status(
            format!("Keypair generated. Public key: {pub_path}\nFingerprint: {fp_hex}"),
            false,
        );
        self.recipient_view.keygen_path.clear();
    }

    /// Add a password recipient to the container (requires current K_master via re-open).
    pub fn action_add_password_recipient(&mut self) {
        // TODO: use K_master from the active mount instead of re-opening.
        // For now: prompt not implemented — the user needs to call via the password-loaded flow.
        self.set_status(
            "To add a password recipient, re-open the container with your current password first \
             (action_load_recipients), then this action will work.",
            true,
        );
    }

    /// Add an ML-KEM recipient using a .vpub file.
    pub fn action_add_key_recipient(&mut self) {
        let pubkey_path = self.recipient_view.new_pubkey_path.clone();
        let container_path = self.recipient_view.container_path.clone();

        match std::fs::read(&pubkey_path) {
            Ok(bytes) => {
                if bytes.len() != vnmcore::crypto::kem::EK_SIZE {
                    self.set_status(
                        format!("Invalid public key file (expected {} bytes, got {})",
                            vnmcore::crypto::kem::EK_SIZE, bytes.len()),
                        true,
                    );
                    return;
                }
                let ek: vnmcore::KemEncapKey = bytes.try_into().unwrap();
                // TODO: get K_master from active mount. Currently requires re-open.
                self.set_status(
                    format!("Public key loaded from {pubkey_path}. \
                             Re-open with your password to add this recipient."),
                    false,
                );
                // Store EK for future use when K_master is available
                self.recipient_view.new_pubkey_path.clear();
            }
            Err(e) => self.set_status(format!("Read {pubkey_path}: {e}"), true),
        }
    }

    /// Remove an ML-KEM recipient by fingerprint.
    pub fn action_remove_key_recipient(&mut self, fp: [u8; 8]) {
        // TODO: requires K_master from active mount.
        let fp_hex: String = fp.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
        self.set_status(
            format!("Remove recipient {fp_hex}: requires K_master from active mount (coming soon)."),
            true,
        );
    }
}
