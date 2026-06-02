use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use crate::recent::RecentList;
use crate::keystore::KeyStore;
use crate::ui::{CreateView, MountView};

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    VaultList,
    Create,
    Mount,
    Recipients,
    KeyManager,
}

#[derive(Debug, Clone)]
pub enum MountStatus {
    Mounting,
    Mounted { label: Option<String>, cipher: String, created_at: u64, is_hidden: bool },
    Error(String),
    Gone,
}

pub struct MountedVault {
    pub vault_path: String,
    pub mountpoint: String,
    pub status:     Arc<Mutex<MountStatus>>,
}

/// State for the key manager screen.
#[derive(Default)]
pub struct KeyManagerView {
    // Generate panel
    pub new_label:            String,
    pub use_passphrase:       bool,
    pub new_passphrase:       String,
    pub new_passphrase_confirm: String,
    pub new_kdf_sensitive:    bool,

    // Passphrase-change panel (visible when a protected key is selected)
    pub selected_fp:          Option<[u8; 8]>,
    pub unlock_passphrase:    String,
    pub change_passphrase:    String,
    pub change_passphrase_confirm: String,
    pub change_kdf_sensitive: bool,
}

/// State for the recipient management screen.
#[derive(Default)]
pub struct RecipientView {
    pub mountpoint:       Option<String>,
    pub container_path:   String,
    pub recipients:       Vec<vnmcore::RecipientInfo>,
    pub pending_remove:   Option<[u8; 8]>,
    pub new_password:     String,
    pub new_pubkey_path:  String,
    pub keygen_path:      String,
}

pub struct VenomApp {
    pub screen:           Screen,
    pub mounted:          Vec<MountedVault>,
    pub status_msg:       Option<(String, bool)>,
    pub egui_ctx:         egui::Context,
    pub recent:           RecentList,
    pub recent_enriched:  HashSet<String>,
    pub keys:             KeyStore,
    pub create_view:      CreateView,
    pub mount_view:       MountView,
    pub recipient_view:   RecipientView,
    pub key_manager_view: KeyManagerView,
}

impl VenomApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            screen: Screen::VaultList,
            mounted: vec![],
            status_msg: None,
            egui_ctx: cc.egui_ctx.clone(),
            recent: RecentList::load(),
            recent_enriched: HashSet::new(),
            keys: KeyStore::load(),
            create_view: CreateView::default(),
            mount_view: MountView::default(),
            recipient_view: RecipientView::default(),
            key_manager_view: KeyManagerView::default(),
        }
    }

    pub fn set_status(&mut self, msg: impl Into<String>, is_error: bool) {
        self.status_msg = Some((msg.into(), is_error));
    }
    pub fn clear_status(&mut self) { self.status_msg = None; }
}

impl eframe::App for VenomApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.gc_gone_mounts();

        let updates: Vec<(String, Option<String>, String)> = self.mounted.iter()
            .filter_map(|mv| {
                if self.recent_enriched.contains(&mv.vault_path) { return None; }
                if let MountStatus::Mounted { label, cipher, .. } = &*mv.status.lock().unwrap() {
                    Some((mv.vault_path.clone(), label.clone(), cipher.clone()))
                } else { None }
            }).collect();

        for (path, label, cipher) in updates {
            self.recent.update_metadata(&path, label, Some(cipher));
            self.recent_enriched.insert(path);
        }

        if let Some(fp) = self.recipient_view.pending_remove.take() {
            self.action_remove_key_recipient(fp);
        }

        let any_mounting = self.mounted.iter()
            .any(|mv| matches!(*mv.status.lock().unwrap(), MountStatus::Mounting));
        if any_mounting { ctx.request_repaint(); }

        crate::ui::render(self, ctx);
    }
}
