use std::sync::{Arc, Mutex};
use crate::ui::{CreateView, MountView};

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    VaultList,
    Create,
    Mount,
}

/// Live status of a mount — updated from the background thread.
#[derive(Debug, Clone)]
pub enum MountStatus {
    /// KDF + FUSE handshake in progress.
    Mounting,
    /// FUSE filesystem live and accepting writes.
    Mounted {
        label: Option<String>,
        cipher: String,
        created_at: u64,
    },
    /// Mount failed (wrong password, I/O error, FUSE error…).
    Error(String),
    /// The FUSE thread returned cleanly after unmounting — card can be removed.
    Gone,
}

pub struct MountedVault {
    pub vault_path: String,
    pub mountpoint: String,
    /// Shared with the background thread — updated atomically.
    pub status: Arc<Mutex<MountStatus>>,
}

pub struct VenomApp {
    pub screen: Screen,
    pub mounted: Vec<MountedVault>,
    pub status_msg: Option<(String, bool)>,
    /// Cloned into mount threads so they can trigger a repaint.
    pub egui_ctx: egui::Context,

    pub create_view: CreateView,
    pub mount_view: MountView,
}

impl VenomApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            screen: Screen::VaultList,
            mounted: vec![],
            status_msg: None,
            egui_ctx: cc.egui_ctx.clone(),
            create_view: CreateView::default(),
            mount_view: MountView::default(),
        }
    }

    pub fn set_status(&mut self, msg: impl Into<String>, is_error: bool) {
        self.status_msg = Some((msg.into(), is_error));
    }

    pub fn clear_status(&mut self) {
        self.status_msg = None;
    }
}

impl eframe::App for VenomApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Remove cards whose mount thread has exited cleanly.
        self.gc_gone_mounts();

        // Keep the UI animating while any vault is still connecting.
        let any_mounting = self.mounted.iter().any(|mv| {
            matches!(*mv.status.lock().unwrap(), MountStatus::Mounting)
        });
        if any_mounting {
            ctx.request_repaint();
        }

        crate::ui::render(self, ctx);
    }
}
