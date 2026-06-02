use crate::ui::{CreateView, MountView, VaultListView};

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    VaultList,
    Create,
    Mount,
}

/// A vault that has been opened and is currently mounted.
#[derive(Debug, Clone)]
pub struct MountedVault {
    pub vault_path: String,
    pub mountpoint: String,
    pub label: Option<String>,
    pub cipher: String,
}

pub struct VenomApp {
    pub screen: Screen,
    pub mounted: Vec<MountedVault>,
    pub status_msg: Option<(String, bool)>, // (message, is_error)

    pub create_view: CreateView,
    pub mount_view: MountView,
    pub list_view: VaultListView,
}

impl VenomApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            screen: Screen::VaultList,
            mounted: vec![],
            status_msg: None,
            create_view: CreateView::default(),
            mount_view: MountView::default(),
            list_view: VaultListView::default(),
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
        crate::ui::render(self, ctx);
    }
}
