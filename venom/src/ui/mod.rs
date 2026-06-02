mod topbar;
mod vault_list;
mod create;
mod mount;
mod statusbar;

pub use vault_list::VaultListView;
pub use create::CreateView;
pub use mount::MountView;

use crate::app::state::{VenomApp, Screen};

pub fn render(app: &mut VenomApp, ctx: &egui::Context) {
    topbar::render(app, ctx);
    statusbar::render(app, ctx);

    egui::CentralPanel::default().show(ctx, |ui| {
        match app.screen {
            Screen::VaultList => vault_list::render(app, ui),
            Screen::Create => create::render(app, ui),
            Screen::Mount => mount::render(app, ui),
        }
    });
}
