pub mod theme;
mod topbar;
mod vault_list;
mod create;
mod mount;
mod statusbar;
pub mod recipients;
pub mod key_manager;

pub use create::CreateView;
pub use mount::MountView;

use crate::app::state::{VenomApp, Screen};

pub fn render(app: &mut VenomApp, ctx: &egui::Context) {
    topbar::render(app, ctx);
    statusbar::render(app, ctx);

    egui::CentralPanel::default()
        .frame(egui::Frame::none().fill(theme::BG).inner_margin(egui::Margin::same(16.0)))
        .show(ctx, |ui| {
            match app.screen {
                Screen::VaultList  => vault_list::render(app, ui),
                Screen::Create     => create::render(app, ui),
                Screen::Mount      => mount::render(app, ui),
                Screen::Recipients => recipients::render(app, ui),
                Screen::KeyManager => key_manager::render(app, ui),
            }
        });
}
