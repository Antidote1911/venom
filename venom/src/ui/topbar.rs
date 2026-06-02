use egui::{TopBottomPanel, menu};
use crate::app::state::{VenomApp, Screen};

pub fn render(app: &mut VenomApp, ctx: &egui::Context) {
    TopBottomPanel::top("topbar").show(ctx, |ui| {
        menu::bar(ui, |ui| {
            ui.menu_button("Vault", |ui| {
                if ui.button("New vault…").clicked() {
                    app.screen = Screen::Create;
                    app.clear_status();
                    ui.close_menu();
                }
                if ui.button("Mount vault…").clicked() {
                    app.screen = Screen::Mount;
                    app.clear_status();
                    ui.close_menu();
                }
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new("🔒 Venom")
                        .strong()
                        .color(egui::Color32::from_rgb(100, 180, 255)),
                );
            });
        });
    });
}
