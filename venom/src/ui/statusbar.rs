use egui::{TopBottomPanel, Color32, RichText};
use crate::app::state::VenomApp;

pub fn render(app: &mut VenomApp, ctx: &egui::Context) {
    if let Some((msg, is_error)) = &app.status_msg.clone() {
        TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let color = if *is_error {
                    Color32::from_rgb(220, 80, 80)
                } else {
                    Color32::from_rgb(80, 200, 120)
                };
                ui.label(RichText::new(msg).color(color));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("✕").clicked() {
                        app.clear_status();
                    }
                });
            });
        });
    }
}
