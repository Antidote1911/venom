use egui::{Color32, Frame, Margin, RichText, TopBottomPanel};
use crate::app::state::VenomApp;
use super::theme;

pub fn render(app: &mut VenomApp, ctx: &egui::Context) {
    if let Some((msg, is_error)) = &app.status_msg.clone() {
        let (bg, fg) = if *is_error {
            (Color32::from_rgb(60, 20, 20), theme::ERROR)
        } else {
            (Color32::from_rgb(15, 45, 25), theme::SUCCESS)
        };

        TopBottomPanel::bottom("statusbar")
            .frame(Frame::none().fill(bg).inner_margin(Margin::symmetric(12.0, 6.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let icon = if *is_error { "✗" } else { "✓" };
                    ui.label(RichText::new(icon).color(fg).strong());
                    ui.label(RichText::new(msg.as_str()).color(fg));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button(RichText::new("✕").color(fg)).clicked() {
                            app.clear_status();
                        }
                    });
                });
            });
    }
}
