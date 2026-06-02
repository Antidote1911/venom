use egui::{RichText, Color32};
use crate::app::state::{VenomApp, Screen};

#[derive(Default)]
pub struct VaultListView;

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.add_space(12.0);
    ui.heading("Mounted Vaults");
    ui.add_space(8.0);

    if app.mounted.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(
                RichText::new("No vaults mounted.\nUse Vault → Mount vault… to get started.")
                    .color(Color32::GRAY)
                    .italics(),
            );
        });
        return;
    }

    let mut to_unmount: Option<usize> = None;

    egui::ScrollArea::vertical().show(ui, |ui| {
        for (i, mv) in app.mounted.iter().enumerate() {
            let label = mv.label.as_deref().unwrap_or("(unlabelled)");

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(label).strong().size(15.0));
                        ui.label(
                            RichText::new(format!("📁 {}", mv.vault_path))
                                .color(Color32::GRAY)
                                .small(),
                        );
                        ui.label(
                            RichText::new(format!("⛰ {}  •  🔑 {}", mv.mountpoint, mv.cipher))
                                .color(Color32::GRAY)
                                .small(),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button(RichText::new("Unmount").color(Color32::from_rgb(220, 80, 80)))
                            .clicked()
                        {
                            to_unmount = Some(i);
                        }
                    });
                });
            });

            ui.add_space(4.0);
        }
    });

    if let Some(i) = to_unmount {
        app.action_unmount(i);
    }

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        if ui.button("+ New vault").clicked() {
            app.screen = Screen::Create;
            app.clear_status();
        }
        if ui.button("⛰ Mount vault").clicked() {
            app.screen = Screen::Mount;
            app.clear_status();
        }
    });
}
