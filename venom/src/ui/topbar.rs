use egui::{menu, RichText, TopBottomPanel};
use crate::app::state::{MountStatus, VenomApp, Screen};
use super::theme;

pub fn render(app: &mut VenomApp, ctx: &egui::Context) {
    TopBottomPanel::top("topbar")
        .frame(egui::Frame::none().fill(theme::PANEL).inner_margin(egui::Margin::symmetric(8.0, 4.0)))
        .show(ctx, |ui| {
            menu::bar(ui, |ui| {
                // Brand
                ui.label(
                    RichText::new("🔒 Venom")
                        .strong()
                        .size(15.0)
                        .color(theme::ACCENT),
                );

                ui.separator();

                ui.menu_button("Vault", |ui| {
                    if ui.button("✚  New vault…").clicked() {
                        app.screen = Screen::Create;
                        app.clear_status();
                        ui.close_menu();
                    }
                    if ui.button("⛰  Mount vault…").clicked() {
                        app.screen = Screen::Mount;
                        app.clear_status();
                        ui.close_menu();
                    }
                });

                if ui.button(
                    RichText::new("🗝 Keys")
                        .color(if app.screen == Screen::KeyManager {
                            egui::Color32::from_rgb(180, 140, 255)
                        } else {
                            egui::Color32::GRAY
                        })
                ).clicked() {
                    app.screen = Screen::KeyManager;
                    app.clear_status();
                }

                // Key count badge
                let n_keys = app.keys.entries.len();
                if n_keys > 0 {
                    ui.label(
                        RichText::new(format!("{n_keys}"))
                            .small()
                            .color(egui::Color32::from_rgb(160, 120, 220)),
                    );
                }

                // Right side: mounted vault count badge
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let mounted_count = app.mounted.iter().filter(|mv| {
                        matches!(*mv.status.lock().unwrap(), MountStatus::Mounted { .. })
                    }).count();

                    let mounting_count = app.mounted.iter().filter(|mv| {
                        matches!(*mv.status.lock().unwrap(), MountStatus::Mounting)
                    }).count();

                    if mounting_count > 0 {
                        ui.spinner();
                        ui.label(
                            RichText::new(format!("{mounting_count} connecting…"))
                                .small()
                                .color(theme::WARN),
                        );
                    }
                    if mounted_count > 0 {
                        ui.label(
                            RichText::new(format!("● {mounted_count} mounted"))
                                .small()
                                .color(theme::SUCCESS),
                        );
                    }
                });
            });
        });
}
