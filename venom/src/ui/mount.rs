use egui::{Color32, Frame, Margin, RichText, Vec2};
use crate::app::state::{VenomApp, Screen};
use super::theme;

#[derive(Default)]
pub struct MountView {
    pub vault_path: String,
    pub mountpoint: String,
    pub password: String,
}

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.add_space(8.0);

    // ── Page header ───────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.label(RichText::new("⛰").size(22.0).color(theme::ACCENT));
        ui.add_space(4.0);
        ui.heading("Mount Vault");
    });
    ui.add_space(12.0);

    let avail = ui.available_width();
    let col_w = (avail - 16.0) / 2.0;

    ui.horizontal_top(|ui| {
        // ── Left: form fields ─────────────────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(col_w);

            labeled_field(ui, "Vault directory", |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut app.mount_view.vault_path)
                            .hint_text("/path/to/my-vault")
                            .desired_width(ui.available_width() - 64.0),
                    );
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            app.mount_view.vault_path = p.display().to_string();
                        }
                    }
                });
            });

            labeled_field(ui, "Mountpoint", |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut app.mount_view.mountpoint)
                            .hint_text("/mnt/vault  or  ~/Documents/vault-open")
                            .desired_width(ui.available_width() - 64.0),
                    );
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            app.mount_view.mountpoint = p.display().to_string();
                        }
                    }
                });
            });

            labeled_field(ui, "Passphrase", |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut app.mount_view.password)
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
            });
        });

        ui.add_space(16.0);

        // ── Right: info panel ─────────────────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(col_w);

            Frame::none()
                .fill(Color32::from_rgb(22, 32, 22))
                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(40, 70, 40)))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(Margin::same(12.0))
                .show(ui, |ui| {
                    ui.set_min_width(col_w - 2.0);
                    ui.label(RichText::new("ℹ  How mounting works").color(theme::SUCCESS).strong());
                    ui.add_space(6.0);
                    tip(ui, "1.", "The passphrase derives the encryption key via Argon2id (may take a few seconds).");
                    tip(ui, "2.", "A FUSE filesystem is mounted at the mountpoint. All read/writes are transparently encrypted.");
                    tip(ui, "3.", "Unmounting flushes all cached blocks to disk before removing the mount.");
                });

            ui.add_space(10.0);

            Frame::none()
                .fill(Color32::from_rgb(30, 26, 18))
                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(70, 55, 30)))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(Margin::same(12.0))
                .show(ui, |ui| {
                    ui.set_min_width(col_w - 2.0);
                    ui.label(RichText::new("⚠  Prerequisites").color(theme::WARN).strong());
                    ui.add_space(6.0);
                    tip(ui, "•", "Linux: fuse3 kernel module loaded, fusermount3 in PATH.");
                    tip(ui, "•", "macOS: macFUSE installed.");
                    tip(ui, "•", "The mountpoint directory must exist and be empty.");
                });
        });
    });

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(8.0);

    // ── Action buttons ────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        let can_mount = !app.mount_view.vault_path.is_empty()
            && !app.mount_view.mountpoint.is_empty()
            && !app.mount_view.password.is_empty();

        let btn = egui::Button::new(RichText::new("Mount").color(Color32::WHITE).strong())
            .fill(if can_mount { theme::BTN_PRIMARY } else { theme::CARD })
            .min_size(Vec2::new(100.0, 32.0));

        if ui.add_enabled(can_mount, btn).clicked() {
            app.action_mount_vault();
        }

        if ui.button("Cancel").clicked() {
            app.screen = Screen::VaultList;
            app.clear_status();
        }
    });
}

fn labeled_field(ui: &mut egui::Ui, label: &str, content: impl FnOnce(&mut egui::Ui)) {
    ui.label(RichText::new(label).color(theme::TEXT_MUTED));
    content(ui);
    ui.add_space(8.0);
}

fn tip(ui: &mut egui::Ui, bullet: &str, text: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(bullet).color(theme::TEXT_MUTED).small().strong());
        ui.label(RichText::new(text).color(theme::TEXT_MUTED).small());
    });
    ui.add_space(2.0);
}
