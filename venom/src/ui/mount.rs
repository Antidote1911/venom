use egui::{Color32, Frame, Margin, RichText, Rounding, Vec2};
use crate::app::state::{VenomApp, Screen};
use super::theme;

#[derive(Default)]
pub struct MountView {
    pub vault_path:      String,
    pub mountpoint:      String,
    // ── Password credential
    pub password:        String,
    // ── Key credential
    pub use_key:         bool,
    pub selected_key_fp: Option<[u8; 8]>,  // key chosen from local store
    pub key_passphrase:  String,            // passphrase if selected key is protected
}

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("⛰").size(22.0).color(theme::ACCENT));
        ui.add_space(4.0);
        ui.heading("Mount Container");
    });
    ui.add_space(12.0);

    let avail = ui.available_width();
    let col   = (avail - 16.0) / 2.0;

    ui.horizontal_top(|ui| {
        // ── Left: form ────────────────────────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_max_width(col);

            // Container file
            ui.label(RichText::new("Container file (.vnm)").color(theme::TEXT_MUTED));
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut app.mount_view.vault_path)
                    .hint_text("/home/user/secrets.vnm")
                    .desired_width(ui.available_width() - 90.0));
                if ui.add(
                    egui::Button::new(RichText::new("📄 Open file").color(Color32::WHITE))
                        .fill(theme::BTN_PRIMARY)
                ).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_title("Select Venom container")
                        .add_filter("Venom container (*.vnm)", &["vnm"])
                        .add_filter("All files", &["*"])
                        .pick_file()
                    {
                        app.mount_view.vault_path = p.display().to_string();
                    }
                }
            });
            ui.add_space(8.0);

            // Mountpoint
            ui.label(RichText::new("Mountpoint (empty directory)").color(theme::TEXT_MUTED));
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut app.mount_view.mountpoint)
                    .hint_text("/mnt/vault")
                    .desired_width(ui.available_width() - 90.0));
                if ui.button("📁 Folder…").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_title("Select empty mountpoint directory")
                        .pick_folder()
                    {
                        app.mount_view.mountpoint = p.display().to_string();
                    }
                }
            });
            ui.add_space(10.0);

            // ── Credential toggle ─────────────────────────────────────────────
            ui.label(RichText::new("Credential").color(theme::TEXT_MUTED).strong());
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                if ui.selectable_label(!app.mount_view.use_key, "🔒  Password").clicked() {
                    app.mount_view.use_key = false;
                }
                ui.add_space(8.0);
                if ui.selectable_label(app.mount_view.use_key, "🔑  Private key").clicked() {
                    app.mount_view.use_key = true;
                }
            });
            ui.add_space(6.0);

            if !app.mount_view.use_key {
                // ── Password mode ─────────────────────────────────────────────
                ui.add(egui::TextEdit::singleline(&mut app.mount_view.password)
                    .password(true)
                    .hint_text("Passphrase (outer or hidden volume)")
                    .desired_width(f32::INFINITY));
            } else {
                // ── Key mode ──────────────────────────────────────────────────
                let no_keys = app.keys.entries.is_empty();

                if no_keys {
                    ui.label(
                        RichText::new("No keypairs in store. Generate one in the Key Manager (🗝 Keys).")
                            .small().color(theme::WARN),
                    );
                } else {
                    ui.label(RichText::new("Select a keypair from your store:").color(theme::TEXT_MUTED).small());
                    ui.add_space(4.0);

                    let entries = app.keys.entries.clone();
                    for entry in &entries {
                        let selected = app.mount_view.selected_key_fp == Some(entry.fingerprint);
                        let border = if selected { theme::ACCENT } else { theme::BORDER };
                        let bg     = if selected { Color32::from_rgb(25, 40, 65) } else { theme::CARD };

                        let resp = Frame::none()
                            .fill(bg).stroke(egui::Stroke::new(1.5, border))
                            .rounding(Rounding::same(6.0))
                            .inner_margin(Margin::symmetric(10.0, 6.0))
                            .show(ui, |ui| {
                                ui.set_max_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    let icon = if entry.is_protected { "🔒🔑" } else { "🔑" };
                                    ui.label(RichText::new(icon).color(theme::ACCENT));
                                    ui.label(RichText::new(&entry.label).strong().small());
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.label(
                                            RichText::new(vnmcore::fp_display(&entry.fingerprint))
                                                .monospace().small()
                                                .color(Color32::from_rgb(160, 120, 220)),
                                        );
                                    });
                                });
                            });

                        if resp.response.interact(egui::Sense::click()).clicked() {
                            if selected {
                                app.mount_view.selected_key_fp = None;
                                app.mount_view.key_passphrase.clear();
                            } else {
                                app.mount_view.selected_key_fp = Some(entry.fingerprint);
                                app.mount_view.key_passphrase.clear();
                            }
                        }
                        ui.add_space(3.0);
                    }

                    // Show passphrase field if selected key is protected
                    if let Some(fp) = app.mount_view.selected_key_fp {
                        let is_protected = app.keys.entries.iter()
                            .find(|e| e.fingerprint == fp)
                            .map(|e| e.is_protected)
                            .unwrap_or(false);
                        if is_protected {
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new("Key passphrase (required to unlock this keypair):")
                                    .color(theme::TEXT_MUTED).small(),
                            );
                            ui.add(egui::TextEdit::singleline(&mut app.mount_view.key_passphrase)
                                .password(true)
                                .hint_text("Keypair passphrase")
                                .desired_width(f32::INFINITY));
                        }
                    }
                }
            }
        });

        ui.add_space(16.0);

        // ── Right: info ───────────────────────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(col);

            Frame::none()
                .fill(Color32::from_rgb(22, 32, 22))
                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(40, 70, 40)))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(Margin::same(12.0))
                .show(ui, |ui| {
                    ui.set_max_width(col - 4.0);
                    ui.label(RichText::new("ℹ  How it works").color(theme::SUCCESS).strong());
                    ui.add_space(6.0);
                    tip(ui, "1.", "Argon2id derives the decryption key from your passphrase.");
                    tip(ui, "2.", "The container is mounted read-write via FUSE.");
                    tip(ui, "3.", "Unmounting flushes all cached data before closing.");
                });

            ui.add_space(10.0);

            Frame::none()
                .fill(Color32::from_rgb(30, 22, 40))
                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(90, 40, 120)))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(Margin::same(12.0))
                .show(ui, |ui| {
                    ui.set_max_width(col - 4.0);
                    ui.label(RichText::new("🔐  Hidden volume").color(Color32::from_rgb(180, 120, 255)).strong());
                    ui.add_space(6.0);
                    tip(ui, "•", "Use the hidden passphrase to access the hidden volume.");
                    tip(ui, "•", "Both volumes are indistinguishable — plausible deniability.");
                });

            ui.add_space(10.0);

            Frame::none()
                .fill(Color32::from_rgb(30, 26, 18))
                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(70, 55, 30)))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(Margin::same(12.0))
                .show(ui, |ui| {
                    ui.set_max_width(col - 4.0);
                    ui.label(RichText::new("⚠  Prerequisites").color(theme::WARN).strong());
                    ui.add_space(6.0);
                    tip(ui, "•", "Linux: fuse3 module loaded, fusermount3 in PATH.");
                    tip(ui, "•", "macOS: macFUSE installed.");
                    tip(ui, "•", "Mountpoint must exist and be empty.");
                });
        });
    });

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(8.0);

    // ── Mount button ──────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        let v = &app.mount_view;
        let path_ok = !v.vault_path.is_empty() && !v.mountpoint.is_empty();

        let cred_ok = if v.use_key {
            if let Some(fp) = v.selected_key_fp {
                let is_protected = app.keys.entries.iter()
                    .find(|e| e.fingerprint == fp)
                    .map(|e| e.is_protected)
                    .unwrap_or(false);
                !is_protected || !v.key_passphrase.is_empty()
            } else { false }
        } else {
            !v.password.is_empty()
        };

        let can_mount = path_ok && cred_ok;

        if ui.add_enabled(can_mount,
            egui::Button::new(RichText::new("Mount").color(Color32::WHITE).strong())
                .fill(if can_mount { theme::BTN_PRIMARY } else { theme::CARD })
                .min_size(Vec2::new(100.0, 32.0)),
        ).clicked() {
            app.action_mount_vault();
        }

        if ui.button("Cancel").clicked() {
            app.screen = Screen::VaultList;
            app.clear_status();
        }
    });

    // ── Recent quick-fill ─────────────────────────────────────────────────────
    if !app.recent.is_empty() {
        ui.add_space(16.0);
        ui.separator();
        ui.add_space(6.0);
        ui.label(RichText::new("Recent containers  —  click to fill").small().color(theme::TEXT_MUTED));
        ui.add_space(6.0);

        let entries = app.recent.entries.clone();
        let mut fill: Option<String> = None;

        egui::ScrollArea::vertical()
            .max_height(160.0)
            .id_source("recent_mount")
            .show(ui, |ui| {
                for entry in &entries {
                    let selected = app.mount_view.vault_path == entry.path;
                    let exists   = std::path::Path::new(&entry.path).exists();
                    let bg     = if selected { Color32::from_rgb(25, 40, 65) } else { theme::CARD };
                    let border = if selected { theme::ACCENT } else { theme::BORDER };
                    let resp = Frame::none()
                        .fill(bg).stroke(egui::Stroke::new(1.0, border))
                        .rounding(Rounding::same(6.0)).inner_margin(Margin::symmetric(10.0, 6.0))
                        .show(ui, |ui| {
                            ui.set_max_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(entry.display_name()).strong().small()
                                        .color(if exists { theme::TEXT } else { theme::TEXT_MUTED }));
                                    ui.label(RichText::new(&entry.path).small().monospace().color(theme::TEXT_MUTED));
                                });
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if let Some(c) = &entry.cipher {
                                        ui.label(RichText::new(c).small().color(theme::ACCENT));
                                    }
                                    if !exists {
                                        ui.label(RichText::new("not found").small().color(theme::ERROR));
                                    }
                                });
                            });
                        });
                    if resp.response.interact(egui::Sense::click()).clicked() && exists {
                        fill = Some(entry.path.clone());
                    }
                    ui.add_space(3.0);
                }
            });

        if let Some(p) = fill { app.mount_view.vault_path = p; }
    }
}

fn tip(ui: &mut egui::Ui, bullet: &str, text: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(bullet).color(theme::TEXT_MUTED).small().strong());
        ui.label(RichText::new(text).color(theme::TEXT_MUTED).small());
    });
    ui.add_space(2.0);
}
