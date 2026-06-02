use egui::{Color32, Frame, Margin, RichText, Vec2};
use crate::app::state::{VenomApp, Screen};
use super::theme;

#[derive(Default)]
pub struct CreateView {
    pub vault_path: String,
    pub password: String,
    pub password_confirm: String,
    pub label: String,
    pub cipher_index: usize,  // 0 = ChaCha20, 1 = AES-256-GCM
    pub high_security: bool,
}

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.add_space(8.0);

    // ── Page header ───────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.label(RichText::new("✚").size(22.0).color(theme::ACCENT));
        ui.add_space(4.0);
        ui.heading("New Vault");
    });
    ui.add_space(12.0);

    // Split into two columns
    let avail = ui.available_width();
    let col_w  = (avail - 16.0) / 2.0;

    ui.horizontal_top(|ui| {
        // ── Left column: location & identity ─────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(col_w);

            section_header(ui, "Identity");

            labeled_row(ui, "Label (optional)", |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut app.create_view.label)
                        .hint_text("My Documents")
                        .desired_width(f32::INFINITY),
                );
            });

            labeled_row(ui, "Vault directory", |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut app.create_view.vault_path)
                            .hint_text("/home/user/my-vault")
                            .desired_width(ui.available_width() - 64.0),
                    );
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            app.create_view.vault_path = p.display().to_string();
                        }
                    }
                });
            });

            ui.add_space(10.0);
            section_header(ui, "Passphrase");

            let pw  = &app.create_view.password;
            let pw2 = &app.create_view.password_confirm;
            let match_ok = !pw.is_empty() && pw == pw2;
            let match_bad = !pw2.is_empty() && pw != pw2;

            labeled_row(ui, "Passphrase", |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut app.create_view.password)
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
            });

            labeled_row(ui, "Confirm", |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut app.create_view.password_confirm)
                            .password(true)
                            .desired_width(ui.available_width() - 28.0),
                    );
                    if match_ok {
                        ui.label(RichText::new("✓").color(theme::SUCCESS).strong());
                    } else if match_bad {
                        ui.label(RichText::new("✗").color(theme::ERROR).strong());
                    }
                });
            });
        });

        ui.add_space(16.0);

        // ── Right column: cipher & security profile ───────────────────────────
        ui.vertical(|ui| {
            ui.set_width(col_w);

            section_header(ui, "Encryption");

            labeled_row(ui, "Cipher", |ui| {
                egui::ComboBox::from_id_source("cipher_select")
                    .selected_text(cipher_label(app.create_view.cipher_index))
                    .width(ui.available_width())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut app.create_view.cipher_index,
                            0,
                            "ChaCha20-Poly1305  (recommended)",
                        );
                        ui.selectable_value(
                            &mut app.create_view.cipher_index,
                            1,
                            "AES-256-GCM",
                        );
                    });
            });

            ui.add_space(10.0);
            section_header(ui, "KDF profile");

            profile_card(
                ui,
                !app.create_view.high_security,
                "Interactive",
                "64 MiB · 3 passes",
                "Unlocks in < 1 s. Good for personal use.",
                || app.create_view.high_security = false,
            );
            ui.add_space(6.0);
            profile_card(
                ui,
                app.create_view.high_security,
                "Sensitive",
                "256 MiB · 4 passes",
                "Unlocks in 2–5 s. Best for sensitive data.",
                || app.create_view.high_security = true,
            );
        });
    });

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(8.0);

    // ── Action buttons ────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        let can_create = !app.create_view.vault_path.is_empty()
            && !app.create_view.password.is_empty()
            && app.create_view.password == app.create_view.password_confirm;

        let btn = egui::Button::new(RichText::new("Create vault").color(Color32::WHITE).strong())
            .fill(if can_create { theme::BTN_PRIMARY } else { theme::CARD })
            .min_size(Vec2::new(130.0, 32.0));

        if ui.add_enabled(can_create, btn).clicked() {
            app.action_create_vault();
        }

        if ui.button("Cancel").clicked() {
            app.screen = Screen::VaultList;
            app.clear_status();
        }
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn section_header(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::TEXT_MUTED).small().strong());
    ui.add(egui::Separator::default().spacing(4.0));
    ui.add_space(2.0);
}

fn labeled_row(ui: &mut egui::Ui, label: &str, content: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.set_min_height(26.0);
        ui.label(RichText::new(label).color(theme::TEXT_MUTED));
    });
    content(ui);
    ui.add_space(4.0);
}

fn profile_card(
    ui: &mut egui::Ui,
    selected: bool,
    title: &str,
    subtitle: &str,
    hint: &str,
    on_select: impl FnOnce(),
) {
    let border_color = if selected { theme::ACCENT } else { theme::BORDER };
    let bg = if selected { Color32::from_rgb(25, 40, 65) } else { theme::CARD };

    let resp = Frame::none()
        .fill(bg)
        .stroke(egui::Stroke::new(1.5, border_color))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let dot = if selected { "◉" } else { "○" };
                ui.label(RichText::new(dot).color(if selected { theme::ACCENT } else { theme::TEXT_MUTED }));
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).strong());
                    ui.label(RichText::new(subtitle).color(theme::ACCENT).small().monospace());
                    ui.label(RichText::new(hint).color(theme::TEXT_MUTED).small());
                });
            });
        });

    if resp.response.interact(egui::Sense::click()).clicked() {
        on_select();
    }
}

fn cipher_label(index: usize) -> &'static str {
    match index {
        0 => "ChaCha20-Poly1305",
        _ => "AES-256-GCM",
    }
}
