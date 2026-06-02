use egui::{Color32, Frame, Margin, RichText, Vec2};
use crate::app::state::{VenomApp, Screen};
use super::theme;

#[derive(Default)]
pub struct CreateView {
    pub container_path:       String,
    pub size_mb:              u64,
    pub size_input:           String,    // raw text field
    pub password:             String,
    pub password_confirm:     String,
    pub label:                String,
    pub cipher_index:         usize,     // 0=ChaCha20, 1=AES-256-GCM
    pub high_security:        bool,
    // Hidden volume
    pub hidden_enabled:       bool,
    pub hidden_size_mb:       u64,
    pub hidden_size_input:    String,
    pub hidden_password:      String,
    pub hidden_password_confirm: String,
    pub hidden_label:         String,
}

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("✚").size(22.0).color(theme::ACCENT));
        ui.add_space(4.0);
        ui.heading("New Container");
    });
    ui.add_space(12.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        let avail = ui.available_width();
        let col = (avail - 16.0) / 2.0;

        ui.horizontal_top(|ui| {
            // ── Left: identity + passphrase ───────────────────────────────────
            ui.vertical(|ui| {
                ui.set_width(col);

                section(ui, "Container");

                field(ui, "File path (.vnm)", |ui| {
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut app.create_view.container_path)
                            .hint_text("/home/user/secrets.vnm")
                            .desired_width(ui.available_width() - 90.0));
                        if ui.add(
                            egui::Button::new(
                                RichText::new("💾 Save as…").color(egui::Color32::WHITE)
                            ).fill(theme::BTN_PRIMARY)
                        ).clicked() {
                            if let Some(mut p) = rfd::FileDialog::new()
                                .set_title("Choose container file location")
                                .add_filter("Venom container (*.vnm)", &["vnm"])
                                .save_file()
                            {
                                // Ensure the .vnm extension is present
                                if p.extension().is_none() {
                                    p.set_extension("vnm");
                                }
                                app.create_view.container_path = p.display().to_string();
                            }
                        }
                    });
                });

                field(ui, "Label (optional)", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut app.create_view.label)
                        .hint_text("My secrets")
                        .desired_width(f32::INFINITY));
                });

                field(ui, "Total size (MB)", |ui| {
                    let resp = ui.add(egui::TextEdit::singleline(&mut app.create_view.size_input)
                        .hint_text("100")
                        .desired_width(120.0));
                    if resp.changed() {
                        app.create_view.size_mb = app.create_view.size_input.trim().parse().unwrap_or(0);
                    }
                    ui.label(RichText::new(format!(" = {} MB", app.create_view.size_mb)).color(theme::TEXT_MUTED).small());
                });

                ui.add_space(8.0);
                section(ui, "Outer volume passphrase");

                let pw  = app.create_view.password.clone();
                let pw2 = app.create_view.password_confirm.clone();
                let match_ok  = !pw.is_empty() && pw == pw2;
                let match_bad = !pw2.is_empty() && pw != pw2;

                field(ui, "Passphrase", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut app.create_view.password)
                        .password(true).desired_width(f32::INFINITY));
                });
                field(ui, "Confirm", |ui| {
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut app.create_view.password_confirm)
                            .password(true).desired_width(ui.available_width() - 28.0));
                        if match_ok  { ui.label(RichText::new("✓").color(theme::SUCCESS).strong()); }
                        if match_bad { ui.label(RichText::new("✗").color(theme::ERROR).strong()); }
                    });
                });
            });

            ui.add_space(16.0);

            // ── Right: cipher + KDF + hidden volume ───────────────────────────
            ui.vertical(|ui| {
                ui.set_width(col);

                section(ui, "Encryption");

                field(ui, "Cipher", |ui| {
                    egui::ComboBox::from_id_source("cipher_select")
                        .selected_text(cipher_label(app.create_view.cipher_index))
                        .width(ui.available_width())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut app.create_view.cipher_index, 0, "ChaCha20-Poly1305  (recommended)");
                            ui.selectable_value(&mut app.create_view.cipher_index, 1, "AES-256-GCM");
                        });
                });

                ui.add_space(6.0);
                section(ui, "KDF profile");

                profile_card(ui, !app.create_view.high_security, "Interactive",
                    "64 MiB · 3 passes", "< 1 s on modern hardware.",
                    || app.create_view.high_security = false);
                ui.add_space(4.0);
                profile_card(ui, app.create_view.high_security, "Sensitive",
                    "256 MiB · 4 passes", "2–5 s. Best for sensitive data.",
                    || app.create_view.high_security = true);

                ui.add_space(10.0);

                // ── Hidden volume ─────────────────────────────────────────────
                Frame::none()
                    .fill(if app.create_view.hidden_enabled {
                        Color32::from_rgb(30, 22, 42)
                    } else {
                        theme::CARD
                    })
                    .stroke(egui::Stroke::new(1.5, if app.create_view.hidden_enabled {
                        Color32::from_rgb(150, 80, 240)
                    } else {
                        theme::BORDER
                    }))
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.set_min_width(col - 2.0);
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut app.create_view.hidden_enabled, "");
                            ui.label(RichText::new("Hidden volume  (plausible deniability)").strong());
                        });

                        if app.create_view.hidden_enabled {
                            ui.add_space(8.0);
                            ui.label(
                                RichText::new(
                                    "A second encrypted volume stored in the same file. \
                                     Mounting with the hidden password reveals only the hidden content."
                                ).small().color(theme::TEXT_MUTED),
                            );
                            ui.add_space(8.0);

                            ui.label(RichText::new("Hidden size (MB)").color(theme::TEXT_MUTED).small());
                            let resp = ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_size_input)
                                .hint_text("50").desired_width(120.0));
                            if resp.changed() {
                                app.create_view.hidden_size_mb =
                                    app.create_view.hidden_size_input.trim().parse().unwrap_or(0);
                            }

                            let h_max = app.create_view.size_mb.saturating_sub(2);
                            if app.create_view.hidden_size_mb >= app.create_view.size_mb {
                                ui.label(RichText::new(format!("Must be < {} MB (outer size).", app.create_view.size_mb)).small().color(theme::ERROR));
                            } else if app.create_view.hidden_size_mb > 0 {
                                let outer_usable = app.create_view.size_mb - app.create_view.hidden_size_mb;
                                ui.label(RichText::new(format!("Outer: ~{outer_usable} MB  |  Hidden: ~{} MB", app.create_view.hidden_size_mb)).small().color(theme::TEXT_MUTED));
                            }

                            ui.add_space(6.0);
                            ui.label(RichText::new("Hidden label (optional)").color(theme::TEXT_MUTED).small());
                            ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_label)
                                .hint_text("Hidden vault").desired_width(f32::INFINITY));

                            ui.add_space(4.0);
                            ui.label(RichText::new("Hidden passphrase").color(theme::TEXT_MUTED).small());
                            ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_password)
                                .password(true).desired_width(f32::INFINITY));

                            let h_pw  = app.create_view.hidden_password.clone();
                            let h_pw2 = app.create_view.hidden_password_confirm.clone();
                            let h_ok  = !h_pw.is_empty() && h_pw == h_pw2;
                            let h_bad = !h_pw2.is_empty() && h_pw != h_pw2;

                            ui.label(RichText::new("Confirm hidden passphrase").color(theme::TEXT_MUTED).small());
                            ui.horizontal(|ui| {
                                ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_password_confirm)
                                    .password(true).desired_width(ui.available_width() - 28.0));
                                if h_ok  { ui.label(RichText::new("✓").color(theme::SUCCESS).strong()); }
                                if h_bad { ui.label(RichText::new("✗").color(theme::ERROR).strong()); }
                            });
                        }
                    });
            });
        });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let v = &app.create_view;
            let pw_ok = !v.password.is_empty() && v.password == v.password_confirm;
            let hid_ok = !v.hidden_enabled || (
                !v.hidden_password.is_empty()
                    && v.hidden_password == v.hidden_password_confirm
                    && v.hidden_size_mb > 0
                    && v.hidden_size_mb < v.size_mb
            );
            let can_create = !v.container_path.is_empty() && v.size_mb > 0 && pw_ok && hid_ok;

            if ui.add_enabled(can_create,
                egui::Button::new(RichText::new("Create container").color(Color32::WHITE).strong())
                    .fill(if can_create { theme::BTN_PRIMARY } else { theme::CARD })
                    .min_size(Vec2::new(160.0, 32.0)),
            ).clicked() {
                app.action_create_vault();
            }

            if ui.button("Cancel").clicked() {
                app.screen = Screen::VaultList;
                app.clear_status();
            }

            if app.create_view.size_mb > 0 {
                ui.label(
                    RichText::new(
                        "⚠  Creating fills the container with random bytes — may take a moment for large sizes."
                    ).small().color(theme::WARN),
                );
            }
        });
    });
}

fn section(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::TEXT_MUTED).small().strong());
    ui.add(egui::Separator::default().spacing(4.0));
    ui.add_space(2.0);
}

fn field(ui: &mut egui::Ui, label: &str, content: impl FnOnce(&mut egui::Ui)) {
    ui.label(RichText::new(label).color(theme::TEXT_MUTED).small());
    content(ui);
    ui.add_space(4.0);
}

fn profile_card(ui: &mut egui::Ui, selected: bool, title: &str, subtitle: &str, hint: &str, on_select: impl FnOnce()) {
    let border = if selected { theme::ACCENT } else { theme::BORDER };
    let bg     = if selected { Color32::from_rgb(25, 40, 65) } else { theme::CARD };
    let resp = Frame::none()
        .fill(bg).stroke(egui::Stroke::new(1.5, border))
        .rounding(egui::Rounding::same(8.0)).inner_margin(Margin::same(10.0))
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
    if resp.response.interact(egui::Sense::click()).clicked() { on_select(); }
}

fn cipher_label(index: usize) -> &'static str {
    match index { 0 => "ChaCha20-Poly1305", _ => "AES-256-GCM" }
}
