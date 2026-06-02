use egui::{Color32, Frame, Margin, RichText, Vec2};
use crate::app::state::{VenomApp, Screen};
use super::theme;

#[derive(Default)]
pub struct CreateView {
    pub container_path:          String,
    pub size_mb:                 u64,
    pub size_input:              String,
    pub password:                String,
    pub password_confirm:        String,
    pub label:                   String,
    pub cipher_index:            usize,
    pub high_security:           bool,
    pub hidden_enabled:          bool,
    pub hidden_size_mb:          u64,
    pub hidden_size_input:       String,
    pub hidden_password:         String,
    pub hidden_password_confirm: String,
    pub hidden_label:            String,
    pub selected_recipients:     Vec<[u8; 8]>,
}

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    // ── Title row ─────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.label(RichText::new("✚").size(20.0).color(theme::ACCENT));
        ui.heading("New Container");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Cancel").clicked() {
                app.screen = Screen::VaultList;
                app.clear_status();
            }
        });
    });
    ui.add_space(6.0);
    ui.separator();
    ui.add_space(6.0);

    // ── Compute column width once, before any layout ──────────────────────────
    let total_w = ui.available_width();
    let col     = ((total_w - 20.0) / 2.0).max(200.0);

    // ── Main two-column layout (NO ScrollArea) ────────────────────────────────
    ui.horizontal_top(|ui| {

        // ═══ LEFT COLUMN ════════════════════════════════════════════════════
        ui.allocate_ui_with_layout(
            Vec2::new(col, ui.available_height()),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                // Container file
                compact_label(ui, "Container file (.vnm)");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut app.create_view.container_path)
                        .hint_text("/home/user/secrets.vnm")
                        .desired_width(ui.available_width() - 72.0));
                    if ui.add(
                        egui::Button::new(RichText::new("💾 Save…").color(Color32::WHITE))
                            .fill(theme::BTN_PRIMARY)
                    ).clicked() {
                        if let Some(mut p) = rfd::FileDialog::new()
                            .add_filter("Venom container", &["vnm"]).save_file()
                        {
                            if p.extension().is_none() { p.set_extension("vnm"); }
                            app.create_view.container_path = p.display().to_string();
                        }
                    }
                });
                ui.add_space(4.0);

                // Label + Size on same row
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        compact_label(ui, "Label (optional)");
                        ui.add(egui::TextEdit::singleline(&mut app.create_view.label)
                            .hint_text("My secrets").desired_width(col * 0.55));
                    });
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        compact_label(ui, "Size (MB)");
                        let r = ui.add(egui::TextEdit::singleline(&mut app.create_view.size_input)
                            .hint_text("100").desired_width(col * 0.30));
                        if r.changed() {
                            app.create_view.size_mb = app.create_view.size_input.trim().parse().unwrap_or(0);
                        }
                    });
                });
                ui.add_space(6.0);

                // Passphrase
                let has_recipients = !app.create_view.selected_recipients.is_empty();
                let pw_lbl = if has_recipients { "Passphrase (optional)" } else { "Passphrase" };
                compact_label(ui, pw_lbl);
                ui.add(egui::TextEdit::singleline(&mut app.create_view.password)
                    .password(true).desired_width(col - 8.0));
                ui.add_space(2.0);

                let pw  = &app.create_view.password;
                let pw2 = &app.create_view.password_confirm;
                let match_bad = !pw2.is_empty() && pw != pw2;
                let match_ok  = !pw.is_empty() && pw == pw2;

                compact_label(ui, "Confirm passphrase");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut app.create_view.password_confirm)
                        .password(true).desired_width(col - 36.0));
                    if match_ok  { ui.label(RichText::new("✓").color(theme::SUCCESS).strong()); }
                    if match_bad { ui.label(RichText::new("✗").color(theme::ERROR).strong()); }
                });
                if has_recipients && app.create_view.password.is_empty() {
                    ui.label(RichText::new("No password — key access only.").small().color(theme::WARN));
                }
                ui.add_space(6.0);

                // ── Hidden volume (compact collapsible) ───────────────────────
                ui.horizontal(|ui| {
                    ui.checkbox(&mut app.create_view.hidden_enabled, "");
                    ui.label(RichText::new("Hidden volume (plausible deniability)").strong().small());
                });
                if app.create_view.hidden_enabled {
                    Frame::none()
                        .fill(Color32::from_rgb(28, 20, 40))
                        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(100, 60, 160)))
                        .rounding(egui::Rounding::same(6.0))
                        .inner_margin(Margin::same(8.0))
                        .show(ui, |ui| {
                            ui.set_max_width(col - 16.0);

                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    compact_label(ui, "Hidden size (MB)");
                                    let r = ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_size_input)
                                        .hint_text("50").desired_width(70.0));
                                    if r.changed() {
                                        app.create_view.hidden_size_mb =
                                            app.create_view.hidden_size_input.trim().parse().unwrap_or(0);
                                    }
                                });
                                ui.add_space(8.0);
                                ui.vertical(|ui| {
                                    compact_label(ui, "Hidden label");
                                    ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_label)
                                        .hint_text("(optional)").desired_width(col - 120.0));
                                });
                            });

                            if app.create_view.hidden_size_mb > 0
                                && app.create_view.hidden_size_mb < app.create_view.size_mb
                            {
                                let o = app.create_view.size_mb - app.create_view.hidden_size_mb;
                                ui.label(RichText::new(format!(
                                    "Outer ~{o} MB  |  Hidden ~{} MB", app.create_view.hidden_size_mb
                                )).small().color(theme::TEXT_MUTED));
                            } else if app.create_view.size_mb > 0
                                && app.create_view.hidden_size_mb >= app.create_view.size_mb
                            {
                                ui.label(RichText::new("Must be < total size.").small().color(theme::ERROR));
                            }

                            ui.add_space(4.0);
                            let hpw  = &app.create_view.hidden_password;
                            let hpw2 = &app.create_view.hidden_password_confirm;
                            let h_ok  = !hpw.is_empty() && hpw == hpw2;
                            let h_bad = !hpw2.is_empty() && hpw != hpw2;

                            compact_label(ui, "Hidden passphrase");
                            ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_password)
                                .password(true).desired_width(f32::INFINITY));
                            ui.horizontal(|ui| {
                                ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_password_confirm)
                                    .password(true).hint_text("Confirm").desired_width(ui.available_width() - 26.0));
                                if h_ok  { ui.label(RichText::new("✓").color(theme::SUCCESS).strong()); }
                                if h_bad { ui.label(RichText::new("✗").color(theme::ERROR).strong()); }
                            });
                        });
                }

                // ── Key recipients ────────────────────────────────────────────
                if !app.keys.entries.is_empty() {
                    ui.add_space(6.0);
                    ui.label(RichText::new("Key recipients").color(theme::TEXT_MUTED).small().strong());
                    Frame::none()
                        .fill(Color32::from_rgb(18, 18, 30))
                        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(70, 50, 110)))
                        .rounding(egui::Rounding::same(6.0))
                        .inner_margin(Margin::same(6.0))
                        .show(ui, |ui| {
                            ui.set_max_width(col - 16.0);
                            for entry in app.keys.entries.clone().iter() {
                                let fp = entry.fingerprint;
                                let mut checked = app.create_view.selected_recipients.contains(&fp);
                                ui.horizontal(|ui| {
                                    if ui.checkbox(&mut checked, "").changed() {
                                        if checked { app.create_view.selected_recipients.push(fp); }
                                        else       { app.create_view.selected_recipients.retain(|r| r != &fp); }
                                    }
                                    ui.label(RichText::new(&entry.label).small().strong());
                                    ui.label(
                                        RichText::new(vnmcore::fp_display(&fp))
                                            .monospace().small()
                                            .color(Color32::from_rgb(140, 100, 180)),
                                    );
                                    if entry.is_protected { ui.label(RichText::new("🔒").small()); }
                                });
                            }
                        });
                    if !app.create_view.selected_recipients.is_empty() {
                        ui.label(RichText::new(format!(
                            "{} recipient(s) — can open with .key file",
                            app.create_view.selected_recipients.len()
                        )).small().color(theme::SUCCESS));
                    }
                }
            }, // end left column
        );

        ui.add_space(20.0);

        // ═══ RIGHT COLUMN ════════════════════════════════════════════════════
        ui.allocate_ui_with_layout(
            Vec2::new(col, ui.available_height()),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                // Cipher
                compact_label(ui, "Cipher");
                egui::ComboBox::from_id_source("cipher_select")
                    .selected_text(cipher_label(app.create_view.cipher_index))
                    .width(col - 8.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut app.create_view.cipher_index, 0, "ChaCha20-Poly1305  (recommended)");
                        ui.selectable_value(&mut app.create_view.cipher_index, 1, "AES-256-GCM");
                    });
                ui.add_space(8.0);

                // KDF profile
                compact_label(ui, "KDF profile");
                kdf_row(ui, col, !app.create_view.high_security,
                    "Interactive", "64 MiB · 3 passes · < 1 s",
                    || app.create_view.high_security = false);
                ui.add_space(3.0);
                kdf_row(ui, col, app.create_view.high_security,
                    "Sensitive", "256 MiB · 4 passes · 2–5 s",
                    || app.create_view.high_security = true);
                ui.add_space(8.0);

                // Action button (right column, bottom area)
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(6.0);

                let (can, size_mb) = {
                    let v = &app.create_view;
                    let has_rec = !v.selected_recipients.is_empty();
                    let pw_ok   = has_rec || (!v.password.is_empty() && v.password == v.password_confirm);
                    let hid_ok  = !v.hidden_enabled || (
                        !v.hidden_password.is_empty()
                            && v.hidden_password == v.hidden_password_confirm
                            && v.hidden_size_mb > 0
                            && v.hidden_size_mb < v.size_mb
                    );
                    (!v.container_path.is_empty() && v.size_mb > 0 && pw_ok && hid_ok, v.size_mb)
                };

                if ui.add_enabled(
                    can,
                    egui::Button::new(RichText::new("⚡  Create container").color(Color32::WHITE).strong())
                        .fill(if can { theme::BTN_PRIMARY } else { theme::CARD })
                        .min_size(Vec2::new(col - 8.0, 34.0)),
                ).clicked() {
                    app.action_create_vault();
                }

                if size_mb > 0 {
                    ui.add_space(4.0);
                    ui.label(RichText::new("⚠  Large containers take time to fill.")
                        .small().color(theme::WARN));
                }
            }, // end right column
        );
    }); // end horizontal_top
}

// ── Compact helpers ───────────────────────────────────────────────────────────

fn compact_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::TEXT_MUTED).small());
}

fn kdf_row(ui: &mut egui::Ui, col: f32, selected: bool, title: &str, subtitle: &str, on_click: impl FnOnce()) {
    let border = if selected { theme::ACCENT } else { theme::BORDER };
    let bg     = if selected { Color32::from_rgb(22, 36, 60) } else { theme::CARD };

    let resp = Frame::none()
        .fill(bg).stroke(egui::Stroke::new(1.5, border))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(Margin::symmetric(10.0, 6.0))
        .show(ui, |ui| {
            ui.set_width(col - 8.0);
            ui.horizontal(|ui| {
                let dot = if selected { "◉" } else { "○" };
                ui.label(RichText::new(dot).color(if selected { theme::ACCENT } else { theme::TEXT_MUTED }));
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).strong().small());
                    ui.label(RichText::new(subtitle).color(theme::ACCENT).small().monospace());
                });
            });
        });

    if resp.response.interact(egui::Sense::click()).clicked() {
        on_click();
    }
}

fn cipher_label(index: usize) -> &'static str {
    match index { 0 => "ChaCha20-Poly1305", _ => "AES-256-GCM" }
}
