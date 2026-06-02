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
    // Hidden volume
    pub hidden_enabled:          bool,
    pub hidden_size_mb:          u64,
    pub hidden_size_input:       String,
    pub hidden_password:         String,
    pub hidden_password_confirm: String,
    pub hidden_label:            String,
    // Key recipients
    pub selected_recipients:     Vec<[u8; 8]>,
}

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("✚").size(22.0).color(theme::ACCENT));
        ui.add_space(4.0);
        ui.heading("New Container");
    });
    ui.add_space(12.0);

    // ── Calculate column width BEFORE the ScrollArea ──────────────────────────
    // Inside a ScrollArea, available_width() can report a stale/inflated value.
    let avail = ui.available_width().min(ui.ctx().screen_rect().width() - 48.0);
    let col   = ((avail - 24.0) / 2.0).max(160.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        // Clamp the content width so it never causes horizontal overflow.
        ui.set_max_width(avail);

        ui.horizontal_top(|ui| {
            // ── Left column ───────────────────────────────────────────────────
            ui.allocate_ui_with_layout(
                egui::Vec2::new(col, f32::INFINITY),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    left_column(app, ui, col);
                },
            );

            ui.add_space(24.0);

            // ── Right column ──────────────────────────────────────────────────
            ui.allocate_ui_with_layout(
                egui::Vec2::new(col, f32::INFINITY),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    right_column(app, ui, col);
                },
            );
        });

        // ── Key recipients (full width) ───────────────────────────────────────
        if !app.keys.entries.is_empty() {
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(6.0);
            recipients_panel(app, ui);
        }

        // ── Action buttons ────────────────────────────────────────────────────
        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);
        action_row(app, ui);
    });
}

// ── Left column ───────────────────────────────────────────────────────────────

fn left_column(app: &mut VenomApp, ui: &mut egui::Ui, _col: f32) {
    section(ui, "Container");

    field(ui, "File path (.vnm)", |ui| {
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut app.create_view.container_path)
                .hint_text("/home/user/secrets.vnm")
                .desired_width(ui.available_width() - 80.0));
            if ui.add(
                egui::Button::new(RichText::new("💾 Save as…").color(Color32::WHITE))
                    .fill(theme::BTN_PRIMARY)
            ).clicked() {
                if let Some(mut p) = rfd::FileDialog::new()
                    .set_title("Choose container file location")
                    .add_filter("Venom container (*.vnm)", &["vnm"])
                    .save_file()
                {
                    if p.extension().is_none() { p.set_extension("vnm"); }
                    app.create_view.container_path = p.display().to_string();
                }
            }
        });
    });

    field(ui, "Label (optional)", |ui| {
        ui.add(egui::TextEdit::singleline(&mut app.create_view.label)
            .hint_text("My secrets").desired_width(f32::INFINITY));
    });

    field(ui, "Total size (MB)", |ui| {
        ui.horizontal(|ui| {
            let resp = ui.add(egui::TextEdit::singleline(&mut app.create_view.size_input)
                .hint_text("100").desired_width(100.0));
            if resp.changed() {
                app.create_view.size_mb = app.create_view.size_input.trim().parse().unwrap_or(0);
            }
            ui.label(RichText::new(format!("= {} MB", app.create_view.size_mb)).color(theme::TEXT_MUTED).small());
        });
    });

    ui.add_space(8.0);
    section(ui, "Outer volume passphrase");

    let pw  = app.create_view.password.clone();
    let pw2 = app.create_view.password_confirm.clone();
    let match_ok  = !pw.is_empty() && pw == pw2;
    let match_bad = !pw2.is_empty() && pw != pw2;
    let has_recipients = !app.create_view.selected_recipients.is_empty();

    field(ui, if has_recipients { "Passphrase (optional with key recipients)" } else { "Passphrase" }, |ui| {
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

    if has_recipients && app.create_view.password.is_empty() {
        ui.label(
            RichText::new("No password — opens via key only.")
                .small().color(theme::WARN),
        );
    }
}

// ── Right column ──────────────────────────────────────────────────────────────

fn right_column(app: &mut VenomApp, ui: &mut egui::Ui, col: f32) {
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

    ui.add_space(8.0);
    section(ui, "KDF profile");

    profile_card(ui, col, !app.create_view.high_security,
        "Interactive", "64 MiB · 3 passes", "< 1 s on modern hardware.",
        || app.create_view.high_security = false);
    ui.add_space(4.0);
    profile_card(ui, col, app.create_view.high_security,
        "Sensitive", "256 MiB · 4 passes", "2–5 s. Best for sensitive data.",
        || app.create_view.high_security = true);

    ui.add_space(10.0);

    // Hidden volume card
    let hidden = app.create_view.hidden_enabled;
    let border = if hidden { Color32::from_rgb(150, 80, 240) } else { theme::BORDER };
    let bg     = if hidden { Color32::from_rgb(30, 22, 42) } else { theme::CARD };

    Frame::none()
        .fill(bg).stroke(egui::Stroke::new(1.5, border))
        .rounding(egui::Rounding::same(8.0)).inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            ui.set_max_width(col - 20.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut app.create_view.hidden_enabled, "");
                ui.label(RichText::new("Hidden volume  (plausible deniability)").strong().small());
            });

            if app.create_view.hidden_enabled {
                ui.add_space(6.0);
                ui.label(RichText::new(
                    "A second encrypted volume in the same file. \
                     The hidden password reveals only hidden content."
                ).small().color(theme::TEXT_MUTED));
                ui.add_space(6.0);

                ui.label(RichText::new("Hidden size (MB)").color(theme::TEXT_MUTED).small());
                let resp = ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_size_input)
                    .hint_text("50").desired_width(100.0));
                if resp.changed() {
                    app.create_view.hidden_size_mb = app.create_view.hidden_size_input.trim().parse().unwrap_or(0);
                }

                if app.create_view.hidden_size_mb > 0
                    && app.create_view.hidden_size_mb < app.create_view.size_mb
                {
                    let outer = app.create_view.size_mb - app.create_view.hidden_size_mb;
                    ui.label(RichText::new(format!(
                        "Outer: ~{outer} MB  |  Hidden: ~{} MB", app.create_view.hidden_size_mb
                    )).small().color(theme::TEXT_MUTED));
                } else if app.create_view.hidden_size_mb >= app.create_view.size_mb && app.create_view.size_mb > 0 {
                    ui.label(RichText::new("Must be < total size.").small().color(theme::ERROR));
                }

                ui.add_space(4.0);
                ui.label(RichText::new("Hidden label (optional)").color(theme::TEXT_MUTED).small());
                ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_label)
                    .hint_text("Hidden vault").desired_width(f32::INFINITY));

                let hpw  = &app.create_view.hidden_password;
                let hpw2 = &app.create_view.hidden_password_confirm;
                let h_ok  = !hpw.is_empty() && hpw == hpw2;
                let h_bad = !hpw2.is_empty() && hpw != hpw2;

                ui.add_space(4.0);
                ui.label(RichText::new("Hidden passphrase").color(theme::TEXT_MUTED).small());
                ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_password)
                    .password(true).desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut app.create_view.hidden_password_confirm)
                        .password(true).hint_text("Confirm").desired_width(ui.available_width() - 28.0));
                    if h_ok  { ui.label(RichText::new("✓").color(theme::SUCCESS).strong()); }
                    if h_bad { ui.label(RichText::new("✗").color(theme::ERROR).strong()); }
                });
            }
        });
}

// ── Key recipients ────────────────────────────────────────────────────────────

fn recipients_panel(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.label(
        RichText::new("Key recipients  (can open this container with their private key)")
            .color(theme::TEXT_MUTED).small().strong(),
    );
    ui.add_space(4.0);
    Frame::none()
        .fill(egui::Color32::from_rgb(20, 20, 32))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(80, 60, 120)))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::same(8.0))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            for entry in app.keys.entries.clone().iter() {
                let fp      = entry.fingerprint;
                let mut checked = app.create_view.selected_recipients.contains(&fp);
                ui.horizontal(|ui| {
                    if ui.checkbox(&mut checked, "").changed() {
                        if checked { app.create_view.selected_recipients.push(fp); }
                        else       { app.create_view.selected_recipients.retain(|r| r != &fp); }
                    }
                    ui.label(RichText::new(&entry.label).strong().small());
                    ui.label(
                        RichText::new(vnmcore::fp_display(&fp))
                            .monospace().small()
                            .color(egui::Color32::from_rgb(160, 120, 200)),
                    );
                    if entry.is_protected { ui.label(RichText::new("🔒").small()); }
                });
            }
            if app.create_view.selected_recipients.is_empty() {
                ui.label(RichText::new("No recipient selected — password access only.").small().color(theme::TEXT_MUTED).italics());
            } else {
                ui.label(RichText::new(format!(
                    "{} recipient(s) — they can open with their .key file.",
                    app.create_view.selected_recipients.len()
                )).small().color(theme::SUCCESS));
            }
        });
}

// ── Action row ────────────────────────────────────────────────────────────────

fn action_row(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        let v = &app.create_view;
        let has_recipients = !v.selected_recipients.is_empty();
        let pw_ok  = has_recipients || (!v.password.is_empty() && v.password == v.password_confirm);
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
                .min_size(Vec2::new(150.0, 32.0)),
        ).clicked() {
            app.action_create_vault();
        }

        if ui.button("Cancel").clicked() {
            app.screen = Screen::VaultList;
            app.clear_status();
        }

        if app.create_view.size_mb > 0 {
            ui.label(
                RichText::new("⚠  Large containers take time to pre-fill.")
                    .small().color(theme::WARN),
            );
        }
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

fn profile_card(ui: &mut egui::Ui, col: f32, selected: bool, title: &str, subtitle: &str, hint: &str, on_select: impl FnOnce()) {
    let border = if selected { theme::ACCENT } else { theme::BORDER };
    let bg     = if selected { Color32::from_rgb(25, 40, 65) } else { theme::CARD };
    let inner_w = (col - 24.0).max(80.0);
    let resp = Frame::none()
        .fill(bg).stroke(egui::Stroke::new(1.5, border))
        .rounding(egui::Rounding::same(8.0)).inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            ui.set_width(inner_w);   // explicit width — prevents horizontal overflow
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
