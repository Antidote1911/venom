use egui::{Color32, Frame, Margin, RichText, Rounding, Ui, Vec2};
use crate::app::state::{VenomApp, Screen};
use crate::keystore::KeyEntry;
use super::theme;

pub fn render(app: &mut VenomApp, ui: &mut Ui) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("🗝").size(22.0).color(theme::ACCENT));
        ui.add_space(4.0);
        ui.heading("Key Manager");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(format!("{} keypair(s)", app.keys.entries.len()))
                    .small().color(theme::TEXT_MUTED),
            );
        });
    });
    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "Hybrid post-quantum keypairs — X25519 (classical) + ML-KEM-1024 (FIPS 203).\n\
             Both keys are independent. Security holds even if one algorithm is broken."
        ).small().color(theme::TEXT_MUTED),
    );
    ui.add_space(12.0);

    let avail = ui.available_width();
    let col   = (avail - 16.0) / 2.0;

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| { ui.set_width(col); key_list(app, ui); });
        ui.add_space(16.0);
        ui.vertical(|ui| { ui.set_width(col); generate_panel(app, ui); ui.add_space(12.0); import_panel(app, ui); });
    });

    ui.add_space(16.0);
    ui.separator();
    ui.add_space(8.0);
    if ui.button("Close").clicked() { app.screen = Screen::VaultList; app.clear_status(); }
}

// ── Key list ──────────────────────────────────────────────────────────────────

fn key_list(app: &mut VenomApp, ui: &mut Ui) {
    ui.label(RichText::new("My keypairs").color(theme::TEXT_MUTED).small().strong());
    ui.add_space(6.0);

    if app.keys.entries.is_empty() {
        Frame::none()
            .fill(theme::CARD).stroke(egui::Stroke::new(1.0, theme::BORDER))
            .rounding(Rounding::same(8.0)).inner_margin(Margin::same(16.0))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("🗝").size(32.0));
                    ui.add_space(6.0);
                    ui.label(RichText::new("No keypairs yet.").color(theme::TEXT_MUTED));
                    ui.label(RichText::new("Generate one to get started.").small().color(theme::TEXT_MUTED));
                });
            });
        return;
    }

    let mut to_remove:     Option<[u8; 8]>           = None;
    let mut to_export_pub: Option<([u8; 8], String)>  = None;

    egui::ScrollArea::vertical()
        .max_height(ui.available_height() - 50.0)
        .show(ui, |ui| {
            for entry in app.keys.entries.clone().iter() {
                key_card(ui, entry, &mut to_remove, &mut to_export_pub);
                ui.add_space(6.0);
            }
        });

    if let Some(fp) = to_remove {
        app.keys.remove(&fp);
        app.set_status("Keypair deleted.", false);
    }
    if let Some((fp, label)) = to_export_pub {
        if let Some(dest) = rfd::FileDialog::new()
            .set_title(format!("Export public key — {label}"))
            .add_filter("Venom public key", &["pub"])
            .save_file()
        {
            // Ensure .pub extension
            let dest = if dest.extension().is_none() {
                dest.with_extension("pub")
            } else { dest };

            match app.keys.export_pub(&fp, &dest) {
                Ok(_)  => app.set_status(format!("Public key exported → {}", dest.display()), false),
                Err(e) => app.set_status(format!("Export failed: {e}"), true),
            }
        }
    }
}

fn key_card(
    ui:            &mut Ui,
    entry:         &KeyEntry,
    to_remove:     &mut Option<[u8; 8]>,
    to_export_pub: &mut Option<([u8; 8], String)>,
) {
    Frame::none()
        .fill(Color32::from_rgb(22, 28, 42))
        .stroke(egui::Stroke::new(1.5, theme::ACCENT))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            // Header
            ui.horizontal(|ui| {
                ui.label(RichText::new("🔑").color(theme::ACCENT));
                ui.label(RichText::new(&entry.label).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new("X25519 + ML-KEM-1024").small().color(Color32::from_rgb(160, 120, 220)));
                });
            });

            // Fingerprint
            ui.label(
                RichText::new(entry.fp_hex())
                    .monospace().small()
                    .color(Color32::from_rgb(180, 140, 255)),
            );

            // Date
            if entry.created_at > 0 {
                ui.label(RichText::new(format_ts(entry.created_at)).small().color(theme::TEXT_MUTED));
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.add(
                    egui::Button::new(RichText::new("📤 Export .pub").color(Color32::WHITE))
                        .fill(theme::BTN_PRIMARY)
                        .min_size(Vec2::new(110.0, 26.0))
                ).on_hover_text("Export your public key to share with others").clicked() {
                    *to_export_pub = Some((entry.fingerprint, entry.label.clone()));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(
                        egui::Button::new(RichText::new("Delete").color(Color32::WHITE))
                            .fill(theme::BTN_DANGER)
                            .min_size(Vec2::new(60.0, 26.0))
                    ).clicked() {
                        *to_remove = Some(entry.fingerprint);
                    }
                });
            });
        });
}

// ── Generate panel ────────────────────────────────────────────────────────────

fn generate_panel(app: &mut VenomApp, ui: &mut Ui) {
    ui.label(RichText::new("Generate new keypair").color(theme::TEXT_MUTED).small().strong());
    ui.add_space(4.0);

    Frame::none()
        .fill(Color32::from_rgb(18, 28, 18))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(40, 80, 40)))
        .rounding(Rounding::same(8.0)).inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(RichText::new("X25519 (classical)  +  ML-KEM-1024 (FIPS 203, NIST Cat. 5)").small().color(theme::SUCCESS));
            ui.label(RichText::new("Both keys are independent — neither is derived from the other.").small().color(theme::TEXT_MUTED));
            ui.label(RichText::new("Saved as:  <fingerprint>.key  (private + public, chmod 600)").small().monospace().color(theme::TEXT_MUTED));
            ui.add_space(8.0);

            ui.label(RichText::new("Label").color(theme::TEXT_MUTED).small());
            ui.add(
                egui::TextEdit::singleline(&mut app.key_manager_view.new_label)
                    .hint_text("My key / Work / Personal…")
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(8.0);

            let can_gen = !app.key_manager_view.new_label.trim().is_empty();
            if ui.add_enabled(
                can_gen,
                egui::Button::new(RichText::new("⚡ Generate keypair").color(Color32::WHITE).strong())
                    .fill(if can_gen { theme::BTN_PRIMARY } else { theme::CARD })
                    .min_size(Vec2::new(150.0, 30.0)),
            ).clicked() {
                let label = app.key_manager_view.new_label.trim().to_string();
                match app.keys.generate(&label) {
                    Ok(entry) => {
                        app.set_status(
                            format!("Keypair '{}' created — {}", label, entry.fp_hex()),
                            false,
                        );
                        app.key_manager_view.new_label.clear();
                    }
                    Err(e) => app.set_status(format!("Failed: {e}"), true),
                }
            }
        });
}

// ── Import panel ──────────────────────────────────────────────────────────────

fn import_panel(app: &mut VenomApp, ui: &mut Ui) {
    ui.label(RichText::new("Import keypair").color(theme::TEXT_MUTED).small().strong());
    ui.add_space(4.0);

    Frame::none()
        .fill(theme::CARD)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .rounding(Rounding::same(8.0)).inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            if ui.add(
                egui::Button::new("📥 Import .key file")
                    .min_size(Vec2::new(f32::INFINITY, 28.0))
            ).on_hover_text("Import a complete keypair (.key) from a backup or another machine").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Import keypair")
                    .add_filter("Venom keypair", &["key"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                {
                    match app.keys.import_key(&path) {
                        Ok(e)  => app.set_status(format!("Imported '{}' ({})", e.label, e.fp_hex()), false),
                        Err(e) => app.set_status(format!("Import failed: {e}"), true),
                    }
                }
            }

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(6.0);

            ui.label(
                RichText::new(
                    "Share your .pub file with others so they can add you as a recipient.\n\
                     Keep your .key file secret — it's the only way to open containers encrypted for you."
                ).small().color(theme::TEXT_MUTED),
            );
        });
}

fn format_ts(secs: u64) -> String {
    let d = secs / 86400 + 719_468;
    let era = d / 146_097; let doe = d % 146_097;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp = (5*doy+2)/153; let dd = doy - (153*mp+2)/5 + 1;
    let mo = if mp < 10 { mp+3 } else { mp-9 };
    let y = if mo <= 2 { y+1 } else { y };
    format!("Created {y:04}-{mo:02}-{dd:02}")
}
