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
            ui.label(RichText::new(format!("{} keypair(s)", app.keys.entries.len())).small().color(theme::TEXT_MUTED));
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
        ui.vertical(|ui| {
            ui.set_width(col);
            generate_panel(app, ui);
            ui.add_space(12.0);
            import_panel(app, ui);
            // Show passphrase management if a key is selected
            if app.key_manager_view.selected_fp.is_some() {
                ui.add_space(12.0);
                passphrase_panel(app, ui);
            }
        });
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
    let mut to_select:     Option<[u8; 8]>            = None;

    egui::ScrollArea::vertical()
        .max_height(ui.available_height() - 50.0)
        .show(ui, |ui| {
            for entry in app.keys.entries.clone().iter() {
                let selected = app.key_manager_view.selected_fp.as_ref() == Some(&entry.fingerprint);
                key_card(ui, entry, selected, &mut to_remove, &mut to_export_pub, &mut to_select);
                ui.add_space(6.0);
            }
        });

    if let Some(fp) = to_remove {
        if app.key_manager_view.selected_fp == Some(fp) {
            app.key_manager_view.selected_fp = None;
        }
        match app.keys.remove(&fp) {
            Ok(_)  => app.set_status("Keypair deleted.", false),
            Err(e) => app.set_status(format!("Delete failed: {e}"), true),
        }
    }
    if let Some(fp) = to_select {
        app.key_manager_view.selected_fp =
            if app.key_manager_view.selected_fp == Some(fp) { None } else { Some(fp) };
        app.key_manager_view.unlock_passphrase.clear();
        app.key_manager_view.change_passphrase.clear();
        app.key_manager_view.change_passphrase_confirm.clear();
    }
    if let Some((fp, label)) = to_export_pub {
        if let Some(dest) = rfd::FileDialog::new()
            .set_title(format!("Export public key — {label}"))
            .add_filter("Venom public key", &["pub"])
            .save_file()
        {
            let dest = if dest.extension().is_none() { dest.with_extension("pub") } else { dest };
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
    selected:      bool,
    to_remove:     &mut Option<[u8; 8]>,
    to_export_pub: &mut Option<([u8; 8], String)>,
    to_select:     &mut Option<[u8; 8]>,
) {
    let border = if selected { Color32::from_rgb(200, 160, 255) } else { theme::ACCENT };
    let bg     = if selected { Color32::from_rgb(32, 22, 52) } else { Color32::from_rgb(22, 28, 42) };

    Frame::none()
        .fill(bg).stroke(egui::Stroke::new(1.5, border))
        .rounding(Rounding::same(8.0)).inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            ui.horizontal(|ui| {
                let lock_icon = if entry.is_protected { "🔒🔑" } else { "🔑" };
                ui.label(RichText::new(lock_icon).color(theme::ACCENT));
                ui.label(RichText::new(&entry.label).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if entry.is_protected {
                        ui.label(RichText::new("protected").small().color(theme::SUCCESS));
                    } else {
                        ui.label(RichText::new("unprotected").small().color(theme::WARN));
                    }
                });
            });

            ui.label(
                RichText::new(vnmcore::fp_display(&entry.fingerprint))
                    .monospace().small().color(Color32::from_rgb(180, 140, 255)),
            );
            if entry.created_at > 0 {
                ui.label(RichText::new(format_ts(entry.created_at)).small().color(theme::TEXT_MUTED));
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.add(
                    egui::Button::new(RichText::new("📤 Export .pub").color(Color32::WHITE))
                        .fill(theme::BTN_PRIMARY).min_size(Vec2::new(110.0, 26.0))
                ).on_hover_text("Export public key to share with others").clicked() {
                    *to_export_pub = Some((entry.fingerprint, entry.label.clone()));
                }

                let manage_label = if selected { "▲ Passphrase" } else { "▼ Passphrase" };
                if ui.add(
                    egui::Button::new(RichText::new(manage_label).small())
                        .min_size(Vec2::new(100.0, 26.0))
                ).on_hover_text("Manage passphrase protection").clicked() {
                    *to_select = Some(entry.fingerprint);
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(
                        egui::Button::new(RichText::new("Delete").color(Color32::WHITE))
                            .fill(theme::BTN_DANGER).min_size(Vec2::new(60.0, 26.0))
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
            ui.label(RichText::new("X25519 + ML-KEM-1024 (FIPS 203, NIST Cat. 5)").small().color(theme::SUCCESS));
            ui.label(RichText::new("Both keys are independent random values.").small().color(theme::TEXT_MUTED));
            ui.add_space(8.0);

            ui.label(RichText::new("Label").color(theme::TEXT_MUTED).small());
            ui.add(egui::TextEdit::singleline(&mut app.key_manager_view.new_label)
                .hint_text("My key / Work / Personal…").desired_width(f32::INFINITY));
            ui.add_space(6.0);

            // Passphrase option
            ui.checkbox(&mut app.key_manager_view.use_passphrase, "Protect with passphrase");

            if app.key_manager_view.use_passphrase {
                ui.add_space(4.0);

                let pw  = &app.key_manager_view.new_passphrase;
                let pw2 = &app.key_manager_view.new_passphrase_confirm;
                let match_ok  = !pw.is_empty() && pw == pw2;
                let match_bad = !pw2.is_empty() && pw != pw2;

                ui.label(RichText::new("Passphrase").color(theme::TEXT_MUTED).small());
                ui.add(egui::TextEdit::singleline(&mut app.key_manager_view.new_passphrase)
                    .password(true).desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut app.key_manager_view.new_passphrase_confirm)
                        .password(true).hint_text("Confirm passphrase").desired_width(ui.available_width() - 28.0));
                    if match_ok  { ui.label(RichText::new("✓").color(theme::SUCCESS).strong()); }
                    if match_bad { ui.label(RichText::new("✗").color(theme::ERROR).strong()); }
                });

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.radio_value(&mut app.key_manager_view.new_kdf_sensitive, false, "Interactive (64 MiB)");
                    ui.radio_value(&mut app.key_manager_view.new_kdf_sensitive, true,  "Sensitive (256 MiB)");
                });
            }

            ui.add_space(8.0);

            let pw_ok = !app.key_manager_view.use_passphrase
                || (!app.key_manager_view.new_passphrase.is_empty()
                    && app.key_manager_view.new_passphrase == app.key_manager_view.new_passphrase_confirm);
            let can_gen = !app.key_manager_view.new_label.trim().is_empty() && pw_ok;

            if ui.add_enabled(
                can_gen,
                egui::Button::new(RichText::new("⚡ Generate keypair").color(Color32::WHITE).strong())
                    .fill(if can_gen { theme::BTN_PRIMARY } else { theme::CARD })
                    .min_size(Vec2::new(150.0, 30.0)),
            ).clicked() {
                let label   = app.key_manager_view.new_label.trim().to_string();
                let profile = if app.key_manager_view.new_kdf_sensitive { 1u8 } else { 0u8 };
                let result  = if app.key_manager_view.use_passphrase {
                    let pw = app.key_manager_view.new_passphrase.as_bytes().to_vec();
                    app.keys.generate_protected(&label, &pw, profile)
                } else {
                    app.keys.generate(&label)
                };
                match result {
                    Ok(e) => {
                        app.set_status(format!("Keypair '{}' created — {}", label, e.fp_hex()), false);
                        app.key_manager_view.new_label.clear();
                        app.key_manager_view.new_passphrase.clear();
                        app.key_manager_view.new_passphrase_confirm.clear();
                        app.key_manager_view.use_passphrase = false;
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
        .fill(theme::CARD).stroke(egui::Stroke::new(1.0, theme::BORDER))
        .rounding(Rounding::same(8.0)).inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            if ui.add(
                egui::Button::new("📥 Import .key file").min_size(Vec2::new(f32::INFINITY, 28.0))
            ).on_hover_text("Import a keypair from a backup or another machine").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Import keypair").add_filter("Venom keypair", &["key"])
                    .pick_file()
                {
                    match app.keys.import_key(&path) {
                        Ok(e)  => app.set_status(format!("Imported '{}' ({})", e.label, e.fp_hex()), false),
                        Err(e) => app.set_status(format!("Import failed: {e}"), true),
                    }
                }
            }
            ui.add_space(4.0);
            ui.label(RichText::new(
                "Share your .pub file with others so they can add you as a recipient.\n\
                 Keep your .key file secret and protected."
            ).small().color(theme::TEXT_MUTED));
        });
}

// ── Passphrase management panel ───────────────────────────────────────────────

fn passphrase_panel(app: &mut VenomApp, ui: &mut Ui) {
    let fp = match app.key_manager_view.selected_fp { Some(f) => f, None => return };
    let entry = match app.keys.entries.iter().find(|e| e.fingerprint == fp).cloned() {
        Some(e) => e, None => return,
    };

    ui.label(RichText::new(format!("Passphrase — {}", entry.label)).color(theme::TEXT_MUTED).small().strong());
    ui.add_space(4.0);

    let purple_border = egui::Stroke::new(1.0, Color32::from_rgb(120, 80, 180));
    Frame::none()
        .fill(Color32::from_rgb(26, 20, 42)).stroke(purple_border)
        .rounding(Rounding::same(8.0)).inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            if entry.is_protected {
                // ── Remove protection ──────────────────────────────────────
                ui.label(RichText::new("🔒 This keypair is passphrase-protected.").small().color(theme::SUCCESS));
                ui.add_space(6.0);

                ui.label(RichText::new("Current passphrase (to remove protection):").color(theme::TEXT_MUTED).small());
                ui.add(egui::TextEdit::singleline(&mut app.key_manager_view.unlock_passphrase)
                    .password(true).desired_width(f32::INFINITY));

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.add(
                        egui::Button::new(RichText::new("🔓 Remove protection").color(Color32::WHITE))
                            .fill(Color32::from_rgb(100, 60, 160)).min_size(Vec2::new(150.0, 26.0))
                    ).clicked() {
                        let pw = app.key_manager_view.unlock_passphrase.as_bytes().to_vec();
                        match app.keys.unprotect(&fp, &pw) {
                            Ok(_)  => { app.set_status(format!("Passphrase removed from '{}'.", entry.label), false);
                                        app.key_manager_view.unlock_passphrase.clear(); }
                            Err(e) => app.set_status(format!("Failed: {e}"), true),
                        }
                    }
                });
            } else {
                // ── Add protection ─────────────────────────────────────────
                ui.label(RichText::new("⚠ This keypair is not passphrase-protected.").small().color(theme::WARN));
                ui.label(RichText::new("It relies on filesystem permissions only (chmod 600).").small().color(theme::TEXT_MUTED));
                ui.add_space(6.0);

                let pw  = &app.key_manager_view.change_passphrase;
                let pw2 = &app.key_manager_view.change_passphrase_confirm;
                let match_ok  = !pw.is_empty() && pw == pw2;
                let match_bad = !pw2.is_empty() && pw != pw2;

                ui.label(RichText::new("New passphrase:").color(theme::TEXT_MUTED).small());
                ui.add(egui::TextEdit::singleline(&mut app.key_manager_view.change_passphrase)
                    .password(true).desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut app.key_manager_view.change_passphrase_confirm)
                        .password(true).hint_text("Confirm").desired_width(ui.available_width() - 28.0));
                    if match_ok  { ui.label(RichText::new("✓").color(theme::SUCCESS).strong()); }
                    if match_bad { ui.label(RichText::new("✗").color(theme::ERROR).strong()); }
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.radio_value(&mut app.key_manager_view.change_kdf_sensitive, false, "Interactive");
                    ui.radio_value(&mut app.key_manager_view.change_kdf_sensitive, true,  "Sensitive");
                });
                ui.add_space(4.0);

                if ui.add_enabled(
                    match_ok,
                    egui::Button::new(RichText::new("🔒 Add passphrase protection").color(Color32::WHITE))
                        .fill(if match_ok { Color32::from_rgb(100, 60, 160) } else { theme::CARD })
                        .min_size(Vec2::new(f32::INFINITY, 26.0))
                ).clicked() {
                    let pw      = app.key_manager_view.change_passphrase.as_bytes().to_vec();
                    let profile = if app.key_manager_view.change_kdf_sensitive { 1u8 } else { 0u8 };
                    match app.keys.protect(&fp, None, &pw, profile) {
                        Ok(_)  => { app.set_status(format!("Passphrase added to '{}'.", entry.label), false);
                                    app.key_manager_view.change_passphrase.clear();
                                    app.key_manager_view.change_passphrase_confirm.clear(); }
                        Err(e) => app.set_status(format!("Failed: {e}"), true),
                    }
                }
            }
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
