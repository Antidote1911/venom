use egui::{Color32, Frame, Margin, RichText, Vec2};
use crate::app::state::{VenomApp, Screen};
use super::theme;

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("👥").size(22.0).color(theme::ACCENT));
        ui.add_space(4.0);
        ui.heading("Manage Recipients");
    });

    if let Some(mp) = &app.recipient_view.mountpoint.clone() {
        ui.add_space(4.0);
        ui.label(RichText::new(format!("Container mounted at: {mp}")).small().color(theme::TEXT_MUTED));
    }

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    // ── Current recipients ────────────────────────────────────────────────────
    ui.label(RichText::new("Current recipients").color(theme::TEXT_MUTED).small().strong());
    ui.add_space(6.0);

    if app.recipient_view.recipients.is_empty() {
        ui.label(RichText::new("No recipients loaded.").color(theme::TEXT_MUTED).italics().small());
    } else {
        for (i, r) in app.recipient_view.recipients.iter().enumerate() {
            Frame::none()
                .fill(theme::CARD)
                .stroke(egui::Stroke::new(1.0, theme::BORDER))
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(Margin::symmetric(10.0, 6.0))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        if r.is_key {
                            let fp = hex_fp(&r.fingerprint);
                            ui.label(RichText::new("🔑").color(Color32::from_rgb(180, 120, 255)));
                            ui.label(RichText::new(format!("ML-KEM key  {fp}")).monospace().small());
                        } else {
                            ui.label(RichText::new("🔒").color(theme::ACCENT));
                            ui.label(RichText::new(format!("Password slot #{}", r.slot_index + 1)).small());
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if r.is_key {
                                if ui.add(
                                    egui::Button::new(RichText::new("Remove").color(Color32::WHITE))
                                        .fill(theme::BTN_DANGER)
                                ).clicked() {
                                    app.recipient_view.pending_remove = Some(r.fingerprint);
                                }
                            }
                        });
                    });
                });
            ui.add_space(4.0);
        }
    }

    // ── Add password recipient ────────────────────────────────────────────────
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);
    ui.label(RichText::new("Add password recipient").color(theme::TEXT_MUTED).small().strong());
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut app.recipient_view.new_password)
            .password(true)
            .hint_text("New passphrase")
            .desired_width(240.0));
        if ui.add(
            egui::Button::new(RichText::new("Add").color(Color32::WHITE))
                .fill(theme::BTN_PRIMARY)
                .min_size(Vec2::new(60.0, 28.0))
        ).clicked() && !app.recipient_view.new_password.is_empty() {
            app.action_add_password_recipient();
        }
    });

    // ── Add ML-KEM recipient ──────────────────────────────────────────────────
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);
    ui.label(RichText::new("Add ML-KEM recipient (post-quantum)").color(theme::TEXT_MUTED).small().strong());
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut app.recipient_view.new_pubkey_path)
            .hint_text("Path to .vpub file")
            .desired_width(ui.available_width() - 130.0));
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Select public key (.vpub)")
                .add_filter("Venom public key", &["vpub"])
                .add_filter("All files", &["*"])
                .pick_file()
            {
                app.recipient_view.new_pubkey_path = p.display().to_string();
            }
        }
        if ui.add(
            egui::Button::new(RichText::new("Add").color(Color32::WHITE))
                .fill(Color32::from_rgb(140, 80, 220))
                .min_size(Vec2::new(60.0, 28.0))
        ).clicked() && !app.recipient_view.new_pubkey_path.is_empty() {
            app.action_add_key_recipient();
        }
    });

    // ── Generate keypair ──────────────────────────────────────────────────────
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);
    ui.label(RichText::new("Generate new ML-KEM-1024 keypair (NIST Category 5)").color(theme::TEXT_MUTED).small().strong());
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut app.recipient_view.keygen_path)
            .hint_text("/home/user/my-key  (produces .vpub and .vpriv)")
            .desired_width(ui.available_width() - 110.0));
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Choose key file base name")
                .save_file()
            {
                app.recipient_view.keygen_path = p.display().to_string();
            }
        }
    });
    ui.add_space(4.0);
    if ui.add(
        egui::Button::new(RichText::new("Generate keypair").color(Color32::WHITE))
            .fill(Color32::from_rgb(100, 60, 180))
            .min_size(Vec2::new(140.0, 30.0))
    ).clicked() && !app.recipient_view.keygen_path.is_empty() {
        app.action_generate_keypair();
    }

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(8.0);
    if ui.button("Close").clicked() {
        app.screen = Screen::VaultList;
        app.clear_status();
    }
}

fn hex_fp(fp: &[u8; 8]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}
