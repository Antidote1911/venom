use egui::RichText;
use crate::app::state::{VenomApp, Screen};

#[derive(Default)]
pub struct CreateView {
    pub vault_path: String,
    pub password: String,
    pub password_confirm: String,
    pub label: String,
    pub cipher_index: usize, // 0 = ChaCha20, 1 = AES-256-GCM
    pub high_security: bool,
}

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.add_space(12.0);
    ui.heading("Create New Vault");
    ui.add_space(16.0);

    egui::Grid::new("create_form")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .show(ui, |ui| {
            ui.label("Label (optional):");
            ui.text_edit_singleline(&mut app.create_view.label);
            ui.end_row();

            ui.label("Vault directory:");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut app.create_view.vault_path);
                if ui.small_button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        app.create_view.vault_path = path.display().to_string();
                    }
                }
            });
            ui.end_row();

            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut app.create_view.password).password(true));
            ui.end_row();

            ui.label("Confirm password:");
            ui.add(
                egui::TextEdit::singleline(&mut app.create_view.password_confirm).password(true),
            );
            ui.end_row();

            ui.label("Cipher:");
            egui::ComboBox::from_id_source("cipher_select")
                .selected_text(cipher_label(app.create_view.cipher_index))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.create_view.cipher_index, 0, "ChaCha20-Poly1305");
                    ui.selectable_value(&mut app.create_view.cipher_index, 1, "AES-256-GCM");
                });
            ui.end_row();

            ui.label("Security profile:");
            ui.horizontal(|ui| {
                ui.radio_value(&mut app.create_view.high_security, false, "Interactive (64 MiB)");
                ui.radio_value(&mut app.create_view.high_security, true, "Sensitive (256 MiB)");
            });
            ui.end_row();
        });

    if app.create_view.high_security {
        ui.add_space(4.0);
        ui.label(
            RichText::new("⚠ Sensitive profile: vault unlock may take several seconds.")
                .color(egui::Color32::YELLOW)
                .small(),
        );
    }

    ui.add_space(16.0);
    ui.horizontal(|ui| {
        if ui.button("Create").clicked() {
            app.action_create_vault();
        }
        if ui.button("Cancel").clicked() {
            app.screen = Screen::VaultList;
            app.clear_status();
        }
    });
}

fn cipher_label(index: usize) -> &'static str {
    match index {
        0 => "ChaCha20-Poly1305",
        _ => "AES-256-GCM",
    }
}
