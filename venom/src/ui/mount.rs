use crate::app::state::{VenomApp, Screen};

#[derive(Default)]
pub struct MountView {
    pub vault_path: String,
    pub mountpoint: String,
    pub password: String,
}

pub fn render(app: &mut VenomApp, ui: &mut egui::Ui) {
    ui.add_space(12.0);
    ui.heading("Mount Vault");
    ui.add_space(16.0);

    egui::Grid::new("mount_form")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .show(ui, |ui| {
            ui.label("Vault directory:");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut app.mount_view.vault_path);
                if ui.small_button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        app.mount_view.vault_path = path.display().to_string();
                    }
                }
            });
            ui.end_row();

            ui.label("Mountpoint:");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut app.mount_view.mountpoint);
                if ui.small_button("Browse…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        app.mount_view.mountpoint = path.display().to_string();
                    }
                }
            });
            ui.end_row();

            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut app.mount_view.password).password(true));
            ui.end_row();
        });

    ui.add_space(16.0);
    ui.horizontal(|ui| {
        if ui.button("Mount").clicked() {
            app.action_mount_vault();
        }
        if ui.button("Cancel").clicked() {
            app.screen = Screen::VaultList;
            app.clear_status();
        }
    });
}
