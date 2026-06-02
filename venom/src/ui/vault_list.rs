use egui::{Color32, RichText, Ui};
use crate::app::state::{MountStatus, VenomApp, Screen};

#[derive(Default)]
pub struct VaultListView;

pub fn render(app: &mut VenomApp, ui: &mut Ui) {
    ui.add_space(12.0);
    ui.heading("Mounted Vaults");
    ui.add_space(8.0);

    if app.mounted.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(
                RichText::new("No vaults mounted.\nUse Vault → Mount vault… to get started.")
                    .color(Color32::GRAY)
                    .italics(),
            );
        });
        ui.add_space(16.0);
        bottom_bar(app, ui);
        return;
    }

    let mut to_unmount: Option<usize> = None;
    let mut to_dismiss: Option<usize> = None;
    let mut to_open: Option<String> = None;

    egui::ScrollArea::vertical()
        .max_height(ui.available_height() - 48.0)
        .show(ui, |ui| {
            for (i, mv) in app.mounted.iter().enumerate() {
                let status = mv.status.lock().unwrap().clone();
                vault_card(ui, i, mv.vault_path.as_str(), mv.mountpoint.as_str(), &status,
                    &mut to_unmount, &mut to_dismiss, &mut to_open);
                ui.add_space(6.0);
            }
        });

    if let Some(i) = to_unmount { app.action_unmount(i); }
    if let Some(i) = to_dismiss { app.action_dismiss_error(i); }
    if let Some(p) = to_open    { app.action_open_folder(&p); }

    bottom_bar(app, ui);
}

fn vault_card(
    ui: &mut Ui,
    index: usize,
    vault_path: &str,
    mountpoint: &str,
    status: &MountStatus,
    to_unmount: &mut Option<usize>,
    to_dismiss: &mut Option<usize>,
    to_open: &mut Option<String>,
) {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // ── Left column: metadata ─────────────────────────────
                ui.vertical(|ui| {
                    match status {
                        MountStatus::Mounting => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(
                                    RichText::new("Mounting…")
                                        .strong()
                                        .color(Color32::from_rgb(180, 180, 60)),
                                );
                            });
                            ui.label(
                                RichText::new(vault_path).color(Color32::GRAY).small(),
                            );
                        }

                        MountStatus::Mounted { label, cipher, created_at } => {
                            let title = label.as_deref().unwrap_or("(unlabelled)");
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("● ")
                                        .color(Color32::from_rgb(80, 200, 120))
                                        .strong(),
                                );
                                ui.label(RichText::new(title).strong().size(15.0));
                            });
                            ui.label(
                                RichText::new(format!("📁  {vault_path}"))
                                    .color(Color32::GRAY).small(),
                            );
                            ui.label(
                                RichText::new(format!("⛰  {mountpoint}"))
                                    .color(Color32::GRAY).small(),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "🔑  {cipher}   •   {}",
                                    format_timestamp(*created_at)
                                ))
                                .color(Color32::GRAY).small(),
                            );
                        }

                        MountStatus::Error(msg) => {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("✗ ")
                                        .color(Color32::from_rgb(220, 80, 80))
                                        .strong(),
                                );
                                ui.label(RichText::new("Mount failed").strong());
                            });
                            ui.label(
                                RichText::new(vault_path).color(Color32::GRAY).small(),
                            );
                            ui.label(
                                RichText::new(msg.as_str())
                                    .color(Color32::from_rgb(220, 100, 100))
                                    .small(),
                            );
                        }
                    }
                });

                // ── Right column: action buttons ──────────────────────
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    match status {
                        MountStatus::Mounting => {
                            let btn = egui::Button::new(
                                RichText::new("Cancel").color(Color32::from_rgb(220, 80, 80)),
                            );
                            if ui.add(btn).clicked() {
                                *to_unmount = Some(index);
                            }
                        }

                        MountStatus::Mounted { .. } => {
                            if ui
                                .button(
                                    RichText::new("Unmount")
                                        .color(Color32::from_rgb(220, 80, 80)),
                                )
                                .clicked()
                            {
                                *to_unmount = Some(index);
                            }
                            if ui.button("Open folder").clicked() {
                                *to_open = Some(mountpoint.to_string());
                            }
                        }

                        MountStatus::Error(_) => {
                            if ui.button("Dismiss").clicked() {
                                *to_dismiss = Some(index);
                            }
                        }
                    }
                });
            });
        });
}

fn bottom_bar(app: &mut VenomApp, ui: &mut Ui) {
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui.button("+ New vault").clicked() {
            app.screen = Screen::Create;
            app.clear_status();
        }
        if ui.button("⛰ Mount vault").clicked() {
            app.screen = Screen::Mount;
            app.clear_status();
        }
    });
}

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM".
fn format_timestamp(secs: u64) -> String {
    // Simple manual formatter — no external crate needed.
    let s = secs;
    let mins_total = s / 60;
    let hour = (mins_total / 60) % 24;
    let min = mins_total % 60;

    // Days since Unix epoch → Gregorian calendar
    let days = s / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {hour:02}:{min:02}")
}

fn days_to_ymd(mut days: u64) -> (u32, u32, u32) {
    // Rata Die algorithm (simplified, valid for years 1970–2200).
    days += 719_468;
    let era = days / 146_097;
    let doe = days % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y as u32, mo as u32, d as u32)
}
