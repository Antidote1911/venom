use egui::{Color32, Frame, Margin, RichText, Rounding, Ui, Vec2};
use crate::app::state::{MountStatus, VenomApp, Screen};
use super::theme;

#[derive(Default)]
pub struct VaultListView;

pub fn render(app: &mut VenomApp, ui: &mut Ui) {
    ui.add_space(8.0);

    // ── Header row ────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.heading("Vaults");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(
                    egui::Button::new(RichText::new("⛰  Mount vault").color(Color32::WHITE))
                        .fill(theme::BTN_PRIMARY)
                        .min_size(Vec2::new(120.0, 28.0)),
                )
                .clicked()
            {
                app.screen = Screen::Mount;
                app.clear_status();
            }
            ui.add_space(4.0);
            if ui
                .add(
                    egui::Button::new(RichText::new("✚  New vault"))
                        .min_size(Vec2::new(100.0, 28.0)),
                )
                .clicked()
            {
                app.screen = Screen::Create;
                app.clear_status();
            }
        });
    });

    ui.add_space(10.0);

    // ── Empty state ───────────────────────────────────────────────────────────
    if app.mounted.is_empty() {
        empty_state(ui);
        return;
    }

    // ── Vault cards ───────────────────────────────────────────────────────────
    let mut to_unmount: Option<usize> = None;
    let mut to_dismiss: Option<usize> = None;
    let mut to_open: Option<String>   = None;

    egui::ScrollArea::vertical()
        .max_height(ui.available_height() - 8.0)
        .show(ui, |ui| {
            for (i, mv) in app.mounted.iter().enumerate() {
                let status = mv.status.lock().unwrap().clone();
                vault_card(
                    ui, i,
                    mv.vault_path.as_str(),
                    mv.mountpoint.as_str(),
                    &status,
                    &mut to_unmount,
                    &mut to_dismiss,
                    &mut to_open,
                );
                ui.add_space(8.0);
            }
        });

    if let Some(i) = to_unmount { app.action_unmount(i); }
    if let Some(i) = to_dismiss { app.action_dismiss_error(i); }
    if let Some(p) = to_open    { app.action_open_folder(&p); }
}

// ── Vault card ────────────────────────────────────────────────────────────────

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
    let (border_color, bg) = match status {
        MountStatus::Mounting => (theme::WARN,    Color32::from_rgb(34, 32, 20)),
        MountStatus::Mounted { .. } => (theme::SUCCESS, Color32::from_rgb(20, 34, 24)),
        MountStatus::Error(_) => (theme::ERROR,   Color32::from_rgb(38, 20, 20)),
    };

    Frame::none()
        .fill(bg)
        .stroke(egui::Stroke::new(1.5, border_color))
        .rounding(Rounding::same(10.0))
        .inner_margin(Margin::same(14.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                // ── Left: status icon + info ──────────────────────────────────
                ui.vertical(|ui| {
                    match status {
                        MountStatus::Mounting => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new("Connecting…")
                                        .strong()
                                        .size(15.0)
                                        .color(theme::WARN),
                                );
                            });
                            mono_row(ui, "vault", vault_path);
                            mono_row(ui, "mount", mountpoint);
                        }

                        MountStatus::Mounted { label, cipher, created_at } => {
                            let title = label.as_deref().unwrap_or("Unnamed vault");
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("●")
                                        .color(theme::SUCCESS)
                                        .strong(),
                                );
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new(title).strong().size(15.0),
                                );
                                ui.label(
                                    RichText::new(format!("  read-write"))
                                        .small()
                                        .color(theme::SUCCESS),
                                );
                            });
                            ui.add_space(2.0);
                            mono_row(ui, "vault", vault_path);
                            mono_row(ui, "mount", mountpoint);
                            ui.horizontal(|ui| {
                                pill(ui, cipher, theme::ACCENT);
                                ui.label(
                                    RichText::new(format_ts(*created_at))
                                        .small()
                                        .color(theme::TEXT_MUTED),
                                );
                            });
                        }

                        MountStatus::Error(msg) => {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("✗")
                                        .color(theme::ERROR)
                                        .strong(),
                                );
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new("Mount failed")
                                        .strong()
                                        .size(15.0)
                                        .color(theme::ERROR),
                                );
                            });
                            mono_row(ui, "vault", vault_path);
                            ui.label(
                                RichText::new(msg.as_str())
                                    .small()
                                    .color(theme::ERROR),
                            );
                        }
                    }
                });

                // ── Right: action buttons ─────────────────────────────────────
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(4.0);
                    match status {
                        MountStatus::Mounting => {
                            if ui
                                .add(
                                    egui::Button::new(RichText::new("Cancel").color(Color32::WHITE))
                                        .fill(theme::BTN_DANGER)
                                        .min_size(Vec2::new(80.0, 28.0)),
                                )
                                .clicked()
                            {
                                *to_unmount = Some(index);
                            }
                        }
                        MountStatus::Mounted { .. } => {
                            if ui
                                .add(
                                    egui::Button::new(RichText::new("Unmount").color(Color32::WHITE))
                                        .fill(theme::BTN_DANGER)
                                        .min_size(Vec2::new(90.0, 28.0)),
                                )
                                .clicked()
                            {
                                *to_unmount = Some(index);
                            }
                            ui.add_space(6.0);
                            if ui
                                .add(
                                    egui::Button::new("Open folder")
                                        .min_size(Vec2::new(100.0, 28.0)),
                                )
                                .clicked()
                            {
                                *to_open = Some(mountpoint.to_string());
                            }
                        }
                        MountStatus::Error(_) => {
                            if ui
                                .add(
                                    egui::Button::new("Dismiss")
                                        .min_size(Vec2::new(80.0, 28.0)),
                                )
                                .clicked()
                            {
                                *to_dismiss = Some(index);
                            }
                        }
                    }
                });
            });
        });
}

// ── Empty state ───────────────────────────────────────────────────────────────

fn empty_state(ui: &mut Ui) {
    let avail = ui.available_size();
    ui.allocate_ui_with_layout(
        avail,
        egui::Layout::centered_and_justified(egui::Direction::TopDown),
        |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(avail.y * 0.20);
                ui.label(RichText::new("🔒").size(52.0));
                ui.add_space(12.0);
                ui.label(
                    RichText::new("No vaults mounted")
                        .size(18.0)
                        .color(theme::TEXT_MUTED),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new("Create a new vault or mount an existing one to get started.")
                        .color(theme::TEXT_MUTED)
                        .small(),
                );
            });
        },
    );
}

// ── Small helpers ─────────────────────────────────────────────────────────────

fn mono_row(ui: &mut Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{key}:")).small().color(theme::TEXT_MUTED));
        ui.label(RichText::new(value).small().monospace().color(theme::TEXT_MUTED));
    });
}

fn pill(ui: &mut Ui, text: &str, color: Color32) {
    Frame::none()
        .fill(color.gamma_multiply(0.18))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.5)))
        .rounding(Rounding::same(4.0))
        .inner_margin(Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).small().color(color));
        });
}

fn format_ts(secs: u64) -> String {
    let m = secs / 60;
    let h = (m / 60) % 24;
    let mn = m % 60;
    let d = secs / 86400 + 719_468;
    let era = d / 146_097;
    let doe = d % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let dd = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("created {y:04}-{mo:02}-{dd:02} {h:02}:{mn:02}")
}
