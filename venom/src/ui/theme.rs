use egui::{Color32, FontFamily, FontId, Rounding, TextStyle, Visuals};

// ── Palette ───────────────────────────────────────────────────────────────────
pub const BG: Color32          = Color32::from_rgb(18,  18,  22);
pub const PANEL: Color32       = Color32::from_rgb(28,  28,  34);
pub const CARD: Color32        = Color32::from_rgb(36,  36,  44);
pub const CARD_HOVER: Color32  = Color32::from_rgb(44,  44,  54);
pub const BORDER: Color32      = Color32::from_rgb(55,  55,  70);
pub const TEXT: Color32        = Color32::from_rgb(220, 220, 230);
pub const TEXT_MUTED: Color32  = Color32::from_rgb(130, 130, 150);
pub const ACCENT: Color32      = Color32::from_rgb(90,  170, 255);
pub const SUCCESS: Color32     = Color32::from_rgb(80,  200, 120);
pub const WARN: Color32        = Color32::from_rgb(240, 190, 60);
pub const ERROR: Color32       = Color32::from_rgb(220, 80,  80);
pub const BTN_PRIMARY: Color32 = Color32::from_rgb(55,  120, 210);
pub const BTN_DANGER: Color32  = Color32::from_rgb(170, 50,  50);

// ── Theme setup ───────────────────────────────────────────────────────────────

pub fn apply(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();

    visuals.window_fill      = PANEL;
    visuals.panel_fill       = BG;
    visuals.faint_bg_color   = PANEL;
    visuals.extreme_bg_color = BG;

    visuals.window_stroke    = egui::Stroke::new(1.0, BORDER);
    visuals.widgets.noninteractive.bg_fill   = CARD;
    visuals.widgets.inactive.bg_fill         = CARD;
    visuals.widgets.hovered.bg_fill          = CARD_HOVER;
    visuals.widgets.active.bg_fill           = BTN_PRIMARY;

    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT_MUTED);
    visuals.widgets.inactive.fg_stroke       = egui::Stroke::new(1.0, TEXT);
    visuals.widgets.hovered.fg_stroke        = egui::Stroke::new(1.5, ACCENT);
    visuals.widgets.active.fg_stroke         = egui::Stroke::new(1.5, Color32::WHITE);

    visuals.widgets.noninteractive.rounding  = Rounding::same(6.0);
    visuals.widgets.inactive.rounding        = Rounding::same(6.0);
    visuals.widgets.hovered.rounding         = Rounding::same(6.0);
    visuals.widgets.active.rounding          = Rounding::same(6.0);

    visuals.window_rounding = Rounding::same(10.0);
    visuals.menu_rounding   = Rounding::same(8.0);

    visuals.selection.bg_fill   = BTN_PRIMARY.gamma_multiply(0.6);
    visuals.selection.stroke    = egui::Stroke::new(1.0, ACCENT);

    visuals.hyperlink_color  = ACCENT;
    visuals.warn_fg_color    = WARN;
    visuals.error_fg_color   = ERROR;

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Small,   FontId::new(11.0, FontFamily::Proportional)),
        (TextStyle::Body,    FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Button,  FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Heading, FontId::new(20.0, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
    ]
    .into();
    style.spacing.item_spacing   = egui::Vec2::new(8.0, 6.0);
    style.spacing.button_padding = egui::Vec2::new(12.0, 6.0);
    style.spacing.window_margin  = egui::Margin::same(16.0);
    ctx.set_style(style);
}
