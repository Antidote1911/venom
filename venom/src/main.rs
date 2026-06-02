mod app;
mod recent;
mod keystore;
mod ui;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Venom")
            .with_inner_size([900.0, 620.0])
            .with_min_inner_size([800.0, 580.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Venom",
        native_options,
        Box::new(|cc| {
            ui::theme::apply(&cc.egui_ctx);
            Ok(Box::new(app::VenomApp::new(cc)))
        }),
    )
}
