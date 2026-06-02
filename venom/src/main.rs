mod app;
mod ui;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Venom")
            .with_inner_size([720.0, 500.0])
            .with_min_inner_size([600.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Venom",
        native_options,
        Box::new(|cc| Ok(Box::new(app::VenomApp::new(cc)))),
    )
}
