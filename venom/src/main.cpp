#include <QApplication>
#include <QStyleFactory>
#include "ui/MainWindow.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Venom"));
    app.setApplicationVersion(QStringLiteral("0.1.0"));
    app.setOrganizationName(QStringLiteral("VenomProject"));

    // Use the classic Fusion style — no custom stylesheet
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    Venom::MainWindow window;
    window.show();

    return app.exec();
}
