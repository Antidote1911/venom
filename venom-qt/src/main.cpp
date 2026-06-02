#include <QApplication>
#include <QFont>
#include "ui/MainWindow.h"
#include "ui/Style.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Venom"));
    app.setApplicationVersion(QStringLiteral("0.1.0"));
    app.setOrganizationName(QStringLiteral("VenomProject"));

    // Apply global dark stylesheet
    app.setStyleSheet(VenomStyle::darkStyleSheet());

    // Default font
    QFont font(QStringLiteral("Noto Sans"), 10);
    font.setStyleStrategy(QFont::PreferAntialias);
    app.setFont(font);

    Venom::MainWindow window;
    window.show();

    return app.exec();
}
