#include "MainWindow.h"
#include "CreateDialog.h"
#include "MountDialog.h"
#include "KeyManagerDialog.h"
#include "VaultCard.h"
#include "Style.h"
#include <QApplication>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFrame>
#include <QScrollArea>
#include <QMessageBox>
#include <QFileDialog>

namespace Venom {

// ── VaultListWidget (inline) ──────────────────────────────────────────────────

class VaultListWidget : public QWidget {
    Q_OBJECT
public:
    explicit VaultListWidget(QWidget* parent = nullptr) : QWidget(parent) {
        m_layout = new QVBoxLayout(this);
        m_layout->setContentsMargins(0, 0, 0, 0);
        m_layout->setSpacing(8);
        m_layout->addStretch();
    }

    void refresh(const QList<MountedContainer>& containers, VenomCore* core) {
        // Clear old cards
        while (m_layout->count() > 1) {
            auto* item = m_layout->takeAt(0);
            if (item->widget()) item->widget()->deleteLater();
            delete item;
        }
        for (const auto& c : containers) {
            auto* card = new VaultCard(c, core, this);
            m_layout->insertWidget(m_layout->count() - 1, card);
        }

        if (containers.isEmpty()) {
            auto* lbl = new QLabel(
                QStringLiteral("No vaults mounted.\n\nUse + New Container or ⛰ Mount to get started."),
                this);
            lbl->setAlignment(Qt::AlignCenter);
            lbl->setProperty("class", "muted");
            lbl->setStyleSheet("color: #606080; font-size: 15px;");
            m_layout->insertWidget(0, lbl);
        }
    }

private:
    QVBoxLayout* m_layout;
};

// ── MainWindow ────────────────────────────────────────────────────────────────

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_core(new VenomCore(this))
{
    setWindowTitle(QStringLiteral("🔒 Venom"));
    setMinimumSize(900, 620);
    resize(1000, 680);
    setupUi();
    setupConnections();
}

void MainWindow::setupUi() {
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // ── Top bar ───────────────────────────────────────────────────────────────
    auto* topBar = new QWidget;
    topBar->setFixedHeight(48);
    topBar->setStyleSheet(
        "background-color: #1e1e2c; border-bottom: 1px solid #2e2e40;");
    auto* tbLayout = new QHBoxLayout(topBar);
    tbLayout->setContentsMargins(16, 0, 16, 0);

    auto* brand = new QLabel(QStringLiteral("🔒  Venom"));
    brand->setStyleSheet("color: #5ab0ff; font-size: 16px; font-weight: bold;");
    tbLayout->addWidget(brand);
    tbLayout->addStretch();

    m_btnCreate = new QPushButton(QStringLiteral("✚  New Container"));
    m_btnCreate->setProperty("primary", true);
    m_btnCreate->setFixedHeight(32);
    tbLayout->addWidget(m_btnCreate);

    m_btnMount = new QPushButton(QStringLiteral("⛰  Mount"));
    m_btnMount->setFixedHeight(32);
    tbLayout->addWidget(m_btnMount);

    m_btnKeys = new QPushButton(QStringLiteral("🗝  Keys"));
    m_btnKeys->setFixedHeight(32);
    tbLayout->addWidget(m_btnKeys);

    root->addWidget(topBar);

    // ── Vault list (scrollable) ────────────────────────────────────────────────
    m_vaultList = new VaultListWidget;
    auto* scroll = new QScrollArea;
    scroll->setWidget(m_vaultList);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("background: transparent;");

    auto* contentArea = new QWidget;
    auto* cLayout = new QVBoxLayout(contentArea);
    cLayout->setContentsMargins(24, 16, 24, 16);
    cLayout->addWidget(scroll);

    root->addWidget(contentArea, 1);

    // ── Status bar ────────────────────────────────────────────────────────────
    m_statusLabel = new QLabel;
    m_statusLabel->setFixedHeight(28);
    m_statusLabel->setContentsMargins(12, 0, 12, 0);
    m_statusLabel->setStyleSheet(
        "background: #0e0e18; color: #6060a0; border-top: 1px solid #2e2e40; font-size: 12px;");
    root->addWidget(m_statusLabel);

    refreshVaultList();
}

void MainWindow::setupConnections() {
    connect(m_btnCreate, &QPushButton::clicked, this, &MainWindow::openCreateDialog);
    connect(m_btnMount,  &QPushButton::clicked, this, &MainWindow::openMountDialog);
    connect(m_btnKeys,   &QPushButton::clicked, this, &MainWindow::openKeyManager);

    connect(m_core, &VenomCore::mountStarted,    this, &MainWindow::onMountStarted);
    connect(m_core, &VenomCore::mountGone,       this, &MainWindow::onMountGone);
    connect(m_core, &VenomCore::mountError,      this, &MainWindow::onMountError);
    connect(m_core, &VenomCore::containerCreated,this, &MainWindow::onContainerCreated);
    connect(m_core, &VenomCore::keyGenerated,    this, &MainWindow::onKeyGenerated);
    connect(m_core, &VenomCore::errorOccurred,   this, &MainWindow::onError);
}

void MainWindow::refreshVaultList() {
    m_vaultList->refresh(m_core->mountedContainers(), m_core);
}

void MainWindow::showStatus(const QString& msg, bool isError) {
    m_statusLabel->setText(msg);
    m_statusLabel->setStyleSheet(
        isError
        ? "background:#0e0e18; color:#dc5050; border-top:1px solid #2e2e40; font-size:12px; padding-left:12px;"
        : "background:#0e0e18; color:#50c878; border-top:1px solid #2e2e40; font-size:12px; padding-left:12px;");
}

// ── Slots ─────────────────────────────────────────────────────────────────────

void MainWindow::onMountStarted(const Venom::MountedContainer&) { refreshVaultList(); showStatus("Vault mounted."); }
void MainWindow::onMountGone(const QString& mp)                  { refreshVaultList(); showStatus(QStringLiteral("Unmounted: ") + mp); }
void MainWindow::onMountError(const QString&, const QString& e)  { refreshVaultList(); showStatus(e, true); }
void MainWindow::onContainerCreated(const QString& p)            { showStatus(QStringLiteral("Container created: ") + p); }
void MainWindow::onKeyGenerated(const QString& p)                { showStatus(QStringLiteral("Keypair saved: ") + p); }
void MainWindow::onError(const QString& msg)                     { showStatus(msg, true); }

void MainWindow::openCreateDialog() {
    CreateDialog dlg(m_core, this);
    dlg.exec();
}

void MainWindow::openMountDialog() {
    MountDialog dlg(m_core, this);
    dlg.exec();
}

void MainWindow::openKeyManager() {
    KeyManagerDialog dlg(m_core, this);
    dlg.exec();
}

void MainWindow::unmount(const QString& mp) {
    m_core->unmount(mp);
}

} // namespace Venom

#include "MainWindow.moc"
