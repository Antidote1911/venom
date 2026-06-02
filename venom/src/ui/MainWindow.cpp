#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QDesktopServices>
#include <QUrl>
#include <QMessageBox>
#include <QFileDialog>
#include <QListWidgetItem>
#include <QFile>
#include <QFileInfo>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QDir>

namespace Venom {

// ── Vault card ────────────────────────────────────────────────────────────────

static QWidget* makeVaultCard(const MountedContainer& info, VenomCore* core, QWidget* parent)
{
    auto* card = new QGroupBox(
        info.label.isEmpty() ? QStringLiteral("(unlabelled)") : info.label, parent);

    auto* layout  = new QHBoxLayout(card);
    auto* infoLbl = new QLabel(
        info.vaultPath + QStringLiteral("\n") + info.mountpoint + QStringLiteral("\n") +
        info.cipher + QStringLiteral("  •  ") +
        info.createdAt.toString(QStringLiteral("yyyy-MM-dd")) +
        (info.isHidden ? QStringLiteral("  •  [hidden volume]") : QString{}));
    infoLbl->setWordWrap(true);
    layout->addWidget(infoLbl, 1);

    auto* btnOpen    = new QPushButton(QStringLiteral("Open folder"));
    auto* btnUnmount = new QPushButton(QStringLiteral("Unmount"));

    const QString mp = info.mountpoint;
    QObject::connect(btnOpen,    &QPushButton::clicked, [mp]{ QDesktopServices::openUrl(QUrl::fromLocalFile(mp)); });
    QObject::connect(btnUnmount, &QPushButton::clicked, [core, mp]{ core->unmount(mp); });

    auto* btnBox = new QVBoxLayout;
    btnBox->addWidget(btnOpen);
    btnBox->addWidget(btnUnmount);
    layout->addLayout(btnBox);

    card->setProperty("mountpoint", info.mountpoint);
    return card;
}

// ── MainWindow ────────────────────────────────────────────────────────────────

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_core(new VenomCore(this))
{
    ui->setupUi(this);
    m_vaultLayout = qobject_cast<QVBoxLayout*>(ui->vaultListContainer->layout());

    // ── Menu actions → switch tabs ────────────────────────────────────────────
    connect(ui->actionNew,        &QAction::triggered, this, [this]{ ui->tabWidget->setCurrentIndex(1); });
    connect(ui->actionMount,      &QAction::triggered, this, [this]{ ui->tabWidget->setCurrentIndex(1); });
    connect(ui->actionKeyManager, &QAction::triggered, this, [this]{ ui->tabWidget->setCurrentIndex(2); });

    // ── Tab 2 — Create container ──────────────────────────────────────────────
    connect(ui->btnBrowseCreate, &QPushButton::clicked, this, &MainWindow::browseCreatePath);
    connect(ui->btnCreateContainer, &QPushButton::clicked, this, &MainWindow::onCreateContainer);

    // ── Tab 2 — Mount container ───────────────────────────────────────────────
    connect(ui->btnBrowseVault,      &QPushButton::clicked, this, &MainWindow::browseVaultPath);
    connect(ui->btnBrowseMountpoint, &QPushButton::clicked, this, &MainWindow::browseMountpoint);
    connect(ui->btnBrowseKey,        &QPushButton::clicked, this, &MainWindow::browseKeyFile);
    connect(ui->btnMount,            &QPushButton::clicked, this, &MainWindow::onMount);

    connect(ui->rbMountPassword, &QRadioButton::toggled, this, [this](bool on){
        ui->stackMount->setCurrentIndex(on ? 0 : 1);
    });

    // ── Tab 3 — Key manager ───────────────────────────────────────────────────
    connect(ui->btnGenerate,  &QPushButton::clicked, this, &MainWindow::onGenerateKey);
    connect(ui->btnImportKey, &QPushButton::clicked, this, &MainWindow::onImportKey);
    connect(ui->btnExportPub, &QPushButton::clicked, this, &MainWindow::onExportPub);
    connect(ui->btnDeleteKey, &QPushButton::clicked, this, &MainWindow::onDeleteKey);

    // Enable drag & drop onto the key list
    ui->listKeys->setAcceptDrops(true);
    ui->listKeys->installEventFilter(this);

    // Refresh key lists whenever a relevant tab is shown
    connect(ui->tabWidget, &QTabWidget::currentChanged, this, [this](int idx){
        if (idx == 0) refreshMountKeyList();
        if (idx == 1) refreshCreateKeyList();
        if (idx == 2) refreshKeyList();
    });

    // Mount key list: clicking a local key auto-fills the path field
    connect(ui->listMountKeys, &QListWidget::currentRowChanged, this, [this](int row){
        if (row < 0 || row >= m_keys.size()) return;
        const auto& k = m_keys.at(row);
        if (k.isPubOnly) return; // can't mount with a public-only key
        const QString home = QString::fromLocal8Bit(qgetenv("HOME"));
        const QString path = home + QStringLiteral("/.config/venom/keys/") + k.filename;
        ui->leKeyPath->setText(path);
        ui->leKeyPath->setToolTip(path);
    });

    // ── VenomCore signals ─────────────────────────────────────────────────────
    connect(m_core, &VenomCore::mountStarted,     this, &MainWindow::onMountStarted);
    connect(m_core, &VenomCore::mountGone,        this, &MainWindow::onMountGone);
    connect(m_core, &VenomCore::mountError,       this, &MainWindow::onMountError);
    connect(m_core, &VenomCore::containerCreated, this, &MainWindow::onContainerCreated);
    connect(m_core, &VenomCore::keyGenerated,     this, &MainWindow::onKeyGenerated);
    connect(m_core, &VenomCore::errorOccurred,    this, &MainWindow::onError);

    refreshVaultList();
}

MainWindow::~MainWindow() { delete ui; }

// ── Vault list ────────────────────────────────────────────────────────────────

void MainWindow::refreshVaultList()
{
    ui->lblEmptyState->setVisible(m_core->mountedContainers().isEmpty());
}

void MainWindow::addVaultCard(const MountedContainer& info)
{
    auto* card = makeVaultCard(info, m_core, ui->vaultListContainer);
    m_vaultLayout->insertWidget(m_vaultLayout->count() - 1, card);
    ui->lblEmptyState->setVisible(false);
}

void MainWindow::removeVaultCard(const QString& mountpoint)
{
    for (int i = 0; i < m_vaultLayout->count(); ++i) {
        auto* item = m_vaultLayout->itemAt(i);
        if (!item || !item->widget()) continue;
        if (item->widget()->property("mountpoint").toString() == mountpoint) {
            item->widget()->deleteLater();
            m_vaultLayout->removeItem(item);
            break;
        }
    }
    refreshVaultList();
}

// ── Key lists ─────────────────────────────────────────────────────────────────

static QString keyDisplayText(const KeyEntry& k)
{
    QString prefix;
    if (k.isPubOnly)   prefix = QStringLiteral("[pub]  ");
    else if (k.isProtected) prefix = QStringLiteral("[protected]  ");
    return prefix + k.label + QStringLiteral("  —  ") +
           k.createdAt.toString(QStringLiteral("yyyy-MM-dd"));
}

void MainWindow::refreshKeyList()
{
    m_keys = m_core->localKeys();
    ui->listKeys->clear();
    for (const auto& k : m_keys)
        ui->listKeys->addItem(keyDisplayText(k));
}

void MainWindow::refreshCreateKeyList()
{
    m_keys = m_core->localKeys();
    ui->listCreateKeys->clear();
    for (const auto& k : m_keys)
        ui->listCreateKeys->addItem(keyDisplayText(k));
}

void MainWindow::refreshMountKeyList()
{
    m_keys = m_core->localKeys();
    ui->listMountKeys->clear();
    for (const auto& k : m_keys)
        ui->listMountKeys->addItem(keyDisplayText(k));
}

// ── Drag & drop on key list ───────────────────────────────────────────────────

bool MainWindow::eventFilter(QObject* watched, QEvent* event)
{
    if (watched != ui->listKeys) return QMainWindow::eventFilter(watched, event);

    if (event->type() == QEvent::DragEnter) {
        auto* e = static_cast<QDragEnterEvent*>(event);
        if (e->mimeData()->hasUrls()) {
            for (const QUrl& url : e->mimeData()->urls()) {
                const QString ext = QFileInfo(url.toLocalFile()).suffix().toLower();
                if (ext == QLatin1String("key") || ext == QLatin1String("pub")) {
                    e->acceptProposedAction();
                    return true;
                }
            }
        }
        return true;
    }

    if (event->type() == QEvent::Drop) {
        auto* e = static_cast<QDropEvent*>(event);
        const QString storeDir = QString::fromLocal8Bit(qgetenv("HOME"))
                                 + QStringLiteral("/.config/venom/keys/");
        QDir().mkpath(storeDir);
        bool imported = false;
        for (const QUrl& url : e->mimeData()->urls()) {
            const QString src = url.toLocalFile();
            const QString ext = QFileInfo(src).suffix().toLower();
            if (ext != QLatin1String("key") && ext != QLatin1String("pub")) continue;

            const QString dest = storeDir + QFileInfo(src).fileName();
            if (QFileInfo(src).canonicalFilePath() == QFileInfo(dest).canonicalFilePath()) continue;
            if (QFile::exists(dest)) QFile::remove(dest);
            QFile::copy(src, dest);
            imported = true;
        }
        if (imported) refreshKeyList();
        e->acceptProposedAction();
        return true;
    }

    return QMainWindow::eventFilter(watched, event);
}

// ── Tab 2: Create ─────────────────────────────────────────────────────────────

void MainWindow::browseCreatePath()
{
    const QString p = QFileDialog::getSaveFileName(
        this, tr("Container file"), {}, tr("Venom container (*.vnm)"));
    if (!p.isEmpty())
        ui->lePath->setText(p.endsWith(QLatin1String(".vnm")) ? p : p + QLatin1String(".vnm"));
}

void MainWindow::onCreateContainer()
{
    const QString path = ui->lePath->text().trimmed();
    if (path.isEmpty()) { QMessageBox::warning(this, {}, tr("Enter a container path.")); return; }

    const QString pw  = ui->lePassword->text();
    const QString pw2 = ui->leConfirm->text();
    if (pw != pw2) { QMessageBox::warning(this, {}, tr("Passphrases do not match.")); return; }

    const quint8 cipher = static_cast<quint8>(ui->cbCipher->currentIndex());
    const quint8 kdf    = static_cast<quint8>(ui->cbKdf->currentIndex());

    // Collect selected key recipients
    const QString home = QString::fromLocal8Bit(qgetenv("HOME"));
    QStringList recipientPaths;
    for (auto* item : ui->listCreateKeys->selectedItems()) {
        const int row = ui->listCreateKeys->row(item);
        if (row >= 0 && row < m_keys.size())
            recipientPaths << home + QStringLiteral("/.config/venom/keys/") + m_keys.at(row).filename;
    }

    m_core->createContainer(path, pw, static_cast<quint64>(ui->sbSize->value()),
                            cipher, kdf, ui->leLabel->text().trimmed(), recipientPaths);
}

// ── Tab 2: Mount ──────────────────────────────────────────────────────────────

void MainWindow::browseVaultPath()
{
    const QString p = QFileDialog::getOpenFileName(
        this, tr("Open container"), {}, tr("Venom container (*.vnm);;All files (*)"));
    if (!p.isEmpty()) ui->leVaultPath->setText(p);
}

void MainWindow::browseMountpoint()
{
    const QString p = QFileDialog::getExistingDirectory(this, tr("Select mountpoint"));
    if (!p.isEmpty()) ui->leMountpoint->setText(p);
}

void MainWindow::browseKeyFile()
{
    const QString p = QFileDialog::getOpenFileName(
        this, tr("Select key file"), {}, tr("Venom key (*.key);;All files (*)"));
    if (!p.isEmpty()) ui->leKeyPath->setText(p);
}

void MainWindow::onMount()
{
    const QString vault = ui->leVaultPath->text().trimmed();
    const QString mp    = ui->leMountpoint->text().trimmed();
    if (vault.isEmpty()) { QMessageBox::warning(this, {}, tr("Enter the container path.")); return; }
    if (mp.isEmpty())    { QMessageBox::warning(this, {}, tr("Enter a mountpoint directory.")); return; }

    if (ui->rbMountPassword->isChecked()) {
        m_core->mountWithPassword(vault, mp, ui->leMountPassword->text());
    } else {
        const QString kp = ui->leKeyPath->text().trimmed();
        if (kp.isEmpty()) { QMessageBox::warning(this, {}, tr("Select a .key file.")); return; }
        m_core->mountWithKey(vault, mp, kp, ui->leKeyPassphrase->text());
    }
}

// ── Tab 3: Key manager ────────────────────────────────────────────────────────

void MainWindow::onGenerateKey()
{
    const QString label = ui->leGenLabel->text().trimmed();
    if (label.isEmpty()) { QMessageBox::warning(this, {}, tr("Enter a label for the keypair.")); return; }

    const QString path = QFileDialog::getSaveFileName(
        this, tr("Save keypair"), {}, tr("Venom key (*.key)"));
    if (path.isEmpty()) return;

    const QString fullPath = path.endsWith(QLatin1String(".key")) ? path : path + QLatin1String(".key");
    m_core->generateKey(fullPath, label, ui->leGenPassphrase->text(), ui->chkSensitive->isChecked());
    ui->leGenLabel->clear();
    ui->leGenPassphrase->clear();
}

void MainWindow::onImportKey()
{
    const QString src = QFileDialog::getOpenFileName(
        this, tr("Import keypair"), {}, tr("Venom key (*.key);;All files (*)"));
    if (src.isEmpty()) return;

    const QString home = QString::fromLocal8Bit(qgetenv("HOME"));
    const QString storeDir = home + QStringLiteral("/.config/venom/keys/");
    const QString dest = storeDir + QFileInfo(src).fileName();

    // Create the store directory if it doesn't exist yet
    QDir().mkpath(storeDir);

    // If the file is already in the store, nothing to do
    if (QFileInfo(src).canonicalFilePath() == QFileInfo(dest).canonicalFilePath()) {
        QMessageBox::information(this, {}, tr("This key is already in the store."));
        return;
    }

    // Overwrite if a key with the same filename already exists
    if (QFile::exists(dest))
        QFile::remove(dest);

    if (!QFile::copy(src, dest)) {
        QMessageBox::warning(this, {}, tr("Could not copy the key file to the store.\n%1 → %2")
                             .arg(src, dest));
        return;
    }
    refreshKeyList();
}

void MainWindow::onExportPub()
{
    const int row = ui->listKeys->currentRow();
    if (row < 0 || row >= m_keys.size()) {
        QMessageBox::information(this, {}, tr("Select a key first."));
        return;
    }
    const auto& k = m_keys.at(row);
    const QString dest = QFileDialog::getSaveFileName(
        this, tr("Export public key"), k.label + QStringLiteral(".pub"),
        tr("Venom public key (*.pub)"));
    if (dest.isEmpty()) return;

    const QString dp   = dest.endsWith(QLatin1String(".pub")) ? dest : dest + QLatin1String(".pub");
    const QString home = QString::fromLocal8Bit(qgetenv("HOME"));
    const QString src  = home + QStringLiteral("/.config/venom/keys/") + k.filename;

    if (k.isPubOnly) {
        // Already a public-only file — just copy it to the destination
        if (QFile::exists(dp)) QFile::remove(dp);
        if (!QFile::copy(src, dp))
            QMessageBox::warning(this, {}, tr("Could not copy the public key file.\n%1").arg(src));
    } else {
        // Extract the public part from the .key file via FFI
        m_core->exportPublicKey(src, dp, {});
    }
}

void MainWindow::onDeleteKey()
{
    const int row = ui->listKeys->currentRow();
    if (row < 0 || row >= m_keys.size()) return;
    const auto& k = m_keys.at(row);

    const QString what = k.isPubOnly ? tr("public key") : tr("keypair");
    if (QMessageBox::question(this, {},
            tr("Delete %1 ‘%2’?\nThis cannot be undone.").arg(what, k.label),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;

    const QString home = QString::fromLocal8Bit(qgetenv("HOME"));
    QFile::remove(home + QStringLiteral("/.config/venom/keys/") + k.filename);
    refreshKeyList();
}

// ── VenomCore signal handlers ─────────────────────────────────────────────────

void MainWindow::onMountStarted(const MountedContainer& info)
{
    addVaultCard(info);
    ui->tabWidget->setCurrentIndex(0);
    statusBar()->showMessage(QStringLiteral("Mounted: ") + info.mountpoint, 5000);
}

void MainWindow::onMountGone(const QString& mp)
{
    removeVaultCard(mp);
    statusBar()->showMessage(QStringLiteral("Unmounted: ") + mp, 4000);
}

void MainWindow::onMountError(const QString&, const QString& error)
{
    statusBar()->showMessage(QStringLiteral("Error: ") + error, 8000);
}

void MainWindow::onContainerCreated(const QString& path)
{
    statusBar()->showMessage(QStringLiteral("Container created: ") + path, 5000);
    // Clear create form
    ui->lePath->clear();
    ui->leLabel->clear();
    ui->lePassword->clear();
    ui->leConfirm->clear();
    ui->sbSize->setValue(100);
}

void MainWindow::onKeyGenerated(const QString& path)
{
    statusBar()->showMessage(QStringLiteral("Keypair saved: ") + path, 5000);
    refreshKeyList();
}

void MainWindow::onError(const QString& msg)
{
    statusBar()->showMessage(QStringLiteral("Error: ") + msg, 8000);
    QMessageBox::warning(this, QStringLiteral("Venom"), msg);
}

} // namespace Venom
