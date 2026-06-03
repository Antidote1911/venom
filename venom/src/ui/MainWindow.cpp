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
#include <QStandardPaths>
#include <QStorageInfo>

namespace Venom {

// ── Helpers ───────────────────────────────────────────────────────────────────

static QString formatFileSize(qint64 bytes)
{
    if (bytes >= 1024LL * 1024 * 1024)
        return QStringLiteral("%1 GB").arg(bytes / (1024.0 * 1024 * 1024), 0, 'f', 1);
    if (bytes >= 1024 * 1024)
        return QStringLiteral("%1 MB").arg(bytes / (1024.0 * 1024), 0, 'f', 1);
    return QStringLiteral("%1 KB").arg(bytes / 1024.0, 0, 'f', 0);
}

/// Returns a list of (keyFilePath, driveDisplayName) found on removable/external volumes.
/// Scans <root>/venom/ then <root>/ for *.key files.
static QList<QPair<QString,QString>> scanUsbKeyFiles()
{
    const QStringList skipPrefixes = {
        QStringLiteral("/sys"), QStringLiteral("/proc"), QStringLiteral("/dev"),
        QStringLiteral("/run/user"), QStringLiteral("/boot"), QStringLiteral("/snap"),
        QStringLiteral("/tmp"),  QStringLiteral("/var"),
    };

    QList<QPair<QString,QString>> result;
    for (const QStorageInfo& vol : QStorageInfo::mountedVolumes()) {
        if (!vol.isValid() || !vol.isReady()) continue;
        const QString root = vol.rootPath();
        if (root == QLatin1String("/")) continue;
        bool skip = false;
        for (const QString& p : skipPrefixes) { if (root.startsWith(p)) { skip = true; break; } }
        if (skip) continue;

        const QString name = vol.displayName().isEmpty()
            ? QFileInfo(root).fileName()
            : vol.displayName();

        // Prefer venom/ subfolder, fall back to root
        const QDir venomDir(root + QStringLiteral("/venom"));
        const QDir scanDir = venomDir.exists() ? venomDir : QDir(root);
        for (const QFileInfo& fi : scanDir.entryInfoList({QStringLiteral("*.key")}, QDir::Files))
            result << qMakePair(fi.absoluteFilePath(), name);
    }
    return result;
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
    // Default containers directory: ~/Documents/venom/ (or ~/ as fallback)
    {
        QString docs = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
        if (docs.isEmpty()) docs = QDir::homePath();
        const QString defaultDir = docs + QStringLiteral("/venom/");
        ui->lePath->setText(defaultDir + QStringLiteral("vault.vnm"));

        // Live-update the path when the label changes (until user picks a custom path)
        connect(ui->leLabel, &QLineEdit::textChanged, this, [this, defaultDir](const QString& text) {
            if (m_containerPathManual) return;
            QString name = text.trimmed();
            for (QChar& c : name)
                if (!c.isLetterOrNumber() && c != '-') c = '_';
            if (name.isEmpty()) name = QStringLiteral("vault");
            ui->lePath->setText(defaultDir + name + QStringLiteral(".vnm"));
        });
    }
    connect(ui->btnBrowseCreate, &QPushButton::clicked, this, &MainWindow::browseCreatePath);
    connect(ui->btnCreateContainer, &QPushButton::clicked, this, &MainWindow::onCreateContainer);

    // Key-only warning: shown when password is empty and at least one key recipient is selected
    auto updateKeyOnlyWarning = [this]() {
        const bool keyOnly = ui->lePassword->text().isEmpty()
                          && !ui->listCreateKeys->selectedItems().isEmpty();
        ui->lblKeyOnlyWarning->setVisible(keyOnly);
    };
    connect(ui->lePassword,        &QLineEdit::textChanged,          this, updateKeyOnlyWarning);
    connect(ui->listCreateKeys,    &QListWidget::itemSelectionChanged, this, updateKeyOnlyWarning);

    // ── Tab 2 — Mount container ───────────────────────────────────────────────
    connect(ui->btnBrowseVault,      &QPushButton::clicked, this, &MainWindow::browseVaultPath);
    connect(ui->btnBrowseMountpoint, &QPushButton::clicked, this, &MainWindow::browseMountpoint);

    // Auto-fill mountpoint from vault filename when not manually overridden
    connect(ui->leVaultPath, &QLineEdit::textChanged, this, [this](const QString& vaultPath) {
        if (m_mountpointManual) return;
        const QString stem = QFileInfo(vaultPath.trimmed()).completeBaseName();
        if (stem.isEmpty()) return;
        const QString base = QDir::homePath() + QStringLiteral("/mnt/venom/");
        ui->leMountpoint->setText(base + stem);
    });
    connect(ui->btnBrowseKey,        &QPushButton::clicked, this, &MainWindow::browseKeyFile);
    connect(ui->btnMount,            &QPushButton::clicked, this, &MainWindow::onMount);

    connect(ui->rbMountPassword, &QRadioButton::toggled, this, [this](bool on){
        ui->stackMount->setCurrentIndex(on ? 0 : 1);
    });

    // USB refresh button in mount key section
    connect(ui->btnRefreshUsb, &QPushButton::clicked, this, &MainWindow::refreshMountKeyList);

    // ── Tab 3 — Key manager ───────────────────────────────────────────────────
    connect(ui->btnGenerate,  &QPushButton::clicked, this, &MainWindow::onGenerateKey);
    connect(ui->btnImportKey, &QPushButton::clicked, this, &MainWindow::onImportKey);
    connect(ui->btnExportPub, &QPushButton::clicked, this, &MainWindow::onExportPub);
    connect(ui->btnDeleteKey, &QPushButton::clicked, this, &MainWindow::onDeleteKey);

    // Enable drag & drop onto the key list
    ui->listKeys->setAcceptDrops(true);
    ui->listKeys->installEventFilter(this);

    // Refresh lists whenever a relevant tab is shown
    connect(ui->tabWidget, &QTabWidget::currentChanged, this, [this](int idx){
        if (idx == 0) { refreshUnifiedVaultList(); refreshMountKeyList(); }
        if (idx == 1) refreshCreateKeyList();
        if (idx == 2) { refreshKeyList(); refreshKeyDestCombo(); }
    });

    // When a local key is selected, clear the external path field to avoid ambiguity
    connect(ui->listMountKeys, &QListWidget::currentRowChanged, this, [this](int row){
        if (row >= 0 && ui->listMountKeys->item(row))
            ui->leKeyPath->clear();
    });

    // ── VenomCore signals ─────────────────────────────────────────────────────
    connect(m_core, &VenomCore::mountStarted,     this, &MainWindow::onMountStarted);
    connect(m_core, &VenomCore::mountGone,        this, &MainWindow::onMountGone);
    connect(m_core, &VenomCore::mountError,       this, &MainWindow::onMountError);
    connect(m_core, &VenomCore::containerCreated, this, &MainWindow::onContainerCreated);
    connect(m_core, &VenomCore::keyGenerated,     this, &MainWindow::onKeyGenerated);
    connect(m_core, &VenomCore::errorOccurred,    this, &MainWindow::onError);

    refreshUnifiedVaultList();
    refreshKeyDestCombo();
}

MainWindow::~MainWindow() { delete ui; }

// ── Unified vault list ────────────────────────────────────────────────────────

void MainWindow::refreshUnifiedVaultList()
{
    // Delete only the dynamically created cards — never touch permanent UI widgets
    for (QWidget* card : std::as_const(m_vaultCards)) {
        m_vaultLayout->removeWidget(card);
        delete card;
    }
    m_vaultCards.clear();

    // Mounted containers (any directory)
    const QList<MountedContainer> mounted = m_core->mountedContainers();
    QStringList seenPaths;
    int insertPos = 0;
    for (const auto& mc : mounted) {
        seenPaths << QFileInfo(mc.vaultPath).canonicalFilePath();
        QWidget* card = makeMountedCard(mc);
        m_vaultCards << card;
        m_vaultLayout->insertWidget(insertPos++, card);
    }

    // Unmounted containers from default directory
    QString docs = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (docs.isEmpty()) docs = QDir::homePath();
    const QDir dir(docs + QStringLiteral("/venom/"));
    const auto entries = dir.entryInfoList({QStringLiteral("*.vnm")}, QDir::Files, QDir::Name);
    for (const auto& fi : entries) {
        if (seenPaths.contains(fi.canonicalFilePath())) continue;
        QWidget* card = makeUnmountedCard(fi);
        m_vaultCards << card;
        m_vaultLayout->insertWidget(insertPos++, card);
    }

    ui->lblEmptyState->setVisible(m_vaultCards.isEmpty());
}

QWidget* MainWindow::makeMountedCard(const MountedContainer& mc)
{
    auto* card   = new QGroupBox(ui->vaultListContainer);
    auto* layout = new QHBoxLayout(card);

    // Info column
    auto* info   = new QVBoxLayout;
    const qint64 sz = QFileInfo(mc.vaultPath).size();

    auto* row1 = new QLabel(
        QStringLiteral("<b>%1</b>").arg(QFileInfo(mc.vaultPath).fileName()) +
        QStringLiteral("&nbsp;&nbsp;<span style='color:#27ae60'>● Mounted</span>"));
    row1->setTextFormat(Qt::RichText);

    auto* row2 = new QLabel(mc.vaultPath + QStringLiteral("  •  ") + formatFileSize(sz));
    row2->setWordWrap(true);

    QString meta = mc.cipher;
    if (!mc.label.isEmpty())   meta.prepend(mc.label + QStringLiteral("  •  "));
    if (mc.isHidden)           meta += QStringLiteral("  •  [hidden]");
    meta += QStringLiteral("  •  ") + mc.createdAt.toString(QStringLiteral("yyyy-MM-dd"));
    auto* row3 = new QLabel(meta);
    row3->setStyleSheet(QStringLiteral("color: gray; font-size: 11px;"));

    info->addWidget(row1);
    info->addWidget(row2);
    info->addWidget(row3);
    layout->addLayout(info, 1);

    // Buttons column
    auto* btnOpen    = new QPushButton(QStringLiteral("Open folder"));
    auto* btnUnmount = new QPushButton(QStringLiteral("Unmount"));
    const QString mp = mc.mountpoint;
    QObject::connect(btnOpen,    &QPushButton::clicked, [mp]{ QDesktopServices::openUrl(QUrl::fromLocalFile(mp)); });
    QObject::connect(btnUnmount, &QPushButton::clicked, [this, mp]{ m_core->unmount(mp); });
    auto* btns = new QVBoxLayout;
    btns->addWidget(btnOpen);
    btns->addWidget(btnUnmount);
    layout->addLayout(btns);

    return card;
}

QWidget* MainWindow::makeUnmountedCard(const QFileInfo& fi)
{
    auto* card   = new QGroupBox(ui->vaultListContainer);
    auto* layout = new QHBoxLayout(card);

    // Info column
    auto* info = new QVBoxLayout;

    auto* row1 = new QLabel(
        QStringLiteral("<b>%1</b>").arg(fi.fileName()) +
        QStringLiteral("&nbsp;&nbsp;<span style='color:#7f8c8d'>○ Not mounted</span>"));
    row1->setTextFormat(Qt::RichText);

    auto* row2 = new QLabel(fi.absoluteFilePath() + QStringLiteral("  •  ") + formatFileSize(fi.size()));
    row2->setWordWrap(true);

    info->addWidget(row1);
    info->addWidget(row2);
    layout->addLayout(info, 1);

    // Mount button
    auto* btnMount = new QPushButton(QStringLiteral("Mount"));
    const QString path = fi.absoluteFilePath();
    QObject::connect(btnMount, &QPushButton::clicked, [this, path]{
        ui->leVaultPath->setText(path);
    });
    layout->addWidget(btnMount, 0, Qt::AlignTop);

    return card;
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

static QListWidgetItem* makeSeparatorItem(const QString& text)
{
    auto* sep = new QListWidgetItem(text);
    sep->setFlags(Qt::NoItemFlags);
    QFont f = sep->font();
    f.setBold(true);
    sep->setFont(f);
    sep->setForeground(Qt::gray);
    return sep;
}

void MainWindow::refreshMountKeyList()
{
    m_keys = m_core->localKeys();
    ui->listMountKeys->clear();
    const QString home = QString::fromLocal8Bit(qgetenv("HOME"));

    // ── Local private keys ────────────────────────────────────────────────────
    bool hasLocal = false;
    for (const auto& k : m_keys) {
        if (k.isPubOnly) continue;
        if (!hasLocal) {
            ui->listMountKeys->addItem(makeSeparatorItem(QStringLiteral("── Local keys ──")));
            hasLocal = true;
        }
        auto* item = new QListWidgetItem(keyDisplayText(k));
        item->setData(Qt::UserRole, home + QStringLiteral("/.config/venom/keys/") + k.filename);
        ui->listMountKeys->addItem(item);
    }

    // ── USB keys ──────────────────────────────────────────────────────────────
    const auto usbKeys = scanUsbKeyFiles();
    bool hasUsb = false;
    for (const auto& [path, drive] : usbKeys) {
        if (!hasUsb) {
            ui->listMountKeys->addItem(
                makeSeparatorItem(QStringLiteral("── USB: ") + drive + QStringLiteral(" ──")));
            hasUsb = true;
        }

        // Read label and fingerprint from the key file
        VnmKeyInfo info{};
        QString displayText;
        if (vnm_key_read_info(path.toUtf8().constData(), &info)) {
            const QString label = QString::fromUtf8(
                reinterpret_cast<const char*>(info.label));
            const QString fp = QString::fromLatin1(
                reinterpret_cast<const char*>(info.fingerprint));
            displayText = (label.isEmpty() ? QFileInfo(path).baseName() : label)
                        + QStringLiteral("  —  ") + fp;
        } else {
            displayText = QFileInfo(path).fileName(); // fallback: filename only
        }

        auto* item = new QListWidgetItem(displayText);
        item->setData(Qt::UserRole, path);
        item->setToolTip(path);
        item->setForeground(QColor(QStringLiteral("#2980b9")));
        ui->listMountKeys->addItem(item);
    }

    // Show hint when no USB keys detected
    ui->lblInsertUsb->setVisible(!hasUsb);
}

void MainWindow::refreshKeyDestCombo()
{
    ui->cbKeyDest->clear();
    ui->cbKeyDest->addItem(
        QStringLiteral("Local store (~/.config/venom/keys/)"),
        QStringLiteral("local"));

    for (const QStorageInfo& vol : QStorageInfo::mountedVolumes()) {
        if (!vol.isValid() || !vol.isReady()) continue;
        const QString root = vol.rootPath();
        if (root == QLatin1String("/")) continue;
        const QStringList skip = {
            QStringLiteral("/sys"), QStringLiteral("/proc"), QStringLiteral("/dev"),
            QStringLiteral("/run/user"), QStringLiteral("/boot"), QStringLiteral("/snap"),
            QStringLiteral("/tmp"), QStringLiteral("/var"),
        };
        bool shouldSkip = false;
        for (const QString& p : skip) { if (root.startsWith(p)) { shouldSkip = true; break; } }
        if (shouldSkip) continue;
        const QString name = vol.displayName().isEmpty()
            ? QFileInfo(root).fileName() : vol.displayName();
        const QString usbVenomDir = root + QStringLiteral("/venom");
        ui->cbKeyDest->addItem(
            QStringLiteral("USB: ") + name + QStringLiteral(" (") + root + QStringLiteral("/venom/)"),
            usbVenomDir);
    }
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
        this, tr("Container file"), ui->lePath->text(), tr("Venom container (*.vnm)"));
    if (!p.isEmpty()) {
        ui->lePath->setText(p.endsWith(QLatin1String(".vnm")) ? p : p + QLatin1String(".vnm"));
        m_containerPathManual = true;
    }
}

void MainWindow::onCreateContainer()
{
    const QString path = ui->lePath->text().trimmed();
    if (path.isEmpty()) { QMessageBox::warning(this, {}, tr("Enter a container path.")); return; }

    // Ensure parent directory exists
    QDir().mkpath(QFileInfo(path).absolutePath());

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
    if (!p.isEmpty()) {
        ui->leMountpoint->setText(p);
        m_mountpointManual = true;
    }
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

    // Create mountpoint directory if it doesn't exist yet
    QDir().mkpath(mp);

    if (ui->rbMountPassword->isChecked()) {
        m_core->mountWithPassword(vault, mp, ui->leMountPassword->text());
    } else {
        // Priority: selected key from the local store (path in UserRole), then external path
        QString kp;
        const int row = ui->listMountKeys->currentRow();
        if (row >= 0 && ui->listMountKeys->item(row))
            kp = ui->listMountKeys->item(row)->data(Qt::UserRole).toString();
        if (kp.isEmpty())
            kp = ui->leKeyPath->text().trimmed();
        if (kp.isEmpty()) {
            QMessageBox::warning(this, {}, tr("Select a key from the list or browse for a .key file."));
            return;
        }
        m_core->mountWithKey(vault, mp, kp, ui->leKeyPassphrase->text());
    }
}

// ── Tab 3: Key manager ────────────────────────────────────────────────────────

void MainWindow::onGenerateKey()
{
    const QString label = ui->leGenLabel->text().trimmed();
    if (label.isEmpty()) { QMessageBox::warning(this, {}, tr("Enter a label for the keypair.")); return; }

    const QString dest = ui->cbKeyDest->currentData().toString();
    if (dest == QStringLiteral("local") || dest.isEmpty()) {
        m_core->generateKey(label, ui->leGenPassphrase->text(), ui->chkSensitive->isChecked());
    } else {
        // Save directly to USB drive's venom/ directory — never touches local store
        m_core->generateKeyToDir(dest, label, ui->leGenPassphrase->text(), ui->chkSensitive->isChecked());
    }
    ui->leGenLabel->clear();
    ui->leGenPassphrase->clear();
}

void MainWindow::onImportKey()
{
    const QString src = QFileDialog::getOpenFileName(
        this, tr("Import key"), {},
        tr("Venom keys (*.key *.pub);;Keypair (*.key);;Public key (*.pub);;All files (*)"));
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
    refreshUnifiedVaultList();
    ui->tabWidget->setCurrentIndex(0);
    statusBar()->showMessage(QStringLiteral("Mounted: ") + info.mountpoint, 5000);
}

void MainWindow::onMountGone(const QString& mp)
{
    statusBar()->showMessage(QStringLiteral("Unmounted: ") + mp, 4000);
    refreshUnifiedVaultList();
    // Reset mount form fields so the next vault auto-fills the mountpoint
    m_mountpointManual = false;
    ui->leVaultPath->clear();
    ui->leMountpoint->clear();
}

void MainWindow::onMountError(const QString&, const QString& error)
{
    statusBar()->showMessage(QStringLiteral("Error: ") + error, 8000);
}

void MainWindow::onContainerCreated(const QString& path)
{
    statusBar()->showMessage(QStringLiteral("Container created: ") + path, 5000);
    refreshUnifiedVaultList();
    // Clear create form and reset path to auto-mode for next container
    m_containerPathManual = false;
    ui->leLabel->clear();  // triggers textChanged → resets lePath to default
    ui->lePassword->clear();
    ui->leConfirm->clear();
    ui->sbSize->setValue(100);
}

void MainWindow::onKeyGenerated(const QString& path)
{
    statusBar()->showMessage(QStringLiteral("Keypair saved: ") + path, 5000);
    refreshKeyList();
    refreshMountKeyList(); // USB keys may have changed
}

void MainWindow::onError(const QString& msg)
{
    statusBar()->showMessage(QStringLiteral("Error: ") + msg, 8000);
    QMessageBox::warning(this, QStringLiteral("Venom"), msg);
}

} // namespace Venom
