#include "KeyManagerDialog.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QGroupBox>
#include <QFrame>

namespace Venom {

KeyManagerDialog::KeyManagerDialog(VenomCore* core, QWidget* parent)
    : QDialog(parent), m_core(core)
{
    setWindowTitle(QStringLiteral("🗝  Key Manager"));
    setMinimumSize(640, 540);

    auto* root = new QHBoxLayout(this);
    root->setContentsMargins(20, 16, 20, 16);
    root->setSpacing(16);

    // ── Left: key list ────────────────────────────────────────────────────────
    auto* leftCol = new QVBoxLayout;
    auto* lbl1 = new QLabel(QStringLiteral("My Keypairs  (X25519 + ML-KEM-1024)"));
    lbl1->setStyleSheet("color:#8080a0; font-size:11px; font-weight:bold;");
    leftCol->addWidget(lbl1);

    m_keyList = new QListWidget;
    m_keyList->setStyleSheet(
        "QListWidget { background:#0e0e1a; border:1px solid #2e2e40; border-radius:6px; }"
        "QListWidget::item { color:#dcdce6; padding:8px; border-bottom:1px solid #1e1e2c; }"
        "QListWidget::item:selected { background:#192840; color:#5ab0ff; }");
    leftCol->addWidget(m_keyList, 1);

    auto* listBtns = new QHBoxLayout;
    auto* btnExport = new QPushButton(QStringLiteral("📤 Export .pub"));
    auto* btnDelete = new QPushButton(QStringLiteral("Delete"));
    btnDelete->setStyleSheet(
        "background:#6e2020; color:white; border:1px solid #a04040; "
        "border-radius:5px; padding:4px 10px;");
    listBtns->addWidget(btnExport); listBtns->addStretch(); listBtns->addWidget(btnDelete);
    leftCol->addLayout(listBtns);

    auto* btnImport = new QPushButton(QStringLiteral("📥 Import .key file"));
    btnImport->setFixedHeight(30);
    leftCol->addWidget(btnImport);

    root->addLayout(leftCol, 3);

    // ── Right: generate ───────────────────────────────────────────────────────
    auto* sep = new QFrame; sep->setFrameShape(QFrame::VLine);
    sep->setStyleSheet("color:#2e2e40;"); root->addWidget(sep);

    auto* rightCol = new QVBoxLayout;
    rightCol->setSpacing(8);
    auto* lbl2 = new QLabel(QStringLiteral("Generate New Keypair"));
    lbl2->setStyleSheet("color:#8080a0; font-size:11px; font-weight:bold;");
    rightCol->addWidget(lbl2);

    auto* info = new QLabel(
        QStringLiteral("Algorithm: X25519 (classical)\n+ ML-KEM-1024 (FIPS 203)\n\n"
                        "Both keys are independent.\nSecurity holds if only one is broken."));
    info->setStyleSheet("color:#606080; font-size:11px;");
    rightCol->addWidget(info);

    auto* sep2 = new QFrame; sep2->setFrameShape(QFrame::HLine);
    sep2->setStyleSheet("color:#2e2e40;"); rightCol->addWidget(sep2);

    auto* lbl3 = new QLabel(QStringLiteral("Label"));
    lbl3->setStyleSheet("color:#8080a0; font-size:11px;");
    m_labelEdit = new QLineEdit;
    m_labelEdit->setPlaceholderText(QStringLiteral("My key / Work / Personal…"));
    rightCol->addWidget(lbl3); rightCol->addWidget(m_labelEdit);

    auto* lbl4 = new QLabel(QStringLiteral("Passphrase  (optional)"));
    lbl4->setStyleSheet("color:#8080a0; font-size:11px;");
    m_passphraseEdit = new QLineEdit;
    m_passphraseEdit->setEchoMode(QLineEdit::Password);
    m_passphraseEdit->setPlaceholderText(QStringLiteral("Leave empty for no protection"));
    rightCol->addWidget(lbl4); rightCol->addWidget(m_passphraseEdit);

    m_sensitiveCheck = new QCheckBox(QStringLiteral("Sensitive profile (256 MiB / 4 passes)"));
    rightCol->addWidget(m_sensitiveCheck);

    auto* btnGen = new QPushButton(QStringLiteral("⚡  Generate keypair"));
    btnGen->setProperty("primary", true);
    btnGen->setFixedHeight(34);
    rightCol->addWidget(btnGen);
    rightCol->addStretch();

    auto* btnClose = new QPushButton(QStringLiteral("Close"));
    rightCol->addWidget(btnClose);

    root->addLayout(rightCol, 2);

    // ── Signals ───────────────────────────────────────────────────────────────
    connect(btnGen,    &QPushButton::clicked, this, &KeyManagerDialog::onGenerate);
    connect(btnImport, &QPushButton::clicked, this, &KeyManagerDialog::onImport);
    connect(btnExport, &QPushButton::clicked, this, &KeyManagerDialog::onExportPub);
    connect(btnDelete, &QPushButton::clicked, this, &KeyManagerDialog::onDelete);
    connect(btnClose,  &QPushButton::clicked, this, &QDialog::accept);

    onRefresh();
}

void KeyManagerDialog::onRefresh() {
    m_keys = m_core->localKeys();
    m_keyList->clear();
    for (const auto& k : m_keys) {
        const QString ico = k.isProtected ? QStringLiteral("🔒🔑  ") : QStringLiteral("🔑  ");
        const QString text = ico + k.label + QStringLiteral("\n    ")
                           + k.fingerprint + QStringLiteral("   ")
                           + k.createdAt.toString(QStringLiteral("yyyy-MM-dd"));
        auto* item = new QListWidgetItem(text);
        m_keyList->addItem(item);
    }
}

void KeyManagerDialog::onGenerate() {
    const QString label = m_labelEdit->text().trimmed();
    if (label.isEmpty()) {
        QMessageBox::warning(this, {}, QStringLiteral("Enter a label."));
        return;
    }
    const QString savePath = QFileDialog::getSaveFileName(this,
        QStringLiteral("Save keypair as"), {},
        QStringLiteral("Venom key (*.key)"));
    if (savePath.isEmpty()) return;

    const QString path = savePath.endsWith(QStringLiteral(".key")) ? savePath : savePath + QStringLiteral(".key");
    m_core->generateKey(path, label, m_passphraseEdit->text(), m_sensitiveCheck->isChecked());
    m_labelEdit->clear(); m_passphraseEdit->clear();
    onRefresh();
}

void KeyManagerDialog::onImport() {
    const QString path = QFileDialog::getOpenFileName(this,
        QStringLiteral("Import keypair"), {},
        QStringLiteral("Venom key (*.key);;All files (*)"));
    if (path.isEmpty()) return;
    // Copy to key store
    const QString home = QString::fromLocal8Bit(qgetenv("HOME"));
    const QString storeDir = home + QStringLiteral("/.config/venom/keys/");
    QFileInfo fi(path);
    QFile::copy(path, storeDir + fi.fileName());
    onRefresh();
}

void KeyManagerDialog::onExportPub() {
    const int row = m_keyList->currentRow();
    if (row < 0 || row >= m_keys.size()) {
        QMessageBox::information(this, {}, QStringLiteral("Select a keypair first."));
        return;
    }
    const auto& k = m_keys.at(row);
    const QString dest = QFileDialog::getSaveFileName(this,
        QStringLiteral("Export public key"), k.label + QStringLiteral(".pub"),
        QStringLiteral("Venom public key (*.pub)"));
    if (dest.isEmpty()) return;

    const QString home = QString::fromLocal8Bit(qgetenv("HOME"));
    const QString fp   = k.fingerprint.toLower().remove(QStringLiteral(":"));
    const QString keyPath = home + QStringLiteral("/.config/venom/keys/") + fp + QStringLiteral(".key");
    m_core->exportPublicKey(keyPath, dest.endsWith(QStringLiteral(".pub")) ? dest : dest + QStringLiteral(".pub"), {});
}

void KeyManagerDialog::onDelete() {
    const int row = m_keyList->currentRow();
    if (row < 0 || row >= m_keys.size()) return;
    const auto& k = m_keys.at(row);
    if (QMessageBox::question(this, {},
        QStringLiteral("Delete keypair '") + k.label + QStringLiteral("'?\nThis cannot be undone."),
        QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;

    const QString home = QString::fromLocal8Bit(qgetenv("HOME"));
    const QString fp   = k.fingerprint.toLower().remove(QStringLiteral(":"));
    QFile::remove(home + QStringLiteral("/.config/venom/keys/") + fp + QStringLiteral(".key"));
    onRefresh();
}

} // namespace Venom
