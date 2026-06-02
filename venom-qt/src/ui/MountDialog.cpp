#include "MountDialog.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QRadioButton>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QStackedWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QFrame>

namespace Venom {

MountDialog::MountDialog(VenomCore* core, QWidget* parent)
    : QDialog(parent), m_core(core)
{
    setWindowTitle(QStringLiteral("Mount Container"));
    setMinimumSize(540, 440);

    auto* root = new QVBoxLayout(this);
    root->setSpacing(10);
    root->setContentsMargins(24, 20, 24, 20);

    // ── Container file ────────────────────────────────────────────────────────
    auto* lbl1 = new QLabel(QStringLiteral("Container File (.vnm)"));
    lbl1->setStyleSheet("color:#8080a0; font-size:11px; font-weight:bold;");
    root->addWidget(lbl1);

    auto* pathRow = new QHBoxLayout;
    m_vaultPath = new QLineEdit;
    m_vaultPath->setPlaceholderText(QStringLiteral("/home/user/secrets.vnm"));
    auto* btnC = new QPushButton(QStringLiteral("📄 Open…"));
    btnC->setProperty("primary", true);
    pathRow->addWidget(m_vaultPath, 1); pathRow->addWidget(btnC);
    root->addLayout(pathRow);

    // ── Mountpoint ────────────────────────────────────────────────────────────
    auto* lbl2 = new QLabel(QStringLiteral("Mountpoint (empty directory)"));
    lbl2->setStyleSheet("color:#8080a0; font-size:11px;");
    root->addWidget(lbl2);

    auto* mpRow = new QHBoxLayout;
    m_mountpoint = new QLineEdit;
    m_mountpoint->setPlaceholderText(QStringLiteral("/mnt/vault"));
    auto* btnM = new QPushButton(QStringLiteral("📁 Folder…"));
    mpRow->addWidget(m_mountpoint, 1); mpRow->addWidget(btnM);
    root->addLayout(mpRow);

    // ── Credential ────────────────────────────────────────────────────────────
    auto* sep1 = new QFrame; sep1->setFrameShape(QFrame::HLine);
    sep1->setStyleSheet("color:#2e2e40;"); root->addWidget(sep1);

    m_credGroup = new QButtonGroup(this);
    auto* credRow = new QHBoxLayout;
    auto* rPw  = new QRadioButton(QStringLiteral("🔒  Passphrase"));
    auto* rKey = new QRadioButton(QStringLiteral("🔑  Private Key"));
    rPw->setChecked(true);
    m_credGroup->addButton(rPw,  0);
    m_credGroup->addButton(rKey, 1);
    credRow->addWidget(rPw); credRow->addWidget(rKey); credRow->addStretch();
    root->addLayout(credRow);

    // Password panel
    m_pwPanel = new QWidget;
    auto* pwLayout = new QVBoxLayout(m_pwPanel);
    pwLayout->setContentsMargins(0, 0, 0, 0);
    m_password = new QLineEdit;
    m_password->setEchoMode(QLineEdit::Password);
    m_password->setPlaceholderText(QStringLiteral("Passphrase (outer or hidden volume)"));
    pwLayout->addWidget(m_password);
    root->addWidget(m_pwPanel);

    // Key panel
    m_keyPanel = new QWidget;
    m_keyPanel->setVisible(false);
    auto* keyLayout = new QVBoxLayout(m_keyPanel);
    keyLayout->setContentsMargins(0, 0, 0, 0);
    keyLayout->setSpacing(6);

    m_keys = m_core->localKeys();
    if (!m_keys.isEmpty()) {
        auto* klbl = new QLabel(QStringLiteral("Select from store:"));
        klbl->setStyleSheet("color:#8080a0; font-size:11px;");
        keyLayout->addWidget(klbl);
        m_keyList = new QListWidget;
        m_keyList->setMaximumHeight(100);
        m_keyList->setStyleSheet(
            "QListWidget { background:#1a1a28; border:1px solid #373746; border-radius:5px; }"
            "QListWidget::item:selected { background:#3778d2; }"
            "QListWidget::item { color:#dcdce6; padding:4px; }");
        for (const auto& k : m_keys) {
            const QString ico = k.isProtected ? QStringLiteral("🔒🔑 ") : QStringLiteral("🔑 ");
            auto* item = new QListWidgetItem(ico + k.label + QStringLiteral("  ") + k.fingerprint);
            m_keyList->addItem(item);
        }
        keyLayout->addWidget(m_keyList);
    } else {
        m_keyList = nullptr;
        auto* noKeys = new QLabel(QStringLiteral(
            "No keypairs in local store.\nGenerate or import a .key file via the Key Manager."));
        noKeys->setStyleSheet("color:#f0be3c;");
        keyLayout->addWidget(noKeys);
    }

    auto* kpRow = new QHBoxLayout;
    m_keyPath = new QLineEdit;
    m_keyPath->setPlaceholderText(QStringLiteral("Or browse for a .key file…"));
    auto* btnK = new QPushButton(QStringLiteral("Browse…"));
    kpRow->addWidget(m_keyPath, 1); kpRow->addWidget(btnK);
    keyLayout->addLayout(kpRow);

    m_keyPw = new QLineEdit;
    m_keyPw->setEchoMode(QLineEdit::Password);
    m_keyPw->setPlaceholderText(QStringLiteral("Key passphrase (if protected)"));
    keyLayout->addWidget(m_keyPw);

    root->addWidget(m_keyPanel);
    root->addStretch();

    // ── Buttons ───────────────────────────────────────────────────────────────
    auto* sep2 = new QFrame; sep2->setFrameShape(QFrame::HLine);
    sep2->setStyleSheet("color:#2e2e40;"); root->addWidget(sep2);

    auto* buttons = new QDialogButtonBox;
    auto* btnOk = buttons->addButton(QStringLiteral("⛰  Mount"), QDialogButtonBox::AcceptRole);
    btnOk->setProperty("primary", true);
    buttons->addButton(QDialogButtonBox::Cancel);
    root->addWidget(buttons);

    connect(btnC,      &QPushButton::clicked,  this, &MountDialog::onBrowseContainer);
    connect(btnM,      &QPushButton::clicked,  this, &MountDialog::onBrowseMountpoint);
    connect(btnK,      &QPushButton::clicked,  this, &MountDialog::onBrowseKey);
    connect(buttons,   &QDialogButtonBox::accepted, this, &MountDialog::onAccepted);
    connect(buttons,   &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_credGroup, &QButtonGroup::idClicked, this, [this](int){ onCredentialToggled(); });
}

void MountDialog::onCredentialToggled() {
    const bool useKey = m_credGroup->checkedId() == 1;
    m_pwPanel->setVisible(!useKey);
    m_keyPanel->setVisible(useKey);
}

void MountDialog::onBrowseContainer() {
    const QString f = QFileDialog::getOpenFileName(this,
        QStringLiteral("Select container"), {},
        QStringLiteral("Venom container (*.vnm);;All files (*)"));
    if (!f.isEmpty()) m_vaultPath->setText(f);
}

void MountDialog::onBrowseMountpoint() {
    const QString d = QFileDialog::getExistingDirectory(this,
        QStringLiteral("Select mountpoint directory"));
    if (!d.isEmpty()) m_mountpoint->setText(d);
}

void MountDialog::onBrowseKey() {
    const QString f = QFileDialog::getOpenFileName(this,
        QStringLiteral("Select private key"), {},
        QStringLiteral("Venom key (*.key);;All files (*)"));
    if (!f.isEmpty()) m_keyPath->setText(f);
}

void MountDialog::onAccepted() {
    const QString vp = m_vaultPath->text().trimmed();
    const QString mp = m_mountpoint->text().trimmed();
    if (vp.isEmpty() || mp.isEmpty()) {
        QMessageBox::warning(this, {}, QStringLiteral("Container path and mountpoint are required."));
        return;
    }

    if (m_credGroup->checkedId() == 0) {
        // Password mode
        m_core->mountWithPassword(vp, mp, m_password->text());
    } else {
        // Key mode
        QString kp = m_keyPath->text().trimmed();
        if (kp.isEmpty() && m_keyList && m_keyList->currentRow() >= 0) {
            // Use selected store key — look up path from fingerprint
            const auto& entry = m_keys.at(m_keyList->currentRow());
            const QString home = QString::fromLocal8Bit(qgetenv("HOME"));
            kp = home + QStringLiteral("/.config/venom/keys/")
                      + entry.fingerprint.toLower().remove(QStringLiteral(":"))
                      + QStringLiteral(".key");
        }
        if (kp.isEmpty()) {
            QMessageBox::warning(this, {}, QStringLiteral("Select a keypair or browse for a .key file."));
            return;
        }
        m_core->mountWithKey(vp, mp, kp, m_keyPw->text());
    }
    accept();
}

} // namespace Venom
