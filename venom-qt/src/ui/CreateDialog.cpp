#include "CreateDialog.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QLabel>
#include <QPushButton>
#include <QRadioButton>
#include <QMessageBox>
#include <QFrame>

namespace Venom {

CreateDialog::CreateDialog(VenomCore* core, QWidget* parent)
    : QDialog(parent), m_core(core)
{
    setWindowTitle(QStringLiteral("New Container"));
    setMinimumSize(580, 480);

    auto* root = new QVBoxLayout(this);
    root->setSpacing(12);
    root->setContentsMargins(24, 20, 24, 20);

    // ── Container path ────────────────────────────────────────────────────────
    auto* sectionPath = new QLabel(QStringLiteral("Container File"));
    sectionPath->setStyleSheet("color:#8080a0; font-size:11px; font-weight:bold;");
    root->addWidget(sectionPath);

    auto* pathRow = new QHBoxLayout;
    m_path = new QLineEdit;
    m_path->setPlaceholderText(QStringLiteral("/home/user/secrets.vnm"));
    auto* btnBrowse = new QPushButton(QStringLiteral("💾 Save as…"));
    btnBrowse->setProperty("primary", true);
    pathRow->addWidget(m_path, 1);
    pathRow->addWidget(btnBrowse);
    root->addLayout(pathRow);

    // ── Label + Size ──────────────────────────────────────────────────────────
    auto* row2 = new QHBoxLayout;
    auto* lblLabel = new QVBoxLayout;
    auto* lbl1 = new QLabel(QStringLiteral("Label (optional)"));
    lbl1->setStyleSheet("color:#8080a0; font-size:11px;");
    m_label = new QLineEdit;
    m_label->setPlaceholderText(QStringLiteral("My secrets"));
    lblLabel->addWidget(lbl1); lblLabel->addWidget(m_label);
    auto* sizeCol = new QVBoxLayout;
    auto* lbl2 = new QLabel(QStringLiteral("Size (MB)"));
    lbl2->setStyleSheet("color:#8080a0; font-size:11px;");
    m_size = new QSpinBox;
    m_size->setRange(1, 8192);
    m_size->setValue(100);
    sizeCol->addWidget(lbl2); sizeCol->addWidget(m_size);
    row2->addLayout(lblLabel, 3);
    row2->addSpacing(12);
    row2->addLayout(sizeCol, 1);
    root->addLayout(row2);

    // ── Passphrase ────────────────────────────────────────────────────────────
    auto* sep1 = new QFrame; sep1->setFrameShape(QFrame::HLine);
    sep1->setStyleSheet("color:#2e2e40;"); root->addWidget(sep1);
    auto* sectionPw = new QLabel(QStringLiteral("Passphrase  (leave blank for key-only access)"));
    sectionPw->setStyleSheet("color:#8080a0; font-size:11px; font-weight:bold;");
    root->addWidget(sectionPw);

    auto* pwRow = new QHBoxLayout;
    m_password = new QLineEdit; m_password->setEchoMode(QLineEdit::Password);
    m_password->setPlaceholderText(QStringLiteral("Passphrase"));
    m_confirm  = new QLineEdit; m_confirm->setEchoMode(QLineEdit::Password);
    m_confirm->setPlaceholderText(QStringLiteral("Confirm"));
    pwRow->addWidget(m_password); pwRow->addWidget(m_confirm);
    root->addLayout(pwRow);

    // ── Cipher + KDF ──────────────────────────────────────────────────────────
    auto* sep2 = new QFrame; sep2->setFrameShape(QFrame::HLine);
    sep2->setStyleSheet("color:#2e2e40;"); root->addWidget(sep2);
    auto* encRow = new QHBoxLayout;

    auto* cipherCol = new QVBoxLayout;
    auto* lbl3 = new QLabel(QStringLiteral("Cipher"));
    lbl3->setStyleSheet("color:#8080a0; font-size:11px;");
    m_cipher = new QComboBox;
    m_cipher->addItem(QStringLiteral("ChaCha20-Poly1305  (recommended)"), 0);
    m_cipher->addItem(QStringLiteral("AES-256-GCM"), 1);
    cipherCol->addWidget(lbl3); cipherCol->addWidget(m_cipher);
    encRow->addLayout(cipherCol, 2);
    encRow->addSpacing(12);

    auto* kdfCol = new QVBoxLayout;
    auto* lbl4 = new QLabel(QStringLiteral("KDF Profile"));
    lbl4->setStyleSheet("color:#8080a0; font-size:11px;");
    kdfCol->addWidget(lbl4);
    m_kdf = new QButtonGroup(this);
    auto* r1 = new QRadioButton(QStringLiteral("Interactive  (64 MiB, < 1 s)"));
    auto* r2 = new QRadioButton(QStringLiteral("Sensitive  (256 MiB, 2–5 s)"));
    r1->setChecked(true);
    m_kdf->addButton(r1, 0);
    m_kdf->addButton(r2, 1);
    kdfCol->addWidget(r1); kdfCol->addWidget(r2);
    encRow->addLayout(kdfCol, 3);
    root->addLayout(encRow);

    // ── Buttons ───────────────────────────────────────────────────────────────
    auto* sep3 = new QFrame; sep3->setFrameShape(QFrame::HLine);
    sep3->setStyleSheet("color:#2e2e40;"); root->addWidget(sep3);

    auto* buttons = new QDialogButtonBox;
    auto* btnOk  = buttons->addButton(QStringLiteral("⚡  Create Container"), QDialogButtonBox::AcceptRole);
    btnOk->setProperty("primary", true);
    buttons->addButton(QDialogButtonBox::Cancel);
    root->addWidget(buttons);

    connect(btnBrowse, &QPushButton::clicked, this, &CreateDialog::onBrowse);
    connect(buttons,   &QDialogButtonBox::accepted, this, &CreateDialog::onAccepted);
    connect(buttons,   &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void CreateDialog::onBrowse() {
    const QString f = QFileDialog::getSaveFileName(this,
        QStringLiteral("Choose container location"), {},
        QStringLiteral("Venom container (*.vnm)"));
    if (!f.isEmpty()) {
        m_path->setText(f.endsWith(QStringLiteral(".vnm")) ? f : f + QStringLiteral(".vnm"));
    }
}

void CreateDialog::onAccepted() {
    const QString path = m_path->text().trimmed();
    if (path.isEmpty()) {
        QMessageBox::warning(this, {}, QStringLiteral("Choose a file path."));
        return;
    }
    const QString pw  = m_password->text();
    const QString pw2 = m_confirm->text();
    if (!pw.isEmpty() && pw != pw2) {
        QMessageBox::warning(this, {}, QStringLiteral("Passphrases do not match."));
        return;
    }
    const quint8 cipher  = static_cast<quint8>(m_cipher->currentData().toInt());
    const quint8 profile = static_cast<quint8>(m_kdf->checkedId());

    m_core->createContainer(path, pw, static_cast<quint64>(m_size->value()),
                            cipher, profile, m_label->text().trimmed());
    accept();
}

} // namespace Venom
