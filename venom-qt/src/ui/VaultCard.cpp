#include "VaultCard.h"
#include "Style.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QDesktopServices>
#include <QUrl>
#include <QProcess>

namespace Venom {

VaultCard::VaultCard(const MountedContainer& info, VenomCore* core, QWidget* parent)
    : QFrame(parent), m_info(info), m_core(core)
{
    setProperty("card", true);
    setStyleSheet(
        "QFrame { background-color: #141428; border: 1.5px solid #50c878; "
        "border-radius: 10px; } "
        "QFrame:hover { border-color: #70e898; }"
    );

    auto* outer = new QHBoxLayout(this);
    outer->setContentsMargins(16, 12, 16, 12);

    // Left: info
    auto* infoLayout = new QVBoxLayout;
    infoLayout->setSpacing(2);

    QString title = info.label.isEmpty() ? QStringLiteral("(unlabelled)") : info.label;
    auto* titleLbl = new QLabel(
        (info.isHidden ? QStringLiteral("🔐 ") : QStringLiteral("● ")) + title);
    titleLbl->setStyleSheet("color: #50c878; font-size: 15px; font-weight: bold;");
    infoLayout->addWidget(titleLbl);

    auto* pathLbl = new QLabel(QStringLiteral("📁  ") + info.vaultPath);
    pathLbl->setStyleSheet("color: #606080; font-size: 12px; font-family: monospace;");
    infoLayout->addWidget(pathLbl);

    auto* mpLbl = new QLabel(QStringLiteral("⛰  ") + info.mountpoint);
    mpLbl->setStyleSheet("color: #606080; font-size: 12px; font-family: monospace;");
    infoLayout->addWidget(mpLbl);

    auto* meta = new QLabel(
        info.cipher + QStringLiteral("  •  ") +
        info.createdAt.toString(QStringLiteral("yyyy-MM-dd")) +
        (info.isHidden ? QStringLiteral("  •  hidden volume") : QString{}));
    meta->setStyleSheet("color: #505070; font-size: 11px;");
    infoLayout->addWidget(meta);

    outer->addLayout(infoLayout, 1);

    // Right: buttons
    auto* btnLayout = new QVBoxLayout;
    btnLayout->setSpacing(6);

    auto* btnOpen = new QPushButton(QStringLiteral("Open folder"));
    btnOpen->setFixedSize(110, 28);
    connect(btnOpen, &QPushButton::clicked, this, [this](){
        QDesktopServices::openUrl(QUrl::fromLocalFile(m_info.mountpoint));
    });

    auto* btnUnmount = new QPushButton(QStringLiteral("Unmount"));
    btnUnmount->setFixedSize(110, 28);
    btnUnmount->setProperty("danger", true);
    btnUnmount->setStyleSheet(
        "background:#6e2020; color:white; border:1px solid #a04040; "
        "border-radius:5px; font-weight:bold;");
    connect(btnUnmount, &QPushButton::clicked, this, [this](){
        m_core->unmount(m_info.mountpoint);
    });

    btnLayout->addWidget(btnOpen);
    btnLayout->addWidget(btnUnmount);
    btnLayout->addStretch();

    outer->addLayout(btnLayout);
}

} // namespace Venom
