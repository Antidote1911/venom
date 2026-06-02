#pragma once
#include <QFrame>
#include <QLabel>
#include <QPushButton>
#include "../backend/VenomCore.h"

namespace Venom {

class VaultCard : public QFrame {
    Q_OBJECT
public:
    VaultCard(const MountedContainer& info, VenomCore* core, QWidget* parent = nullptr);

signals:
    void unmountRequested(const QString& mountpoint);
    void openFolderRequested(const QString& mountpoint);

private:
    MountedContainer m_info;
    VenomCore*       m_core;
};

} // namespace Venom
