#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QButtonGroup>
#include <QListWidget>
#include "../backend/VenomCore.h"

namespace Venom {

class MountDialog : public QDialog {
    Q_OBJECT
public:
    explicit MountDialog(VenomCore* core, QWidget* parent = nullptr);

private slots:
    void onAccepted();
    void onBrowseContainer();
    void onBrowseMountpoint();
    void onBrowseKey();
    void onCredentialToggled();

private:
    VenomCore*    m_core;
    QLineEdit*    m_vaultPath;
    QLineEdit*    m_mountpoint;
    // Password credential
    QButtonGroup* m_credGroup;
    QWidget*      m_pwPanel;
    QLineEdit*    m_password;
    // Key credential
    QWidget*      m_keyPanel;
    QListWidget*  m_keyList;   // keys from local store
    QLineEdit*    m_keyPath;   // or browse manually
    QLineEdit*    m_keyPw;     // passphrase for key

    QList<KeyEntry> m_keys;
};

} // namespace Venom
