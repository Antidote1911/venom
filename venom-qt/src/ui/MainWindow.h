#pragma once
#include <QMainWindow>
#include <QStackedWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include "../backend/VenomCore.h"

namespace Venom {

class VaultListWidget;
class CreateDialog;
class MountDialog;
class KeyManagerDialog;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onMountStarted(const Venom::MountedContainer& info);
    void onMountGone(const QString& mountpoint);
    void onMountError(const QString& mountpoint, const QString& error);
    void onContainerCreated(const QString& path);
    void onKeyGenerated(const QString& path);
    void onError(const QString& msg);
    void openCreateDialog();
    void openMountDialog();
    void openKeyManager();
    void unmount(const QString& mountpoint);

private:
    void setupUi();
    void setupConnections();
    void refreshVaultList();
    void showStatus(const QString& msg, bool isError = false);

    VenomCore*       m_core;
    VaultListWidget* m_vaultList;
    QLabel*          m_statusLabel;
    QPushButton*     m_btnCreate;
    QPushButton*     m_btnMount;
    QPushButton*     m_btnKeys;
};

} // namespace Venom
