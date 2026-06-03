#pragma once
#include <QMainWindow>
#include <QVBoxLayout>
#include <QList>
#include "../backend/VenomCore.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

namespace Venom {

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    // VenomCore signals
    void onMountStarted(const Venom::MountedContainer& info);
    void onMountGone(const QString& mountpoint);
    void onMountError(const QString& mountpoint, const QString& error);
    void onContainerCreated(const QString& path);
    void onKeyGenerated(const QString& path);
    void onError(const QString& message);

    // Tab 2 — Create
    void browseCreatePath();
    void onCreateContainer();

    // Tab 2 — Mount
    void browseVaultPath();
    void browseMountpoint();
    void browseKeyFile();
    void onMount();

    // Tab 3 — Key manager
    void onGenerateKey();
    void onImportKey();
    void onExportPub();
    void onDeleteKey();

private:
    void refreshVaultList();
    void refreshDiscoveredVaults();
    void addVaultCard(const MountedContainer& info);
    void removeVaultCard(const QString& mountpoint);
    void refreshKeyList();
    void refreshCreateKeyList();
    void refreshMountKeyList();

    Ui::MainWindow*  ui;
    VenomCore*       m_core;
    QVBoxLayout*     m_vaultLayout;
    QList<KeyEntry>  m_keys;
    bool             m_containerPathManual  = false; ///< true once user picks a custom container path
    bool             m_mountpointManual     = false; ///< true once user picks a custom mountpoint
};

} // namespace Venom
