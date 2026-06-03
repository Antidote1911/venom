#pragma once
#include <QMainWindow>
#include <QVBoxLayout>
#include <QList>
#include <QFileInfo>
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
    void refreshUnifiedVaultList();
    QWidget* makeMountedCard(const MountedContainer& mc);
    QWidget* makeUnmountedCard(const QFileInfo& fi);
    void refreshKeyList();
    void refreshCreateKeyList();
    void refreshMountKeyList();
    void refreshKeyDestCombo();  ///< populate cbKeyDest with local store + USB drives

    Ui::MainWindow*  ui;
    VenomCore*       m_core;
    QVBoxLayout*     m_vaultLayout;
    QList<KeyEntry>  m_keys;
    bool             m_containerPathManual  = false;
    bool             m_mountpointManual     = false;
    QList<QWidget*>  m_vaultCards;  ///< dynamically created vault cards (not owned by layout directly)
};

} // namespace Venom
