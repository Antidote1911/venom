#pragma once
#include <QThread>
#include <QString>
#include "VenomCore.h"
// vnmcore.h already contains its own extern "C" guard
#include <vnmcore.h>

namespace Venom {

/**
 * Worker thread that calls vnm_mount_blocking (which blocks until unmounted).
 * Emits Qt signals safely via QMetaObject::invokeMethod.
 */
class MountWorker : public QThread {
    Q_OBJECT

public:
    MountWorker(VnmHandle*     handle,
                const QString& mountpoint,
                VenomCore*     core,
                QObject*       parent = nullptr)
        : QThread(parent)
        , m_handle(handle)
        , m_mountpoint(mountpoint)
        , m_core(core)
    {}

    void run() override;

signals:
    void mounted(Venom::MountedContainer info);
    void gone(QString mountpoint);
    void error(QString mountpoint, QString message);

private:
    VnmHandle* m_handle;
    QString    m_mountpoint;
    VenomCore* m_core;
};

} // namespace Venom
