#include "MountWorker.h"
#include <QMetaObject>

namespace Venom {

// Callback context passed to vnm_mount_blocking
struct MountCtx {
    MountWorker* worker;
    QString      mountpoint;
};

static void cb_mounted(const char* label, const char* cipher,
                        uint64_t created_at, bool is_hidden, void* ud)
{
    auto* ctx = static_cast<MountCtx*>(ud);
    MountedContainer info;
    info.mountpoint = ctx->mountpoint;
    info.vaultPath  = {};   // filled in by VenomCore
    info.label      = label  ? QString::fromUtf8(label)  : QString{};
    info.cipher     = cipher ? QString::fromUtf8(cipher) : QString{};
    info.createdAt  = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(created_at));
    info.isHidden   = is_hidden;
    emit ctx->worker->mounted(info);
}

static void cb_gone(void* ud) {
    auto* ctx = static_cast<MountCtx*>(ud);
    emit ctx->worker->gone(ctx->mountpoint);
}

static void cb_error(const char* msg, void* ud) {
    auto* ctx = static_cast<MountCtx*>(ud);
    emit ctx->worker->error(ctx->mountpoint,
        msg ? QString::fromUtf8(msg) : QStringLiteral("Unknown FUSE error"));
}

void MountWorker::run() {
    MountCtx ctx{ this, m_mountpoint };
    vnm_mount_blocking(
        m_handle,
        m_mountpoint.toUtf8().constData(),
        cb_mounted, cb_error, cb_gone,
        &ctx
    );
    vnm_container_free(m_handle);
    m_handle = nullptr;
}

} // namespace Venom
