#include "VenomCore.h"
#include "MountWorker.h"
#include <QMetaType>

namespace Venom {

VenomCore::VenomCore(QObject* parent) : QObject(parent) {
    qRegisterMetaType<Venom::MountedContainer>();
    qRegisterMetaType<Venom::KeyEntry>();
}

VenomCore::~VenomCore() = default;

// ── Create ────────────────────────────────────────────────────────────────────

void VenomCore::createContainer(const QString&     path,
                                const QString&     password,
                                quint64            sizeMB,
                                quint8             cipher,
                                quint8             kdfProfile,
                                const QString&     label,
                                const QStringList& recipientKeyPaths)
{
    char* err = nullptr;
    VnmHandle* h = vnm_container_create(
        path.toUtf8().constData(),
        password.toUtf8().constData(),
        sizeMB, cipher, kdfProfile,
        label.isEmpty() ? nullptr : label.toUtf8().constData(),
        &err
    );
    if (!h) {
        QString msg = err ? QString::fromUtf8(err) : "Unknown error";
        vnm_free_string(err);
        emit errorOccurred(msg);
        return;
    }
    for (const QString& kp : recipientKeyPaths) {
        bool ok = vnm_container_add_key_recipient(h, kp.toUtf8().constData(), &err);
        if (!ok) {
            QString msg = err ? QString::fromUtf8(err) : "Failed to add key recipient";
            vnm_free_string(err);
            vnm_container_free(h);
            emit errorOccurred(msg);
            return;
        }
    }
    vnm_container_free(h);
    emit containerCreated(path);
}

// ── Mount ─────────────────────────────────────────────────────────────────────

void VenomCore::mountWithPassword(const QString& vaultPath,
                                  const QString& mountpoint,
                                  const QString& password)
{
    char* err = nullptr;
    VnmHandle* h = vnm_container_open_password(
        vaultPath.toUtf8().constData(),
        password.toUtf8().constData(),
        &err
    );
    if (!h) {
        QString msg = err ? QString::fromUtf8(err) : "Authentication failed";
        vnm_free_string(err);
        emit mountError(mountpoint, msg);
        return;
    }
    auto* worker = new MountWorker(h, mountpoint, this, this);
    connect(worker, &MountWorker::mounted, this, [this](Venom::MountedContainer info){
        addMounted(info);
        emit mountStarted(info);
    }, Qt::QueuedConnection);
    connect(worker, &MountWorker::gone, this, [this](QString mp){
        removeMounted(mp);
        emit mountGone(mp);
    }, Qt::QueuedConnection);
    connect(worker, &MountWorker::error, this, [this](QString mp, QString msg){
        removeMounted(mp);
        emit mountError(mp, msg);
    }, Qt::QueuedConnection);
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
}

void VenomCore::mountWithKey(const QString& vaultPath,
                             const QString& mountpoint,
                             const QString& keyPath,
                             const QString& keyPassphrase)
{
    char* err = nullptr;
    VnmHandle* h = vnm_container_open_key(
        vaultPath.toUtf8().constData(),
        keyPath.toUtf8().constData(),
        keyPassphrase.toUtf8().constData(),
        &err
    );
    if (!h) {
        QString msg = err ? QString::fromUtf8(err) : "Key authentication failed";
        vnm_free_string(err);
        emit mountError(mountpoint, msg);
        return;
    }
    auto* worker = new MountWorker(h, mountpoint, this, this);
    connect(worker, &MountWorker::mounted, this, [this](Venom::MountedContainer info){
        addMounted(info);
        emit mountStarted(info);
    }, Qt::QueuedConnection);
    connect(worker, &MountWorker::gone, this, [this](QString mp){
        removeMounted(mp);
        emit mountGone(mp);
    }, Qt::QueuedConnection);
    connect(worker, &MountWorker::error, this, [this](QString mp, QString msg){
        removeMounted(mp);
        emit mountError(mp, msg);
    }, Qt::QueuedConnection);
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
}

void VenomCore::unmount(const QString& mountpoint) {
    bool ok = vnm_unmount(mountpoint.toUtf8().constData());
    if (!ok) emit errorOccurred(QStringLiteral("Unmount failed for: ") + mountpoint);
}

// ── Key management ────────────────────────────────────────────────────────────

void VenomCore::generateKey(const QString& label,
                            const QString& passphrase,
                            bool           sensitive)
{
    char* err = nullptr;
    char* path = vnm_key_generate_auto(
        label.toUtf8().constData(),
        passphrase.toUtf8().constData(),
        sensitive, &err
    );
    if (!path) {
        QString msg = err ? QString::fromUtf8(err) : "Key generation failed";
        vnm_free_string(err);
        emit errorOccurred(msg);
        return;
    }
    const QString savedPath = QString::fromUtf8(path);
    vnm_free_string(path);
    emit keyGenerated(savedPath);
}

void VenomCore::exportPublicKey(const QString& keyPath,
                                const QString& destPath,
                                const QString& keyPassphrase)
{
    char* err = nullptr;
    bool ok = vnm_key_export_pub(
        keyPath.toUtf8().constData(),
        destPath.toUtf8().constData(),
        keyPassphrase.toUtf8().constData(),
        &err
    );
    if (!ok) {
        QString msg = err ? QString::fromUtf8(err) : "Export failed";
        vnm_free_string(err);
        emit errorOccurred(msg);
    }
}

QList<KeyEntry> VenomCore::localKeys() const {
    QList<KeyEntry> result;
    VnmKeyList* list = vnm_keylist_load();
    if (!list) return result;
    const size_t n = vnm_keylist_count(list);
    for (size_t i = 0; i < n; ++i) {
        VnmKeyInfo info{};
        if (vnm_keylist_get(list, i, &info)) {
            result.append(KeyEntry{
                .fingerprint = QString::fromLatin1(reinterpret_cast<const char*>(info.fingerprint)),
                .label       = QString::fromUtf8(reinterpret_cast<const char*>(info.label)),
                .filename    = QString::fromUtf8(reinterpret_cast<const char*>(info.filename)),
                .createdAt   = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(info.created_at)),
                .isProtected = info.is_protected,
                .isPubOnly   = info.is_pub_only
            });
        }
    }
    vnm_keylist_free(list);
    return result;
}

} // namespace Venom
