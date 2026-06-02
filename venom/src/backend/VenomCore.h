#pragma once

#include <QObject>
#include <QString>
#include <QList>
#include <QDateTime>

extern "C" {
#include <vnmcore.h>
}

namespace Venom {

// ── Data structures ──────────────────────────────────────────────────────────

struct MountedContainer {
    QString     vaultPath;
    QString     mountpoint;
    QString     label;
    QString     cipher;
    QDateTime   createdAt;
    bool        isHidden  = false;
};

struct KeyEntry {
    QString     fingerprint;
    QString     label;
    QDateTime   createdAt;
    bool        isProtected = false;
};

// ── VenomCore ─────────────────────────────────────────────────────────────────

/**
 * Singleton-style Qt wrapper around the vnmcore C FFI.
 *
 * All Rust operations that can block (KDF, FUSE mount) run on worker threads.
 * Signals are emitted on the main thread for UI updates.
 */
class VenomCore : public QObject {
    Q_OBJECT

public:
    explicit VenomCore(QObject* parent = nullptr);
    ~VenomCore() override;

    // ── Synchronous operations (run on calling thread) ────────────────────────

    /** Create a new container. Emits containerCreated or errorOccurred. */
    void createContainer(const QString&     path,
                         const QString&     password,
                         quint64            sizeMB,
                         quint8             cipher,
                         quint8             kdfProfile,
                         const QString&     label,
                         const QStringList& recipientKeyPaths = {});

    // ── Async operations (spawn QThread internally) ───────────────────────────

    /** Open + mount a container with a password. */
    void mountWithPassword(const QString& vaultPath,
                           const QString& mountpoint,
                           const QString& password);

    /** Open + mount a container with a private key file. */
    void mountWithKey(const QString& vaultPath,
                      const QString& mountpoint,
                      const QString& keyPath,
                      const QString& keyPassphrase);

    /** Unmount a container. */
    void unmount(const QString& mountpoint);

    // ── Key management ────────────────────────────────────────────────────────

    void generateKey(const QString& savePath,
                     const QString& label,
                     const QString& passphrase,
                     bool           sensitivProfile);

    void exportPublicKey(const QString& keyPath,
                         const QString& destPath,
                         const QString& keyPassphrase);

    // ── Queries ───────────────────────────────────────────────────────────────

    QList<MountedContainer> mountedContainers() const { return m_mounted; }
    QList<KeyEntry>         localKeys() const;

signals:
    void containerCreated(const QString& path);
    void mountStarted(const Venom::MountedContainer& info);
    void mountGone(const QString& mountpoint);
    void mountError(const QString& mountpoint, const QString& error);
    void keyGenerated(const QString& path);
    void errorOccurred(const QString& message);

private:
    QList<MountedContainer> m_mounted;

    void addMounted(const MountedContainer& m) { m_mounted.append(m); }
    void removeMounted(const QString& mp) {
        m_mounted.erase(std::remove_if(m_mounted.begin(), m_mounted.end(),
            [&](const auto& c){ return c.mountpoint == mp; }), m_mounted.end());
    }
};

} // namespace Venom

Q_DECLARE_METATYPE(Venom::MountedContainer)
Q_DECLARE_METATYPE(Venom::KeyEntry)
