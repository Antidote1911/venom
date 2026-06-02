/**
 * @file vnmcore.h
 * @brief C API for the Venom cryptographic container library.
 *
 * Build the Rust library first:
 *   cargo build --release -p vnmcore-ffi
 *
 * Link with:
 *   -L<workspace>/target/release -lvnmcore_ffi
 *   (plus system libs: -ldl -lpthread -lm on Linux)
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque handles ─────────────────────────────────────────────────────────── */

/** Opaque handle to an open VnmContainer. */
typedef struct VnmHandle VnmHandle;

/** Opaque list of key entries from the local key store. */
typedef struct VnmKeyList VnmKeyList;

/* ── Key info struct ─────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  fingerprint[24];   /**< Hex with colons: "ab:cd:ef:01:23:45:67:89\0" */
    uint8_t  label[128];        /**< UTF-8, null-terminated */
    uint64_t created_at;        /**< Unix timestamp */
    bool     is_protected;      /**< True if .key file has passphrase protection */
} VnmKeyInfo;

/* ── String helpers ─────────────────────────────────────────────────────────── */

/** Free a string returned by any vnm_* function via error_out. */
void vnm_free_string(char* s);

/* ── Container lifecycle ─────────────────────────────────────────────────────── */

/**
 * Create a new container.
 * @param path        File path for the new .vnm file (must not exist)
 * @param password    Outer passphrase; empty string = key-only container
 * @param size_mb     Total container size in megabytes
 * @param cipher      0 = ChaCha20-Poly1305, 1 = AES-256-GCM
 * @param kdf_profile 0 = interactive (64 MiB), 1 = sensitive (256 MiB)
 * @param label       Human-readable label (may be NULL)
 * @param error_out   On error: caller-owned string to free with vnm_free_string
 * @return Handle or NULL on error
 */
VnmHandle* vnm_container_create(
    const char* path,
    const char* password,
    uint64_t    size_mb,
    uint8_t     cipher,
    uint8_t     kdf_profile,
    const char* label,
    char**      error_out
);

/**
 * Open an existing container with a passphrase.
 * Tries outer header first, then hidden header with the same passphrase.
 */
VnmHandle* vnm_container_open_password(
    const char* path,
    const char* password,
    char**      error_out
);

/**
 * Open an existing container with a hybrid private key (.key file).
 * @param key_passphrase Empty string if the key file is not passphrase-protected
 */
VnmHandle* vnm_container_open_key(
    const char* path,
    const char* key_path,
    const char* key_passphrase,
    char**      error_out
);

/** Release a container handle. */
void vnm_container_free(VnmHandle* handle);

/** Container label (owned by handle, valid while handle is alive). */
const char* vnm_container_get_label(const VnmHandle* handle);

/** Cipher name (owned by handle). */
const char* vnm_container_get_cipher(const VnmHandle* handle);

/** Creation timestamp (Unix seconds). */
uint64_t vnm_container_get_created_at(const VnmHandle* handle);

/** True if this is the hidden volume. */
bool vnm_container_get_is_hidden(const VnmHandle* handle);

/* ── Mount / unmount ─────────────────────────────────────────────────────────── */

/**
 * Mount callbacks — all called on the Rust FUSE thread.
 * The Qt side must use QMetaObject::invokeMethod(Qt::QueuedConnection) to
 * forward events to the main thread.
 */
typedef void (*VnmMountedCb)(const char* label, const char* cipher,
                              uint64_t created_at, bool is_hidden, void* user_data);
typedef void (*VnmErrorCb)  (const char* error, void* user_data);
typedef void (*VnmGoneCb)   (void* user_data);

/**
 * Mount a container.  BLOCKS until the filesystem is unmounted.
 * Must be called from a dedicated thread (e.g. QThread).
 * Calls on_mounted when FUSE is ready, on_gone when cleanly unmounted,
 * or on_error on failure.
 */
void vnm_mount_blocking(
    VnmHandle*    handle,
    const char*   mountpoint,
    VnmMountedCb  on_mounted,
    VnmErrorCb    on_error,
    VnmGoneCb     on_gone,
    void*         user_data
);

/**
 * Unmount via fusermount3 / umount.
 * @return true if the unmount command exited with success
 */
bool vnm_unmount(const char* mountpoint);

/* ── Recipient management ────────────────────────────────────────────────────── */

/** Add a hybrid key recipient to an open container (using a .pub file). */
bool vnm_container_add_key_recipient(
    const VnmHandle* handle,
    const char*      pub_path,
    char**           error_out
);

/* ── Key management ──────────────────────────────────────────────────────────── */

/**
 * Generate a new hybrid X25519 + ML-KEM-1024 keypair.
 * Saves to key_path as a .key file.
 * @param passphrase Empty string for no passphrase protection
 * @param kdf_sensitive true = Sensitive profile (256 MiB), false = Interactive (64 MiB)
 */
bool vnm_key_generate(
    const char* key_path,
    const char* label,
    const char* passphrase,
    bool        kdf_sensitive,
    char**      error_out
);

/** Export the public portion of a .key file as a .pub file for sharing. */
bool vnm_key_export_pub(
    const char* key_path,
    const char* pub_path,
    const char* key_passphrase,
    char**      error_out
);

/** Read public metadata from a .key file (no passphrase needed). */
bool vnm_key_read_info(
    const char* key_path,
    VnmKeyInfo* info_out
);

/* ── Key store listing ───────────────────────────────────────────────────────── */

/** Load all keys from ~/.config/venom/keys/. Caller must free with vnm_keylist_free. */
VnmKeyList* vnm_keylist_load(void);

/** Free a key list. */
void vnm_keylist_free(VnmKeyList* list);

/** Number of entries in the list. */
size_t vnm_keylist_count(const VnmKeyList* list);

/** Get key info at index. Returns false if index out of range. */
bool vnm_keylist_get(const VnmKeyList* list, size_t index, VnmKeyInfo* info_out);

#ifdef __cplusplus
} /* extern "C" */
#endif
