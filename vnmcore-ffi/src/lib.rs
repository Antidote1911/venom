//! C FFI layer for vnmcore.
//!
//! Exposes vnmcore's API as a C-compatible interface for Qt6/C++ or any other language.
//!
//! ## Memory contract
//! - Handles returned by `vnm_container_*` are caller-owned → must call `vnm_container_free`.
//! - String slices (returned as `*const c_char`) live as long as the handle.
//! - Error strings (via `*mut *mut c_char`) must be freed with `vnm_free_string`.

use std::ffi::{CStr, CString, c_char, c_void};
use vnmcore::{
    VnmContainer,
    container::CipherAlgorithm,
    fs::container::{OpenCredential},
    fp_display,
};
use vnmcore::crypto::key_file::{read_key_file, read_key_file_protected, read_key_public};

// ── Error helpers ─────────────────────────────────────────────────────────────

fn set_error(msg: &str, error_out: *mut *mut c_char) {
    if !error_out.is_null() {
        let s = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
        unsafe { *error_out = s.into_raw(); }
    }
}

fn clear_error(error_out: *mut *mut c_char) {
    if !error_out.is_null() { unsafe { *error_out = std::ptr::null_mut(); } }
}

fn cstr(ptr: *const c_char) -> Option<&'static str> {
    if ptr.is_null() { return None; }
    unsafe { CStr::from_ptr(ptr).to_str().ok() }
}

fn cstr_or<'a>(ptr: *const c_char, default: &'a str) -> &'a str {
    cstr(ptr).unwrap_or(default)
}

/// Free a string allocated by vnm_* functions.
#[no_mangle]
pub extern "C" fn vnm_free_string(s: *mut c_char) {
    if !s.is_null() { unsafe { drop(CString::from_raw(s)); } }
}

// ── Container handle ──────────────────────────────────────────────────────────

pub struct VnmHandle {
    container: VnmContainer,
    label_c:   CString,
    cipher_c:  CString,
}

impl VnmHandle {
    fn boxed(c: VnmContainer) -> *mut Self {
        let label_c  = CString::new(c.label.clone().unwrap_or_default()).unwrap_or_default();
        let cipher_c = CString::new(c.cipher.to_string()).unwrap_or_default();
        Box::into_raw(Box::new(VnmHandle { container: c, label_c, cipher_c }))
    }
}

/// Create a new container.
/// `password` may be `""` for a key-only container.
#[no_mangle]
pub extern "C" fn vnm_container_create(
    path:        *const c_char,
    password:    *const c_char,
    size_mb:     u64,
    cipher:      u8,
    kdf_profile: u8,
    label:       *const c_char,
    error_out:   *mut *mut c_char,
) -> *mut VnmHandle {
    clear_error(error_out);
    let Some(path_s) = cstr(path) else { set_error("null path", error_out); return std::ptr::null_mut(); };
    let pw_s    = cstr_or(password, "");
    let label_s = cstr(label);
    let alg = match cipher {
        1 => CipherAlgorithm::DeoxysII256,
        2 => CipherAlgorithm::Serpent256,
        3 => CipherAlgorithm::Triple,
        _ => CipherAlgorithm::XChaCha20Poly1305,
    };
    let prof    = if kdf_profile == 1 { "sensitive" } else { "interactive" };
    let lbl_opt = label_s.filter(|s| !s.is_empty()).map(|s| s.to_string());

    match VnmContainer::create(path_s, pw_s.as_bytes(), size_mb * 1024 * 1024, alg, prof, lbl_opt, None) {
        Ok(c)  => VnmHandle::boxed(c),
        Err(e) => { set_error(&e.to_string(), error_out); std::ptr::null_mut() }
    }
}

/// Open with password.
#[no_mangle]
pub extern "C" fn vnm_container_open_password(
    path: *const c_char, password: *const c_char, error_out: *mut *mut c_char,
) -> *mut VnmHandle {
    clear_error(error_out);
    let Some(p) = cstr(path) else { set_error("null path", error_out); return std::ptr::null_mut(); };
    let pw = cstr_or(password, "");
    match VnmContainer::open(p, OpenCredential::Password(pw.as_bytes())) {
        Ok(c)  => VnmHandle::boxed(c),
        Err(e) => { set_error(&e.to_string(), error_out); std::ptr::null_mut() }
    }
}

/// Open with a hybrid private key (.key file).
#[no_mangle]
pub extern "C" fn vnm_container_open_key(
    path: *const c_char, key_path: *const c_char, key_passphrase: *const c_char,
    error_out: *mut *mut c_char,
) -> *mut VnmHandle {
    clear_error(error_out);
    let Some(p)  = cstr(path)     else { set_error("null path", error_out); return std::ptr::null_mut(); };
    let Some(kp) = cstr(key_path) else { set_error("null key_path", error_out); return std::ptr::null_mut(); };
    let passphrase = cstr_or(key_passphrase, "");

    let kf = if passphrase.is_empty() {
        read_key_file(std::path::Path::new(kp))
    } else {
        read_key_file_protected(std::path::Path::new(kp), passphrase.as_bytes())
    };

    match kf {
        Err(e) => { set_error(&e.to_string(), error_out); std::ptr::null_mut() }
        Ok(kf) => match VnmContainer::open(p, OpenCredential::PrivateKey(&kf.key)) {
            Ok(c)  => VnmHandle::boxed(c),
            Err(e) => { set_error(&e.to_string(), error_out); std::ptr::null_mut() }
        }
    }
}

#[no_mangle]
pub extern "C" fn vnm_container_free(h: *mut VnmHandle) {
    if !h.is_null() { unsafe { drop(Box::from_raw(h)); } }
}

#[no_mangle]
pub extern "C" fn vnm_container_get_label(h: *const VnmHandle) -> *const c_char {
    if h.is_null() { return std::ptr::null(); }
    unsafe { (*h).label_c.as_ptr() }
}
#[no_mangle]
pub extern "C" fn vnm_container_get_cipher(h: *const VnmHandle) -> *const c_char {
    if h.is_null() { return std::ptr::null(); }
    unsafe { (*h).cipher_c.as_ptr() }
}
#[no_mangle]
pub extern "C" fn vnm_container_get_created_at(h: *const VnmHandle) -> u64 {
    if h.is_null() { return 0; }
    unsafe { (*h).container.created_at }
}
#[no_mangle]
pub extern "C" fn vnm_container_get_is_hidden(h: *const VnmHandle) -> bool {
    if h.is_null() { return false; }
    unsafe { (*h).container.is_hidden }
}

// ── Mount ─────────────────────────────────────────────────────────────────────

pub type VnmMountedCb = extern "C" fn(*const c_char, *const c_char, u64, bool, *mut c_void);
pub type VnmErrorCb   = extern "C" fn(*const c_char, *mut c_void);
pub type VnmGoneCb    = extern "C" fn(*mut c_void);

/// Mount a container — BLOCKS until unmounted. Run from a dedicated thread.
///
/// # Ownership
/// This function takes ownership of `handle` — the caller must NOT call
/// `vnm_container_free` after this returns.  The handle is freed internally.
#[no_mangle]
pub extern "C" fn vnm_mount_blocking(
    handle:     *mut VnmHandle,
    mountpoint: *const c_char,
    on_mounted: Option<VnmMountedCb>,
    on_error:   Option<VnmErrorCb>,
    on_gone:    Option<VnmGoneCb>,
    user_data:  *mut c_void,
) {
    if handle.is_null() || mountpoint.is_null() { return; }
    let mp = match unsafe { CStr::from_ptr(mountpoint) }.to_str() {
        Ok(s) => s.to_string(), Err(_) => return,
    };

    // Consume the Box — this is the single owner from here on.
    let owned = unsafe { Box::from_raw(handle) };

    // Signal "mounted" before blocking.
    if let Some(cb) = on_mounted {
        cb(owned.label_c.as_ptr(), owned.cipher_c.as_ptr(),
           owned.container.created_at, owned.container.is_hidden, user_data);
    }

    // Destructure to move the container into an Arc without copying.
    // label_c / cipher_c are dropped here (end of their scope).
    let VnmHandle { container, .. } = *owned;

    #[cfg(target_family = "unix")]
    {
        use vnmcore::fs::fuse::driver;
        let container = std::sync::Arc::new(container);
        match driver::mount(container, &mp) {
            Ok(_)  => { if let Some(cb) = on_gone  { cb(user_data); } }
            Err(e) => {
                let msg = CString::new(format!("FUSE: {e}")).unwrap_or_default();
                if let Some(cb) = on_error { cb(msg.as_ptr(), user_data); }
            }
        }
    }
    #[cfg(not(target_family = "unix"))]
    {
        let msg = CString::new("FUSE not supported on this platform").unwrap_or_default();
        if let Some(cb) = on_error { cb(msg.as_ptr(), user_data); }
    }
}

/// Unmount (calls fusermount3 / umount). Returns true on success.
#[no_mangle]
pub extern "C" fn vnm_unmount(mountpoint: *const c_char) -> bool {
    let Some(mp) = cstr(mountpoint) else { return false; };
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    {
        if std::process::Command::new("fusermount3").args(["-u", mp])
            .status().map(|s| s.success()).unwrap_or(false) { return true; }
        std::process::Command::new("fusermount").args(["-u", mp])
            .status().map(|s| s.success()).unwrap_or(false)
    }
    #[cfg(target_os = "macos")]
    { std::process::Command::new("umount").arg(mp).status().map(|s| s.success()).unwrap_or(false) }
    #[cfg(target_os = "windows")]
    { let _ = mp; false }
}

// ── Recipient management ──────────────────────────────────────────────────────

/// Add a hybrid key recipient using a .pub or .key file.
/// Accepts both public-only (.pub) and full keypair (.key) files.
#[no_mangle]
pub extern "C" fn vnm_container_add_key_recipient(
    handle: *const VnmHandle, key_path: *const c_char, error_out: *mut *mut c_char,
) -> bool {
    clear_error(error_out);
    if handle.is_null() { return false; }
    let Some(kp) = cstr(key_path) else { return false; };
    let path = std::path::Path::new(kp);

    // Try .pub first, then fall back to reading the public part of a .key file.
    let public_key = if let Ok(d) = vnmcore::read_pub_file(path) {
        d.public
    } else {
        match read_key_public(path) {
            Ok(d)  => d.public,
            Err(e) => { set_error(&e.to_string(), error_out); return false; }
        }
    };

    match unsafe { (*handle).container.add_key_recipient(&public_key) } {
        Ok(_)  => true,
        Err(e) => { set_error(&e.to_string(), error_out); false }
    }
}

// ── Key management ────────────────────────────────────────────────────────────

/// Generate a new hybrid keypair.
#[no_mangle]
pub extern "C" fn vnm_key_generate(
    key_path: *const c_char, label: *const c_char,
    passphrase: *const c_char, kdf_sensitive: bool,
    error_out: *mut *mut c_char,
) -> bool {
    clear_error(error_out);
    let Some(kp) = cstr(key_path) else { return false; };
    let lbl = cstr_or(label, "");
    let pw  = cstr_or(passphrase, "");
    let profile = if kdf_sensitive { 1u8 } else { 0u8 };
    let key = vnmcore::hybrid_generate();
    let result = if pw.is_empty() {
        vnmcore::write_key_file(std::path::Path::new(kp), &key, lbl)
    } else {
        vnmcore::write_key_file_protected(std::path::Path::new(kp), &key, lbl, pw.as_bytes(), profile)
    };
    match result {
        Ok(_)  => true,
        Err(e) => { set_error(&e.to_string(), error_out); false }
    }
}

/// Generate a keypair into an explicit directory (e.g. a USB drive).
/// Saves to `<dir>/<fingerprint_hex>.key`. Creates the directory if absent.
/// Returns the saved path (free with `vnm_free_string`), or NULL on error.
#[no_mangle]
pub extern "C" fn vnm_key_generate_to_dir(
    dir:           *const c_char,
    label:         *const c_char,
    passphrase:    *const c_char,
    kdf_sensitive: bool,
    error_out:     *mut *mut c_char,
) -> *mut c_char {
    clear_error(error_out);
    let Some(dir_s) = cstr(dir) else { set_error("null dir", error_out); return std::ptr::null_mut(); };
    let lbl     = cstr_or(label, "");
    let pw      = cstr_or(passphrase, "");
    let profile = if kdf_sensitive { 1u8 } else { 0u8 };

    let keys_dir = std::path::Path::new(dir_s);
    if let Err(e) = std::fs::create_dir_all(keys_dir) {
        set_error(&e.to_string(), error_out);
        return std::ptr::null_mut();
    }
    let key = vnmcore::hybrid_generate();
    let fp_hex: String = key.public.fingerprint().iter().map(|b| format!("{b:02x}")).collect();
    let path = keys_dir.join(format!("{fp_hex}.key"));
    let result = if pw.is_empty() {
        vnmcore::write_key_file(&path, &key, lbl)
    } else {
        vnmcore::write_key_file_protected(&path, &key, lbl, pw.as_bytes(), profile)
    };
    match result {
        Ok(_) => match std::ffi::CString::new(path.to_string_lossy().into_owned()) {
            Ok(cs) => cs.into_raw(),
            Err(e) => { set_error(&e.to_string(), error_out); std::ptr::null_mut() }
        },
        Err(e) => { set_error(&e.to_string(), error_out); std::ptr::null_mut() }
    }
}

/// Generate a new hybrid keypair and save it automatically to
/// `~/$XDG_CONFIG_HOME/venom/keys/<fingerprint_hex>.key`.
/// Returns the saved path as a heap-allocated C string (free with `vnm_free_string`),
/// or NULL on error (error set in `error_out`).
#[no_mangle]
pub extern "C" fn vnm_key_generate_auto(
    label:         *const c_char,
    passphrase:    *const c_char,
    kdf_sensitive: bool,
    error_out:     *mut *mut c_char,
) -> *mut c_char {
    clear_error(error_out);
    let lbl     = cstr_or(label, "");
    let pw      = cstr_or(passphrase, "");
    let profile = if kdf_sensitive { 1u8 } else { 0u8 };

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let keys_dir = std::path::PathBuf::from(home)
        .join(".config").join("venom").join("keys");
    if let Err(e) = std::fs::create_dir_all(&keys_dir) {
        set_error(&e.to_string(), error_out);
        return std::ptr::null_mut();
    }

    let key = vnmcore::hybrid_generate();
    let fp_hex: String = key.public.fingerprint().iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let path = keys_dir.join(format!("{fp_hex}.key"));

    let result = if pw.is_empty() {
        vnmcore::write_key_file(&path, &key, lbl)
    } else {
        vnmcore::write_key_file_protected(&path, &key, lbl, pw.as_bytes(), profile)
    };

    match result {
        Ok(_) => {
            let s = path.to_string_lossy().into_owned();
            match std::ffi::CString::new(s) {
                Ok(cs) => cs.into_raw(),
                Err(e) => { set_error(&e.to_string(), error_out); std::ptr::null_mut() }
            }
        }
        Err(e) => { set_error(&e.to_string(), error_out); std::ptr::null_mut() }
    }
}

/// Export the public portion of a .key as a .pub file.
#[no_mangle]
pub extern "C" fn vnm_key_export_pub(
    key_path: *const c_char, pub_path: *const c_char, _key_passphrase: *const c_char,
    error_out: *mut *mut c_char,
) -> bool {
    clear_error(error_out);
    let (Some(kp), Some(pp)) = (cstr(key_path), cstr(pub_path)) else { return false; };
    let pub_data = match read_key_public(std::path::Path::new(kp)) {
        Ok(d)  => d,
        Err(e) => { set_error(&e.to_string(), error_out); return false; }
    };
    match vnmcore::write_pub_file(std::path::Path::new(pp), &pub_data.public, &pub_data.label, pub_data.created_at) {
        Ok(_)  => true,
        Err(e) => { set_error(&e.to_string(), error_out); false }
    }
}

// ── Key store listing ─────────────────────────────────────────────────────────

/// Info for one key entry (FFI-safe, fixed-size).
#[repr(C)]
pub struct VnmKeyInfo {
    pub fingerprint:  [u8; 24],
    pub label:        [u8; 128],
    pub filename:     [u8; 256],  // actual filename in the key store (e.g. "alice.pub")
    pub created_at:   u64,
    pub is_protected: bool,
    pub is_pub_only:  bool,       // true for .pub files (no private key)
}

fn fill(buf: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&b[..n]);
    buf[n] = 0;
}

// (fingerprint, label, filename, created_at, is_protected, is_pub_only)
pub struct VnmKeyList {
    entries: Vec<(String, String, String, u64, bool, bool)>,
}

#[no_mangle]
pub extern "C" fn vnm_keylist_load() -> *mut VnmKeyList {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir  = std::path::PathBuf::from(home).join(".config").join("venom").join("keys");
    let mut v = vec![];
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for item in rd.flatten() {
            let p = item.path();
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            match p.extension().and_then(|e| e.to_str()) {
                Some("key") => {
                    if let Ok(d) = read_key_public(&p) {
                        v.push((fp_display(&d.public.fingerprint()), d.label, fname, d.created_at, d.is_protected, false));
                    }
                }
                Some("pub") => {
                    if let Ok(d) = vnmcore::read_pub_file(&p) {
                        v.push((fp_display(&d.public.fingerprint()), d.label, fname, d.created_at, false, true));
                    }
                }
                _ => {}
            }
        }
    }
    v.sort_by(|a, b| b.3.cmp(&a.3));
    Box::into_raw(Box::new(VnmKeyList { entries: v }))
}

#[no_mangle]
pub extern "C" fn vnm_keylist_free(list: *mut VnmKeyList) {
    if !list.is_null() { unsafe { drop(Box::from_raw(list)); } }
}

#[no_mangle]
pub extern "C" fn vnm_keylist_count(list: *const VnmKeyList) -> usize {
    if list.is_null() { return 0; }
    unsafe { (*list).entries.len() }
}

#[no_mangle]
pub extern "C" fn vnm_keylist_get(list: *const VnmKeyList, i: usize, out: *mut VnmKeyInfo) -> bool {
    if list.is_null() || out.is_null() { return false; }
    let entries = unsafe { &(*list).entries };
    if i >= entries.len() { return false; }
    let (fp, lbl, fname, ts, prot, pub_only) = &entries[i];
    let info = unsafe { &mut *out };
    fill(&mut info.fingerprint, fp);
    fill(&mut info.label, lbl);
    fill(&mut info.filename, fname);
    info.created_at   = *ts;
    info.is_protected = *prot;
    info.is_pub_only  = *pub_only;
    true
}

/// Read public metadata from a .key or .pub file (no passphrase needed).
/// Returns false if the file cannot be read or is not a valid Venom key file.
#[no_mangle]
pub extern "C" fn vnm_key_read_info(
    key_path: *const c_char,
    info_out:  *mut VnmKeyInfo,
) -> bool {
    if key_path.is_null() || info_out.is_null() { return false; }
    let Some(kp) = cstr(key_path) else { return false; };
    let path = std::path::Path::new(kp);

    // Try .key first (read_key_public), then .pub (read_pub_file)
    let (fp, label, created_at, is_protected, is_pub_only) =
        if let Ok(d) = read_key_public(path) {
            (fp_display(&d.public.fingerprint()), d.label, d.created_at, d.is_protected, false)
        } else if let Ok(d) = vnmcore::read_pub_file(path) {
            (fp_display(&d.public.fingerprint()), d.label, d.created_at, false, true)
        } else {
            return false;
        };

    let info = unsafe { &mut *info_out };
    *info = VnmKeyInfo {
        fingerprint:  [0; 24],
        label:        [0; 128],
        filename:     [0; 256],
        created_at,
        is_protected,
        is_pub_only,
    };
    fill(&mut info.fingerprint, &fp);
    fill(&mut info.label,       &label);
    fill(&mut info.filename,    path.file_name().and_then(|n| n.to_str()).unwrap_or(""));
    true
}
