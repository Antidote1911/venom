# Venom — Project Status

> Last updated: 2026-06-02

## What is Venom?

Venom is a cryptographic container filesystem written in Rust, in the style of CryFS.
A vault is a **directory of individually-encrypted block files** (not a single opaque
blob). Each file stored inside the vault becomes one or more encrypted `.blk` blocks,
and the directory tree is itself encrypted — an attacker who sees the vault directory
cannot tell how many files exist, their names, or their sizes.

### Workspace layout

```
venom/
├── vnmcore/      Core library: crypto, block store, virtual filesystem, FUSE driver
│   ├── src/
│   │   ├── container/   VaultConfig, CipherAlgorithm, KdfParams, block header
│   │   ├── crypto/      keys, KDF (Argon2id), cipher (AES-GCM / ChaCha20)
│   │   ├── storage/     BlockStore, VaultNode, DirectoryBlock, FileBlock
│   │   └── fs/          Vault API, FUSE driver (op_* + Filesystem trait)
│   ├── tests/           56 integration tests
│   └── examples/        mount_test — diagnostic CLI tool
└── venom/        GUI application (egui 0.28 / eframe)
    └── src/
        ├── app/         state, actions
        ├── ui/          theme, topbar, vault_list, create, mount, statusbar
        └── recent.rs    recent-vaults persistence
```

---

## Done

### vnmcore — Core library

- [x] **Container format** (`vnm_bootstrap.json` + `vnm_config.enc` + `blocks/`)
  - Bootstrap file stores KDF params + cipher in plaintext (needed to derive key)
  - Config block stores root UUID, label, creation timestamp — encrypted
  - Block files: `blocks/<xx>/<uuid>.blk` — magic header + nonce + AEAD ciphertext + tag
  - Block UUID used as AAD → swapping blocks between vaults is detected

- [x] **Ciphers** — ChaCha20-Poly1305 and AES-256-GCM (chosen at vault creation)
- [x] **Key derivation** — Argon2id, two profiles:
  - Interactive: 64 MiB / 3 iterations (< 1 s on modern hardware)
  - Sensitive: 256 MiB / 4 iterations (2–5 s)
- [x] **Key types** — `MasterKey` / `DerivedKey` both `ZeroizeOnDrop`
- [x] **Block store** — two-level bucketing (`blocks/<xx>/`) to limit directory entries
- [x] **Virtual filesystem nodes** — `DirectoryBlock`, `FileBlock`, continuation blocks
- [x] **Vault API** — `Vault::create`, `Vault::open`, `read_node`, `write_node`, `update_node`

### FUSE driver (Linux / macOS)

- [x] **op_* architecture** — each FUSE operation has a pure `op_*()` method returning
  `Result<T, libc_errno>` (testable without mounting), and a thin `Filesystem` wrapper
- [x] **Read operations** — `lookup`, `getattr`, `readdir`, `read`
- [x] **Write operations** — `mkdir`, `rmdir`, `create`, `unlink`, `rename`, `write`,
  `setattr` (truncate / extend)
- [x] **In-memory file cache**
  - `open` decrypts all blocks into a `Vec<u8>` — subsequent reads/writes hit RAM only
  - `write` patches the buffer, sets `dirty = true`
  - `flush` / `release` re-encrypts and writes blocks only if dirty
  - `Drop` impl calls `flush_all()` as a safety net
  - `getattr` returns cached size for open dirty files (keeps kernel metadata consistent)
- [x] **Multi-block files** — files > 30 KB are split across continuation blocks;
  old continuation blocks are deleted on every flush
- [x] **Unmount** — `fusermount3` → `fusermount` fallback on Linux; `umount` on macOS
- [x] **Mount options hardened** — `AllowOther` and `AutoUnmount` removed; both require
  elevated privileges or `/etc/fuse.conf` on Arch/modern Linux and caused EPERM for
  unprivileged users. Mounts are owner-only by design.
- [x] **Diagnostic example** — `cargo run -p vnmcore --example mount_test` to test
  FUSE independently of the GUI

### Tests — 56 total, all passing

| Suite | Count | Covers |
|-------|------:|--------|
| `crypto_tests` | 8 | ChaCha20/AES round-trip, wrong key, AAD swap, tampered bits, KDF determinism, nonce uniqueness |
| `vault_tests` | 7 | create/open both ciphers, wrong password rejected, root block, directory/file block CRUD, duplicate vault |
| `fuse_cache_tests` | 12 | cache lifecycle: open, dirty flag, flush, no-op flush, release, Drop, multi-flush cycle, unlink eviction, two-fh conflict |
| `fuse_ops_tests` | 29 | mkdir/rmdir, create/unlink, write+flush+read, cross-close persistence, multiblock (75 KB), rename same/cross dir, setattr truncate/extend, full tree, vault reopen |

### GUI (egui 0.28)

#### Mount lifecycle
- [x] **Async mount** — dedicated thread per mount (`vnm-mount:<mp>`); KDF + FUSE
  never block the UI thread
- [x] **Mount status machine** — `Mounting` (spinner) → `Mounted` (green) →
  `Gone` (clean unmount, auto-removed) → `Error` (red, dismissable)
- [x] **`Arc<Mutex<MountStatus>>`** shared between UI and mount thread; thread calls
  `ctx.request_repaint()` on every state change
- [x] **Duplicate mountpoint guard** — rejects second mount to the same path
- [x] **Unmount** — `action_unmount` calls `fusermount3` → `fusermount` fallback;
  returns `Result<(), String>`; card stays if unmount fails with error in status bar
- [x] **`MountStatus::Gone`** — mount thread sets this on clean `driver::mount()` return;
  `gc_gone_mounts()` removes the card on the next frame tick
- [x] **`Dismiss error`** — remove failed vault cards without unmounting

#### Open folder
- [x] **Path existence check** — verifies mountpoint exists before launching
- [x] **Fallback chain** — `xdg-open` → `nautilus` → `dolphin` → `thunar` →
  `nemo` → `pcmanfm` → `caja` (skips `NotFound`, reports other errors)
- [x] **Status feedback** — shows which binary was used on success, or the error

#### Recent vaults (`~/.config/venom/recent.json`)
- [x] **Persistence** — up to 10 entries, JSON, auto-saved on every change
- [x] **Progressive enrichment** — cipher read from `vnm_bootstrap.json` immediately
  (no KDF); label synced by `update()` once mount thread reports `Mounted`
- [x] **Vault list — empty state** — hero icon + "Recent Vaults" section; each row
  shows name, path, cipher pill, last-used date; `[Mount]` fills path + navigates;
  `[✕]` removes entry; row greyed + button disabled if directory not found
- [x] **Vault list — non-empty state** — unmounted recent vaults shown below active cards
- [x] **Mount form** — "Recent Vaults" quick-fill panel; click row fills vault path;
  selected row highlighted; entries marked "not found" are non-clickable

#### UI design
- [x] **Dark theme** — custom palette via `egui::Visuals` + `egui::Style`
  (`BG` / `PANEL` / `CARD` / `ACCENT` / `SUCCESS` / `WARN` / `ERROR` / `BTN_*`)
- [x] **Topbar** — mounted count badge (green), connecting spinner (yellow)
- [x] **Create view** — two-column layout, inline password match indicator (✓/✗),
  KDF profile cards with visual selection, primary button disabled until form is valid
- [x] **Mount view** — two-column layout with "How it works" and "Prerequisites" panels
- [x] **Vault list cards** — status-aware border colour, cipher pill, creation date,
  "read-write" label, sized action buttons

---

## In progress / not started

### Security

- [ ] **Password zeroization in GUI** — `MountView::password` is a plain `String`;
  it should be a `zeroize::Zeroizing<String>` or cleared immediately after the thread
  receives its copy
- [ ] **`action_create_vault` is synchronous** — KDF blocks the UI thread during vault
  creation; should mirror the async mount pattern (spawn thread, show spinner)
- [ ] **Key stretching audit** — verify no key material leaks through stack copies
  during cipher operations

### FUSE / filesystem

- [ ] **FUSE write operations are not atomic** — a crash between deleting old
  continuation blocks and writing new ones can corrupt the vault; needs a
  write-ahead log or copy-on-write approach
- [ ] **Directory entry ordering** — entries stored in insertion order; no sorting
  or deduplication beyond the `EEXIST` guard
- [ ] **Hard links / symlinks** — `link` and `symlink` ops not implemented
- [ ] **Extended attributes** — `getxattr` / `setxattr` not implemented
- [ ] **File timestamps** — `atime` / `mtime` / `ctime` always `UNIX_EPOCH`; no
  persistent timestamp storage in blocks
- [ ] **Permissions** — `perm` hardcoded (0o755 / 0o644); no persistent ACL storage
- [ ] **`opendir` / `releasedir`** — no directory-level file handles; `readdir` always
  re-reads from disk
- [ ] **Large directory performance** — `readdir` deserializes the directory block on
  every call; no directory entry cache
- [ ] **Windows support** — FUSE layer is `#[cfg(target_family = "unix")]` only;
  WinFsp / Dokan integration not started

### Vault format

- [ ] **Vault integrity manifest** — no global checksum of block UUIDs; an attacker
  could silently delete blocks without detection
- [ ] **Vault metadata hiding** — `vnm_bootstrap.json` reveals KDF parameters and
  cipher algorithm; consider encrypting or using fixed dummy values
- [ ] **Configurable block size** — `DEFAULT_BLOCK_SIZE = 32768` is hardcoded;
  the field exists in `VaultConfig` but is not exposed in the create form
- [ ] **Deduplication** — fresh nonce per encrypt means identical plaintexts produce
  different ciphertexts; no dedup (intentional for security, increases storage)

### GUI

- [ ] **Vault browser** — once mounted, show the decrypted directory tree inside
  the app (file manager panel)
- [ ] **Tray icon** — system-tray indicator showing mounted vault count; unmount
  from tray menu
- [ ] **Auto-unmount on idle** — unmount after N minutes without activity
- [ ] **Mount from CLI** — `venom mount <vault> <mp> [--password-stdin]` for
  scripted / headless use
- [ ] **Progress bar during create** — KDF progress is opaque; show a deterministic
  progress estimate or at least a spinner
- [ ] **Windows FUSE indicator** — on Windows, explain FUSE is unavailable and
  point to the roadmap

### Testing & CI

- [ ] **Property-based tests** — use `proptest` to fuzz block crypto with random
  plaintexts, offsets, and sizes
- [ ] **FUSE mount smoke test** — a CI job that mounts a test vault, writes a file
  via the OS, reads it back, and unmounts (requires a Linux runner with FUSE enabled)
- [ ] **Benchmarks** — block encrypt/decrypt throughput for both ciphers; KDF timing

### Distribution

- [ ] **GitHub Actions CI** — `cargo test` + `cargo clippy` + `cargo fmt --check`
  on every push
- [ ] **Release packaging** — Flatpak / AppImage for Linux, `.app` for macOS
- [ ] **`CHANGELOG.md`** and semantic versioning

---

## Known limitations

1. **Single-process mount** — the FUSE thread and GUI share the same process. If
   the GUI crashes, the mount thread is killed. The `Drop` flush runs for normal
   exits, but a `SIGSEGV` skips it and dirty cached data is lost.
2. **Owner-only mounts** — `AllowOther` was removed to support unprivileged use;
   other users on the same machine cannot access the mountpoint.
3. **Full-file RAM loading** — entire files are loaded into memory on `open()`. A
   1 GB file consumes 1 GB of RSS. Streaming / lazy loading is not implemented.
4. **Password copy in thread** — password bytes are cloned into the mount thread as
   `Vec<u8>` and dropped after `Vault::open`. No explicit `zeroize` call on the copy.
5. **Recent list stores plaintext paths** — `~/.config/venom/recent.json` reveals
   vault directory paths. No vault content is leaked, but the existence and location
   of vaults is visible to anyone with read access to the home directory.
