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
- [x] **`FOPEN_DIRECT_IO`** — set in `open()` and `create()` replies, bypasses the
  kernel page cache entirely. Without this flag the kernel buffers dirty pages and
  flushes them using `fh = 0` (no file handle); our fallback path would hit EIO.
  Fix eliminates the GIO `.goutputstream-*` residue bug and the "erreur
  d'entrée/sortie" shown by Thunar/XFCE after creating a new file.
- [x] **`statfs()`** — reports a large virtual disk (~512 GB free) so file managers
  don't interpret the default fuser `bavail = 0` as "no space left" and refuse
  to create files.
- [x] **Mount options hardened** — `AllowOther` removed (requires `user_allow_other`
  in `/etc/fuse.conf` → EPERM for unprivileged users); `AutoUnmount` removed (same
  issue on Arch / modern kernels). Mounts are owner-only. Unmount via
  `fusermount3 -u <mp>` or the GUI button.
- [x] **Diagnostic example** — `cargo run -p vnmcore --example mount_test`

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
- [x] **Mount status machine** — `Mounting` → `Mounted` → `Gone` (auto-removed) →
  `Error` (red, dismissable)
- [x] **`Arc<Mutex<MountStatus>>`** shared with mount thread; thread calls
  `ctx.request_repaint()` on every state change
- [x] **Duplicate mountpoint guard**
- [x] **Unmount** — `fusermount3` → `fusermount` fallback; returns `Result<(), String>`;
  card stays visible if unmount fails, with error in status bar
- [x] **`MountStatus::Gone`** — set by thread on clean `driver::mount()` return;
  `gc_gone_mounts()` removes the card on the next frame tick
- [x] **Dismiss error** — remove failed vault cards

#### Open folder
- [x] **Path existence check** before launching
- [x] **Fallback chain** — `xdg-open` → `nautilus` → `dolphin` → `thunar` →
  `nemo` → `pcmanfm` → `caja`
- [x] **Status feedback** — shows binary used on success, error message on failure

#### Recent vaults (`~/.config/venom/recent.json`)
- [x] Persist up to 10 entries, deduplication, JSON
- [x] Cipher read from `vnm_bootstrap.json` immediately (no KDF needed)
- [x] Label synced by `update()` once mount thread reports `Mounted`
- [x] Vault list empty state: recent section with `[Mount]` and `[✕]` per row
- [x] Vault list non-empty: unmounted recent vaults shown at the bottom
- [x] Mount form: quick-fill panel (click row → fills vault path)
- [x] Rows greyed and unclickable when vault directory not found on disk

#### UI design
- [x] Custom dark theme (`theme.rs`) — `BG / PANEL / CARD / ACCENT / SUCCESS / WARN / ERROR / BTN_*`
- [x] Topbar — mounted count badge, connecting spinner
- [x] Create view — two-column layout, password match indicator, KDF profile cards,
  primary button disabled until form is valid
- [x] Mount view — two-column layout with "How it works" and "Prerequisites" panels
- [x] Vault list cards — status-aware border colour, cipher pill, creation date,
  "read-write" label, sized buttons

---

## In progress / not started

### Container format

- [ ] **Single-file container (VeraCrypt style)** — present the vault as one opaque
  file instead of a directory of block files. Requires a new `SingleFileBlockStore`
  that addresses blocks by slot offset within the file. The GUI would add a
  "Container type" selector (Directory / Single file) and a "Max size" field in
  the Create view. Both formats would be auto-detected on open.
  Comparison vs current approach:
  - ✓ Single opaque blob, easy to transport/backup
  - ✓ No plaintext directory structure visible
  - ✗ Must be pre-allocated (or use sparse file)
  - ✗ Not cloud-sync friendly (whole file changes on any write)
  - Estimated effort: ~2 weeks

- [ ] **Vault integrity manifest** — no global checksum of block UUIDs; an attacker
  could silently delete blocks without detection
- [ ] **Vault metadata hiding** — `vnm_bootstrap.json` reveals KDF parameters and
  cipher algorithm
- [ ] **Configurable block size** — `DEFAULT_BLOCK_SIZE = 32768` is hardcoded;
  the field exists in `VaultConfig` but is not exposed in the Create form
- [ ] **Deduplication** — fresh nonce per encrypt; no dedup (intentional for security)

### Security

- [ ] **Password zeroization in GUI** — `MountView::password` is a plain `String`;
  should be `zeroize::Zeroizing<String>` or cleared immediately after being copied
  into the mount thread
- [ ] **`action_create_vault` is synchronous** — KDF blocks the UI thread during
  creation; should mirror the async mount pattern
- [ ] **Key stretching audit** — verify no key material leaks through stack copies
  during cipher operations

### FUSE / filesystem

- [ ] **Write operations are not atomic** — a crash between deleting old continuation
  blocks and writing new ones can corrupt the vault; needs write-ahead log or CoW
- [ ] **Directory entry ordering** — entries stored in insertion order; no sorting
- [ ] **Hard links / symlinks** — `link` and `symlink` not implemented
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

### GUI

- [ ] **Vault browser** — once mounted, show the decrypted directory tree inside
  the app (file manager panel)
- [ ] **Tray icon** — system-tray indicator showing mounted vault count
- [ ] **Auto-unmount on idle** — unmount after N minutes without activity
- [ ] **Mount from CLI** — `venom mount <vault> <mp> [--password-stdin]`
- [ ] **Progress bar during create** — KDF progress is opaque; show a spinner at
  minimum, or a deterministic progress estimate

### Testing & CI

- [ ] **Property-based tests** — `proptest` to fuzz block crypto with random
  plaintexts, offsets, and sizes
- [ ] **FUSE mount smoke test** — CI job that mounts a vault, writes a file via OS,
  reads back, unmounts (requires Linux runner with FUSE)
- [ ] **Benchmarks** — block encrypt/decrypt throughput; KDF timing

### Distribution

- [ ] **GitHub Actions CI** — `cargo test` + `cargo clippy` + `cargo fmt --check`
- [ ] **Release packaging** — Flatpak / AppImage for Linux, `.app` for macOS
- [ ] **`CHANGELOG.md`** and semantic versioning

---

## Known limitations

1. **Single-process mount** — if the GUI crashes, the mount thread is killed. The
   `Drop` flush runs for clean exits; a `SIGSEGV` skips it and dirty data is lost.
2. **Owner-only mounts** — `AllowOther` was removed to support unprivileged users;
   other users on the same machine cannot access the mountpoint.
3. **Full-file RAM loading** — entire files are loaded into memory on `open()`. A
   1 GB file consumes 1 GB of RSS. Streaming / lazy loading is not implemented.
4. **Password copy in thread** — password bytes are cloned into the mount thread as
   `Vec<u8>` and dropped after `Vault::open`. No explicit `zeroize` call on the copy.
5. **Recent list stores plaintext paths** — `~/.config/venom/recent.json` reveals
   vault directory locations. No vault content is leaked, but vault existence and
   location are visible to anyone with read access to the home directory.
6. **`.goutputstream-*` residue** — GIO (Thunar/XFCE, gedit, etc.) uses atomic saves
   (create temp → write → rename). Any operation that fails mid-way leaves a
   `.goutputstream-XXXXXX` file in the vault. This was most commonly triggered by
   the EIO bug (now fixed with `FOPEN_DIRECT_IO`). Existing residues can be removed
   with `find <mountpoint> -name '.goutputstream-*' -delete`.
