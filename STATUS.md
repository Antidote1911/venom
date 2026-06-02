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
└── venom/        GUI application (egui / eframe)
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

### Tests — 56 total, all passing

| Suite | Count | Covers |
|-------|------:|--------|
| `crypto_tests` | 8 | ChaCha20/AES round-trip, wrong key, AAD swap, tampered bits, KDF determinism, nonce uniqueness |
| `vault_tests` | 7 | create/open both ciphers, wrong password rejected, root block, directory/file block CRUD, duplicate vault |
| `fuse_cache_tests` | 12 | cache lifecycle: open, dirty flag, flush, no-op flush, release, Drop, multi-flush cycle, unlink eviction, two-fh conflict |
| `fuse_ops_tests` | 29 | mkdir/rmdir, create/unlink, write+flush+read, cross-close persistence, multiblock (75 KB), rename same/cross dir, setattr truncate/extend, full tree, vault reopen |

### GUI (egui 0.28)

- [x] **Async mount** — dedicated thread per mount; KDF + FUSE never block the UI thread
- [x] **Mount status** — `Mounting` (spinner) → `Mounted` (green) → `Error` (red)
- [x] **`Arc<Mutex<MountStatus>>`** shared between UI and mount thread; thread calls
  `ctx.request_repaint()` on status change
- [x] **Duplicate mountpoint guard**
- [x] **Unmount** — calls `fusermount3`/`fusermount`/`umount`; removes card from list
- [x] **Open folder** — `xdg-open` (Linux) / `open` (macOS) / `explorer` (Windows)
- [x] **Dismiss error** — remove failed vault cards without unmounting
- [x] **Create view** — two-column layout, password match indicator, profile cards,
  primary button disabled until inputs are valid
- [x] **Mount view** — two-column layout with info and prerequisite panels
- [x] **Vault list** — status-aware cards, cipher pill badge, creation date,
  "read-write" label when mounted
- [x] **Dark theme** — custom palette via `egui::Visuals` + `egui::Style`
- [x] **Topbar** — mounted count badge, connecting spinner

---

## In progress / not started

### Security

- [ ] **Password zeroization in GUI** — `MountView::password` is a plain `String`;
  it should be a `zeroize::Zeroizing<String>` or cleared immediately after the thread
  receives its copy
- [ ] **`action_create_vault` is synchronous** — KDF blocks the UI thread during
  creation; should mirror the async mount pattern
- [ ] **Key stretching audit** — verify no key material leaks through stack copies
  during cipher operations

### FUSE / filesystem

- [ ] **FUSE write operations are not atomic** — a crash between deleting old
  continuation blocks and writing new ones can corrupt the vault; needs a
  write-ahead log or copy-on-write approach
- [ ] **Directory entry ordering** — entries are stored in insertion order; no
  sorting or deduplication beyond the EEXIST guard
- [ ] **Hard links / symlinks** — not implemented (`link`, `symlink` ops missing)
- [ ] **Extended attributes** — `getxattr`, `setxattr` not implemented
- [ ] **File timestamps** — `atime`/`mtime`/`ctime` are always `UNIX_EPOCH`; no
  persistent timestamp storage in blocks
- [ ] **Permissions** — `perm` is hardcoded (0o755 / 0o644); no persistent ACL storage
- [ ] **`opendir` / `releasedir`** — no directory-level file handles; readdir always
  re-reads from disk
- [ ] **Large directory performance** — readdir reads and deserializes the directory
  block on every call; no directory entry cache
- [ ] **Windows support** — FUSE layer is `#[cfg(target_family = "unix")]` only;
  WinFsp / Dokan integration not started

### Vault format

- [ ] **Vault integrity manifest** — no global checksum of all block UUIDs; an
  attacker could silently delete blocks
- [ ] **Vault metadata hiding** — `vnm_bootstrap.json` reveals the KDF parameters
  and cipher algorithm; consider encrypting or standardising these values
- [ ] **Block size configuration** — `DEFAULT_BLOCK_SIZE = 32768` is hardcoded in
  `VaultConfig`; the field exists but is not wired to the create form
- [ ] **Deduplication** — identical plaintexts always produce different ciphertexts
  (fresh nonce); no deduplication, which is intentional but increases size

### GUI

- [ ] **Vault browser** — once mounted, show the decrypted directory tree inside
  the app (file manager panel)
- [ ] **Recent vaults list** — persist recently used vault paths to a config file
  (`~/.config/venom/config.toml`) so they can be mounted without re-browsing
- [ ] **Tray icon** — system-tray indicator showing mounted vault count; allow
  unmount from tray menu
- [ ] **Auto-unmount on idle** — unmount after N minutes of inactivity
- [ ] **Mount from CLI** — `venom mount <vault> <mp> [--password-stdin]` for
  scripted / headless use
- [ ] **Windows FUSE indicator** — when running on Windows, explain that FUSE is
  not yet available and point to the roadmap
- [ ] **Progress bar during create** — KDF progress is opaque; show a deterministic
  progress estimate

### Testing & CI

- [ ] **Property-based tests** — use `proptest` to fuzz block crypto with random
  plaintexts, offsets, and sizes
- [ ] **Actual FUSE mount smoke test** — a CI job that mounts a test vault, writes
  a file via the OS, reads it back, and unmounts (requires a Linux runner with FUSE)
- [ ] **Benchmarks** — block encrypt/decrypt throughput for both ciphers; KDF timing

### Distribution

- [ ] **GitHub Actions CI** — `cargo test` + `cargo clippy` + `cargo fmt --check`
  on push
- [ ] **Release packaging** — Flatpak / AppImage for Linux, `.app` for macOS
- [ ] **`CHANGELOG.md`** and semantic versioning

---

## Known limitations

1. **Single-process mount** — the FUSE thread and GUI share the same process. If
   the GUI crashes, the mount thread is killed and the filesystem is lost (the
   Drop flush runs, but a SIGSEGV skips it).
2. **No multi-user access** — `AllowOther` is set, but concurrent access from
   multiple processes to the same block is not safe (no locking at the block level).
3. **Memory usage** — entire files are loaded into RAM on open. A 1 GB file will
   consume 1 GB of RSS. Streaming / lazy loading is not implemented.
4. **Password in thread** — the password bytes are copied into the mount thread as
   `Vec<u8>` and dropped after `Vault::open`. No explicit zeroize call on the copy.
