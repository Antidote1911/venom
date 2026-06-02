# Venom — Project Status

> Last updated: 2026-06-02

## What is Venom?

Venom is a cryptographic container filesystem written in Rust, inspired by VeraCrypt.
A container is a **single opaque file** (`.vnm`). Its entire content is encrypted —
an attacker who sees the file cannot determine how many files are stored inside, their
names, sizes, or directory structure. The same file can host two independent volumes
(plausible deniability).

### Workspace layout

```
venom/
├── vnmcore/      Core library: crypto, slot store, virtual filesystem, FUSE driver
│   ├── src/
│   │   ├── container/   CipherAlgorithm, KdfParams, on-disk header format
│   │   ├── crypto/      Argon2id KDF, AES-256-GCM / ChaCha20-Poly1305 AEAD
│   │   ├── storage/     SlotStore, VaultNode, DirectoryBlock, FileBlock
│   │   └── fs/          VnmContainer API, FUSE driver (op_* + Filesystem trait)
│   ├── tests/           25 integration tests
│   └── examples/        mount_test — diagnostic CLI tool
└── venom/        GUI application (egui 0.28 / eframe)
    └── src/
        ├── app/         state, actions
        ├── ui/          theme, topbar, vault_list, create, mount, statusbar
        └── recent.rs    recent-containers persistence (~/.config/venom/recent.json)
```

---

## Done

### Container format — `.vnm` single file

```
[0..512]     Outer header  — encrypted with outer password
[512..1024]  Hidden header — encrypted with hidden password (random bytes if unused)
[1024..]     Data area: fixed-size slots (32 KB each)
             Outer volume:  slots [0..outer_limit)  (slot 0 = alloc bitmap)
             Hidden volume: slots [outer_limit..N)  (slot N-1 = hidden alloc bitmap)
```

- [x] **Slot on-disk layout** — `u32_LE(encrypted_len)` prefix + VNMB block
  (magic + version + nonce + ciphertext + AEAD tag) + zero padding to 32 KB.
  Length prefix required so `decrypt_block` finds the exact AEAD tag boundary
  (not the last 16 bytes of the 32 KB buffer which would be padding zeros).
- [x] **Header format** — 512 bytes each:
  `salt(32) + cipher_id(1) + KDF_params(12) + nonce(12) + encrypted_body(439 B)`
  KDF params stored outside the encrypted region so the key can be derived before
  decryption. AAD distinguishes header type (`vnm:outer:v1` / `vnm:hidden:v1`).
- [x] **Slot encryption** — master key (random 32 bytes, stored encrypted in header);
  slot index as AAD → prevents cross-volume slot substitution attacks.
- [x] **Allocation bitmap** — compact bit-per-slot bitmap in slot 0 (outer) and
  last slot (hidden). Replaces the naive `Vec<u64>` free list which would exceed
  32 KB for containers ≥ ~500 MB ("plaintext too large for one slot" fix).
  Bitmap size: 500 MB → 2 KB; 8 GB → 32 KB (practical per-volume size limit).
- [x] **Pre-allocation with random bytes** — required for plausible deniability;
  ensures the entire file looks like random data before headers are written.
- [x] **Ciphers** — ChaCha20-Poly1305 and AES-256-GCM (chosen at creation)
- [x] **Key derivation** — Argon2id, two profiles:
  - Interactive: 64 MiB / 3 iterations (< 1 s)
  - Sensitive: 256 MiB / 4 iterations (2–5 s)
- [x] **Block IDs** — `u64` slot indices (replaced UUID strings from the old
  multi-file format; propagated through `VaultNode`, FUSE InodeMap, tests)

### Hidden volume (plausible deniability)

- [x] **Two-password design** — same `.vnm` file, two independent encrypted volumes.
  Outer password → outer filesystem. Hidden password → hidden filesystem.
  Neither volume can prove the other exists.
- [x] **Independent master keys** — each volume has its own random 32-byte master key
  stored in its header; slots of one volume cannot be decrypted with the other's key.
- [x] **Automatic detection in `VnmContainer::open`** — tries outer header first,
  then hidden header. The caller just provides a password; the correct volume is
  selected transparently.
- [x] **Slot partitioning** — outer uses slots `[0..outer_limit)`,
  hidden uses `[outer_limit..total_slots)`. Each volume is unaware of the other.
- [x] **GUI** — Create form includes a collapsible "Hidden volume" section (size,
  label, passphrase + confirm).

### VnmContainer API

- [x] `VnmContainer::create(path, password, size_bytes, cipher, kdf, label, hidden_opts)`
- [x] `VnmContainer::open(path, password)` — auto-detects outer / hidden
- [x] `read_node(slot)`, `write_node(node)`, `update_node(slot, node)`, `free_node(slot)`
- [x] `flush()` — persists allocation bitmap + file buffers to disk

### FUSE driver (Linux / macOS)

- [x] **op_* architecture** — pure business-logic methods returning `Result<T, errno>`,
  testable without FUSE mount; thin `Filesystem` wrappers call them.
- [x] **Read** — `lookup`, `getattr`, `readdir`, `read`
- [x] **Write** — `mkdir`, `rmdir`, `create`, `unlink`, `rename`, `write`, `setattr`
- [x] **In-memory file cache** per open file handle:
  `open` → decrypt all slots into `Vec<u8>` · `write` → patch + dirty · `flush`/`release` → persist only if dirty · `Drop` → `flush_all()`
- [x] **Multi-slot files** — files > 30 KB split across continuation slots;
  old continuation slots freed (wiped) and reallocated on flush.
- [x] **`FOPEN_DIRECT_IO`** — bypasses kernel page cache; eliminates the `fh=0`
  writeback path that caused EIO (Thunar/XFCE "erreur d'entrée/sortie" bug).
- [x] **`statfs()`** — reports actual free slots; prevents "no space left" false errors.
- [x] **Forward secrecy on free** — freed slots are overwritten with random bytes
  before being marked available.
- [x] **Mount options** — `AllowOther` and `AutoUnmount` removed (both require
  elevated privileges on modern Linux → EPERM for unprivileged users).
- [x] **`mount_test` example** — `cargo run -p vnmcore --example mount_test <file> <mp>`

### Tests — 25 total, all passing

| Suite | Count | Covers |
|-------|------:|--------|
| `crypto_tests` | 8 | ChaCha20/AES round-trip, wrong key, AAD binding, tamper detection, KDF determinism, nonce uniqueness |
| `container_tests` | 9 | create/open both ciphers, wrong password, root dir, CRUD nodes, data persistence after flush, hidden volume create + both-password mount, outer/hidden data independence |
| `fuse_cache_tests` (inline) | 8 | cache lifecycle: open, dirty flag, flush, Drop flush, op_mkdir, op_create+write+release+open+read, op_unlink, op_rename |

> Note: test count dropped from 56 to 25 because the old multi-file format tests
> (`vault_tests`, `fuse_ops_tests`) were replaced by the new `container_tests` suite.
> The 8 original `crypto_tests` are unchanged.

### GUI (egui 0.28)

#### Create
- [x] Two-column layout: path + label + size + passphrase | cipher + KDF profile + hidden volume
- [x] "Save as…" file browser for `.vnm` path
- [x] Password match indicator (✓/✗ inline)
- [x] KDF profile cards (Interactive / Sensitive)
- [x] **Hidden volume section** — collapsible; size (MB), label, passphrase + confirm;
  live validation (hidden size < total size)
- [x] "Create container" button disabled until all fields valid
- [x] Warning that large containers take time (random-fill)

#### Mount
- [x] File browser (`.vnm` filter) instead of folder picker
- [x] Single passphrase field — auto-selects outer or hidden volume
- [x] Info panel: 3-step how-it-works + hidden volume deniability note + prerequisites
- [x] Recent containers quick-fill panel

#### Mount lifecycle
- [x] Async mount thread (`vnm-mount:<mp>`); KDF + FUSE never block UI thread
- [x] Status: `Mounting` (spinner) → `Mounted` (green, shows `is_hidden` badge) →
  `Gone` (auto-removed) → `Error` (dismissable)
- [x] Vault card shows "🔐 hidden" badge when hidden volume is mounted
- [x] Duplicate mountpoint guard; `gc_gone_mounts()` each frame

#### Unmount / open folder
- [x] `fusermount3` → `fusermount` fallback; card kept if fails
- [x] `xdg-open` → `nautilus` → `dolphin` → `thunar` → `nemo` → `pcmanfm` → `caja`
- [x] Path existence check before attempting to open

#### Recent containers (`~/.config/venom/recent.json`)
- [x] Up to 10 entries; cipher read from bootstrap immediately (no KDF)
- [x] Label enriched by `update()` once mount thread reports `Mounted`
- [x] Empty state and non-empty list show recent rows with `[Mount]` / `[✕]`
- [x] Mount form quick-fill panel

#### UI design
- [x] Custom dark theme (`BG / PANEL / CARD / ACCENT / SUCCESS / WARN / ERROR / BTN_*`)
- [x] Topbar: mounted count + connecting spinner

---

## In progress / not started

### Container format / security

- [ ] **Write atomicity** — a crash between freeing old continuation slots and writing
  new ones can corrupt a file. Needs write-ahead log or copy-on-write approach.
- [ ] **Integrity manifest** — no global HMAC of the allocation bitmap or slot list;
  an attacker could silently flip bits in the bitmap to prevent access to specific slots.
- [ ] **Volume size limit** — the per-volume allocation bitmap must fit in one slot
  (32 KB − overhead = ~32 KB usable). Hard limit ≈ 8 GB per volume. Larger containers
  require a multi-slot bitmap or B-tree allocation structure.
- [ ] **Deduplication** — intentionally absent (fresh nonce per encrypt is correct),
  but documentation should clarify the storage overhead for duplicate content.
- [ ] **Password zeroization** — `CreateView::password` and `MountView::password`
  are plain `String`; should be zeroized after use in the mount/create thread.
- [ ] **Async create** — `action_create_vault` blocks the UI thread during random-fill
  and KDF (can take 10+ seconds for large containers + sensitive profile). Should
  mirror the async mount pattern with a progress indicator.

### FUSE / filesystem

- [ ] **Hard links / symlinks** — `link` and `symlink` not implemented
- [ ] **Extended attributes** — `getxattr` / `setxattr` not implemented
- [ ] **File timestamps** — `atime` / `mtime` / `ctime` always `UNIX_EPOCH`
- [ ] **Permissions** — `perm` hardcoded (0o755 / 0o644); no persistent ACL
- [ ] **Large directory performance** — `readdir` re-reads and deserializes the
  directory slot on every call; no in-memory directory cache
- [ ] **Windows support** — WinFsp / Dokan integration not started

### GUI

- [ ] **Progress bar during create** — random-fill + KDF is opaque; show at minimum
  a spinner with elapsed time
- [ ] **Outer volume "safe fill" warning** — when a container has a hidden volume,
  warn the user when the outer volume is nearing its safe capacity limit
  (`outer_limit` slots), to avoid overwriting the hidden volume
- [ ] **Vault browser panel** — show the mounted directory tree inside the app
- [ ] **Tray icon** — mounted count in system tray; unmount from tray menu
- [ ] **Auto-unmount on idle**
- [ ] **CLI mode** — `venom mount <file.vnm> <mp> [--password-stdin]`

### Testing & CI

- [ ] **Restore `fuse_ops_tests`** — 29 integration tests covering the full FUSE
  op_* surface were lost during the format migration; needs rewrite for the new
  `u64` slot-based API
- [ ] **Property-based tests** — `proptest` for crypto round-trips with random
  plaintexts, offsets, and slot indices
- [ ] **FUSE mount smoke test** — CI job: create container, mount, write file via OS,
  read back, unmount (requires Linux runner with fuse3)
- [ ] **Benchmarks** — encrypt/decrypt throughput per cipher; KDF timing per profile

### Distribution

- [ ] **GitHub Actions CI** — `cargo test` + `cargo clippy` + `cargo fmt --check`
- [ ] **Release packaging** — Flatpak / AppImage for Linux, `.app` for macOS
- [ ] **`CHANGELOG.md`** and semantic versioning

---

## Known limitations

1. **Single-process mount** — the FUSE thread shares the process with the GUI. A
   `SIGSEGV` skips the `Drop` flush and dirty cached data is lost. Normal exits
   (unmount, quit) flush correctly.
2. **Owner-only mounts** — `AllowOther` removed; other users on the same machine
   cannot access the mountpoint.
3. **Full-file RAM loading** — entire files are decrypted into memory on `open()`.
   A 500 MB file consumes 500 MB of RSS. Streaming is not implemented.
4. **Password copy in mount thread** — password bytes are cloned as `Vec<u8>` and
   dropped after `VnmContainer::open`. No explicit `zeroize` on the copy.
5. **Recent list stores plaintext paths** — `~/.config/venom/recent.json` reveals
   container file locations on disk.
6. **`.goutputstream-*` residues** — GIO (Thunar, gedit…) atomic saves create a temp
   file and rename it. Failed saves leave `.goutputstream-XXXXXX` behind. Fixed with
   `FOPEN_DIRECT_IO`; existing residues: `find <mp> -name '.goutputstream-*' -delete`.
7. **Outer volume safe-fill unenforced** — when a hidden volume exists, the GUI does
   not prevent the user from filling the outer volume past `outer_limit` slots, which
   would overwrite the hidden volume's data.
