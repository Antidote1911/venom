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
├── vnmcore/      Core library: crypto, slot store, virtual filesystem, OS drivers
│   ├── src/
│   │   ├── container/   CipherAlgorithm, KdfParams, on-disk header format
│   │   ├── crypto/      Argon2id KDF, AES-256-GCM / ChaCha20-Poly1305 AEAD
│   │   ├── storage/     SlotStore, VaultNode, DirectoryBlock, FileBlock
│   │   └── fs/          VnmContainer API, FUSE driver (Unix), WinFSP driver (Windows)
│   ├── tests/           26 integration tests
│   └── examples/        mount_test — diagnostic CLI tool
└── venom/        GUI application (egui 0.28 / eframe)
    └── src/
        ├── app/         state, actions (platform-agnostic mount dispatch)
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
  Length prefix required so `decrypt_block` finds the exact AEAD tag boundary.
- [x] **Header format** — 512 bytes each:
  `salt(32) + cipher_id(1) + KDF_params(12) + nonce(12) + encrypted_body(439 B)`.
  KDF params stored in plaintext so the key can be derived before decryption.
  AAD distinguishes header type (`vnm:outer:v1` / `vnm:hidden:v1`).
- [x] **Slot encryption** — master key (random 32 bytes, stored encrypted in header);
  slot index as AAD → prevents cross-volume slot substitution attacks.
- [x] **Allocation bitmap** — compact bit-per-slot bitmap in slot 0 (outer) and
  last slot (hidden). Replaces a `Vec<u64>` free list which exceeds the 32 KB slot
  limit for containers ≥ ~500 MB. Sizes: 500 MB → 2 KB; 8 GB → 32 KB.
- [x] **Pre-allocation with random bytes** — entire file filled with random data
  before headers are written (required for plausible deniability).
- [x] **Ciphers** — ChaCha20-Poly1305 and AES-256-GCM (chosen at creation)
- [x] **Key derivation** — Argon2id, two profiles:
  - Interactive: 64 MiB / 3 iterations (< 1 s)
  - Sensitive: 256 MiB / 4 iterations (2–5 s)
- [x] **Linked-list file chain** — `FileBlock.next_slot: Option<u64>` replaces the
  old flat `continuation_slots: Vec<u64>`. Keeps every slot payload ≤ 30 KB
  regardless of file size. Fixes crash when copying large files (e.g., MP4 videos)
  where the flat list exceeded the 32 KB slot limit.
- [x] **Serialization: MessagePack** (`rmp-serde 1.3`) replaces `bincode`.
  Uses `to_vec_named` (string field keys) — readable from any language with a
  MessagePack library (Python, Go, C#, Java…). Allocation bitmap remains custom
  binary (no serde, more compact).

### Interoperability

| Layer | Format | Notes |
|-------|--------|-------|
| Header | Custom binary (fixed layout, LE integers) | Easy to implement in any language |
| Slot crypto | Standard AEAD (AES-256-GCM or ChaCha20-Poly1305) | IETF RFCs |
| KDF | Argon2id | IETF RFC 9106 |
| VaultNode payload | MessagePack (named fields) | Libraries in 50+ languages |

### Hidden volume (plausible deniability)

- [x] **Two-password design** — same `.vnm` file, two independent encrypted volumes.
  Outer password → outer filesystem. Hidden password → hidden filesystem.
  Neither volume can prove the other exists.
- [x] **Independent master keys** — each volume has its own random 32-byte master key;
  slots of one volume cannot be decrypted with the other's key.
- [x] **Automatic detection in `VnmContainer::open`** — tries outer header first,
  then hidden. The caller provides a password; the correct volume is selected
  transparently.
- [x] **Slot partitioning** — outer `[0..outer_limit)`, hidden `[outer_limit..total)`.
  Each volume is unaware of the other.
- [x] **GUI** — Create form has a collapsible "Hidden volume" section (size, label,
  passphrase + confirm, live validation).

### VnmContainer API

- [x] `VnmContainer::create(path, password, size_bytes, cipher, kdf, label, hidden_opts)`
- [x] `VnmContainer::open(path, password)` — auto-detects outer / hidden
- [x] `read_node(slot)`, `write_node(node)`, `update_node(slot, node)`, `free_node(slot)`
- [x] `flush()` — persists allocation bitmap + file buffers to disk

### FUSE driver — Linux / macOS (`fs/fuse.rs`)

- [x] **op_* architecture** — pure business-logic methods (`Result<T, errno>`),
  testable without mounting; thin `Filesystem` wrappers call them.
- [x] **Read** — `lookup`, `getattr`, `readdir`, `read`
- [x] **Write** — `mkdir`, `rmdir`, `create`, `unlink`, `rename`, `write`, `setattr`
- [x] **In-memory file cache** — `open` loads all slots; `write` patches cache + dirty;
  `flush`/`release` persists only if dirty; `Drop` calls `flush_all()`.
- [x] **Multi-slot files** — linked-list chain; old slots wiped on flush.
- [x] **`FOPEN_DIRECT_IO`** — bypasses kernel page cache; eliminates `fh=0` writeback
  EIO (Thunar/XFCE "erreur d'entrée/sortie" bug, `.goutputstream-*` residues).
- [x] **`statfs()`** — reports real free slots × 32 KB.
- [x] **Forward secrecy on free** — freed slots overwritten with random bytes.
- [x] **Mount options** — `AllowOther` + `AutoUnmount` removed (EPERM on modern Linux).

### WinFSP driver — Windows (`fs/winfsp.rs`)

Implements `winfsp 0.13` `FileSystemContext` trait, providing a native Windows
filesystem backed by the same `.vnm` container format:

- [x] **Required methods** — `get_security_by_name`, `open`, `close`
- [x] **File operations** — `create`, `read`, `write`, `flush`, `set_file_size`,
  `get_file_info`, `set_basic_info`
- [x] **Directory operations** — `read_directory` (populates Explorer's file list)
- [x] **Delete / rename** — `set_delete` (deferred deletion via `pending_delete`),
  `cleanup` (FspCleanupDelete flag), `rename` (case-insensitive, cross-directory)
- [x] **Volume info** — `get_volume_info` reports real free space
- [x] **In-memory cache** — same `HashMap<u64, OpenFile>` pattern as FUSE;
  `Mutex<Inner>` for WinFSP's multi-threaded model
- [x] **Path resolution** — `resolve()` walks the VaultNode tree using Windows
  backslash paths (case-insensitive, compatible with Explorer and command prompt)
- [x] **Windows timestamps** — Unix seconds → FILETIME (100 ns since 1601-01-01)
- [x] **Mount point** — drive letter (`V:`) or empty directory path
- [x] **Unmount** — `net use <mp> /delete` + `winfsp.exe /unmount` fallback
- [x] **Requires** — WinFSP installed (https://winfsp.dev, free, MIT licence)

### Platform dispatch (`venom/src/app/actions.rs`)

- [x] `mount_thread()` — unified background thread for all platforms
- [x] `platform_mount()`:
  - `#[cfg(target_family = "unix")]` → FUSE
  - `#[cfg(target_os = "windows")]` → WinFSP
- [x] GUI mount form — `📄 Open file` button (blue) vs `📁 Folder…` (neutral);
  distinct labels prevent confusion between container file and mountpoint pickers.

### Tests — 26 total, all passing

| Suite | Count | Covers |
|-------|------:|--------|
| `crypto_tests` | 8 | ChaCha20/AES round-trip, wrong key, AAD binding, tamper detection, KDF determinism, nonce uniqueness |
| `container_tests` | 9 | create/open both ciphers, wrong password, root dir, CRUD nodes, data persistence, hidden volume (both-password mount), outer/hidden independence |
| `fuse_cache_tests` (inline) | 9 | cache lifecycle + **large_file_linked_chain_roundtrip** (75 KB across 3 slots, verifies linked-list fix) |

### GUI (egui 0.28)

#### Create
- [x] Two-column layout: path + label + size + passphrase | cipher + KDF + hidden volume
- [x] `💾 Save as…` file browser, auto-appends `.vnm` if extension missing
- [x] Password match indicator (✓/✗ inline)
- [x] KDF profile cards (Interactive / Sensitive)
- [x] Hidden volume section: collapsible, live size validation
- [x] "Create container" disabled until form is valid
- [x] Warning about random-fill time for large containers

#### Mount
- [x] `📄 Open file` (blue) opens `.vnm` file picker with title + "All files" fallback
- [x] `📁 Folder…` (neutral) opens directory picker for mountpoint
- [x] Single passphrase field — auto-selects outer or hidden volume
- [x] Info panel: how-it-works + hidden volume note + prerequisites
- [x] Recent containers quick-fill panel

#### Mount lifecycle
- [x] Async `mount_thread()` (all platforms); KDF + OS mount never block UI thread
- [x] Status: `Mounting` → `Mounted` (green + `🔐 hidden` badge) → `Gone` → `Error`
- [x] `gc_gone_mounts()` each frame removes cleanly-unmounted cards

#### Unmount / open folder
- [x] Linux: `fusermount3` → `fusermount` fallback
- [x] Windows: `net use /delete` → `winfsp.exe /unmount` fallback
- [x] Open folder: `xdg-open` → nautilus → dolphin → thunar → nemo → pcmanfm → caja
- [x] Path existence check before attempting to open

#### Recent containers (`~/.config/venom/recent.json`)
- [x] Up to 10 entries; cipher read without KDF; label enriched post-mount
- [x] Empty state, non-empty list, mount form quick-fill

#### UI design
- [x] Custom dark theme + topbar badges

---

## In progress / not started

### Container format / security

- [ ] **Write atomicity** — crash between freeing old continuation slots and writing
  new ones can corrupt a file. Needs write-ahead log or copy-on-write.
- [ ] **Integrity manifest** — no global HMAC of the allocation bitmap; an attacker
  could flip bits to block access to specific slots.
- [ ] **Volume size limit** — allocation bitmap must fit in one slot (≈ 8 GB per
  volume). Larger containers require a multi-slot bitmap or B-tree allocator.
- [ ] **Password zeroization** — `CreateView::password` and `MountView::password`
  are plain `String`; should be zeroized after the mount/create thread receives them.
- [ ] **Async create** — random-fill + KDF blocks the UI thread (up to 30 s for a
  large sensitive-profile container). Should use a progress-reporting async pattern.

### FUSE / filesystem

- [ ] **Hard links / symlinks** — `link` and `symlink` not implemented
- [ ] **Extended attributes** — `getxattr` / `setxattr` not implemented
- [ ] **File timestamps** — always `UNIX_EPOCH`; no persistent storage in slots
- [ ] **Permissions** — hardcoded 0o755/0o644; no persistent ACL
- [ ] **Large directory performance** — `readdir` re-reads the directory slot on
  every call; no in-memory directory cache

### WinFSP driver

- [ ] **Windows smoke test** — actual mount + file copy + unmount on a Windows CI runner
- [ ] **WinFSP error mapping** — not all `FspError` codes map cleanly to our
  `VnmError`; edge cases (e.g., path-too-long, sharing violations) need validation
- [ ] **macOS WinFSP equivalent** — macFUSE path is implemented but not tested on CI

### GUI

- [ ] **Progress bar during create** — show spinner + elapsed time at minimum
- [ ] **Outer safe-fill warning** — alert user when outer volume nears `outer_limit`
  (risk of overwriting hidden volume data)
- [ ] **Vault browser panel** — show mounted directory tree inside the app
- [ ] **Tray icon** — mounted count; unmount from tray menu
- [ ] **Auto-unmount on idle**
- [ ] **CLI mode** — `venom mount <file.vnm> <mp> [--password-stdin]`

### Testing & CI

- [ ] **Restore `fuse_ops_tests`** — 29 integration tests for the FUSE op_* surface
  were lost during the format migration; needs rewrite for the `u64` slot-based API
- [ ] **Property-based tests** — `proptest` for crypto round-trips
- [ ] **FUSE mount smoke test** — CI job: create, mount, write file, read back, unmount
- [ ] **Benchmarks** — encrypt/decrypt throughput; KDF timing

### Distribution

- [ ] **GitHub Actions CI** — `cargo test` + `cargo clippy` + `cargo fmt --check`
- [ ] **Release packaging** — Flatpak/AppImage (Linux), `.app` (macOS), installer (Windows)
- [ ] **`CHANGELOG.md`** and semantic versioning

---

## Known limitations

1. **Single-process mount (Unix)** — if the GUI crashes (`SIGSEGV`), the FUSE thread
   dies and dirty cached data is lost. Normal exits flush correctly via `Drop`.
2. **Owner-only mounts (Unix)** — `AllowOther` removed; other users on the machine
   cannot access the mountpoint.
3. **Full-file RAM loading** — entire files are decrypted into memory on `open()`.
   A 500 MB file consumes 500 MB of RSS. Streaming is not implemented.
4. **Password copy in thread** — password bytes cloned as `Vec<u8>`, dropped after
   `VnmContainer::open`. No explicit `zeroize` on the copy.
5. **Recent list stores plaintext paths** — `~/.config/venom/recent.json` reveals
   container file locations on disk (no vault content, but existence is visible).
6. **`.goutputstream-*` residues (Unix)** — GIO atomic saves leave temp files if
   they fail mid-way. Fixed with `FOPEN_DIRECT_IO`. Clean up existing ones:
   `find <mp> -name '.goutputstream-*' -delete`.
7. **Outer safe-fill unenforced** — the GUI does not prevent filling the outer volume
   past `outer_limit`, which would overwrite the hidden volume's data.
8. **WinFSP not tested on real hardware** — the Windows driver compiles and maps all
   key operations, but has not been validated by an actual Windows mount session.
