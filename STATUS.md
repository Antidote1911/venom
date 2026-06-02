# Venom — Project Status

> Last updated: 2026-06-02

## What is Venom?

Venom is a cryptographic container filesystem written in Rust, inspired by VeraCrypt.
A container is a **single opaque file** (`.vnm`). Its entire content is encrypted —
an attacker who sees the file cannot determine how many files are stored inside, their
names, sizes, or directory structure. The same file can host two independent volumes
(plausible deniability) and can be decrypted by multiple independent recipients,
each with their own credential (password or post-quantum private key).

### Workspace layout

```
venom/
├── vnmcore/      Core library: crypto, slot store, virtual filesystem, OS drivers
│   ├── src/
│   │   ├── container/   header v3, CipherAlgorithm, KdfParams, recipient slots
│   │   ├── crypto/      Argon2id KDF, AES-256-GCM / ChaCha20-Poly1305, ML-KEM-1024
│   │   ├── storage/     SlotStore, VaultNode, DirectoryBlock, FileBlock
│   │   └── fs/          VnmContainer API, FUSE (Unix), WinFSP (Windows)
│   ├── tests/           27 integration tests
│   └── examples/        mount_test — diagnostic CLI tool
└── venom/        GUI application (egui 0.28 / eframe)
    └── src/
        ├── app/         state, actions (platform-agnostic mount dispatch)
        ├── ui/          theme, topbar, vault_list, create, mount, recipients, statusbar
        └── recent.rs    recent-containers (~/.config/venom/recent.json)
```

---

## Done

### Container format v3 — `.vnm` single file

```
[0..512]                   Outer header (VNM3) — encrypted with K_master
[512..1024]                Random reserved bytes (no header here — deniability)
[1024..14984]              Recipient area (fixed, 13 960 bytes):
  8 × 101 B  Password slots  salt(32) + kdf_profile(1) + AEAD(K_master)
  8 × 1644 B ML-KEM slots    fingerprint(8) + KEM_ct(1568) + AEAD(K_master)
[14984..]                  Data slots (32 KB each)
[end-512..end]             Hidden header (VNM3) or random bytes
```

**Key design principle**: `K_master` is a random 32-byte key, never derived from
a password. Credentials (password, private key) only decrypt `K_master`. This means
adding or revoking a recipient **never re-encrypts any data**.

- [x] **Slot on-disk layout** — `u32_LE(len)` prefix + VNMB block (magic + version +
  nonce + ciphertext + AEAD tag) + zero padding to 32 KB.
  Prefix is required so `decrypt_block` finds the exact AEAD tag boundary.
- [x] **Header format v3** (512 B):
  `salt(64) + cipher_id(1) + kdf_profile(1) + n_pw(1) + n_key(1) + nonce_area(8) + enc_body(432 B)`.
  - Salt increased to **64 bytes** (matches VeraCrypt, was 32)
  - KDF params **not exposed** — only a 1-byte profile ID (0=interactive, 1=sensitive);
    exact Argon2id parameters hardcoded per profile, not attacker-visible
  - Header body encrypted with `K_master` (not with password-derived key), bound with
    AAD `"vnm:header:outer:v3"` / `"vnm:header:hidden:v3"`
- [x] **Slot encryption** — master key (random 32 B, stored in recipient slots);
  slot index as AAD → prevents cross-volume slot substitution
- [x] **Allocation bitmap** — compact bit-per-slot in slot 0 (outer) / last slot (hidden).
  500 MB → 2 KB bitmap; 8 GB → 32 KB (practical per-volume limit)
- [x] **Pre-allocation with random bytes** — deniability requirement
- [x] **Ciphers** — ChaCha20-Poly1305 and AES-256-GCM
- [x] **Key derivation** — Argon2id (RFC 9106, PHC winner):
  - Interactive: 64 MiB / 3 iterations (< 1 s)
  - Sensitive: 256 MiB / 4 iterations (2–5 s)
- [x] **Linked-list file chain** — `FileBlock.next_slot: Option<u64>`.
  Fixes large-file crash (flat `Vec<u64>` of continuation indices exceeded 32 KB)
- [x] **Serialization: MessagePack** (`rmp-serde`, named fields) — readable from
  Python, Go, C#, Java…; allocation bitmap stays custom binary

### Security hardening vs VeraCrypt

| Property | VeraCrypt | Venom |
|---|:---:|:---:|
| Per-slot integrity (AEAD) | ✗ XTS | ✓ |
| Argon2id KDF (memory-hard) | ✗ PBKDF2 | ✓ |
| Deleted slot wipe | ✗ | ✓ |
| Random nonce per write | ✗ XTS deterministic | ✓ |
| Salt 64 bytes | ✓ | ✓ |
| KDF params hidden | ~ trial | ~ profile ID |
| Hidden volume deniability | ✓ | ✓ |
| Multi-recipient (ML-KEM) | ✗ | ✓ |
| Header backup | ✓ | ✗ TODO |

Full comparison: see `SECURITY.md`.

### Multi-recipient containers (post-quantum)

- [x] **ML-KEM-1024** (NIST FIPS 203, Category 5 — ~256-bit post-quantum security)
  via `ml-kem 0.3` (pure Rust, `getrandom` feature)
- [x] **Key types**: Seed (64 B private), EncapKey (1568 B public), Ciphertext (1568 B)
- [x] **`kem::generate()`** → `(seed, encap_key)`
- [x] **`kem::encapsulate(ek)`** → `(ciphertext, shared_secret_32B)`
- [x] **`kem::decapsulate(seed, ct)`** → `shared_secret_32B`
- [x] **`kem::fingerprint(ek)`** → `SHA-256(ek)[0..8]` for quick slot matching
- [x] **Password slots** — up to 8 per container; each has its own Argon2id salt
- [x] **ML-KEM slots** — up to 8 per container; fingerprint enables fast rejection
- [x] **`VnmContainer::open(path, OpenCredential::Password(pw))`**
- [x] **`VnmContainer::open(path, OpenCredential::PrivateKey(&seed))`**
- [x] **`add_key_recipient(&encap_key)`** — adds ML-KEM slot, no data re-encryption
- [x] **`add_password_recipient(&pw)`** — adds password slot
- [x] **`remove_key_recipient(&fingerprint)`** — revokes by fingerprint, wipes slot
- [x] **`list_recipients()`** — returns slot type + fingerprint for each slot

### Interoperability

| Layer | Format | Portability |
|---|---|---|
| Header | Custom binary (fixed LE layout) | Any language |
| Slot crypto | AES-256-GCM or ChaCha20-Poly1305 | IETF RFCs |
| KDF | Argon2id | RFC 9106, 50+ language libs |
| ML-KEM | FIPS 203 standard | Growing ecosystem |
| VaultNode payload | MessagePack (named fields) | 50+ language libs |

### Hidden volume (plausible deniability)

- [x] **Two-password design** — same `.vnm`, two independent encrypted volumes.
  Neither volume can prove the other exists.
- [x] **Hidden header at `file_end − 512`** — outer header does not reference the
  hidden area; the file appears as a normal container with slack space at the end
- [x] **Outer claims only its own capacity** — `total_slots` in outer header = outer slots
  only, hides the existence of the hidden volume from the outer volume user
- [x] **Independent master keys** — slots of one volume cannot be decrypted with the other
- [x] **Automatic detection** — `VnmContainer::open` tries outer header, then hidden
- [x] **GUI** — collapsible hidden volume section in Create form

### VnmContainer API

```rust
VnmContainer::create(path, password, size, cipher, kdf, label, hidden_opts)
VnmContainer::open(path, OpenCredential::Password(pw))
VnmContainer::open(path, OpenCredential::PrivateKey(&seed))
container.add_key_recipient(&encap_key)
container.remove_key_recipient(&fingerprint)
container.add_password_recipient(&new_password)
container.list_recipients() -> Vec<RecipientInfo>
container.read_node(slot) / write_node(node) / update_node(slot, node) / free_node(slot)
container.flush()
```

### FUSE driver — Linux / macOS (`fs/fuse.rs`)

- [x] `op_*` architecture (testable without mounting), thin `Filesystem` wrappers
- [x] Read: `lookup`, `getattr`, `readdir`, `read`
- [x] Write: `mkdir`, `rmdir`, `create`, `unlink`, `rename`, `write`, `setattr`
- [x] In-memory file cache; `FOPEN_DIRECT_IO`; `statfs()`; forward secrecy on free
- [x] Mount options hardened (`AllowOther` + `AutoUnmount` removed)

### WinFSP driver — Windows (`fs/winfsp.rs`)

- [x] `winfsp 0.13` `FileSystemContext` trait; `Mutex<Inner>` for multi-threading
- [x] All core ops: `create`, `open`, `close`, `read`, `write`, `flush`, `rename`,
  `set_delete`, `cleanup`, `read_directory`, `get_volume_info`
- [x] Case-insensitive path resolution, Windows FILETIME, drive-letter mount points
- [x] Requires WinFSP installed (https://winfsp.dev)

### Tests — 27 total, all passing

| Suite | Count | Covers |
|-------|------:|--------|
| `crypto_tests` | 8 | ChaCha20/AES round-trip, wrong key, AAD binding, tamper detection, KDF, nonces |
| `container_tests` | 10 | create/open both ciphers, wrong password, root dir, CRUD, persistence, hidden volume, **ML-KEM generate/encap/decap round-trip**, **add ML-KEM recipient + open with private key**, **multiple ML-KEM recipients** |
| `fuse_cache_tests` (inline) | 9 | cache lifecycle + large file linked-list (75 KB / 3 slots) |

### GUI (egui 0.28)

- [x] Create: two-column layout, size field, hidden volume section, save-as browser
- [x] Mount: file picker (`📄 Open file`), `📁 Folder…`, single passphrase field
- [x] **Recipients screen** (`👥 Recipients` button on mounted vault cards):
  - List current slots (password + ML-KEM with fingerprint)
  - Add password recipient
  - Add ML-KEM recipient (browse `.vpub` file)
  - Remove ML-KEM recipient by fingerprint
  - **Generate ML-KEM-1024 keypair** → `.vpub` (public) + `.vpriv` (seed)
- [x] Async mount thread; `Mounting → Mounted → Gone / Error` state machine
- [x] `🔐 hidden` badge for hidden-volume mounts
- [x] Open folder fallback chain; path existence check
- [x] Recent containers (up to 10, JSON, cipher hint without KDF)
- [x] Custom dark theme

---

## In progress / not started

### Container format / security

- [ ] **Recipients screen: K_master access** — currently the GUI `add_key_recipient`
  / `remove_key_recipient` require K_master, which is only available right after open.
  The GUI needs to either re-open the container or store K_master in the mount state.
- [ ] **Write atomicity** — crash between freeing and writing continuation slots
  can corrupt a file. Needs WAL or copy-on-write.
- [ ] **Integrity manifest** — no global HMAC over the allocation bitmap.
- [ ] **Volume size limit** — bitmap must fit in one slot (≈ 8 GB per volume).
- [ ] **Password zeroization** — `CreateView::password` / `MountView::password`
  should be zeroized after use.
- [ ] **Async create** — random-fill + KDF blocks the UI thread for large containers.
- [ ] **Header backup** — single header per volume; corruption = total data loss.
  VeraCrypt keeps a backup copy.

### FUSE / filesystem

- [ ] Hard links / symlinks, extended attributes, file timestamps, persistent ACLs
- [ ] Large directory cache (`readdir` re-reads on every call)

### WinFSP driver

- [ ] Windows smoke test on real hardware / CI runner
- [ ] WinFSP error mapping edge cases

### GUI

- [ ] Progress bar during create (random-fill can take 30+ s for large containers)
- [ ] Outer safe-fill warning when hidden volume exists
- [ ] Vault browser panel, tray icon, auto-unmount on idle
- [ ] CLI mode (`venom mount <file.vnm> <mp> --password-stdin`)

### Testing & CI

- [ ] Restore `fuse_ops_tests` (29 tests lost during format migration)
- [ ] Property-based tests (`proptest`)
- [ ] FUSE mount smoke test (CI with fuse3)
- [ ] Benchmarks

### Distribution

- [ ] GitHub Actions CI
- [ ] Release packaging (Flatpak/AppImage, `.app`, Windows installer)
- [ ] `CHANGELOG.md` and semantic versioning

---

## Known limitations

1. **Single-process mount (Unix)** — `SIGSEGV` kills the FUSE thread; dirty data lost.
   Normal exits flush via `Drop`.
2. **Owner-only mounts** — `AllowOther` removed; other users cannot access the mountpoint.
3. **Full-file RAM loading** — entire files decrypted into memory on `open()`.
   A 500 MB file consumes 500 MB RSS. Streaming not implemented.
4. **Password copy in thread** — cloned as `Vec<u8>`, no explicit `zeroize` on the copy.
5. **Recent list stores plaintext paths** — container locations visible in
   `~/.config/venom/recent.json`.
6. **`.goutputstream-*` residues** — fixed with `FOPEN_DIRECT_IO`; clean existing:
   `find <mp> -name '.goutputstream-*' -delete`.
7. **Outer safe-fill unenforced** — no GUI guard against overwriting hidden volume data.
8. **WinFSP untested on real hardware** — driver compiles and maps all ops, but no
   live mount session has been validated.
9. **Recipient management requires re-open** — adding/removing recipients via the GUI
   currently requires re-opening the container (K_master not stored in mount state).
