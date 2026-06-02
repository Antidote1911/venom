# Venom — Project Status

> Last updated: 2026-06-02

## What is Venom?

Venom is a cryptographic container filesystem written in Rust, inspired by VeraCrypt.
A container is a **single opaque file** (`.vnm`). Its entire content is encrypted —
an attacker who sees the file cannot determine how many files are stored inside, their
names, sizes, or directory structure. The same file can host two independent volumes
(plausible deniability) and can be decrypted by multiple independent recipients,
each with their own credential (password or post-quantum hybrid private key).

### Workspace layout

```
venom/
├── vnmcore/      Core library: crypto, slot store, virtual filesystem, OS drivers
│   ├── src/
│   │   ├── container/   header v1, CipherAlgorithm, KdfParams, recipient slots
│   │   ├── crypto/      Argon2id KDF, AES-256-GCM / ChaCha20-Poly1305,
│   │   │                hybrid_kem (X25519 + ML-KEM-1024), key file format
│   │   ├── storage/     SlotStore, VaultNode, DirectoryBlock, FileBlock
│   │   └── fs/          VnmContainer API, FUSE (Unix), WinFSP (Windows)
│   ├── tests/           28 integration tests
│   └── examples/        mount_test — diagnostic CLI tool
└── venom/        GUI application (egui 0.28 / eframe)
    └── src/
        ├── app/         state, actions
        ├── ui/          theme, topbar, vault_list, create, mount,
        │                recipients, key_manager, statusbar
        ├── keystore.rs  local hybrid-key storage (~/.config/venom/keys/)
        └── recent.rs    recent containers (~/.config/venom/recent.json)
```

---

## Done

### Container format — `.vnm` (version 1, definitive)

```
[0..512]      Outer header (VNM1) — encrypted with K_master
[512..1024]   Random reserved bytes
[1024..15240] Recipient area (fixed, 14 216 bytes):
                8 × 101 B    Password slots: salt(32)+profile(1)+AEAD(K_master,68B)
                8 × 1676 B   Hybrid key slots: fp(8)+x25519_eph(32)+mlkem_ct(1568)+AEAD(68B)
[15240..]     Data slots (32 KB each)
[end-512..end] Hidden header (VNM1) or random bytes
```

**Key design**: `K_master` is a random 32-byte key, never derived from a password.
Credentials only serve to decrypt `K_master`. Adding or revoking a recipient
**never re-encrypts any data**.

- [x] Slot layout, header format, allocation bitmap, linked-list file chain — see previous versions
- [x] **Format V1 is definitive** — all intermediate development versions removed
- [x] Serialization: MessagePack (`rmp-serde`, named fields) — readable from any language

### Security hardening vs VeraCrypt

| Property | VeraCrypt | Venom |
|---|:---:|:---:|
| Per-slot AEAD integrity | ✗ XTS | ✓ |
| Memory-hard KDF (Argon2id) | ✗ PBKDF2 | ✓ |
| Deleted slot wiped | ✗ | ✓ |
| Random nonce per write | ✗ deterministic | ✓ |
| Salt 64 bytes | ✓ | ✓ |
| KDF params hidden | ~ trial | ~ profile ID |
| Hidden volume deniability | ✓ | ✓ |
| Multi-recipient | ✗ | ✓ |
| Post-quantum + classical hybrid | ✗ | ✓ |
| Header backup | ✓ | ✗ TODO |

Full analysis: see `SECURITY.md`.

### Multi-recipient containers — hybrid post-quantum

#### Cryptographic design

Two **fully independent** keypairs — neither derived from the other:

```
X25519     classical ECDH  (fast, universally deployed)
ML-KEM-1024 post-quantum   (NIST FIPS 203, Category 5, ~256-bit PQ security)
```

**Encapsulation** (adding a recipient):
```
x25519_eph_sk = random()
x25519_shared = X25519(x25519_eph_sk, recipient.x25519_pk)
(mlkem_ct, mlkem_ss) = ML-KEM.Encaps(recipient.mlkem_ek)

hybrid_key = SHA-256(
    "venom:hybrid:v1"   ← domain separator
    || x25519_shared    ← 32 bytes (ECDH result)
    || mlkem_ss         ← 32 bytes (ML-KEM shared secret)
    || x25519_eph_pk    ← 32 bytes (ciphertext binding)
    || mlkem_ct         ← 1568 bytes (ciphertext binding)
)
```

**Security**: an attacker must break **both** X25519 and ML-KEM-1024 simultaneously.
If quantum computers break X25519 → ML-KEM-1024 still holds.
If ML-KEM-1024 has a classical weakness → X25519 still holds.

- [x] `hybrid_generate()` → `HybridPrivateKey { x25519_sk, x25519_pk, mlkem_seed, mlkem_ek }`
  X25519 and ML-KEM-1024 keys are generated independently from separate random sources.
- [x] `hybrid_encapsulate(pub)` → `(x25519_eph_pk, mlkem_ct, hybrid_key)`
- [x] `hybrid_decapsulate(priv, x25519_eph_pk, mlkem_ct)` → `hybrid_key`
- [x] `fingerprint` = `SHA-256(x25519_pk || mlkem_ek)[0..8]` — binds to BOTH public keys
- [x] Password slots (up to 8) — independent Argon2id salt per slot
- [x] Hybrid key slots (up to 8) — fingerprint for O(1) rejection before decapsulation
- [x] `VnmContainer::open(path, OpenCredential::Password(pw))`
- [x] `VnmContainer::open(path, OpenCredential::PrivateKey(&hybrid_key))`
- [x] `add_key_recipient(&HybridPublicKey)` — no data re-encryption
- [x] `remove_key_recipient(&fingerprint)` — wipes slot with random bytes
- [x] `list_recipients()` → type + fingerprint per slot

### Hybrid key file format

**`.key`** — complete keypair (two variants, distinguished by `protected` byte):

*Unprotected* (1 785 bytes — relies on `chmod 600`):
```
b"VKEY" + version u32 + created_at u64 + label[64] + fingerprint[8]
        + x25519_pk[32] + mlkem_ek[1568]   ← PUBLIC, always in plaintext
        + protected=0
        + x25519_sk[32] + mlkem_seed[64]   ← private, plaintext
```

*Passphrase-protected* (1 886 bytes — private scalars encrypted):
```
b"VKEY" + version + created_at + label + fingerprint
        + x25519_pk[32] + mlkem_ek[1568]   ← PUBLIC, always in plaintext
        + protected=1
        + argon2_salt[64] + kdf_profile[1]
        + encrypt_block(                    ← private, ChaCha20-Poly1305 AEAD
            Argon2id(passphrase, salt),
            aad = "vnm:key:protect:v1",
            x25519_sk[32] || mlkem_seed[64]
          ) = 132 bytes
```

**Design principle**: public portions (`x25519_pk`, `mlkem_ek`) are **always in
plaintext** regardless of protection — recipient management and fingerprint display
work without a passphrase. Only private scalars are encrypted.

**`.pub`** — public portion only, 1 688 bytes (safe to share freely):
```
b"VPUB" + version u32 + created_at u64 + label[64] + fingerprint[8]
        + x25519_pk[32] + mlkem_ek[1568]
```

The `.pub` is exported on demand from the Key Manager.

### Local key store (`~/.config/venom/keys/`)

Files: `<fingerprint_hex>.key` (private+public bundle)

| Method | Action |
|---|---|
| `generate(label)` | Creates X25519 + ML-KEM-1024 independently, saves unprotected `.key` |
| `generate_protected(label, passphrase, profile)` | Same, with passphrase protection |
| `import_key(path)` | Imports a `.key` file from backup or another machine |
| `export_pub(fp, dest)` | Writes the `.pub` file for sharing |
| `protect(fp, old_pw, new_pw, profile)` | Add or change passphrase on existing key |
| `unprotect(fp, passphrase)` | Remove passphrase protection |
| `remove(fp)` | Deletes the `.key` file |
| `get_key(fp)` | Returns private key (fails if passphrase-protected) |
| `get_key_with_passphrase(fp, pw)` | Decrypts and returns private key |
| `get_public(fp)` | Returns public key (always works, no passphrase needed) |

### VnmContainer API

```rust
VnmContainer::create(path, password, size, cipher, kdf, label, hidden_opts)
VnmContainer::open(path, OpenCredential::Password(pw))
VnmContainer::open(path, OpenCredential::PrivateKey(&hybrid_key))
container.add_key_recipient(&hybrid_pub)
container.add_password_recipient(&new_password)
container.remove_key_recipient(&fingerprint)
container.list_recipients() -> Vec<RecipientInfo>
container.read_node / write_node / update_node / free_node / flush
```

### FUSE driver — Linux / macOS (`fs/fuse.rs`)

- [x] `op_*` architecture (testable without mounting); thin `Filesystem` wrappers
- [x] Full read/write support; in-memory cache; `FOPEN_DIRECT_IO`; `statfs()`
- [x] Forward secrecy: freed slots overwritten; mount options hardened

### WinFSP driver — Windows (`fs/winfsp.rs`)

- [x] `winfsp 0.13` `FileSystemContext` trait; all core ops implemented
- [x] Case-insensitive paths, FILETIME, drive-letter mount, `Mutex<Inner>`
- [x] Requires WinFSP installed (https://winfsp.dev)

### Tests — 27 total, all passing

| Suite | Count | Covers |
|-------|------:|--------|
| `crypto_tests` | 8 | ChaCha20/AES AEAD, wrong key, AAD binding, tamper, KDF |
| `container_tests` | 11 | create/open (both ciphers), wrong password, CRUD, persistence, hidden volume, hybrid KEM round-trip, add hybrid recipient + open with private key, multiple recipients, **key file passphrase protect/unprotect round-trip, wrong passphrase rejected, public readable without passphrase** |
| `fuse_cache_tests` (inline) | 9 | cache lifecycle + large-file linked-list (75 KB) |

### GUI (egui 0.28)

#### Key Manager (`Screen::KeyManager`)
- [x] **🗝 Keys** button in topbar with keypair-count badge (purple)
- [x] **Key list** — each entry as a card:
  - `🔒🔑` (passphrase-protected, green badge) or `🔑` (unprotected, orange badge)
  - Label, fingerprint `ab:cd:ef:01:23:45:67:89` (purple monospace), creation date
  - `[📤 Export .pub]` — save dialog → `.pub` file to share
  - `[▼ Passphrase]` toggle — reveals the passphrase management panel
  - `[Delete]` — removes the `.key` file
- [x] **Passphrase management panel** (per selected key):
  - Unprotected key: new passphrase + confirm + KDF profile + `🔒 Add passphrase protection`
  - Protected key: current passphrase field + `🔓 Remove protection`
- [x] **Generate panel** — label field + optional passphrase (checkbox → fields + profile)
  + `⚡ Generate keypair`
- [x] **Import panel** — `[📥 Import .key file]` — copies to store, reads metadata without passphrase

#### Recipients screen (`Screen::Recipients`)
- [x] Lists current password and hybrid key slots per mounted container
- [x] Add password recipient / add hybrid key recipient (browse `.pub`)
- [x] Remove hybrid recipient by fingerprint

#### Create form
- [x] Two-column layout; save-as browser (`.vnm`); size field; KDF profile cards
- [x] **Key recipients panel** — checkboxes for each known keypair; password becomes
  optional when at least one recipient is selected (key-only container supported)
- [x] Hidden volume section; live size validation; passphrase match indicator
- [x] "Create container" button disabled until form is valid

#### Mount form
- [x] **Credential toggle `🔒 Password / 🔑 Private key`**:
  - Password mode: passphrase field (outer or hidden volume)
  - Private key mode: scrollable list of keypairs from local store; click to select;
    passphrase field appears when selected key is passphrase-protected;
    button activates when key selected (+ passphrase if needed)
- [x] `📄 Open file` (blue) / `📁 Folder…` (grey) pickers
- [x] Recent containers quick-fill panel

#### Vault list / lifecycle
- [x] Vault cards: `🔐 hidden` badge, `👥 Recipients` button
- [x] Async mount thread; `Mounting → Mounted → Gone / Error` state machine
- [x] Open folder fallback chain; path existence check

#### Bug fixes
- [x] **Key deletion persistence** — `remove()` now returns `Result<(), String>`,
  surfaces errors in status bar; tries both filename formats (with/without colons)
  for backward compatibility
- [x] **Layout truncation** — `ui.available_width()` inside `ScrollArea::vertical()`
  inflates column widths. Fixed by:
  - Calculating column width **before** the `ScrollArea`
  - Using `ui.set_max_width(avail)` inside scroll areas
  - `allocate_ui_with_layout(Vec2::new(col, ∞), ...)` for explicit column sizing
  - `profile_card` uses `ui.set_width(col - 24.0)` instead of `set_min_width(available)`

#### Recent containers / UI design
- [x] Recent containers (10 entries, JSON)
- [x] Custom dark theme, topbar badges

---

## In progress / not started

### Security

- [ ] **Recipient management requires password re-entry** — `K_master` is not kept
  in mount state; adding/removing recipients requires re-opening the container.
- [ ] **Write atomicity** — crash during slot replacement can corrupt a file.
- [ ] **Integrity manifest** — no global HMAC over the allocation bitmap.
- [ ] **Volume size limit** — bitmap must fit in one slot (≈ 8 GB per volume).
- [ ] **Password zeroization** — GUI password fields are plain `String`.
- [ ] **Async create** — random-fill + KDF blocks the UI thread.
- [ ] **Header backup** — corruption = total data loss.

### GUI

- [ ] **Key integration with Recipients screen** — use the local key store to
  select a recipient by label/fingerprint instead of browsing for a raw `.pub`
- [ ] Progress bar during container creation
- [ ] Outer safe-fill warning for hidden volumes
- [ ] Vault browser panel, tray icon, auto-unmount on idle
- [ ] CLI mode (`venom mount <file.vnm> <mp> --password-stdin`)

### FUSE / WinFSP

- [ ] Hard links, symlinks, extended attributes, timestamps, persistent ACLs
- [ ] Large directory cache
- [ ] Windows smoke test; WinFSP error mapping

### Testing & CI

- [ ] Restore `fuse_ops_tests` (29 tests lost in format migration)
- [ ] Property-based tests, FUSE smoke test, benchmarks
- [ ] GitHub Actions CI

### Distribution

- [ ] Release packaging; `CHANGELOG.md`; semantic versioning

---

## Known limitations

1. **Single-process mount (Unix)** — `SIGSEGV` kills the FUSE thread; dirty data lost.
2. **Owner-only mounts** — `AllowOther` removed; other users cannot access mountpoint.
3. **Full-file RAM loading** — entire files decrypted on `open()`. 500 MB → 500 MB RSS.
4. **Password bytes unzeroized** — cloned as `Vec<u8>`, no explicit zeroize call.
5. **Plaintext paths in config** — container locations visible in `~/.config/venom/`.
6. **`.goutputstream-*` residues** — fixed with `FOPEN_DIRECT_IO`; clean:
   `find <mp> -name '.goutputstream-*' -delete`.
7. **Outer safe-fill unenforced** — no GUI guard against overwriting hidden volume data.
8. **WinFSP untested on real hardware** — driver compiles, no live session validated.
9. **Unprotected `.key` files rely on filesystem permissions** — if no passphrase is
   set, `chmod 600` is the only protection. Use the Key Manager to add passphrase
   protection for any key that may be stored on a shared or backed-up volume.
10. **Recipient management requires re-open** — `K_master` not kept in mount state;
    adding/removing recipients requires entering the password again.
