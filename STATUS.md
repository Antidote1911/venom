# Venom — Project Status

> Last updated: 2026-06-02

## What is Venom?

Venom is a cryptographic container filesystem written in Rust, inspired by VeraCrypt.
A container is a **single opaque file** (`.vnm`). Its entire content is encrypted —
an attacker who sees the file cannot determine how many files are stored inside, their
names, sizes, or directory structure. The same file can host two independent volumes
(plausible deniability) and can be decrypted by multiple independent recipients,
each with their own credential (password or post-quantum ML-KEM private key).

### Workspace layout

```
venom/
├── vnmcore/      Core library: crypto, slot store, virtual filesystem, OS drivers
│   ├── src/
│   │   ├── container/   header v1, CipherAlgorithm, KdfParams, recipient slots
│   │   ├── crypto/      Argon2id KDF, AES-256-GCM / ChaCha20-Poly1305,
│   │   │                ML-KEM-1024, key file format (.vpub / .vpriv)
│   │   ├── storage/     SlotStore, VaultNode, DirectoryBlock, FileBlock
│   │   └── fs/          VnmContainer API, FUSE (Unix), WinFSP (Windows)
│   ├── tests/           27 integration tests
│   └── examples/        mount_test — diagnostic CLI tool
└── venom/        GUI application (egui 0.28 / eframe)
    └── src/
        ├── app/         state, actions
        ├── ui/          theme, topbar, vault_list, create, mount,
        │                recipients, key_manager, statusbar
        ├── keystore.rs  local ML-KEM key storage (~/.config/venom/keys/)
        └── recent.rs    recent containers (~/.config/venom/recent.json)
```

---

## Done

### Container format — `.vnm` (version 1, definitive)

```
[0..512]      Outer header (VNM1) — encrypted with K_master
[512..1024]   Random reserved bytes (no header here — deniability)
[1024..14984] Recipient area (fixed, 13 960 bytes):
                8 × 101 B   Password slots: salt(32)+profile(1)+AEAD(K_master,68B)
                8 × 1644 B  ML-KEM-1024 slots: fp(8)+KEM_ct(1568)+AEAD(K_master,68B)
[14984..]     Data slots (32 KB each)
[end-512..end] Hidden header (VNM1) or random bytes
```

**Key design**: `K_master` is a random 32-byte key, never derived from a password.
Credentials (password or ML-KEM private key) only serve to decrypt `K_master`.
Adding or revoking a recipient **never re-encrypts any data**.

- [x] **Slot layout** — `u32_LE(len)` prefix + VNMB block (magic+version+nonce+ciphertext+tag)
  + zero padding to 32 KB. Prefix fixes AEAD tag alignment (prevents AuthFailed on open).
- [x] **Header format** (512 B each):
  `salt(64) + cipher_id(1) + kdf_profile(1) + n_pw(1) + n_key(1) + enc_body(432 B)`
  - Salt: **64 bytes** (matches VeraCrypt)
  - KDF params: **not exposed** — only a 1-byte profile ID; exact Argon2id params
    are hardcoded per profile (attacker cannot tune hardware for exact params)
  - Header body encrypted with `K_master`, bound with AAD
    `"vnm:header:outer:v1"` / `"vnm:header:hidden:v1"`
- [x] **Recipient area** — fixed 13 960-byte region before the data area.
  Adding/removing recipients does not shift the data area.
- [x] **Slot encryption** — slot index as AAD → prevents cross-volume substitution
- [x] **Allocation bitmap** — bit-per-slot; 500 MB → 2 KB; 8 GB → 32 KB limit
- [x] **Pre-allocation with random bytes** — deniability requirement
- [x] **Ciphers** — ChaCha20-Poly1305 and AES-256-GCM
- [x] **KDF** — Argon2id (RFC 9106): Interactive (64 MiB/3 iter) or Sensitive (256 MiB/4 iter)
- [x] **Linked-list file chain** — `next_slot: Option<u64>` per FileBlock.
  Fixes large-file crash where flat slot-index list exceeded 32 KB slot.
- [x] **Serialization** — MessagePack (`rmp-serde`, named fields) — readable from any language
- [x] **Format is definitively V1** — all traces of intermediate development versions removed

### Security hardening vs VeraCrypt

| Property | VeraCrypt | Venom |
|---|:---:|:---:|
| Per-slot AEAD integrity | ✗ XTS | ✓ |
| Argon2id (memory-hard KDF) | ✗ PBKDF2 | ✓ |
| Deleted slot wiped (forward secrecy) | ✗ | ✓ |
| Random nonce per write | ✗ deterministic | ✓ |
| Salt 64 bytes | ✓ | ✓ |
| KDF params hidden | ~ trial-and-error | ~ profile ID only |
| Hidden volume deniability | ✓ | ✓ |
| Multi-recipient (ML-KEM) | ✗ | ✓ |
| Header backup | ✓ | ✗ TODO |

Full analysis: see `SECURITY.md`.

### Multi-recipient containers (post-quantum)

- [x] **ML-KEM-1024** (NIST FIPS 203, Category 5 — ~256-bit post-quantum security)
  via `ml-kem 0.3` crate (pure Rust, `getrandom` feature)
- [x] **`kem::generate()`** → `(seed: [u8;64], encap_key: [u8;1568])`
- [x] **`kem::encapsulate(ek)`** → `(ciphertext: [u8;1568], shared_secret: [u8;32])`
- [x] **`kem::decapsulate(seed, ct)`** → `shared_secret: [u8;32]`
- [x] **`kem::fingerprint(ek)`** → `SHA-256(ek)[0..8]` for quick slot matching
- [x] **Password slots** (up to 8) — each has its own Argon2id salt; one container
  can have multiple passwords independently
- [x] **ML-KEM slots** (up to 8) — fingerprint enables O(1) rejection before decap
- [x] **`VnmContainer::open(path, OpenCredential::Password(pw))`**
- [x] **`VnmContainer::open(path, OpenCredential::PrivateKey(&seed))`**
- [x] **`add_key_recipient(&encap_key)`** — no data re-encryption
- [x] **`add_password_recipient(&pw)`**
- [x] **`remove_key_recipient(&fingerprint)`** — wipes the slot with random bytes
- [x] **`list_recipients()`** → `Vec<RecipientInfo>` with type + fingerprint

### ML-KEM key file format

Two binary file formats for exchanging and persisting ML-KEM keys:

**`.vpub`** — public encapsulation key (1 656 bytes, safe to share):
```
b"VKPB" + version u32 + created_at u64 + label[64] + fingerprint[8] + ek[1568]
```

**`.vpriv`** — private decapsulation key (153 bytes, keep secret):
```
b"VKPR" + version u32 + created_at u64 + label[64] + fingerprint[8]
       + protected u8 (0=plaintext, 1=encrypted—future) + seed[64]
```
- Plaintext seed stored as `protected=0`; file mode `600` on Unix
- Passphrase-protected storage (`protected=1`) reserved for future version
- The public key is always re-derivable from the seed (`ek_from_seed`)

### Local key store (`~/.config/venom/keys/`)

Files: `<fingerprint_hex>.vpub` and optionally `<fingerprint_hex>.vpriv`

| Method | Action |
|---|---|
| `generate(label)` | Creates both files, seeds the store |
| `import_pub(path)` | Imports a foreign `.vpub` |
| `import_priv(path)` | Imports `.vpriv`, derives and saves the matching `.vpub` |
| `export_pub(fp, dest)` | Copies `.vpub` to user-chosen location (sharing) |
| `export_priv(fp, dest)` | Copies `.vpriv` to user-chosen location (backup) |
| `remove(fp)` | Deletes both files from store |
| `get_encap_key(fp)` | Returns `EncapKey` for `add_key_recipient` |
| `get_seed(fp)` | Returns `Seed` for `OpenCredential::PrivateKey` |

### VnmContainer API

```rust
// Create
VnmContainer::create(path, password, size, cipher, kdf, label, hidden_opts)

// Open — password or ML-KEM private key
VnmContainer::open(path, OpenCredential::Password(pw))
VnmContainer::open(path, OpenCredential::PrivateKey(&seed))

// Recipients
container.add_key_recipient(&encap_key)
container.add_password_recipient(&new_password)
container.remove_key_recipient(&fingerprint)
container.list_recipients() -> Vec<RecipientInfo>

// Nodes
container.read_node(slot) / write_node(node) / update_node(slot, node) / free_node(slot)
container.flush()
```

### FUSE driver — Linux / macOS (`fs/fuse.rs`)

- [x] `op_*` architecture (testable without mounting); thin `Filesystem` wrappers
- [x] Read: `lookup`, `getattr`, `readdir`, `read`; Write: all standard ops
- [x] In-memory file cache; `FOPEN_DIRECT_IO`; `statfs()`; forward secrecy on free
- [x] Mount options hardened (`AllowOther` + `AutoUnmount` removed — EPERM fix)

### WinFSP driver — Windows (`fs/winfsp.rs`)

- [x] `winfsp 0.13` `FileSystemContext` trait; `Mutex<Inner>` for multi-threading
- [x] All core ops: `create`, `open`, `close`, `read`, `write`, `flush`, `rename`,
  `set_delete`, `cleanup`, `read_directory`, `get_volume_info`
- [x] Case-insensitive path resolution, FILETIME timestamps, drive-letter mount
- [x] Requires WinFSP installed (https://winfsp.dev, free, MIT)

### Tests — 27 total, all passing

| Suite | Count | Covers |
|-------|------:|--------|
| `crypto_tests` | 8 | ChaCha20/AES round-trip, wrong key, AAD, tamper, KDF, nonces |
| `container_tests` | 10 | create/open (both ciphers), wrong password, root dir, CRUD, persistence, hidden volume, ML-KEM round-trip, add ML-KEM recipient + open with private key, multiple recipients |
| `fuse_cache_tests` (inline) | 9 | cache lifecycle + large file (75 KB, 3 slots) |

### GUI (egui 0.28)

#### Key Manager (`Screen::KeyManager`)
- [x] **🗝 Keys** button in topbar with key-count badge
- [x] **Key list** — each key shows as a card:
  - Own keypair: blue border, `🔑` icon, `"keypair"` badge
  - Imported public: grey border, `👤` icon, `"public only"` badge
  - Fingerprint displayed as `ab:cd:ef:01:23:45:67:89` (purple monospace)
  - Creation date, `[Export .vpub]`, `[Export .vpriv]` (own keys only), `[Delete]`
- [x] **Generate panel** — label field + `⚡ Generate` button; algorithm info shown
- [x] **Import panel** — `[Import .vpub]` / `[Import .vpriv]` file pickers

#### Recipients screen (`Screen::Recipients`)
- [x] Lists current password and ML-KEM slots per mounted container
- [x] Add password recipient / add ML-KEM recipient (browse `.vpub`)
- [x] Remove ML-KEM recipient by fingerprint

#### Create / Mount / Vault list
- [x] Create: size field, hidden volume section, KDF cards, save-as browser
- [x] Mount: `📄 Open file` (blue) / `📁 Folder…` (grey), single passphrase field
- [x] Vault cards: `🔐 hidden` badge, `👥 Recipients` button
- [x] Async mount thread; `Mounting → Mounted → Gone / Error` state machine
- [x] Open folder: `xdg-open` → fallback chain → path existence check

#### Recent containers / UI design
- [x] Recent list (10 entries, JSON, cipher read without KDF)
- [x] Custom dark theme, topbar badges

---

## In progress / not started

### Security

- [ ] **Recipient management from GUI requires re-open** — `add_key_recipient` /
  `remove_key_recipient` need `K_master`, which is only available right after
  `VnmContainer::open`. The GUI currently re-opens; storing `K_master` in mount state
  would allow live management without re-entering the password.
- [ ] **Private key passphrase protection** — `.vpriv` `protected=1` format is defined
  but not yet implemented. Currently relies on filesystem permissions only.
- [ ] **Write atomicity** — crash between freeing and writing continuation slots
  can corrupt a file. Needs WAL or copy-on-write.
- [ ] **Integrity manifest** — no global HMAC over the allocation bitmap.
- [ ] **Volume size limit** — bitmap must fit in one slot (≈ 8 GB per volume).
- [ ] **Password zeroization** — GUI password fields are plain `String`.
- [ ] **Async create** — random-fill + KDF blocks the UI thread for large containers.
- [ ] **Header backup** — corruption of the single header = total data loss.

### FUSE / filesystem

- [ ] Hard links / symlinks, extended attributes, timestamps, persistent ACLs
- [ ] Large directory performance (no `readdir` cache)

### WinFSP driver

- [ ] Windows smoke test on real hardware / CI
- [ ] WinFSP error mapping edge cases

### GUI

- [ ] **Key integration with Recipients screen** — use the local key store to
  populate the recipient selector (pick a known key by label / fingerprint)
  instead of browsing for a raw `.vpub` file
- [ ] **Mount with key** — add `OpenCredential::PrivateKey` path in the mount form
  (pick a key from the local store or browse for a `.vpriv` file)
- [ ] Progress bar during container creation
- [ ] Outer safe-fill warning for hidden volumes
- [ ] Vault browser panel, tray icon, auto-unmount on idle
- [ ] CLI mode (`venom mount <file.vnm> <mp> --password-stdin`)

### Testing & CI

- [ ] Restore `fuse_ops_tests` (29 tests lost in format migration)
- [ ] Property-based tests, FUSE smoke test, benchmarks
- [ ] GitHub Actions CI

### Distribution

- [ ] Release packaging (Flatpak / AppImage / `.app` / Windows installer)
- [ ] `CHANGELOG.md` and semantic versioning

---

## Known limitations

1. **Single-process mount (Unix)** — `SIGSEGV` kills the FUSE thread; dirty data lost.
2. **Owner-only mounts** — `AllowOther` removed; other users cannot access the mountpoint.
3. **Full-file RAM loading** — entire files decrypted on `open()`. 500 MB → 500 MB RSS.
4. **Password bytes in thread** — cloned as `Vec<u8>`, no explicit `zeroize`.
5. **Recent list / key store store plaintext paths** — container locations and key
   metadata visible in `~/.config/venom/`.
6. **`.goutputstream-*` residues** — GIO temp files from failed atomic saves.
   Fixed with `FOPEN_DIRECT_IO`. Clean: `find <mp> -name '.goutputstream-*' -delete`.
7. **Outer safe-fill unenforced** — GUI does not prevent overwriting hidden volume data.
8. **WinFSP untested on real hardware** — driver compiles, no live mount validated.
9. **Private keys stored unencrypted** — `.vpriv` files rely on `chmod 600`.
   Passphrase protection (`protected=1`) not yet implemented.
10. **Recipient management requires password re-entry** — `K_master` is not kept
    in memory after mounting, so adding/removing recipients requires re-opening.
