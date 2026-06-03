# Venom — Project Status

> Last updated: 2026-06-03

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
│   │   ├── container/   header v1, CipherAlgorithm (4 ciphers), KdfParams, recipient slots
│   │   ├── crypto/      Argon2id KDF, XChaCha20 / Deoxys-II-256 / Serpent-256-EAX / Triple,
│   │   │                hybrid_kem (X25519 + ML-KEM-1024), key file format
│   │   ├── storage/     SlotStore (per-slot BLAKE3 key derivation, BLAKE3 Merkle tree),
│   │   ├── storage/     SlotStore, VaultNode, DirectoryBlock, FileBlock
│   │   └── fs/          VnmContainer API, FUSE (Unix), WinFSP (Windows)
│   ├── tests/           41 integration tests
│   └── examples/        mount_test — diagnostic CLI tool
└── venom/        Qt6/C++20 frontend
    └── src/
        ├── backend/     VenomCore (Qt↔FFI bridge), MountWorker
        └── ui/          MainWindow (.ui + .cpp)
```

---

## Done

### Container format — `.vnm` (version 1, definitive)

```
[0..512]         Outer header (VNM1) — encrypted with K_master
[512..1024]      Hidden header backup (or random bytes)
[1024..2432]     Password recipient area: 8 × 176 B
                   salt(32) + profile(1) + Triple_AEAD(K_master, 143B)
                   Password slots always use Triple regardless of container cipher.
[2432..16376]    Hybrid key recipient area: 8 × 1743 B
                   x25519_eph_pk(32) + mlkem_ct(1568) + AEAD(K_master, ≤143B)
[16376..]        Data slots (32 KB each)
[EOF-1024..EOF-512]  Outer header backup
[EOF-512..EOF]   Hidden header primary (or random bytes)
```

**Key design**: `K_master` is a random 32-byte key, never derived from a password.
Credentials only serve to decrypt `K_master`. Adding or revoking a recipient
**never re-encrypts any data**.

- [x] Slot layout, header format, allocation bitmap, file chain — definitive
- [x] **Format V1 is definitive** — all intermediate development versions removed
- [x] Serialization: MessagePack (`rmp-serde`, named fields) — readable from any language
- [x] Header backup: outer at EOF-512/EOF-1024 (geographic separation), hidden at [512..1024]
- [x] Anti-rollback: monotonic generation counter in allocation block + `~/.config/venom/rollback.json`

### Cipher algorithms

| ID | Algorithm | Notes |
|---:|-----------|-------|
| 0 | XChaCha20-Poly1305 | Default; 192-bit nonce |
| 1 | Deoxys-II-256 | CAESAR finalist; 120-bit nonce |
| 2 | Serpent-256-EAX | EAX = CTR + OMAC; 128-bit nonce |
| 3 | Triple (cascade) | XChaCha20-Poly1305 → Deoxys-II-256 → Serpent-256-EAX |

Password slots always use Triple encryption for `K_master`.
Cipher is never stored in plaintext — discovered by blind AEAD probing on open.

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
| Header backup | ✓ | ✓ outer + hidden |
| Anti-rollback | ✗ | ✓ |
| K_master always Triple-wrapped | ✗ | ✓ password slots |

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

hybrid_key = BLAKE3_derive_key(
    context  = "venom:hybrid:v1",
    material = x25519_shared  (32 B)
             || mlkem_ss      (32 B)
             || x25519_eph_pk (32 B, ciphertext binding)
             || mlkem_ct      (1568 B, ciphertext binding)
)
```

**Security**: an attacker must break **both** X25519 and ML-KEM-1024 simultaneously.
If quantum computers break X25519 → ML-KEM-1024 still holds.
If ML-KEM-1024 has a classical weakness → X25519 still holds.

- [x] `hybrid_generate()` → `HybridPrivateKey { x25519_sk, x25519_pk, mlkem_seed, mlkem_ek }`
- [x] `hybrid_encapsulate(pub)` → `(x25519_eph_pk, mlkem_ct, hybrid_key)`
- [x] `hybrid_decapsulate(priv, x25519_eph_pk, mlkem_ct)` → `hybrid_key`
- [x] `fingerprint` = `BLAKE3(x25519_pk || mlkem_ek)[0..8]`
- [x] Password slots (up to 8) — independent Argon2id salt per slot, always Triple-encrypted
- [x] Hybrid key slots (up to 8) — blind AEAD probing (all 4 ciphers) on open
- [x] `VnmContainer::open(path, OpenCredential::Password(pw))`
- [x] `VnmContainer::open(path, OpenCredential::PrivateKey(&hybrid_key))`
- [x] `add_key_recipient(&HybridPublicKey)` — no data re-encryption
- [x] `remove_key_recipient(&fingerprint)` — wipes slot with random bytes
- [x] `list_recipients()` → type + slot_index per slot

### Hybrid key file format

**`.key`** — complete keypair (two variants, distinguished by `protected` byte):

*Unprotected* (1 785 bytes — relies on `chmod 600`):
```
b"VKEY" + version u32 + created_at u64 + label[64] + fingerprint[8]
        + x25519_pk[32] + mlkem_ek[1568]   ← PUBLIC, always in plaintext
        + protected=0
        + x25519_sk[32] + mlkem_seed[64]   ← private, plaintext
```

*Passphrase-protected* (1 898 bytes — private scalars encrypted):
```
b"VKEY" + version + created_at + label + fingerprint
        + x25519_pk[32] + mlkem_ek[1568]   ← PUBLIC, always in plaintext
        + protected=1
        + argon2_salt[64] + kdf_profile[1]
        + encrypt_block(                    ← private, XChaCha20-Poly1305 AEAD
            Argon2id(passphrase, salt),
            aad = "vnm:key:protect:v1",
            x25519_sk[32] || mlkem_seed[64]
          ) = 144 bytes
```

**`.pub`** — public portion only, 1 688 bytes (safe to share freely):
```
b"VPUB" + version u32 + created_at u64 + label[64] + fingerprint[8]
        + x25519_pk[32] + mlkem_ek[1568]
```

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

### Tests — 43 total, all passing

| Suite | Count | Covers |
|-------|------:|--------|
| `crypto_tests` | 14 | XChaCha20 / Deoxys-II-256 / Serpent-256-EAX / Triple AEAD, wrong key, AAD binding, tamper, KDF, Triple container create/open |
| `container_tests` | 18 | create/open (all 4 ciphers), wrong password, CRUD, persistence, hidden volume, hybrid KEM, add recipient, multiple recipients, key file passphrase, rollback detection, Merkle verification, Merkle tamper detection |
| `fuse_cache_tests` (inline) | 11 | cache lifecycle, large-file chunk roundtrip, write-through, rename, unlink |

### GUI — Qt6/C++20

- [x] Create container: path, size, **4 cipher choices** (XChaCha20-Poly1305 / Deoxys-II-256 / Serpent-256-EAX / Triple), KDF profile, label, key recipients
- [x] Mount with password or private key (`.key` file + passphrase)
- [x] Unmount; vault cards showing cipher name, creation date, label
- [x] Key Manager: generate, import, export `.pub`, passphrase protection
- [x] Add/remove recipients on open container

---

## In progress / not started

### Security

- [ ] **Recipient management requires password re-entry** — `K_master` is not kept
  in mount state; adding/removing recipients requires re-opening the container.
- [ ] **Write atomicity** — crash during slot replacement can corrupt a file.
- [x] **Global integrity** — BLAKE3 Merkle tree over all encrypted slots; root in allocation block; verified at mount (detects external slot modification/removal)
- [ ] **Volume size limit** — bitmap must fit in one slot (≈ 8 GB per volume).
- [ ] **Password zeroization** — GUI password fields are plain `String`.
- [ ] **Async create** — random-fill + KDF blocks the UI thread.

### GUI

- [ ] Progress bar during container creation
- [ ] Outer safe-fill warning for hidden volumes
- [ ] Vault browser panel, tray icon, auto-unmount on idle
- [ ] CLI mode (`venom mount <file.vnm> <mp> --password-stdin`)

### FUSE / WinFSP

- [ ] Hard links, symlinks, extended attributes, timestamps, persistent ACLs
- [ ] Large directory cache
- [ ] Windows smoke test; WinFSP error mapping

### Testing & CI

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
