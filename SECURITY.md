# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Send a private report to: **libertykondracki28@outlook.com**

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- The affected component (`vnmcore`, `vnmcore-ffi`, `venom` Qt frontend)

You will receive an acknowledgement within **72 hours** and a status update
within **7 days**. We will coordinate a fix and disclosure timeline with you.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| `master` (latest) | ✓ |
| Older commits | ✗ |

Venom has not yet reached a stable release. All security fixes are applied
to `master`. There are no backport branches.

---

## Security Properties

### Encryption

| Property | Value |
|----------|-------|
| Default cipher | XChaCha20-Poly1305 — 192-bit random nonce (birthday bound 2⁹⁶) |
| Alt cipher — Deoxys-II-256 | 120-bit random nonce (birthday bound 2⁶⁰); CAESAR "defense in depth" finalist |
| Alt cipher — Serpent-256-EAX | 128-bit random nonce; EAX = CTR + OMAC (Serpent-based MAC, no external primitive) |
| Triple cipher | XChaCha20-Poly1305 + Deoxys-II-256 + Serpent-256-EAX — 111 B overhead per slot; three 256-bit subkeys via BLAKE3 `derive_key()`, each layer authenticated independently |
| Password slot protection | **Always Triple** — `K_master` in password slots is wrapped with Triple regardless of the container's data cipher |
| Per-slot key isolation | `slot_key = BLAKE3_derive_key("venom:slot:v1", K_master‖slot_index)` — cipher-level compromise of one slot does not expose K_master or other slot keys |
| Slot integrity | 128-bit AEAD tag per slot (or 48 B for Triple); slot_index in both derived key and AAD (two independent binding layers) |
| Global integrity | BLAKE3 Merkle tree over all encrypted slots; root stored in allocation block; verified at mount time — detects external slot modification or removal |
| Cipher anonymity | Byte 64 of the header is always `0`; the real cipher is discovered blindly via AEAD probing (all 4 ciphers tried) during open. An observer without the password cannot determine which cipher a container uses. |

Every slot is independently authenticated. Bit-flip attacks and slot-swap
attacks are detected before decryption completes.

### Key Memory Protection

The master key (`K_master`) is generated and decrypted directly into
`mlock(2)`-pinned heap pages, preventing the OS from writing it to the
swap file. The memory is also zeroed via `Zeroize` on drop.

### Anti-Rollback

Each container carries a monotonically increasing generation counter in its
allocation block. On every `flush()`, the counter is incremented and the new
value is persisted to `~/.config/venom/rollback.json`. On the next open,
if the container's generation is lower than the stored baseline,
`VnmError::RollbackDetected` is returned — the container may have been
replaced with an older copy (backup replay, cloud sync regression).
`VnmContainer::reset_rollback_state()` resets the baseline for deliberate restores.

### Key Derivation

| Profile | Algorithm | Memory | Iterations | Parallelism |
|---------|-----------|-------:|----------:|------------:|
| `interactive` | Argon2id (RFC 9106) | 64 MiB | 3 | 4 |
| `sensitive`   | Argon2id (RFC 9106) | 256 MiB | 4 | 4 |

Argon2id is memory-hard: GPU farms and ASICs are impractical at these
parameters. The KDF profile is stored as a 1-byte id (0 or 1) — exact
parameters are not exposed.

### Recipient Model

- **Password slots** (max 8): `Argon2id(password, salt) → Triple_AEAD(K_master)`
  Password slots always use Triple encryption for the strongest possible key
  wrapping, independently of which cipher the container data uses.
- **Hybrid key slots** (max 8): `X25519 + ML-KEM-1024 → AEAD(K_master)`
  - Recipient identity is **not exposed** — no plaintext fingerprint in
    slots; all slots are tried blindly on open (recipient anonymity).
  - Post-quantum security: resistant to Shor's algorithm as long as
    ML-KEM-1024 holds; falls back to X25519 security if ML-KEM is broken.

### USB Key Workflow

Private key material can be kept exclusively on a USB drive, never written to the host machine:

- **Generate to USB**: the Key Manager saves `<fingerprint>.key` directly to `<usb>/venom/`
  via `vnm_key_generate_to_dir()` — `~/.config/venom/keys/` is never touched.
- **Mount from USB**: the GUI detects `.key` files on removable volumes via `QStorageInfo`
  and reads them in-place. The path is passed directly to the decryption routine; no copy
  is made on the host disk.
- **Air-gap use case**: take the container to a work machine, insert USB, decrypt, eject —
  no key material ever persists on the work machine.
- **Combined protection**: pair USB key with a passphrase on the `.key` file for two-factor
  security (something you have + something you know).

### Plausible Deniability

- The entire file is filled with cryptographically random bytes at creation.
- Unused recipient slots are indistinguishable from active slots.
- **Hidden volumes**: a second encrypted volume lives at the end of the file.
  Its header is encrypted with a key derived directly from the hidden
  password — no structural marker distinguishes it from random bytes.
- The outer header claims full container capacity; no field reveals the
  existence or size of a hidden volume.

### Forward Secrecy

Freed data slots are immediately overwritten with random bytes before being
returned to the free list. Deleted files leave no recoverable ciphertext.

---

## Known Limitations

| Limitation | Impact |
|------------|--------|
| Hidden volume: single password only | The hidden volume does not support ML-KEM key recipients or multiple passwords. |
| No `fsck` tool | Orphaned slots (from a crash during write-through) are not reclaimed automatically. |
| Custom filesystem format | A forensic examiner with the key can identify the Venom VaultNode format. Standard filesystems (FAT, ext4) inside the container would offer stronger format deniability. |
| Chunk 0 not written until `close()` | A crash before `close()` may leave write-through chunks on disk that are not referenced in the head slot index. |
| Write atomicity | Crash during slot replacement can corrupt a file. |

---

## Cryptographic Dependencies

| Crate | Algorithm | Notes |
|-------|-----------|-------|
| `chacha20poly1305 0.11-rc.3` | XChaCha20-Poly1305 (192-bit nonce) | RustCrypto, kept up to date |
| `deoxys 0.2.0-rc.3` | Deoxys-II-256 AEAD (120-bit nonce) | RustCrypto, standalone cipher + Triple layer 2 |
| `eax 0.6.0-rc.3` | EAX mode (CTR + OMAC) | RustCrypto, used with `Serpent256` newtype |
| `serpent 0.6.0` | Serpent block cipher (128-bit blocks, 256-bit key via `Serpent256` newtype) | RustCrypto; used in EAX mode for both standalone cipher and Triple layer 3 |
| `cipher 0.5` | `BlockCipherEncrypt`, `BlockCipherEncClosure` traits | RustCrypto |
| `hybrid-array 0.4` | `Array<u8, U16>` block type, typenum bounds | RustCrypto |
| `ml-kem 0.3` | ML-KEM-1024 (FIPS 203) | RustCrypto, kept up to date |
| `x25519-dalek 2` | X25519 ECDH | kept up to date |
| `argon2 0.5` | Argon2id (RFC 9106) | RustCrypto, kept up to date |
| `blake3 1` | BLAKE3 — hashing, `derive_key()` (Triple subkeys, KEM combiner, per-slot keys), Merkle tree, fingerprints | kept up to date |
| `zeroize` | Memory zeroing on drop | RustCrypto, kept up to date |
| `libc` | `mlock(2)` / `munlock(2)` | Unix only, for K_master swap protection |

Dependencies are reviewed on each update. `cargo audit` is recommended
before any release build.
