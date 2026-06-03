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
| Alt cipher | AES-256-GCM — 128-bit random nonce (birthday bound 2⁶⁴, non-standard IV via GHASH) |
| Integrity | 128-bit AEAD tag per slot |
| AAD | `slot_index as u64 LE` — binds ciphertext to physical location |
| Cipher anonymity | Byte 64 of the header is always `0`; the real cipher is discovered blindly via AEAD during open. An observer without the password cannot determine which cipher a container uses. |

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

- **Password slots** (max 8): `Argon2id(password, salt) → AEAD(K_master)`
- **Hybrid key slots** (max 8): `X25519 + ML-KEM-1024 → AEAD(K_master)`
  - Recipient identity is **not exposed** — no plaintext fingerprint in
    slots; all slots are tried blindly on open (recipient anonymity).
  - Post-quantum security: resistant to Shor's algorithm as long as
    ML-KEM-1024 holds; falls back to X25519 security if ML-KEM is broken.

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
| ~~No header backup~~ | Implemented: outer backup at EOF-512/EOF-1024 (geographic separation), hidden backup at [512..1024]. |
| Hidden volume: single password only | The hidden volume does not support ML-KEM key recipients or multiple passwords. |
| No `fsck` tool | Orphaned slots (from a crash during write-through) are not reclaimed automatically. |
| Custom filesystem format | A forensic examiner with the key can identify the Venom VaultNode format. Standard filesystems (FAT, ext4) inside the container would offer stronger format deniability. |
| Chunk 0 not written until `close()` | A crash before `close()` may leave write-through chunks on disk that are not referenced in the head slot index. |

---

## Cryptographic Dependencies

| Crate | Algorithm | Notes |
|-------|-----------|-------|
| `aes-gcm` | AES-256-GCM with 16-byte nonce | RustCrypto, kept up to date |
| `chacha20poly1305` | XChaCha20-Poly1305 (192-bit nonce) | RustCrypto, kept up to date |
| `ml-kem` | ML-KEM-1024 (FIPS 203) | RustCrypto, kept up to date |
| `x25519-dalek` | X25519 ECDH | kept up to date |
| `argon2` | Argon2id (RFC 9106) | RustCrypto, kept up to date |
| `sha2` | SHA-256 | RustCrypto, kept up to date |
| `zeroize` | Memory zeroing on drop | RustCrypto, kept up to date |
| `libc` | `mlock(2)` / `munlock(2)` | Unix only, for K_master swap protection |

Dependencies are reviewed on each update. `cargo audit` is recommended
before any release build.
