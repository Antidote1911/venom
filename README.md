# Venom

**Post-quantum encrypted container with hidden volumes and multi-recipient support.**

Venom stores an entire encrypted filesystem inside a single `.vnm` file.
The file is filled with random bytes at creation — unused space is
indistinguishable from encrypted data, enabling plausible deniability.

---

## Features

- **AEAD encryption** — four cipher choices (see table below); one or three auth tags per 32 KB slot
- **Password slot protection** — `K_master` in password slots is **always** wrapped with Triple encryption regardless of the container cipher
- **Cipher anonymity** — cipher choice is never exposed in plaintext; discovered blindly via AEAD on open
- **Memory-hard KDF** — Argon2id (interactive: 64 MiB / sensitive: 256 MiB)
- **Post-quantum recipients** — X25519 + ML-KEM-1024 hybrid KEM (NIST FIPS 203)
- **Multi-recipient** — up to 8 password slots and 8 hybrid key slots per container
- **Recipient anonymity** — no plaintext fingerprint in key slots; all slots tried blindly
- **Hidden volumes** — a second encrypted volume lives at EOF, indistinguishable from random bytes
- **Anti-rollback** — monotonic generation counter detects container replacement with an older copy
- **Forward secrecy** — freed slots are immediately overwritten with random bytes
- **K_master in locked memory** — master key generated and decrypted directly into `mlock`'d heap pages, never written to swap
- **FUSE mount** — containers mount as a regular directory on Linux
- **Qt6 GUI** — create, mount, unmount, manage recipients

### Cipher algorithms

| ID | Algorithm | Nonce | Tag | Overhead | Notes |
|---:|-----------|------:|----:|--------:|-------|
| 0 | XChaCha20-Poly1305 | 192 bit | 16 B | 48 B | Default; birthday bound 2⁹⁶ |
| 1 | Deoxys-II-256 | 120 bit | 16 B | 39 B | CAESAR "defense in depth" finalist |
| 2 | Serpent-256-EAX | 128 bit | 16 B | 40 B | EAX = CTR + OMAC (Serpent-based) |
| 3 | Triple (cascade) | 55 B (3×) | 64 B | 127 B | XChaCha20-Poly1305 → Deoxys-II-256 → Serpent-256 (3 layers) |

---

## Comparison with VeraCrypt

| Property | VeraCrypt | Venom |
|----------|:---------:|:-----:|
| **Encryption mode** | XTS-AES (no integrity) | AEAD per slot (XChaCha20 / Deoxys-II-256 / Serpent-EAX / **Triple**) |
| **Per-block authentication** | ✗ silent corruption possible | ✓ 128-bit tag (or 64 B Triple), decryption fails on tampering |
| **Slot-swap / relocation attack** | ✗ | ✓ slot index as AAD |
| **Nonce** | Deterministic (sector number) | Random per write (120–192 bit depending on cipher) |
| **Cipher anonymity** | N/A | ✓ cipher_id always 0; real cipher discovered blindly |
| **KDF** | PBKDF2-SHA512 | Argon2id (memory-hard, RFC 9106) |
| **GPU/ASIC resistance** | ✗ CPU-bound only | ✓ 64–256 MiB RAM required per guess |
| **Post-quantum recipients** | ✗ | ✓ X25519 + ML-KEM-1024 (NIST FIPS 203) |
| **Multi-recipient** | ✗ single password/keyfile | ✓ up to 8 passwords + 8 hybrid keys |
| **Recipient anonymity** | N/A | ✓ no plaintext fingerprint in container |
| **Hidden volumes** | ✓ | ✓ |
| **Anti-rollback** | ✗ | ✓ monotonic generation counter + local state file |
| **Forward secrecy (deleted files)** | ✗ ciphertext remains on disk | ✓ slot wiped with random bytes on free |
| **Key material in locked memory** | ✗ | ✓ K_master in `mlock`'d heap, never swapped |
| **Header backup** | ✓ redundant copy | ✓ outer at EOF, hidden at [512..1024] (geographic separation) |
| **Cipher cascades** | ✓ AES-Twofish-Serpent… | ✓ Triple: XChaCha20-256 + Deoxys-II-256 + Serpent-256 |
| **Inner filesystem** | FAT / exFAT / ext4 / NTFS | Custom VaultNode (msgpack) |
| **Single-file container** | ✓ | ✓ |
| **FUSE mount** | ✓ | ✓ |
| **Open-source** | ✓ | ✓ |

> VeraCrypt's XTS mode was designed for raw disk encryption where the OS filesystem
> layer provides integrity. Venom authenticates every slot independently — there is
> no equivalent OS layer to rely on inside a FUSE container.

---

## Security model

Each 32 KB slot is independently encrypted with a fresh random nonce and
authenticated with `slot_index` as AAD (prevents slot-swap attacks).
Password slots always use Triple encryption to protect `K_master` regardless
of the container's data cipher.
See [`FORMAT.md`](FORMAT.md) for the full binary format specification and
[`SECURITY.md`](SECURITY.md) for the security policy and known limitations.

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| Rust | 1.75+ |
| C++ compiler | C++20 (GCC 12+ or Clang 15+) |
| Qt | 6.5+ |
| FUSE | `libfuse3` (Linux) |
| CMake | 3.20+ |

---

## Build

### Core library + FFI

```sh
cargo build --release
```

The compiled library is at `target/release/libvnmcore_ffi.so`.

### Qt6 frontend

```sh
cd venom
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Or open the `venom/` directory in Qt Creator.

---

## Usage (CLI — `vnmcore` examples)

### Create a container

```rust
VnmContainer::create(
    "vault.vnm",
    b"my-password",
    512 * 1024 * 1024,               // 512 MB
    CipherAlgorithm::XChaCha20Poly1305, // ::DeoxysII256 | ::Serpent256 | ::Triple
    "interactive",
    Some("My vault".into()),
    None,                             // no hidden volume
)?;
```

### Open and mount

```sh
# via Qt GUI: drag the .vnm file onto the window
# or via FUSE directly (see vnmcore/examples/)
```

### Add a post-quantum recipient

```sh
# Generate a keypair
# venom GUI → Key Manager → Generate

# Add the recipient's .pub file to an open container
# venom GUI → container info → Add recipient → select .pub
```

---

## Architecture

```
venom/              Qt6/C++20 frontend
vnmcore-ffi/        C FFI layer (vnmcore → Qt bridge)
vnmcore/
  src/
    container/      header, recipient slots (password + hybrid KEM)
    crypto/         AEAD, Argon2id, X25519, ML-KEM-1024, key files
    fs/
      container.rs  VnmContainer API (create, open, recipients)
      fuse.rs       FUSE driver with chunk-level LRU cache
    storage/
      slot_store.rs encrypted slot I/O + allocation bitmap + generation counter
      vault_fs.rs   VaultNode types (Directory, File, FileData, FileIndex)
    locked_memory.rs  mlock wrapper for key material
    rollback.rs       anti-rollback generation state (~/.config/venom/rollback.json)
```

### File storage model

Files are split into 30 KB chunks. The head slot stores metadata and an
ordered index of chunk slot ids — no linked list traversal needed.
Random access is O(1). The FUSE driver keeps at most ~7.7 MB of decoded
chunks in memory per open file regardless of file size.

---

## Key files

Venom uses hybrid keypairs stored in `~/.config/venom/keys/`.

| Extension | Content |
|-----------|---------|
| `.key` | Full keypair (X25519 scalar + ML-KEM-1024 seed), optionally passphrase-protected |
| `.pub` | Public portion only — safe to share with container owners |

Share your `.pub` file with anyone who should be able to open your containers.

---

## Format

The complete binary format is documented in [`FORMAT.md`](FORMAT.md):
container layout, header fields, recipient slot encodings, chunk index
structure, key file formats, and FUSE write semantics.

---

## License

MIT — see [`LICENSE`](LICENSE) if present, or `[workspace.package] license`
in `Cargo.toml`.
