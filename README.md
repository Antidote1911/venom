# Venom

**Post-quantum encrypted container with hidden volumes and multi-recipient support.**

Venom stores an entire encrypted filesystem inside a single `.vnm` file.
The file is filled with random bytes at creation — unused space is
indistinguishable from encrypted data, enabling plausible deniability.

---

## Features

- **AEAD encryption** — AES-256-GCM or ChaCha20-Poly1305, one 128-bit auth tag per 30 KB slot
- **Memory-hard KDF** — Argon2id (interactive: 64 MiB / sensitive: 256 MiB)
- **Post-quantum recipients** — X25519 + ML-KEM-1024 hybrid KEM (NIST FIPS 203)
- **Multi-recipient** — up to 8 password slots and 8 hybrid key slots per container
- **Recipient anonymity** — no plaintext fingerprint in key slots; all slots tried blindly
- **Hidden volumes** — a second encrypted volume lives at EOF, indistinguishable from random bytes
- **Forward secrecy** — freed slots are immediately overwritten with random bytes
- **FUSE mount** — containers mount as a regular directory on Linux
- **Qt6 GUI** — create, mount, unmount, manage recipients

---

## Security model

Each 32 KB slot is independently encrypted with a fresh random nonce and
authenticated with `slot_index` as AAD (prevents slot-swap attacks).
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
    512 * 1024 * 1024,          // 512 MB
    CipherAlgorithm::ChaCha20Poly1305,
    "interactive",
    Some("My vault".into()),
    None,                        // no hidden volume
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
      slot_store.rs encrypted slot I/O + allocation bitmap
      vault_fs.rs   VaultNode types (Directory, File, FileData, FileIndex)
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
