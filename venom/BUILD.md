# Build venom-qt

## Prerequisites

```bash
# Arch Linux
sudo pacman -S qt6-base cmake ninja

# Ubuntu 24.04+
sudo apt install qt6-base-dev cmake ninja-build

# Fedora
sudo dnf install qt6-qtbase-devel cmake ninja-build
```

## Step 1 — Build the Rust library

```bash
cd /path/to/venom           # workspace root
cargo build --release -p vnmcore-ffi
```

This produces:
- `target/release/libvnmcore_ffi.a`  (static, used by CMake)
- `target/release/libvnmcore_ffi.so` (shared, optional)

## Step 2 — Build the Qt6 application

```bash
cd venom-qt
mkdir build && cd build
cmake .. -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DVNMCORE_WORKSPACE=/path/to/venom
ninja
```

The binary is at `build/venom-qt`.

## Notes

- The CMake target `vnmcore_ffi_build` rebuilds the Rust library automatically
  whenever you run `ninja` (requires `cargo` in PATH).
- On Windows, replace the static lib path with `vnmcore_ffi.lib` and link
  against `ws2_32 userenv bcrypt ntdll`.
- The header is at `vnmcore-ffi/include/vnmcore.h` — include it in any C/C++ project.

## Architecture

```
Qt6 C++20 GUI
      │
      │ calls
      ▼
vnmcore-ffi (cdylib / staticlib)
      │
      │ uses
      ▼
vnmcore (Rust)
  ├── crypto: Argon2id, AES-GCM, ChaCha20, ML-KEM-1024, X25519
  ├── container: .vnm format v1, hidden volume, multi-recipient
  └── fs: FUSE driver (Unix), WinFSP driver (Windows)
```
