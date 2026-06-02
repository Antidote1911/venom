#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
QT_DIR="$ROOT/venom"
BUILD_DIR="$QT_DIR/build"

echo "==> Building vnmcore-ffi (Rust)"
cargo build --release -p vnmcore-ffi

echo "==> Configuring CMake"
if [ ! -f "$BUILD_DIR/build.ninja" ]; then
    cmake -S "$QT_DIR" -B "$BUILD_DIR" -G Ninja -DCMAKE_BUILD_TYPE=Release
fi

echo "==> Compiling .ui files and building venom (Qt6/C++)"
cmake --build "$BUILD_DIR"

echo ""
echo "Build complete: $BUILD_DIR/venom-qt"
