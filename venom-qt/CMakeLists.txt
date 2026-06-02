cmake_minimum_required(VERSION 3.22)
project(venom-qt VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# ── Qt6 ───────────────────────────────────────────────────────────────────────
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Concurrent)
qt_standard_project_setup()

# ── vnmcore-ffi ───────────────────────────────────────────────────────────────
# Build the Rust library if not already built.
# Run:  cargo build --release -p vnmcore-ffi   (from the workspace root)
# Then: cmake -DVNM_LIB_DIR=<workspace>/target/release ..

if(NOT DEFINED VNMCORE_WORKSPACE)
    set(VNMCORE_WORKSPACE "${CMAKE_SOURCE_DIR}/..")
endif()

if(NOT DEFINED VNM_LIB_DIR)
    set(VNM_LIB_DIR "${VNMCORE_WORKSPACE}/target/release")
endif()

set(VNM_INCLUDE_DIR "${VNMCORE_WORKSPACE}/vnmcore-ffi/include")

# Optional: build the Rust library automatically via CMake
add_custom_target(vnmcore_ffi_build
    COMMAND cargo build --release -p vnmcore-ffi
    WORKING_DIRECTORY "${VNMCORE_WORKSPACE}"
    COMMENT "Building vnmcore-ffi (Rust)"
)

# ── Source files ──────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/backend/VenomCore.h
    src/backend/VenomCore.cpp
    src/backend/MountWorker.h
    src/backend/MountWorker.cpp
    src/ui/MainWindow.h
    src/ui/MainWindow.cpp
    src/ui/VaultCard.h
    src/ui/VaultCard.cpp
    src/ui/CreateDialog.h
    src/ui/CreateDialog.cpp
    src/ui/MountDialog.h
    src/ui/MountDialog.cpp
    src/ui/KeyManagerDialog.h
    src/ui/KeyManagerDialog.cpp
    src/ui/Style.h
)

qt_add_executable(venom-qt ${SOURCES})

target_include_directories(venom-qt PRIVATE
    src
    "${VNM_INCLUDE_DIR}"
)

# Link the Rust library
if(UNIX AND NOT APPLE)
    # fuse3 is required by the fuser crate embedded in libvnmcore_ffi.a
    find_library(FUSE3_LIB NAMES fuse3 REQUIRED)
    target_link_libraries(venom-qt PRIVATE
        Qt6::Core Qt6::Widgets Qt6::Concurrent
        "${VNM_LIB_DIR}/libvnmcore_ffi.a"
        ${FUSE3_LIB}
        dl pthread m
    )
elseif(APPLE)
    target_link_libraries(venom-qt PRIVATE
        Qt6::Core Qt6::Widgets Qt6::Concurrent
        "${VNM_LIB_DIR}/libvnmcore_ffi.a"
    )
elseif(WIN32)
    target_link_libraries(venom-qt PRIVATE
        Qt6::Core Qt6::Widgets Qt6::Concurrent
        "${VNM_LIB_DIR}/vnmcore_ffi.lib"
        ws2_32 userenv bcrypt ntdll
    )
endif()

add_dependencies(venom-qt vnmcore_ffi_build)
