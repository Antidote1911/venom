pub mod container;

pub use container::{VnmContainer, HiddenVolumeOptions, MIN_SIZE};

#[cfg(all(target_family = "unix", feature = "fuse"))]
pub mod fuse;

#[cfg(target_os = "windows")]
pub mod winfsp;
