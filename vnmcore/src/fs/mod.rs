pub mod container;

pub use container::{VnmContainer, HiddenVolumeOptions, MIN_SIZE};

#[cfg(target_family = "unix")]
pub mod fuse;
