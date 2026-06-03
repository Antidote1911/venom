/// Diagnostic: create or open a container and mount it.
/// Usage: cargo run -p vnmcore --example mount_test -- <container.vnm> <mountpoint>
use std::sync::Arc;
use vnmcore::{container::CipherAlgorithm, fs::{VnmContainer, fuse::driver}, OpenCredential};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: mount_test <container.vnm> <mountpoint>");
        std::process::exit(1);
    }
    let container_path = &args[1];
    let mountpoint     = &args[2];
    const MB: u64 = 1024 * 1024;

    let c = if std::path::Path::new(container_path).exists() {
        println!("[1/3] Opening existing container {container_path}…");
        VnmContainer::open(container_path, OpenCredential::Password(b"test-password")).expect("open failed")
    } else {
        println!("[1/3] Creating new container {container_path} (16 MB)…");
        VnmContainer::create(
            container_path, b"test-password", 16 * MB,
            CipherAlgorithm::XChaCha20Poly1305, "interactive",
            Some("test".into()), None,
        ).expect("create failed")
    };

    println!("[2/3] Mounting at {mountpoint}  (fusermount3 -u <mp> to stop)…");
    match driver::mount(Arc::new(c), mountpoint) {
        Ok(_)  => println!("[3/3] Unmounted cleanly."),
        Err(e) => eprintln!("[3/3] Mount error: {e}"),
    }
}
