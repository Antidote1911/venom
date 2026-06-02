/// Diagnostic tool: create a vault, mount it, write a file, unmount.
/// Usage:  cargo run -p vnmcore --example mount_test -- <vault_dir> <mountpoint>
use std::sync::Arc;
use vnmcore::{container::CipherAlgorithm, fs::{Vault, fuse::driver}};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: mount_test <vault_dir> <mountpoint>");
        std::process::exit(1);
    }
    let vault_dir  = &args[1];
    let mountpoint = &args[2];

    // Create or open vault
    let vault = if std::path::Path::new(vault_dir).join("vnm_bootstrap.json").exists() {
        println!("[1/3] Opening existing vault at {vault_dir}…");
        Vault::open(vault_dir, b"test-password").expect("open failed")
    } else {
        println!("[1/3] Creating new vault at {vault_dir}…");
        std::fs::create_dir_all(vault_dir).ok();
        Vault::create(vault_dir, b"test-password", CipherAlgorithm::ChaCha20Poly1305, "interactive", Some("test".into()))
            .expect("create failed")
    };

    println!("[2/3] Mounting at {mountpoint}  (Ctrl-C or fusermount3 -u to stop)…");
    match driver::mount(Arc::new(vault), mountpoint) {
        Ok(_)  => println!("[3/3] Unmounted cleanly."),
        Err(e) => eprintln!("[3/3] Mount error: {e}"),
    }
}
