use vnmcore::container::CipherAlgorithm;
use vnmcore::fs::container::{VnmContainer, HiddenVolumeOptions, OpenCredential};
use vnmcore::storage::{VaultNode, NodeKind};
use vnmcore::storage::vault_fs::{DirectoryBlock, DirEntry, FileBlock};
use vnmcore::{kem_generate, kem_ek_from_seed};

const MB: u64 = 1024 * 1024;

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("vnm_{name}_{}.vnm", std::process::id()))
}

// ── Basic create / open ───────────────────────────────────────────────────────

#[test]
fn create_and_reopen_chacha() {
    let path = tmp("chacha");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"password", 4*MB, CipherAlgorithm::ChaCha20Poly1305,
        "interactive", Some("test".into()), None).unwrap();
    let c = VnmContainer::open(&path, OpenCredential::Password(b"password")).unwrap();
    assert_eq!(c.label.as_deref(), Some("test"));
    assert_eq!(c.cipher, CipherAlgorithm::ChaCha20Poly1305);
    assert!(!c.is_hidden);
    std::fs::remove_file(&path).ok();
}

#[test]
fn create_and_reopen_aes() {
    let path = tmp("aes");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::Aes256Gcm, "interactive", None, None).unwrap();
    let c = VnmContainer::open(&path, OpenCredential::Password(b"pass")).unwrap();
    assert_eq!(c.cipher, CipherAlgorithm::Aes256Gcm);
    std::fs::remove_file(&path).ok();
}

#[test]
fn wrong_password_rejected() {
    let path = tmp("wrong_pw");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"correct", 4*MB, CipherAlgorithm::ChaCha20Poly1305,
        "interactive", None, None).unwrap();
    assert!(VnmContainer::open(&path, OpenCredential::Password(b"wrong")).is_err());
    std::fs::remove_file(&path).ok();
}

// ── Root block ────────────────────────────────────────────────────────────────

#[test]
fn root_block_is_empty_directory() {
    let path = tmp("root");
    let _ = std::fs::remove_file(&path);
    let c = VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::ChaCha20Poly1305,
        "interactive", None, None).unwrap();
    match c.read_node(c.root_slot()).unwrap() {
        VaultNode::Directory(d) => assert!(d.entries.is_empty()),
        _ => panic!("root must be a directory"),
    }
    std::fs::remove_file(&path).ok();
}

// ── Node CRUD ─────────────────────────────────────────────────────────────────

#[test]
fn write_and_read_file_node() {
    let path = tmp("file_node");
    let _ = std::fs::remove_file(&path);
    let c = VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::Aes256Gcm,
        "interactive", None, None).unwrap();
    let content = b"Hello, Venom!".to_vec();
    let file = VaultNode::File(FileBlock {
        kind: NodeKind::File, total_size: content.len() as u64, next_slot: None, data: content.clone(),
    });
    let slot = c.write_node(&file).unwrap();
    match c.read_node(slot).unwrap() {
        VaultNode::File(f) => { assert_eq!(f.data, content); assert_eq!(f.total_size, content.len() as u64); }
        _ => panic!("expected file"),
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn data_survives_reopen() {
    let path = tmp("reopen");
    let _ = std::fs::remove_file(&path);
    let c = VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::ChaCha20Poly1305,
        "interactive", Some("vault".into()), None).unwrap();
    let content = b"persistent".to_vec();
    let file = VaultNode::File(FileBlock {
        kind: NodeKind::File, total_size: content.len() as u64, next_slot: None, data: content.clone(),
    });
    let slot = c.write_node(&file).unwrap();
    c.flush().unwrap();
    drop(c);
    let c2 = VnmContainer::open(&path, OpenCredential::Password(b"pass")).unwrap();
    match c2.read_node(slot).unwrap() {
        VaultNode::File(f) => assert_eq!(f.data, content),
        _ => panic!(),
    }
    std::fs::remove_file(&path).ok();
}

// ── Hidden volume ─────────────────────────────────────────────────────────────

#[test]
fn hidden_volume_both_passwords_work() {
    let path = tmp("hidden");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"outer-pass", 8*MB, CipherAlgorithm::ChaCha20Poly1305,
        "interactive", Some("Outer".into()),
        Some(HiddenVolumeOptions { password: b"hidden-pass", size_bytes: 2*MB,
            label: Some("Hidden".into()), kdf_profile: "interactive" })).unwrap();

    let outer = VnmContainer::open(&path, OpenCredential::Password(b"outer-pass")).unwrap();
    assert!(!outer.is_hidden);
    assert_eq!(outer.label.as_deref(), Some("Outer"));

    let hidden = VnmContainer::open(&path, OpenCredential::Password(b"hidden-pass")).unwrap();
    assert!(hidden.is_hidden);
    assert_eq!(hidden.label.as_deref(), Some("Hidden"));

    assert!(VnmContainer::open(&path, OpenCredential::Password(b"wrong")).is_err());
    std::fs::remove_file(&path).ok();
}

// ── ML-KEM multi-recipient ────────────────────────────────────────────────────

#[test]
fn ml_kem_generate_and_use() {
    // Test that kem_generate + ek_from_seed + encapsulate + decapsulate round-trip works
    use vnmcore::crypto::kem::{encapsulate, decapsulate};
    let (seed, ek) = kem_generate();
    let ek2 = kem_ek_from_seed(&seed);
    assert_eq!(ek, ek2, "ek_from_seed must recover the same public key");

    let (ct, ss1) = encapsulate(&ek).unwrap();
    let ss2 = decapsulate(&seed, &ct).unwrap();
    assert_eq!(ss1, ss2, "shared secrets must match");
}

#[test]
fn add_key_recipient_and_open_with_private_key() {
    let path = tmp("kem_recipient");
    let _ = std::fs::remove_file(&path);

    // Create container with password
    let c = VnmContainer::create(&path, b"outer", 8*MB, CipherAlgorithm::ChaCha20Poly1305,
        "interactive", Some("KEM test".into()), None).unwrap();

    // Generate a keypair for Alice
    let (alice_seed, alice_ek) = kem_generate();

    // Add Alice as ML-KEM recipient
    c.add_key_recipient(&alice_ek).unwrap();
    c.flush().unwrap();
    drop(c);

    // Open with Alice's private key
    let c2 = VnmContainer::open(&path, OpenCredential::PrivateKey(&alice_seed)).unwrap();
    assert_eq!(c2.label.as_deref(), Some("KEM test"));
    assert!(!c2.is_hidden);

    // Original password still works
    let c3 = VnmContainer::open(&path, OpenCredential::Password(b"outer")).unwrap();
    assert_eq!(c3.label.as_deref(), Some("KEM test"));

    std::fs::remove_file(&path).ok();
}

#[test]
fn multiple_key_recipients() {
    let path = tmp("multi_kem");
    let _ = std::fs::remove_file(&path);

    let c = VnmContainer::create(&path, b"pw", 8*MB, CipherAlgorithm::ChaCha20Poly1305,
        "interactive", None, None).unwrap();

    let (seed_a, ek_a) = kem_generate();
    let (seed_b, ek_b) = kem_generate();

    c.add_key_recipient(&ek_a).unwrap();
    c.add_key_recipient(&ek_b).unwrap();
    c.flush().unwrap();
    drop(c);

    // Both Alice and Bob can open it
    assert!(VnmContainer::open(&path, OpenCredential::PrivateKey(&seed_a)).is_ok());
    assert!(VnmContainer::open(&path, OpenCredential::PrivateKey(&seed_b)).is_ok());
    // Password still works
    assert!(VnmContainer::open(&path, OpenCredential::Password(b"pw")).is_ok());
    // Unknown key fails
    let (seed_c, _) = kem_generate();
    assert!(VnmContainer::open(&path, OpenCredential::PrivateKey(&seed_c)).is_err());

    std::fs::remove_file(&path).ok();
}
