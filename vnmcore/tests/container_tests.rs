use vnmcore::container::CipherAlgorithm;
use vnmcore::fs::container::{VnmContainer, HiddenVolumeOptions};
use vnmcore::storage::{VaultNode, NodeKind};
use vnmcore::storage::vault_fs::{DirectoryBlock, DirEntry, FileBlock};

const MB: u64 = 1024 * 1024;

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("vnm_test_{name}_{}.vnm", std::process::id()))
}

// ── Basic create / open ───────────────────────────────────────────────────────

#[test]
fn create_and_reopen_chacha() {
    let path = tmp("create_chacha");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"password", 4*MB, CipherAlgorithm::ChaCha20Poly1305, "interactive", Some("test".into()), None).unwrap();
    let c = VnmContainer::open(&path, b"password").unwrap();
    assert_eq!(c.label.as_deref(), Some("test"));
    assert_eq!(c.cipher, CipherAlgorithm::ChaCha20Poly1305);
    assert!(!c.is_hidden);
    std::fs::remove_file(&path).ok();
}

#[test]
fn create_and_reopen_aes() {
    let path = tmp("create_aes");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::Aes256Gcm, "interactive", None, None).unwrap();
    let c = VnmContainer::open(&path, b"pass").unwrap();
    assert_eq!(c.cipher, CipherAlgorithm::Aes256Gcm);
    std::fs::remove_file(&path).ok();
}

#[test]
fn wrong_password_rejected() {
    let path = tmp("wrong_pw");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"correct", 4*MB, CipherAlgorithm::ChaCha20Poly1305, "interactive", None, None).unwrap();
    let err = VnmContainer::open(&path, b"wrong");
    assert!(err.is_err());
    std::fs::remove_file(&path).ok();
}

// ── Root block ────────────────────────────────────────────────────────────────

#[test]
fn root_block_is_empty_directory() {
    let path = tmp("root_dir");
    let _ = std::fs::remove_file(&path);
    let c = VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::ChaCha20Poly1305, "interactive", None, None).unwrap();
    match c.read_node(c.root_slot()).unwrap() {
        VaultNode::Directory(d) => assert!(d.entries.is_empty(), "root must be empty on new container"),
        _ => panic!("root must be a directory"),
    }
    std::fs::remove_file(&path).ok();
}

// ── Node CRUD ─────────────────────────────────────────────────────────────────

#[test]
fn write_and_read_directory_node() {
    let path = tmp("write_dir");
    let _ = std::fs::remove_file(&path);
    let c = VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::ChaCha20Poly1305, "interactive", None, None).unwrap();

    let sub = VaultNode::Directory(DirectoryBlock { kind: NodeKind::Directory, entries: vec![] });
    let sub_slot = c.write_node(&sub).unwrap();

    let root_slot = c.root_slot();
    let mut root = match c.read_node(root_slot).unwrap() { VaultNode::Directory(d) => d, _ => panic!() };
    root.entries.push(DirEntry { name: "subdir".into(), slot: sub_slot, kind: NodeKind::Directory });
    c.update_node(root_slot, &VaultNode::Directory(root)).unwrap();

    let updated = match c.read_node(root_slot).unwrap() { VaultNode::Directory(d) => d, _ => panic!() };
    assert_eq!(updated.entries.len(), 1);
    assert_eq!(updated.entries[0].name, "subdir");
    assert_eq!(updated.entries[0].slot, sub_slot);
    std::fs::remove_file(&path).ok();
}

#[test]
fn write_and_read_file_node() {
    let path = tmp("write_file");
    let _ = std::fs::remove_file(&path);
    let c = VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::Aes256Gcm, "interactive", None, None).unwrap();
    let content = b"Hello, Venom!".to_vec();
    let file = VaultNode::File(FileBlock {
        kind: NodeKind::File, total_size: content.len() as u64,
        continuation_slots: vec![], data: content.clone(),
    });
    let slot = c.write_node(&file).unwrap();
    match c.read_node(slot).unwrap() {
        VaultNode::File(f) => { assert_eq!(f.data, content); assert_eq!(f.total_size, 13); }
        _ => panic!("expected file"),
    }
    std::fs::remove_file(&path).ok();
}

// ── Reopen after flush ────────────────────────────────────────────────────────

#[test]
fn data_survives_reopen() {
    let path = tmp("reopen");
    let _ = std::fs::remove_file(&path);
    let c = VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::ChaCha20Poly1305, "interactive", Some("vault".into()), None).unwrap();
    let content = b"persistent".to_vec();
    let file = VaultNode::File(FileBlock {
        kind: NodeKind::File, total_size: content.len() as u64,
        continuation_slots: vec![], data: content.clone(),
    });
    let slot = c.write_node(&file).unwrap();
    c.flush().unwrap();
    drop(c);

    let c2 = VnmContainer::open(&path, b"pass").unwrap();
    match c2.read_node(slot).unwrap() {
        VaultNode::File(f) => assert_eq!(f.data, content),
        _ => panic!(),
    }
    std::fs::remove_file(&path).ok();
}

// ── Hidden volume ─────────────────────────────────────────────────────────────

#[test]
fn hidden_volume_create_and_mount_both() {
    let path = tmp("hidden");
    let _ = std::fs::remove_file(&path);

    // Create with hidden volume
    VnmContainer::create(
        &path,
        b"outer-pass",
        8 * MB,
        CipherAlgorithm::ChaCha20Poly1305,
        "interactive",
        Some("Outer".into()),
        Some(HiddenVolumeOptions {
            password:   b"hidden-pass",
            size_bytes: 2 * MB,
            label:      Some("Hidden".into()),
            kdf_profile: "interactive",
        }),
    ).unwrap();

    // Mount outer volume with outer password
    let outer = VnmContainer::open(&path, b"outer-pass").unwrap();
    assert!(!outer.is_hidden);
    assert_eq!(outer.label.as_deref(), Some("Outer"));

    // Mount hidden volume with hidden password
    let hidden = VnmContainer::open(&path, b"hidden-pass").unwrap();
    assert!(hidden.is_hidden);
    assert_eq!(hidden.label.as_deref(), Some("Hidden"));

    // Wrong password → error
    assert!(VnmContainer::open(&path, b"wrong").is_err());

    std::fs::remove_file(&path).ok();
}

#[test]
fn hidden_and_outer_volumes_independent() {
    let path = tmp("hidden_data");
    let _ = std::fs::remove_file(&path);

    VnmContainer::create(
        &path, b"outer", 8*MB, CipherAlgorithm::ChaCha20Poly1305, "interactive", None,
        Some(HiddenVolumeOptions { password: b"hidden", size_bytes: 2*MB, label: None, kdf_profile: "interactive" }),
    ).unwrap();

    // Write to outer volume
    let outer = VnmContainer::open(&path, b"outer").unwrap();
    let outer_data = b"outer secret".to_vec();
    let outer_file = VaultNode::File(FileBlock {
        kind: NodeKind::File, total_size: outer_data.len() as u64,
        continuation_slots: vec![], data: outer_data.clone(),
    });
    let outer_slot = outer.write_node(&outer_file).unwrap();
    outer.flush().unwrap();

    // Write to hidden volume
    let hidden_c = VnmContainer::open(&path, b"hidden").unwrap();
    let hidden_data = b"hidden secret".to_vec();
    let hidden_file = VaultNode::File(FileBlock {
        kind: NodeKind::File, total_size: hidden_data.len() as u64,
        continuation_slots: vec![], data: hidden_data.clone(),
    });
    let hidden_slot = hidden_c.write_node(&hidden_file).unwrap();
    hidden_c.flush().unwrap();

    // Read back outer — its data intact
    let outer2 = VnmContainer::open(&path, b"outer").unwrap();
    match outer2.read_node(outer_slot).unwrap() {
        VaultNode::File(f) => assert_eq!(f.data, outer_data),
        _ => panic!(),
    }

    // Read back hidden — its data intact
    let hidden2 = VnmContainer::open(&path, b"hidden").unwrap();
    match hidden2.read_node(hidden_slot).unwrap() {
        VaultNode::File(f) => assert_eq!(f.data, hidden_data),
        _ => panic!(),
    }

    std::fs::remove_file(&path).ok();
}
