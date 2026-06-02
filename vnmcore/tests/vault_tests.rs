use vnmcore::container::CipherAlgorithm;
use vnmcore::fs::Vault;
use vnmcore::storage::{VaultNode, NodeKind};
use vnmcore::storage::vault_fs::{DirectoryBlock, FileBlock, DirEntry};

fn tmp_dir(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("vnm_test_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

#[test]
fn create_and_reopen_chacha() {
    let path = tmp_dir("create_chacha");
    let password = b"correct-horse-battery-staple";

    Vault::create(&path, password, CipherAlgorithm::ChaCha20Poly1305, "interactive", Some("test-vault".into()))
        .expect("create should succeed");

    let vault = Vault::open(&path, password).expect("open with correct password should succeed");
    assert_eq!(vault.config.label.as_deref(), Some("test-vault"));
    assert_eq!(vault.config.cipher, CipherAlgorithm::ChaCha20Poly1305);

    std::fs::remove_dir_all(&path).ok();
}

#[test]
fn create_and_reopen_aes() {
    let path = tmp_dir("create_aes");
    let password = b"secure-passphrase";

    Vault::create(&path, password, CipherAlgorithm::Aes256Gcm, "interactive", None)
        .expect("create should succeed");

    let vault = Vault::open(&path, password).expect("open should succeed");
    assert_eq!(vault.config.cipher, CipherAlgorithm::Aes256Gcm);

    std::fs::remove_dir_all(&path).ok();
}

#[test]
fn wrong_password_rejected() {
    let path = tmp_dir("wrong_pw");
    Vault::create(&path, b"real-password", CipherAlgorithm::ChaCha20Poly1305, "interactive", None)
        .unwrap();

    let result = Vault::open(&path, b"bad-password");
    assert!(result.is_err(), "wrong password must be rejected");

    std::fs::remove_dir_all(&path).ok();
}

#[test]
fn root_block_is_empty_directory() {
    let path = tmp_dir("root_dir");
    let vault = Vault::create(&path, b"pass", CipherAlgorithm::ChaCha20Poly1305, "interactive", None).unwrap();

    let root = vault.read_node(vault.root_id()).expect("root block must be readable");
    match root {
        VaultNode::Directory(d) => assert!(d.entries.is_empty(), "fresh vault root must be empty"),
        _ => panic!("root must be a directory"),
    }

    std::fs::remove_dir_all(&path).ok();
}

#[test]
fn write_and_read_directory_block() {
    let path = tmp_dir("write_dir");
    let vault = Vault::create(&path, b"pass", CipherAlgorithm::ChaCha20Poly1305, "interactive", None).unwrap();

    // Write a subdirectory block
    let sub = VaultNode::Directory(DirectoryBlock {
        kind: NodeKind::Directory,
        entries: vec![],
    });
    let sub_id = vault.write_node(&sub).unwrap();

    // Add it to root
    let root_id = vault.root_id().to_string();
    let mut root = match vault.read_node(&root_id).unwrap() {
        VaultNode::Directory(d) => d,
        _ => panic!(),
    };
    root.entries.push(DirEntry {
        name: "subdir".into(),
        block_id: sub_id.clone(),
        kind: NodeKind::Directory,
    });
    vault.update_node(&root_id, &VaultNode::Directory(root)).unwrap();

    // Read back and verify
    let updated_root = match vault.read_node(&root_id).unwrap() {
        VaultNode::Directory(d) => d,
        _ => panic!(),
    };
    assert_eq!(updated_root.entries.len(), 1);
    assert_eq!(updated_root.entries[0].name, "subdir");
    assert_eq!(updated_root.entries[0].block_id, sub_id);

    std::fs::remove_dir_all(&path).ok();
}

#[test]
fn write_and_read_file_block() {
    let path = tmp_dir("write_file");
    let vault = Vault::create(&path, b"pass", CipherAlgorithm::Aes256Gcm, "interactive", None).unwrap();

    let content = b"Hello, Venom!".to_vec();
    let file = VaultNode::File(FileBlock {
        kind: NodeKind::File,
        total_size: content.len() as u64,
        continuation_ids: vec![],
        data: content.clone(),
    });
    let file_id = vault.write_node(&file).unwrap();

    let recovered = match vault.read_node(&file_id).unwrap() {
        VaultNode::File(f) => f,
        _ => panic!("expected file block"),
    };
    assert_eq!(recovered.data, content);
    assert_eq!(recovered.total_size, content.len() as u64);

    std::fs::remove_dir_all(&path).ok();
}

#[test]
fn vault_already_exists_error() {
    let path = tmp_dir("exists_check");
    Vault::create(&path, b"pass", CipherAlgorithm::ChaCha20Poly1305, "interactive", None).unwrap();

    // Second create in the same non-empty directory must fail
    let result = Vault::create(&path, b"pass2", CipherAlgorithm::ChaCha20Poly1305, "interactive", None);
    assert!(result.is_err());

    std::fs::remove_dir_all(&path).ok();
}
