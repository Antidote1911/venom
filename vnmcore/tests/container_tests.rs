use vnmcore::container::CipherAlgorithm;
use vnmcore::fs::container::{VnmContainer, HiddenVolumeOptions, OpenCredential};
use vnmcore::storage::{VaultNode, NodeKind};
use vnmcore::storage::vault_fs::FileBlock;
use vnmcore::hybrid_generate;
use vnmcore::error::VnmError;

const MB: u64 = 1024 * 1024;

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("vnm_{name}_{}.vnm", std::process::id()))
}

// ── Basic create / open ───────────────────────────────────────────────────────


#[test]
fn create_and_reopen_chacha() {
    let path = tmp("chacha");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"password", 4*MB, CipherAlgorithm::XChaCha20Poly1305,
        "interactive", Some("test".into()), None).unwrap();
    let c = VnmContainer::open(&path, OpenCredential::Password(b"password")).unwrap();
    assert_eq!(c.label.as_deref(), Some("test"));
    assert_eq!(c.cipher, CipherAlgorithm::XChaCha20Poly1305);
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
    VnmContainer::create(&path, b"correct", 4*MB, CipherAlgorithm::XChaCha20Poly1305,
        "interactive", None, None).unwrap();
    assert!(VnmContainer::open(&path, OpenCredential::Password(b"wrong")).is_err());
    std::fs::remove_file(&path).ok();
}

// ── Anti-rollback ─────────────────────────────────────────────────────────────

#[test]
fn rollback_detected_after_container_replaced() {
    let path = tmp("rollback");
    let _ = std::fs::remove_file(&path);

    // Create and mount the container (flush establishes generation baseline)
    let c = VnmContainer::create(&path, b"pw", 4*MB, CipherAlgorithm::XChaCha20Poly1305,
        "interactive", None, None).unwrap();
    c.flush().unwrap(); // generation = 1, stored in rollback state
    let snapshot = std::fs::read(&path).unwrap(); // snapshot at generation 1
    c.flush().unwrap(); // generation = 2
    c.flush().unwrap(); // generation = 3
    drop(c);

    // "Attacker" replaces the container with the old snapshot (generation = 1)
    std::fs::write(&path, &snapshot).unwrap();

    // Re-opening must fail with RollbackDetected
    // create() calls save_free_list() → gen=1; each flush() increments again.
    // snapshot is taken after first flush() → gen=2.
    // Two more flush() calls → gen=4 (last baseline).
    // After restore: current_gen=2 < expected_gen=4.
    match VnmContainer::open(&path, OpenCredential::Password(b"pw")) {
        Err(VnmError::RollbackDetected { current_gen: 2, expected_gen: 4 }) => {}
        Err(e) => panic!("expected RollbackDetected(2, 4), got: {e}"),
        Ok(_)  => panic!("open should have failed with rollback error"),
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn reset_rollback_allows_deliberate_restore() {
    let path = tmp("rollback_reset");
    let _ = std::fs::remove_file(&path);

    let c = VnmContainer::create(&path, b"pw", 4*MB, CipherAlgorithm::XChaCha20Poly1305,
        "interactive", None, None).unwrap();
    c.flush().unwrap();
    let snapshot = std::fs::read(&path).unwrap();
    c.flush().unwrap();
    c.flush().unwrap();

    // Reset the rollback baseline (simulates "I know this is a restore")
    c.reset_rollback_state().unwrap();
    drop(c);

    // Restore to old snapshot
    std::fs::write(&path, &snapshot).unwrap();

    // Should open successfully after reset
    assert!(VnmContainer::open(&path, OpenCredential::Password(b"pw")).is_ok());

    std::fs::remove_file(&path).ok();
}

// ── Header backup / recovery ──────────────────────────────────────────────────

#[test]
fn backup_header_survives_primary_corruption() {
    use std::io::{Seek, SeekFrom, Write};
    let path = tmp("header_backup");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"password", 4*MB, CipherAlgorithm::XChaCha20Poly1305,
        "interactive", Some("backup test".into()), None).unwrap();

    // Corrupt the primary outer header (first 512 bytes) with zeros
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&[0u8; 512]).unwrap();
    }

    // Container must still open using the backup header at EOF-512
    let c = VnmContainer::open(&path, OpenCredential::Password(b"password")).unwrap();
    assert_eq!(c.label.as_deref(), Some("backup test"));
    assert!(!c.is_hidden);
    std::fs::remove_file(&path).ok();
}

#[test]
fn hidden_backup_header_survives_primary_corruption() {
    use std::io::{Seek, SeekFrom, Write};
    let path = tmp("hidden_backup");
    let _ = std::fs::remove_file(&path);
    VnmContainer::create(&path, b"outer", 8*MB, CipherAlgorithm::XChaCha20Poly1305,
        "interactive", Some("Outer".into()),
        Some(vnmcore::fs::container::HiddenVolumeOptions {
            password: b"hidden", size_bytes: 2*MB,
            label: Some("Hidden".into()), kdf_profile: "interactive",
        })).unwrap();

    // Corrupt the primary hidden header (last 512 bytes) with zeros
    let file_size = std::fs::metadata(&path).unwrap().len();
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(file_size - 512)).unwrap();
        f.write_all(&[0u8; 512]).unwrap();
    }

    // Hidden volume must still open using the backup header at [512..1024]
    let c = VnmContainer::open(&path, OpenCredential::Password(b"hidden")).unwrap();
    assert!(c.is_hidden);
    assert_eq!(c.label.as_deref(), Some("Hidden"));
    std::fs::remove_file(&path).ok();
}

// ── Root block ────────────────────────────────────────────────────────────────

#[test]
fn root_block_is_empty_directory() {
    let path = tmp("root");
    let _ = std::fs::remove_file(&path);
    let c = VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::XChaCha20Poly1305,
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
        kind: NodeKind::File, total_size: content.len() as u64,
        data_slots: vec![], index_chain: None, data: content.clone(),
    });
    let slot = c.write_node(&file).unwrap();
    match c.read_node(slot).unwrap() {
        VaultNode::File(f) => {
            assert_eq!(f.data, content);
            assert_eq!(f.total_size, content.len() as u64);
        }
        _ => panic!("expected file"),
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn data_survives_reopen() {
    let path = tmp("reopen");
    let _ = std::fs::remove_file(&path);
    let c = VnmContainer::create(&path, b"pass", 4*MB, CipherAlgorithm::XChaCha20Poly1305,
        "interactive", Some("vault".into()), None).unwrap();
    let content = b"persistent".to_vec();
    let file = VaultNode::File(FileBlock {
        kind: NodeKind::File, total_size: content.len() as u64,
        data_slots: vec![], index_chain: None, data: content.clone(),
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
    VnmContainer::create(&path, b"outer-pass", 8*MB, CipherAlgorithm::XChaCha20Poly1305,
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
fn hybrid_kem_round_trip() {
    use vnmcore::crypto::hybrid_kem::{generate, encapsulate, decapsulate};
    let alice = generate();
    let ct = encapsulate(&alice.public).unwrap();
    let ss2 = decapsulate(&alice, &ct.x25519_eph_pk, &ct.mlkem_ct).unwrap();
    assert_eq!(ct.shared_secret, ss2, "hybrid shared secrets must match");
}

#[test]
fn add_key_recipient_and_open_with_private_key() {
    let path = tmp("hybrid_recipient");
    let _ = std::fs::remove_file(&path);

    let c = VnmContainer::create(&path, b"outer", 8*MB, CipherAlgorithm::XChaCha20Poly1305,
        "interactive", Some("Hybrid test".into()), None).unwrap();

    let alice = hybrid_generate();
    c.add_key_recipient(&alice.public).unwrap();
    c.flush().unwrap();
    drop(c);

    // Open with Alice's hybrid private key
    let c2 = VnmContainer::open(&path, OpenCredential::PrivateKey(&alice)).unwrap();
    assert_eq!(c2.label.as_deref(), Some("Hybrid test"));

    // Password still works
    assert!(VnmContainer::open(&path, OpenCredential::Password(b"outer")).is_ok());

    std::fs::remove_file(&path).ok();
}

#[test]
fn multiple_key_recipients() {
    let path = tmp("multi_hybrid");
    let _ = std::fs::remove_file(&path);

    let c = VnmContainer::create(&path, b"pw", 8*MB, CipherAlgorithm::XChaCha20Poly1305,
        "interactive", None, None).unwrap();

    let alice = hybrid_generate();
    let bob   = hybrid_generate();
    c.add_key_recipient(&alice.public).unwrap();
    c.add_key_recipient(&bob.public).unwrap();
    c.flush().unwrap();
    drop(c);

    assert!(VnmContainer::open(&path, OpenCredential::PrivateKey(&alice)).is_ok());
    assert!(VnmContainer::open(&path, OpenCredential::PrivateKey(&bob)).is_ok());
    assert!(VnmContainer::open(&path, OpenCredential::Password(b"pw")).is_ok());
    // Unknown key fails
    let carol = hybrid_generate();
    assert!(VnmContainer::open(&path, OpenCredential::PrivateKey(&carol)).is_err());

    std::fs::remove_file(&path).ok();
}

// ── Key file passphrase protection ────────────────────────────────────────────

#[test]
fn key_file_passphrase_protect_roundtrip() {
    use vnmcore::crypto::key_file::{
        encode_key_file, encode_key_file_protected,
        decode_key_file, decode_key_file_with_passphrase,
        read_public_from_key_bytes,
    };

    let key = vnmcore::hybrid_generate();
    let label = "test-key";

    // Unprotected encode/decode
    let raw = encode_key_file(&key, label);
    let kf  = decode_key_file(&raw).unwrap();
    assert_eq!(kf.key.x25519_sk, key.x25519_sk);
    assert_eq!(kf.key.mlkem_seed, key.mlkem_seed);
    assert!(!kf.is_protected);

    // Public portions readable without passphrase from unprotected
    let pub_data = read_public_from_key_bytes(&raw).unwrap();
    assert_eq!(pub_data.public.x25519_pk, key.public.x25519_pk);
    assert!(!pub_data.is_protected);

    // Protected encode/decode
    let enc = encode_key_file_protected(&key, label, b"s3cret", 0).unwrap();
    // Public portions still readable without passphrase
    let pub_enc = read_public_from_key_bytes(&enc).unwrap();
    assert_eq!(pub_enc.public.x25519_pk, key.public.x25519_pk);
    assert!(pub_enc.is_protected);

    // Decoding without passphrase fails
    assert!(decode_key_file(&enc).is_err());

    // Wrong passphrase fails
    assert!(decode_key_file_with_passphrase(&enc, b"wrong").is_err());

    // Correct passphrase succeeds
    let kf2 = decode_key_file_with_passphrase(&enc, b"s3cret").unwrap();
    assert_eq!(kf2.key.x25519_sk,   key.x25519_sk);
    assert_eq!(kf2.key.mlkem_seed,  key.mlkem_seed);
    assert!(kf2.is_protected);
}
