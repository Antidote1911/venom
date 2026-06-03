use vnmcore::container::{CipherAlgorithm, KdfParams};
use vnmcore::crypto::{decrypt_block, derive_key, encrypt_block};

fn dummy_kdf() -> KdfParams {
    // Minimal params for fast tests — never use in production
    KdfParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
        salt: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".into(),
    }
}

fn derive_test_key(password: &[u8]) -> [u8; 32] {
    let dk = derive_key(password, &dummy_kdf()).unwrap();
    dk.as_array_32().unwrap()
}

#[test]
fn chacha20_round_trip() {
    let key = derive_test_key(b"hunter2");
    let plaintext = b"Hello, encrypted world!";
    let block_id = b"test-block-001";

    let ciphertext = encrypt_block(&key, CipherAlgorithm::XChaCha20Poly1305, block_id, plaintext).unwrap();
    let recovered = decrypt_block(&key, CipherAlgorithm::XChaCha20Poly1305, block_id, &ciphertext).unwrap();

    assert_eq!(recovered, plaintext);
}

#[test]
fn deoxys_ii_256_round_trip() {
    let key = derive_test_key(b"hunter2");
    let plaintext = b"Deoxys-II-256 standalone";
    let block_id = b"test-block-002";

    let ciphertext = encrypt_block(&key, CipherAlgorithm::DeoxysII256, block_id, plaintext).unwrap();
    let recovered = decrypt_block(&key, CipherAlgorithm::DeoxysII256, block_id, &ciphertext).unwrap();

    assert_eq!(recovered, plaintext);
}

#[test]
fn serpent256_round_trip() {
    let key = derive_test_key(b"hunter2");
    let plaintext = b"Serpent-256-EAX authenticated";
    let block_id = b"test-block-003";

    let ciphertext = encrypt_block(&key, CipherAlgorithm::Serpent256, block_id, plaintext).unwrap();
    let recovered = decrypt_block(&key, CipherAlgorithm::Serpent256, block_id, &ciphertext).unwrap();

    assert_eq!(recovered, plaintext);
}

#[test]
fn wrong_key_fails_authentication() {
    let key_a = derive_test_key(b"correct-password");
    let key_b = derive_test_key(b"wrong-password");
    let plaintext = b"secret data";
    let block_id = b"test-block-003";

    let ciphertext = encrypt_block(&key_a, CipherAlgorithm::XChaCha20Poly1305, block_id, plaintext).unwrap();
    let result = decrypt_block(&key_b, CipherAlgorithm::XChaCha20Poly1305, block_id, &ciphertext);

    assert!(result.is_err(), "decryption with wrong key must fail");
}

#[test]
fn wrong_block_id_fails_aad() {
    // AAD binding: decrypting a block with the wrong UUID must fail
    let key = derive_test_key(b"password");
    let plaintext = b"sensitive";

    let ciphertext = encrypt_block(&key, CipherAlgorithm::XChaCha20Poly1305, b"block-A", plaintext).unwrap();
    let result = decrypt_block(&key, CipherAlgorithm::XChaCha20Poly1305, b"block-B", &ciphertext);

    assert!(result.is_err(), "swapped block_id must be rejected by AAD check");
}

#[test]
fn flipped_bit_detected() {
    let key = derive_test_key(b"password");
    let plaintext = b"integrity check";
    let block_id = b"test-block-005";

    let mut ciphertext = encrypt_block(&key, CipherAlgorithm::DeoxysII256, block_id, plaintext).unwrap();
    let len = ciphertext.len();
    ciphertext[len - 17] ^= 0xFF;

    let result = decrypt_block(&key, CipherAlgorithm::DeoxysII256, block_id, &ciphertext);
    assert!(result.is_err(), "tampered ciphertext must be rejected");
}

#[test]
fn kdf_deterministic() {
    let kdf = dummy_kdf();
    let k1 = derive_key(b"same-password", &kdf).unwrap();
    let k2 = derive_key(b"same-password", &kdf).unwrap();
    assert_eq!(k1.as_bytes(), k2.as_bytes(), "KDF must be deterministic with same salt");
}

#[test]
fn kdf_different_passwords_differ() {
    let kdf = dummy_kdf();
    let k1 = derive_key(b"password-a", &kdf).unwrap();
    let k2 = derive_key(b"password-b", &kdf).unwrap();
    assert_ne!(k1.as_bytes(), k2.as_bytes());
}

#[test]
fn encrypt_produces_different_nonces() {
    // Each encryption call must produce a fresh nonce → different ciphertexts
    let key = derive_test_key(b"password");
    let plaintext = b"same plaintext";
    let block_id = b"nonce-test";

    let c1 = encrypt_block(&key, CipherAlgorithm::XChaCha20Poly1305, block_id, plaintext).unwrap();
    let c2 = encrypt_block(&key, CipherAlgorithm::XChaCha20Poly1305, block_id, plaintext).unwrap();

    assert_ne!(c1, c2, "successive encryptions must use different nonces");
}

#[test]
fn triple_cipher_round_trip() {
    let key = derive_test_key(b"triple-test");
    let plaintext = b"XChaCha20 + DeoxysII-256 + Serpent-256";
    let aad = b"triple-aad";

    let ct = encrypt_block(&key, CipherAlgorithm::Triple, aad, plaintext).unwrap();
    let pt = decrypt_block(&key, CipherAlgorithm::Triple, aad, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn triple_cipher_wrong_key_fails() {
    let key  = derive_test_key(b"key-a");
    let key2 = derive_test_key(b"key-b");
    let ct = encrypt_block(&key, CipherAlgorithm::Triple, b"aad", b"secret").unwrap();
    assert!(decrypt_block(&key2, CipherAlgorithm::Triple, b"aad", &ct).is_err());
}

#[test]
fn triple_cipher_tampered_tag_fails() {
    let key = derive_test_key(b"key");
    let mut ct = encrypt_block(&key, CipherAlgorithm::Triple, b"aad", b"data").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0xFF; // flip a bit in the outer HMAC tag
    assert!(decrypt_block(&key, CipherAlgorithm::Triple, b"aad", &ct).is_err());
}

#[test]
fn triple_cipher_wrong_aad_fails() {
    let key = derive_test_key(b"key");
    let ct = encrypt_block(&key, CipherAlgorithm::Triple, b"aad-correct", b"data").unwrap();
    assert!(decrypt_block(&key, CipherAlgorithm::Triple, b"aad-wrong", &ct).is_err());
}

#[test]
fn triple_container_create_open() {
    use vnmcore::fs::container::{VnmContainer, OpenCredential};
    use std::path::PathBuf;
    let path: PathBuf = std::env::temp_dir()
        .join(format!("vnm_triple_{}.vnm", std::process::id()));
    let _ = std::fs::remove_file(&path);

    VnmContainer::create(&path, b"pw", 4 * 1024 * 1024,
        CipherAlgorithm::Triple, "interactive", Some("triple test".into()), None).unwrap();

    let c = VnmContainer::open(&path, OpenCredential::Password(b"pw")).unwrap();
    assert_eq!(c.cipher, CipherAlgorithm::Triple);
    assert_eq!(c.label.as_deref(), Some("triple test"));
    std::fs::remove_file(&path).ok();
}
