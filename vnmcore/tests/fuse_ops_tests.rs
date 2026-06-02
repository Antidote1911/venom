//! Integration tests for FUSE write operations.
//!
//! These tests call the op_*() methods on VenomFuse directly — no FUSE
//! mount required — and verify state via both the cache and the on-disk
//! vault. Each test covers a complete scenario end-to-end.

#[cfg(feature = "fuse")]
mod fuse_ops {
    use std::sync::Arc;
    use vnmcore::container::CipherAlgorithm;
    use vnmcore::fs::fuse::driver::{VenomFuse, ROOT_INO};
    use vnmcore::fs::Vault;
    use vnmcore::storage::VaultNode;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn tmp(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vnm_ops_{label}_{}", std::process::id()))
    }

    fn setup(label: &str) -> (Arc<Vault>, VenomFuse, std::path::PathBuf) {
        let path = tmp(label);
        let _ = std::fs::remove_dir_all(&path);
        let vault = Arc::new(
            Vault::create(&path, b"pass", CipherAlgorithm::ChaCha20Poly1305, "interactive", None).unwrap(),
        );
        let fuse = VenomFuse::new(vault.clone());
        (vault, fuse, path)
    }

    /// Assert that `name` exists under `parent_ino` and return its inode.
    fn assert_exists(fuse: &mut VenomFuse, parent: u64, name: &str) -> u64 {
        let (ino, _) = fuse.op_lookup(parent, name)
            .unwrap_or_else(|e| panic!("lookup '{name}' failed with errno {e}"));
        ino
    }

    /// Assert that `name` does NOT exist under `parent_ino`.
    fn assert_missing(fuse: &mut VenomFuse, parent: u64, name: &str) {
        let err = fuse.op_lookup(parent, name)
            .err()
            .unwrap_or_else(|| panic!("lookup '{name}' should have failed but succeeded"));
        assert_eq!(err, libc::ENOENT, "expected ENOENT for missing entry '{name}'");
    }

    /// Read all data for a file identified by `ino` / `fh` from cache.
    fn read_all(fuse: &mut VenomFuse, ino: u64, fh: u64) -> Vec<u8> {
        fuse.op_read(ino, fh, 0, u32::MAX).unwrap()
    }

    // ── mkdir ─────────────────────────────────────────────────────────────────

    #[test]
    fn mkdir_creates_directory_in_parent() {
        let (_v, mut fuse, path) = setup("mkdir_basic");

        let (ino, node) = fuse.op_mkdir(ROOT_INO, "docs").unwrap();
        assert!(matches!(node, VaultNode::Directory(_)));
        assert_ne!(ino, ROOT_INO);

        // Lookup confirms it's there
        assert_exists(&mut fuse, ROOT_INO, "docs");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn mkdir_duplicate_name_fails_eexist() {
        let (_v, mut fuse, path) = setup("mkdir_dup");

        fuse.op_mkdir(ROOT_INO, "dir").unwrap();
        let err = fuse.op_mkdir(ROOT_INO, "dir").unwrap_err();
        assert_eq!(err, libc::EEXIST);

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn mkdir_nested_directories() {
        let (_v, mut fuse, path) = setup("mkdir_nested");

        let (parent_ino, _) = fuse.op_mkdir(ROOT_INO, "a").unwrap();
        fuse.op_mkdir(parent_ino, "b").unwrap();
        let (b_ino, _) = fuse.op_lookup(parent_ino, "b").unwrap();
        fuse.op_mkdir(b_ino, "c").unwrap();

        // Deep lookup
        let (a_ino, _) = fuse.op_lookup(ROOT_INO, "a").unwrap();
        let (b_ino2, _) = fuse.op_lookup(a_ino, "b").unwrap();
        assert_exists(&mut fuse, b_ino2, "c");

        std::fs::remove_dir_all(&path).ok();
    }

    // ── rmdir ─────────────────────────────────────────────────────────────────

    #[test]
    fn rmdir_removes_empty_directory() {
        let (_v, mut fuse, path) = setup("rmdir_empty");

        fuse.op_mkdir(ROOT_INO, "tmp").unwrap();
        fuse.op_rmdir(ROOT_INO, "tmp").unwrap();
        assert_missing(&mut fuse, ROOT_INO, "tmp");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn rmdir_non_empty_fails_enotempty() {
        let (_v, mut fuse, path) = setup("rmdir_nonempty");

        let (dir_ino, _) = fuse.op_mkdir(ROOT_INO, "dir").unwrap();
        fuse.op_create(dir_ino, "file.txt").unwrap();

        let err = fuse.op_rmdir(ROOT_INO, "dir").unwrap_err();
        assert_eq!(err, libc::ENOTEMPTY);

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn rmdir_nonexistent_fails_enoent() {
        let (_v, mut fuse, path) = setup("rmdir_missing");

        let err = fuse.op_rmdir(ROOT_INO, "ghost").unwrap_err();
        assert_eq!(err, libc::ENOENT);

        std::fs::remove_dir_all(&path).ok();
    }

    // ── create ────────────────────────────────────────────────────────────────

    #[test]
    fn create_adds_file_to_parent() {
        let (_v, mut fuse, path) = setup("create_basic");

        let (ino, fh) = fuse.op_create(ROOT_INO, "hello.txt").unwrap();
        assert_ne!(ino, ROOT_INO);
        assert_ne!(fh, 0);
        assert_exists(&mut fuse, ROOT_INO, "hello.txt");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn create_duplicate_name_fails_eexist() {
        let (_v, mut fuse, path) = setup("create_dup");

        fuse.op_create(ROOT_INO, "file.txt").unwrap();
        let err = fuse.op_create(ROOT_INO, "file.txt").unwrap_err();
        assert_eq!(err, libc::EEXIST);

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn create_returns_usable_file_handle() {
        let (_v, mut fuse, path) = setup("create_fh");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        assert_ne!(fh, 0);

        // The returned fh must be immediately usable for read/write.
        fuse.op_write(ino, fh, 0, b"immediate").unwrap();
        let data = read_all(&mut fuse, ino, fh);
        assert_eq!(data, b"immediate");

        std::fs::remove_dir_all(&path).ok();
    }

    // ── write + read ──────────────────────────────────────────────────────────

    #[test]
    fn write_read_roundtrip_via_cache() {
        let (_v, mut fuse, path) = setup("write_read");

        let (ino, fh) = fuse.op_create(ROOT_INO, "note.txt").unwrap();
        let written = fuse.op_write(ino, fh, 0, b"hello, cache!").unwrap();
        assert_eq!(written, 13);

        let data = read_all(&mut fuse, ino, fh);
        assert_eq!(data, b"hello, cache!");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn write_at_offset_fills_gap_with_zeros() {
        let (_v, mut fuse, path) = setup("write_offset");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        fuse.op_write(ino, fh, 5, b"hi").unwrap();

        let data = read_all(&mut fuse, ino, fh);
        assert_eq!(&data[..5], &[0u8; 5]);
        assert_eq!(&data[5..7], b"hi");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn write_flush_persists_to_disk() {
        let (vault, mut fuse, path) = setup("write_flush");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"persisted").unwrap();
        fuse.op_flush(fh).unwrap();

        // Verify on disk via a fresh vault handle
        let v2 = Vault::open(&path, b"pass").unwrap();
        let (file_ino, _) = fuse.op_lookup(ROOT_INO, "f.txt").unwrap();
        let file_id = fuse.block_id_of(file_ino).unwrap();
        match v2.read_node(&file_id).unwrap() {
            VaultNode::File(f) => assert_eq!(f.data, b"persisted"),
            _ => panic!("expected file"),
        }

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn write_release_reopen_read_survives_close() {
        let (_v, mut fuse, path) = setup("write_reopen");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"survive close").unwrap();
        fuse.op_release(fh).unwrap();

        // After release: re-opening with a different fh proves eviction happened
        // (the old fh is now invalid; op_read on it would return empty data)
        let fh2 = fuse.op_open(ino).unwrap();
        let data = read_all(&mut fuse, ino, fh2);
        assert_eq!(data, b"survive close");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn multiple_sequential_writes_accumulate() {
        let (_v, mut fuse, path) = setup("seq_writes");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"foo").unwrap();
        fuse.op_write(ino, fh, 3, b"bar").unwrap();
        fuse.op_write(ino, fh, 6, b"baz").unwrap();

        let data = read_all(&mut fuse, ino, fh);
        assert_eq!(data, b"foobarbaz");

        std::fs::remove_dir_all(&path).ok();
    }

    // ── large file (multi-block) ──────────────────────────────────────────────

    #[test]
    fn large_file_multiblock_write_read() {
        let (_v, mut fuse, path) = setup("multiblock");

        // 75 KB of pseudo-random-ish data (spans 3 blocks of 30 KB each)
        let payload: Vec<u8> = (0u32..75_000).map(|i| (i * 7 + 13) as u8).collect();

        let (ino, fh) = fuse.op_create(ROOT_INO, "big.bin").unwrap();
        fuse.op_write(ino, fh, 0, &payload).unwrap();
        fuse.op_release(fh).unwrap();

        // Re-open and verify full content
        let fh2 = fuse.op_open(ino).unwrap();
        let data = read_all(&mut fuse, ino, fh2);
        assert_eq!(data.len(), 75_000);
        assert_eq!(data, payload);

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn large_file_continuation_blocks_on_disk() {
        let (vault, mut fuse, path) = setup("multiblock_disk");

        let payload = vec![0xABu8; 35_000]; // just over one block
        let (ino, fh) = fuse.op_create(ROOT_INO, "big.bin").unwrap();
        fuse.op_write(ino, fh, 0, &payload).unwrap();
        fuse.op_flush(fh).unwrap();

        let file_id = fuse.block_id_of(ino).unwrap();
        let fb = match vault.read_node(&file_id).unwrap() {
            VaultNode::File(f) => f,
            _ => panic!(),
        };
        assert_eq!(fb.total_size, 35_000);
        assert_eq!(fb.continuation_ids.len(), 1, "one continuation block expected");

        // Continuation block must also exist on disk
        assert!(vault.store.exists(&fb.continuation_ids[0]));

        std::fs::remove_dir_all(&path).ok();
    }

    // ── unlink ────────────────────────────────────────────────────────────────

    #[test]
    fn unlink_removes_file_from_directory() {
        let (_v, mut fuse, path) = setup("unlink_basic");

        fuse.op_create(ROOT_INO, "bye.txt").unwrap();
        assert_exists(&mut fuse, ROOT_INO, "bye.txt");

        fuse.op_unlink(ROOT_INO, "bye.txt").unwrap();
        assert_missing(&mut fuse, ROOT_INO, "bye.txt");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn unlink_deletes_block_files_from_disk() {
        let (vault, mut fuse, path) = setup("unlink_disk");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        fuse.op_write(ino, fh, 0, &vec![1u8; 35_000]).unwrap(); // triggers continuation
        fuse.op_flush(fh).unwrap();

        let file_id = fuse.block_id_of(ino).unwrap();
        let cont_id = match vault.read_node(&file_id).unwrap() {
            VaultNode::File(f) => f.continuation_ids.first().cloned().unwrap(),
            _ => panic!(),
        };

        fuse.op_unlink(ROOT_INO, "f.txt").unwrap();

        assert!(!vault.store.exists(&file_id), "main block must be deleted");
        assert!(!vault.store.exists(&cont_id), "continuation block must be deleted");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn unlink_nonexistent_fails_enoent() {
        let (_v, mut fuse, path) = setup("unlink_missing");

        let err = fuse.op_unlink(ROOT_INO, "ghost.txt").unwrap_err();
        assert_eq!(err, libc::ENOENT);

        std::fs::remove_dir_all(&path).ok();
    }

    // ── rename ────────────────────────────────────────────────────────────────

    #[test]
    fn rename_within_same_directory() {
        let (_v, mut fuse, path) = setup("rename_same_dir");

        let (ino, fh) = fuse.op_create(ROOT_INO, "old.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"content").unwrap();
        fuse.op_release(fh).unwrap();

        fuse.op_rename(ROOT_INO, "old.txt", ROOT_INO, "new.txt").unwrap();

        assert_missing(&mut fuse, ROOT_INO, "old.txt");
        let new_ino = assert_exists(&mut fuse, ROOT_INO, "new.txt");

        // Data is preserved
        let fh2 = fuse.op_open(new_ino).unwrap();
        assert_eq!(read_all(&mut fuse, new_ino, fh2), b"content");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn rename_to_different_directory() {
        let (_v, mut fuse, path) = setup("rename_cross_dir");

        let (dir_ino, _) = fuse.op_mkdir(ROOT_INO, "subdir").unwrap();
        let (ino, fh) = fuse.op_create(ROOT_INO, "file.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"moved").unwrap();
        fuse.op_release(fh).unwrap();

        fuse.op_rename(ROOT_INO, "file.txt", dir_ino, "file.txt").unwrap();

        assert_missing(&mut fuse, ROOT_INO, "file.txt");
        let new_ino = assert_exists(&mut fuse, dir_ino, "file.txt");

        let fh2 = fuse.op_open(new_ino).unwrap();
        assert_eq!(read_all(&mut fuse, new_ino, fh2), b"moved");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn rename_overwrites_existing_destination() {
        let (_v, mut fuse, path) = setup("rename_overwrite");

        let (ino_a, fh_a) = fuse.op_create(ROOT_INO, "a.txt").unwrap();
        fuse.op_write(ino_a, fh_a, 0, b"from-a").unwrap();
        fuse.op_release(fh_a).unwrap();

        let (ino_b, fh_b) = fuse.op_create(ROOT_INO, "b.txt").unwrap();
        fuse.op_write(ino_b, fh_b, 0, b"from-b").unwrap();
        fuse.op_release(fh_b).unwrap();

        // Rename a → b: b is overwritten
        fuse.op_rename(ROOT_INO, "a.txt", ROOT_INO, "b.txt").unwrap();

        assert_missing(&mut fuse, ROOT_INO, "a.txt");
        let b_ino = assert_exists(&mut fuse, ROOT_INO, "b.txt");
        let fh = fuse.op_open(b_ino).unwrap();
        assert_eq!(read_all(&mut fuse, b_ino, fh), b"from-a");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn rename_nonexistent_fails_enoent() {
        let (_v, mut fuse, path) = setup("rename_missing");

        let err = fuse.op_rename(ROOT_INO, "ghost.txt", ROOT_INO, "new.txt").unwrap_err();
        assert_eq!(err, libc::ENOENT);

        std::fs::remove_dir_all(&path).ok();
    }

    // ── setattr (truncate) ────────────────────────────────────────────────────

    #[test]
    fn setattr_truncate_shortens_file() {
        let (_v, mut fuse, path) = setup("trunc_short");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"hello world").unwrap();

        fuse.op_setattr_size(ino, Some(fh), 5).unwrap();
        let data = read_all(&mut fuse, ino, fh);
        assert_eq!(data, b"hello");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn setattr_extend_pads_with_zeros() {
        let (_v, mut fuse, path) = setup("trunc_extend");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"hi").unwrap();

        fuse.op_setattr_size(ino, Some(fh), 6).unwrap();
        let data = read_all(&mut fuse, ino, fh);
        assert_eq!(data, b"hi\0\0\0\0");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn setattr_truncate_without_open_fh_goes_to_disk() {
        let (vault, mut fuse, path) = setup("trunc_disk");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"abcdefgh").unwrap();
        fuse.op_release(fh).unwrap(); // close: flushes and evicts

        // Truncate while the file is closed (no open_files entry)
        fuse.op_setattr_size(ino, None, 4).unwrap();

        let file_id = fuse.block_id_of(ino).unwrap();
        match vault.read_node(&file_id).unwrap() {
            VaultNode::File(f) => {
                assert_eq!(f.total_size, 4);
                assert_eq!(f.data, b"abcd");
            }
            _ => panic!(),
        }

        std::fs::remove_dir_all(&path).ok();
    }

    // ── Complex scenarios ─────────────────────────────────────────────────────

    #[test]
    fn overwrite_existing_file_content() {
        let (_v, mut fuse, path) = setup("overwrite");

        let (ino, fh) = fuse.op_create(ROOT_INO, "f.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"original content").unwrap();
        fuse.op_release(fh).unwrap();

        let fh2 = fuse.op_open(ino).unwrap();
        // Overwrite first 8 bytes, keep the rest
        fuse.op_write(ino, fh2, 0, b"modified").unwrap();
        fuse.op_release(fh2).unwrap();

        let fh3 = fuse.op_open(ino).unwrap();
        let data = read_all(&mut fuse, ino, fh3);
        assert_eq!(data, b"modified content");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn directory_tree_create_and_verify() {
        // Build:  root/
        //           docs/
        //             readme.txt  ("docs readme")
        //           src/
        //             main.rs     ("fn main() {}")
        //             lib.rs      ("pub mod lib;")
        let (_v, mut fuse, path) = setup("tree");

        let (docs, _) = fuse.op_mkdir(ROOT_INO, "docs").unwrap();
        let (src, _) = fuse.op_mkdir(ROOT_INO, "src").unwrap();

        let (_, fh) = fuse.op_create(docs, "readme.txt").unwrap();
        let (readme_ino, _) = fuse.op_lookup(docs, "readme.txt").unwrap();
        fuse.op_write(readme_ino, fh, 0, b"docs readme").unwrap();
        fuse.op_release(fh).unwrap();

        let (_, fh) = fuse.op_create(src, "main.rs").unwrap();
        let (main_ino, _) = fuse.op_lookup(src, "main.rs").unwrap();
        fuse.op_write(main_ino, fh, 0, b"fn main() {}").unwrap();
        fuse.op_release(fh).unwrap();

        let (_, fh) = fuse.op_create(src, "lib.rs").unwrap();
        let (lib_ino, _) = fuse.op_lookup(src, "lib.rs").unwrap();
        fuse.op_write(lib_ino, fh, 0, b"pub mod lib;").unwrap();
        fuse.op_release(fh).unwrap();

        // Verify entire tree by re-reading every file
        let r_ino = assert_exists(&mut fuse, docs, "readme.txt");
        let fh = fuse.op_open(r_ino).unwrap();
        assert_eq!(read_all(&mut fuse, r_ino, fh), b"docs readme");

        let m_ino = assert_exists(&mut fuse, src, "main.rs");
        let fh = fuse.op_open(m_ino).unwrap();
        assert_eq!(read_all(&mut fuse, m_ino, fh), b"fn main() {}");

        let l_ino = assert_exists(&mut fuse, src, "lib.rs");
        let fh = fuse.op_open(l_ino).unwrap();
        assert_eq!(read_all(&mut fuse, l_ino, fh), b"pub mod lib;");

        std::fs::remove_dir_all(&path).ok();
    }

    #[test]
    fn vault_reopened_preserves_full_tree() {
        // Same tree as above, but we close and reopen the vault to verify
        // everything was actually persisted to disk.
        let (vault, mut fuse, path) = setup("tree_reopen");

        let (docs, _) = fuse.op_mkdir(ROOT_INO, "docs").unwrap();
        let (ino, fh) = fuse.op_create(docs, "readme.txt").unwrap();
        fuse.op_write(ino, fh, 0, b"persistent readme").unwrap();
        fuse.op_release(fh).unwrap();
        drop(fuse); // flush_all() via Drop

        // Reopen the vault as a fresh VenomFuse
        let vault2 = Arc::new(Vault::open(&path, b"pass").unwrap());
        let mut fuse2 = VenomFuse::new(vault2);

        let (docs2, _) = fuse2.op_lookup(ROOT_INO, "docs").unwrap();
        let (readme_ino, _) = fuse2.op_lookup(docs2, "readme.txt").unwrap();
        let fh2 = fuse2.op_open(readme_ino).unwrap();
        assert_eq!(read_all(&mut fuse2, readme_ino, fh2), b"persistent readme");

        std::fs::remove_dir_all(&path).ok();
    }
}
