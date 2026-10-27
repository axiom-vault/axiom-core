//! File I/O through a real FUSE mount of an in-memory vault.

#![cfg(feature = "fuse")]

use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;

use axiomvault_common::{VaultId, VaultPath};
use axiomvault_crypto::KdfParams;
use axiomvault_fuse::mount::{mount, MountOptions};
use axiomvault_storage::{MemoryProvider, StorageProvider};
use axiomvault_vault::{VaultConfig, VaultSession, VaultTree};

/// Spans several 64 KiB stream frames and ends mid-frame.
const FILE_SIZE: usize = 300_000;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Mount a fresh vault and run `test` against the mount point, or skip
/// when FUSE is not usable here.
fn with_mount(test: impl FnOnce(&Path)) {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping: /dev/fuse is not available");
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let session = runtime.block_on(async {
        let password = b"test-password";
        let creation = VaultConfig::new(
            VaultId::new("fuse-test").unwrap(),
            password,
            "memory",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap();
        let provider = Arc::new(MemoryProvider::new());
        for dir in ["/d", "/m"] {
            provider
                .create_dir(&VaultPath::parse(dir).unwrap())
                .await
                .unwrap();
        }
        VaultSession::unlock(creation.config, password, provider, VaultTree::new()).unwrap()
    });
    let mount_point = tempfile::tempdir().unwrap();
    let handle = mount(
        Arc::new(session),
        mount_point.path(),
        // `auto_unmount` needs an ACL other than owner-only in fuser 0.17.
        MountOptions {
            auto_unmount: false,
            ..MountOptions::default()
        },
        runtime.handle().clone(),
    )
    .unwrap();
    test(mount_point.path());
    handle.unmount();
}

fn read_at(file: &fs::File, offset: u64, len: usize) -> Vec<u8> {
    let mut buffer = vec![0; len];
    let mut filled = 0;
    while filled < len {
        let count = file
            .read_at(&mut buffer[filled..], offset + filled as u64)
            .unwrap();
        if count == 0 {
            break;
        }
        filled += count;
    }
    buffer.truncate(filled);
    buffer
}

#[test]
fn ranged_reads_cross_frame_boundaries_and_stop_at_eof() {
    with_mount(|root| {
        let path = root.join("data.bin");
        let content = pattern(FILE_SIZE);
        fs::write(&path, &content).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), FILE_SIZE as u64);

        let file = fs::File::open(&path).unwrap();
        let size = FILE_SIZE as u64;
        for (offset, len) in [
            (0, 4096),
            (65_530, 100),
            (131_062, 131_072),
            (1_000, 70_000),
            (size - 50, 100),
            (size, 10),
            (size + 4096, 10),
        ] {
            let start = (offset as usize).min(FILE_SIZE);
            let end = (start + len).min(FILE_SIZE);
            assert_eq!(
                read_at(&file, offset, len),
                &content[start..end],
                "offset {offset}"
            );
        }
        drop(file);
        assert_eq!(fs::read(&path).unwrap(), content);
    });
}

#[test]
fn read_after_write_within_one_handle() {
    with_mount(|root| {
        let path = root.join("data.bin");
        let mut content = pattern(FILE_SIZE);
        fs::write(&path, &content).unwrap();

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all_at(b"hello", 70_000).unwrap();
        file.write_all_at(b"tail", FILE_SIZE as u64).unwrap();
        content[70_000..70_005].copy_from_slice(b"hello");
        content.extend_from_slice(b"tail");

        assert_eq!(read_at(&file, 69_990, 20), &content[69_990..70_010]);
        assert_eq!(fs::metadata(&path).unwrap().len(), content.len() as u64);
        drop(file);

        assert_eq!(fs::read(&path).unwrap(), content);
    });
}

#[test]
fn truncating_rewrite_replaces_content() {
    with_mount(|root| {
        let path = root.join("data.bin");
        fs::write(&path, pattern(FILE_SIZE)).unwrap();
        fs::write(&path, b"short").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"short");

        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(2)
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"sh");
    });
}

#[test]
fn sequential_write_then_random_access_on_one_handle() {
    with_mount(|root| {
        let path = root.join("stream.bin");
        let mut content = pattern(FILE_SIZE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        for (index, piece) in content.chunks(50_000).enumerate() {
            file.write_all_at(piece, (index * 50_000) as u64).unwrap();
        }
        assert_eq!(fs::metadata(&path).unwrap().len(), FILE_SIZE as u64);

        assert_eq!(read_at(&file, 131_000, 1_000), &content[131_000..132_000]);
        file.write_all_at(b"head", 0).unwrap();
        content[..4].copy_from_slice(b"head");
        assert_eq!(read_at(&file, 0, 8), &content[..8]);
        drop(file);

        assert_eq!(fs::read(&path).unwrap(), content);
    });
}
