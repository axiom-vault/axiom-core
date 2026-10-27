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

/// The storage behind a mount, for tests that tamper with or break it.
struct Storage<'a> {
    provider: &'a MemoryProvider,
    runtime: &'a tokio::runtime::Runtime,
}

impl Storage<'_> {
    /// Paths of the stored content blobs.
    fn blobs(&self) -> Vec<VaultPath> {
        let dir = VaultPath::parse("/d").unwrap();
        let entries = self.runtime.block_on(self.provider.list(&dir)).unwrap();
        entries
            .iter()
            .map(|entry| dir.join(&entry.name).unwrap())
            .collect()
    }

    /// Flip the last byte of every content blob, which lies in the end
    /// frame, so that all data decrypts and only the end fails.
    fn tamper_end_frames(&self) {
        for blob in self.blobs() {
            self.runtime.block_on(async {
                let mut data = self.provider.download(&blob).await.unwrap();
                *data.last_mut().unwrap() ^= 1;
                self.provider.upload(&blob, data).await.unwrap();
            });
        }
    }

    /// Remove the metadata directory, so that saving the tree fails, or
    /// bring it back.
    fn set_metadata_dir(&self, present: bool) {
        let dir = VaultPath::parse("/m").unwrap();
        self.runtime.block_on(async {
            if present {
                self.provider.create_dir(&dir).await.unwrap();
                return;
            }
            for entry in self.provider.list(&dir).await.unwrap() {
                let path = dir.join(&entry.name).unwrap();
                self.provider.delete(&path).await.unwrap();
            }
            self.provider.delete_dir(&dir).await.unwrap();
        });
    }
}

/// Mount a fresh vault and run `test` against the mount point, or skip
/// when FUSE is not usable here.
fn with_mount(test: impl FnOnce(&Path)) {
    with_storage(|root, _| test(root));
}

/// Like [`with_mount`], also handing `test` the storage behind the mount.
fn with_storage(test: impl FnOnce(&Path, &Storage)) {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping: /dev/fuse is not available");
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let provider = Arc::new(MemoryProvider::new());
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
        for dir in ["/d", "/m"] {
            provider
                .create_dir(&VaultPath::parse(dir).unwrap())
                .await
                .unwrap();
        }
        VaultSession::unlock(
            creation.config,
            password,
            provider.clone(),
            VaultTree::new(),
        )
        .unwrap()
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
    test(
        mount_point.path(),
        &Storage {
            provider: &provider,
            runtime: &runtime,
        },
    );
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

#[test]
fn failed_streamed_write_poisons_the_handle() {
    with_storage(|root, storage| {
        let path = root.join("stream.bin");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all_at(&pattern(FILE_SIZE), 0).unwrap();

        // A write elsewhere saves the streamed content first, which fails
        // once the tree can't be saved.
        storage.set_metadata_dir(false);
        assert!(file.write_at(b"head", 0).is_err());
        storage.set_metadata_dir(true);

        // The stored file is still empty. Writing on must not save the
        // tail after a zero-filled gap where the streamed content was.
        assert!(file.write_at(b"tail", FILE_SIZE as u64).is_err());
        assert!(file.sync_all().is_err());
        drop(file);
        assert_eq!(fs::read(&path).unwrap(), b"");
    });
}

#[test]
fn truncating_overwrite_does_not_read_the_old_content() {
    with_storage(|root, storage| {
        let path = root.join("data.bin");
        fs::write(&path, pattern(FILE_SIZE)).unwrap();
        storage.tamper_end_frames();
        fs::write(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");

        fs::write(&path, pattern(FILE_SIZE)).unwrap();
        storage.tamper_end_frames();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(read_at(&file, 0, 10), &pattern(10)[..]);
        file.set_len(0).unwrap();
        file.write_all_at(b"new", 0).unwrap();
        drop(file);
        assert_eq!(fs::read(&path).unwrap(), b"new");
    });
}

#[test]
fn growing_past_the_buffer_limit_fails_with_efbig() {
    with_mount(|root| {
        let path = root.join("big.bin");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let efbig = Some(libc::EFBIG);
        assert_eq!(file.set_len(1 << 40).unwrap_err().raw_os_error(), efbig);
        assert_eq!(
            file.write_at(b"x", 1 << 40).unwrap_err().raw_os_error(),
            efbig
        );
        drop(file);
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    });
}
