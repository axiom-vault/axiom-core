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

    /// Whether a tree has been saved, which every vault mutation does.
    fn has_tree(&self) -> bool {
        let path = VaultPath::parse("/m/tree.json").unwrap();
        self.runtime.block_on(self.provider.exists(&path)).unwrap()
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

/// Sorted names in the directory at `path`.
fn names(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn unknown_provider_capacity_does_not_report_a_full_disk_or_prevent_copy() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    with_mount(|root| {
        let path = CString::new(root.as_os_str().as_bytes()).unwrap();
        let mut capacity = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: path is NUL-terminated and capacity points to writable space.
        let result = unsafe { libc::statvfs(path.as_ptr(), capacity.as_mut_ptr()) };
        assert_eq!(
            result, -1,
            "unknown provider quota must not look like zero free space"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );

        let content = pattern(FILE_SIZE);
        fs::write(root.join("original.bin"), &content).unwrap();
        assert_eq!(
            fs::copy(root.join("original.bin"), root.join("copied.bin")).unwrap(),
            content.len() as u64
        );
        assert_eq!(fs::read(root.join("copied.bin")).unwrap(), content);
    });
}

#[test]
fn rename_moves_directories_and_keeps_open_source_handles_usable() {
    with_mount(|root| {
        fs::create_dir(root.join("before")).unwrap();
        let path = root.join("before/file.txt");
        fs::write(&path, b"original").unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        fs::rename(root.join("before"), root.join("after")).unwrap();
        file.write_all_at(b"updated!", 0).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(!root.join("before").exists());
        assert_eq!(fs::read(root.join("after/file.txt")).unwrap(), b"updated!");
        fs::rename(root.join("after/file.txt"), root.join("moved.txt")).unwrap();
        assert_eq!(fs::read(root.join("moved.txt")).unwrap(), b"updated!");
    });
}

#[test]
fn rename_replaces_an_existing_file_for_atomic_editor_save() {
    with_mount(|root| {
        fs::write(root.join("document.txt"), b"old contents").unwrap();
        let temporary = root.join(".document.tmp");
        let mut file = fs::File::create(&temporary).unwrap();
        std::io::Write::write_all(&mut file, b"new contents").unwrap();
        file.sync_all().unwrap();
        // Editors may rename the source while its descriptor is still open.
        fs::rename(&temporary, root.join("document.txt")).unwrap();
        drop(file);
        assert!(!temporary.exists());
        assert_eq!(
            fs::read(root.join("document.txt")).unwrap(),
            b"new contents"
        );
    });
}

#[test]
fn failed_rename_keeps_both_files_and_recovers_after_storage_returns() {
    with_storage(|root, storage| {
        fs::write(root.join("source"), b"source contents").unwrap();
        fs::write(root.join("target"), b"target contents").unwrap();
        storage.set_metadata_dir(false);
        assert!(fs::rename(root.join("source"), root.join("target")).is_err());
        assert_eq!(fs::read(root.join("source")).unwrap(), b"source contents");
        assert_eq!(fs::read(root.join("target")).unwrap(), b"target contents");
        storage.set_metadata_dir(true);
        fs::rename(root.join("source"), root.join("target")).unwrap();
        assert_eq!(fs::read(root.join("target")).unwrap(), b"source contents");
    });
}

#[test]
fn rename_rejects_directory_cycles_and_nonempty_replacement() {
    with_mount(|root| {
        fs::create_dir(root.join("parent")).unwrap();
        fs::create_dir(root.join("parent/child")).unwrap();
        assert_eq!(
            fs::rename(root.join("parent"), root.join("parent/child/nested"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        fs::create_dir(root.join("other")).unwrap();
        assert_eq!(
            fs::rename(root.join("other"), root.join("parent"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTEMPTY)
        );
        assert!(root.join("other").is_dir());
        assert!(root.join("parent/child").is_dir());
    });
}

#[test]
fn rename_refuses_an_open_destination_without_losing_either_file() {
    with_mount(|root| {
        fs::write(root.join("source"), b"new").unwrap();
        fs::write(root.join("target"), b"old").unwrap();
        let target = fs::File::open(root.join("target")).unwrap();
        assert_eq!(
            fs::rename(root.join("source"), root.join("target"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBUSY)
        );
        assert_eq!(fs::read(root.join("source")).unwrap(), b"new");
        assert_eq!(fs::read(root.join("target")).unwrap(), b"old");
        drop(target);
        fs::rename(root.join("source"), root.join("target")).unwrap();
        assert_eq!(fs::read(root.join("target")).unwrap(), b"new");
    });
}

#[cfg(target_os = "linux")]
#[test]
fn rename_noreplace_preserves_an_existing_destination() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    with_mount(|root| {
        let source = root.join("source");
        let target = root.join("target");
        fs::write(&source, b"new").unwrap();
        fs::write(&target, b"old").unwrap();
        let from = CString::new(source.as_os_str().as_bytes()).unwrap();
        let to = CString::new(target.as_os_str().as_bytes()).unwrap();
        // SAFETY: Both NUL-terminated paths remain alive for the syscall.
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        assert_eq!(result, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EEXIST)
        );
        assert_eq!(fs::read(&source).unwrap(), b"new");
        assert_eq!(fs::read(&target).unwrap(), b"old");
    });
}

#[test]
fn renamed_content_survives_reopening_and_remounting_a_local_vault() {
    use axiomvault_storage::create_default_registry;
    use axiomvault_vault::{InMemoryFreshnessAnchor, VaultManager};
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping: /dev/fuse is not available");
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let mount_point = tempfile::tempdir().unwrap();
    let manager = VaultManager::with_registry_and_anchor(
        create_default_registry(),
        Arc::new(InMemoryFreshnessAnchor::new()),
    );
    let config = serde_json::json!({"root": storage.path()});
    let session = runtime
        .block_on(manager.create_vault(
            VaultId::new("synthetic-rename-remount").unwrap(),
            b"synthetic-only",
            "local",
            config.clone(),
            KdfParams::moderate(),
        ))
        .unwrap()
        .session;
    let handle = mount(
        Arc::new(session),
        mount_point.path(),
        MountOptions::default(),
        runtime.handle().clone(),
    )
    .unwrap();
    fs::write(mount_point.path().join("original"), b"old").unwrap();
    fs::write(mount_point.path().join("temporary"), b"durable replacement").unwrap();
    fs::rename(
        mount_point.path().join("temporary"),
        mount_point.path().join("original"),
    )
    .unwrap();
    handle.unmount();
    let reopened = runtime
        .block_on(manager.open_vault("local", config, b"synthetic-only"))
        .unwrap();
    let handle = mount(
        Arc::new(reopened),
        mount_point.path(),
        MountOptions::default(),
        runtime.handle().clone(),
    )
    .unwrap();
    assert_eq!(
        fs::read(mount_point.path().join("original")).unwrap(),
        b"durable replacement"
    );
    assert!(!mount_point.path().join("temporary").exists());
    handle.unmount();
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

        // The new file was never saved. Writing on must not save the tail
        // after a zero-filled gap where the streamed content was. Until the
        // kernel drops its cached entry the file may still read as empty.
        assert!(file.write_at(b"tail", FILE_SIZE as u64).is_err());
        assert!(file.sync_all().is_err());
        drop(file);
        assert!(fs::read(&path).map_or(true, |content| content.is_empty()));
    });
}

#[test]
fn created_file_is_saved_once_with_its_content() {
    with_storage(|root, storage| {
        let path = root.join("new.txt");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all_at(b"hello", 0).unwrap();

        // Visible through the mount before the vault changes.
        assert_eq!(fs::metadata(&path).unwrap().len(), 5);
        assert_eq!(names(root), ["new.txt"]);
        assert!(!storage.has_tree());

        drop(file);
        assert_eq!(storage.blobs().len(), 1);
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    });
}

#[test]
fn created_file_closed_without_writes_is_empty() {
    with_storage(|root, storage| {
        let path = root.join("empty");
        drop(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap(),
        );
        assert_eq!(storage.blobs().len(), 1);
        assert_eq!(fs::read(&path).unwrap(), b"");
    });
}

#[test]
fn opening_a_created_file_again_saves_it_first() {
    with_mount(|root| {
        let path = root.join("shared");
        let writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        writer.write_all_at(b"first", 0).unwrap();

        let reader = fs::File::open(&path).unwrap();
        assert_eq!(read_at(&reader, 0, 16), b"first");
        writer.write_all_at(b" second", 5).unwrap();
        drop(writer);
        drop(reader);
        assert_eq!(fs::read(&path).unwrap(), b"first second");
    });
}

#[test]
fn created_file_keeps_its_directory_and_can_be_removed() {
    with_mount(|root| {
        let dir = root.join("dir");
        fs::create_dir(&dir).unwrap();
        let path = dir.join("file");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        assert!(fs::remove_dir(&dir).is_err());
        fs::remove_file(&path).unwrap();
        drop(file);
        assert!(names(&dir).is_empty());
        fs::remove_dir(&dir).unwrap();
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

#[test]
fn reads_behind_the_stream_return_the_right_data() {
    with_mount(|root| {
        let path = root.join("data.bin");
        let content = pattern(FILE_SIZE);
        fs::write(&path, &content).unwrap();

        let file = fs::File::open(&path).unwrap();
        for offset in [200_000, 10, 250_000, 70_000, 0] {
            assert_eq!(
                read_at(&file, offset as u64, 1_000),
                &content[offset..offset + 1_000],
                "offset {offset}"
            );
        }
    });
}

#[test]
fn tampered_end_fails_a_read_that_ends_on_a_page() {
    with_storage(|root, storage| {
        let path = root.join("aligned.bin");
        let content = pattern(2 * 65_536);
        fs::write(&path, &content).unwrap();
        assert_eq!(fs::read(&path).unwrap(), content);

        storage.tamper_end_frames();
        let error = fs::read(&path).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    });
}

#[test]
fn small_files_read_whole_serve_every_offset() {
    with_storage(|root, storage| {
        let path = root.join("small.bin");
        let content = pattern(4096);
        fs::write(&path, &content).unwrap();

        let file = fs::File::open(&path).unwrap();
        for offset in [100, 0, 4000, 4096] {
            let end = (offset + 1_000).min(content.len());
            assert_eq!(
                read_at(&file, offset as u64, 1_000),
                &content[offset..end],
                "offset {offset}"
            );
        }

        storage.tamper_end_frames();
        let error = fs::read(&path).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    });
}
