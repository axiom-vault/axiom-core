//! FUSE mount management.
//!
//! Provides a high-level interface for mounting and unmounting vaults.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use fuser::{BackgroundSession, Config, MountOption, SessionACL};
use tokio::runtime::Handle;
use tracing::{error, info};

use crate::filesystem::VaultFilesystem;
use axiomvault_common::{Error, Result};
use axiomvault_vault::VaultSession;

/// Mount options for FUSE filesystem.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Allow other users to access the mount.
    pub allow_other: bool,
    /// Enable auto unmount when process exits.
    ///
    /// fuser rejects this with owner-only access, so it requires `allow_other`.
    pub auto_unmount: bool,
    /// Read-only mount.
    pub read_only: bool,
    /// Default permissions.
    pub default_permissions: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            allow_other: false,
            auto_unmount: false,
            read_only: false,
            default_permissions: true,
        }
    }
}

impl MountOptions {
    /// Refuse option combinations that expose decrypted data to other local users.
    ///
    /// `allow_other` without kernel `default_permissions` lets every local user read
    /// the plaintext, because the filesystem does not enforce mode bits itself.
    pub fn validate(&self) -> Result<()> {
        if self.allow_other && !self.default_permissions {
            return Err(Error::InvalidInput(
                "allow_other requires default_permissions: without it every local user \
                 could read the decrypted vault contents"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Handle to a mounted FUSE filesystem.
///
/// The mount is automatically unmounted when this handle is dropped.
/// Internally backed by a `fuser::BackgroundSession` which owns the OS mount
/// and the FUSE request-servicing thread.
pub struct MountHandle {
    mount_point: PathBuf,
    /// Keeps the background FUSE thread alive. Taken and joined on drop.
    session: Option<BackgroundSession>,
}

impl MountHandle {
    /// Get the mount point path.
    pub fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    /// Whether the FUSE session has ended, e.g. because the filesystem was
    /// unmounted externally (`fusermount3 -u`, `umount`).
    pub fn is_finished(&self) -> bool {
        self.session
            .as_ref()
            .is_none_or(|session| session.guard.is_finished())
    }

    /// Unmount the filesystem.
    ///
    /// This is automatically called when the handle is dropped.
    pub fn unmount(self) {
        // Drop will handle unmounting
        drop(self);
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        let Some(session) = self.session.take() else {
            return;
        };
        // Join the background thread so the filesystem, and with it the vault
        // session, is dropped (closing vault files and zeroizing keys) before
        // the process can exit. Dropping a BackgroundSession alone detaches it.
        let result = if session.guard.is_finished() {
            session.join()
        } else {
            info!("Unmounting vault");
            session.umount_and_join()
        };
        if let Err(e) = result {
            error!("Failed to unmount vault: {}", e);
        }
    }
}

/// Mount a vault session as a FUSE filesystem.
///
/// # Arguments
/// - `session`: Active vault session to mount
/// - `mount_point`: Directory where the vault will be mounted
/// - `options`: Mount configuration options
/// - `runtime`: Tokio runtime handle for async operations
///
/// # Preconditions
/// - Session must be active
/// - Mount point must exist and be an empty directory
/// - User must have FUSE permissions
///
/// # Postconditions
/// - Returns a handle that keeps the mount active
/// - Vault is accessible as a regular filesystem at mount_point
///
/// # Errors
/// - Mount point does not exist
/// - Mount point is not empty
/// - FUSE not available
/// - Permission denied
pub fn mount(
    session: Arc<VaultSession>,
    mount_point: impl AsRef<Path>,
    options: MountOptions,
    runtime: Handle,
) -> Result<MountHandle> {
    options.validate()?;
    let mount_point = mount_point.as_ref().to_path_buf();

    // Verify mount point exists
    if !mount_point.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Mount point does not exist: {:?}", mount_point),
        )));
    }

    if !mount_point.is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Mount point is not a directory: {:?}", mount_point),
        )));
    }

    info!("Mounting vault");

    // Create filesystem
    let fs = VaultFilesystem::new(session, runtime);

    // Configure mount options
    let mut config = Config::default();

    config.mount_options = vec![
        MountOption::FSName("axiomvault".to_string()),
        MountOption::Subtype("axiomvault".to_string()),
    ];

    config.acl = if options.allow_other {
        SessionACL::All
    } else {
        SessionACL::Owner
    };

    if options.auto_unmount {
        config.mount_options.push(MountOption::AutoUnmount);
    }

    if options.read_only {
        config.mount_options.push(MountOption::RO);
    }

    if options.default_permissions {
        config.mount_options.push(MountOption::DefaultPermissions);
    }

    // Spawn the FUSE request-servicing thread via fuser::spawn_mount.
    // The BackgroundSession returned here:
    //   1. performs the kernel mount syscall,
    //   2. starts a dedicated OS thread to service /dev/fuse read/write,
    //   3. unmounts and joins the thread on drop.
    let bg_session = fuser::spawn_mount(fs, &mount_point, &config).map_err(|e| {
        error!("Failed to mount vault");
        Error::Io(e)
    })?;

    info!("Vault mounted successfully");

    Ok(MountHandle {
        mount_point,
        session: Some(bg_session),
    })
}

/// Check if FUSE is available on the system.
///
/// # Returns
/// - `true` if FUSE is available
/// - `false` otherwise
pub fn is_fuse_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/dev/fuse").exists()
    }

    #[cfg(target_os = "macos")]
    {
        // Check for macFUSE
        Path::new("/Library/Filesystems/macfuse.fs").exists()
            || Path::new("/Library/Filesystems/osxfuse.fs").exists()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Get platform-specific FUSE information.
pub fn fuse_info() -> String {
    #[cfg(target_os = "linux")]
    {
        if is_fuse_available() {
            "FUSE available via /dev/fuse".to_string()
        } else {
            "FUSE not available. Install fuse3 package.".to_string()
        }
    }

    #[cfg(target_os = "macos")]
    {
        if is_fuse_available() {
            "macFUSE available".to_string()
        } else {
            "macFUSE not installed. Visit https://osxfuse.github.io/".to_string()
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "FUSE not supported on this platform".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_mount_options() {
        let opts = MountOptions::default();
        assert!(!opts.allow_other);
        assert!(!opts.auto_unmount);
        assert!(!opts.read_only);
        assert!(opts.default_permissions);
    }

    #[test]
    fn test_validate_refuses_allow_other_without_default_permissions() {
        let opts = MountOptions {
            allow_other: true,
            default_permissions: false,
            ..Default::default()
        };
        let err = opts.validate().unwrap_err().to_string();
        assert!(err.contains("allow_other requires default_permissions"));
    }

    #[test]
    fn test_validate_accepts_safe_combinations() {
        assert!(MountOptions::default().validate().is_ok());
        let allow_other = MountOptions {
            allow_other: true,
            ..Default::default()
        };
        assert!(allow_other.validate().is_ok());
        let no_perms = MountOptions {
            default_permissions: false,
            ..Default::default()
        };
        assert!(no_perms.validate().is_ok());
    }

    #[test]
    fn test_fuse_info() {
        let info = fuse_info();
        assert!(!info.is_empty());
    }

    /// An external `fusermount3 -u` must end the session, and dropping the
    /// handle must then release the vault session. Skipped where FUSE is unusable.
    #[test]
    fn test_external_unmount_ends_session() {
        use axiomvault_common::VaultId;
        use axiomvault_crypto::KdfParams;
        use axiomvault_storage::MemoryProvider;
        use axiomvault_vault::{VaultConfig, VaultTree};
        use std::process::Command;
        use std::time::{Duration, Instant};

        if !is_fuse_available() {
            return;
        }
        let creation = VaultConfig::new(
            VaultId::new("test").unwrap(),
            b"test-password",
            "memory",
            serde_json::Value::Null,
            KdfParams::interactive(),
        )
        .unwrap();
        let session = Arc::new(
            VaultSession::unlock(
                creation.config,
                b"test-password",
                Arc::new(MemoryProvider::new()),
                VaultTree::new(),
            )
            .unwrap(),
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let Ok(handle) = mount(
            session.clone(),
            dir.path(),
            MountOptions::default(),
            runtime.handle().clone(),
        ) else {
            return;
        };
        assert!(!handle.is_finished());

        let unmounted = Command::new("fusermount3")
            .arg("-u")
            .arg(dir.path())
            .status()
            .is_ok_and(|status| status.success());
        if !unmounted {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(handle.is_finished());

        handle.unmount();
        assert_eq!(Arc::strong_count(&session), 1);
    }
}
