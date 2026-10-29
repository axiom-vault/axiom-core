//! Process hardening for the key-holding daemon.

/// Marks the process non-dumpable: no core dumps, and `/proc/<pid>/mem`,
/// `/proc/<pid>/environ` and ptrace become unavailable to other processes of
/// the same uid (only root, with `CAP_SYS_PTRACE`, can still attach).
#[cfg(target_os = "linux")]
pub fn disable_dumping() -> std::io::Result<()> {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes no pointers and only changes a
    // flag on the calling process.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn disable_dumping() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "PR_SET_DUMPABLE is Linux-only",
    ))
}

/// Locks all current and future pages in RAM so key material is never
/// swapped out.
///
/// With `MCL_FUTURE` every later mapping counts against `RLIMIT_MEMLOCK`, and
/// one that would exceed it fails, which aborts the process on allocation
/// (Argon2 alone allocates up to 256 MiB). So this refuses unless the limit
/// is unlimited, e.g. `LimitMEMLOCK=infinity` under systemd.
#[cfg(target_os = "linux")]
pub fn lock_memory() -> std::io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the rlimit struct we own.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if limit.rlim_cur != libc::RLIM_INFINITY {
        return Err(std::io::Error::other(format!(
            "RLIMIT_MEMLOCK is {} bytes, not unlimited; locking all future \
             allocations under it would abort the daemon",
            limit.rlim_cur
        )));
    }
    // SAFETY: mlockall takes only flags.
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn lock_memory() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "memory locking is only implemented on Linux",
    ))
}
