//! FUSE filesystem implementation for AxiomVault.
//!
//! Implements the fuser::Filesystem trait to expose an encrypted vault
//! as a standard filesystem.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, WriteFlags,
};
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use zeroize::{Zeroize, Zeroizing};

use axiomvault_common::VaultPath;
use axiomvault_vault::{FileReader, FileWriter, VaultOperations, VaultSession};

/// Largest size a handle grows a file to outside a streamed write. Such
/// writes and truncates hold the whole plaintext in one buffer, so a larger
/// size could exhaust memory and abort the mount. Streamed writes are not
/// bounded by it.
const MAX_BUFFERED_SIZE: u64 = 1 << 30;

/// Helper function to create FileAttr with common defaults.
fn create_file_attr(ino: INodeNo, is_dir: bool, size: u64) -> FileAttr {
    let now = SystemTime::now();
    FileAttr {
        ino,
        size,
        blocks: size.div_ceil(512),
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: if is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        },
        perm: if is_dir { 0o700 } else { 0o600 },
        nlink: if is_dir { 2 } else { 1 },
        // SAFETY: `getuid`/`getgid` are async-signal-safe POSIX syscalls with no
        // preconditions and no side effects; they always return the current
        // process's UID/GID.
        uid: unsafe { libc::getuid() },
        // SAFETY: see `getuid` above.
        gid: unsafe { libc::getgid() },
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Inode number mapping to vault paths.
struct InodeMap {
    path_to_inode: HashMap<String, INodeNo>,
    inode_to_path: HashMap<INodeNo, String>,
    next_inode: u64,
}

impl InodeMap {
    /// Return the inode for a path, if it has been assigned.
    fn get_inode_for_path(&self, path: &str) -> Option<INodeNo> {
        self.path_to_inode.get(path).copied()
    }
}

impl InodeMap {
    fn new() -> Self {
        let mut map = Self {
            path_to_inode: HashMap::new(),
            inode_to_path: HashMap::new(),
            next_inode: 2, // 1 is reserved for root
        };
        // Root inode
        map.path_to_inode.insert("/".to_string(), INodeNo::ROOT);
        map.inode_to_path.insert(INodeNo::ROOT, "/".to_string());
        map
    }

    fn get_or_create_inode(&mut self, path: &str) -> INodeNo {
        if let Some(&ino) = self.path_to_inode.get(path) {
            ino
        } else {
            let ino = INodeNo(self.next_inode);
            self.next_inode += 1;
            self.path_to_inode.insert(path.to_string(), ino);
            self.inode_to_path.insert(ino, path.to_string());
            ino
        }
    }

    fn get_path(&self, inode: INodeNo) -> Option<&str> {
        self.inode_to_path.get(&inode).map(|s| s.as_str())
    }

    fn remove_inode(&mut self, path: &str) {
        if let Some(ino) = self.path_to_inode.remove(path) {
            self.inode_to_path.remove(&ino);
        }
    }
}

/// File handle tracking for open files.
struct OpenFile {
    path: String,
    /// Whole plaintext, loaded on the first write or truncate. Until then
    /// reads stream through `reader` and nothing else is held in memory.
    buffer: Option<Vec<u8>>,
    reader: Option<ReadCursor>,
    /// Sequential writes into an empty file, encrypted as they arrive.
    /// Any other access first saves what it has written.
    writer: Option<FileWriter>,
    dirty: bool,
    /// Set when streaming a write failed. What was streamed is lost, so
    /// every later operation fails instead of saving a partial file.
    failed: bool,
}

/// Sequential reader of an open file, with the chunk it returned last kept
/// so that small and overlapping reads don't decrypt a frame twice.
struct ReadCursor {
    reader: FileReader,
    /// File offset of `chunk[0]`.
    start: u64,
    chunk: Zeroizing<Vec<u8>>,
}

/// Read up to `size` bytes at `offset` through the handle's sequential
/// reader. Reads that continue or skip forward reuse it; a read before its
/// current chunk starts a new one.
async fn read_streamed(
    session: &VaultSession,
    file: &mut OpenFile,
    offset: u64,
    size: usize,
) -> std::result::Result<Zeroizing<Vec<u8>>, Errno> {
    if file
        .reader
        .as_ref()
        .is_none_or(|cursor| offset < cursor.start)
    {
        let ops = VaultOperations::new(session).map_err(|_| Errno::EIO)?;
        let path = VaultPath::parse(&file.path).map_err(|_| Errno::ENOENT)?;
        let reader = ops.open_file_reader(&path, offset).await.map_err(|e| {
            error!("Failed to open file for reading: {}", e);
            Errno::EIO
        })?;
        file.reader = Some(ReadCursor {
            reader,
            start: offset,
            chunk: Zeroizing::new(Vec::new()),
        });
    }
    let Some(cursor) = file.reader.as_mut() else {
        return Err(Errno::EIO);
    };

    let mut data = Zeroizing::new(Vec::with_capacity(size));
    let mut position = offset;
    while data.len() < size {
        let end = cursor.start + cursor.chunk.len() as u64;
        if position < end {
            let from = (position - cursor.start) as usize;
            let take = (size - data.len()).min(cursor.chunk.len() - from);
            data.extend_from_slice(&cursor.chunk[from..from + take]);
            position += take as u64;
            continue;
        }
        match cursor.reader.next_chunk().await {
            Some(Ok(chunk)) => {
                cursor.start = end;
                cursor.chunk = chunk;
            }
            Some(Err(e)) => {
                error!("Failed to read file: {}", e);
                file.reader = None;
                return Err(Errno::EIO);
            }
            None => break,
        }
    }
    Ok(data)
}

/// Load the whole plaintext of `file` into its buffer, unless it already is.
async fn load_buffer(
    session: &VaultSession,
    file: &mut OpenFile,
) -> std::result::Result<(), Errno> {
    if file.buffer.is_none() {
        let ops = VaultOperations::new(session).map_err(|_| Errno::EIO)?;
        let path = VaultPath::parse(&file.path).map_err(|_| Errno::ENOENT)?;
        let content = ops.read_file(&path).await.map_err(|e| {
            error!("Failed to read file: {}", e);
            Errno::EIO
        })?;
        file.reader = None;
        file.buffer = Some(content);
    }
    Ok(())
}

/// Save the content a handle has streamed so far, if it is streaming.
async fn finish_writer(
    session: &VaultSession,
    file: &mut OpenFile,
) -> std::result::Result<(), Errno> {
    if file.failed {
        return Err(Errno::EIO);
    }
    let Some(writer) = file.writer.take() else {
        return Ok(());
    };
    let result = async {
        let ops = VaultOperations::new(session).map_err(|_| Errno::EIO)?;
        let path = VaultPath::parse(&file.path).map_err(|_| Errno::EIO)?;
        ops.finish_file_writer(&path, writer).await.map_err(|e| {
            error!("Failed to write file: {}", e);
            Errno::EIO
        })
    }
    .await;
    file.failed = result.is_err();
    result?;
    file.reader = None;
    info!("File saved");
    Ok(())
}

/// Start streaming a write at offset 0 when the file is still empty, which
/// is how `cp`, `dd` and most writers produce a whole file.
async fn start_writer(
    session: &VaultSession,
    file: &mut OpenFile,
) -> std::result::Result<(), Errno> {
    let ops = VaultOperations::new(session).map_err(|_| Errno::EIO)?;
    let path = VaultPath::parse(&file.path).map_err(|_| Errno::ENOENT)?;
    let empty = match &file.buffer {
        Some(buffer) => buffer.is_empty(),
        None => matches!(ops.metadata(&path).await, Ok((_, false, Some(0)))),
    };
    if !empty {
        return Ok(());
    }
    let writer = ops.open_file_writer(&path).await.map_err(|e| {
        error!("Failed to open file for writing: {}", e);
        Errno::EIO
    })?;
    file.writer = Some(writer);
    file.buffer = None;
    file.reader = None;
    file.dirty = false;
    Ok(())
}

/// Write a dirty handle's buffer back to the vault.
async fn persist(session: &VaultSession, file: &mut OpenFile) -> std::result::Result<(), Errno> {
    finish_writer(session, file).await?;
    let Some(buffer) = file.buffer.as_ref().filter(|_| file.dirty) else {
        return Ok(());
    };

    let ops = VaultOperations::new(session).map_err(|e| {
        error!("Failed to get operations: {}", e);
        Errno::EIO
    })?;

    let path = VaultPath::parse(&file.path).map_err(|e| {
        error!("Invalid path: {}", e);
        Errno::EIO
    })?;

    ops.update_file(&path, buffer).await.map_err(|e| {
        error!("Failed to write file: {}", e);
        Errno::EIO
    })?;

    file.dirty = false;
    info!("File saved");
    Ok(())
}

/// FUSE filesystem implementation for an encrypted vault.
///
/// This translates FUSE operations into vault operations, handling
/// encryption and decryption transparently.
pub struct VaultFilesystem {
    session: Arc<VaultSession>,
    runtime: Handle,
    inodes: Arc<RwLock<InodeMap>>,
    open_files: Arc<RwLock<HashMap<FileHandle, OpenFile>>>,
    next_fh: Arc<RwLock<u64>>,
    ttl: Duration,
}

// SAFETY: All components are Arc/RwLock (thread-safe) or owned Tokio Handle.
// No raw pointers or thread-unsafe data structures are stored.
unsafe impl Send for VaultFilesystem {}

// SAFETY: All mutable state is protected by RwLock, ensuring safe concurrent access.
unsafe impl Sync for VaultFilesystem {}

impl VaultFilesystem {
    /// Create a new FUSE filesystem for a vault session.
    ///
    /// # Preconditions
    /// - Session must be active
    /// - Runtime handle must be valid
    ///
    /// # Arguments
    /// - `session`: Active vault session
    /// - `runtime`: Tokio runtime handle for async operations
    pub fn new(session: Arc<VaultSession>, runtime: Handle) -> Self {
        Self {
            session,
            runtime,
            inodes: Arc::new(RwLock::new(InodeMap::new())),
            open_files: Arc::new(RwLock::new(HashMap::new())),
            next_fh: Arc::new(RwLock::new(1)),
            ttl: Duration::from_secs(1),
        }
    }

    /// Save a handle's pending writes, keeping the handle open.
    fn sync_handle(&self, fh: FileHandle, reply: ReplyEmpty) {
        let session = self.session.clone();
        let open_files = self.open_files.clone();

        self.runtime.block_on(async move {
            let mut files = open_files.write().await;
            let result = match files.get_mut(&fh) {
                Some(file) => persist(&session, file).await,
                None => Err(Errno::EBADF),
            };
            match result {
                Ok(()) => reply.ok(),
                Err(errno) => reply.error(errno),
            }
        });
    }
}

impl Filesystem for VaultFilesystem {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        debug!("lookup: parent={}", parent);

        let session = self.session.clone();
        let inodes = self.inodes.clone();
        let ttl = self.ttl;

        self.runtime.block_on(async move {
            let parent_path = {
                let map = inodes.read().await;
                match map.get_path(parent) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
            };

            let child_path = if parent_path == "/" {
                format!("/{}", name_str)
            } else {
                format!("{}/{}", parent_path, name_str)
            };

            let ops = match VaultOperations::new(&session) {
                Ok(o) => o,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };

            let path = match VaultPath::parse(&child_path) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            };

            if !ops.exists(&path).await {
                reply.error(Errno::ENOENT);
                return;
            }

            match ops.metadata(&path).await {
                Ok((_, is_dir, size)) => {
                    let mut map = inodes.write().await;
                    let ino = map.get_or_create_inode(&child_path);
                    let attr = create_file_attr(ino, is_dir, size.unwrap_or(0));
                    reply.entry(&ttl, &attr, Generation(0));
                }
                Err(e) => {
                    error!("Failed to get metadata: {}", e);
                    reply.error(Errno::EIO);
                }
            }
        });
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        debug!("getattr: ino={}", ino);

        let session = self.session.clone();
        let inodes = self.inodes.clone();
        let open_files = self.open_files.clone();
        let ttl = self.ttl;

        self.runtime.block_on(async move {
            let path_str = {
                let map = inodes.read().await;
                match map.get_path(ino) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
            };

            if path_str == "/" {
                // Root directory
                let attr = create_file_attr(INodeNo::ROOT, true, 0);
                reply.attr(&ttl, &attr);
                return;
            }

            let ops = match VaultOperations::new(&session) {
                Ok(o) => o,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };

            let path = match VaultPath::parse(&path_str) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            };

            // A handle's buffer holds the size the file will have once saved.
            let open_size = open_files
                .read()
                .await
                .values()
                .filter(|file| file.path == path_str)
                .find_map(|file| match (&file.writer, &file.buffer) {
                    (Some(writer), _) => Some(writer.size()),
                    (None, buffer) => buffer.as_ref().map(|buffer| buffer.len() as u64),
                });

            match ops.metadata(&path).await {
                Ok((_, is_dir, size)) => {
                    let attr = create_file_attr(ino, is_dir, open_size.or(size).unwrap_or(0));
                    reply.attr(&ttl, &attr);
                }
                Err(e) => {
                    error!("Failed to get metadata: {}", e);
                    reply.error(Errno::EIO);
                }
            }
        });
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        debug!("readdir: ino={}, offset={}", u64::from(ino), offset);

        let session = self.session.clone();
        let inodes = self.inodes.clone();

        self.runtime.block_on(async move {
            let path_str = {
                let map = inodes.read().await;
                match map.get_path(ino) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
            };

            let ops = match VaultOperations::new(&session) {
                Ok(o) => o,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };

            let path = match VaultPath::parse(&path_str) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            };

            let entries = match ops.list_directory(&path).await {
                Ok(e) => e,
                Err(e) => {
                    error!("Failed to list directory: {}", e);
                    reply.error(Errno::EIO);
                    return;
                }
            };

            let mut i = offset as usize;

            // . and .. entries
            if i == 0 {
                if reply.add(ino, 1, FileType::Directory, ".") {
                    reply.ok();
                    return;
                }
                i += 1;
            }
            if i == 1 {
                // Look up the actual parent inode instead of always returning 1.
                let parent_ino = {
                    let map = inodes.read().await;
                    if path_str == "/" {
                        // Root's parent is itself (POSIX convention).
                        INodeNo::ROOT
                    } else {
                        // Walk up one component to find the parent path string.
                        let parent_path = path_str
                            .rfind('/')
                            .map(|idx| {
                                let p = &path_str[..idx];
                                if p.is_empty() {
                                    "/"
                                } else {
                                    p
                                }
                            })
                            .unwrap_or("/");
                        map.get_inode_for_path(parent_path).unwrap_or(INodeNo::ROOT)
                    }
                };
                if reply.add(parent_ino, 2, FileType::Directory, "..") {
                    reply.ok();
                    return;
                }
                i += 1;
            }

            // Add regular entries
            for (idx, (name, is_dir, _)) in entries.iter().enumerate().skip(i.saturating_sub(2)) {
                let child_path = if path_str == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", path_str, name)
                };

                let child_ino = {
                    let mut map = inodes.write().await;
                    map.get_or_create_inode(&child_path)
                };

                let file_type = if *is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };

                if reply.add(child_ino, (idx + 3) as u64, file_type, name) {
                    break;
                }
            }

            reply.ok();
        });
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        debug!("open: ino={}, flags={:?}", ino, flags);

        let inodes = self.inodes.clone();
        let open_files = self.open_files.clone();
        let next_fh = self.next_fh.clone();

        self.runtime.block_on(async move {
            let path_str = {
                let map = inodes.read().await;
                match map.get_path(ino) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
            };

            if VaultPath::parse(&path_str).is_err() {
                reply.error(Errno::ENOENT);
                return;
            }

            // Content is decrypted lazily: streamed by reads, or loaded by
            // the first write. A truncating open starts from an empty buffer.
            let truncate = flags.0 & libc::O_TRUNC != 0;

            let fh = {
                let mut fh_guard = next_fh.write().await;
                let handle = FileHandle(*fh_guard);
                *fh_guard += 1;
                handle
            };

            {
                let mut files = open_files.write().await;
                files.insert(
                    fh,
                    OpenFile {
                        path: path_str,
                        buffer: truncate.then(Vec::new),
                        reader: None,
                        writer: None,
                        dirty: truncate,
                        failed: false,
                    },
                );
            }

            reply.opened(fh, FopenFlags::empty());
        });
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        debug!(
            "read: fh={}, offset={}, size={}",
            u64::from(fh),
            offset,
            size
        );

        let session = self.session.clone();
        let open_files = self.open_files.clone();

        self.runtime.block_on(async move {
            let mut files = open_files.write().await;
            let Some(file) = files.get_mut(&fh) else {
                reply.error(Errno::EBADF);
                return;
            };
            if let Err(errno) = finish_writer(&session, file).await {
                reply.error(errno);
                return;
            }
            // Streaming can't seek back: a new reader downloads and decrypts
            // the file from its start. To bound that to once per handle, a
            // read behind the reader loads the whole file into the buffer,
            // as before reads were streamed, trading memory for random access.
            let behind = file
                .reader
                .as_ref()
                .is_some_and(|cursor| offset < cursor.start);
            if behind {
                if let Err(errno) = load_buffer(&session, file).await {
                    reply.error(errno);
                    return;
                }
            }
            match &file.buffer {
                Some(buffer) => {
                    let offset =
                        usize::try_from(offset).map_or(buffer.len(), |o| o.min(buffer.len()));
                    let end = offset.saturating_add(size as usize).min(buffer.len());
                    reply.data(&buffer[offset..end]);
                }
                None => match read_streamed(&session, file, offset, size as usize).await {
                    Ok(data) => reply.data(&data),
                    Err(errno) => reply.error(errno),
                },
            }
        });
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        debug!(
            "write: fh={}, offset={}, size={}",
            u64::from(fh),
            offset,
            data.len()
        );

        let session = self.session.clone();
        let open_files = self.open_files.clone();

        self.runtime.block_on(async move {
            let mut files = open_files.write().await;
            let Some(file) = files.get_mut(&fh) else {
                reply.error(Errno::EBADF);
                return;
            };
            if file.failed {
                reply.error(Errno::EIO);
                return;
            }
            if file.writer.is_none() && offset == 0 {
                if let Err(errno) = start_writer(&session, file).await {
                    reply.error(errno);
                    return;
                }
            }
            if let Some(writer) = file.writer.as_mut() {
                if offset == writer.size() {
                    match writer.write(data).await {
                        Ok(()) => reply.written(data.len() as u32),
                        Err(e) => {
                            error!("Failed to write file: {}", e);
                            file.failed = true;
                            reply.error(Errno::EIO);
                        }
                    }
                    return;
                }
            }
            let Some(end) = offset
                .checked_add(data.len() as u64)
                .filter(|&end| end <= MAX_BUFFERED_SIZE)
            else {
                reply.error(Errno::EFBIG);
                return;
            };
            let loaded = match finish_writer(&session, file).await {
                Ok(()) => load_buffer(&session, file).await,
                Err(errno) => Err(errno),
            };
            if let Err(errno) = loaded {
                reply.error(errno);
                return;
            }
            let Some(buffer) = file.buffer.as_mut() else {
                reply.error(Errno::EIO);
                return;
            };

            let offset = offset as usize;
            let end = end as usize;

            // Extend buffer if necessary
            if end > buffer.len() {
                buffer.resize(end, 0);
            }

            buffer[offset..end].copy_from_slice(data);
            file.dirty = true;

            reply.written(data.len() as u32);
        });
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        debug!("release: fh={}", u64::from(fh));

        let session = self.session.clone();
        let open_files = self.open_files.clone();

        self.runtime.block_on(async move {
            let file = {
                let mut files = open_files.write().await;
                files.remove(&fh)
            };

            if let Some(mut file) = file {
                let flush_result = persist(&session, &mut file).await;

                // Always zeroize decrypted file content, regardless of flush outcome.
                file.buffer.zeroize();
                file.path.zeroize();

                match flush_result {
                    Ok(()) => reply.ok(),
                    Err(errno) => reply.error(errno),
                }
                return;
            }

            reply.ok();
        });
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        debug!("create: parent={}", u64::from(parent));

        let session = self.session.clone();
        let inodes = self.inodes.clone();
        let open_files = self.open_files.clone();
        let next_fh = self.next_fh.clone();
        let ttl = self.ttl;

        self.runtime.block_on(async move {
            let parent_path = {
                let map = inodes.read().await;
                match map.get_path(parent) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
            };

            let child_path = if parent_path == "/" {
                format!("/{}", name_str)
            } else {
                format!("{}/{}", parent_path, name_str)
            };

            let ops = match VaultOperations::new(&session) {
                Ok(o) => o,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };

            let path = match VaultPath::parse(&child_path) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(Errno::EINVAL);
                    return;
                }
            };

            // Create empty file
            if let Err(e) = ops.create_file(&path, &[]).await {
                error!("Failed to create file: {}", e);
                reply.error(Errno::EIO);
                return;
            }

            let ino = {
                let mut map = inodes.write().await;
                map.get_or_create_inode(&child_path)
            };

            let fh = {
                let mut fh_guard = next_fh.write().await;
                let handle = FileHandle(*fh_guard);
                *fh_guard += 1;
                handle
            };

            {
                let mut files = open_files.write().await;
                files.insert(
                    fh,
                    OpenFile {
                        path: child_path,
                        buffer: Some(vec![]),
                        reader: None,
                        writer: None,
                        dirty: false,
                        failed: false,
                    },
                );
            }

            let attr = create_file_attr(ino, false, 0);

            reply.created(&ttl, &attr, Generation(0), fh, FopenFlags::empty());
        });
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        debug!("mkdir: parent={}", u64::from(parent));

        let session = self.session.clone();
        let inodes = self.inodes.clone();
        let ttl = self.ttl;

        self.runtime.block_on(async move {
            let parent_path = {
                let map = inodes.read().await;
                match map.get_path(parent) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
            };

            let child_path = if parent_path == "/" {
                format!("/{}", name_str)
            } else {
                format!("{}/{}", parent_path, name_str)
            };

            let ops = match VaultOperations::new(&session) {
                Ok(o) => o,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };

            let path = match VaultPath::parse(&child_path) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(Errno::EINVAL);
                    return;
                }
            };

            if let Err(e) = ops.create_directory(&path).await {
                error!("Failed to create directory: {}", e);
                reply.error(Errno::EIO);
                return;
            }

            let ino = {
                let mut map = inodes.write().await;
                map.get_or_create_inode(&child_path)
            };

            let attr = create_file_attr(ino, true, 0);

            reply.entry(&ttl, &attr, Generation(0));
        });
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        debug!("unlink: parent={}", parent);

        let session = self.session.clone();
        let inodes = self.inodes.clone();

        self.runtime.block_on(async move {
            let parent_path = {
                let map = inodes.read().await;
                match map.get_path(parent) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
            };

            let child_path = if parent_path == "/" {
                format!("/{}", name_str)
            } else {
                format!("{}/{}", parent_path, name_str)
            };

            let ops = match VaultOperations::new(&session) {
                Ok(o) => o,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };

            let path = match VaultPath::parse(&child_path) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(Errno::EINVAL);
                    return;
                }
            };

            if let Err(e) = ops.delete_file(&path).await {
                error!("Failed to delete file: {}", e);
                reply.error(Errno::EIO);
                return;
            }

            {
                let mut map = inodes.write().await;
                map.remove_inode(&child_path);
            }

            reply.ok();
        });
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        debug!("rmdir: parent={}", parent);

        let session = self.session.clone();
        let inodes = self.inodes.clone();

        self.runtime.block_on(async move {
            let parent_path = {
                let map = inodes.read().await;
                match map.get_path(parent) {
                    Some(p) => p.to_string(),
                    None => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
            };

            let child_path = if parent_path == "/" {
                format!("/{}", name_str)
            } else {
                format!("{}/{}", parent_path, name_str)
            };

            let ops = match VaultOperations::new(&session) {
                Ok(o) => o,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };

            let path = match VaultPath::parse(&child_path) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(Errno::EINVAL);
                    return;
                }
            };

            if let Err(e) = ops.delete_directory(&path).await {
                error!("Failed to delete directory: {}", e);
                reply.error(Errno::EIO);
                return;
            }

            {
                let mut map = inodes.write().await;
                map.remove_inode(&child_path);
            }

            reply.ok();
        });
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        debug!("setattr: ino={}, size={:?}", u64::from(ino), size);

        if let Some(size) = size {
            if size > MAX_BUFFERED_SIZE {
                reply.error(Errno::EFBIG);
                return;
            }
            let session = self.session.clone();
            let inodes = self.inodes.clone();
            let open_files = self.open_files.clone();

            // Truncate the buffer of an open handle, or rewrite the stored
            // file when none is open.
            let result: std::result::Result<(), Errno> = self.runtime.block_on(async move {
                let path_str = inodes
                    .read()
                    .await
                    .get_path(ino)
                    .ok_or(Errno::ENOENT)?
                    .to_string();
                let mut files = open_files.write().await;
                let handle = fh.filter(|fh| files.contains_key(fh)).or_else(|| {
                    files
                        .iter()
                        .find(|(_, f)| f.path == path_str)
                        .map(|(fh, _)| *fh)
                });
                let mut detached = OpenFile {
                    path: path_str,
                    buffer: (size == 0).then(Vec::new),
                    reader: None,
                    writer: None,
                    dirty: false,
                    failed: false,
                };
                let file = match handle.and_then(|fh| files.get_mut(&fh)) {
                    Some(file) => file,
                    None => &mut detached,
                };
                finish_writer(&session, file).await?;
                if size == 0 {
                    // Nothing of the old content survives, so don't decrypt it.
                    file.reader = None;
                    file.buffer.zeroize();
                    file.buffer = Some(Vec::new());
                } else {
                    load_buffer(&session, file).await?;
                }
                if let Some(buffer) = file.buffer.as_mut() {
                    buffer.resize(size as usize, 0);
                }
                file.dirty = true;
                let result = persist(&session, &mut detached).await;
                detached.buffer.zeroize();
                result
            });
            if let Err(errno) = result {
                reply.error(errno);
                return;
            }
        }

        self.getattr(_req, ino, fh, reply);
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        debug!("flush: fh={}", u64::from(fh));
        self.sync_handle(fh, reply);
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        debug!("fsync: fh={}", u64::from(fh));
        self.sync_handle(fh, reply);
    }
}
