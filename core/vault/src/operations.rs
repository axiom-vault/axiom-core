//! Vault file operations with encryption/decryption.

use std::collections::HashSet;
use std::future::Future;
use std::io::{Read, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use blake2::Digest;
use futures::{Stream, StreamExt};
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::config::DATA_DIRNAME;
use crate::manifest::{digest, finish_digest, DigestHasher};
use crate::session::VaultSession;
use crate::tree::{TreeNode, VaultTree};
use axiomvault_common::{Error, Result, VaultPath};
use axiomvault_crypto::aead::{NONCE_SIZE, TAG_SIZE};
use axiomvault_crypto::{decrypt, encrypt, DecryptingStream, EncryptingStream, MasterKey};
use axiomvault_storage::{ByteStream, StorageProvider};

const STREAM_CONTENT_VERSION: u8 = 2;
/// Ciphertext is handed to the provider in chunks of about this size.
const UPLOAD_CHUNK_SIZE: usize = 1024 * 1024;
/// Chunks in flight between the blocking crypto task and the async provider.
const UPLOAD_CHANNEL_CAPACITY: usize = 4;
/// Plaintext written to a [`FileWriter`] is handed to the encryptor in
/// batches of this size, so small writes don't each wake another thread.
const WRITE_BATCH_SIZE: usize = 1024 * 1024;
/// Files up to this size (four 64 KiB stream frames) are read in one piece
/// rather than streamed. Setting up a stream (blocking tasks, channels, a
/// chunked download) costs more than reading such a file, and its plaintext
/// and ciphertext together take no more memory than the frames a stream
/// keeps in flight anyway.
const STREAM_READ_THRESHOLD: u64 = 256 * 1024;
/// Bytes the one-shot AEAD encoding (content version 0) adds to the
/// plaintext: the nonce in front of it and the tag behind it.
const ONE_SHOT_OVERHEAD: u64 = (NONCE_SIZE + TAG_SIZE) as u64;

/// `Write` adapter that batches ciphertext into chunks for a provider upload
/// stream; the [`HashingStream`] on the other end hashes them.
struct ChunkSender {
    sender: tokio::sync::mpsc::Sender<Result<Vec<u8>>>,
    buffer: Vec<u8>,
}

impl Write for ChunkSender {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.buffer.len() + bytes.len() > UPLOAD_CHUNK_SIZE {
            self.flush()?;
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let chunk = std::mem::replace(&mut self.buffer, Vec::with_capacity(UPLOAD_CHUNK_SIZE));
        self.sender.blocking_send(Ok(chunk)).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "upload stopped consuming encrypted data",
            )
        })
    }
}

/// Provider upload stream over the chunks of a [`ChunkSender`]. It hashes
/// each chunk as the provider takes it, so the hash runs on the upload side
/// instead of the encrypt thread. Once dropped, it hands over the digest of
/// everything it yielded, unless ciphertext was left that the provider never
/// took.
struct HashingStream {
    receiver: tokio::sync::mpsc::Receiver<Result<Vec<u8>>>,
    hasher: DigestHasher,
    digest: Option<tokio::sync::oneshot::Sender<String>>,
}

impl HashingStream {
    /// Returns the stream and a future of its digest.
    fn new(
        receiver: tokio::sync::mpsc::Receiver<Result<Vec<u8>>>,
    ) -> (Self, impl Future<Output = Result<String>>) {
        let (sender, digest) = tokio::sync::oneshot::channel();
        let stream = Self {
            receiver,
            hasher: DigestHasher::new(),
            digest: Some(sender),
        };
        let digest = async move {
            digest.await.map_err(|_| {
                Error::Storage("upload stopped before taking all encrypted data".to_string())
            })
        };
        (stream, digest)
    }
}

impl Stream for HashingStream {
    type Item = Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let item = ready!(self.receiver.poll_recv(cx));
        if let Some(Ok(chunk)) = &item {
            self.hasher.update(chunk);
        }
        Poll::Ready(item)
    }
}

impl Drop for HashingStream {
    fn drop(&mut self) {
        // Closing first means the encryptor can't send anything after the
        // check; if it is still running, it fails instead.
        self.receiver.close();
        if self.receiver.try_recv().is_err() {
            if let Some(sender) = self.digest.take() {
                let _ = sender.send(finish_digest(std::mem::take(&mut self.hasher)));
            }
        }
    }
}

/// `Read` adapter that serves downloaded ciphertext chunks to the decryptor.
struct ChunkReceiver {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    offset: usize,
}

impl Read for ChunkReceiver {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        while self.offset == self.pending.len() {
            match self.receiver.blocking_recv() {
                Some(chunk) => {
                    self.pending = chunk;
                    self.offset = 0;
                }
                None => return Ok(0),
            }
        }
        let count = buffer.len().min(self.pending.len() - self.offset);
        buffer[..count].copy_from_slice(&self.pending[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

/// `Write` adapter that hands decrypted chunks to the re-encryption task.
struct PlaintextSender(tokio::sync::mpsc::Sender<Vec<u8>>);

impl Write for PlaintextSender {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.blocking_send(bytes.to_vec()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "re-encryption stopped consuming plaintext",
            )
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `Write` sink that keeps plaintext bytes `[skip, skip + wanted)` and drops
/// the rest. With `stop_when_full`, the write that fills it fails, which
/// stops the decryptor before it opens any later frame. `wanted` must be
/// non-zero.
struct PlaintextWindow {
    skip: u64,
    wanted: usize,
    bytes: Vec<u8>,
    stop_when_full: bool,
    /// Set by the write that filled the window and stopped the decryptor.
    stopped: bool,
}

impl Write for PlaintextWindow {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let skipped = usize::try_from(self.skip).map_or(bytes.len(), |skip| skip.min(bytes.len()));
        self.skip -= skipped as u64;
        let rest = &bytes[skipped..];
        let take = rest.len().min(self.wanted - self.bytes.len());
        self.bytes.extend_from_slice(&rest[..take]);
        if self.stop_when_full && self.bytes.len() == self.wanted {
            self.stopped = true;
            return Err(std::io::Error::other("plaintext window is full"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `Write` adapter that hands decrypted plaintext to a [`FileReader`],
/// dropping the first `skip` bytes.
struct ReaderSender {
    sender: tokio::sync::mpsc::Sender<Result<Zeroizing<Vec<u8>>>>,
    skip: u64,
}

impl Write for ReaderSender {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let skipped = usize::try_from(self.skip).map_or(bytes.len(), |skip| skip.min(bytes.len()));
        self.skip -= skipped as u64;
        if skipped < bytes.len() {
            let chunk = Zeroizing::new(bytes[skipped..].to_vec());
            self.sender.blocking_send(Ok(chunk)).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "file reader was dropped")
            })?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Sequential plaintext of a vault file, decrypted frame by frame as it is
/// consumed. Dropping it stops the download and the decryption.
pub struct FileReader {
    receiver: tokio::sync::mpsc::Receiver<Result<Zeroizing<Vec<u8>>>>,
    size: u64,
}

impl FileReader {
    /// File size as recorded in the authenticated tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Next piece of plaintext, or `None` once the whole file has been
    /// returned and its ciphertext matched the authenticated snapshot.
    pub async fn next_chunk(&mut self) -> Option<Result<Zeroizing<Vec<u8>>>> {
        self.receiver.recv().await
    }
}

/// `Read` adapter that serves plaintext handed to a [`FileWriter`] to the
/// encryptor and hands each piece back once it has been consumed, so the
/// writer wipes and reuses it off the encryption thread.
struct WriterReceiver {
    receiver: tokio::sync::mpsc::Receiver<Zeroizing<Vec<u8>>>,
    consumed: tokio::sync::mpsc::UnboundedSender<Zeroizing<Vec<u8>>>,
    pending: Zeroizing<Vec<u8>>,
    offset: usize,
}

impl Read for WriterReceiver {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        while self.offset == self.pending.len() {
            match self.receiver.blocking_recv() {
                Some(chunk) => {
                    // A writer that has gone away drops the piece, which wipes it.
                    let _ = self
                        .consumed
                        .send(std::mem::replace(&mut self.pending, chunk));
                    self.offset = 0;
                }
                None => return Ok(0),
            }
        }
        let count = buffer.len().min(self.pending.len() - self.offset);
        buffer[..count].copy_from_slice(&self.pending[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

/// New content for an existing vault file, or the content of a new one,
/// encrypted and uploaded as it is written. Nothing changes in the vault
/// until [`VaultOperations::finish_file_writer`]; a writer dropped before
/// that leaves only an unreferenced blob behind.
pub struct FileWriter {
    sender: tokio::sync::mpsc::Sender<Zeroizing<Vec<u8>>>,
    encrypt_task: tokio::task::JoinHandle<Result<()>>,
    /// Yields the digest of the uploaded ciphertext.
    upload_task: tokio::task::JoinHandle<Result<String>>,
    encrypted_name: String,
    /// Session master key the name and content are encrypted under.
    master_key_id: u64,
    size: u64,
    /// Written plaintext not yet handed to the encryptor. Never grows past
    /// its capacity, so it is never reallocated with unwiped contents.
    batch: Zeroizing<Vec<u8>>,
    /// Batches the encryptor has consumed, still holding their plaintext.
    consumed: tokio::sync::mpsc::UnboundedReceiver<Zeroizing<Vec<u8>>>,
    /// Finishing creates the file instead of replacing its content.
    create: bool,
}

impl FileWriter {
    /// Number of bytes written so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Append `data` to the new content.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        let mut rest = data;
        while !rest.is_empty() {
            let take = rest.len().min(WRITE_BATCH_SIZE - self.batch.len());
            self.batch.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.batch.len() == WRITE_BATCH_SIZE {
                self.send_batch().await?;
            }
        }
        self.size += data.len() as u64;
        Ok(())
    }

    /// Hand the batched plaintext to the encryptor, continuing in a wiped
    /// batch it has already consumed if there is one.
    async fn send_batch(&mut self) -> Result<()> {
        let next = match self.consumed.try_recv() {
            // The encryptor's initial empty piece has no room for a batch.
            Ok(mut used) if used.capacity() >= WRITE_BATCH_SIZE => {
                used.zeroize();
                used
            }
            _ => Zeroizing::new(Vec::with_capacity(WRITE_BATCH_SIZE)),
        };
        let batch = std::mem::replace(&mut self.batch, next);
        self.sender
            .send(batch)
            .await
            .map_err(|_| Error::Storage("encryption stopped consuming plaintext".to_string()))
    }
}

/// Encrypt a filename under `master_key`.
fn encrypt_name_with(master_key: &MasterKey, name: &str) -> Result<String> {
    let dir_key = master_key.derive_directory_key(b"names");
    let encrypted = encrypt(dir_key.as_bytes(), name.as_bytes())?;
    Ok(URL_SAFE_NO_PAD.encode(encrypted))
}

/// Encrypted names of every file object `tree` references.
pub(crate) fn file_object_names(tree: &VaultTree) -> HashSet<String> {
    fn collect(node: &TreeNode, names: &mut HashSet<String>) {
        if node.is_file() {
            names.insert(node.metadata.encrypted_name.clone());
        }
        for child in node.children.values() {
            collect(child, names);
        }
    }
    let mut names = HashSet::new();
    collect(tree.root(), &mut names);
    names
}

/// Re-encrypt every node of `tree` from `old_key` to `new_key`.
///
/// Each node gets a fresh encrypted name under the new key, so every file
/// object is written to a new path and the objects the current generation
/// references stay untouched. Every path written, complete or not, is pushed
/// to `written` before its upload starts. Returns the re-keyed tree; nothing
/// is published.
pub(crate) async fn reencrypt_tree(
    provider: &Arc<dyn StorageProvider>,
    old_key: &MasterKey,
    new_key: &MasterKey,
    tree: &VaultTree,
    written: &mut Vec<VaultPath>,
) -> Result<VaultTree> {
    fn collect(node: &TreeNode, path: &VaultPath, paths: &mut Vec<VaultPath>) -> Result<()> {
        for (name, child) in &node.children {
            let child_path = path.join(name)?;
            collect(child, &child_path, paths)?;
            paths.push(child_path);
        }
        Ok(())
    }
    let mut paths = Vec::new();
    collect(tree.root(), &VaultPath::parse("/")?, &mut paths)?;

    let data_dir = VaultPath::parse(DATA_DIRNAME)?;
    let mut rotated = tree.clone();
    for path in paths {
        let node = rotated.get_node_mut(&path)?;
        let new_name = encrypt_name_with(new_key, &node.metadata.name)?;
        if !node.is_file() {
            node.metadata.encrypted_name = new_name;
            continue;
        }
        let old_name = node.metadata.encrypted_name.clone();
        let expected_digest = node.metadata.content_digest.clone();
        let content_version = node.metadata.content_version;
        let size = node.metadata.size.unwrap_or(0);
        let old_path = data_dir.join(&old_name)?;
        let new_path = data_dir.join(&new_name)?;
        let old_file_key = Zeroizing::new(
            old_key
                .derive_file_key(old_name.as_bytes())
                .as_bytes()
                .to_vec(),
        );
        let new_file_key = Zeroizing::new(
            new_key
                .derive_file_key(new_name.as_bytes())
                .as_bytes()
                .to_vec(),
        );

        written.push(new_path.clone());
        let new_digest = match content_version {
            0 => {
                let ciphertext =
                    download_exact(provider.as_ref(), &old_path, size + ONE_SHOT_OVERHEAD).await?;
                if expected_digest.is_some_and(|expected| expected != digest(&ciphertext)) {
                    return Err(Error::Crypto(
                        "encrypted file does not match the authenticated snapshot".to_string(),
                    ));
                }
                let plaintext = Zeroizing::new(decrypt(&old_file_key, &ciphertext)?);
                let ciphertext = encrypt(&new_file_key, &plaintext)?;
                let new_digest = digest(&ciphertext);
                provider.upload(&new_path, ciphertext).await?;
                new_digest
            }
            STREAM_CONTENT_VERSION => {
                reencrypt_stream(
                    provider,
                    &old_path,
                    &new_path,
                    old_file_key,
                    new_file_key,
                    expected_digest,
                    size,
                )
                .await?
            }
            other => {
                return Err(Error::Crypto(format!(
                    "Unsupported file content version: {other}"
                )))
            }
        };

        let node = rotated.get_node_mut(&path)?;
        node.metadata.encrypted_name = new_name;
        node.metadata.content_digest = Some(new_digest);
    }
    Ok(rotated)
}

/// Stream one framed object from `from` (under `old_key`) to `to` (under
/// `new_key`) with bounded memory. Returns the new ciphertext digest.
async fn reencrypt_stream(
    provider: &Arc<dyn StorageProvider>,
    from: &VaultPath,
    to: &VaultPath,
    old_key: Zeroizing<Vec<u8>>,
    new_key: Zeroizing<Vec<u8>>,
    expected_digest: Option<String>,
    plaintext_size: u64,
) -> Result<String> {
    let encrypted_size = EncryptingStream::new(&new_key)?.encrypted_len(plaintext_size);
    let mut download = download_stream_bounded(provider.as_ref(), from, encrypted_size).await?;
    let (cipher_sender, cipher_receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
    let (plain_sender, plain_receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
    let (upload_sender, upload_receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);

    let decrypt_task = tokio::task::spawn_blocking(move || -> Result<()> {
        let input = ChunkReceiver {
            receiver: cipher_receiver,
            pending: Vec::new(),
            offset: 0,
        };
        DecryptingStream::new(&old_key)?.decrypt_stream(input, PlaintextSender(plain_sender))?;
        Ok(())
    });
    let encrypt_task = tokio::task::spawn_blocking(move || -> Result<()> {
        let input = ChunkReceiver {
            receiver: plain_receiver,
            pending: Vec::new(),
            offset: 0,
        };
        let mut output = ChunkSender {
            sender: upload_sender,
            buffer: Vec::new(),
        };
        let result = EncryptingStream::new(&new_key)
            .and_then(|stream| stream.encrypt_stream(input, &mut output))
            .and_then(|_| Ok(output.flush()?));
        if let Err(error) = &result {
            // Abort the upload so the provider discards its partial object.
            let _ = output
                .sender
                .blocking_send(Err(Error::Storage(error.to_string())));
        }
        result
    });

    let feed = async move {
        let mut hasher = DigestHasher::new();
        while let Some(chunk) = download.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            // The decryptor stops consuming once it hits an invalid frame.
            if cipher_sender.send(chunk).await.is_err() {
                break;
            }
        }
        Ok::<_, Error>(finish_digest(hasher))
    };
    let (encrypted_stream, content_digest) = HashingStream::new(upload_receiver);
    let (read_digest, upload_result) = tokio::join!(
        feed,
        provider.upload_sized_stream(to, Box::pin(encrypted_stream), encrypted_size)
    );
    let decryption_result = decrypt_task
        .await
        .map_err(|error| Error::Storage(format!("decryption task failed: {error}")))?;
    let encryption_result = encrypt_task
        .await
        .map_err(|error| Error::Storage(format!("encryption task failed: {error}")))?;
    let read_digest = read_digest?;
    // A failed decryption ends the plaintext early, so the upload may still
    // succeed with a truncated object; it is rejected here before any commit.
    decryption_result?;
    if expected_digest.is_some_and(|expected| expected != read_digest) {
        return Err(Error::Crypto(
            "encrypted file does not match the authenticated snapshot".to_string(),
        ));
    }
    upload_result?;
    encryption_result?;
    content_digest.await
}

/// Download the object at `path`, which the authenticated snapshot says is
/// `expected_len` bytes long. A longer object fails as soon as it runs past
/// that length, so the backend can't make this hold more than the snapshot
/// allows; a shorter one fails at its end.
async fn download_exact(
    provider: &dyn StorageProvider,
    path: &VaultPath,
    expected_len: u64,
) -> Result<Vec<u8>> {
    let mismatch =
        || Error::Crypto("encrypted file does not match the authenticated snapshot".to_string());
    let len = usize::try_from(expected_len).map_err(|_| mismatch())?;
    let data = match provider.download_bounded(path, expected_len).await {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::FileTooLarge => return Err(mismatch()),
        result => result?,
    };
    if data.len() != len {
        return Err(mismatch());
    }
    Ok(data)
}

/// Stream the object at `path`, which the authenticated snapshot says is
/// `expected_len` bytes long. Like [`download_exact`], the stream fails as
/// soon as it runs past that length, so the backend can't make a streamed
/// read consume more than the snapshot allows, and fails at its end if it
/// is shorter, so an older, shorter version of the file is not accepted
/// in its place. It ends after its first error.
async fn download_stream_bounded(
    provider: &dyn StorageProvider,
    path: &VaultPath,
    expected_len: u64,
) -> Result<ByteStream> {
    let download = provider.download_stream(path).await?;
    Ok(Box::pin(futures::stream::unfold(
        Some((download, expected_len)),
        |state| async move {
            let (mut download, remaining) = state?;
            let mismatch = || {
                Error::Crypto(
                    "encrypted file does not match the authenticated snapshot".to_string(),
                )
            };
            match download.next().await {
                Some(Ok(chunk)) => match remaining.checked_sub(chunk.len() as u64) {
                    Some(remaining) => Some((Ok(chunk), Some((download, remaining)))),
                    None => Some((Err(mismatch()), None)),
                },
                Some(Err(error)) => Some((Err(error), None)),
                None if remaining != 0 => Some((Err(mismatch()), None)),
                None => None,
            }
        },
    )))
}

fn persist_plaintext_noclobber(destination: &Path, plaintext: &[u8]) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| Error::InvalidInput("Destination has no parent".to_string()))?;
    #[cfg(not(unix))]
    {
        let _ = (parent, plaintext);
        return Err(Error::NotPermitted(
            "secure plaintext-file ACL creation is not implemented on this platform".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut output = tempfile::NamedTempFile::new_in(parent)?;
        output
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        output.write_all(plaintext)?;
        output.as_file().sync_all()?;
        output
            .persist_noclobber(destination)
            .map_err(|error| Error::Io(error.error))?;
        Ok(())
    }
}

/// Vault operations handler.
///
/// Provides encrypted file operations using an active session.
pub struct VaultOperations<'a> {
    session: &'a VaultSession,
}

impl<'a> VaultOperations<'a> {
    /// Create new operations handler for a session.
    pub fn new(session: &'a VaultSession) -> Result<Self> {
        if !session.is_active() {
            return Err(Error::NotPermitted("Session is not active".to_string()));
        }
        Ok(Self { session })
    }

    /// Encrypt a filename.
    fn encrypt_name(&self, name: &str) -> Result<String> {
        encrypt_name_with(self.session.master_key()?, name)
    }

    /// Create a new file with encrypted content.
    ///
    /// # Preconditions
    /// - Parent directory must exist
    /// - File must not exist
    /// - Session must be active
    ///
    /// # Postconditions
    /// - File is created in storage with encrypted content
    /// - Tree is updated with new file entry
    ///
    /// # Errors
    /// - Parent not found
    /// - File already exists
    /// - Encryption failure
    /// - Storage failure
    pub async fn create_file(&self, path: &VaultPath, content: &[u8]) -> Result<()> {
        let name = path
            .name()
            .ok_or_else(|| Error::InvalidInput("Invalid file path".to_string()))?;

        debug!("Creating encrypted file");

        let encrypted_name = self.encrypt_name(name)?;

        let master_key = self.session.master_key()?;
        let file_key = master_key.derive_file_key(encrypted_name.as_bytes());
        let encrypted_content = encrypt(file_key.as_bytes(), content)?;

        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;
        let mut tree = self.session.tree().write().await;
        let mut candidate = tree.clone();
        candidate.create_file(path, &encrypted_name, content.len() as u64)?;

        let content_digest = digest(&encrypted_content);
        self.session
            .provider()
            .upload(&storage_path, encrypted_content)
            .await?;

        candidate.get_node_mut(path)?.metadata.content_digest = Some(content_digest);
        self.session.save_tree_snapshot(&candidate).await?;
        *tree = candidate;

        info!(size = content.len(), "File created");
        Ok(())
    }

    /// Import a local file through bounded-memory encryption and provider streaming.
    ///
    /// Ciphertext frames flow straight from the encryptor into the provider
    /// upload; nothing is staged on disk or held in memory beyond a few chunks.
    pub async fn create_file_from_path(
        &self,
        path: &VaultPath,
        source: impl AsRef<Path>,
    ) -> Result<()> {
        let name = path
            .name()
            .ok_or_else(|| Error::InvalidInput("Invalid file path".to_string()))?;
        if self.session.tree().read().await.get_node(path).is_ok() {
            return Err(Error::AlreadyExists(format!("Path already exists: {path}")));
        }
        let source = source.as_ref().to_path_buf();
        let size = tokio::fs::metadata(&source).await?.len();
        let encrypted_name = self.encrypt_name(name)?;
        let file_key = self
            .session
            .master_key()?
            .derive_file_key(encrypted_name.as_bytes());
        let key = Zeroizing::new(file_key.as_bytes().to_vec());
        let encrypted_size = EncryptingStream::new(&key)?.encrypted_len(size);

        let (sender, receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
        let encrypt_task = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut output = ChunkSender {
                sender,
                buffer: Vec::new(),
            };
            let result = std::fs::File::open(source)
                .map_err(Error::from)
                .and_then(|mut input| {
                    EncryptingStream::new(&key)?.encrypt_stream(&mut input, &mut output)?;
                    Ok(output.flush()?)
                });
            if let Err(error) = &result {
                // Abort the upload so the provider discards its partial object.
                let _ = output
                    .sender
                    .blocking_send(Err(Error::Storage(error.to_string())));
            }
            result
        });
        let (encrypted_stream, content_digest) = HashingStream::new(receiver);
        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;
        let mut tree = self.session.tree().write().await;
        let upload_result = self
            .session
            .provider()
            .upload_sized_stream(&storage_path, Box::pin(encrypted_stream), encrypted_size)
            .await;
        let encryption_result = encrypt_task
            .await
            .map_err(|error| Error::Storage(format!("encryption task failed: {}", error)))?;
        upload_result?;
        encryption_result?;
        let content_digest = content_digest.await?;

        let mut candidate = tree.clone();
        candidate.create_file(path, &encrypted_name, size)?;
        let node = candidate.get_node_mut(path)?;
        node.metadata.content_version = STREAM_CONTENT_VERSION;
        node.metadata.content_digest = Some(content_digest);
        self.session.save_tree_snapshot(&candidate).await?;
        *tree = candidate;
        info!(size, "File imported");
        Ok(())
    }

    /// Export a vault file without materializing ciphertext or plaintext in memory.
    /// Plaintext is written to a temporary sibling and only published after every
    /// frame, including the authenticated end frame, has verified successfully and
    /// the downloaded ciphertext matches the digest in the authenticated snapshot.
    pub async fn export_file_to_path(
        &self,
        path: &VaultPath,
        destination: impl AsRef<Path>,
    ) -> Result<()> {
        let (encrypted_name, expected_digest, content_version, size) = {
            let tree = self.session.tree().read().await;
            let node = tree.get_node(path)?;
            if !node.is_file() {
                return Err(Error::InvalidInput("Not a file".to_string()));
            }
            (
                node.metadata.encrypted_name.clone(),
                node.metadata.content_digest.clone(),
                node.metadata.content_version,
                node.metadata.size.unwrap_or(0),
            )
        };
        if content_version == 0 {
            // Existing vaults predate stream framing. Preserve deterministic
            // compatibility instead of guessing from random nonce bytes. This
            // one-time legacy path uses the old whole-object API; rewriting the
            // file through import/update migrates it to version 2.
            let content = self.read_file(path).await?;
            let destination = destination.as_ref().to_path_buf();
            return tokio::task::spawn_blocking(move || {
                persist_plaintext_noclobber(&destination, &content)
            })
            .await
            .map_err(|error| Error::Storage(format!("plaintext write task failed: {error}")))?;
        }
        if content_version != STREAM_CONTENT_VERSION {
            return Err(Error::Crypto(format!(
                "Unsupported file content version: {}",
                content_version
            )));
        }
        let destination = destination.as_ref().to_path_buf();
        let parent = destination
            .parent()
            .ok_or_else(|| Error::InvalidInput("Destination has no parent".to_string()))?
            .to_path_buf();
        let file_key = self
            .session
            .master_key()?
            .derive_file_key(encrypted_name.as_bytes());
        let key = Zeroizing::new(file_key.as_bytes().to_vec());
        let encrypted_len = EncryptingStream::new(&key)?.encrypted_len(size);
        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;
        let mut stream = download_stream_bounded(
            self.session.provider().as_ref(),
            &storage_path,
            encrypted_len,
        )
        .await?;

        let (sender, receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
        let decrypt_task =
            tokio::task::spawn_blocking(move || -> Result<tempfile::NamedTempFile> {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut input = ChunkReceiver {
                        receiver,
                        pending: Vec::new(),
                        offset: 0,
                    };
                    let mut output = tempfile::NamedTempFile::new_in(parent)?;
                    output
                        .as_file()
                        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
                    DecryptingStream::new(&key)?
                        .decrypt_stream(&mut input, output.as_file_mut())?;
                    output.as_file().sync_all()?;
                    Ok(output)
                }
                #[cfg(not(unix))]
                {
                    let _ = (receiver, parent, key);
                    Err(Error::NotPermitted(
                        "secure plaintext-file ACL creation is not implemented on this platform"
                            .to_string(),
                    ))
                }
            });
        let mut hasher = DigestHasher::new();
        let mut download_result = Ok(());
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    hasher.update(&chunk);
                    // The decryptor stops consuming once it hits an invalid frame.
                    if sender.send(chunk).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    download_result = Err(error);
                    break;
                }
            }
        }
        drop(sender);
        let decryption_result = decrypt_task
            .await
            .map_err(|error| Error::Storage(format!("decryption task failed: {}", error)))?;
        download_result?;
        let output = decryption_result?;
        if expected_digest.is_some_and(|expected| expected != finish_digest(hasher)) {
            return Err(Error::Crypto(
                "encrypted file does not match the authenticated snapshot".to_string(),
            ));
        }
        tokio::task::spawn_blocking(move || {
            output
                .persist_noclobber(destination)
                .map(|_| ())
                .map_err(|error| Error::Io(error.error))
        })
        .await
        .map_err(|error| Error::Storage(format!("plaintext write task failed: {error}")))?
    }

    /// Read and decrypt file content.
    ///
    /// # Preconditions
    /// - File must exist
    /// - Session must be active
    ///
    /// # Postconditions
    /// - Returns decrypted file content
    ///
    /// # Errors
    /// - File not found
    /// - Decryption failure
    /// - Storage failure
    pub async fn read_file(&self, path: &VaultPath) -> Result<Vec<u8>> {
        debug!("Reading encrypted file");

        let (encrypted_name, expected_digest, content_version, size) = {
            let tree = self.session.tree().read().await;
            let node = tree.get_node(path)?;
            if !node.is_file() {
                return Err(Error::InvalidInput("Not a file".to_string()));
            }
            (
                node.metadata.encrypted_name.clone(),
                node.metadata.content_digest.clone(),
                node.metadata.content_version,
                // Every writer records the size; a node without one is read
                // as empty, as the streamed paths do.
                node.metadata.size.unwrap_or(0),
            )
        };

        let master_key = self.session.master_key()?;
        let file_key = master_key.derive_file_key(encrypted_name.as_bytes());
        let encrypted_len = match content_version {
            0 => size + ONE_SHOT_OVERHEAD,
            STREAM_CONTENT_VERSION => {
                EncryptingStream::new(file_key.as_bytes())?.encrypted_len(size)
            }
            other => {
                return Err(Error::Crypto(format!(
                    "Unsupported file content version: {other}"
                )))
            }
        };
        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;
        let encrypted_content = download_exact(
            self.session.provider().as_ref(),
            &storage_path,
            encrypted_len,
        )
        .await?;
        if expected_digest.is_some_and(|expected| expected != digest(&encrypted_content)) {
            return Err(Error::Crypto(
                "encrypted file does not match the authenticated snapshot".to_string(),
            ));
        }

        let content = if content_version == 0 {
            decrypt(file_key.as_bytes(), &encrypted_content)?
        } else {
            let mut plaintext = Zeroizing::new(Vec::with_capacity(encrypted_content.len()));
            DecryptingStream::new(file_key.as_bytes())?
                .decrypt_stream(encrypted_content.as_slice(), &mut *plaintext)?;
            std::mem::take(&mut *plaintext)
        };

        debug!(size = content.len(), "File read");
        Ok(content)
    }

    /// Read at most `max_bytes` of a file from `offset` on, and the file's
    /// size as recorded in the authenticated tree.
    ///
    /// Only the window is held in memory, and stream frames after it are
    /// never decrypted. The whole ciphertext is still downloaded and hashed,
    /// because its digest in the authenticated snapshot is what ties the
    /// blob to the current generation. Frames before `offset` are decrypted
    /// and dropped, as the stream can only be authenticated in order; that
    /// costs about as much as the hashing every read does anyway. A node
    /// without a digest (written before digests existed) has nothing else
    /// that would catch a truncated or extended blob, so every frame up to
    /// the authenticated end frame is decrypted, and all but the window
    /// dropped. Files written in one piece (content version 0) are read
    /// whole.
    pub async fn read_file_range(
        &self,
        path: &VaultPath,
        offset: u64,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, u64)> {
        let (encrypted_name, expected_digest, content_version, size) = {
            let tree = self.session.tree().read().await;
            let node = tree.get_node(path)?;
            if !node.is_file() {
                return Err(Error::InvalidInput("Not a file".to_string()));
            }
            (
                node.metadata.encrypted_name.clone(),
                node.metadata.content_digest.clone(),
                node.metadata.content_version,
                node.metadata.size.unwrap_or(0),
            )
        };
        if max_bytes == 0 || offset >= size {
            return Ok((Vec::new(), size));
        }
        if content_version != STREAM_CONTENT_VERSION {
            let content = self.read_file(path).await?;
            let start = usize::try_from(offset).map_or(content.len(), |o| o.min(content.len()));
            let end = start.saturating_add(max_bytes).min(content.len());
            return Ok((content[start..end].to_vec(), size));
        }

        let file_key = self
            .session
            .master_key()?
            .derive_file_key(encrypted_name.as_bytes());
        let key = Zeroizing::new(file_key.as_bytes().to_vec());
        let encrypted_len = EncryptingStream::new(&key)?.encrypted_len(size);
        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;
        let mut stream = download_stream_bounded(
            self.session.provider().as_ref(),
            &storage_path,
            encrypted_len,
        )
        .await?;

        let verify_with_digest = expected_digest.is_some();
        let (sender, receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
        let decrypt_task = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let mut input = ChunkReceiver {
                receiver,
                pending: Vec::new(),
                offset: 0,
            };
            let mut window = PlaintextWindow {
                skip: offset,
                wanted: max_bytes,
                bytes: Vec::new(),
                stop_when_full: verify_with_digest,
                stopped: false,
            };
            match DecryptingStream::new(&key)?.decrypt_stream(&mut input, &mut window) {
                Ok(_) => Ok(window.bytes),
                Err(_) if window.stopped => Ok(window.bytes),
                Err(error) => Err(error),
            }
        });
        let mut hasher = DigestHasher::new();
        let mut download_result = Ok(());
        let mut decrypting = true;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    hasher.update(&chunk);
                    // Once the decryptor stops (window full or invalid
                    // frame), the rest is only hashed.
                    if decrypting && sender.send(chunk).await.is_err() {
                        decrypting = false;
                    }
                }
                Err(error) => {
                    download_result = Err(error);
                    break;
                }
            }
        }
        drop(sender);
        let decryption_result = decrypt_task
            .await
            .map_err(|error| Error::Storage(format!("decryption task failed: {}", error)))?;
        download_result?;
        let bytes = decryption_result?;
        if expected_digest.is_some_and(|expected| expected != finish_digest(hasher)) {
            return Err(Error::Crypto(
                "encrypted file does not match the authenticated snapshot".to_string(),
            ));
        }
        debug!(returned = bytes.len(), size, "File range read");
        Ok((bytes, size))
    }

    /// Open a file for sequential reading from `offset` on.
    ///
    /// Download and decryption run in the background, at most a few frames
    /// ahead of the consumer, so memory stays bounded whatever the file
    /// size. Each frame is authenticated before its plaintext is handed out,
    /// and a truncated stream fails at its missing end frame. The ciphertext
    /// digest can only be checked once the whole blob has been downloaded,
    /// so a mismatch surfaces as an error in place of the end of the file.
    /// Frames before `offset` are decrypted and dropped. Files written in
    /// one piece (content version 0) and files of at most
    /// `STREAM_READ_THRESHOLD` bytes are read, verified and decrypted whole
    /// before this returns.
    pub async fn open_file_reader(&self, path: &VaultPath, offset: u64) -> Result<FileReader> {
        let (encrypted_name, expected_digest, content_version, size) = {
            let tree = self.session.tree().read().await;
            let node = tree.get_node(path)?;
            if !node.is_file() {
                return Err(Error::InvalidInput("Not a file".to_string()));
            }
            (
                node.metadata.encrypted_name.clone(),
                node.metadata.content_digest.clone(),
                node.metadata.content_version,
                node.metadata.size.unwrap_or(0),
            )
        };
        let (plain_sender, receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
        if offset >= size {
            return Ok(FileReader { receiver, size });
        }
        if content_version != STREAM_CONTENT_VERSION || size <= STREAM_READ_THRESHOLD {
            let content = Zeroizing::new(self.read_file(path).await?);
            let start = usize::try_from(offset).map_or(content.len(), |o| o.min(content.len()));
            if start < content.len() {
                let _ = plain_sender.try_send(Ok(Zeroizing::new(content[start..].to_vec())));
            }
            return Ok(FileReader { receiver, size });
        }

        let file_key = self
            .session
            .master_key()?
            .derive_file_key(encrypted_name.as_bytes());
        let key = Zeroizing::new(file_key.as_bytes().to_vec());
        let encrypted_len = EncryptingStream::new(&key)?.encrypted_len(size);
        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;
        let mut stream = download_stream_bounded(
            self.session.provider().as_ref(),
            &storage_path,
            encrypted_len,
        )
        .await?;

        let (sender, cipher_receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
        let mut output = ReaderSender {
            sender: plain_sender.clone(),
            skip: offset,
        };
        let decrypt_task = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut input = ChunkReceiver {
                receiver: cipher_receiver,
                pending: Vec::new(),
                offset: 0,
            };
            DecryptingStream::new(&key)?.decrypt_stream(&mut input, &mut output)?;
            Ok(())
        });
        tokio::spawn(async move {
            let mut hasher = DigestHasher::new();
            let mut download_result = Ok(());
            while let Some(chunk) = stream.next().await {
                if plain_sender.is_closed() {
                    return;
                }
                match chunk {
                    Ok(chunk) => {
                        hasher.update(&chunk);
                        if sender.send(chunk).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        download_result = Err(error);
                        break;
                    }
                }
            }
            drop(sender);
            let result = match decrypt_task.await {
                Err(error) => Err(Error::Storage(format!("decryption task failed: {}", error))),
                Ok(decryption_result) => download_result.and(decryption_result).and_then(|()| {
                    if expected_digest.is_some_and(|expected| expected != finish_digest(hasher)) {
                        Err(Error::Crypto(
                            "encrypted file does not match the authenticated snapshot".to_string(),
                        ))
                    } else {
                        Ok(())
                    }
                }),
            };
            if let Err(error) = result {
                let _ = plain_sender.send(Err(error)).await;
            }
        });
        Ok(FileReader { receiver, size })
    }

    /// Start replacing the content of the file at `path` with a stream of
    /// writes. Plaintext is encrypted and uploaded as it arrives, with at
    /// most a few chunks in flight.
    pub async fn open_file_writer(&self, path: &VaultPath) -> Result<FileWriter> {
        if !self.session.tree().read().await.get_node(path)?.is_file() {
            return Err(Error::InvalidInput("Not a file".to_string()));
        }
        self.start_file_writer(path, false)
    }

    /// Start writing a new file at `path`, which must not exist yet. The
    /// file appears in the vault, with all its content, only when the writer
    /// is finished, so a new file costs one snapshot publication.
    pub async fn create_file_writer(&self, path: &VaultPath) -> Result<FileWriter> {
        if self.session.tree().read().await.get_node(path).is_ok() {
            return Err(Error::AlreadyExists(format!("{path} already exists")));
        }
        self.start_file_writer(path, true)
    }

    fn start_file_writer(&self, path: &VaultPath, create: bool) -> Result<FileWriter> {
        let name = path
            .name()
            .ok_or_else(|| Error::InvalidInput("Invalid file path".to_string()))?;
        let encrypted_name = self.encrypt_name(name)?;
        let file_key = self
            .session
            .master_key()?
            .derive_file_key(encrypted_name.as_bytes());
        let key = Zeroizing::new(file_key.as_bytes().to_vec());
        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;

        let (sender, receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
        let (consumed_sender, consumed) = tokio::sync::mpsc::unbounded_channel();
        let (cipher_sender, cipher_receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
        let encrypt_task = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut input = WriterReceiver {
                receiver,
                consumed: consumed_sender,
                pending: Zeroizing::new(Vec::new()),
                offset: 0,
            };
            let mut output = ChunkSender {
                sender: cipher_sender,
                buffer: Vec::new(),
            };
            let result = EncryptingStream::new(&key)
                .and_then(|stream| stream.encrypt_stream(&mut input, &mut output))
                .and_then(|_| Ok(output.flush()?));
            if let Err(error) = &result {
                // Abort the upload so the provider discards its partial object.
                let _ = output
                    .sender
                    .blocking_send(Err(Error::Storage(error.to_string())));
            }
            result
        });
        let provider = self.session.provider();
        let upload_task = tokio::spawn(async move {
            let (encrypted_stream, content_digest) = HashingStream::new(cipher_receiver);
            provider
                .upload_stream(&storage_path, Box::pin(encrypted_stream))
                .await?;
            content_digest.await
        });
        Ok(FileWriter {
            sender,
            encrypt_task,
            upload_task,
            encrypted_name,
            master_key_id: self.session.master_key_id(),
            size: 0,
            batch: Zeroizing::new(Vec::with_capacity(WRITE_BATCH_SIZE)),
            consumed,
            create,
        })
    }

    /// Finish a [`FileWriter`] and make its content the content of `path`.
    pub async fn finish_file_writer(&self, path: &VaultPath, mut writer: FileWriter) -> Result<()> {
        let sent = if writer.batch.is_empty() {
            Ok(())
        } else {
            writer.send_batch().await
        };
        let FileWriter {
            sender,
            encrypt_task,
            upload_task,
            encrypted_name,
            master_key_id,
            size,
            batch: _,
            consumed: _,
            create,
        } = writer;
        drop(sender);
        let encryption_result = encrypt_task
            .await
            .map_err(|error| Error::Storage(format!("encryption task failed: {}", error)))?;
        let content_digest = upload_task
            .await
            .map_err(|error| Error::Storage(format!("upload task failed: {}", error)))??;
        encryption_result?;
        sent?;
        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;

        let mut tree = self.session.tree().write().await;
        let mut candidate = tree.clone();
        let node = if master_key_id != self.session.master_key_id() {
            // Published under another key, the file would be unreadable.
            Err(Error::Conflict(
                "the master key changed while the file was written".to_string(),
            ))
        } else if create {
            candidate.create_file(path, &encrypted_name, size)
        } else {
            Ok(())
        }
        .and_then(|()| candidate.get_node_mut(path))
        .and_then(|node| {
            if node.is_file() {
                Ok(node)
            } else {
                Err(Error::InvalidInput("Not a file".to_string()))
            }
        });
        let node = match node {
            Ok(node) => node,
            Err(error) => {
                // Nothing refers to the new blob, as when the file was
                // deleted while it was written. A failed snapshot save below
                // keeps it, as the snapshot may have been published anyway.
                if let Err(error) = self.session.provider().delete(&storage_path).await {
                    warn!(%error, "File write failed and new blob cleanup failed");
                }
                return Err(error);
            }
        };
        let old_encrypted_name =
            std::mem::replace(&mut node.metadata.encrypted_name, encrypted_name);
        node.metadata.size = Some(size);
        node.metadata.modified_at = chrono::Utc::now();
        node.metadata.content_digest = Some(content_digest);
        node.metadata.content_version = STREAM_CONTENT_VERSION;
        self.session.save_tree_snapshot(&candidate).await?;
        *tree = candidate;

        if !create {
            let old_storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&old_encrypted_name)?;
            if let Err(error) = self.session.provider().delete(&old_storage_path).await {
                warn!(%error, "File updated but obsolete blob cleanup failed");
            }
        }
        info!(size, "File written");
        Ok(())
    }

    /// Update file with new encrypted content.
    ///
    /// # Preconditions
    /// - File must exist
    /// - Session must be active
    ///
    /// # Postconditions
    /// - File content is updated with new encrypted data
    /// - Tree metadata is updated
    ///
    /// # Errors
    /// - File not found
    /// - Encryption failure
    /// - Storage failure
    pub async fn update_file(&self, path: &VaultPath, content: &[u8]) -> Result<()> {
        debug!("Updating encrypted file");

        let mut tree = self.session.tree().write().await;
        let old_encrypted_name = {
            let node = tree.get_node(path)?;
            if !node.is_file() {
                return Err(Error::InvalidInput("Not a file".to_string()));
            }
            node.metadata.encrypted_name.clone()
        };

        let name = path
            .name()
            .ok_or_else(|| Error::InvalidInput("Invalid file path".to_string()))?;
        let encrypted_name = self.encrypt_name(name)?;
        let master_key = self.session.master_key()?;
        let file_key = master_key.derive_file_key(encrypted_name.as_bytes());
        let stream = EncryptingStream::new(file_key.as_bytes())?;
        let mut encrypted_content =
            Vec::with_capacity(stream.encrypted_len(content.len() as u64) as usize);
        stream.encrypt_stream(content, &mut encrypted_content)?;
        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;
        let old_storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&old_encrypted_name)?;

        let mut candidate = tree.clone();
        let node = candidate.get_node_mut(path)?;
        node.metadata.encrypted_name = encrypted_name;
        node.metadata.size = Some(content.len() as u64);
        node.metadata.modified_at = chrono::Utc::now();
        node.metadata.content_digest = Some(digest(&encrypted_content));
        node.metadata.content_version = STREAM_CONTENT_VERSION;

        self.session
            .provider()
            .upload(&storage_path, encrypted_content)
            .await?;

        self.session.save_tree_snapshot(&candidate).await?;
        *tree = candidate;

        if let Err(error) = self.session.provider().delete(&old_storage_path).await {
            warn!(%error, "File updated but obsolete blob cleanup failed");
        }

        info!(size = content.len(), "File updated");
        Ok(())
    }

    /// Delete a file.
    ///
    /// # Preconditions
    /// - File must exist
    ///
    /// # Postconditions
    /// - Tree entry is removed
    /// - The obsolete content blob is removed on a best-effort basis
    ///
    /// # Errors
    /// - File not found
    /// - Tree persistence failure
    pub async fn delete_file(&self, path: &VaultPath) -> Result<()> {
        debug!("Deleting file");

        let mut tree = self.session.tree().write().await;
        let encrypted_name = {
            let node = tree.get_node(path)?;
            if !node.is_file() {
                return Err(Error::InvalidInput("Not a file".to_string()));
            }
            node.metadata.encrypted_name.clone()
        };

        let storage_path = VaultPath::parse(DATA_DIRNAME)?.join(&encrypted_name)?;
        let mut candidate = tree.clone();
        candidate.remove(path)?;

        self.session.save_tree_snapshot(&candidate).await?;
        *tree = candidate;

        if let Err(error) = self.session.provider().delete(&storage_path).await {
            warn!(%error, "File deleted but obsolete blob cleanup failed");
        }

        info!("File deleted");
        Ok(())
    }

    /// Create a directory.
    ///
    /// # Preconditions
    /// - Parent must exist
    /// - Directory must not exist
    ///
    /// # Postconditions
    /// - Directory is created in tree
    /// - Directory metadata is stored
    ///
    /// # Errors
    /// - Parent not found
    /// - Already exists
    pub async fn create_directory(&self, path: &VaultPath) -> Result<()> {
        let name = path
            .name()
            .ok_or_else(|| Error::InvalidInput("Invalid directory path".to_string()))?;

        debug!("Creating directory");

        let encrypted_name = self.encrypt_name(name)?;

        let mut tree = self.session.tree().write().await;
        let mut candidate = tree.clone();
        candidate.create_directory(path, &encrypted_name)?;
        self.session.save_tree_snapshot(&candidate).await?;
        *tree = candidate;

        info!("Directory created");
        Ok(())
    }

    /// List directory contents.
    ///
    /// # Preconditions
    /// - Path must be a directory
    ///
    /// # Returns
    /// List of (name, is_directory, size) tuples.
    pub async fn list_directory(
        &self,
        path: &VaultPath,
    ) -> Result<Vec<(String, bool, Option<u64>)>> {
        let tree = self.session.tree().read().await;
        let contents = tree.list(path)?;

        Ok(contents
            .iter()
            .map(|node| {
                (
                    node.metadata.name.clone(),
                    node.is_directory(),
                    node.metadata.size,
                )
            })
            .collect())
    }

    /// Delete an empty directory.
    ///
    /// # Preconditions
    /// - Path must be a directory
    /// - Directory must be empty
    ///
    /// # Errors
    /// - Not a directory
    /// - Directory not empty
    pub async fn delete_directory(&self, path: &VaultPath) -> Result<()> {
        debug!("Deleting directory");

        let mut tree = self.session.tree().write().await;
        let mut candidate = tree.clone();
        {
            let node = candidate.get_node(path)?;

            if !node.is_directory() {
                return Err(Error::InvalidInput("Not a directory".to_string()));
            }

            if !node.children.is_empty() {
                return Err(Error::InvalidInput("Directory not empty".to_string()));
            }
        }
        candidate.remove(path)?;
        self.session.save_tree_snapshot(&candidate).await?;
        *tree = candidate;

        info!("Directory deleted");
        Ok(())
    }

    /// Check if path exists.
    pub async fn exists(&self, path: &VaultPath) -> bool {
        let tree = self.session.tree().read().await;
        tree.exists(path)
    }

    /// Get metadata for a path.
    pub async fn metadata(&self, path: &VaultPath) -> Result<(String, bool, Option<u64>)> {
        let tree = self.session.tree().read().await;
        let node = tree.get_node(path)?;
        Ok((
            node.metadata.name.clone(),
            node.is_directory(),
            node.metadata.size,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VaultConfig;
    use crate::tree::VaultTree;
    use async_trait::async_trait;
    use axiomvault_common::VaultId;
    use axiomvault_crypto::stream::DEFAULT_CHUNK_SIZE;
    use axiomvault_crypto::KdfParams;
    use axiomvault_storage::provider::ByteStream;
    use axiomvault_storage::{MemoryProvider, Metadata, StorageProvider};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct FailingProvider {
        inner: MemoryProvider,
        fail_data_upload: AtomicBool,
        fail_tree_upload: AtomicBool,
        fail_delete: AtomicBool,
        served_blob: Mutex<Option<Vec<u8>>>,
        streamed: Arc<AtomicUsize>,
    }

    impl FailingProvider {
        fn new() -> Self {
            Self {
                inner: MemoryProvider::new(),
                fail_data_upload: AtomicBool::new(false),
                fail_tree_upload: AtomicBool::new(false),
                fail_delete: AtomicBool::new(false),
                served_blob: Mutex::new(None),
                streamed: Arc::new(AtomicUsize::new(0)),
            }
        }

        /// Stream `blob` in 4 KiB chunks for every data object from now on,
        /// counting the bytes the reader takes.
        fn serve_data_blob(&self, blob: Vec<u8>) {
            self.streamed.store(0, Ordering::SeqCst);
            *self.served_blob.lock().unwrap() = Some(blob);
        }

        fn fail_next_data_upload(&self) {
            self.fail_data_upload.store(true, Ordering::SeqCst);
        }

        fn fail_next_delete(&self) {
            self.fail_delete.store(true, Ordering::SeqCst);
        }

        fn fail_next_tree_upload(&self) {
            self.fail_tree_upload.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl StorageProvider for FailingProvider {
        fn name(&self) -> &str {
            "failing-memory"
        }

        async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
            if path.to_string_path().starts_with("/d/")
                && self.fail_data_upload.swap(false, Ordering::SeqCst)
            {
                return Err(Error::Storage("injected upload failure".to_string()));
            }
            if path.to_string_path() == "/m/tree.json"
                && self.fail_tree_upload.swap(false, Ordering::SeqCst)
            {
                return Err(Error::Storage("injected tree upload failure".to_string()));
            }
            self.inner.upload(path, data).await
        }

        async fn upload_stream(&self, path: &VaultPath, stream: ByteStream) -> Result<Metadata> {
            self.inner.upload_stream(path, stream).await
        }

        async fn download(&self, path: &VaultPath) -> Result<Vec<u8>> {
            self.inner.download(path).await
        }

        async fn download_stream(&self, path: &VaultPath) -> Result<ByteStream> {
            let served = self.served_blob.lock().unwrap().clone();
            match served {
                Some(blob) if path.to_string_path().starts_with("/d/") => {
                    let streamed = self.streamed.clone();
                    let chunks: Vec<Vec<u8>> = blob.chunks(4096).map(<[u8]>::to_vec).collect();
                    Ok(Box::pin(futures::stream::iter(chunks).map(move |chunk| {
                        streamed.fetch_add(chunk.len(), Ordering::SeqCst);
                        Ok(chunk)
                    })))
                }
                _ => self.inner.download_stream(path).await,
            }
        }

        async fn exists(&self, path: &VaultPath) -> Result<bool> {
            self.inner.exists(path).await
        }

        async fn delete(&self, path: &VaultPath) -> Result<()> {
            if self.fail_delete.swap(false, Ordering::SeqCst) {
                return Err(Error::Storage("injected delete failure".to_string()));
            }
            self.inner.delete(path).await
        }

        async fn list(&self, path: &VaultPath) -> Result<Vec<Metadata>> {
            self.inner.list(path).await
        }

        async fn metadata(&self, path: &VaultPath) -> Result<Metadata> {
            self.inner.metadata(path).await
        }

        async fn create_dir(&self, path: &VaultPath) -> Result<Metadata> {
            self.inner.create_dir(path).await
        }

        async fn delete_dir(&self, path: &VaultPath) -> Result<()> {
            self.inner.delete_dir(path).await
        }

        async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
            self.inner.rename(from, to).await
        }

        async fn copy(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
            self.inner.copy(from, to).await
        }
    }

    async fn create_test_session() -> VaultSession {
        let id = VaultId::new("test").unwrap();
        let password = b"test-password";
        let params = KdfParams::moderate();
        let creation =
            VaultConfig::new(id, password, "memory", serde_json::Value::Null, params).unwrap();

        let provider = Arc::new(MemoryProvider::new());

        provider
            .create_dir(&VaultPath::parse("/d").unwrap())
            .await
            .unwrap();

        provider
            .create_dir(&VaultPath::parse("/m").unwrap())
            .await
            .unwrap();

        use crate::tree::VaultTree;
        VaultSession::unlock(creation.config, password, provider, VaultTree::new()).unwrap()
    }

    async fn create_failing_test_session() -> (VaultSession, Arc<FailingProvider>) {
        let id = VaultId::new("test").unwrap();
        let password = b"test-password";
        let creation = VaultConfig::new(
            id,
            password,
            "memory",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap();
        let provider = Arc::new(FailingProvider::new());
        provider
            .create_dir(&VaultPath::parse("/d").unwrap())
            .await
            .unwrap();
        provider
            .create_dir(&VaultPath::parse("/m").unwrap())
            .await
            .unwrap();
        let session = VaultSession::unlock(
            creation.config,
            password,
            provider.clone(),
            VaultTree::new(),
        )
        .unwrap();
        (session, provider)
    }

    #[tokio::test]
    async fn create_upload_failure_leaves_no_tree_entry() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/not-created.txt").unwrap();
        provider.fail_next_data_upload();

        assert!(ops.create_file(&path, b"secret").await.is_err());
        assert!(!ops.exists(&path).await);
    }

    #[tokio::test]
    async fn update_upload_failure_preserves_metadata_and_content() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/unchanged.txt").unwrap();
        ops.create_file(&path, b"old").await.unwrap();
        let old_metadata = ops.metadata(&path).await.unwrap();
        provider.fail_next_data_upload();

        assert!(ops.update_file(&path, b"new content").await.is_err());
        assert_eq!(ops.metadata(&path).await.unwrap(), old_metadata);
        assert_eq!(ops.read_file(&path).await.unwrap(), b"old");
    }

    #[tokio::test]
    async fn delete_cleanup_failure_does_not_undo_published_removal() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/not-deleted.txt").unwrap();
        ops.create_file(&path, b"old").await.unwrap();
        provider.fail_next_delete();

        ops.delete_file(&path).await.unwrap();
        assert!(!ops.exists(&path).await);
    }

    #[tokio::test]
    async fn create_tree_persistence_failure_keeps_recoverable_orphan() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/rolled-back.txt").unwrap();
        provider.fail_next_tree_upload();

        assert!(ops.create_file(&path, b"secret").await.is_err());
        assert!(!ops.exists(&path).await);
        assert_eq!(
            provider
                .list(&VaultPath::parse("/d").unwrap())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn streamed_create_tree_persistence_failure_keeps_recoverable_orphan() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("source.txt");
        std::fs::write(&source, b"secret").unwrap();
        let path = VaultPath::parse("/rolled-back-stream.txt").unwrap();
        provider.fail_next_tree_upload();

        assert!(ops.create_file_from_path(&path, &source).await.is_err());
        assert!(!ops.exists(&path).await);
        assert_eq!(
            provider
                .list(&VaultPath::parse("/d").unwrap())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn streamed_create_with_unreadable_source_leaves_no_blob() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let path = VaultPath::parse("/missing.txt").unwrap();

        assert!(ops
            .create_file_from_path(&path, temp.path().join("missing.txt"))
            .await
            .is_err());
        assert!(!ops.exists(&path).await);
        assert!(provider
            .list(&VaultPath::parse("/d").unwrap())
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn update_tree_persistence_failure_restores_blob_and_metadata() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/restored.txt").unwrap();
        ops.create_file(&path, b"old").await.unwrap();
        let old_metadata = ops.metadata(&path).await.unwrap();
        provider.fail_next_tree_upload();

        assert!(ops.update_file(&path, b"new content").await.is_err());
        assert_eq!(ops.metadata(&path).await.unwrap(), old_metadata);
        assert_eq!(ops.read_file(&path).await.unwrap(), b"old");
    }

    #[tokio::test]
    async fn delete_tree_persistence_failure_restores_blob_and_tree() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/restored.txt").unwrap();
        ops.create_file(&path, b"old").await.unwrap();
        provider.fail_next_tree_upload();

        assert!(ops.delete_file(&path).await.is_err());
        assert!(ops.exists(&path).await);
        assert_eq!(ops.read_file(&path).await.unwrap(), b"old");
    }

    #[tokio::test]
    async fn directory_tree_persistence_failures_leave_memory_unchanged() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/directory").unwrap();
        provider.fail_next_tree_upload();
        assert!(ops.create_directory(&path).await.is_err());
        assert!(!ops.exists(&path).await);

        ops.create_directory(&path).await.unwrap();
        provider.fail_next_tree_upload();
        assert!(ops.delete_directory(&path).await.is_err());
        assert!(ops.exists(&path).await);
    }

    #[tokio::test]
    async fn test_create_and_read_file() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();

        let path = VaultPath::parse("/test.txt").unwrap();
        let content = b"Hello, encrypted world!";

        ops.create_file(&path, content).await.unwrap();
        let read_content = ops.read_file(&path).await.unwrap();

        assert_eq!(read_content, content);
    }

    #[tokio::test]
    async fn test_update_file() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();

        let path = VaultPath::parse("/test.txt").unwrap();
        ops.create_file(&path, b"initial").await.unwrap();
        ops.update_file(&path, b"updated").await.unwrap();

        let content = ops.read_file(&path).await.unwrap();
        assert_eq!(content, b"updated");
    }

    #[tokio::test]
    async fn legacy_one_shot_file_exports_via_versioned_fallback() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let destination = temp.path().join("legacy.txt");
        let path = VaultPath::parse("/legacy.txt").unwrap();
        ops.create_file(&path, b"legacy content").await.unwrap();

        ops.export_file_to_path(&path, &destination).await.unwrap();

        assert_eq!(std::fs::read(destination).unwrap(), b"legacy content");
    }

    #[tokio::test]
    async fn test_large_file_path_roundtrip_uses_stream_api() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("source.bin");
        let destination = temp.path().join("destination.bin");
        let data = vec![0x5a; 8 * 1024 * 1024];
        std::fs::write(&source, &data).unwrap();
        let path = VaultPath::parse("/large.bin").unwrap();

        ops.create_file_from_path(&path, &source).await.unwrap();
        ops.export_file_to_path(&path, &destination).await.unwrap();

        assert_eq!(std::fs::read(destination).unwrap(), data);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn valid_stream_export_does_not_clobber_existing_destination() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("source.bin");
        let destination = temp.path().join("destination.bin");
        std::fs::write(&source, vec![0x5a; 256 * 1024]).unwrap();
        std::fs::write(&destination, b"existing safe content").unwrap();
        let path = VaultPath::parse("/noclobber.bin").unwrap();
        ops.create_file_from_path(&path, &source).await.unwrap();

        assert!(ops.export_file_to_path(&path, &destination).await.is_err());
        assert_eq!(
            std::fs::read(destination).unwrap(),
            b"existing safe content"
        );
    }

    #[tokio::test]
    async fn tampered_chunk_does_not_publish_partial_plaintext() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("source.bin");
        let destination = temp.path().join("destination.bin");
        std::fs::write(&source, vec![0x5a; 256 * 1024]).unwrap();
        std::fs::write(&destination, b"existing safe content").unwrap();
        let path = VaultPath::parse("/tampered.bin").unwrap();
        ops.create_file_from_path(&path, &source).await.unwrap();

        let data_dir = VaultPath::parse("/d").unwrap();
        let stored = session.provider().list(&data_dir).await.unwrap();
        let stored_path = data_dir.join(&stored[0].name).unwrap();
        let mut ciphertext = session.provider().download(&stored_path).await.unwrap();
        let middle = ciphertext.len() / 2;
        ciphertext[middle] ^= 0x80;
        session
            .provider()
            .upload(&stored_path, ciphertext)
            .await
            .unwrap();

        assert!(ops.export_file_to_path(&path, &destination).await.is_err());
        assert_eq!(
            std::fs::read(destination).unwrap(),
            b"existing safe content"
        );
    }

    /// A streamed file five 64 KiB frames and a bit long, with no two
    /// frames alike.
    async fn streamed_file(ops: &VaultOperations<'_>, path: &VaultPath) -> Vec<u8> {
        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("source.bin");
        let data: Vec<u8> = (0..5 * 64 * 1024 + 1234).map(|i| (i % 251) as u8).collect();
        std::fs::write(&source, &data).unwrap();
        ops.create_file_from_path(path, &source).await.unwrap();
        data
    }

    #[tokio::test]
    async fn range_reads_return_the_window_and_the_full_size() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/large.bin").unwrap();
        let data = streamed_file(&ops, &path).await;
        let size = data.len() as u64;

        for (offset, max_bytes) in [
            (0, 100),
            // Across the first frame boundary, and across two of them.
            (64 * 1024 - 10, 20),
            (64 * 1024 - 1, 64 * 1024 + 2),
            // The tail, and past it.
            (data.len() - 5, 100),
            (0, usize::MAX),
        ] {
            let (bytes, total) = ops
                .read_file_range(&path, offset as u64, max_bytes)
                .await
                .unwrap();
            let end = offset.saturating_add(max_bytes).min(data.len());
            assert_eq!(
                bytes,
                &data[offset..end],
                "offset {offset}, max {max_bytes}"
            );
            assert_eq!(total, size);
        }
        for (offset, max_bytes) in [(size, 10), (size + 1, 10), (0, 0)] {
            let (bytes, total) = ops.read_file_range(&path, offset, max_bytes).await.unwrap();
            assert!(bytes.is_empty());
            assert_eq!(total, size);
        }

        ops.create_file(
            &VaultPath::parse("/small.txt").unwrap(),
            b"one-shot content",
        )
        .await
        .unwrap();
        let (bytes, total) = ops
            .read_file_range(&VaultPath::parse("/small.txt").unwrap(), 3, 5)
            .await
            .unwrap();
        assert_eq!((bytes.as_slice(), total), (&b"-shot"[..], 16));

        ops.create_directory(&VaultPath::parse("/dir").unwrap())
            .await
            .unwrap();
        assert!(ops
            .read_file_range(&VaultPath::parse("/dir").unwrap(), 0, 1)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn range_reads_check_the_whole_ciphertext_against_the_snapshot() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/tampered.bin").unwrap();
        streamed_file(&ops, &path).await;

        // Flip a byte in the last data frame, which a prefix read never
        // decrypts.
        let data_dir = VaultPath::parse("/d").unwrap();
        let stored = session.provider().list(&data_dir).await.unwrap();
        let stored_path = data_dir.join(&stored[0].name).unwrap();
        let mut ciphertext = session.provider().download(&stored_path).await.unwrap();
        let near_end = ciphertext.len() - 200;
        ciphertext[near_end] ^= 0x80;
        session
            .provider()
            .upload(&stored_path, ciphertext)
            .await
            .unwrap();

        let err = ops.read_file_range(&path, 0, 16).await.unwrap_err();
        assert!(err.to_string().contains("authenticated snapshot"), "{err}");
    }

    #[tokio::test]
    async fn range_reads_of_nodes_without_a_digest_verify_the_end_frame() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/old.bin").unwrap();
        let data = streamed_file(&ops, &path).await;
        session
            .tree()
            .write()
            .await
            .get_node_mut(&path)
            .unwrap()
            .metadata
            .content_digest = None;
        let data_dir = VaultPath::parse("/d").unwrap();
        let stored = session.provider().list(&data_dir).await.unwrap();
        let stored_path = data_dir.join(&stored[0].name).unwrap();
        let ciphertext = session.provider().download(&stored_path).await.unwrap();

        let truncated = ciphertext[..ciphertext.len() - 10].to_vec();
        let mut extended = ciphertext.clone();
        extended.extend_from_slice(b"appended");
        for blob in [truncated, extended] {
            session.provider().upload(&stored_path, blob).await.unwrap();
            assert!(ops.read_file(&path).await.is_err());
            assert!(ops.read_file_range(&path, 0, 16).await.is_err());
        }

        session
            .provider()
            .upload(&stored_path, ciphertext)
            .await
            .unwrap();
        let (bytes, _) = ops.read_file_range(&path, 0, 16).await.unwrap();
        assert_eq!(bytes, &data[..16]);
    }

    async fn read_to_end(reader: &mut FileReader) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while let Some(chunk) = reader.next_chunk().await {
            bytes.extend_from_slice(&chunk?);
        }
        Ok(bytes)
    }

    #[tokio::test]
    async fn file_readers_stream_from_an_offset_and_report_tampering() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/large.bin").unwrap();
        let data = streamed_file(&ops, &path).await;

        for offset in [0, 64 * 1024 - 1, data.len() - 5, data.len(), data.len() + 1] {
            let mut reader = ops.open_file_reader(&path, offset as u64).await.unwrap();
            assert_eq!(reader.size(), data.len() as u64);
            let start = offset.min(data.len());
            assert_eq!(read_to_end(&mut reader).await.unwrap(), &data[start..]);
        }

        let data_dir = VaultPath::parse("/d").unwrap();
        let stored = session.provider().list(&data_dir).await.unwrap();
        let stored_path = data_dir.join(&stored[0].name).unwrap();
        let mut ciphertext = session.provider().download(&stored_path).await.unwrap();
        let near_end = ciphertext.len() - 200;
        ciphertext[near_end] ^= 0x80;
        session
            .provider()
            .upload(&stored_path, ciphertext)
            .await
            .unwrap();
        let mut reader = ops.open_file_reader(&path, 0).await.unwrap();
        assert!(read_to_end(&mut reader).await.is_err());

        // Rewritten files use the stream format too.
        ops.update_file(&path, &data[..1000]).await.unwrap();
        let mut reader = ops.open_file_reader(&path, 10).await.unwrap();
        assert_eq!(read_to_end(&mut reader).await.unwrap(), &data[10..1000]);
    }

    #[tokio::test]
    async fn small_file_readers_verify_the_whole_file_up_front() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/small.bin").unwrap();
        let data: Vec<u8> = (0..STREAM_READ_THRESHOLD)
            .map(|i| (i % 251) as u8)
            .collect();
        ops.create_file(&path, b"").await.unwrap();
        ops.update_file(&path, &data).await.unwrap();

        let mut reader = ops.open_file_reader(&path, 100).await.unwrap();
        assert_eq!(reader.size(), data.len() as u64);
        let chunk = reader.next_chunk().await.unwrap().unwrap();
        assert_eq!(chunk.as_slice(), &data[100..]);
        assert!(reader.next_chunk().await.is_none());

        // A truncated blob fails before any of its plaintext is handed out.
        let data_dir = VaultPath::parse("/d").unwrap();
        let stored = session.provider().list(&data_dir).await.unwrap();
        let stored_path = data_dir.join(&stored[0].name).unwrap();
        let mut ciphertext = session.provider().download(&stored_path).await.unwrap();
        ciphertext.truncate(ciphertext.len() - 10);
        session
            .provider()
            .upload(&stored_path, ciphertext)
            .await
            .unwrap();
        assert!(ops.open_file_reader(&path, 0).await.is_err());
    }

    #[tokio::test]
    async fn reads_download_only_the_authenticated_ciphertext_length() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let data = vec![0x42; 4096];
        let one_shot = VaultPath::parse("/one-shot.bin").unwrap();
        ops.create_file(&one_shot, &data).await.unwrap();
        let streamed = VaultPath::parse("/streamed.bin").unwrap();
        ops.create_file(&streamed, b"").await.unwrap();
        ops.update_file(&streamed, &data).await.unwrap();

        // Nonce and tag; header, one data frame and the end frame.
        for (path, expected_len) in [(&one_shot, 4096 + 24 + 16), (&streamed, 5 + 4096 + 2 * 57)] {
            let tree = session.tree().read().await;
            let name = &tree.get_node(path).unwrap().metadata.encrypted_name;
            let blob_path = VaultPath::parse(DATA_DIRNAME).unwrap().join(name).unwrap();
            drop(tree);
            let blob = provider.download(&blob_path).await.unwrap();
            assert_eq!(blob.len(), expected_len);

            let mut oversized = blob.clone();
            oversized.resize(16 * 1024 * 1024, 0);
            provider.serve_data_blob(oversized);
            assert!(matches!(ops.read_file(path).await, Err(Error::Crypto(_))));
            // Cut off within one chunk of the expected length.
            assert!(provider.streamed.load(Ordering::SeqCst) <= expected_len + 4096);
            assert!(ops.open_file_reader(path, 0).await.is_err());
            assert!(provider.streamed.load(Ordering::SeqCst) <= 2 * (expected_len + 4096));

            provider.serve_data_blob(blob[..blob.len() - 1].to_vec());
            assert!(matches!(ops.read_file(path).await, Err(Error::Crypto(_))));

            provider.serve_data_blob(blob);
            assert_eq!(ops.read_file(path).await.unwrap(), data);
        }
    }

    #[tokio::test]
    async fn key_rotation_downloads_only_the_authenticated_ciphertext_length() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/one-shot.bin").unwrap();
        ops.create_file(&path, &[0x42; 4096]).await.unwrap();
        provider.serve_data_blob(vec![0; 16 * 1024 * 1024]);

        let tree = session.tree().read().await.clone();
        let dyn_provider: Arc<dyn StorageProvider> = provider.clone();
        let result = reencrypt_tree(
            &dyn_provider,
            session.master_key().unwrap(),
            &MasterKey::from_bytes([7; 32]),
            &tree,
            &mut Vec::new(),
        )
        .await;
        assert!(matches!(result, Err(Error::Crypto(_))));
        assert!(provider.streamed.load(Ordering::SeqCst) <= 4096 + 24 + 16 + 4096);
    }

    #[tokio::test]
    async fn streamed_reads_require_the_authenticated_ciphertext_length() {
        let (session, provider) = create_failing_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/large.bin").unwrap();
        let data = streamed_file(&ops, &path).await;
        let name = session
            .tree()
            .read()
            .await
            .get_node(&path)
            .unwrap()
            .metadata
            .encrypted_name
            .clone();
        let key = session
            .master_key()
            .unwrap()
            .derive_file_key(name.as_bytes());
        let stream = EncryptingStream::new(key.as_bytes()).unwrap();
        let expected_len = stream.encrypted_len(data.len() as u64) as usize;
        // Validly framed content of the same file, twice as long, as an
        // older version of it or a forged one would be.
        let mut longer = Vec::new();
        stream
            .encrypt_stream(
                &[data.as_slice(), data.as_slice()].concat()[..],
                &mut longer,
            )
            .unwrap();
        // And a shorter one, as an older version would be: a rollback.
        let mut shorter = Vec::new();
        stream
            .encrypt_stream(&data[..data.len() / 2], &mut shorter)
            .unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let destination = temp.path().join("export.bin");

        // Without a digest, the length is all that catches either stream.
        for clear_digest in [false, true] {
            if clear_digest {
                let mut tree = session.tree().write().await;
                tree.get_node_mut(&path).unwrap().metadata.content_digest = None;
            }
            for blob in [&longer, &shorter] {
                provider.serve_data_blob(blob.clone());
                let result = ops.read_file_range(&path, 0, 16).await;
                assert!(matches!(result, Err(Error::Crypto(_))));
                assert!(provider.streamed.load(Ordering::SeqCst) < expected_len + 4096);

                provider.serve_data_blob(blob.clone());
                let mut reader = ops.open_file_reader(&path, 0).await.unwrap();
                let result = read_to_end(&mut reader).await;
                assert!(matches!(result, Err(Error::Crypto(_))));
                assert!(provider.streamed.load(Ordering::SeqCst) < expected_len + 4096);

                provider.serve_data_blob(blob.clone());
                let result = ops.export_file_to_path(&path, &destination).await;
                assert!(matches!(result, Err(Error::Crypto(_))));
                assert!(!destination.exists());
                assert!(provider.streamed.load(Ordering::SeqCst) < expected_len + 4096);

                provider.serve_data_blob(blob.clone());
                let tree = session.tree().read().await.clone();
                let dyn_provider: Arc<dyn StorageProvider> = provider.clone();
                let result = reencrypt_tree(
                    &dyn_provider,
                    session.master_key().unwrap(),
                    &MasterKey::from_bytes([7; 32]),
                    &tree,
                    &mut Vec::new(),
                )
                .await;
                assert!(matches!(result, Err(Error::Crypto(_))));
                assert!(provider.streamed.load(Ordering::SeqCst) < expected_len + 4096);
            }
        }
    }

    #[tokio::test]
    async fn reads_of_every_size_and_version_round_trip() {
        let temp = tempfile::TempDir::new().unwrap();
        let creation = VaultConfig::new(
            VaultId::new("test").unwrap(),
            b"test-password",
            "local",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap();
        // Local files stream in 64 KiB chunks, so reads span chunk edges.
        let provider = Arc::new(axiomvault_storage::LocalProvider::new(temp.path()).unwrap());
        for dir in ["/d", "/m"] {
            provider
                .create_dir(&VaultPath::parse(dir).unwrap())
                .await
                .unwrap();
        }
        let session = VaultSession::unlock(
            creation.config,
            b"test-password",
            provider,
            VaultTree::new(),
        )
        .unwrap();
        let ops = VaultOperations::new(&session).unwrap();
        let threshold = STREAM_READ_THRESHOLD as usize;
        for size in [
            0,
            1,
            4096,
            DEFAULT_CHUNK_SIZE - 1,
            DEFAULT_CHUNK_SIZE,
            DEFAULT_CHUNK_SIZE + 1,
            threshold - 1,
            threshold,
            threshold + 1,
        ] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let one_shot = VaultPath::parse(&format!("/one-shot-{size}")).unwrap();
            ops.create_file(&one_shot, &data).await.unwrap();
            let streamed = VaultPath::parse(&format!("/streamed-{size}")).unwrap();
            ops.create_file(&streamed, b"").await.unwrap();
            ops.update_file(&streamed, &data).await.unwrap();
            for path in [&one_shot, &streamed] {
                assert_eq!(ops.read_file(path).await.unwrap(), data, "{path}");
                let mut reader = ops.open_file_reader(path, 0).await.unwrap();
                assert_eq!(read_to_end(&mut reader).await.unwrap(), data, "{path}");
            }
        }
    }

    #[tokio::test]
    async fn file_writers_replace_content_only_when_finished() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/written.bin").unwrap();
        ops.create_file(&path, b"old").await.unwrap();
        // Spans several write batches, with writes that straddle them.
        let data: Vec<u8> = (0..2 * WRITE_BATCH_SIZE + 200_000)
            .map(|i| (i % 251) as u8)
            .collect();

        let mut writer = ops.open_file_writer(&path).await.unwrap();
        writer.write(&data[..1000]).await.unwrap();
        drop(writer);
        assert_eq!(ops.read_file(&path).await.unwrap(), b"old");

        let mut writer = ops.open_file_writer(&path).await.unwrap();
        for piece in data.chunks(30_000) {
            writer.write(piece).await.unwrap();
        }
        assert_eq!(writer.size(), data.len() as u64);
        ops.finish_file_writer(&path, writer).await.unwrap();
        assert_eq!(ops.read_file(&path).await.unwrap(), data);
        let (_, _, size) = ops.metadata(&path).await.unwrap();
        assert_eq!(size, Some(data.len() as u64));
    }

    #[tokio::test]
    async fn streamed_writes_record_the_digest_of_the_stored_blob() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let imported = VaultPath::parse("/imported.bin").unwrap();
        let data = streamed_file(&ops, &imported).await;
        let written = VaultPath::parse("/written.bin").unwrap();
        let mut writer = ops.create_file_writer(&written).await.unwrap();
        writer.write(&data).await.unwrap();
        ops.finish_file_writer(&written, writer).await.unwrap();

        let data_dir = VaultPath::parse("/d").unwrap();
        let tree = session.tree().read().await;
        for path in [&imported, &written] {
            let metadata = &tree.get_node(path).unwrap().metadata;
            let blob_path = data_dir.join(&metadata.encrypted_name).unwrap();
            let blob = session.provider().download(&blob_path).await.unwrap();
            assert_eq!(metadata.content_digest, Some(digest(&blob)));
        }
    }

    #[tokio::test]
    async fn hashing_streams_cut_short_yield_no_digest() {
        let (sender, receiver) = tokio::sync::mpsc::channel(UPLOAD_CHANNEL_CAPACITY);
        let (mut stream, digest) = HashingStream::new(receiver);
        sender.send(Ok(b"taken".to_vec())).await.unwrap();
        sender.send(Ok(b"left".to_vec())).await.unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap(), b"taken");
        drop(stream);
        assert!(digest.await.is_err());
        assert!(sender.send(Ok(Vec::new())).await.is_err());
    }

    #[tokio::test]
    async fn finishing_a_writer_of_a_deleted_file_removes_its_blob() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();
        let path = VaultPath::parse("/written.bin").unwrap();
        ops.create_file(&path, b"old").await.unwrap();
        let mut writer = ops.open_file_writer(&path).await.unwrap();
        writer.write(b"new").await.unwrap();
        ops.delete_file(&path).await.unwrap();

        assert!(ops.finish_file_writer(&path, writer).await.is_err());
        let blobs = session
            .provider()
            .list(&VaultPath::parse("/d").unwrap())
            .await
            .unwrap();
        assert!(blobs.is_empty());
    }

    #[tokio::test]
    async fn test_delete_file() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();

        let path = VaultPath::parse("/test.txt").unwrap();
        ops.create_file(&path, b"content").await.unwrap();
        assert!(ops.exists(&path).await);

        ops.delete_file(&path).await.unwrap();
        assert!(!ops.exists(&path).await);
    }

    #[tokio::test]
    async fn test_create_directory() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();

        let path = VaultPath::parse("/mydir").unwrap();
        ops.create_directory(&path).await.unwrap();

        let (name, is_dir, _) = ops.metadata(&path).await.unwrap();
        assert_eq!(name, "mydir");
        assert!(is_dir);
    }

    #[tokio::test]
    async fn test_list_directory() {
        let session = create_test_session().await;
        let ops = VaultOperations::new(&session).unwrap();

        ops.create_directory(&VaultPath::parse("/dir").unwrap())
            .await
            .unwrap();
        ops.create_file(&VaultPath::parse("/dir/a.txt").unwrap(), b"a")
            .await
            .unwrap();
        ops.create_file(&VaultPath::parse("/dir/b.txt").unwrap(), b"b")
            .await
            .unwrap();

        let contents = ops
            .list_directory(&VaultPath::parse("/dir").unwrap())
            .await
            .unwrap();
        assert_eq!(contents.len(), 2);
    }
}
