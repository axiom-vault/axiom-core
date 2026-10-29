//! Async client for the agent socket.

use std::path::Path;

use tokio::net::{
    unix::{OwnedReadHalf, OwnedWriteHalf, UCred},
    UnixStream,
};

use crate::protocol::{write_line, AgentError, LineReader, Payload, Request, Response};

/// A failed request: either the socket or the daemon said no.
#[derive(Debug)]
pub enum ClientError {
    /// The daemon could not be reached, or broke the protocol.
    Io(std::io::Error),
    /// The daemon answered with an error.
    Agent(AgentError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "agent socket error: {err}"),
            Self::Agent(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

pub struct AgentClient {
    reader: LineReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    peer: UCred,
}

impl AgentClient {
    pub async fn connect(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        let peer = stream.peer_cred()?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: LineReader::new(reader),
            writer,
            peer,
        })
    }

    /// Credentials of the process that owns the listening socket.
    pub fn peer(&self) -> UCred {
        self.peer
    }

    pub async fn request(&mut self, request: &Request) -> Result<Payload, ClientError> {
        write_line(&mut self.writer, request).await?;
        let line = self.reader.read_line().await?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "agent closed the connection",
            )
        })?;
        let response: Response = serde_json::from_slice(&line).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("malformed agent response: {err}"),
            )
        })?;
        Result::from(response).map_err(ClientError::Agent)
    }
}
