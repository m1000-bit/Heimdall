//! Error type for the inter-AI transport.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cryptographic error: {0}")]
    Crypto(#[from] heimdall_crypto::Error),

    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error("frame exceeds the {max} byte limit: {actual} bytes")]
    FrameTooLarge { max: usize, actual: usize },

    #[error("connection closed by peer")]
    Closed,

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("replayed frame: sequence {0} was already accepted")]
    Replay(u64),

    #[error("out-of-order frame: expected {expected}, got {actual}")]
    OutOfOrder { expected: u64, actual: u64 },

    #[error("timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error("listener error: {0}")]
    Listener(String),

    #[error("the session is not established yet")]
    NotEstablished,
}
