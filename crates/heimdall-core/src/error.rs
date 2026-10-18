pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("transport error: {0}")]
    Ipc(#[from] heimdall_ipc::Error),

    #[error("cryptographic error: {0}")]
    Crypto(#[from] heimdall_crypto::Error),

    #[error("commit gate refused the change: {0}")]
    Gate(#[from] crate::gate::GateError),

    #[error("no Sentinel is listening on the endpoint: {0}")]
    NoSentinel(String),

    #[error("not connected to Sentinel")]
    NotConnected,
}
