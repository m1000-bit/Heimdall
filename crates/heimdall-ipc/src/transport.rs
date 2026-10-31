//! Cross-platform local transport.
//!
//! The two AIs are separate processes on the same host, so the transport is a
//! local IPC endpoint: a Unix domain socket on Linux/macOS and a named pipe on
//! Windows. Neither provides confidentiality, which is why everything above
//! this layer is authenticated and encrypted.
//!
//! Access control is enforced by the OS, not by the application:
//!
//! * Unix: the socket lives in a `0700` directory and the socket itself is
//!   `0600`, so only the owning user can reach it.
//! * Windows: the pipe is created with `first_pipe_instance(true)` and held
//!   continuously, so another local process cannot squat on the name.
//!
//! Holding the endpoint is *never* sufficient to be trusted. Trust comes from
//! the pinned Ed25519 identity verified in `heimdall_crypto::session`.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[cfg(windows)]
use platform::{WindowsListener, bind, endpoint_path};
#[cfg(unix)]
use platform::{bind, endpoint_path};

/// On Windows a stream may be the accepting side (`NamedPipeServer`) or the
/// connecting side (`NamedPipeClient`). Both implement the same async I/O, so
/// they are unified behind one variant.
#[cfg(windows)]
type WindowsStream = platform::WindowsStream;

/// Default endpoint name for the Core -> Sentinel channel.
pub const DEFAULT_ENDPOINT: &str = "heimdall-sentinel";

/// A bidirectional byte stream to the peer, already framed at the [`crate::frame`]
/// level.
#[derive(Debug)]
pub struct Stream {
    inner: Inner,
}

#[derive(Debug)]
enum Inner {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    Windows(WindowsStream),
    /// In-memory pipe. Used by tests and by the loopback mode Sentinel runs in
    /// when it is embedded in the same process as Core during development.
    #[cfg(any(test, feature = "in-memory"))]
    Pipe(tokio::io::DuplexStream),
}

impl Stream {
    /// Connects to a listening peer.
    ///
    /// `async` because connecting to a Unix socket can block; on Windows the
    /// named-pipe open is synchronous, which is why the lint is silenced rather
    /// than the signature being platform-split.
    #[allow(clippy::unused_async)]
    pub async fn connect(endpoint: &str) -> Result<Self> {
        #[cfg(unix)]
        let inner = platform::connect(endpoint).await?;
        #[cfg(windows)]
        let inner = Self::inner_for(endpoint)?;
        Ok(Self { inner })
    }

    /// Creates a connected in-memory pair. Either end reads what the other
    /// writes.
    #[cfg(any(test, feature = "in-memory"))]
    pub fn in_memory_pair(capacity: usize) -> (Self, Self) {
        let (a, b) = tokio::io::duplex(capacity);
        (
            Self {
                inner: Inner::Pipe(a),
            },
            Self {
                inner: Inner::Pipe(b),
            },
        )
    }

    /// Writes one complete frame. Frames are written whole and never
    /// interleaved, so two concurrent senders cannot corrupt each other's
    /// byte stream.
    pub async fn write_frame(&mut self, bytes: &[u8]) -> Result<()> {
        match &mut self.inner {
            #[cfg(unix)]
            Inner::Unix(s) => {
                s.write_all(bytes).await?;
                s.flush().await?;
            }
            #[cfg(windows)]
            Inner::Windows(s) => {
                s.write_all(bytes).await?;
                s.flush().await?;
            }
            #[cfg(any(test, feature = "in-memory"))]
            Inner::Pipe(s) => {
                s.write_all(bytes).await?;
                s.flush().await?;
            }
        }
        Ok(())
    }

    /// Reads exactly one complete frame.
    pub async fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut header = [0u8; crate::frame::HEADER_LEN];
        read_exact(&mut self.inner, &mut header).await?;
        // The decode refuses a length that is not believable, so the
        // allocation below is bounded by the frame limit and not by whatever
        // the peer claimed. A header is eighteen bytes; without that check
        // it could ask for four gigabytes.
        let parsed = crate::frame::Header::decode(&header)?;

        let mut body = vec![0u8; parsed.ciphertext_len as usize];
        read_exact(&mut self.inner, &mut body).await?;

        let mut out = Vec::with_capacity(crate::frame::HEADER_LEN + body.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Accepts inbound connections on an endpoint.
#[derive(Debug)]
pub struct Listener {
    inner: InnerListener,
    path: PathBuf,
}

#[derive(Debug)]
enum InnerListener {
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    #[cfg(windows)]
    Windows(WindowsListener),
}

impl Listener {
    /// Binds the endpoint. On Unix a stale socket file from a crashed run is
    /// removed first, otherwise bind fails with `EADDRINUSE` even though
    /// nothing is listening.
    pub async fn bind(endpoint: &str) -> Result<Self> {
        let path = endpoint_path(endpoint);
        let inner = bind(endpoint).await?;
        Ok(Self { inner, path })
    }

    /// Waits for the next peer to connect.
    pub async fn accept(&mut self) -> Result<Stream> {
        let inner = match &mut self.inner {
            #[cfg(unix)]
            InnerListener::Unix(l) => Inner::Unix(l.accept().await?.0),
            #[cfg(windows)]
            InnerListener::Windows(l) => l.accept().await?,
        };
        Ok(Stream { inner })
    }

    pub fn endpoint_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Leave no endpoint behind: a stale socket would let a later run appear
        // to be serving when it is not.
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn read_exact(stream: &mut Inner, buf: &mut [u8]) -> Result<()> {
    match stream {
        #[cfg(unix)]
        Inner::Unix(s) => {
            s.read_exact(buf).await.map_err(map_io)?;
        }
        #[cfg(windows)]
        Inner::Windows(s) => {
            s.read_exact(buf).await.map_err(map_io)?;
        }
        #[cfg(any(test, feature = "in-memory"))]
        Inner::Pipe(s) => {
            s.read_exact(buf).await.map_err(map_io)?;
        }
    }
    Ok(())
}

fn map_io(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe => Error::Closed,
        _ => Error::Io(e),
    }
}

#[cfg(unix)]
mod platform {
    use super::{Error, Result};
    use std::path::PathBuf;
    use tokio::net::{UnixListener, UnixStream};

    /// `$XDG_RUNTIME_DIR` when usable, otherwise a per-user directory under the
    /// temp dir. Falling back to a shared world-writable directory would let
    /// another local account pre-create the socket and impersonate Sentinel.
    ///
    /// An endpoint that starts with a path separator is a path, not a name, and
    /// is used as it stands. A deployment needs this: the daemon may run as a
    /// service account whose runtime directory is not the one an operator's
    /// session uses, and the two have to be pointed at the same socket.
    pub(super) fn endpoint_path(endpoint: &str) -> PathBuf {
        if endpoint.starts_with('/') {
            return PathBuf::from(endpoint);
        }
        if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
            if !dir.is_empty() {
                return PathBuf::from(dir).join(format!("{endpoint}.sock"));
            }
        }
        std::env::temp_dir()
            .join(format!("heimdall-{}", user_key()))
            .join(format!("{endpoint}.sock"))
    }

    fn user_key() -> String {
        #[cfg(target_os = "linux")]
        if let Ok(s) = std::fs::read_to_string("/proc/self/loginuid") {
            let s = s.trim();
            if !s.is_empty() && s != "4294967295" {
                return s.to_string();
            }
        }
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "default".into())
    }

    /// The permissions the endpoint and the directory holding it are given.
    ///
    /// 0600 and 0700 by default: only the account the daemon runs as can
    /// reach the socket. A deployment that runs the daemon as a service
    /// account and the operator's tools as another account needs the two in
    /// the same group, and can say so with `$HEIMDALL_SOCKET_MODE=660`. The
    /// mode is applied to the socket and to the directory around it, so
    /// loosening the socket without loosening the way in achieves nothing.
    fn endpoint_modes() -> (u32, u32) {
        let requested = std::env::var("HEIMDALL_SOCKET_MODE").ok();
        socket_modes(requested.as_deref())
    }

    /// The modes for a requested mode, or the private ones when there is none.
    pub(crate) fn socket_modes(requested: Option<&str>) -> (u32, u32) {
        const DEFAULT_SOCKET: u32 = 0o600;
        const DEFAULT_DIR: u32 = 0o700;
        let Some(text) = requested else {
            return (DEFAULT_SOCKET, DEFAULT_DIR);
        };
        match u32::from_str_radix(text.trim(), 8) {
            Ok(mode) if (1..=0o777).contains(&mode) => {
                let socket = mode & 0o777;
                (socket, (mode | 0o100) & 0o777)
            }
            // An unusable mode falls back to the safe one rather than to
            // something permissive.
            _ => (DEFAULT_SOCKET, DEFAULT_DIR),
        }
    }

    pub(super) async fn bind(endpoint: &str) -> Result<super::InnerListener> {
        use std::os::unix::fs::PermissionsExt as _;

        let path = endpoint_path(endpoint);
        let (socket_mode, dir_mode) = endpoint_modes();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            // 0700 by default: nobody but the owning user can traverse into
            // this directory.
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(dir_mode))?;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::Listener(format!(
                    "cannot clear stale endpoint {}: {e}",
                    path.display()
                )));
            }
        }

        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(socket_mode))?;
        Ok(super::InnerListener::Unix(listener))
    }

    pub(super) async fn connect(endpoint: &str) -> Result<super::Inner> {
        let path = endpoint_path(endpoint);
        Ok(super::Inner::Unix(UnixStream::connect(&path).await?))
    }
}

#[cfg(windows)]
mod platform {
    use super::{Error, Result};
    use std::path::PathBuf;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };

    pub(super) fn endpoint_path(endpoint: &str) -> PathBuf {
        PathBuf::from(format!(r"\\.\pipe\{endpoint}"))
    }

    /// Keeps two pipe instances alive at all times: one being served, one spare.
    ///
    /// A named pipe exists only while a handle to it is open. If the listener
    /// dropped its handle between accepting connections, another local process
    /// could create the same name and become the peer Core trusts by path.
    #[derive(Debug)]
    pub(super) struct WindowsListener {
        name: PathBuf,
        spare: NamedPipeServer,
    }

    impl WindowsListener {
        pub(super) async fn bind(endpoint: &str) -> Result<super::InnerListener> {
            let name = endpoint_path(endpoint);

            let first = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&name)
                .map_err(|e| {
                    Error::Listener(format!("cannot create pipe {}: {e}", name.display()))
                })?;
            let spare = ServerOptions::new().create(&name).map_err(|e| {
                Error::Listener(format!("cannot reserve pipe {}: {e}", name.display()))
            })?;

            // Block until the first peer shows up, exactly as `accept` would.
            first.connect().await?;

            Ok(super::InnerListener::Windows(Self { name, spare }))
        }

        pub(super) async fn accept(&mut self) -> Result<super::Inner> {
            // Create the replacement before handing this instance out, so the
            // name is never unclaimed.
            let replacement = ServerOptions::new().create(&self.name).map_err(|e| {
                Error::Listener(format!("cannot re-arm pipe {}: {e}", self.name.display()))
            })?;
            let current = std::mem::replace(&mut self.spare, replacement);

            current.connect().await?;
            Ok(super::Inner::Windows(current.into()))
        }
    }

    /// Accepting side or connecting side of a Windows named pipe.
    #[derive(Debug)]
    pub(super) enum WindowsStream {
        Server(NamedPipeServer),
        Client(NamedPipeClient),
    }

    impl From<NamedPipeServer> for WindowsStream {
        fn from(s: NamedPipeServer) -> Self {
            Self::Server(s)
        }
    }

    impl From<NamedPipeClient> for WindowsStream {
        fn from(c: NamedPipeClient) -> Self {
            Self::Client(c)
        }
    }

    // The two pipe handles behave identically once connected, so the async I/O
    // traits are forwarded rather than duplicated for each variant.
    impl AsyncRead for WindowsStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.get_mut() {
                Self::Server(s) => std::pin::Pin::new(s).poll_read(cx, buf),
                Self::Client(c) => std::pin::Pin::new(c).poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for WindowsStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            match self.get_mut() {
                Self::Server(s) => std::pin::Pin::new(s).poll_write(cx, buf),
                Self::Client(c) => std::pin::Pin::new(c).poll_write(cx, buf),
            }
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.get_mut() {
                Self::Server(s) => std::pin::Pin::new(s).poll_flush(cx),
                Self::Client(c) => std::pin::Pin::new(c).poll_flush(cx),
            }
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.get_mut() {
                Self::Server(s) => std::pin::Pin::new(s).poll_shutdown(cx),
                Self::Client(c) => std::pin::Pin::new(c).poll_shutdown(cx),
            }
        }
    }

    pub(super) async fn bind(endpoint: &str) -> Result<super::InnerListener> {
        WindowsListener::bind(endpoint).await
    }

    pub(super) fn connect(endpoint: &str) -> Result<super::Inner> {
        let name = endpoint_path(endpoint);
        let s = ClientOptions::new()
            .open(&name)
            .map_err(|e| Error::Listener(format!("cannot open pipe {}: {e}", name.display())))?;
        Ok(super::Inner::Windows(s.into()))
    }
}

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

impl Inner {
    #[cfg(windows)]
    fn from_client(endpoint: &str) -> Result<Self> {
        platform::connect(endpoint)
    }
}

#[cfg(windows)]
impl Stream {
    fn inner_for(endpoint: &str) -> Result<Inner> {
        Inner::from_client(endpoint)
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::platform::{endpoint_path, socket_modes};

    #[test]
    fn an_absolute_endpoint_is_a_path() {
        assert_eq!(
            endpoint_path("/run/heimdall/heimdall-sentinel.sock"),
            std::path::PathBuf::from("/run/heimdall/heimdall-sentinel.sock")
        );
    }

    #[test]
    fn a_named_endpoint_is_not_a_path() {
        let path = endpoint_path("heimdall-sentinel");
        assert!(path.ends_with("heimdall-sentinel.sock"));
        // A named endpoint is resolved against XDG_RUNTIME_DIR on Unix, so it
        // is an absolute path. What matters is that it is not taken as a
        // path the user typed verbatim -- the name itself is preserved as
        // the final component.
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            "heimdall-sentinel.sock"
        );
    }

    #[test]
    fn the_socket_is_private_by_default() {
        let (socket, dir) = socket_modes(None);
        assert_eq!(socket, 0o600);
        assert_eq!(dir, 0o700);
    }

    #[test]
    fn a_group_mode_opens_the_way_in_to_the_group() {
        let (socket, dir) = socket_modes(Some("660"));
        assert_eq!(socket, 0o660);
        assert_eq!(dir, 0o760);
    }

    #[test]
    fn an_unusable_mode_falls_back_to_the_private_one() {
        for bad in ["", "  ", "rwx", "9999", "0777x"] {
            let (socket, dir) = socket_modes(Some(bad));
            assert_eq!(socket, 0o600, "{bad:?} was not refused");
            assert_eq!(dir, 0o700, "{bad:?} was not refused");
        }
    }
}
