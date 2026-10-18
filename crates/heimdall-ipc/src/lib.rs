//! # heimdall-ipc
//!
//! The authenticated channel between Heimdall Core and Heimdall Sentinel.
//!
//! Layering, bottom up:
//!
//! | Layer      | Responsibility                                              |
//! |------------|-------------------------------------------------------------|
//! | transport  | Local endpoint (Unix socket / Windows named pipe) with OS-level access control |
//! | frame      | Length-prefixed records whose header is covered by the AEAD tag |
//! | session    | Handshake, directional keys, strict ordering, replay rejection |
//! | message    | Typed, bounded, hand-rolled encoding of the inter-AI vocabulary |
//!
//! Design rules enforced across the crate:
//!
//! * **Nothing is trusted because of where it came from.** The endpoint path is
//!   not a capability; only a pinned Ed25519 identity authenticates a peer.
//! * **Every length is checked before it is used to allocate.**
//! * **The frame type and sequence number are authenticated data**, so they
//!   cannot be rewritten without invalidating the tag.
//! * **Decryption buffers are scrubbed** once a message has been parsed.
//! * **A gap in the sequence terminates the session** rather than being
//!   skipped.

pub mod error;
pub mod frame;
pub mod message;
pub mod session;
pub mod transport;

pub use error::{Error, Result};
pub use message::{CloseReason, ContainmentScope, Message, Severity};
pub use session::{Session, Side};
pub use transport::{Listener, Stream};
