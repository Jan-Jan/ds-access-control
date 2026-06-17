//! Device-to-device transport over iroh QUIC. The peer's authenticated
//! EndpointId is its P2pDeviceKey, so a connection proves device-key custody.

pub mod endpoint;
pub mod wire;

use thiserror::Error;

/// Selects how `OrgEndpoint` is bound and how peers are dialled.
///
/// - `Loopback`: relay disabled, binds on `127.0.0.1`, dials the full
///   `EndpointAddr` embedded in the blob.  Used by offline tests and
///   same-machine demo runs.
/// - `Networked`: uses iroh's `presets::N0` (n0 relay servers + DNS/Pkarr
///   discovery), binds on all interfaces, and dials purely by `EndpointId`
///   so iroh's discovery/relay resolves connectivity.  Required for two
///   laptops over the internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportMode {
    /// Relay disabled; bind loopback; dial by `EndpointAddr`.
    #[default]
    Loopback,
    /// n0 relay + DNS discovery; bind wildcard; dial by `EndpointId`.
    Networked,
}

/// ALPN protocol id for the ODS org-node channel.
pub const ALPN: &[u8] = b"/ods/org-node/1";

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("iroh bind error: {0}")]
    Bind(String),
    #[error("iroh connect error: {0}")]
    Connect(String),
    #[error("iroh accept error: {0}")]
    Accept(String),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("frame too large: {0} bytes (max {max})", max = MAX_FRAME)]
    FrameTooLarge(usize),
    #[error("malformed wire message")]
    Malformed,
}

/// Maximum accepted frame size (defensive cap against a hostile peer).
pub const MAX_FRAME: usize = 1 << 20; // 1 MiB — generous for a delta + secret.
