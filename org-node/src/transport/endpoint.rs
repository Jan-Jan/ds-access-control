//! OrgEndpoint: an iroh endpoint whose EndpointId is the device's P2pDeviceKey.
//!
//! The QUIC handshake authenticates the remote endpoint's ed25519 key, so
//! `recv_one` returns the CRYPTOGRAPHICALLY AUTHENTICATED remote `P2pDeviceKey`.
//! The caller is responsible for cross-checking that key against the members trie.
use iroh::{
    EndpointAddr, EndpointId, RelayMode, TransportAddr,
    endpoint::{Connection, presets},
};
use org_members::P2pDeviceKey;

use crate::keys::SigningKeypair;
use crate::transport::{
    ALPN, MAX_FRAME, TransportError, TransportMode,
    wire::{WireMessage, decode_body, encode_frame},
};

/// An iroh endpoint bound to a device's ed25519 key.
///
/// Its `EndpointId` equals the device's `P2pDeviceKey`, so successfully
/// completing the QUIC handshake proves device-secret custody.
pub struct OrgEndpoint {
    inner: iroh::Endpoint,
    device_key: P2pDeviceKey,
}

impl OrgEndpoint {
    /// Bind an endpoint using `device`'s ed25519 seed as the iroh identity.
    ///
    /// Equivalent to `bind_with_mode(device, TransportMode::Loopback)`.
    ///
    /// Binds to `127.0.0.1:0` (random loopback port) with relay disabled and
    /// no discovery service configured.  Binding to `localhost` rather than the
    /// wildcard (`0.0.0.0`) ensures [`node_addr_for_dial`] returns a real,
    /// dialable socket address immediately after bind — the wildcard address
    /// is not dialable by a peer.
    ///
    /// Existing call sites (tests) are unaffected — they continue to get the
    /// loopback/offline behaviour.
    ///
    /// [`node_addr_for_dial`]: OrgEndpoint::node_addr_for_dial
    pub async fn bind(device: &SigningKeypair) -> Result<Self, TransportError> {
        Self::bind_with_mode(device, TransportMode::Loopback).await
    }

    /// Bind an endpoint with an explicit [`TransportMode`].
    ///
    /// - [`TransportMode::Loopback`]: relay disabled, binds on `127.0.0.1`.
    ///   Used by offline tests and same-machine demo runs. Identical to the
    ///   legacy `bind()` behaviour.
    /// - [`TransportMode::Networked`]: uses `presets::N0` (n0 relay servers +
    ///   DNS/Pkarr address discovery).  Binds on all interfaces (default iroh
    ///   bind).  Required for two laptops communicating across the internet.
    pub async fn bind_with_mode(
        device: &SigningKeypair,
        mode: TransportMode,
    ) -> Result<Self, TransportError> {
        let sk = iroh::SecretKey::from_bytes(&device.to_seed());
        let inner = match mode {
            TransportMode::Loopback => iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .secret_key(sk)
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await
                .map_err(|e| TransportError::Bind(e.to_string()))?,
            TransportMode::Networked => {
                // presets::N0 configures:
                //   - n0's relay servers (RelayMode::Default via default_relay_mode())
                //   - PkarrPublisher to iroh.link (publishes this node's address)
                //   - DnsAddressLookup via iroh.link (resolves peer EndpointIds)
                // Together these allow two endpoints on different networks to find
                // each other purely by EndpointId.
                iroh::Endpoint::builder(presets::N0)
                    .secret_key(sk)
                    .alpns(vec![ALPN.to_vec()])
                    .bind()
                    .await
                    .map_err(|e| TransportError::Bind(e.to_string()))?
            }
        };
        Ok(Self {
            inner,
            device_key: device.device_key(),
        })
    }

    /// This endpoint's device key (equal to its iroh `EndpointId`).
    pub fn device_key(&self) -> P2pDeviceKey {
        self.device_key
    }

    /// The dialable address (EndpointId + current direct bound socket addresses).
    ///
    /// Built from [`iroh::Endpoint::id`] plus the UDP sockets returned by
    /// [`iroh::Endpoint::bound_sockets`].  This is reliable for loopback/LAN
    /// connections immediately after [`bind`] — `Endpoint::addr()` relies on
    /// async network-path discovery, which may not have run yet.
    ///
    /// Use this for out-of-band address exchange before calling [`send`].
    ///
    /// [`bind`]: OrgEndpoint::bind
    /// [`send`]: OrgEndpoint::send
    pub fn node_addr_for_dial(&self) -> EndpointAddr {
        EndpointAddr::from_parts(
            self.inner.id(),
            self.inner
                .bound_sockets()
                .into_iter()
                .map(TransportAddr::Ip),
        )
    }

    /// Access the raw iroh `Endpoint` (for tests / advanced callers).
    pub fn inner(&self) -> &iroh::Endpoint {
        &self.inner
    }

    /// Dial `peer` by its full `EndpointAddr`, open a bidirectional stream, and
    /// send one framed [`WireMessage`].
    ///
    /// Used in [`TransportMode::Loopback`]: the `EndpointAddr` carries explicit
    /// socket addresses (from the out-of-band blob exchange) so iroh can connect
    /// without discovery.
    ///
    /// Waits for the send stream to be fully flushed before returning.  The
    /// connection is then explicitly closed (code 0) so the remote's
    /// `Connection::closed()` resolves promptly.
    pub async fn send(
        &self,
        peer: impl Into<EndpointAddr>,
        msg: &WireMessage,
    ) -> Result<(), TransportError> {
        self.send_conn(peer.into(), msg).await
    }

    /// Dial `peer` purely by its `EndpointId` (for [`TransportMode::Networked`]).
    ///
    /// `EndpointId` implements `Into<EndpointAddr>`, so iroh will attempt to
    /// resolve the peer's current address via the configured address-lookup
    /// services (Pkarr DNS) and relay through n0's relay servers if no direct
    /// path is available.  This works across NATs and firewalls as long as both
    /// endpoints have reached the relay.
    pub async fn send_to_id(
        &self,
        peer_id: EndpointId,
        msg: &WireMessage,
    ) -> Result<(), TransportError> {
        self.send_conn(peer_id.into(), msg).await
    }

    /// Shared send implementation — connects to `addr`, writes the message,
    /// and closes the connection.
    async fn send_conn(
        &self,
        addr: EndpointAddr,
        msg: &WireMessage,
    ) -> Result<(), TransportError> {
        let conn = self
            .inner
            .connect(addr, ALPN)
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        let (mut send, _recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        let framed = encode_frame(msg)?;
        send.write_all(&framed)
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        send.finish()
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        // stopped() returns once the peer has acknowledged receipt of all sent
        // data (after our finish()), so the message is delivered before we close.
        send.stopped()
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        // Signal QUIC CONNECTION_CLOSE so the remote's conn.closed() resolves.
        conn.close(0u32.into(), b"done");
        Ok(())
    }

    /// Accept one inbound connection, read one framed [`WireMessage`], and
    /// return it together with the AUTHENTICATED remote device key.
    ///
    /// The remote key is extracted from the TLS certificate presented during
    /// the QUIC handshake — it is cryptographically bound to the peer's secret.
    pub async fn recv_one(&self) -> Result<(P2pDeviceKey, WireMessage), TransportError> {
        let incoming = self
            .inner
            .accept()
            .await
            .ok_or_else(|| TransportError::Accept("endpoint closed".into()))?;
        let conn: Connection = incoming
            .await
            .map_err(|e| TransportError::Accept(e.to_string()))?;
        let remote_id: EndpointId = conn.remote_id();
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(remote_id.as_bytes())
            .map_err(|_| TransportError::Malformed)?;
        let remote_key = P2pDeviceKey::new(verifying);

        let (_send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        // read_to_end gives the entire stream; strip the 4-byte length prefix
        // that encode_frame prepended (kept for framing-level forward compat).
        let raw = recv
            .read_to_end(MAX_FRAME + 4)
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        let payload = if raw.len() >= 4 { &raw[4..] } else { &raw[..] };
        let msg = decode_body(payload)?;
        Ok((remote_key, msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKeypair;

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn endpoint_id_equals_device_key() {
        let device = SigningKeypair::from_seed([7u8; 32]);
        let ep = OrgEndpoint::bind(&device).await.unwrap();
        // The iroh EndpointId bytes must equal the device key bytes.
        assert_eq!(ep.inner().id().as_bytes(), device.device_key().as_bytes());
        assert_eq!(ep.device_key().as_bytes(), device.device_key().as_bytes());
    }
}
