# ODS Phase 2.3 — `org-node` iroh transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give `org-node` a real device-to-device transport over **iroh** QUIC, where each device's `NodeId` (iroh `EndpointId`) **is** its `P2pDeviceKey` — so connecting to a peer cryptographically proves they hold that device's secret. Over the authenticated channel, deliver a `SignedDeltaEnvelope` (and the org secret on admission). Prove it with a two-node test that delivers an admit envelope and verifies it.

**Architecture:** All transport code is behind a new `transport` cargo feature (like `chain`), so the 2.1 core stays dependency-light. The transport surfaces the **authenticated** remote `P2pDeviceKey` from each connection (iroh's QUIC handshake authenticates the ed25519 endpoint key); org-node's higher logic cross-checks that key against the members trie. The two-node integration test wires transport → authentication → `verify_envelope_against_chain` against a `MockChain` (offline, fast) — the real-chain verify path is already proven by Phase 2.2's e2e, so this phase does NOT depend on the network.

**Tech Stack:** Rust 2021, `iroh` 1.x (QUIC P2P dialed by public key), `tokio`, `postcard` (wire framing), `org-node` 2.1 core (`SignedDeltaEnvelope`, `verify_envelope_against_chain`, `SigningKeypair`, `MockChain`).

**Spec:** [`docs/superpowers/specs/2026-06-15-ods-phase-2-poc-design.md`](../specs/2026-06-15-ods-phase-2-poc-design.md) §5.3 (iroh channel authentication, `NodeId = P2pDeviceKey`), §6 stories 2–4 (key exchange → A pushes envelope+secret → B verifies), §7 S3 (iroh is a transport stand-in).

---

## ⚠️ VERSION PIN: iroh 0.98.2 (NOT 1.0)

iroh 1.0 requires `ed25519-dalek 3.0.0-rc.0`, which conflicts with the workspace's
existing `spike-p2panda` → `p2panda-net` (pins `ed25519-dalek 3.0.0-pre.6`). So
**`org-node` pins `iroh = "0.98"` (resolves 0.98.2)**, which is lock-compatible.
The 0.98 API is the predecessor of the 1.0 surface below — apply this naming map
and verify exact signatures against **docs.rs/iroh/0.98.2** (or `cargo doc -p iroh`):

| 1.0 (below)            | 0.98.2 (USE THIS)                  |
|------------------------|------------------------------------|
| `EndpointId`           | `NodeId`                           |
| `EndpointAddr`         | `NodeAddr`                         |
| `Endpoint::builder(preset)` | `Endpoint::builder()` (no preset arg) |
| `endpoint.id()`        | `endpoint.node_id()`               |
| `endpoint.addr()`      | `endpoint.node_addr().await` (async; returns `Result<NodeAddr>`) — or build a `NodeAddr` from `node_id()` + `bound_sockets()` |
| `Connection::remote_id()` | `Connection::remote_node_id() -> Result<NodeId, _>` |

Identity bridge (unchanged): iroh's `SecretKey::from_bytes(&[u8;32])` from the
device seed; `NodeId`/`PublicKey` is the 32-byte ed25519 key; convert to/from
org-node's `P2pDeviceKey` via raw bytes (`.as_bytes()`/`from_bytes`) — the two
`ed25519-dalek` major versions never meet at the type level. For a local/loopback
connect, disable relay/discovery (`.relay_mode(iroh::RelayMode::Disabled)` on the
builder — CONFIRM) and dial a `NodeAddr` carrying the peer's direct `bound_sockets()`.

## iroh 1.0 API reference (translate to 0.98 per the map above; confirm flagged items)

- `iroh::SecretKey::from_bytes(&[u8; 32]) -> SecretKey`; `.public() -> PublicKey`; `.to_bytes() -> [u8;32]`. `PublicKey`/`EndpointId` is the 32-byte ed25519 key.
- `iroh::Endpoint::builder(preset: impl Preset) -> Builder` (use `iroh::endpoint::presets::N0` or equivalent default preset — **confirm the exact preset path**); `.secret_key(SecretKey)`, `.alpns(Vec<Vec<u8>>)`, `.bind().await -> Result<Endpoint, BindError>`.
- `Endpoint::connect(impl Into<EndpointAddr>, alpn: &[u8]) -> Result<Connection, ConnectError>` (async).
- `Endpoint::accept() -> Accept<'_>` (await → `Option<Incoming>`; await the `Incoming` → `Result<Connection>`). Double-await pattern.
- `Endpoint::id() -> EndpointId`, `Endpoint::addr() -> EndpointAddr`, `Endpoint::bound_sockets() -> Vec<SocketAddr>`.
- `Connection::remote_id() -> EndpointId` (authenticated; infallible in the normal handshake-completed state).
- `Connection::open_bi() -> OpenBi` / `accept_bi() -> AcceptBi` → `(SendStream, RecvStream)`.
- **Confirm against docs:** `SendStream::write_all(&[u8])`, `SendStream::finish()`, `RecvStream::read_to_end(max: usize) -> Result<Vec<u8>>` (quinn-style; exact names/return types may differ slightly in iroh 1.x).
- **Confirm against docs:** how to build an `EndpointAddr` from an `EndpointId` + direct `SocketAddr`s (for a LAN/loopback connect without relay/discovery) — likely `EndpointAddr::from(id)` then `.with_direct_addresses(addrs)`, or `EndpointAddr::new(id)`. For the two-node test, the simplest robust path is to pass the peer's full `endpoint.addr()` (which already includes direct loopback addresses) — do that rather than hand-building from a bare id.
- `EndpointId`/`PublicKey` → 32 bytes: confirm the accessor (`.as_bytes() -> &[u8;32]` or `.to_bytes()`), needed to compare against `P2pDeviceKey::as_bytes()`.

> iroh 1.0 is very new and renamed `NodeId→EndpointId`, `NodeAddr→EndpointAddr`. Where this plan's API guesses are flagged "confirm", the implementer MUST check the exact signature on docs.rs/iroh/1.x (or `cargo doc`) before finalising — do not invent. The DESIGN (framing, auth check, tests) below is fixed; only the iroh call spellings may need adjustment.

---

## File structure

```
org-node/
  Cargo.toml                 # + [feature] transport; + iroh, tokio (feature-gated)
  src/
    lib.rs                   # + #[cfg(feature="transport")] pub mod transport;
    transport/
      mod.rs                 # re-exports; TransportError; ALPN const
      wire.rs                # WireMessage + length-prefixed postcard framing (pure, tested)
      endpoint.rs            # OrgEndpoint: bind (NodeId = device key), send, recv_one
  tests/
    transport_handshake.rs   # NEW (gated): two-node deliver-envelope + authenticate + verify(MockChain)
```

`transport/wire.rs` is pure and unit-tested (framing round-trip). `endpoint.rs` needs a tokio runtime but binds to loopback (no internet) — a unit test can bind and assert identity. The full deliver/authenticate/verify path is the integration test.

---

## Task 0: Add the `transport` feature and deps

**Files:**
- Modify: `org-node/Cargo.toml`
- Modify: `org-node/src/lib.rs`

- [ ] **Step 1: Add feature + deps**

```toml
[features]
# ... existing default / chain ...
# Device-to-device transport over iroh QUIC (NodeId = P2pDeviceKey).
transport = ["dep:iroh", "dep:tokio", "dep:postcard"]
```

In `[dependencies]` (postcard is already present as a normal dep from 2.1 — reuse it; only add iroh/tokio as optional if not already):

```toml
iroh = { version = "1", optional = true }
# tokio is already optional (added for `chain`); ensure the `transport` feature
# enables it. If tokio is listed only under `chain`, change its entry to be
# shared and have BOTH features depend on "dep:tokio".
```

> If `tokio` is already an optional dep used by `chain`, do NOT duplicate it — just add `"dep:tokio"` to the `transport` feature list. Confirm `postcard` is a normal (non-optional) dep already (it is, from Phase 2.1); if so, drop `dep:postcard` from the feature list.

- [ ] **Step 2: Wire the module**

In `lib.rs`:
```rust
#[cfg(feature = "transport")]
pub mod transport;
```

- [ ] **Step 3: Verify both old and new feature sets build**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node` (core).
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node --features transport` (pulls iroh — SLOW first time, let it finish).
Expected: both compile. (`transport/` modules don't exist yet — comment the `pub mod transport;` until Task 1 creates `mod.rs`, or create an empty `transport/mod.rs` now.)

- [ ] **Step 4: Commit**

```bash
git add org-node/Cargo.toml org-node/src/lib.rs
git commit -m "feat(org-node): add feature-gated transport deps (iroh)"
```

---

## Task 1: `WireMessage` + length-prefixed framing (pure, tested)

**Files:**
- Create: `org-node/src/transport/mod.rs`
- Create: `org-node/src/transport/wire.rs`

- [ ] **Step 1: Module root**

`org-node/src/transport/mod.rs`:
```rust
//! Device-to-device transport over iroh QUIC. The peer's authenticated
//! EndpointId is its P2pDeviceKey, so a connection proves device-key custody.
#![cfg(feature = "transport")]

pub mod endpoint;
pub mod wire;

use thiserror::Error;

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
```

- [ ] **Step 2: Write the failing test + `WireMessage` + framing**

`org-node/src/transport/wire.rs`:
```rust
//! The wire payload exchanged over the channel, with length-prefixed framing.
use serde::{Deserialize, Serialize};

use crate::envelope::SignedDeltaEnvelope;
use crate::transport::{TransportError, MAX_FRAME};

/// One message over the org-node channel: a signed delta, plus (on admission)
/// the org secret key handed to a newly verified member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessage {
    pub envelope: SignedDeltaEnvelope,
    pub org_secret: Option<[u8; 32]>,
}

/// Encode a WireMessage as `len(u32 LE) ‖ postcard(msg)`.
pub fn encode_frame(msg: &WireMessage) -> Result<Vec<u8>, TransportError> {
    let body = postcard::to_allocvec(msg).map_err(|_| TransportError::Malformed)?;
    if body.len() > MAX_FRAME {
        return Err(TransportError::FrameTooLarge(body.len()));
    }
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
    framed.extend_from_slice(&body);
    Ok(framed)
}

/// Decode the postcard body (already de-framed) into a WireMessage.
pub fn decode_body(body: &[u8]) -> Result<WireMessage, TransportError> {
    if body.len() > MAX_FRAME {
        return Err(TransportError::FrameTooLarge(body.len()));
    }
    postcard::from_bytes(body).map_err(|_| TransportError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKeypair;
    use crate::ids::OrgId;
    use crate::test_fixtures::admit_member_delta;

    fn sample_msg() -> WireMessage {
        let admin = SigningKeypair::from_seed([1u8; 32]);
        let (delta, _) = admit_member_delta(&admin);
        let env = SignedDeltaEnvelope::build(OrgId::new([5u8; 20]), 2, &delta, &admin).unwrap();
        WireMessage { envelope: env, org_secret: Some([9u8; 32]) }
    }

    #[test]
    fn frame_round_trips() {
        let msg = sample_msg();
        let framed = encode_frame(&msg).unwrap();
        // strip the 4-byte length prefix
        let len = u32::from_le_bytes(framed[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, framed.len() - 4);
        let back = decode_body(&framed[4..]).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn oversize_body_is_rejected() {
        // A body claiming > MAX_FRAME must be rejected by decode_body.
        let big = vec![0u8; MAX_FRAME + 1];
        assert!(matches!(decode_body(&big), Err(TransportError::FrameTooLarge(_))));
    }
}
```

> `WireMessage` needs `SignedDeltaEnvelope: Serialize + Deserialize + PartialEq + Eq` — it has all four (Phase 2.1). `test_fixtures` is `#[cfg(test)]`; these tests are in the lib so they can use it.

- [ ] **Step 3: Run the framing tests**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features transport --lib transport::wire::`
Expected: 2 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add org-node/src/transport/mod.rs org-node/src/transport/wire.rs org-node/src/lib.rs
git commit -m "feat(org-node): transport WireMessage + length-prefixed framing"
```

---

## Task 2: `OrgEndpoint::bind` — identity (NodeId = device key)

**Files:**
- Create: `org-node/src/transport/endpoint.rs`

- [ ] **Step 1: Write `bind` + identity accessors**

```rust
//! OrgEndpoint: an iroh endpoint whose EndpointId is a device's P2pDeviceKey.
use iroh::{Endpoint, SecretKey};
use org_members::P2pDeviceKey;

use crate::keys::SigningKeypair;
use crate::transport::{TransportError, ALPN};

/// An iroh endpoint bound to a device's ed25519 key. Its EndpointId equals the
/// device's P2pDeviceKey, so dialing it proves device-secret custody.
pub struct OrgEndpoint {
    inner: Endpoint,
    device_key: P2pDeviceKey,
}

impl OrgEndpoint {
    /// Bind an endpoint using `device`'s ed25519 secret as the iroh identity.
    pub async fn bind(device: &SigningKeypair) -> Result<Self, TransportError> {
        let sk = SecretKey::from_bytes(&device.to_seed());
        // CONFIRM preset path against docs.rs/iroh/1.x (e.g. iroh::endpoint::presets::N0).
        let inner = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(sk)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| TransportError::Bind(e.to_string()))?;
        Ok(Self { inner, device_key: device.device_key() })
    }

    /// This endpoint's device key (== its iroh EndpointId).
    pub fn device_key(&self) -> P2pDeviceKey {
        self.device_key
    }

    /// The dialable address (id + direct addresses) for out-of-band exchange.
    pub fn addr(&self) -> iroh::EndpointAddr {
        self.inner.addr()
    }

    /// Access the raw iroh endpoint (for advanced callers / tests).
    pub fn inner(&self) -> &Endpoint {
        &self.inner
    }
}
```

- [ ] **Step 2: Write an identity test (binds to loopback, no internet)**

Append:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn endpoint_id_equals_device_key() {
        let device = SigningKeypair::from_seed([7u8; 32]);
        let ep = OrgEndpoint::bind(&device).await.unwrap();
        // iroh EndpointId bytes must equal the device key bytes.
        // CONFIRM the EndpointId->bytes accessor (.as_bytes()/.to_bytes()).
        assert_eq!(ep.inner().id().as_bytes(), device.device_key().as_bytes());
        assert_eq!(ep.device_key().as_bytes(), device.device_key().as_bytes());
    }
}
```

> This test needs `#[tokio::test]` — `tokio` with the `macros` + `rt` features must be available under `--features transport` (it is, shared from `chain`; if `chain`'s tokio features don't include `macros`/`rt-multi-thread`, the dev-dependency `tokio` from Phase 2.2 provides them for tests). If binding requires network access and fails in the sandbox, the endpoint still binds to a local UDP socket (no internet needed) — but if it genuinely cannot bind, report BLOCKED with the error.

- [ ] **Step 3: Run the identity test**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features transport --lib transport::endpoint::`
Expected: `endpoint_id_equals_device_key` PASS. If the `id().as_bytes()` accessor name is wrong, fix it per docs and re-run.

- [ ] **Step 4: Commit**

```bash
git add org-node/src/transport/endpoint.rs
git commit -m "feat(org-node): OrgEndpoint::bind — iroh EndpointId == P2pDeviceKey"
```

---

## Task 3: `send` and `recv_one` — the authenticated channel

**Files:**
- Modify: `org-node/src/transport/endpoint.rs`

- [ ] **Step 1: Add `send`**

```rust
use crate::transport::wire::{encode_frame, decode_body, WireMessage};

impl OrgEndpoint {
    /// Dial `peer`, open a bidirectional stream, send one framed WireMessage.
    pub async fn send(
        &self,
        peer: impl Into<iroh::EndpointAddr>,
        msg: &WireMessage,
    ) -> Result<(), TransportError> {
        let conn = self
            .inner
            .connect(peer, ALPN)
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        let (mut send, mut _recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        let framed = encode_frame(msg)?;
        send.write_all(&framed)
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        send.finish().map_err(|e| TransportError::Stream(e.to_string()))?;
        // Keep the connection until the peer has read the stream.
        conn.closed().await;
        Ok(())
    }
}
```

> CONFIRM: `write_all`, `finish` (does it return `Result`? is it async?), and `conn.closed()` against docs.rs/iroh/1.x. Adjust spellings; the contract is "send the framed bytes and don't drop the connection before they're read."

- [ ] **Step 2: Add `recv_one`**

```rust
impl OrgEndpoint {
    /// Accept one inbound connection, read one framed WireMessage, and return it
    /// together with the AUTHENTICATED remote device key (the peer's EndpointId).
    pub async fn recv_one(&self) -> Result<(P2pDeviceKey, WireMessage), TransportError> {
        let incoming = self
            .inner
            .accept()
            .await
            .ok_or_else(|| TransportError::Accept("endpoint closed".into()))?;
        let conn = incoming
            .await
            .map_err(|e| TransportError::Accept(e.to_string()))?;
        // Authenticated by the QUIC handshake: this IS the peer's device key.
        // CONFIRM remote_id() -> EndpointId and the bytes accessor.
        let remote = P2pDeviceKey::new(
            ed25519_dalek::VerifyingKey::from_bytes(conn.remote_id().as_bytes())
                .map_err(|_| TransportError::Malformed)?,
        );
        let (mut _send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        let body = recv
            .read_to_end(MAX_FRAME)
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        // read_to_end gives the WHOLE stream; our sender prefixes a u32 length,
        // but read_to_end already bounds it — strip the 4-byte prefix if present.
        let payload = if body.len() >= 4 { &body[4..] } else { &body[..] };
        let msg = decode_body(payload)?;
        Ok((remote, msg))
    }
}
```

> Import `MAX_FRAME` and `ed25519_dalek`. **Framing note:** if `read_to_end` returns the full stream, the explicit 4-byte length prefix is redundant for a single-message stream — but keep `encode_frame`/the prefix for forward-compat and just strip it here. Alternatively, read the 4-byte length then exactly that many bytes; either is acceptable, but be consistent with what `send` writes. Pick ONE and make the round-trip test (Task 4) prove it.
> CONFIRM `remote_id()`, `as_bytes()`, `read_to_end(usize)` against docs.

- [ ] **Step 3: Build with feature**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node --features transport`
Expected: compiles (adjust any confirmed-API spellings).

- [ ] **Step 4: Commit**

```bash
git add org-node/src/transport/endpoint.rs
git commit -m "feat(org-node): OrgEndpoint send + recv_one (authenticated device key)"
```

---

## Task 4: Two-node integration test — deliver, authenticate, verify

**Files:**
- Create: `org-node/tests/transport_handshake.rs`

This proves stories 3→4 over a real iroh channel, offline: A delivers an admit envelope (+org secret) to B; B authenticates A's device key from the connection and verifies the envelope against a `MockChain` seeded with the new root.

- [ ] **Step 1: Write the test**

```rust
#![cfg(feature = "transport")]
//! Two real iroh endpoints on loopback. A sends an admit envelope to B; B
//! authenticates A's device key from the connection and verifies against a
//! MockChain. Offline (no relay/internet needed for loopback direct connect).
use org_node::chain::{MockChain, OrgState};
use org_node::ids::OrgId;
use org_node::keys::SigningKeypair;
use org_node::sequence::SeqGuard;
use org_node::transport::endpoint::OrgEndpoint;
use org_node::transport::wire::WireMessage;
use org_node::verify::{verify_envelope_against_chain, VerifyContext};
use org_node::SignedDeltaEnvelope;
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::{MemberId, MemberLeaf};

// Build the same admin genesis trie + admit delta the core fixtures use, but
// inline here (test_fixtures is lib-private to the crate).
fn admin_kp() -> SigningKeypair { SigningKeypair::from_seed([1u8; 32]) }

fn genesis_and_admit(admin: &SigningKeypair)
    -> (OrgTrie<Blake3Hasher>, OrgTrie<Blake3Hasher>, org_members::delta::Delta)
{
    let admin_leaf = MemberLeaf::new(
        MemberId::new([1u8; 32]), "admin", admin.member_key(), "A", "U",
        vec![admin.device_key()],
    ).unwrap();
    let (genesis, _) = OrgTrie::<Blake3Hasher>::genesis(vec![admin_leaf]).unwrap().recalculate().unwrap();
    let b_m = SigningKeypair::from_seed([2u8; 32]);
    let b_d = SigningKeypair::from_seed([3u8; 32]);
    let b_leaf = MemberLeaf::new(
        MemberId::new([2u8; 32]), "bob", b_m.member_key(), "B", "U",
        vec![b_d.device_key()],
    ).unwrap();
    let (new_trie, delta) = genesis.add_member(b_leaf).unwrap().recalculate().unwrap();
    (genesis, new_trie, delta)
}

#[tokio::test]
async fn delivers_and_verifies_admit_over_iroh() {
    let admin = admin_kp();                       // A's MEMBER key (signs envelope)
    let a_device = SigningKeypair::from_seed([10u8; 32]); // A's DEVICE key (iroh identity)
    let b_device = SigningKeypair::from_seed([11u8; 32]);
    let org = OrgId::new([5u8; 20]);

    let (genesis, new_trie, delta) = genesis_and_admit(&admin);
    let new_root = new_trie.root_hash().unwrap();
    let env = SignedDeltaEnvelope::build(org, 2, &delta, &admin).unwrap();
    let msg = WireMessage { envelope: env.clone(), org_secret: Some([0xab; 32]) };

    // Bind both endpoints.
    let ep_a = OrgEndpoint::bind(&a_device).await.unwrap();
    let ep_b = OrgEndpoint::bind(&b_device).await.unwrap();
    let b_addr = ep_b.addr();

    // B receives in a task.
    let recv = tokio::spawn(async move { ep_b.recv_one().await });

    // A sends to B's address.
    ep_a.send(b_addr, &msg).await.unwrap();

    let (remote_device, got) = recv.await.unwrap().unwrap();

    // 1. The channel authenticated A's DEVICE key.
    assert_eq!(remote_device.as_bytes(), a_device.device_key().as_bytes());
    // 2. The envelope arrived intact.
    assert_eq!(got, msg);

    // 3. B verifies the received envelope against a MockChain seeded with the
    //    new root at epoch 2 (simulating what B independently reads on-chain).
    let mut chain = MockChain::new();
    chain.set(org, OrgState { root_hash: new_root, org_pub_key: [0u8; 32], epoch: 2 });
    let ctx = VerifyContext {
        expected_org_id: org,
        author_member_key: &admin.verifying_key(),
        seq_guard: SeqGuard::from_last_seen(1),
        last_committed_epoch: 1,
    };
    let out = verify_envelope_against_chain(&genesis, &got.envelope, &ctx, &chain).unwrap();
    assert_eq!(out.trie.root_hash().unwrap(), new_root);
    assert_eq!(out.epoch, 2);
}
```

> Add a `[[test]]` entry to `org-node/Cargo.toml`:
> ```toml
> [[test]]
> name = "transport_handshake"
> path = "tests/transport_handshake.rs"
> required-features = ["transport"]
> ```
> `org-members` is already a dev-dependency (Phase 2.2). The test connects over loopback direct addresses (B's `addr()` includes them); if iroh's default preset insists on relay/discovery and the loopback direct path doesn't connect, CONFIRM how to force a direct/local connection (a relay-disabled preset or `.relay_mode(...)` on the builder) and apply it in `OrgEndpoint::bind`.

- [ ] **Step 2: Run the integration test**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features transport --test transport_handshake -- --nocapture`
Expected: `delivers_and_verifies_admit_over_iroh` PASS. Two iroh endpoints connect over loopback, the envelope is delivered, A's device key is authenticated, and the verify succeeds.

> If the connection hangs (relay/discovery waiting on the network), that's the direct-connection issue — fix `bind` to force direct/local mode (relay disabled) and re-run. If it cannot be made to connect locally in this environment, report DONE_WITH_CONCERNS with the exact symptom; do NOT fake the test.

- [ ] **Step 3: Commit**

```bash
git add org-node/tests/transport_handshake.rs org-node/Cargo.toml
git commit -m "test(org-node): two-node iroh handshake — deliver, authenticate, verify"
```

---

## Task 5: Green + clippy + README

**Files:**
- Modify: `org-node/README.md`

- [ ] **Step 1: Core + each feature green**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node` (core, 21 tests).
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features transport --lib` (core + framing + identity tests).
Expected: pass.

- [ ] **Step 2: Clippy gates**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo clippy -p org-node --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo clippy -p org-node --lib --features transport -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`
Expected: both clean.

- [ ] **Step 3: README**

Add a "Transport (Phase 2.3)" section: the `transport` feature; `OrgEndpoint` (iroh `EndpointId == P2pDeviceKey`); the ALPN; `WireMessage` + framing; `send`/`recv_one` and that `recv_one` returns the **authenticated** remote device key (caller must still cross-check it against the members trie); the two-node test; and S3 (iroh is a transport stand-in; real discovery/relay vs the PoC's direct/loopback connect).

- [ ] **Step 4: Commit**

```bash
git add org-node/README.md
git commit -m "docs(org-node): README — Phase 2.3 iroh transport"
```

---

## Self-review notes (author check — applied)

- **Spec coverage:** §5.3 `NodeId = P2pDeviceKey` + channel authentication → Tasks 2–3 (`OrgEndpoint`, `recv_one` returns authenticated device key); stories 2–4 deliver-and-verify → Task 4; S3 (transport stand-in) noted in README.
- **Authentication boundary:** the transport surfaces the QUIC-authenticated remote device key; it does NOT itself decide trust — the caller cross-checks against the trie (as `verify`/the trie own). The test asserts the authenticated key equals A's device key.
- **Offline by design:** the integration test verifies against `MockChain`, so it needs no internet (only loopback iroh). The real-chain verify path is already proven by Phase 2.2's e2e — this phase doesn't re-litigate it.
- **iroh 1.0 novelty:** every iroh call is either verified against docs.rs (listed at top) or explicitly flagged "CONFIRM" for the implementer to check before finalising — no invented APIs slip through silently. The design (framing, auth, tests) is fixed.
- **No core regression:** all transport code is `#[cfg(feature="transport")]`.
- **Build constraint:** every cargo command uses `CARGO_HOME=/tmp/cargo_home_fuzz`.

## Follow-up phase (separate plan)
- **2.4 shell** — persona/org persistence (encrypted at rest), Tauri commands/events, SvelteKit screens, two-instance demo (wires together core + chain + transport into the 5 user stories).
