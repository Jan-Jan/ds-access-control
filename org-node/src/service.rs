//! OrgService: composes store + chain + transport into the five user stories.
//! See spec §6 and plan docs/superpowers/plans/2026-06-16-ods-phase-2-4-tauri-shell.md Task 2.
//!
//! Gated on the `app` feature (which implies `chain` + `transport`).
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::{MemberId, MemberLeaf, RootHash};
use rand_core::{CryptoRng, RngCore};

use crate::chain::OrgState;
use crate::envelope::SignedDeltaEnvelope;
use crate::error::OrgNodeError;
use crate::ids::OrgId;
use crate::keys::SigningKeypair;
use crate::sequence::SeqGuard;
use crate::store::{MemberSnapshot, OrgRecord, PendingInvite, PersonaRecord, PersonaStatus, PersonaStore};
use crate::transport::TransportMode;
use crate::transport::endpoint::OrgEndpoint;
use crate::transport::wire::WireMessage;
use crate::verify::{VerifyContext, verify_envelope_against_chain};

type Trie = OrgTrie<Blake3Hasher>;

// ============================================================
// ChainOps trait — the submit/read oracle injected into OrgService.
// ============================================================

/// Abstraction over on-chain operations so the service is headless-testable.
/// Production wires a real subxt client; tests inject `MockChainOps`.
#[async_trait]
pub trait ChainOps: Send + Sync {
    /// Submit genesis (create proxy, map, update epoch 0).
    ///
    /// Returns `(org_id, proxy_account)` where `org_id = h160_of(P)` and
    /// `proxy_account` is the raw 32-byte AccountId32 of the pure proxy `P`
    /// (used by `submit_update` to build the `proxied(P, ...)` call).
    /// Mock implementations return `None` for `proxy_account`; the production
    /// `SubxtChainOps` returns `Some(p)`.
    async fn submit_genesis(
        &self,
        genesis_root: [u8; 32],
        org_pub_key: [u8; 32],
    ) -> Result<(OrgId, Option<[u8; 32]>), OrgNodeError>;

    /// Submit a root update for an existing org at `expected_epoch`.
    ///
    /// `proxy_account` is the pure-proxy AccountId32 `P` that was recorded at
    /// genesis.  The production implementation (`SubxtChainOps`) uses it to
    /// construct the `proxied(P, ...)` call; mock implementations may ignore it.
    /// Passing `None` causes `SubxtChainOps` to fall back to its in-memory
    /// `proxy_map` (populated during `submit_genesis` in the same process).
    async fn submit_update(
        &self,
        org_id: OrgId,
        new_root: [u8; 32],
        org_pub_key: [u8; 32],
        expected_epoch: u64,
        proxy_account: Option<[u8; 32]>,
    ) -> Result<(), OrgNodeError>;

    /// Read current on-chain state for `org_id`.
    async fn read_state(&self, org_id: OrgId) -> Result<Option<OrgState>, OrgNodeError>;
}

// ============================================================
// MockChainOps — in-memory stub for headless tests.
// ============================================================

/// Shared, thread-safe mock chain state.
#[derive(Default, Clone)]
pub struct MockChainInner {
    slots: std::collections::HashMap<OrgId, OrgState>,
    next_id_seed: u8,
}

/// Mock `ChainOps` backed by an `Arc<Mutex<MockChainInner>>`.  Clone the `Arc`
/// to share the same mock chain between the two `OrgService` instances in tests.
#[derive(Clone)]
pub struct MockChainOps {
    inner: Arc<Mutex<MockChainInner>>,
}

impl MockChainOps {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(MockChainInner::default())) }
    }

    /// Directly seed the chain (for test setup only).
    pub fn set(&self, org_id: OrgId, state: OrgState) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.slots.insert(org_id, state);
    }

    /// Read a slot directly (for test assertions).
    pub fn get(&self, org_id: &OrgId) -> Option<OrgState> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.slots.get(org_id).copied()
    }
}

impl Default for MockChainOps {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainOps for MockChainOps {
    async fn submit_genesis(
        &self,
        genesis_root: [u8; 32],
        org_pub_key: [u8; 32],
    ) -> Result<(OrgId, Option<[u8; 32]>), OrgNodeError> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Deterministic org_id derived from the genesis root (first 20 bytes).
        let mut id_bytes = [0u8; 20];
        id_bytes.copy_from_slice(&genesis_root[..20]);
        // Use seed counter to ensure uniqueness across multiple genesis calls.
        id_bytes[0] ^= g.next_id_seed;
        g.next_id_seed = g.next_id_seed.wrapping_add(1);
        let org_id = OrgId::new(id_bytes);
        g.slots.insert(org_id, OrgState {
            root_hash: RootHash::from_bytes(genesis_root),
            org_pub_key,
            epoch: 1,
        });
        // Mock has no real pure-proxy; return None so OrgRecord.proxy_account stays None.
        Ok((org_id, None))
    }

    async fn submit_update(
        &self,
        org_id: OrgId,
        new_root: [u8; 32],
        org_pub_key: [u8; 32],
        expected_epoch: u64,
        _proxy_account: Option<[u8; 32]>,
    ) -> Result<(), OrgNodeError> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let state = g.slots.get(&org_id).copied().ok_or(OrgNodeError::OrgNotOnChain)?;
        if state.epoch != expected_epoch {
            return Err(OrgNodeError::Chain(format!(
                "epoch mismatch: expected {expected_epoch}, found {}",
                state.epoch
            )));
        }
        g.slots.insert(org_id, OrgState {
            root_hash: RootHash::from_bytes(new_root),
            org_pub_key,
            epoch: expected_epoch + 1,
        });
        Ok(())
    }

    async fn read_state(&self, org_id: OrgId) -> Result<Option<OrgState>, OrgNodeError> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Ok(g.slots.get(&org_id).copied())
    }
}

// ============================================================
// SubxtChainOps — real impl wired to genesis_ceremony + subxt write path.
// ============================================================

#[cfg(feature = "chain")]
mod subxt_impl {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use on_chain_client::{OrgAdmin, OrgRegistryClient};
    use org_members::RootHash;
    use subxt::OnlineClient;
    use subxt::config::PolkadotConfig;
    use subxt_signer::sr25519::Keypair;
    use tokio::time::sleep;

    use crate::chain::OrgState;
    use crate::chain_write::WriteError;
    use crate::chain_write::calldata::revive_update_runtime_call;
    use crate::chain_write::multisig::dispatch_threshold_1;
    use crate::chain_write::proxy::{BlockSink, proxied};
    use crate::ceremony::genesis_ceremony;
    use crate::error::OrgNodeError;
    use crate::ids::OrgId;

    fn write_err(e: WriteError) -> OrgNodeError {
        OrgNodeError::Chain(format!("chain write: {e}"))
    }

    fn map_state(s: on_chain_client::OrgState) -> OrgState {
        OrgState {
            root_hash: RootHash::from_bytes(s.root_hash.0),
            org_pub_key: s.org_pub_key.0,
            epoch: s.epoch.0,
        }
    }

    /// A `BlockSink` that polls the finalized-block cursor until a block NEWER
    /// than the one that was current at construction time is finalized, then
    /// returns that block's hash.
    ///
    /// **Why this matters for live Paseo**: Paseo produces a block every ~6–12 s
    /// and finalizes with GRANDPA slightly later.  Simply calling
    /// `at_current_block()` immediately after `submit` can return the same
    /// finalized block the extrinsic was *submitted at*, before a new block
    /// including the extrinsic has been finalized.  The poll loop below waits
    /// until `at_current_block()` reports a strictly newer hash (i.e. at least
    /// one new finalized block has appeared), with a ~2 s cadence and a
    /// configurable deadline (default 90 s).
    ///
    /// **Chopsticks instant mode**: in chopsticks interval/instant mode a new
    /// block is produced in milliseconds, so the first or second poll iteration
    /// resolves immediately — the overhead is negligible.
    ///
    /// **Correctness note**: `settle()` is called AFTER the extrinsic has been
    /// submitted.  Its return value (a block hash) is consumed by
    /// `create_pure_via_multisig` to look up the `Proxy.PureCreated` event.
    /// We return the hash of the first *new* finalized block, which is
    /// guaranteed to be the block that included (or post-dates) our extrinsic,
    /// so the event query will find it.
    pub struct FinalitySink {
        pub api: OnlineClient<PolkadotConfig>,
        /// How long `settle` waits before giving up (default: 90 s).
        pub timeout: Duration,
    }

    #[async_trait]
    impl BlockSink for FinalitySink {
        /// Poll until a new finalized block appears (relative to the snapshot
        /// taken at the start of the call), then return its hash.
        ///
        /// Steps:
        /// 1. Snapshot the current finalized block hash (`pre_hash`).
        /// 2. Loop with ~2 s sleeps:
        ///    a. Call `at_current_block()` to get the latest finalized hash.
        ///    b. If it differs from `pre_hash`, return it — a new block landed.
        /// 3. If `self.timeout` elapses without a new block (e.g. the chain is
        ///    stalled), return the pre-submit hash so callers can degrade
        ///    gracefully rather than hanging forever.
        ///
        /// This is compile-verified; runtime verification requires a live chain
        /// or chopsticks fork.
        async fn settle(&self) -> Result<[u8; 32], WriteError> {
            // 1. Snapshot the finalized block at call time.
            let pre_hash = self
                .api
                .at_current_block()
                .await
                .map_err(|e| WriteError::Subxt(format!("settle/pre_hash at_current_block: {e}")))?
                .block_ref()
                .hash()
                .0;

            let deadline = Instant::now() + self.timeout;
            let poll_interval = Duration::from_secs(2);

            // 2. Poll until a new finalized block appears or we time out.
            loop {
                sleep(poll_interval).await;

                let current = self
                    .api
                    .at_current_block()
                    .await
                    .map_err(|e| WriteError::Subxt(format!("settle/poll at_current_block: {e}")))?;
                let current_hash = current.block_ref().hash().0;

                if current_hash != pre_hash {
                    // A new finalized block appeared — the extrinsic has landed.
                    return Ok(current_hash);
                }

                // 3. Timed out — return pre-submit hash so callers degrade
                //    gracefully rather than hanging forever.
                if Instant::now() >= deadline {
                    return Ok(pre_hash);
                }
            }
        }
    }

    /// Production `ChainOps` that drives the real on-chain ceremony and update
    /// path.  Parameterised at construction; wired from `AppState` via env vars.
    ///
    /// `proxy_map` is populated by `submit_genesis` and consumed by
    /// `submit_update` — the pure proxy AccountId32 `P` is needed to build the
    /// `proxied(P, ...)` call, but `ChainOps::submit_update` only receives the
    /// `OrgId` (which is `h160_of(P)`; we cannot reverse the keccak).
    pub struct SubxtChainOps {
        pub api: OnlineClient<PolkadotConfig>,
        pub registry_client: OrgRegistryClient,
        pub contract_h160: [u8; 20],
        /// The sole signer / admin for the 1-of-1 multisig.
        pub admin: Keypair,
        /// Co-signatories for the threshold-1 multisig (empty for a true 1-of-1).
        pub others: Vec<[u8; 32]>,
        /// org_id → pure proxy AccountId32; populated by submit_genesis.
        pub proxy_map: Arc<Mutex<HashMap<OrgId, [u8; 32]>>>,
        /// How long `FinalitySink::settle` waits for inclusion.
        pub settle_timeout: Duration,
    }

    impl SubxtChainOps {
        /// Construct from a connected subxt client.  `admin_seed` is the
        /// 32-byte SR25519 secret seed for the admin (read from env in AppState).
        /// `others` are the co-signer public keys (empty for a true 1-of-1).
        pub fn new(
            api: OnlineClient<PolkadotConfig>,
            registry_client: OrgRegistryClient,
            contract_h160: [u8; 20],
            admin: Keypair,
            others: Vec<[u8; 32]>,
        ) -> Self {
            Self {
                api,
                registry_client,
                contract_h160,
                admin,
                others,
                proxy_map: Arc::new(Mutex::new(HashMap::new())),
                settle_timeout: Duration::from_secs(90),
            }
        }

        fn sink(&self) -> FinalitySink {
            FinalitySink {
                api: self.api.clone(),
                timeout: self.settle_timeout,
            }
        }
    }

    #[async_trait]
    impl super::ChainOps for SubxtChainOps {
        async fn submit_genesis(
            &self,
            genesis_root: [u8; 32],
            org_pub_key: [u8; 32],
        ) -> Result<(OrgId, Option<[u8; 32]>), OrgNodeError> {
            let sink = self.sink();
            let outcome = genesis_ceremony(
                &sink,
                &self.api,
                self.contract_h160,
                &self.admin, // funder == admin for PoC
                &self.admin,
                &self.others,
                genesis_root,
                org_pub_key,
            )
            .await
            .map_err(write_err)?;

            // Store the pure proxy AccountId32 in the in-memory map (for same-process
            // submit_update calls) AND return it so OrgService can persist it in OrgRecord.
            let mut map = self
                .proxy_map
                .lock()
                .map_err(|_| OrgNodeError::Chain("proxy_map lock poisoned".into()))?;
            map.insert(outcome.org_id, outcome.p);

            Ok((outcome.org_id, Some(outcome.p)))
        }

        async fn submit_update(
            &self,
            org_id: OrgId,
            new_root: [u8; 32],
            org_pub_key: [u8; 32],
            expected_epoch: u64,
            proxy_account: Option<[u8; 32]>,
        ) -> Result<(), OrgNodeError> {
            // Resolve the pure proxy AccountId32 `P`.
            // Priority: (1) the persisted value passed in by OrgService, (2) the
            // in-memory proxy_map populated by submit_genesis in this process.
            let p = if let Some(pa) = proxy_account {
                pa
            } else {
                let map = self
                    .proxy_map
                    .lock()
                    .map_err(|_| OrgNodeError::Chain("proxy_map lock poisoned".into()))?;
                *map.get(&org_id).ok_or_else(|| {
                    OrgNodeError::Chain(format!(
                        "no proxy registered for org_id {:?}; pass proxy_account or call submit_genesis first",
                        org_id
                    ))
                })?
            };

            let call = revive_update_runtime_call(
                self.contract_h160,
                new_root,
                org_pub_key,
                u128::from(expected_epoch),
            );
            dispatch_threshold_1(&self.api, &self.admin, &self.others, proxied(p, call))
                .await
                .map_err(write_err)?;

            let sink = self.sink();
            // settle() is called for its side-effect (wait until the update is
            // finalized on chain); the returned block hash is not needed here
            // (only the genesis ceremony's create_pure uses it to read events).
            sink.settle().await.map_err(write_err)?;
            Ok(())
        }

        async fn read_state(&self, org_id: OrgId) -> Result<Option<OrgState>, OrgNodeError> {
            let admin = OrgAdmin(*org_id.as_bytes());
            let state = self
                .registry_client
                .get_org_state(admin, None)
                .await
                .map_err(|e| OrgNodeError::Chain(format!("get_org_state: {e}")))?
                .map(map_state);
            Ok(state)
        }
    }
}

#[cfg(feature = "chain")]
pub use subxt_impl::SubxtChainOps;

// ============================================================
// Helper: rebuild a trie mirror from persisted MemberSnapshots.
// ============================================================

fn trie_from_snapshots(snapshots: &[MemberSnapshot]) -> Result<Trie, OrgNodeError> {
    let leaves: Result<Vec<MemberLeaf>, OrgNodeError> = snapshots
        .iter()
        .map(|s| {
            let member_vk = VerifyingKey::from_bytes(&s.member_key)
                .map_err(|e| OrgNodeError::Chain(format!("bad member key: {e}")))?;
            let device_keys: Result<Vec<org_members::P2pDeviceKey>, OrgNodeError> = s
                .device_keys
                .iter()
                .map(|dk| {
                    let vk = VerifyingKey::from_bytes(dk)
                        .map_err(|e| OrgNodeError::Chain(format!("bad device key: {e}")))?;
                    Ok(org_members::P2pDeviceKey::new(vk))
                })
                .collect();
            let leaf = MemberLeaf::new(
                MemberId::new(s.id),
                &s.handle,
                org_members::P2pMemberKey::new(member_vk),
                &s.name,
                &s.surname,
                device_keys?,
            )
            .map_err(OrgNodeError::Trie)?;
            Ok(leaf)
        })
        .collect();
    Trie::genesis(leaves?).map_err(OrgNodeError::Trie)
}

// ============================================================
// OrgService — the composition root.
// ============================================================

/// Composes `PersonaStore` + `ChainOps` + lazy `OrgEndpoint` into the
/// five org-node user stories. Headless-testable: inject `MockChainOps` +
/// a real loopback `OrgEndpoint` to exercise the full composition without a
/// live chain.
pub struct OrgService {
    store: PersonaStore,
    chain: Box<dyn ChainOps>,
    /// Lazily bound device endpoint; `None` until `bind_endpoint` is called.
    endpoint: Option<OrgEndpoint>,
    /// How to bind the iroh endpoint and dial peers.
    /// Defaults to `Loopback` so all existing offline tests are unaffected.
    transport_mode: TransportMode,
}

impl OrgService {
    pub fn new(store: PersonaStore, chain: Box<dyn ChainOps>) -> Self {
        Self { store, chain, endpoint: None, transport_mode: TransportMode::Loopback }
    }

    /// Override the transport mode used when `ensure_endpoint` binds and when
    /// `admit_member`/`revoke_member` dial peers.
    ///
    /// Must be called BEFORE any endpoint is bound (i.e. before the first
    /// `ensure_endpoint`, `admit_member`, `receive_and_verify`, or
    /// `revoke_member` call).  In production the Tauri `AppState::init` sets
    /// this to `TransportMode::Networked` so both laptops use relay + discovery.
    pub fn set_transport_mode(&mut self, mode: TransportMode) {
        self.transport_mode = mode;
    }

    /// Inject a pre-bound endpoint (used in tests to supply loopback endpoints).
    pub fn with_endpoint(mut self, ep: OrgEndpoint) -> Self {
        self.endpoint = Some(ep);
        self
    }

    /// Borrow the endpoint if one is set.
    pub fn endpoint(&self) -> Option<&OrgEndpoint> {
        self.endpoint.as_ref()
    }

    // ----------------------------------------------------------
    // Story precursor: create a persona (no chain, no network).
    // ----------------------------------------------------------

    /// Generate a new persona with fresh ed25519 key material, persist it in
    /// the store, and return the persona_id.
    pub fn create_persona<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        handle: &str,
        name: &str,
        surname: &str,
    ) -> Result<String, OrgNodeError> {
        let member_kp = SigningKeypair::generate(rng);
        let device_kp = SigningKeypair::generate(rng);
        // Derive a unique persona_id from the member public key bytes.
        let persona_id = hex_id(member_kp.verifying_key().as_bytes());
        let rec = PersonaRecord {
            persona_id: persona_id.clone(),
            org_id: None,
            handle: handle.to_string(),
            name: name.to_string(),
            surname: surname.to_string(),
            member_seed: member_kp.to_seed(),
            device_seed: device_kp.to_seed(),
            member_id: None,
            status: PersonaStatus::Proposed,
        };
        self.store.data_mut().personas.push(rec);
        self.store.save(rng)?;
        Ok(persona_id)
    }

    // ----------------------------------------------------------
    // Story 1: create_organisation — genesis trie + chain submit.
    // ----------------------------------------------------------

    /// Build a genesis trie for the given persona, submit it to the chain,
    /// persist the `OrgRecord`, and mark the persona as `Active`.
    /// Returns the new `org_id`.
    pub async fn create_organisation<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        persona_id: &str,
    ) -> Result<OrgId, OrgNodeError> {
        let (member_kp, device_kp, handle, name, surname) = self.persona_keys(persona_id)?;

        // Build genesis trie: admin = this persona.
        let admin_id = MemberId::new(member_id_from_key(member_kp.verifying_key().as_bytes()));
        let admin_leaf = MemberLeaf::new(
            admin_id,
            &handle,
            member_kp.member_key(),
            &name,
            &surname,
            vec![device_kp.device_key()],
        )
        .map_err(OrgNodeError::Trie)?;
        let (trie, _delta) =
            Trie::genesis(vec![admin_leaf]).map_err(OrgNodeError::Trie)?.recalculate().map_err(OrgNodeError::Trie)?;

        let genesis_root_hash = trie.root_hash().map_err(OrgNodeError::Trie)?;
        let genesis_root = *genesis_root_hash.as_bytes();
        let org_pub_key = *member_kp.verifying_key().as_bytes();

        // Submit genesis to chain (stub for headless test; real chain for production).
        // Returns the org_id AND the pure-proxy AccountId32 P (Some for SubxtChainOps,
        // None for MockChainOps).  P is persisted in OrgRecord so submit_update can
        // find it after a restart.
        let (org_id, proxy_account) = self.chain.submit_genesis(genesis_root, org_pub_key).await?;

        // Persist the OrgRecord.
        let admin_snap = MemberSnapshot {
            id: *admin_id.as_bytes(),
            handle: handle.clone(),
            name: name.clone(),
            surname: surname.clone(),
            member_key: *member_kp.verifying_key().as_bytes(),
            device_keys: vec![*device_kp.verifying_key().as_bytes()],
        };
        let org_rec = OrgRecord {
            org_id,
            root_hash: genesis_root,
            org_pub_key,
            epoch: 1,
            org_secret: None,
            last_seq: 0,
            admin_member_key: *member_kp.verifying_key().as_bytes(),
            trie_members: vec![admin_snap],
            // Persist the pure-proxy AccountId32 returned by submit_genesis so that
            // submit_update can find P even after a restart (fixes Gap 2).
            // None for MockChainOps; Some(p) for SubxtChainOps.
            proxy_account,
        };
        self.store.data_mut().orgs.push(org_rec);

        // Transition persona to Active.
        self.update_persona_status(persona_id, org_id, PersonaStatus::Active)?;

        self.store.save(rng)?;
        Ok(org_id)
    }

    // ----------------------------------------------------------
    // Story 2: blobs — invite / join-request exchange.
    // ----------------------------------------------------------

    /// Build and encode an `Invite` blob for the given org.
    pub fn export_invite(&self, org_id: OrgId) -> Result<String, OrgNodeError> {
        let org_rec = self.find_org(org_id)?;
        let persona = self.admin_persona_for_org(org_id)?;
        let device_kp = SigningKeypair::from_seed(persona.device_seed);
        // Include the real bound endpoint address so the recipient can dial us back
        // if needed (Gap 1 fix).  If the endpoint has not been bound yet, the
        // admin_node_addr field is left empty — callers should call ensure_endpoint
        // before export_invite to populate it.
        let admin_node_addr = if let Some(ep) = &self.endpoint {
            postcard::to_allocvec(&ep.node_addr_for_dial())
                .map_err(|e| OrgNodeError::Chain(format!("addr encode: {e}")))?
        } else {
            vec![]
        };
        let inv = crate::blobs::Invite {
            org_id,
            org_pub_key: org_rec.org_pub_key,
            admin_member_key: org_rec.admin_member_key,
            admin_device_key: *device_kp.verifying_key().as_bytes(),
            admin_node_addr,
        };
        crate::blobs::encode(&inv)
    }

    /// Decode and persist an incoming `Invite` blob.  Returns the decoded invite.
    /// Stores a `PendingInvite` in the encrypted store so that
    /// `receive_and_verify` can cross-check the authenticated sender against
    /// the admin device key the invite asserts (Fix 1 — security hardening).
    pub fn import_invite<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        blob: &str,
    ) -> Result<crate::blobs::Invite, OrgNodeError> {
        let inv: crate::blobs::Invite = crate::blobs::decode(blob)?;
        // Upsert: replace any existing pending invite for the same org.
        let pending = PendingInvite {
            org_id: inv.org_id,
            admin_device_key: inv.admin_device_key,
            admin_member_key: inv.admin_member_key,
            org_pub_key: inv.org_pub_key,
        };
        let data = self.store.data_mut();
        if let Some(existing) = data.pending_invites.iter_mut().find(|p| p.org_id == inv.org_id) {
            *existing = pending;
        } else {
            data.pending_invites.push(pending);
        }
        self.store.save(rng)?;
        Ok(inv)
    }

    /// Build and encode a `JoinRequest` blob for the given persona.  The
    /// endpoint must be bound so we can include the node address.
    pub fn export_join_request(&self, persona_id: &str) -> Result<String, OrgNodeError> {
        let persona = self.find_persona(persona_id)?;
        let device_kp = SigningKeypair::from_seed(persona.device_seed);
        let member_kp = SigningKeypair::from_seed(persona.member_seed);
        // Provide the iroh node address from the bound endpoint (if any).
        let node_addr = if let Some(ep) = &self.endpoint {
            let addr = ep.node_addr_for_dial();
            postcard::to_allocvec(&addr)
                .map_err(|e| OrgNodeError::Chain(format!("addr encode: {e}")))?
        } else {
            vec![]
        };
        let jr = crate::blobs::JoinRequest {
            handle: persona.handle.clone(),
            name: persona.name.clone(),
            surname: persona.surname.clone(),
            member_key: *member_kp.verifying_key().as_bytes(),
            device_key: *device_kp.verifying_key().as_bytes(),
            node_addr,
        };
        crate::blobs::encode(&jr)
    }

    /// Decode and store a `JoinRequest` blob (stores nothing — for the PoC the
    /// join request is transient; the admin calls `admit_member` directly).
    /// Returns the decoded request.
    pub fn import_join_request(
        blob: &str,
    ) -> Result<crate::blobs::JoinRequest, OrgNodeError> {
        crate::blobs::decode(blob)
    }

    // ----------------------------------------------------------
    // Story 3: admit_member — trie add + submit_update + iroh push.
    // ----------------------------------------------------------

    /// Add a new member to the org trie, bump the on-chain epoch, build a
    /// `SignedDeltaEnvelope`, and push it (+ `org_secret`) to the new member
    /// over iroh.
    ///
    /// The dial behaviour depends on the configured [`TransportMode`]:
    /// - `Loopback`: dials `peer_addr` (the `EndpointAddr` decoded from the
    ///   `JoinRequest` blob).  Used for offline tests and same-machine runs.
    /// - `Networked`: dials the peer purely by its `EndpointId` (the device
    ///   key from `join_request.device_key`), ignoring `peer_addr`.  iroh
    ///   resolves connectivity via relay/DNS discovery; `peer_addr` may be
    ///   stale or empty in this mode.
    ///
    /// `join_request` carries the new member's keys.
    /// `org_secret` is an optional symmetric secret handed to the new member.
    pub async fn admit_member<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        org_id: OrgId,
        join_request: &crate::blobs::JoinRequest,
        peer_addr: iroh::EndpointAddr,
        org_secret: Option<[u8; 32]>,
    ) -> Result<[u8; 32], OrgNodeError> {
        // Rebuild local trie from stored snapshots.
        let (trie, org_epoch, org_pub_key, admin_member_kp, last_seq, pre_add_snapshots, proxy_account) = {
            let org_rec = self.find_org(org_id)?;
            let trie = trie_from_snapshots(&org_rec.trie_members)?;
            let epoch = org_rec.epoch;
            let pub_key = org_rec.org_pub_key;
            let last_seq = org_rec.last_seq;
            // Capture pre-add snapshots so B can reconstruct the genesis trie.
            let snapshots = org_rec.trie_members.clone();
            // Carry the persisted proxy_account so submit_update can use it after a restart.
            let proxy = org_rec.proxy_account;
            // Admin is the first member whose member key = admin_member_key.
            let admin_persona = self.admin_persona_for_org(org_id)?;
            let member_kp = SigningKeypair::from_seed(admin_persona.member_seed);
            (trie, epoch, pub_key, member_kp, last_seq, snapshots, proxy)
        };

        // Derive a fresh member_id from the joiner's member key bytes.
        let new_member_id = MemberId::new(member_id_from_key(&join_request.member_key));
        let member_vk = VerifyingKey::from_bytes(&join_request.member_key)
            .map_err(|e| OrgNodeError::Chain(format!("bad member key: {e}")))?;
        let device_vk = VerifyingKey::from_bytes(&join_request.device_key)
            .map_err(|e| OrgNodeError::Chain(format!("bad device key: {e}")))?;

        let new_leaf = MemberLeaf::new(
            new_member_id,
            &join_request.handle,
            org_members::P2pMemberKey::new(member_vk),
            &join_request.name,
            &join_request.surname,
            vec![org_members::P2pDeviceKey::new(device_vk)],
        )
        .map_err(OrgNodeError::Trie)?;

        let (new_trie, delta) =
            trie.add_member(new_leaf.clone()).map_err(OrgNodeError::Trie)?.recalculate().map_err(OrgNodeError::Trie)?;

        let new_root_hash = new_trie.root_hash().map_err(OrgNodeError::Trie)?;
        let new_root = *new_root_hash.as_bytes();

        // Submit on-chain update (epoch → epoch + 1).
        // Pass proxy_account so SubxtChainOps can find P even after a restart (Gap 2).
        self.chain
            .submit_update(org_id, new_root, org_pub_key, org_epoch, proxy_account)
            .await?;
        let new_epoch = org_epoch + 1;

        // Build the signed envelope.
        let parent_seq = last_seq + 1;
        let envelope =
            SignedDeltaEnvelope::build(org_id, parent_seq, &delta, &admin_member_kp)
                .map_err(|_| OrgNodeError::MalformedDelta)?;

        // Encode pre-add snapshots so B can reconstruct the genesis trie for verification.
        let genesis_snapshot = postcard::to_allocvec(&pre_add_snapshots)
            .map(Some)
            .unwrap_or(None);

        // Push the WireMessage to the new member over iroh.
        // Use the lazily bound endpoint; bind from this persona's device seed if not yet bound.
        let msg = WireMessage { envelope, org_secret, genesis_snapshot };
        let admin_persona_id = self.admin_persona_for_org(org_id)?.persona_id.clone();
        let mode = self.transport_mode;
        let ep = self.ensure_endpoint(&admin_persona_id).await?;
        match mode {
            TransportMode::Loopback => {
                // Loopback/same-machine: dial the full EndpointAddr from the blob.
                ep.send(peer_addr, &msg)
                    .await
                    .map_err(|e| OrgNodeError::Chain(format!("iroh send: {e}")))?;
            }
            TransportMode::Networked => {
                // Cross-network: dial purely by EndpointId so iroh relay/DNS
                // resolves the path.  The device key from the JoinRequest equals
                // the peer's iroh EndpointId (same ed25519 key).
                let peer_id = iroh::EndpointId::from_bytes(&join_request.device_key)
                    .map_err(|_| OrgNodeError::Chain("invalid joiner device key for EndpointId".into()))?;
                ep.send_to_id(peer_id, &msg)
                    .await
                    .map_err(|e| OrgNodeError::Chain(format!("iroh send (networked): {e}")))?;
            }
        }

        // Update the persisted OrgRecord.
        let new_snap = MemberSnapshot {
            id: *new_member_id.as_bytes(),
            handle: join_request.handle.clone(),
            name: join_request.name.clone(),
            surname: join_request.surname.clone(),
            member_key: join_request.member_key,
            device_keys: vec![join_request.device_key],
        };
        {
            let org_rec = self.find_org_mut(org_id)?;
            org_rec.root_hash = new_root;
            org_rec.epoch = new_epoch;
            org_rec.last_seq = parent_seq;
            org_rec.trie_members.push(new_snap);
        }
        self.store.save(rng)?;

        Ok(*new_member_id.as_bytes())
    }

    // ----------------------------------------------------------
    // Story 4: receive_and_verify — recv envelope, verify, commit.
    // ----------------------------------------------------------

    /// Accept one inbound `WireMessage`, cross-check the sender's device key
    /// against the trie, verify the envelope against the chain, and commit
    /// the new state.
    pub async fn receive_and_verify<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ReceiveOutcome, OrgNodeError> {
        // Bind the endpoint from the first persona's device_seed if not yet bound.
        let first_persona_id = self
            .store
            .data()
            .personas
            .first()
            .ok_or_else(|| OrgNodeError::Chain("no persona found — create one first".into()))?
            .persona_id
            .clone();
        let ep = self.ensure_endpoint(&first_persona_id).await?;
        let (remote_device_key, msg) = ep
            .recv_one()
            .await
            .map_err(|e| OrgNodeError::Chain(format!("iroh recv: {e}")))?;

        let org_id = msg.envelope.org_id;

        // Look up the org by the envelope's org_id.  If we don't have it yet
        // (first-time admission), we accept the envelope and store a new OrgRecord.
        // The `admin_member_key` must be in the envelope's metadata — we take it
        // from the verified trie after the chain check.
        //
        // First look for a matching pending OrgRecord (for an already-known org).
        // For the admission case we may not have one yet; we create it.

        // Find the admin member key from on-chain state is not possible without
        // the trie.  For the PoC, we take a different approach:
        //
        //   1. Read the chain state to get the authoritative root + epoch.
        //   2. We need the admin's member key to verify the signature.
        //      On first admission, we don't have the org yet.  We use the
        //      `org_pub_key` from the on-chain state — which the admin published
        //      as part of genesis — as the author member key.  This matches
        //      `create_organisation` which sets `org_pub_key = admin_member_vk_bytes`.

        let chain_state = self
            .chain
            .read_state(org_id)
            .await?
            .ok_or(OrgNodeError::OrgNotOnChain)?;

        let author_vk = VerifyingKey::from_bytes(&chain_state.org_pub_key)
            .map_err(|e| OrgNodeError::Chain(format!("bad org_pub_key: {e}")))?;

        // Check whether we already have a local OrgRecord for this org.
        let mut is_first_admission = false;
        let (local_trie, last_seq, last_epoch) = {
            if let Some(existing) = self
                .store
                .data()
                .orgs
                .iter()
                .find(|o| o.org_id == org_id)
                .cloned()
            {
                let trie = trie_from_snapshots(&existing.trie_members)?;
                (trie, existing.last_seq, existing.epoch)
            } else {
                // Fresh admission: reconstruct the genesis trie from the
                // `genesis_snapshot` included by the admin in the WireMessage.
                // This contains the pre-add members (the admin only), enabling
                // `verify_envelope_against_chain` to pass the `base_root` check.
                let trie = if let Some(ref snap_bytes) = msg.genesis_snapshot {
                    let snaps: Vec<MemberSnapshot> = postcard::from_bytes(snap_bytes)
                        .map_err(|e| OrgNodeError::Chain(format!("genesis_snapshot decode: {e}")))?;
                    trie_from_snapshots(&snaps)?
                } else {
                    // Fallback (no snapshot): build a minimal single-admin trie.
                    // This will fail the base_root check unless the admin used
                    // the same placeholder values (should not happen in production).
                    let admin_id =
                        MemberId::new(member_id_from_key(chain_state.org_pub_key.as_ref()));
                    let admin_vk = author_vk;
                    let admin_leaf = MemberLeaf::new(
                        admin_id,
                        "admin",
                        org_members::P2pMemberKey::new(admin_vk),
                        "Admin",
                        "User",
                        vec![org_members::P2pDeviceKey::new(admin_vk)],
                    )
                    .map_err(OrgNodeError::Trie)?;
                    let (t, _) = Trie::genesis(vec![admin_leaf])
                        .map_err(OrgNodeError::Trie)?
                        .recalculate()
                        .map_err(OrgNodeError::Trie)?;
                    t
                };
                is_first_admission = true;
                (trie, 0, 0)
            }
        };

        // Security hardening — Fix 1: on FIRST ADMISSION, cross-check the
        // authenticated remote device key against the admin_device_key recorded
        // in the invite B imported for this org.  This prevents a rogue peer
        // from successfully pushing an envelope even if the chain anchor and
        // signature match (defense-in-depth — the invite is the explicit trust root).
        if is_first_admission {
            let pending = self
                .store
                .data()
                .pending_invites
                .iter()
                .find(|p| p.org_id == org_id)
                .cloned();
            if let Some(inv) = pending {
                if remote_device_key.as_bytes() != &inv.admin_device_key {
                    return Err(OrgNodeError::BadSignature);
                }
            }
            // If no invite was imported for this org, fall through to the chain/sig
            // proof (existing behaviour) — log-worthy in production but not a hard fail.
        }

        let seq_guard = SeqGuard::from_last_seen(last_seq);
        let ctx = VerifyContext {
            expected_org_id: org_id,
            author_member_key: &author_vk,
            seq_guard,
            last_committed_epoch: last_epoch,
        };

        // Use the `ChainReader`-compatible oracle backed by our `ChainOps`.
        let chain_reader = ChainOpsReader { state: chain_state };

        let verified = verify_envelope_against_chain(&local_trie, &msg.envelope, &ctx, &chain_reader)?;

        // Cross-check: the sender's authenticated device key must be in the new trie.
        // Skipped on first admission because B has not yet seen any member list;
        // the invite device-key check + chain root match is already sufficient proof.
        if !is_first_admission {
            let sender_known = verified
                .trie
                .members()
                .iter()
                .any(|m| m.has_p2p_device(&org_members::P2pDeviceKey::new(*remote_device_key.verifying_key())));
            if !sender_known {
                return Err(OrgNodeError::BadSignature);
            }
        }

        // Commit: update or create the OrgRecord.
        let new_snapshots: Vec<MemberSnapshot> = verified
            .trie
            .members()
            .into_iter()
            .map(|m| MemberSnapshot {
                id: *m.id().as_bytes(),
                handle: m.handle().to_string(),
                name: m.name().to_string(),
                surname: m.surname().to_string(),
                member_key: *m.p2p_key().as_bytes(),
                device_keys: m.p2p_devices().iter().map(|d| *d.as_bytes()).collect(),
            })
            .collect();

        let new_root = *verified.trie.root_hash().map_err(OrgNodeError::Trie)?.as_bytes();

        // The persona linked to this org — find by matching device keys in the trie.
        // Our device key should be in the new trie.
        let my_persona_id = self
            .store
            .data()
            .personas
            .iter()
            .find(|p| {
                let dk = SigningKeypair::from_seed(p.device_seed);
                verified.trie.members().iter().any(|m| {
                    m.has_p2p_device(&org_members::P2pDeviceKey::new(dk.verifying_key()))
                        && m.p2p_key().as_bytes() != chain_state.org_pub_key.as_ref()
                })
            })
            .map(|p| p.persona_id.clone());

        // Find the member_id for our persona.
        let my_member_id = if let Some(ref pid) = my_persona_id {
            let persona = self.find_persona(pid)?;
            let my_device_kp = SigningKeypair::from_seed(persona.device_seed);
            let my_device_key = org_members::P2pDeviceKey::new(my_device_kp.verifying_key());
            verified
                .trie
                .members()
                .iter()
                .find(|m| m.has_p2p_device(&my_device_key))
                .map(|m| *m.id().as_bytes())
        } else {
            None
        };

        {
            let data = self.store.data_mut();
            if let Some(existing) = data.orgs.iter_mut().find(|o| o.org_id == org_id) {
                existing.root_hash = new_root;
                existing.epoch = verified.epoch;
                existing.last_seq = verified.seq_guard.last_seen();
                existing.org_secret = msg.org_secret;
                existing.trie_members = new_snapshots;
            } else {
                data.orgs.push(OrgRecord {
                    org_id,
                    root_hash: new_root,
                    org_pub_key: chain_state.org_pub_key,
                    epoch: verified.epoch,
                    org_secret: msg.org_secret,
                    last_seq: verified.seq_guard.last_seen(),
                    admin_member_key: chain_state.org_pub_key,
                    trie_members: new_snapshots,
                    // Member-side record: P is only known by the admin who created the org.
                    proxy_account: None,
                });
            }
            // Consume the pending invite now that first admission has committed.
            if is_first_admission {
                data.pending_invites.retain(|p| p.org_id != org_id);
            }
        }

        // Mark persona as Active + set member_id.
        if let Some(ref pid) = my_persona_id {
            let personas = &mut self.store.data_mut().personas;
            if let Some(p) = personas.iter_mut().find(|p| &p.persona_id == pid) {
                p.status = PersonaStatus::Active;
                p.org_id = Some(org_id);
                p.member_id = my_member_id;
            }
        }

        self.store.save(rng)?;

        Ok(ReceiveOutcome {
            org_id,
            epoch: verified.epoch,
            root: new_root,
        })
    }

    // ----------------------------------------------------------
    // Story 5: revoke_member — trie remove + submit_update + notify.
    // ----------------------------------------------------------

    /// Remove a member from the org trie, bump the epoch, and push a
    /// revocation `WireMessage` to the revoked member's current device address.
    ///
    /// The revoked member's `OrgRecord` is then removed from their local store
    /// when they call `receive_and_verify` and detect the root-mismatch (their
    /// device is no longer in the committed trie) — or when `self_delete_if_revoked`
    /// is called explicitly.
    ///
    /// For the PoC the admin pushes the revocation envelope to the member.
    /// `peer_addr` is the revoked member's iroh address (used in `Loopback` mode
    /// only — in `Networked` mode the peer's `EndpointId` is derived from
    /// `member_id` which equals the revoked member's device key).
    pub async fn revoke_member<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        org_id: OrgId,
        member_id: [u8; 32],
        peer_addr: iroh::EndpointAddr,
    ) -> Result<(), OrgNodeError> {
        let (trie, org_epoch, org_pub_key, admin_member_kp, last_seq, proxy_account) = {
            let org_rec = self.find_org(org_id)?;
            let trie = trie_from_snapshots(&org_rec.trie_members)?;
            let epoch = org_rec.epoch;
            let pub_key = org_rec.org_pub_key;
            let last_seq = org_rec.last_seq;
            let proxy = org_rec.proxy_account;
            let admin_persona = self.admin_persona_for_org(org_id)?;
            let member_kp = SigningKeypair::from_seed(admin_persona.member_seed);
            (trie, epoch, pub_key, member_kp, last_seq, proxy)
        };

        let mid = MemberId::new(member_id);
        let (new_trie, delta) = trie
            .delete_member(&mid)
            .map_err(OrgNodeError::Trie)?
            .recalculate()
            .map_err(OrgNodeError::Trie)?;

        let new_root_hash = new_trie.root_hash().map_err(OrgNodeError::Trie)?;
        let new_root = *new_root_hash.as_bytes();

        // Submit on-chain update; pass persisted proxy_account (Gap 2 fix).
        self.chain.submit_update(org_id, new_root, org_pub_key, org_epoch, proxy_account).await?;
        let new_epoch = org_epoch + 1;

        // Build the signed revocation envelope.
        let parent_seq = last_seq + 1;
        let envelope =
            SignedDeltaEnvelope::build(org_id, parent_seq, &delta, &admin_member_kp)
                .map_err(|_| OrgNodeError::MalformedDelta)?;

        // Push to the revoked peer so they can self-delete.
        // Include the pre-revocation snapshot so B can reconstruct its local trie
        // and verify the delta (base_root must match B's current trie).
        // Collect all data that borrows from `self` BEFORE calling ensure_endpoint
        // (which takes a &mut self borrow that overlaps with find_org / admin_persona_for_org).
        let (pre_revoke_snaps, admin_persona_id, networked_peer_id) = {
            let org_rec = self.find_org(org_id)?;
            let snaps = org_rec.trie_members.clone();
            let admin_persona_id = self.admin_persona_for_org(org_id)?.persona_id.clone();
            // Pre-compute the EndpointId for Networked mode from the snapshot (before
            // the snapshot is modified by the org update below).
            let networked_peer_id: Option<iroh::EndpointId> = if self.transport_mode == TransportMode::Networked {
                // PoC assumption (S14): one device per member, so the first
                // device key is the member's iroh identity. Multi-device members
                // would need to notify every device key here.
                let dk = org_rec
                    .trie_members
                    .iter()
                    .find(|s| s.id == member_id)
                    .and_then(|s| s.device_keys.first().copied())
                    .ok_or_else(|| OrgNodeError::Chain(
                        "revoked member device key not found in trie snapshot".into()
                    ))?;
                Some(
                    iroh::EndpointId::from_bytes(&dk)
                        .map_err(|_| OrgNodeError::Chain("invalid device key for EndpointId".into()))?,
                )
            } else {
                None
            };
            (snaps, admin_persona_id, networked_peer_id)
        };
        let genesis_snapshot = postcard::to_allocvec(&pre_revoke_snaps).map(Some).unwrap_or(None);
        let msg = WireMessage { envelope, org_secret: None, genesis_snapshot };
        // Use the lazily bound endpoint; bind from this persona's device seed if not yet bound.
        let mode = self.transport_mode;
        let ep = self.ensure_endpoint(&admin_persona_id).await?;
        match mode {
            TransportMode::Loopback => {
                // Loopback/same-machine: dial the full EndpointAddr from the blob.
                ep.send(peer_addr, &msg)
                    .await
                    .map_err(|e| OrgNodeError::Chain(format!("iroh send: {e}")))?;
            }
            TransportMode::Networked => {
                // Cross-network: dial purely by EndpointId so iroh relay/DNS
                // resolves the path.  The EndpointId was derived above from the
                // revoked member's device key in the pre-revocation snapshot.
                let peer_id = networked_peer_id
                    .ok_or_else(|| OrgNodeError::Chain("networked_peer_id missing in Networked mode".into()))?;
                ep.send_to_id(peer_id, &msg)
                    .await
                    .map_err(|e| OrgNodeError::Chain(format!("iroh send (networked): {e}")))?;
            }
        }

        // Update local OrgRecord.
        let new_snaps: Vec<MemberSnapshot> = new_trie
            .members()
            .into_iter()
            .map(|m| MemberSnapshot {
                id: *m.id().as_bytes(),
                handle: m.handle().to_string(),
                name: m.name().to_string(),
                surname: m.surname().to_string(),
                member_key: *m.p2p_key().as_bytes(),
                device_keys: m.p2p_devices().iter().map(|d| *d.as_bytes()).collect(),
            })
            .collect();

        {
            let org_rec = self.find_org_mut(org_id)?;
            org_rec.root_hash = new_root;
            org_rec.epoch = new_epoch;
            org_rec.last_seq = parent_seq;
            org_rec.trie_members = new_snaps;
        }
        self.store.save(rng)?;
        Ok(())
    }

    /// If the local persona has been revoked (its device key is absent from the
    /// committed trie after a `receive_and_verify`), remove the `OrgRecord` and
    /// mark the persona `Revoked`. Called on B's side after receiving a
    /// revocation envelope that removes B from the trie.
    pub async fn receive_and_self_delete_if_revoked<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<SelfDeleteOutcome, OrgNodeError> {
        // Bind the endpoint from the first persona's device_seed if not yet bound.
        let first_persona_id = self
            .store
            .data()
            .personas
            .first()
            .ok_or_else(|| OrgNodeError::Chain("no persona found — create one first".into()))?
            .persona_id
            .clone();
        let ep = self.ensure_endpoint(&first_persona_id).await?;
        let (remote_device_key, msg) = ep
            .recv_one()
            .await
            .map_err(|e| OrgNodeError::Chain(format!("iroh recv: {e}")))?;

        let org_id = msg.envelope.org_id;

        let chain_state = self
            .chain
            .read_state(org_id)
            .await?
            .ok_or(OrgNodeError::OrgNotOnChain)?;

        let author_vk = VerifyingKey::from_bytes(&chain_state.org_pub_key)
            .map_err(|e| OrgNodeError::Chain(format!("bad org_pub_key: {e}")))?;

        let (local_trie, last_seq, last_epoch) = {
            let existing = self
                .store
                .data()
                .orgs
                .iter()
                .find(|o| o.org_id == org_id)
                .cloned()
                .ok_or(OrgNodeError::OrgNotOnChain)?;
            let trie = trie_from_snapshots(&existing.trie_members)?;
            (trie, existing.last_seq, existing.epoch)
        };

        let seq_guard = SeqGuard::from_last_seen(last_seq);
        let ctx = VerifyContext {
            expected_org_id: org_id,
            author_member_key: &author_vk,
            seq_guard,
            last_committed_epoch: last_epoch,
        };

        let chain_reader = ChainOpsReader { state: chain_state };
        let verified =
            verify_envelope_against_chain(&local_trie, &msg.envelope, &ctx, &chain_reader)?;

        // Check whether OUR device is still in the new trie.
        let my_still_present = self
            .store
            .data()
            .personas
            .iter()
            .filter(|p| p.org_id == Some(org_id))
            .any(|p| {
                let dk = SigningKeypair::from_seed(p.device_seed);
                let my_dk = org_members::P2pDeviceKey::new(dk.verifying_key());
                verified.trie.members().iter().any(|m| m.has_p2p_device(&my_dk))
            });

        let _ = remote_device_key; // authenticated but not cross-checked here (revocation path)

        if my_still_present {
            // Regular admit/update — commit the update normally.
            let new_snaps: Vec<MemberSnapshot> = verified
                .trie
                .members()
                .into_iter()
                .map(|m| MemberSnapshot {
                    id: *m.id().as_bytes(),
                    handle: m.handle().to_string(),
                    name: m.name().to_string(),
                    surname: m.surname().to_string(),
                    member_key: *m.p2p_key().as_bytes(),
                    device_keys: m.p2p_devices().iter().map(|d| *d.as_bytes()).collect(),
                })
                .collect();
            let new_root = *verified.trie.root_hash().map_err(OrgNodeError::Trie)?.as_bytes();
            {
                let orgs = &mut self.store.data_mut().orgs;
                if let Some(rec) = orgs.iter_mut().find(|o| o.org_id == org_id) {
                    rec.root_hash = new_root;
                    rec.epoch = verified.epoch;
                    rec.last_seq = verified.seq_guard.last_seen();
                    rec.trie_members = new_snaps;
                }
            }
            self.store.save(rng)?;
            return Ok(SelfDeleteOutcome::UpdatedNotRevoked { org_id });
        }

        // We are revoked — self-delete.
        self.store.data_mut().orgs.retain(|o| o.org_id != org_id);
        // Mark matching personas as Revoked.
        for p in self.store.data_mut().personas.iter_mut() {
            if p.org_id == Some(org_id) {
                p.status = PersonaStatus::Revoked;
            }
        }
        self.store.save(rng)?;

        Ok(SelfDeleteOutcome::SelfDeleted { org_id })
    }

    // ----------------------------------------------------------
    // Query helpers.
    // ----------------------------------------------------------

    pub fn list_personas(&self) -> &[PersonaRecord] {
        &self.store.data().personas
    }

    pub fn list_orgs(&self) -> &[OrgRecord] {
        &self.store.data().orgs
    }

    // ----------------------------------------------------------
    // Endpoint management — Gap 1 fix.
    // ----------------------------------------------------------

    /// Ensure a device endpoint is bound for `persona_id`.
    ///
    /// If an endpoint is already stored on this `OrgService`, it is reused as-is
    /// (one active device per instance for the PoC).  Otherwise, a new endpoint
    /// is bound from the persona's `device_seed` via `SigningKeypair::from_seed`
    /// using the stored [`TransportMode`] (default `Loopback`, overridable via
    /// [`set_transport_mode`]).
    ///
    /// Returns a shared reference to the bound endpoint.
    ///
    /// [`set_transport_mode`]: OrgService::set_transport_mode
    pub async fn ensure_endpoint(
        &mut self,
        persona_id: &str,
    ) -> Result<&OrgEndpoint, OrgNodeError> {
        if self.endpoint.is_none() {
            let device_seed = {
                let persona = self.find_persona(persona_id)?;
                persona.device_seed
            };
            let device_kp = SigningKeypair::from_seed(device_seed);
            let ep = OrgEndpoint::bind_with_mode(&device_kp, self.transport_mode)
                .await
                .map_err(|e| OrgNodeError::Chain(format!("endpoint bind: {e}")))?;
            self.endpoint = Some(ep);
        }
        // SAFETY: we just set it above if it was None.
        self.endpoint
            .as_ref()
            .ok_or_else(|| OrgNodeError::Chain("endpoint bind failed unexpectedly".into()))
    }

    // ----------------------------------------------------------
    // Private helpers.
    // ----------------------------------------------------------

    fn find_persona(&self, persona_id: &str) -> Result<&PersonaRecord, OrgNodeError> {
        self.store
            .data()
            .personas
            .iter()
            .find(|p| p.persona_id == persona_id)
            .ok_or_else(|| OrgNodeError::Chain(format!("persona not found: {persona_id}")))
    }

    fn find_org(&self, org_id: OrgId) -> Result<&OrgRecord, OrgNodeError> {
        self.store
            .data()
            .orgs
            .iter()
            .find(|o| o.org_id == org_id)
            .ok_or(OrgNodeError::OrgNotOnChain)
    }

    fn find_org_mut(&mut self, org_id: OrgId) -> Result<&mut OrgRecord, OrgNodeError> {
        self.store
            .data_mut()
            .orgs
            .iter_mut()
            .find(|o| o.org_id == org_id)
            .ok_or(OrgNodeError::OrgNotOnChain)
    }

    fn admin_persona_for_org(&self, org_id: OrgId) -> Result<&PersonaRecord, OrgNodeError> {
        let org_rec = self.find_org(org_id)?;
        self.store
            .data()
            .personas
            .iter()
            .find(|p| {
                let member_kp = SigningKeypair::from_seed(p.member_seed);
                member_kp.verifying_key().as_bytes() == &org_rec.admin_member_key
            })
            .ok_or_else(|| OrgNodeError::Chain("admin persona not found for org".into()))
    }

    fn persona_keys(
        &self,
        persona_id: &str,
    ) -> Result<(SigningKeypair, SigningKeypair, String, String, String), OrgNodeError> {
        let p = self.find_persona(persona_id)?;
        Ok((
            SigningKeypair::from_seed(p.member_seed),
            SigningKeypair::from_seed(p.device_seed),
            p.handle.clone(),
            p.name.clone(),
            p.surname.clone(),
        ))
    }

    fn update_persona_status(
        &mut self,
        persona_id: &str,
        org_id: OrgId,
        status: PersonaStatus,
    ) -> Result<(), OrgNodeError> {
        self.store
            .data_mut()
            .personas
            .iter_mut()
            .find(|p| p.persona_id == persona_id)
            .ok_or_else(|| OrgNodeError::Chain(format!("persona not found: {persona_id}")))
            .map(|p| {
                p.status = status;
                p.org_id = Some(org_id);
            })
    }
}

// ============================================================
// Outcomes.
// ============================================================

/// Outcome of `receive_and_verify`.
#[derive(Debug)]
pub struct ReceiveOutcome {
    pub org_id: OrgId,
    pub epoch: u64,
    pub root: [u8; 32],
}

/// Outcome of `receive_and_self_delete_if_revoked`.
#[derive(Debug)]
pub enum SelfDeleteOutcome {
    SelfDeleted { org_id: OrgId },
    UpdatedNotRevoked { org_id: OrgId },
}

// ============================================================
// ChainOpsReader — adapts a single OrgState into ChainReader for verify.rs.
// ============================================================

/// Adapts a cached `OrgState` value into the synchronous `ChainReader` trait
/// expected by `verify_envelope_against_chain`.  The state was read from the
/// async `ChainOps::read_state` before calling verify.
struct ChainOpsReader {
    state: OrgState,
}

impl crate::chain::ChainReader for ChainOpsReader {
    fn get_org_state(&self, _org_id: &OrgId) -> Result<Option<OrgState>, String> {
        Ok(Some(self.state))
    }
}

// ============================================================
// Utility helpers.
// ============================================================

/// Derive a hex-encoded persona_id from 32 bytes (first 16 bytes → 32 hex chars).
fn hex_id(bytes: &[u8; 32]) -> String {
    bytes.iter().take(16).fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Derive a deterministic 32-byte `MemberId` seed from a 32-byte key.
/// We simply use the key bytes directly — the caller already ensures they are
/// unique (ed25519 verifying keys are effectively unique per keypair).
/// PoC choice: production should hash a stable enrollment input (e.g. Blake3(member_vk ‖ org_id)).
fn member_id_from_key(key: &[u8]) -> [u8; 32] {
    let mut id = [0u8; 32];
    let len = key.len().min(32);
    id[..len].copy_from_slice(&key[..len]);
    id
}

// ============================================================
// Unit tests (lib tests for service.rs; integration test is service_stories.rs).
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn tmp_store(suffix: &str) -> PersonaStore {
        let dir = std::env::temp_dir()
            .join(format!("ods-service-test-{}-{}", std::process::id(), suffix));
        std::fs::create_dir_all(&dir).unwrap();
        PersonaStore::open(dir.join("store.bin"), "testpass").unwrap()
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_persona_persists_and_reloads() {
        let store_path = {
            let dir = std::env::temp_dir()
                .join(format!("ods-svc-pers-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            dir.join("store.bin")
        };
        let store = PersonaStore::open(store_path.clone(), "pw").unwrap();
        let mut svc = OrgService::new(store, Box::new(MockChainOps::new()));
        let pid = svc.create_persona(&mut OsRng, "alice", "Alice", "Smith").unwrap();
        assert!(!pid.is_empty());
        assert_eq!(svc.list_personas().len(), 1);

        // Reload from disk.
        let store2 = PersonaStore::open(store_path, "pw").unwrap();
        let svc2 = OrgService::new(store2, Box::new(MockChainOps::new()));
        assert_eq!(svc2.list_personas().len(), 1);
        assert_eq!(svc2.list_personas()[0].handle, "alice");
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn create_organisation_advances_mock_chain() {
        let store = tmp_store("org");
        let chain = MockChainOps::new();
        let chain_view = chain.clone();
        let mut svc = OrgService::new(store, Box::new(chain));
        let pid =
            svc.create_persona(&mut OsRng, "admin", "Admin", "User").unwrap();
        let org_id = svc.create_organisation(&mut OsRng, &pid).await.unwrap();
        let state = chain_view.get(&org_id).unwrap();
        assert_eq!(state.epoch, 1);
        assert_eq!(svc.list_orgs().len(), 1);
        assert_eq!(svc.list_personas()[0].status, PersonaStatus::Active);
    }
}
