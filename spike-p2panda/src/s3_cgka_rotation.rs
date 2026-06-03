//! Gate 3 substitution: (D)CGKA recompute on trie key change.
//!
//! See `evidence/s3.md` for findings.
//!
//! ## Design
//!
//! `Dcgka<ID, OP, PKI, DGM, KMG>` is fully generic over `PKI`. Gate 3 exercises
//! two flows:
//!
//! - **Flow B (compute):** resolver provides identity keys + pre-key bundles to
//!   a `KeyRegistry<DcgkaMemberId>` (the library's own PKI store); `Dcgka::create`
//!   and `Dcgka::process` succeed with resolver-derived key material.
//!
//! - **Flow C (recompute on rotation):** trie key rotation → rebuild PKI from
//!   resolver → call `trigger_recompute` → new group secret. The
//!   `KeyRegistry::identity_key` then returns the *new* key, not the old one.
//!
//! ## Orphan-rule note
//!
//! `p2panda_encryption::traits::IdentityHandle` cannot be implemented for
//! `spike_common::identity::MemberId` directly in this crate because both are
//! foreign types. We introduce `DcgkaMemberId` — a newtype defined here — so
//! the impl is local.
//!
//! ## Key-bundle construction note
//!
//! Building a `LongTermKeyBundle` requires signing a pre-key with the member's
//! identity secret. The test fixture helpers (`build_member_states`,
//! `init_g3_dcgka_state`) live in the test files because they depend on
//! `KeyManager::init_and_generate_prekey` which is only available under the
//! `test_utils` feature of `p2panda-encryption`. Keeping them in the test crate
//! avoids a feature-flag dependency leak into the production library code.

use std::collections::HashSet;
use std::convert::Infallible;
use std::marker::PhantomData;

use p2panda_encryption::crypto::Rng;
use p2panda_encryption::data_scheme::dcgka::{
    Dcgka, DcgkaState, GroupSecretOutput, OperationOutput, ProcessInput,
};
use p2panda_encryption::data_scheme::group_secret::{GroupSecret, SecretBundle, SecretBundleState};
use p2panda_encryption::key_manager::KeyManager;
use p2panda_encryption::key_registry::{KeyRegistry, KeyRegistryState};
use p2panda_encryption::traits::{GroupMembership, IdentityHandle, OperationId};
use serde::{Deserialize, Serialize};
use spike_common::identity::MemberId;

// ---------------------------------------------------------------------------
// DcgkaMemberId — local newtype so we can impl IdentityHandle
// ---------------------------------------------------------------------------

/// Newtype over [`MemberId`] that implements [`IdentityHandle`].
///
/// `IdentityHandle` is defined in `p2panda-encryption`; `MemberId` is defined
/// in `spike-common`. The orphan rule forbids implementing a foreign trait for
/// a foreign type. `DcgkaMemberId` is defined here, so the impl is local.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DcgkaMemberId(pub MemberId);

impl IdentityHandle for DcgkaMemberId {}

impl std::fmt::Display for DcgkaMemberId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DcgkaMemberId({:x?})", &self.0.0[..4])
    }
}

// ---------------------------------------------------------------------------
// DcgkaOpId — local operation-ID type for DCGKA message sequencing
// ---------------------------------------------------------------------------

/// Simple (member_idx, seq) operation ID for DCGKA control-message ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DcgkaOpId {
    pub member_idx: u64,
    pub seq: u64,
}

impl DcgkaOpId {
    pub fn new(member_idx: u64, seq: u64) -> Self {
        Self { member_idx, seq }
    }
}

impl OperationId for DcgkaOpId {}

// ---------------------------------------------------------------------------
// LocalDgm — minimal local GroupMembership (avoids test_utils dependency)
// ---------------------------------------------------------------------------

/// Minimal in-memory `GroupMembership` implementation.
///
/// Mirrors `p2panda_encryption::data_scheme::test_utils::dgm::TestDgm` in
/// behaviour but is defined here so gate-3 code does not require the
/// `test_utils` feature of `p2panda-encryption` in production builds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDgm<ID, OP> {
    _marker: PhantomData<(ID, OP)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDgmState<ID, OP>
where
    ID: IdentityHandle,
{
    #[allow(dead_code)]
    my_id: ID,
    members: HashSet<ID>,
    _marker: PhantomData<OP>,
}

impl<ID, OP> GroupMembership<ID, OP> for LocalDgm<ID, OP>
where
    ID: IdentityHandle + Serialize + for<'a> Deserialize<'a>,
    OP: OperationId + Serialize + for<'a> Deserialize<'a>,
{
    type State = LocalDgmState<ID, OP>;
    type Error = Infallible;

    fn create(my_id: ID, initial_members: &[ID]) -> Result<Self::State, Self::Error> {
        Ok(LocalDgmState {
            my_id,
            members: HashSet::from_iter(initial_members.iter().cloned()),
            _marker: PhantomData,
        })
    }

    fn from_welcome(my_id: ID, y: Self::State) -> Result<Self::State, Self::Error> {
        Ok(LocalDgmState {
            my_id,
            members: y.members,
            _marker: PhantomData,
        })
    }

    fn add(
        mut y: Self::State,
        _adder: ID,
        added: ID,
        _operation_id: OP,
    ) -> Result<Self::State, Self::Error> {
        y.members.insert(added);
        Ok(y)
    }

    fn remove(
        mut y: Self::State,
        _remover: ID,
        removed: &ID,
        _operation_id: OP,
    ) -> Result<Self::State, Self::Error> {
        y.members.remove(removed);
        Ok(y)
    }

    fn members(y: &Self::State) -> Result<HashSet<ID>, Self::Error> {
        Ok(y.members.clone())
    }
}

impl<ID, OP> LocalDgm<ID, OP>
where
    ID: IdentityHandle + Serialize + for<'a> Deserialize<'a>,
{
    /// Initialises group membership state for a single member (empty — no
    /// initial members; `Dcgka::create` populates membership via the DGM).
    pub fn init(my_id: ID) -> LocalDgmState<ID, OP> {
        LocalDgmState {
            my_id,
            members: HashSet::new(),
            _marker: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Type alias for the gate-3 DCGKA state
// ---------------------------------------------------------------------------

/// Concrete DCGKA state type used throughout gate 3.
///
/// - `ID` = `DcgkaMemberId` — resolver-bridged member identity
/// - `OP` = `DcgkaOpId` — (member_idx, seq) operation identifier
/// - `PKI` = `KeyRegistry<DcgkaMemberId>` — library's in-memory PKI store,
///   populated from the `MemberKeyResolver` at init and after each rotation
/// - `DGM` = `LocalDgm` — local minimal group-membership state (no test_utils)
/// - `KMG` = `KeyManager` — library's key manager holding each node's secrets
pub type G3DcgkaState = DcgkaState<
    DcgkaMemberId,
    DcgkaOpId,
    KeyRegistry<DcgkaMemberId>,
    LocalDgm<DcgkaMemberId, DcgkaOpId>,
    KeyManager,
>;

// ---------------------------------------------------------------------------
// trigger_recompute — drive DCGKA update after trie rotation (Flow C)
// ---------------------------------------------------------------------------

/// Result type for [`trigger_recompute`].
pub type RecomputeResult = Result<
    (
        G3DcgkaState,
        OperationOutput<DcgkaMemberId, DcgkaOpId, LocalDgm<DcgkaMemberId, DcgkaOpId>>,
        SecretBundleState,
        GroupSecret,
    ),
    Box<dyn std::error::Error>,
>;

/// Drives a DCGKA group-secret update for the calling member.
///
/// Called after the trie observer signals a key rotation for a member in the
/// group's ACL. Injects a fresh PKI (built from the updated resolver) into the
/// state and calls `Dcgka::update`, producing a new `GroupSecret`.
///
/// Returns the updated state, the `OperationOutput` (control + direct messages
/// to distribute), the new `SecretBundleState`, and the new `GroupSecret`.
pub fn trigger_recompute(
    state: G3DcgkaState,
    bundle: SecretBundleState,
    new_pki: KeyRegistryState<DcgkaMemberId>,
    rng: &Rng,
) -> RecomputeResult {
    // Inject updated PKI (fresh key material after rotation).
    let mut state = state;
    state.pki = new_pki;

    // Generate a new group secret for the next epoch.
    let new_secret = SecretBundle::generate(&bundle, rng)?;

    // Distribute via DCGKA update.
    let (state_i, output) = Dcgka::update(state, &new_secret, rng)?;

    let bundle_i = SecretBundle::insert(bundle, new_secret.clone());

    Ok((state_i, output, bundle_i, new_secret))
}

// ---------------------------------------------------------------------------
// process_g3_update — process an incoming update control message
// ---------------------------------------------------------------------------

/// Processes an incoming DCGKA update control message for a recipient node.
pub fn process_g3_update(
    state: G3DcgkaState,
    input: ProcessInput<DcgkaMemberId, DcgkaOpId, LocalDgm<DcgkaMemberId, DcgkaOpId>>,
) -> Result<(G3DcgkaState, GroupSecretOutput), Box<dyn std::error::Error>> {
    let (state_i, output) = Dcgka::process(state, input)?;
    Ok((state_i, output))
}
