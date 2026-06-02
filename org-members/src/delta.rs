use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use hashbrown::HashMap;

use crate::error::OrgMembersError;
use crate::hasher::TrieHasher;
use crate::node::Node;
use crate::smt::DefaultHashes;
use crate::trie::OrgTrie;
use crate::types::{MemberId, MemberLeaf, RootHash};

/// A set of changes anchored to a specific base trie root.
///
/// # Canonical-form invariant
///
/// Every `Delta` accepted by `OrgTrie::apply_delta` is in canonical form:
///
/// - `removed` is strictly increasing by `MemberId` and every id is present in
///   the trie at `base_root`.
/// - `upserted` is strictly increasing by `MemberId` and every leaf produces
///   an observable change vs. the current state at that id.
/// - `removed` and `upserted` are disjoint.
///
/// Combined with the fact that `recalculate()`, `calculate_delta()`, and
/// `pending_changes()` all produce canonical deltas by construction (via
/// `diff_recursive`'s left-then-right SMT traversal), this gives the higher-
/// level layer a strong guarantee: for any `(base_root, target_root)` pair,
/// there is exactly one postcard byte string of a `Delta` that `apply_delta`
/// will accept.
///
/// # What this crate does NOT do
///
/// `Delta` is scoped only by `base_root`. The following are the caller's
/// responsibility and MUST be enforced upstream of `apply_delta`:
///
/// - **Authentication** — verify a signature over `postcard(Delta)` bytes
///   against an admin/quorum key before applying.
/// - **Organisation binding** — wrap deltas in `(org_id, postcard(Delta),
///   signature)` envelopes; the lib has no notion of which organisation a
///   delta belongs to.
/// - **Replay protection across time** — `base_root` rejects deltas once the
///   trie has moved past their parent, but a trie that revisits a prior root
///   would accept a stale delta. Use a monotonic sequence number in the
///   envelope.
/// - **Authority** — `apply_delta` accepts any well-formed change; whether the
///   signer is allowed to make this change (quorum, role-based veto, rate
///   limits) is policy that lives above this crate.
/// - **Independent trusted root** — `CandidateTrie::verify_against`'s
///   `expected_root` argument must come from a path the attacker cannot
///   control (on-chain commit, signed admin attestation, etc.), not from the
///   same payload as the delta.
///
/// See `org-members/README.md` for the full enumeration of upstream security
/// responsibilities, and `docs/superpowers/specs/2026-05-28-org-members-
/// hyperbridge-review.md` for the threat model.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Delta {
    pub(crate) base_root: RootHash,
    pub(crate) removed: Vec<MemberId>,
    pub(crate) upserted: Vec<MemberLeaf>,
}

impl Delta {
    pub fn base_root(&self) -> &RootHash {
        &self.base_root
    }

    /// Member ids that were removed.
    pub fn removed(&self) -> &[MemberId] {
        &self.removed
    }

    pub fn upserted(&self) -> &[MemberLeaf] {
        &self.upserted
    }

    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.upserted.is_empty()
    }
}

/// Internal helpers for integration tests that need to construct adversarial
/// deltas (e.g., stale or duplicate removals, confusable upserts) without
/// going through `recalculate()`. Gated behind the `test-helpers` feature so
/// production builds cannot reach these mutators.
#[cfg(feature = "test-helpers")]
#[doc(hidden)]
pub mod test_support {
    use super::*;

    pub fn delta_set_removed(delta: &mut Delta, ids: Vec<MemberId>) {
        delta.removed = ids;
    }

    pub fn delta_set_upserted(delta: &mut Delta, leaves: Vec<MemberLeaf>) {
        delta.upserted = leaves;
    }
}

/// Result of `apply_delta()`. Cannot query members -- can only verify or drop.
pub struct CandidateTrie<H: TrieHasher> {
    pub(crate) root: Arc<Node>,
    pub(crate) defaults: Arc<DefaultHashes>,
    pub(crate) member_count: usize,
    pub(crate) root_hash: RootHash,
    pub(crate) skeleton_index: HashMap<String, String>,
    pub(crate) handle_index: HashMap<String, MemberId>,
    pub(crate) _hasher: core::marker::PhantomData<H>,
}

impl<H: TrieHasher> CandidateTrie<H> {
    pub fn root_hash(&self) -> RootHash {
        self.root_hash
    }

    pub fn verify_against(self, expected_root: &RootHash) -> Result<OrgTrie<H>, OrgMembersError> {
        if self.root_hash != *expected_root {
            return Err(OrgMembersError::VerificationFailed);
        }

        Ok(OrgTrie::from_candidate(
            self.root,
            self.defaults,
            self.member_count,
            self.root_hash,
            self.skeleton_index,
            self.handle_index,
        ))
    }
}

impl<H: TrieHasher> fmt::Debug for CandidateTrie<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateTrie")
            .field("root_hash", &self.root_hash)
            .field("member_count", &self.member_count)
            .finish()
    }
}
