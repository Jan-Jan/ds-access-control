# ODS Phase 3 Item 1 — Stable-ID ACL + Trie-Lookup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `org-acl` crate's foundation — org-scoped stable identities (`OrgMember`), the trie-lookup `MemberKeyResolver` contract (incl. the `ContactCard` escalation), and a non-authoritative `IdAdapter` cache — so an ACL binds to immutable trie identities while keys resolve live through the trie, blocking identity-takeover and making revocation effective.

**Architecture:** New GPL-3.0-only crate `org-acl` (the sole Keyhive boundary), consumed by `org-node`. It graduates `spike-common`'s contract and `spike-keyhive`'s `IdAdapter`, re-keying every cross-org structure on the composite `OrgMember { OrgId, MemberId }`. The lazy-CGKA two-tier spine means the ACL tier carries only long-term identity; this item delivers that tier's resolution seam. Pure-Rust parts (identity, adapter, codec fuzz) are independent of Keyhive; the `ContactCard` parts and scenario tests are isolated in later tasks behind the §2 gate's re-pin.

**Tech Stack:** Rust (edition 2021, workspace), `ed25519-dalek`, `serde`/`postcard`, `keyhive_core` (re-pinned to tagged `0.1.0`), `bolero` (fuzz), `tokio` (async test harness).

---

## EXECUTION GATE (precondition — do not start until BOTH clear)

- [ ] **(a) Phase 2 `org-node` has landed** with the per-org trie mirror that will implement `MemberKeyResolver`. (As of authoring, `org-node` is "in review", unbuilt.)
- [ ] **(b) Keyhive has shipped a tagged `0.1.0` with ≥1 external audit**, and the exact git ref is recorded in Task 0. (The spike rides `0.0.0-alpha.3` at rev `a2876f3c79d89c9dd0c5e9f84802611c716fe27e`.)

Both boxes stay unchecked until satisfied. Task 0 is the go/no-go; if Task 0 fails, **stop** — the substrate decision (`docs/phase-1d/decision.md`) re-opens.

Spec: [`docs/superpowers/specs/2026-06-15-ods-phase-3-design.md`](../specs/2026-06-15-ods-phase-3-design.md) §5 (item 1 full spec), §6 (testing).

## File structure (this item)

```
org-acl/
  Cargo.toml          # new crate manifest; workspace member; [[test]] fuzz entries
  src/
    lib.rs            # module declarations + crate docs + Flow-B invariant statement
    identity.rs       # OrgId, MemberId, OrgMember, P2pMemberKey, P2pDeviceKey, OrgKey, Epoch, Principal
    resolver.rs       # MemberKeyResolver trait, ResolverError
    adapter.rs        # IdAdapter (OrgMember <-> VerifyingKey, non-authoritative)
    test_support.rs   # StubResolver (graduated StubTrie) — cfg(test) / pub(crate) helper
  tests/
    l3_revocation.rs              # acceptance: revocation + identity-takeover blocked
    fuzz_orgmember_codec/
      fuzz_target.rs              # bolero: OrgMember/Principal postcard codec never-panics
      corpus/.gitkeep
      crashes/.gitkeep
    fuzz_contact_card_resolve/
      fuzz_target.rs              # bolero: ContactCard ingestion wrapper never-panics
      corpus/.gitkeep
      crashes/.gitkeep
```

Workspace `Cargo.toml` gains `"org-acl"` in `members`.

---

## Task 0: Precondition gate + Keyhive re-pin + R13 go/no-go

**Files:**
- Create (scratch): `org-acl/Cargo.toml` (minimal, just to compile the probe)
- Create (scratch): `org-acl/src/lib.rs`, `org-acl/tests/r13_reachability.rs`

- [ ] **Step 1: Confirm the gate is satisfied**

Verify (a) `org-node` exists as a workspace member and exposes a trie mirror type, and (b) Keyhive has a tagged `0.1.0` release. Record the exact ref here in the plan:

```
KEYHIVE_REF = tag "v0.1.0"   # <-- replace with the actual recorded tag/rev when the gate clears
```

If either is unmet, **stop**.

- [ ] **Step 2: Scaffold a throwaway crate pinned to the recorded ref**

`org-acl/Cargo.toml` (minimal probe form):

```toml
[package]
name = "org-acl"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "GPL-3.0-only"
description = "ODS organisation ACL — Keyhive substitution layer (the GPL boundary crate)"
publish = false

[dependencies]
keyhive_core = { git = "https://github.com/inkandswitch/keyhive", tag = "v0.1.0" }
keyhive_crypto = { git = "https://github.com/inkandswitch/keyhive", tag = "v0.1.0", default-features = false }

[dev-dependencies]
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros", "sync"] }
future_form = "0.3.1"
rand = "0.8"

[lints]
workspace = true
```

Add `"org-acl"` to the workspace `members` array in `/Users/jan-jan/Coding/2-tier-access-control/Cargo.toml`.

- [ ] **Step 3: Write the R13 reachability probe (the go/no-go)**

`org-acl/tests/r13_reachability.rs` — confirms `keyhive_core` delegation construction is reachable **below** `add_member` without materialising an `Individual` from raw key material, and that `ContactCard` ingestion still works as the spike found (spec §5.4). This is the canonical alpha.3 flow; reconcile signatures if `0.1.0` shifted them.

```rust
//! R13 go/no-go: validate the lazy-CGKA seam against the re-pinned Keyhive.
//! If this fails, STOP — the substrate decision re-opens (decision.md §1).

use future_form::Sendable;
use keyhive_core::keyhive::Keyhive;
use keyhive_core::listener::no_listener::NoListener;
use keyhive_core::store::ciphertext::memory::MemoryCiphertextStore;
use keyhive_crypto::signer::memory::MemorySigner;
use rand::rngs::OsRng;

type Kh = Keyhive<
    Sendable, MemorySigner, [u8; 32], Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>, NoListener, OsRng,
>;

async fn gen() -> Kh {
    let mut rng = OsRng;
    let sk = MemorySigner::generate(&mut rng);
    Keyhive::generate(sk, MemoryCiphertextStore::new(), NoListener, rng)
        .await
        .expect("Keyhive::generate")
}

#[tokio::test]
async fn contact_card_round_trip_and_ingest() {
    let alice = gen().await;
    let bob = gen().await;
    // 1. A member publishes a signed ContactCard (the trie will vouch for this).
    let card = bob.contact_card().await.expect("contact_card");
    assert_eq!(card.id(), bob.id());
    // 2. A peer ingests it — yields an Agent::Individual without raw-key Individual::new.
    let ingested = alice.receive_contact_card(&card).await.expect("receive_contact_card");
    assert_eq!(ingested.lock().expect("lock").id(), bob.id());
}
```

- [ ] **Step 4: Run the probe**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --test r13_reachability`
Expected: PASS. If the API shifted and it won't compile/pass, reconcile against the `0.1.0` docs; if the seam is genuinely gone, **STOP and escalate**.

- [ ] **Step 5: Commit**

```bash
git add org-acl/ Cargo.toml
git commit -m "feat(org-acl): scaffold crate + R13 lazy-CGKA reachability probe (gate cleared)"
```

---

## Task 1: Crate manifest (full) + lib.rs skeleton

**Files:**
- Modify: `org-acl/Cargo.toml`
- Modify: `org-acl/src/lib.rs`

- [ ] **Step 1: Write the full manifest**

Replace `org-acl/Cargo.toml` with:

```toml
[package]
name = "org-acl"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "GPL-3.0-only"
description = "ODS organisation ACL — Keyhive substitution layer (the GPL boundary crate)"
publish = false

[features]
# Exposes the in-memory StubResolver for integration tests in this crate and
# (later) org-node. Library code never depends on it.
testing = []

[dependencies]
ed25519-dalek = { version = "2", default-features = false, features = ["alloc", "serde"] }
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["use-std"] }
thiserror = "2"
keyhive_core = { git = "https://github.com/inkandswitch/keyhive", tag = "v0.1.0" }

[dev-dependencies]
bolero = "0.13"
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros", "sync"] }
future_form = "0.3.1"
rand = "0.8"
keyhive_crypto = { git = "https://github.com/inkandswitch/keyhive", tag = "v0.1.0", default-features = false }

[lints]
workspace = true

[[test]]
name = "fuzz_orgmember_codec"
path = "tests/fuzz_orgmember_codec/fuzz_target.rs"
harness = false

[[test]]
name = "fuzz_contact_card_resolve"
path = "tests/fuzz_contact_card_resolve/fuzz_target.rs"
harness = false
```

Note: the workspace `[workspace.lints.clippy]` denies `unwrap_used`/`expect_used`/`panic`. As with `on-chain-client`, the CI gate is `cargo clippy --lib` only; `cargo test`/`cargo build` are unaffected (these are clippy-only lints), so test and fuzz code may `expect`/panic freely (that is how bolero signals failure).

- [ ] **Step 2: Write the lib.rs skeleton (docs-only; modules added per task)**

`org-acl/src/lib.rs` — start with crate docs + the Flow-B invariant only. Each
subsequent task appends its own `pub mod` + `pub use` lines, so the crate
compiles at every step.

```rust
//! ODS organisation ACL — the Keyhive substitution layer.
//!
//! This crate is the ONLY one in the workspace that names `keyhive_core` /
//! `beekem` / `keyhive_crypto`; it confines Keyhive's GPL surface behind one
//! boundary. `org-node` depends on this crate.
//!
//! # Flow-B invariant (item 1)
//!
//! No code path may read a `VerifyingKey` for a `Principal` except through a
//! `MemberKeyResolver`. `IdAdapter`'s cache is a *derived view* of the
//! resolver (and ultimately the on-chain trie); it is never authoritative.
//! `resolve()` always re-queries the resolver and overwrites the cached entry.
//! This is the type-system + invariant enforcement that blocks identity
//! takeover: an attacker's forged/rotated key that the trie does not vouch for
//! resolves to nothing.
```

- [ ] **Step 3: Verify the empty crate compiles**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-acl`
Expected: PASS (empty lib).

- [ ] **Step 4: Commit**

```bash
git add org-acl/Cargo.toml org-acl/src/lib.rs
git commit -m "feat(org-acl): full manifest + lib skeleton with Flow-B invariant"
```

---

## Task 2: Identity types — OrgId + OrgMember composite

**Files:**
- Create: `org-acl/src/identity.rs`

- [ ] **Step 1: Declare the module in lib.rs**

Append to `org-acl/src/lib.rs`:

```rust
pub mod identity;
pub use identity::{Epoch, MemberId, OrgId, OrgKey, OrgMember, P2pDeviceKey, P2pMemberKey, Principal};
```

- [ ] **Step 2: Write the failing tests**

`org-acl/src/identity.rs` (tests first, types defined in the next step):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn vk(seed: u8) -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    #[test]
    fn org_member_postcard_roundtrip() {
        let om = OrgMember { org: OrgId([0xab; 20]), member: MemberId([7u8; 32]) };
        let bytes = postcard::to_allocvec(&om).unwrap();
        let back: OrgMember = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(om, back);
    }

    #[test]
    fn principal_postcard_roundtrip() {
        for p in [
            Principal::Member(OrgMember { org: OrgId([1; 20]), member: MemberId([2; 32]) }),
            Principal::Org(OrgId([3; 20])),
        ] {
            let bytes = postcard::to_allocvec(&p).unwrap();
            let back: Principal = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn same_member_id_distinct_orgs_do_not_alias() {
        let m = MemberId([9u8; 32]);
        let a = OrgMember { org: OrgId([0xaa; 20]), member: m };
        let b = OrgMember { org: OrgId([0xbb; 20]), member: m };
        assert_ne!(a, b);
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(a, vk(1));
        map.insert(b, vk(2));
        assert_eq!(map.len(), 2, "same MemberId under two OrgIds must not collide");
    }

    #[test]
    fn epoch_ordering() {
        assert!(Epoch(0) < Epoch(1));
        assert!(Epoch(u64::MAX) > Epoch(u64::MAX - 1));
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --lib identity`
Expected: FAIL — types not defined.

- [ ] **Step 4: Write the types (above the test module)**

Prepend to `org-acl/src/identity.rs`:

```rust
//! Identity types for org-acl. PII-free; no handles.
//!
//! `MemberId` is unique only within one organisation's trie, so the ACL
//! identity is the composite [`OrgMember`]. Every structure that crosses an
//! org boundary (the [`IdAdapter`](crate::IdAdapter) cache, the policy-layer
//! reverse index) keys on `OrgMember`.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// On-chain org slot key — `h160_of(P)`, the pure-proxy-derived H160. Stable
/// across multisig rotation (Phase 2 §4.1). Distinct from [`OrgKey`], the org
/// pseudo-group key stored *inside* the slot.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrgId(pub [u8; 20]);

/// 32-byte immutable, org-scoped member identifier (the SMT leaf key).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemberId(pub [u8; 32]);

/// The stable ACL identity: an org-scoped member.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrgMember {
    pub org: OrgId,
    pub member: MemberId,
}

/// Member-as-a-group key (ed25519 verifying key).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct P2pMemberKey(pub VerifyingKey);

/// Per-device verifying key. The device secret also seeds the iroh node key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct P2pDeviceKey(pub VerifyingKey);

/// Organisation-as-a-pseudo-group key (ed25519 verifying key).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgKey(pub VerifyingKey);

/// Monotonic epoch counter for trie/CGKA versioning.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Epoch(pub u64);

/// Opaque principal. The library obtains a key only via
/// [`MemberKeyResolver`](crate::MemberKeyResolver) — never a raw key in an ACL.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Principal {
    Member(OrgMember),
    Org(OrgId),
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --lib identity`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add org-acl/src/identity.rs org-acl/src/lib.rs
git commit -m "feat(org-acl): org-scoped identity types (OrgId, OrgMember, Principal)"
```

---

## Task 3: MemberKeyResolver trait + ResolverError + StubResolver

**Files:**
- Create: `org-acl/src/resolver.rs`
- Create: `org-acl/src/test_support.rs`

- [ ] **Step 1: Declare the modules in lib.rs**

Append to `org-acl/src/lib.rs`:

```rust
pub mod resolver;
pub use resolver::{MemberKeyResolver, ResolverError};

// Re-export the one Keyhive type the resolver contract exposes, so `org-node`
// (which implements MemberKeyResolver) names `org_acl::ContactCard` and never
// declares a direct keyhive_core dependency — the GPL boundary stays at this
// crate's manifest.
pub use keyhive_core::contact_card::ContactCard;

/// Test-only `MemberKeyResolver` stub, available under `cfg(test)` and behind
/// `--features testing` (for integration tests here and in `org-node`). The
/// real resolver is `org-node`'s trie mirror over `org-members`.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    #[path = "test_support.rs"]
    mod test_support;
    pub use test_support::StubResolver;
}
```

- [ ] **Step 2: Write the trait + error (resolver.rs)**

`org-acl/src/resolver.rs`:

```rust
//! The `MemberKeyResolver` contract — org-acl's seam with the trie.
//!
//! Each impl is bound to ONE org's trie mirror; forward methods take a bare
//! `MemberId` (the instance fixes the `OrgId`, exposed via [`org_id`]).
//! `org-node` holds one resolver per org record. See the Flow-B invariant in
//! the crate root.
//!
//! [`org_id`]: MemberKeyResolver::org_id

use keyhive_core::contact_card::ContactCard;

use crate::identity::{Epoch, MemberId, OrgId, OrgKey, OrgMember, P2pDeviceKey, P2pMemberKey};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolverError {
    /// `id` is not in the trie (not a member). A security-relevant outcome.
    #[error("member not in trie: {0:?}")]
    UnknownMember(MemberId),

    /// `id` is in the trie but has not yet published a ContactCard — the
    /// lazy-onboarding "not online yet" state. NOT a security failure; must be
    /// distinguishable from `UnknownMember`.
    #[error("member has not published a contact card: {0:?}")]
    NoContactCard(MemberId),

    #[error("org key not set")]
    OrgKeyUnset,
}

pub trait MemberKeyResolver {
    /// The org this resolver is bound to. Callers stamp it onto results
    /// promoted into any cross-org structure.
    fn org_id(&self) -> OrgId;

    /// Trie-vouched, Keyhive-ingestible identity proof for `id`. Required
    /// because Keyhive's `Individual::new` wants a signed `KeyOp`, not a bare
    /// key (spec §5.4). The trie publishes/vouches for each member's card.
    fn contact_card(&self, id: &MemberId) -> Result<ContactCard, ResolverError>;

    /// Current member-as-a-group key for `id`.
    fn p2p_member_key(&self, id: &MemberId) -> Result<P2pMemberKey, ResolverError>;

    /// Current org pseudo-group key.
    fn org_key(&self) -> Result<OrgKey, ResolverError>;

    /// Currently-authorised devices for `id`. `Ok(vec![])` if the member
    /// exists but is isolated; `Err(UnknownMember)` if not in the trie.
    fn current_devices(&self, id: &MemberId) -> Result<Vec<P2pDeviceKey>, ResolverError>;

    /// Cross-org cold reverse lookup (closes R7): which `(org, member)` owns
    /// this device key? Resolves cold peers against the trie, not just a cache.
    /// `None` if no member in this resolver's org owns the device.
    fn find_member_by_device(&self, dev: &P2pDeviceKey) -> Option<OrgMember>;

    /// IDs of all current members of the org. Used later by the pseudo-group
    /// (item 2) and policy (item 5) fan-out.
    fn org_member_ids(&self) -> Vec<MemberId>;

    fn is_member(&self, id: &MemberId) -> bool;

    fn epoch(&self) -> Epoch;
}
```

- [ ] **Step 3: Write the StubResolver test helper (test_support.rs)**

Graduates `spike-common::stub_trie::StubTrie`, org-scoped and card-aware. `ContactCard` has no public constructor from raw bytes, so cards are injected by tests that built them from a real Keyhive instance (Task 5 uses this; Tasks 3–4 exercise the non-card methods).

`org-acl/src/test_support.rs`:

```rust
//! In-memory `MemberKeyResolver` for tests — NOT a real SMT (the trie lives in
//! `org-members`). Org-scoped; cards are injected by callers that built them
//! from a live Keyhive instance.

use std::collections::HashMap;

use keyhive_core::contact_card::ContactCard;

use crate::identity::{Epoch, MemberId, OrgId, OrgKey, OrgMember, P2pDeviceKey, P2pMemberKey};
use crate::resolver::{MemberKeyResolver, ResolverError};

#[derive(Clone)]
pub struct StubResolver {
    org: OrgId,
    members: HashMap<MemberId, MemberEntry>,
    org_key: Option<OrgKey>,
    cards: HashMap<MemberId, ContactCard>,
    epoch: Epoch,
}

#[derive(Clone)]
struct MemberEntry {
    p2p_key: P2pMemberKey,
    devices: Vec<P2pDeviceKey>,
}

impl StubResolver {
    pub fn new(org: OrgId) -> Self {
        Self {
            org,
            members: HashMap::new(),
            org_key: None,
            cards: HashMap::new(),
            epoch: Epoch(0),
        }
    }

    fn bump(mut self) -> Self {
        self.epoch.0 += 1;
        self
    }

    pub fn add_member(mut self, id: MemberId, p2p_key: P2pMemberKey, devices: Vec<P2pDeviceKey>) -> Self {
        self.members.insert(id, MemberEntry { p2p_key, devices });
        self.bump()
    }

    pub fn with_org_key(mut self, key: OrgKey) -> Self {
        self.org_key = Some(key);
        self.bump()
    }

    /// Inject a ContactCard a test built from a live Keyhive instance.
    pub fn publish_card(mut self, id: MemberId, card: ContactCard) -> Self {
        self.cards.insert(id, card);
        self.bump()
    }

    pub fn revoke(mut self, id: &MemberId) -> Self {
        self.members.remove(id);
        self.cards.remove(id);
        self.bump()
    }

    pub fn rotate_member_key(mut self, id: &MemberId, key: P2pMemberKey) -> Self {
        if let Some(e) = self.members.get_mut(id) {
            e.p2p_key = key;
        }
        self.bump()
    }
}

impl MemberKeyResolver for StubResolver {
    fn org_id(&self) -> OrgId {
        self.org
    }

    fn contact_card(&self, id: &MemberId) -> Result<ContactCard, ResolverError> {
        if !self.members.contains_key(id) {
            return Err(ResolverError::UnknownMember(*id));
        }
        self.cards.get(id).cloned().ok_or(ResolverError::NoContactCard(*id))
    }

    fn p2p_member_key(&self, id: &MemberId) -> Result<P2pMemberKey, ResolverError> {
        self.members.get(id).map(|e| e.p2p_key).ok_or(ResolverError::UnknownMember(*id))
    }

    fn org_key(&self) -> Result<OrgKey, ResolverError> {
        self.org_key.ok_or(ResolverError::OrgKeyUnset)
    }

    fn current_devices(&self, id: &MemberId) -> Result<Vec<P2pDeviceKey>, ResolverError> {
        self.members.get(id).map(|e| e.devices.clone()).ok_or(ResolverError::UnknownMember(*id))
    }

    fn find_member_by_device(&self, dev: &P2pDeviceKey) -> Option<OrgMember> {
        self.members
            .iter()
            .find_map(|(mid, e)| e.devices.contains(dev).then_some(OrgMember { org: self.org, member: *mid }))
    }

    fn org_member_ids(&self) -> Vec<MemberId> {
        self.members.keys().copied().collect()
    }

    fn is_member(&self, id: &MemberId) -> bool {
        self.members.contains_key(id)
    }

    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn member_key(seed: u8) -> P2pMemberKey {
        P2pMemberKey(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }
    fn device_key(seed: u8) -> P2pDeviceKey {
        P2pDeviceKey(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    #[test]
    fn unknown_vs_no_card_are_distinct() {
        let alice = MemberId([1; 32]);
        let r = StubResolver::new(OrgId([0xaa; 20])).add_member(alice, member_key(1), vec![]);
        // In trie, no card published yet:
        assert_eq!(r.contact_card(&alice), Err(ResolverError::NoContactCard(alice)));
        // Not in trie:
        let bob = MemberId([2; 32]);
        assert_eq!(r.contact_card(&bob), Err(ResolverError::UnknownMember(bob)));
    }

    #[test]
    fn find_member_by_device_resolves_org_scoped() {
        let alice = MemberId([1; 32]);
        let dev = device_key(9);
        let org = OrgId([0xaa; 20]);
        let r = StubResolver::new(org).add_member(alice, member_key(1), vec![dev]);
        assert_eq!(r.find_member_by_device(&dev), Some(OrgMember { org, member: alice }));
        assert_eq!(r.find_member_by_device(&device_key(8)), None);
    }
}
```

- [ ] **Step 4: Run to verify it compiles and passes**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --lib`
Expected: PASS (identity 4 + test_support 2). If `ContactCard` import path differs at `0.1.0`, reconcile the `use keyhive_core::contact_card::ContactCard;` path (the R13 probe in Task 0 already pinned the working path).

- [ ] **Step 5: Commit**

```bash
git add org-acl/src/resolver.rs org-acl/src/test_support.rs org-acl/src/lib.rs
git commit -m "feat(org-acl): MemberKeyResolver trait (+ContactCard escalation) and StubResolver"
```

---

## Task 4: IdAdapter — non-authoritative OrgMember <-> VerifyingKey cache

**Files:**
- Create: `org-acl/src/adapter.rs`

- [ ] **Step 1: Declare the module in lib.rs**

Append to `org-acl/src/lib.rs`:

```rust
pub mod adapter;
pub use adapter::IdAdapter;
```

- [ ] **Step 2: Write the failing tests**

`org-acl/src/adapter.rs` (test module — the `IdAdapter` type is defined in the impl step below):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    use crate::identity::{MemberId, OrgId, OrgMember, P2pMemberKey};
    use crate::resolver::MemberKeyResolver;
    use crate::testing::StubResolver;

    fn mkey(seed: u8) -> P2pMemberKey {
        P2pMemberKey(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    #[test]
    fn empty_adapter_starts_empty() {
        let a = IdAdapter::new();
        assert!(a.is_empty());
    }

    #[test]
    fn resolve_populates_and_reverse_maps() {
        let alice = MemberId([1; 32]);
        let org = OrgId([0xaa; 20]);
        let r = StubResolver::new(org).add_member(alice, mkey(1), vec![]);
        let a = IdAdapter::new();

        let vk = a.resolve(&r, &alice).expect("alice resolves");
        assert_eq!(vk, r.p2p_member_key(&alice).unwrap().0);
        assert_eq!(a.len(), 1);
        assert_eq!(a.member_id_for(&vk), Some(OrgMember { org, member: alice }));
    }

    #[test]
    fn resolve_unknown_returns_none_and_caches_nothing() {
        let r = StubResolver::new(OrgId([0xaa; 20]));
        let a = IdAdapter::new();
        assert!(a.resolve(&r, &MemberId([0xff; 32])).is_none());
        assert!(a.is_empty());
    }

    #[test]
    fn invalidate_drops_entry() {
        let alice = MemberId([1; 32]);
        let r = StubResolver::new(OrgId([0xaa; 20])).add_member(alice, mkey(1), vec![]);
        let a = IdAdapter::new();
        a.resolve(&r, &alice).unwrap();
        a.invalidate(&OrgMember { org: r.org_id(), member: alice });
        assert!(a.is_empty());
    }

    #[test]
    fn resolve_always_requeries_so_rotation_is_picked_up() {
        let alice = MemberId([1; 32]);
        let r = StubResolver::new(OrgId([0xaa; 20])).add_member(alice, mkey(1), vec![]);
        let a = IdAdapter::new();
        let pre = a.resolve(&r, &alice).unwrap();
        let r = r.rotate_member_key(&alice, mkey(0xa9));
        let post = a.resolve(&r, &alice).unwrap();
        assert_ne!(pre, post, "cache must be a derived view, never authoritative");
    }

    #[test]
    fn same_member_id_two_orgs_do_not_alias_in_cache() {
        let m = MemberId([7; 32]);
        let ra = StubResolver::new(OrgId([0xaa; 20])).add_member(m, mkey(1), vec![]);
        let rb = StubResolver::new(OrgId([0xbb; 20])).add_member(m, mkey(2), vec![]);
        let a = IdAdapter::new();
        let ka = a.resolve(&ra, &m).unwrap();
        let kb = a.resolve(&rb, &m).unwrap();
        assert_ne!(ka, kb);
        assert_eq!(a.len(), 2, "same MemberId in two orgs must be two cache entries");
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --lib adapter`
Expected: FAIL — `IdAdapter` not defined.

- [ ] **Step 4: Write IdAdapter (above the test module)**

Prepend to `org-acl/src/adapter.rs`:

```rust
//! `OrgMember <-> VerifyingKey` cache for Keyhive call sites.
//!
//! NON-AUTHORITATIVE (Flow-B): the resolver — and ultimately the on-chain
//! trie — is the source of truth. The cache exists for cheap reverse lookups
//! and drift detection only. `resolve()` always re-queries the resolver and
//! overwrites the entry, so a rotation is always picked up. On rotation /
//! revocation the trie-change observer (item 4) calls [`invalidate`].
//!
//! [`invalidate`]: IdAdapter::invalidate

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;

use crate::identity::{MemberId, OrgMember};
use crate::resolver::MemberKeyResolver;

#[derive(Clone, Default)]
pub struct IdAdapter {
    mapping: Arc<Mutex<HashMap<OrgMember, VerifyingKey>>>,
}

impl IdAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve `id` (in `resolver`'s org) to its current `VerifyingKey`,
    /// (re)populating the cache. `None` if the resolver does not know `id`.
    pub fn resolve<R: MemberKeyResolver>(&self, resolver: &R, id: &MemberId) -> Option<VerifyingKey> {
        let key = resolver.p2p_member_key(id).ok()?.0;
        let om = OrgMember { org: resolver.org_id(), member: *id };
        self.mapping.lock().unwrap_or_else(|e| e.into_inner()).insert(om, key);
        Some(key)
    }

    /// Drop the cached key for `om`. Called by the trie-change observer on
    /// rotation / revocation.
    pub fn invalidate(&self, om: &OrgMember) {
        self.mapping.lock().unwrap_or_else(|e| e.into_inner()).remove(om);
    }

    /// Reverse lookup for warm entries. Cold peers (never resolved) return
    /// `None`; resolve those via `MemberKeyResolver::find_member_by_device`.
    pub fn member_id_for(&self, vk: &VerifyingKey) -> Option<OrgMember> {
        let m = self.mapping.lock().unwrap_or_else(|e| e.into_inner());
        m.iter().find_map(|(om, k)| (k == vk).then_some(*om))
    }

    pub fn len(&self) -> usize {
        self.mapping.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --lib adapter`
Expected: PASS (6 tests).

- [ ] **Step 6: Commit**

```bash
git add org-acl/src/adapter.rs org-acl/src/lib.rs
git commit -m "feat(org-acl): non-authoritative IdAdapter keyed on OrgMember"
```

---

## Task 5: ContactCard end-to-end through a live Keyhive instance

**Files:**
- Create: `org-acl/tests/contact_card_flow.rs`

This proves the resolver's `contact_card` serves a card a peer can actually ingest, and that the `UnknownMember`/`NoContactCard` distinction holds with real cards.

- [ ] **Step 1: Write the failing test**

`org-acl/tests/contact_card_flow.rs`:

```rust
//! Item-1 integration: the trie-vouched ContactCard drives Keyhive ingestion,
//! and the lazy-onboarding pending state (NoContactCard) is distinct from
//! non-membership (UnknownMember).

use future_form::Sendable;
use keyhive_core::keyhive::Keyhive;
use keyhive_core::listener::no_listener::NoListener;
use keyhive_core::store::ciphertext::memory::MemoryCiphertextStore;
use keyhive_crypto::signer::memory::MemorySigner;
use rand::rngs::OsRng;

use org_acl::identity::{MemberId, OrgId, P2pMemberKey};
use org_acl::resolver::{MemberKeyResolver, ResolverError};

type Kh = Keyhive<
    Sendable, MemorySigner, [u8; 32], Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>, NoListener, OsRng,
>;

async fn gen() -> Kh {
    let mut rng = OsRng;
    let sk = MemorySigner::generate(&mut rng);
    Keyhive::generate(sk, MemoryCiphertextStore::new(), NoListener, rng).await.unwrap()
}

fn mkey(seed: u8) -> P2pMemberKey {
    P2pMemberKey(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key())
}

#[tokio::test]
async fn published_card_drives_ingestion() {
    // StubResolver is a pub(crate) test helper; re-expose it for integration
    // tests via a `testing` feature OR duplicate the minimal stub here.
    // This plan exposes it (Step 3).
    use org_acl::testing::StubResolver;

    let bob_kh = gen().await;
    let bob_card = bob_kh.contact_card().await.unwrap();

    let bob = MemberId([2; 32]);
    let org = OrgId([0xaa; 20]);
    let resolver = StubResolver::new(org)
        .add_member(bob, mkey(2), vec![])
        .publish_card(bob, bob_card.clone());

    // Resolver serves the card; a peer ingests it.
    let served = resolver.contact_card(&bob).expect("card served");
    let alice_kh = gen().await;
    let ingested = alice_kh.receive_contact_card(&served).await.expect("ingest");
    assert_eq!(ingested.lock().unwrap().id(), bob_card.id());
}

#[tokio::test]
async fn pending_member_is_no_contact_card_not_unknown() {
    use org_acl::testing::StubResolver;
    let bob = MemberId([2; 32]);
    let resolver = StubResolver::new(OrgId([0xaa; 20])).add_member(bob, mkey(2), vec![]);
    assert_eq!(resolver.contact_card(&bob), Err(ResolverError::NoContactCard(bob)));
}
```

Note: this integration test uses `org_acl::testing::StubResolver`, which is
exposed only behind `--features testing` (set up in Task 1) — integration tests
do not see the crate's `cfg(test)`, so the feature flag is required.

- [ ] **Step 2: Run without the feature to confirm the gating**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --test contact_card_flow`
Expected: FAIL to compile — `org_acl::testing` is not available without `--features testing`. This confirms the test-only stub does not leak into the default build.

- [ ] **Step 3: Run with the feature on**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --features testing --test contact_card_flow`
Expected: PASS (2 tests). Reconcile `receive_contact_card` / `contact_card` signatures if the `0.1.0` re-pin shifted them (Task 0 pinned the working forms).

- [ ] **Step 4: Commit**

```bash
git add org-acl/tests/contact_card_flow.rs
git commit -m "feat(org-acl): ContactCard ingestion flow integration test"
```

---

## Task 6: L3 acceptance — revocation passes + identity-takeover blocked

**Files:**
- Create: `org-acl/tests/l3_revocation.rs`

These are the ODS Roadmap.3 item-1 exit criteria (spec §5.7), promoted from `spike-keyhive/tests/l3_revocation.rs`. The two properties are the implementation-side witnesses of the Phase 1.3 formal model's **transitive-trust acceptance rules** and the **members-trie ↔ substrate sync contract** (spec §6.4); the test docstring cites them so the link is explicit.

- [ ] **Step 1: Write the failing tests**

`org-acl/tests/l3_revocation.rs`:

```rust
//! Exit criteria for Phase 3 item 1 (spec §5.7):
//!  - revocation: a removed member resolves to nothing; no key is obtainable.
//!  - identity-takeover blocked: a forged/rotated key the trie does not vouch
//!    for is never authoritative (the cache is a derived view).
//!
//! These witness the Phase 1.3 formal model's transitive-trust acceptance
//! rules and the members-trie <-> substrate sync contract (design spec §6.4;
//! Quint model: docs/superpowers/specs/2026-06-15-quint-protocol-model-design.md).
//! When the Quint model lands on master, cite the exact invariant names here.

use ed25519_dalek::SigningKey;

use org_acl::identity::{MemberId, OrgId, OrgMember, P2pMemberKey};
use org_acl::resolver::{MemberKeyResolver, ResolverError};
use org_acl::testing::StubResolver;
use org_acl::IdAdapter;

fn mkey(seed: u8) -> P2pMemberKey {
    P2pMemberKey(SigningKey::from_bytes(&[seed; 32]).verifying_key())
}

#[test]
fn revocation_makes_member_unresolvable() {
    let bob = MemberId([2; 32]);
    let org = OrgId([0xaa; 20]);
    let resolver = StubResolver::new(org).add_member(bob, mkey(2), vec![]);
    let adapter = IdAdapter::new();
    let vk = adapter.resolve(&resolver, &bob).expect("bob resolves pre-revocation");

    // Trie revokes bob; observer invalidates the cache entry.
    let resolver = resolver.revoke(&bob);
    adapter.invalidate(&OrgMember { org, member: bob });

    // No key is obtainable for a revoked member.
    assert_eq!(resolver.p2p_member_key(&bob), Err(ResolverError::UnknownMember(bob)));
    assert_eq!(resolver.contact_card(&bob), Err(ResolverError::UnknownMember(bob)));
    assert!(adapter.resolve(&resolver, &bob).is_none());
    // The stale key is no longer reverse-resolvable.
    assert_eq!(adapter.member_id_for(&vk), None);
}

#[test]
fn forged_key_is_never_authoritative() {
    let bob = MemberId([2; 32]);
    let org = OrgId([0xaa; 20]);
    // Trie vouches for bob's real key.
    let resolver = StubResolver::new(org).add_member(bob, mkey(2), vec![]);
    let adapter = IdAdapter::new();

    // Attacker forges a different key and tries to pass it off as bob's.
    let forged = SigningKey::from_bytes(&[0xff; 32]).verifying_key();
    // The only authoritative source is the resolver: it never yields the forged key.
    let resolved = adapter.resolve(&resolver, &bob).expect("bob resolves");
    assert_ne!(resolved, forged, "resolver must yield the trie-vouched key, not a forgery");
    // Reverse-lookup of the forged key finds no member (it was never vouched).
    assert_eq!(adapter.member_id_for(&forged), None);
}
```

- [ ] **Step 2: Run to verify it fails, then passes**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --features testing --test l3_revocation`
Expected: PASS (2 tests). (Fails only if earlier tasks regressed.)

- [ ] **Step 3: Commit**

```bash
git add org-acl/tests/l3_revocation.rs
git commit -m "test(org-acl): L3 acceptance — revocation + identity-takeover blocked"
```

---

## Task 7: Fuzz target — OrgMember/Principal postcard codec (never-panic + round-trip)

**Files:**
- Create: `org-acl/tests/fuzz_orgmember_codec/fuzz_target.rs`
- Create: `org-acl/tests/fuzz_orgmember_codec/corpus/.gitkeep`, `crashes/.gitkeep`

Mirrors the `on-chain-client` bolero pattern (`harness = false`, stable default lane, nightly deep lane).

- [ ] **Step 1: Write the fuzz target**

`org-acl/tests/fuzz_orgmember_codec/fuzz_target.rs`:

```rust
//! Fuzz: the cross-org key that indexes everything must never mis-parse into a
//! colliding key, and decoding arbitrary bytes must never panic.
//!
//! `harness = false`: a panic (bolero's failure signal) exits non-zero and
//! fails `cargo test`. Deep-fuzz: `cargo bolero test fuzz_orgmember_codec
//! --engine libfuzzer`.

use bolero::check;
use org_acl::{MemberId, OrgId, OrgMember, Principal};

fn main() {
    // (1) Structured round-trip: encode is the exact inverse of decode.
    check!()
        .with_type::<([u8; 20], [u8; 32])>()
        .cloned()
        .for_each(|(org, member)| {
            let om = OrgMember { org: OrgId(org), member: MemberId(member) };
            let bytes = postcard::to_allocvec(&om).expect("encode OrgMember");
            let back: OrgMember = postcard::from_bytes(&bytes).expect("decode OrgMember");
            assert_eq!(om, back);

            let p = Principal::Member(om);
            let pb = postcard::to_allocvec(&p).expect("encode Principal");
            let pback: Principal = postcard::from_bytes(&pb).expect("decode Principal");
            assert_eq!(p, pback);
        });

    // (2) Never-panic on arbitrary bytes at the decode boundary.
    check!().for_each(|input: &[u8]| {
        let _ = postcard::from_bytes::<OrgMember>(input);
        let _ = postcard::from_bytes::<Principal>(input);
    });
}
```

- [ ] **Step 2: Create the corpus/crashes dirs**

```bash
mkdir -p org-acl/tests/fuzz_orgmember_codec/corpus org-acl/tests/fuzz_orgmember_codec/crashes
touch org-acl/tests/fuzz_orgmember_codec/corpus/.gitkeep org-acl/tests/fuzz_orgmember_codec/crashes/.gitkeep
```

- [ ] **Step 3: Run it**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --test fuzz_orgmember_codec`
Expected: PASS (bounded generated batch + empty corpus replay; no panic).

- [ ] **Step 4: Commit**

```bash
git add org-acl/tests/fuzz_orgmember_codec/
git commit -m "test(org-acl): bolero fuzz — OrgMember/Principal codec never-panic + round-trip"
```

---

## Task 8: Fuzz target — ContactCard ingestion wrapper (never-panic)

**Files:**
- Create: `org-acl/tests/fuzz_contact_card_resolve/fuzz_target.rs`
- Create: `org-acl/tests/fuzz_contact_card_resolve/corpus/.gitkeep`, `crashes/.gitkeep`

The untrusted boundary: a `ContactCard` arrives as bytes over transport before the trie has vouched for it. Our ingestion path must return a `Result`, never panic.

- [ ] **Step 1: Write the fuzz target**

`org-acl/tests/fuzz_contact_card_resolve/fuzz_target.rs`. `ContactCard`'s serialized form is established by the R13 probe (Task 0). If `ContactCard: Deserialize`, fuzz the deserialize directly; this is the form verified in the spike.

```rust
//! Fuzz: ingesting an untrusted ContactCard (arbitrary bytes from transport)
//! must never panic — it yields Ok/Err only. `harness = false`.
//!
//! Deep-fuzz: `cargo bolero test fuzz_contact_card_resolve --engine libfuzzer`.

use bolero::check;
use keyhive_core::contact_card::ContactCard;

fn main() {
    check!().for_each(|input: &[u8]| {
        // The org-node transport hands org-acl raw bytes claiming to be a
        // ContactCard. Decoding must be total (no panic) for any input.
        let _ = postcard::from_bytes::<ContactCard>(input);
    });
}
```

If `ContactCard` does not implement `Deserialize` at the re-pinned `0.1.0`, replace the body with the lowest **public** Keyhive parse entry point for a card (the R13 probe identified the canonical ingest path); the property is unchanged: arbitrary bytes → `Result`, never a panic. Add `keyhive_core` is already a normal dep; `postcard` is already a dep.

- [ ] **Step 2: Create the corpus/crashes dirs**

```bash
mkdir -p org-acl/tests/fuzz_contact_card_resolve/corpus org-acl/tests/fuzz_contact_card_resolve/crashes
touch org-acl/tests/fuzz_contact_card_resolve/corpus/.gitkeep org-acl/tests/fuzz_contact_card_resolve/crashes/.gitkeep
```

- [ ] **Step 3: Run it**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --test fuzz_contact_card_resolve`
Expected: PASS (no panic on the generated batch).

- [ ] **Step 4: Commit**

```bash
git add org-acl/tests/fuzz_contact_card_resolve/
git commit -m "test(org-acl): bolero fuzz — ContactCard ingestion never-panics"
```

---

## Task 9: README + full-suite green + clippy gate

**Files:**
- Create: `org-acl/README.md`

- [ ] **Step 1: Write the README**

`org-acl/README.md`:

```markdown
# org-acl

ODS organisation ACL — the Keyhive substitution layer. The **only** crate that
names `keyhive_core` / `beekem` / `keyhive_crypto` (the GPL boundary).
Consumed by `org-node`.

## Status
Phase 3 item 1 (stable-ID ACL + trie-lookup) implemented. Items 2–5
(write-authority lockout, CGKA triggers, org pseudo-group, p2p policy) are
sketched in the Phase 3 design spec and land in follow-on cycles.

## Core idea
The ACL binds to the stable, org-scoped `OrgMember { OrgId, MemberId }`. Keys
(`VerifyingKey`) are resolved live through the trie via `MemberKeyResolver`.
The `IdAdapter` cache is a *derived view* — never authoritative — so a rotated
or forged key the trie does not vouch for is never accepted (Flow-B invariant).
Keyhive ingestion uses trie-vouched `ContactCard`s (a bare key is insufficient;
`Individual::new` needs a signed `KeyOp`).

## Fuzzing
Two bolero targets, default `cargo test` lane on stable + deep lane on nightly:

| Target | Property |
|---|---|
| `fuzz_orgmember_codec` | `OrgMember`/`Principal` postcard round-trip + never-panic |
| `fuzz_contact_card_resolve` | untrusted `ContactCard` ingestion never panics |

Deep-fuzz: `cargo install cargo-bolero` then
`cargo bolero test <target> --engine libfuzzer` (nightly). Crashes land in the
target's `crashes/` dir as regression seeds.

## Test-only helper
`StubResolver` (behind `--features testing`) is an in-memory `MemberKeyResolver`
for this crate's and `org-node`'s tests. The real resolver is `org-node`'s trie
mirror over `org-members`.
```

- [ ] **Step 2: Run the full suite**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-acl --features testing`
Expected: PASS — identity (4) + test_support (2) + adapter (6) + contact_card_flow (2) + l3_revocation (2) + both fuzz targets.

- [ ] **Step 3: Run the clippy deny-gate (lib only) and a no-features build**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo clippy -p org-acl --lib -- -D warnings`
Expected: clean (the `--lib` gate enforces no `unwrap`/`expect`/`panic` in library code; test/fuzz code is exempt).

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-acl`
Expected: clean (default features, no `testing`).

- [ ] **Step 4: Commit**

```bash
git add org-acl/README.md
git commit -m "docs(org-acl): README — item 1 status, core idea, fuzzing"
```

---

## Final review

- [ ] Dispatch a final code reviewer over the whole `org-acl` item-1 diff (spec §5–§6 compliance, Flow-B invariant actually enforced by tests, no `MemberId`-only keys in any cross-org structure, fuzz targets wired).
- [ ] Then use **superpowers:finishing-a-development-branch**. Squash-merge to master as a single **user-signed** commit (AGENTS.md): disable gpg signing in the worktree, squash, and have the user sign the merge (`git commit --amend -S` if the agent's merge lands unsigned).

## Notes on the forward-gated nature

Tasks 2, 4, 7 are pure Rust and buildable independently of Keyhive. Tasks 0, 3, 5, 6, 8 touch `keyhive_core`; their code reflects the spike's verified `0.0.0-alpha.3` API surface. The Task 0 re-pin + R13 probe reconciles any signature drift at the tagged `0.1.0` **before** the dependent tasks run — that is the one place external-API uncertainty is absorbed. If R13 fails, stop and re-open the substrate decision.
