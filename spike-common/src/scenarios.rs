//! Library-agnostic scenario fixtures and the data types each scenario
//! produces. The fixtures themselves live below as `revocation_fixture()`,
//! `gating_fixture()`, `org_pseudo_group_fixture()` accessor functions;
//! the *markdown* specs live in `spike-common/scenarios/*.md` (added by
//! Task 7) and are the human-readable contract.

use alloc::vec::Vec;

use crate::identity::{MemberId, OrgKey, P2pDeviceKey, P2pMemberKey};
use crate::stub_trie::StubTrie;

/// A library-agnostic scenario fixture loaded by both spikes' L3 tests.
#[derive(Clone, Debug)]
pub struct ScenarioFixture {
    pub name: &'static str,
    pub initial: InitialState,
    pub steps: Vec<Step>,
    pub expected_final: ExpectedFinal,
}

#[derive(Clone, Debug)]
pub struct InitialState {
    pub members: Vec<MemberSeed>,
    pub org_key: Option<OrgKey>,
}

#[derive(Clone, Debug)]
pub struct MemberSeed {
    pub label: &'static str,
    pub id: MemberId,
    pub p2p_key: P2pMemberKey,
    pub devices: Vec<P2pDeviceKey>,
}

#[derive(Clone, Debug)]
pub enum Step {
    RevokeMember { label: &'static str, id: MemberId },
    RemoveDevice { label: &'static str, id: MemberId, device: P2pDeviceKey },
    RotateMemberKey { label: &'static str, id: MemberId, new_key: P2pMemberKey },
    RotateOrgKey { new_key: OrgKey },
    AddMember { seed: MemberSeed },
}

#[derive(Clone, Debug)]
pub struct ExpectedFinal {
    pub member_count: usize,
    /// Free-form observable assertions, one per testable property. Spikes
    /// translate these into library-specific assertions. The matching
    /// markdown spec documents what each string means.
    pub observable_assertions: Vec<&'static str>,
}

impl ScenarioFixture {
    /// Build a `StubTrie` containing the fixture's initial state.
    pub fn bootstrap_stub_trie(&self) -> StubTrie {
        let mut trie = StubTrie::new();
        for m in &self.initial.members {
            trie = trie.add_member(m.id, m.p2p_key, m.devices.clone());
        }
        if let Some(org) = self.initial.org_key {
            trie = trie.with_org_key(org);
        }
        trie
    }

    /// Apply each step in order to a `StubTrie`.
    pub fn apply_to_stub_trie(&self, mut trie: StubTrie) -> StubTrie {
        for step in &self.steps {
            trie = match step {
                Step::RevokeMember { id, .. } => trie.stub_revoke(id),
                Step::RemoveDevice { id, device, .. } => trie.stub_remove_device(id, device),
                Step::RotateMemberKey { id, new_key, .. } => {
                    trie.stub_rotate_member_key(id, *new_key)
                }
                Step::RotateOrgKey { new_key } => trie.stub_rotate_org_key(*new_key),
                Step::AddMember { seed } => {
                    trie.add_member(seed.id, seed.p2p_key, seed.devices.clone())
                }
            };
        }
        trie
    }
}

// Fixture accessors. Each call rebuilds the fixture — cheap, allocations
// are small, and avoids a `Lazy` dependency. Tests use these once each.

#[cfg(feature = "std")]
mod fixture_builders {
    use alloc::vec;

    use ed25519_dalek::SigningKey;

    use super::*;

    fn sk(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    pub(super) fn alice_seed() -> MemberSeed {
        MemberSeed {
            label: "alice",
            id: MemberId([0xa1; 32]),
            p2p_key: P2pMemberKey(sk(0xa2).verifying_key()),
            devices: vec![P2pDeviceKey(sk(0xa3).verifying_key())],
        }
    }

    pub(super) fn bob_seed() -> MemberSeed {
        MemberSeed {
            label: "bob",
            id: MemberId([0xb1; 32]),
            p2p_key: P2pMemberKey(sk(0xb2).verifying_key()),
            devices: vec![P2pDeviceKey(sk(0xb3).verifying_key())],
        }
    }

    pub(super) fn org_key_initial() -> OrgKey {
        OrgKey(sk(0x01).verifying_key())
    }

    pub(super) fn alice_rotated_key() -> P2pMemberKey {
        P2pMemberKey(sk(0xaa).verifying_key())
    }
}

#[cfg(feature = "std")]
pub fn revocation_fixture() -> ScenarioFixture {
    use alloc::vec;
    use fixture_builders::*;

    let alice = alice_seed();
    let bob = bob_seed();
    let bob_id = bob.id;

    ScenarioFixture {
        name: "revocation",
        initial: InitialState {
            members: vec![alice, bob],
            org_key: Some(org_key_initial()),
        },
        steps: vec![Step::RevokeMember { label: "bob", id: bob_id }],
        expected_final: ExpectedFinal {
            member_count: 1,
            observable_assertions: vec![
                "bob's device cannot decrypt new doc payloads after revocation",
                "alice's device can still decrypt the doc",
                "(D)CGKA has advanced one epoch",
            ],
        },
    }
}

#[cfg(feature = "std")]
pub fn gating_fixture() -> ScenarioFixture {
    use alloc::vec;
    use fixture_builders::*;

    let alice = alice_seed();
    let bob = bob_seed();
    let bob_id = bob.id;

    ScenarioFixture {
        name: "gating",
        initial: InitialState {
            members: vec![alice, bob],
            org_key: Some(org_key_initial()),
        },
        steps: vec![Step::RevokeMember { label: "bob", id: bob_id }],
        expected_final: ExpectedFinal {
            member_count: 1,
            observable_assertions: vec![
                "an open p2p sync session from bob's device is terminated within the test's timeout",
                "a fresh sync attempt from bob's device is rejected by the conn policy",
                "alice's session remains open",
            ],
        },
    }
}

#[cfg(feature = "std")]
pub fn org_pseudo_group_fixture() -> ScenarioFixture {
    use alloc::vec;
    use fixture_builders::*;

    let alice = alice_seed();
    let bob = bob_seed();
    let alice_id = alice.id;

    ScenarioFixture {
        name: "org_pseudo_group",
        initial: InitialState {
            members: vec![alice, bob],
            org_key: Some(org_key_initial()),
        },
        steps: vec![Step::RotateMemberKey {
            label: "alice",
            id: alice_id,
            new_key: alice_rotated_key(),
        }],
        expected_final: ExpectedFinal {
            member_count: 2,
            observable_assertions: vec![
                "a doc whose ACL grants the org-as-pseudo-group is readable by alice's new key",
                "the same doc is readable by bob without any explicit ACL change",
                "(D)CGKA recompute was triggered for org-keyed docs",
            ],
        },
    }
}
