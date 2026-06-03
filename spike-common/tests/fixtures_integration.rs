#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use spike_common::scenarios::{
    gating_fixture, org_pseudo_group_fixture, revocation_fixture, ScenarioFixture,
};

fn invariants(f: &ScenarioFixture) {
    assert!(!f.name.is_empty(), "fixture must name itself");
    assert!(!f.initial.members.is_empty(), "fixture starts with at least one member");
    assert!(!f.steps.is_empty(), "fixture has at least one step");
    assert!(
        f.expected_final.observable_assertions.iter().any(|a| !a.is_empty()),
        "fixture has at least one observable assertion",
    );
}

#[test]
fn revocation_fixture_invariants() {
    let f = revocation_fixture();
    invariants(&f);
    assert_eq!(f.name, "revocation");
}

#[test]
fn gating_fixture_invariants() {
    let f = gating_fixture();
    invariants(&f);
    assert_eq!(f.name, "gating");
}

#[test]
fn org_pseudo_group_fixture_invariants() {
    let f = org_pseudo_group_fixture();
    invariants(&f);
    assert_eq!(f.name, "org_pseudo_group");
}

#[test]
fn fixture_steps_apply_to_stub_trie() {
    use spike_common::resolver::MemberKeyResolver;

    let f = revocation_fixture();
    let initial = f.bootstrap_stub_trie();
    let final_trie = f.apply_to_stub_trie(initial);

    assert_eq!(
        final_trie.org_member_ids().len(),
        f.expected_final.member_count,
    );
}
