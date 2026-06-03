#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use spike_common::identity::{MemberId, P2pDeviceKey, P2pMemberKey};
use spike_common::resolver::{MemberKeyResolver, ResolverError};
use spike_common::stub_trie::StubTrie;

fn make_signing(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

#[test]
fn fresh_member_has_key_and_devices() {
    let alice = MemberId([1u8; 32]);
    let alice_p2p = P2pMemberKey(make_signing(2).verifying_key());
    let alice_dev_1 = P2pDeviceKey(make_signing(3).verifying_key());

    let trie = StubTrie::new()
        .add_member(alice, alice_p2p, vec![alice_dev_1]);

    assert!(trie.is_member(&alice));
    assert_eq!(trie.p2p_member_key(&alice).unwrap(), alice_p2p);
    assert_eq!(trie.current_devices(&alice).unwrap(), vec![alice_dev_1]);
    assert_eq!(trie.epoch().0, 1);
}

#[test]
fn unknown_member_lookup_errors() {
    let trie = StubTrie::new();
    let ghost = MemberId([99u8; 32]);
    assert_eq!(trie.p2p_member_key(&ghost), Err(ResolverError::UnknownMember(ghost)));
}

#[test]
fn revoke_member_removes_keys_and_bumps_epoch() {
    let alice = MemberId([1u8; 32]);
    let alice_p2p = P2pMemberKey(make_signing(2).verifying_key());
    let trie = StubTrie::new().add_member(alice, alice_p2p, vec![]);
    let epoch_before = trie.epoch().0;

    let trie = trie.stub_revoke(&alice);

    assert!(!trie.is_member(&alice));
    assert_eq!(trie.p2p_member_key(&alice), Err(ResolverError::UnknownMember(alice)));
    assert!(trie.epoch().0 > epoch_before);
}

#[test]
fn org_key_set_then_rotated() {
    use spike_common::identity::OrgKey;
    let initial = OrgKey(make_signing(10).verifying_key());
    let rotated = OrgKey(make_signing(11).verifying_key());

    let trie = StubTrie::new().with_org_key(initial);
    assert_eq!(trie.org_key().unwrap(), initial);

    let trie = trie.stub_rotate_org_key(rotated);
    assert_eq!(trie.org_key().unwrap(), rotated);
}

#[test]
fn isolated_member_returns_empty_device_set() {
    let alice = MemberId([1u8; 32]);
    let alice_p2p = P2pMemberKey(make_signing(2).verifying_key());
    let trie = StubTrie::new().add_member(alice, alice_p2p, vec![]);

    assert_eq!(trie.current_devices(&alice).unwrap(), Vec::<P2pDeviceKey>::new());
}

#[test]
fn org_member_ids_enumerates_current_members() {
    let alice = MemberId([1u8; 32]);
    let bob = MemberId([2u8; 32]);
    let trie = StubTrie::new()
        .add_member(alice, P2pMemberKey(make_signing(3).verifying_key()), vec![])
        .add_member(bob, P2pMemberKey(make_signing(4).verifying_key()), vec![]);

    let mut ids = trie.org_member_ids();
    ids.sort();
    let mut expected = vec![alice, bob];
    expected.sort();
    assert_eq!(ids, expected);
}
