#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// L2 test: gate 1 — integrated stable-ID ACL flow.
//
// Flow A from §Data flow: doc owner grants ACL right; ACL entry stores
// Principal, not raw key; library resolves the key at use time.
//
// What we verify:
//   Test 1 — materialise_actor_id returns ActorId derived from the trie key.
//   Test 2 — rotation tracking: after rotating a member's key the next call
//             to materialise_actor_id returns the NEW ActorId. This is the
//             runtime confirmation of Probe 3 from Task 4 (previously skipped).
//   Test 3 — Principal::Org resolves via org_key.
//   Test 4 — unknown principal returns a clean error (not a panic).
//   Test 5 — ResolverPki::identity_key_with_resolver returns the current key.
//   Test 6 — IdentityRegistry::identity_key static method via ResolverPki as Y.
//   Test 7 — IdentityRegistry layer rotation tracking.

use ed25519_dalek::SigningKey;
use p2panda_spaces::ActorId;
use p2panda_encryption::traits::IdentityRegistry;
use spike_common::identity::{MemberId, OrgKey, P2pMemberKey, Principal};
use spike_common::stub_trie::StubTrie;
use spike_p2panda::s1_stable_id_acl::{ResolverPki, materialise_actor_id};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn p2p_key(seed: u8) -> P2pMemberKey {
    P2pMemberKey(signing_key(seed).verifying_key())
}

fn org_key_from_seed(seed: u8) -> OrgKey {
    OrgKey(signing_key(seed).verifying_key())
}

const ALICE_ID: MemberId = MemberId([0xa1u8; 32]);

// ---------------------------------------------------------------------------
// Test 1 — materialise_actor_id returns ActorId derived from resolver key
// ---------------------------------------------------------------------------

#[test]
fn flow_a_member_delegation_materialises_via_resolver() {
    let alice_k1 = p2p_key(0x01);
    let trie = StubTrie::new().add_member(ALICE_ID, alice_k1, vec![]);

    let actor = materialise_actor_id(&trie, &Principal::Member(ALICE_ID))
        .expect("Alice is in the trie; should resolve");

    // Confirm the ActorId carries the bytes of alice_k1.
    let expected: ActorId = ActorId::from_bytes(alice_k1.0.as_bytes())
        .expect("valid ed25519 key bytes → valid ActorId");
    assert_eq!(actor, expected, "ActorId should match the resolver's current key K1");
}

// ---------------------------------------------------------------------------
// Test 2 — rotation tracking (the key Probe 3 assertion)
// ---------------------------------------------------------------------------

/// KEY ASSERTION: after rotating a member's key in the trie, the next call to
/// `materialise_actor_id` returns the NEW `ActorId(K2)`, not the stale `ActorId(K1)`.
///
/// This is the runtime confirmation of Probe 3 from Task 4 (l1_p2panda_spaces.rs)
/// which was skipped due to scaffolding cost.
///
/// The TraitImpl salvage path's core property: call-time resolution means the spaces
/// wrapper tracks key rotation automatically — no explicit cache invalidation.
#[test]
fn flow_a_rotation_tracking_materialises_new_key() {
    let alice_k1 = p2p_key(0x01);
    let alice_k2 = p2p_key(0x02); // rotated key

    let trie = StubTrie::new().add_member(ALICE_ID, alice_k1, vec![]);

    // Before rotation — should return ActorId(K1).
    let actor_before = materialise_actor_id(&trie, &Principal::Member(ALICE_ID))
        .expect("should resolve before rotation");
    let expected_k1: ActorId = ActorId::from_bytes(alice_k1.0.as_bytes()).unwrap();
    assert_eq!(
        actor_before, expected_k1,
        "before rotation: ActorId should be derived from K1"
    );

    // Rotate Alice's key to K2 in the trie.
    let trie = trie.stub_rotate_member_key(&ALICE_ID, alice_k2);

    // After rotation — must return ActorId(K2), not K1.
    let actor_after = materialise_actor_id(&trie, &Principal::Member(ALICE_ID))
        .expect("should resolve after rotation");
    let expected_k2: ActorId = ActorId::from_bytes(alice_k2.0.as_bytes()).unwrap();
    assert_eq!(
        actor_after, expected_k2,
        "after rotation: ActorId must reflect NEW key K2"
    );

    // KEY: the two ActorIds are different — rotation produced a new actor identity.
    assert_ne!(
        actor_before, actor_after,
        "K1 and K2 must produce different ActorIds — rotation is tracked"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — Principal::Org materialises via org_key
// ---------------------------------------------------------------------------

#[test]
fn flow_a_org_delegation_materialises_via_resolver() {
    let org_k = org_key_from_seed(0xdd);
    let trie = StubTrie::new().with_org_key(org_k);

    let actor = materialise_actor_id(&trie, &Principal::Org)
        .expect("org key is set; should resolve");

    let expected: ActorId = ActorId::from_bytes(org_k.0.as_bytes()).unwrap();
    assert_eq!(actor, expected, "ActorId should match the org key");
}

// ---------------------------------------------------------------------------
// Test 4 — unknown principal returns error (not a panic)
// ---------------------------------------------------------------------------

#[test]
fn flow_a_unknown_principal_returns_error() {
    let trie = StubTrie::new(); // empty — no members, no org key

    let result = materialise_actor_id(&trie, &Principal::Member(ALICE_ID));
    assert!(result.is_err(), "Unknown member should return ResolverError, not panic");

    let result_org = materialise_actor_id(&trie, &Principal::Org);
    assert!(result_org.is_err(), "Unset org key should return ResolverError");
}

// ---------------------------------------------------------------------------
// Test 5 — ResolverPki::identity_key_with_resolver returns current key
// ---------------------------------------------------------------------------

/// Demonstrates the IdentityRegistry layer: `ResolverPki` wraps a resolver and
/// returns the current X25519-shaped identity key for a given `MemberId`.
///
/// This is the evidence that the encryption layer (DCGKA) can be given
/// stable-ID semantics at the `IdentityRegistry` level.
#[test]
fn identity_registry_returns_resolver_key() {
    let alice_k1 = p2p_key(0x01);
    let trie = StubTrie::new().add_member(ALICE_ID, alice_k1, vec![]);

    let pki = ResolverPki::new(trie);
    let key = pki
        .identity_key_with_resolver(&ALICE_ID)
        .expect("Alice is in the trie");

    let key = key.expect("key should be Some for a known member");
    // X25519PublicKey bytes should match ed25519 compressed bytes of alice_k1.
    assert_eq!(
        key.as_bytes(),
        alice_k1.0.as_bytes(),
        "IdentityRegistry returns the ed25519 compressed bytes of the resolver key"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — IdentityRegistry::identity_key (static method) via ResolverPki as Y
// ---------------------------------------------------------------------------

/// Demonstrates the trait-level call path: `IdentityRegistry::identity_key` is
/// static and takes `y: &ResolverPki<R>` as the state. This shows the escape
/// hatch documented in `s1_stable_id_acl.rs` — the resolver is threaded via `Y`.
#[test]
fn identity_registry_static_method_via_resolver_pki() {
    let alice_k1 = p2p_key(0x01);
    let trie = StubTrie::new().add_member(ALICE_ID, alice_k1, vec![]);
    let pki = ResolverPki::new(trie);

    // Call the static trait method using ResolverPki itself as the Y state.
    let key =
        <ResolverPki<StubTrie> as IdentityRegistry<MemberId, ResolverPki<StubTrie>>>::identity_key(
            &pki,
            &ALICE_ID,
        )
        .expect("static identity_key should not error for a known member");

    let key = key.expect("should return Some for Alice");
    assert_eq!(
        key.as_bytes(),
        alice_k1.0.as_bytes(),
        "static identity_key returns current resolver key via ResolverPki<R>"
    );
}

// ---------------------------------------------------------------------------
// Test 7 — IdentityRegistry rotation tracking (static path)
// ---------------------------------------------------------------------------

/// Confirms that after rotating Alice's key in the trie, a new `ResolverPki`
/// wrapping the updated trie returns K2 from `IdentityRegistry::identity_key`.
/// This is the IdentityRegistry-layer analogue of the rotation-tracking test.
#[test]
fn identity_registry_rotation_tracking() {
    let alice_k1 = p2p_key(0x01);
    let alice_k2 = p2p_key(0x02);

    let trie_before = StubTrie::new().add_member(ALICE_ID, alice_k1, vec![]);
    let pki_before = ResolverPki::new(trie_before.clone());

    let key_before =
        <ResolverPki<StubTrie> as IdentityRegistry<MemberId, ResolverPki<StubTrie>>>::identity_key(
            &pki_before,
            &ALICE_ID,
        )
        .unwrap()
        .unwrap();

    // Rotate and build a new pki pointing at the updated trie.
    let trie_after = trie_before.stub_rotate_member_key(&ALICE_ID, alice_k2);
    let pki_after = ResolverPki::new(trie_after);

    let key_after =
        <ResolverPki<StubTrie> as IdentityRegistry<MemberId, ResolverPki<StubTrie>>>::identity_key(
            &pki_after,
            &ALICE_ID,
        )
        .unwrap()
        .unwrap();

    assert_ne!(
        key_before.as_bytes(),
        key_after.as_bytes(),
        "IdentityRegistry must return different key after rotation"
    );
    assert_eq!(key_before.as_bytes(), alice_k1.0.as_bytes(), "before = K1");
    assert_eq!(key_after.as_bytes(), alice_k2.0.as_bytes(), "after = K2");
}
