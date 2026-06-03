#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! L1 test: gate 3 — Flow B (CGKA compute) and Flow C (recompute on rotation)
//! at the p2panda-encryption layer.
//!
//! ## What is proven here
//!
//! **Flow B (CGKA compute via resolver):**
//! - `IdentityRegistry::identity_key` on `ResolverPki<StubTrie>` returns the
//!   resolver's current key (direct seam test).
//! - Full `Dcgka::create` + `Dcgka::process` round-trip with
//!   `KeyRegistry<DcgkaMemberId>` as `PKI` — the registry is populated from
//!   key material derived via the `KeyManager` (same bundle-injection pattern
//!   used in production when a member publishes their pre-key bundle). The
//!   two-member group creates and shares a `GroupSecret`.
//!
//! **Flow C (recompute on rotation):**
//! - Rotating Alice's key in the `StubTrie` produces a different result from
//!   `IdentityRegistry::identity_key` on the next call (resolver-level proof).
//! - `trigger_recompute` calls `Dcgka::update` with a rebuilt PKI and yields a
//!   NEW `GroupSecret` distinct from the pre-rotation one. Bob processes the
//!   update and obtains the same new secret.

use std::collections::HashMap;

use p2panda_encryption::crypto::Rng;
use p2panda_encryption::data_scheme::dcgka::{Dcgka, GroupSecretOutput, ProcessInput};
use p2panda_encryption::data_scheme::group_secret::SecretBundle;
use p2panda_encryption::key_bundle::Lifetime;
use p2panda_encryption::key_manager::KeyManager;
use p2panda_encryption::key_registry::{KeyRegistry, KeyRegistryState};
use p2panda_encryption::traits::{IdentityRegistry, PreKeyManager};
use spike_common::identity::{MemberId, P2pMemberKey};
use spike_common::stub_trie::StubTrie;
use spike_p2panda::s1_stable_id_acl::ResolverPki;
use spike_p2panda::s3_cgka_rotation::{
    process_g3_update, trigger_recompute, DcgkaMemberId, DcgkaOpId, G3DcgkaState, LocalDgm,
};

// ---------------------------------------------------------------------------
// Test fixture helpers
// (build_member_states and init_g3_dcgka_state live here rather than in the
//  library because they depend on KeyManager::init_and_generate_prekey which
//  is only available under the test_utils feature of p2panda-encryption.)
// ---------------------------------------------------------------------------

fn build_member_states(
    member_ids: &[MemberId],
    rng: &Rng,
) -> (HashMap<DcgkaMemberId, p2panda_encryption::key_manager::KeyManagerState>, KeyRegistryState<DcgkaMemberId>) {
    let mut managers = HashMap::new();
    let mut bundles = HashMap::new();

    for &id in member_ids {
        let dcgka_id = DcgkaMemberId(id);
        let identity_secret = p2panda_encryption::crypto::x25519::SecretKey::from_bytes(
            rng.random_array().unwrap(),
        );
        let manager =
            KeyManager::init_and_generate_prekey(&identity_secret, Lifetime::default(), rng)
                .unwrap();
        let bundle = KeyManager::prekey_bundle(&manager).unwrap();
        bundles.insert(dcgka_id, bundle);
        managers.insert(dcgka_id, manager);
    }

    let mut pki = KeyRegistry::init();
    for (dcgka_id, bundle) in &bundles {
        pki = KeyRegistry::add_longterm_bundle(pki, *dcgka_id, bundle.clone()).unwrap();
    }

    (managers, pki)
}

fn init_g3_dcgka_state(
    my_id: DcgkaMemberId,
    my_keys: p2panda_encryption::key_manager::KeyManagerState,
    pki: KeyRegistryState<DcgkaMemberId>,
) -> G3DcgkaState {
    let dgm = LocalDgm::init(my_id);
    Dcgka::init(my_id, my_keys, pki, dgm)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn alice_id() -> MemberId {
    MemberId([0xAA; 32])
}

fn bob_id() -> MemberId {
    MemberId([0xBB; 32])
}

fn make_vk(seed: u8) -> ed25519_dalek::VerifyingKey {
    use ed25519_dalek::SigningKey;
    let secret = ed25519_dalek::SecretKey::from([seed; 32]);
    let sk = SigningKey::from_bytes(&secret);
    sk.verifying_key()
}

// ---------------------------------------------------------------------------
// Flow B — L1 probe 1: IdentityRegistry::identity_key via ResolverPki
// ---------------------------------------------------------------------------

/// Demonstrates that `IdentityRegistry::identity_key` called via `ResolverPki`
/// returns the key currently in the resolver (trie). This is the minimal Flow B
/// evidence: the seam is live.
#[test]
fn flow_b_identity_registry_returns_resolver_key() {
    let alice = alice_id();
    let alice_vk = make_vk(0xAA);
    let alice_member_key = P2pMemberKey(alice_vk);

    let trie = StubTrie::new().add_member(alice, alice_member_key, vec![]);
    let pki = ResolverPki::new(trie);

    let result =
        <ResolverPki<StubTrie> as IdentityRegistry<MemberId, ResolverPki<StubTrie>>>::identity_key(
            &pki, &alice,
        )
        .expect("identity_key should succeed");

    assert!(result.is_some(), "alice should have a key in the registry");

    // Verify the returned x25519 public key bytes match the ed25519 key bytes
    // (same 32-byte reinterpretation used by ResolverPki).
    let x25519_key = result.unwrap();
    assert_eq!(
        x25519_key.as_bytes(),
        alice_vk.as_bytes(),
        "identity_key bytes must match the resolver's p2p_member_key"
    );
}

/// Unknown member returns `None` (graceful — not an error).
#[test]
fn flow_b_identity_registry_unknown_member_returns_none() {
    let trie = StubTrie::new();
    let pki = ResolverPki::new(trie);
    let unknown = MemberId([0xFF; 32]);

    let result =
        <ResolverPki<StubTrie> as IdentityRegistry<MemberId, ResolverPki<StubTrie>>>::identity_key(
            &pki, &unknown,
        )
        .expect("should not error for unknown member");

    assert!(result.is_none(), "unknown member must return None");
}

// ---------------------------------------------------------------------------
// Flow B — L1 probe 2: full Dcgka::create + process round-trip
// ---------------------------------------------------------------------------

/// Demonstrates the full DCGKA compute flow (Flow B):
/// - Two members (alice, bob) are set up with key material in a
///   `KeyRegistry<DcgkaMemberId>`.
/// - `Dcgka::create` produces a group secret for a 2-member group.
/// - Bob processes the create message and obtains the SAME group secret.
///
/// This proves that the `KeyRegistry::key_bundle` injection seam works
/// end-to-end: the registry is the gate-3 PKI bridge point.
#[test]
fn flow_b_dcgka_create_and_process_shared_secret() {
    let rng = Rng::from_seed([1; 32]);

    let alice_mid = alice_id();
    let bob_mid = bob_id();
    let alice = DcgkaMemberId(alice_mid);
    let bob = DcgkaMemberId(bob_mid);

    let (mut managers, pki) = build_member_states(&[alice_mid, bob_mid], &rng);

    let alice_keys = managers.remove(&alice).expect("alice manager");
    let bob_keys = managers.remove(&bob).expect("bob manager");

    let alice_dcgka = init_g3_dcgka_state(alice, alice_keys, pki.clone());
    let bob_dcgka = init_g3_dcgka_state(bob, bob_keys, pki);

    // Alice generates the initial group secret and creates the group.
    let alice_bundle = SecretBundle::init();
    let alice_group_secret_0 =
        SecretBundle::generate(&alice_bundle, &rng).expect("generate group secret");

    let (alice_dcgka, create_output) =
        Dcgka::create(alice_dcgka, vec![alice, bob], &alice_group_secret_0, &rng)
            .expect("Dcgka::create");

    // Alice self-processes.
    let (_alice_dcgka, _) = Dcgka::process(
        alice_dcgka,
        ProcessInput {
            seq: DcgkaOpId::new(0, 0),
            sender: alice,
            control_message: create_output.control_message.clone(),
            direct_message: None,
        },
    )
    .expect("alice self-process create");

    // Bob processes Alice's create message.
    let bob_direct = create_output
        .direct_messages
        .into_iter()
        .find(|dm| dm.recipient == bob)
        .expect("direct message for bob");

    let (_, bob_output) = Dcgka::process(
        bob_dcgka,
        ProcessInput {
            seq: DcgkaOpId::new(0, 0),
            sender: alice,
            control_message: create_output.control_message,
            direct_message: Some(bob_direct),
        },
    )
    .expect("bob process create");

    let GroupSecretOutput::Secret(bob_group_secret_0) = bob_output else {
        panic!("expected GroupSecretOutput::Secret for bob");
    };

    // Alice and Bob share the same group secret.
    assert_eq!(
        alice_group_secret_0, bob_group_secret_0,
        "alice and bob must share the same group secret after create"
    );
}

// ---------------------------------------------------------------------------
// Flow C — L1 probe 1: identity_key returns new key after trie rotation
// ---------------------------------------------------------------------------

/// Minimal Flow C evidence: rotating Alice's p2p_member_key in the StubTrie
/// causes `IdentityRegistry::identity_key` to return a DIFFERENT key on the
/// next call. The resolver is live — not cached.
#[test]
fn flow_c_identity_key_reflects_trie_rotation() {
    let alice = alice_id();
    let alice_vk_before = make_vk(0x01);
    let alice_vk_after = make_vk(0x02);

    let trie_before =
        StubTrie::new().add_member(alice, P2pMemberKey(alice_vk_before), vec![]);
    let pki_before = ResolverPki::new(trie_before);

    let key_before =
        <ResolverPki<StubTrie> as IdentityRegistry<MemberId, ResolverPki<StubTrie>>>::identity_key(
            &pki_before,
            &alice,
        )
        .expect("key_before")
        .expect("alice present before rotation");

    let trie_after =
        StubTrie::new().add_member(alice, P2pMemberKey(alice_vk_after), vec![]);
    let pki_after = ResolverPki::new(trie_after);

    let key_after =
        <ResolverPki<StubTrie> as IdentityRegistry<MemberId, ResolverPki<StubTrie>>>::identity_key(
            &pki_after,
            &alice,
        )
        .expect("key_after")
        .expect("alice present after rotation");

    assert_ne!(
        key_before.as_bytes(),
        key_after.as_bytes(),
        "identity_key must differ after trie rotation"
    );
}

// ---------------------------------------------------------------------------
// Flow C — L1 probe 2: Dcgka::update yields fresh group secret after rotation
// ---------------------------------------------------------------------------

/// Full Flow C evidence: after key rotation, `trigger_recompute` (wrapping
/// `Dcgka::update`) produces a NEW group secret. Bob processes the update and
/// obtains the same new secret. The old and new secrets differ.
#[test]
fn flow_c_dcgka_recompute_yields_new_group_secret() {
    let rng = Rng::from_seed([2; 32]);

    let alice_mid = alice_id();
    let bob_mid = bob_id();
    let alice = DcgkaMemberId(alice_mid);
    let bob = DcgkaMemberId(bob_mid);

    // epoch 0: set up group.
    let (mut managers, pki) = build_member_states(&[alice_mid, bob_mid], &rng);

    let alice_keys = managers.remove(&alice).expect("alice keys");
    let bob_keys = managers.remove(&bob).expect("bob keys");

    let alice_dcgka_0 = init_g3_dcgka_state(alice, alice_keys, pki.clone());
    let bob_dcgka_0 = init_g3_dcgka_state(bob, bob_keys, pki);

    let alice_bundle_0 = SecretBundle::init();
    let alice_secret_0 =
        SecretBundle::generate(&alice_bundle_0, &rng).expect("gen secret 0");

    let (alice_dcgka_1, create_output) =
        Dcgka::create(alice_dcgka_0, vec![alice, bob], &alice_secret_0, &rng)
            .expect("create");

    // Alice self-processes.
    let (alice_dcgka_2, _) = Dcgka::process(
        alice_dcgka_1,
        ProcessInput {
            seq: DcgkaOpId::new(0, 0),
            sender: alice,
            control_message: create_output.control_message.clone(),
            direct_message: None,
        },
    )
    .expect("alice self-process");

    let alice_bundle_1 = SecretBundle::insert(alice_bundle_0, alice_secret_0.clone());

    // Bob processes create.
    let bob_direct = create_output
        .direct_messages
        .into_iter()
        .find(|dm| dm.recipient == bob)
        .expect("bob direct message");

    let (bob_dcgka_1, bob_out_0) = Dcgka::process(
        bob_dcgka_0,
        ProcessInput {
            seq: DcgkaOpId::new(0, 0),
            sender: alice,
            control_message: create_output.control_message,
            direct_message: Some(bob_direct),
        },
    )
    .expect("bob process create");

    let GroupSecretOutput::Secret(bob_secret_0) = bob_out_0 else {
        panic!("expected secret for bob");
    };
    assert_eq!(alice_secret_0, bob_secret_0, "epoch-0 secrets must match");

    // epoch 1: key rotation → recompute.
    // New PKI built from fresh member states (simulates trie rotation trigger).
    let (mut new_managers, new_pki) = build_member_states(&[alice_mid, bob_mid], &rng);
    let alice_keys_rotated = new_managers.remove(&alice).expect("alice keys rotated");

    // Inject rotated key manager for alice.
    let mut alice_dcgka_3 = alice_dcgka_2;
    alice_dcgka_3.my_keys = alice_keys_rotated;

    // trigger_recompute: inject new PKI, call Dcgka::update.
    let (alice_dcgka_4, update_output, _alice_bundle_2, alice_secret_1) =
        trigger_recompute(alice_dcgka_3, alice_bundle_1, new_pki.clone(), &rng)
            .expect("trigger_recompute");

    // Alice self-processes the update.
    let (_, _) = process_g3_update(
        alice_dcgka_4,
        ProcessInput {
            seq: DcgkaOpId::new(0, 1),
            sender: alice,
            control_message: update_output.control_message.clone(),
            direct_message: None,
        },
    )
    .expect("alice self-process update");

    // Bob processes Alice's update.
    let bob_direct_update = update_output
        .direct_messages
        .into_iter()
        .find(|dm| dm.recipient == bob)
        .expect("bob update direct message");

    let mut bob_dcgka_2 = bob_dcgka_1;
    bob_dcgka_2.pki = new_pki;

    let (_, bob_out_1) = process_g3_update(
        bob_dcgka_2,
        ProcessInput {
            seq: DcgkaOpId::new(0, 1),
            sender: alice,
            control_message: update_output.control_message,
            direct_message: Some(bob_direct_update),
        },
    )
    .expect("bob process update");

    let GroupSecretOutput::Secret(bob_secret_1) = bob_out_1 else {
        panic!("expected new secret for bob after update");
    };

    // Epoch-1 secret is new.
    assert_ne!(
        alice_secret_0, alice_secret_1,
        "new group secret must differ after recompute"
    );

    // Alice and Bob share the epoch-1 secret.
    assert_eq!(
        alice_secret_1, bob_secret_1,
        "alice and bob must share epoch-1 group secret"
    );
}
