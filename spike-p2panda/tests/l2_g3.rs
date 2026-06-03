#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! L2 integration test: gate 3 — combined Flow B + Flow C.
//!
//! Verifies the end-to-end resolver → DCGKA path:
//! 1. A 2-member group is formed with registry-populated key material.
//! 2. Alice and Bob share the epoch-0 group secret.
//! 3. Alice's key is "rotated" (new PKI from fresh member states, simulating
//!    a trie-observer-triggered rebuild); `trigger_recompute` drives a
//!    `Dcgka::update`.
//! 4. The epoch-1 secret differs from epoch-0 (forward-secrecy signal).
//! 5. Alice and Bob still share the same epoch-1 secret after the update.
//! 6. The `IdentityRegistry::identity_key` path (via `ResolverPki`) correctly
//!    reflects the pre- and post-rotation keys at the resolver level.

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
// ---------------------------------------------------------------------------

fn build_member_states(
    member_ids: &[MemberId],
    rng: &Rng,
) -> (
    HashMap<DcgkaMemberId, p2panda_encryption::key_manager::KeyManagerState>,
    KeyRegistryState<DcgkaMemberId>,
) {
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

fn make_vk(seed: u8) -> ed25519_dalek::VerifyingKey {
    use ed25519_dalek::SigningKey;
    let secret = ed25519_dalek::SecretKey::from([seed; 32]);
    let sk = SigningKey::from_bytes(&secret);
    sk.verifying_key()
}

// ---------------------------------------------------------------------------
// Combined Flow B + Flow C integration test
// ---------------------------------------------------------------------------

/// Combined Flow B + Flow C integration test.
///
/// Proves:
/// - `KeyRegistry<DcgkaMemberId>` populated with key material enables
///   `Dcgka::create` (Flow B).
/// - `trigger_recompute` after a key rotation produces a new epoch secret that
///   differs from the pre-rotation secret (Flow C).
/// - Both Alice and Bob share the post-rotation secret.
/// - `IdentityRegistry::identity_key` via `ResolverPki` reflects the rotation.
#[test]
fn l2_g3_combined_flow_b_and_c() {
    let rng = Rng::from_seed([42; 32]);

    let alice_mid = MemberId([0xAA; 32]);
    let bob_mid = MemberId([0xBB; 32]);
    let alice = DcgkaMemberId(alice_mid);
    let bob = DcgkaMemberId(bob_mid);

    // ---- Resolver layer: Flow B seam check ----
    let alice_vk_before = make_vk(0x01);
    let alice_vk_after = make_vk(0x02);

    let trie_before = StubTrie::new()
        .add_member(alice_mid, P2pMemberKey(alice_vk_before), vec![])
        .add_member(bob_mid, P2pMemberKey(make_vk(0x03)), vec![]);

    let pki_resolver_before = ResolverPki::new(trie_before);
    let resolver_key_before = <ResolverPki<StubTrie> as IdentityRegistry<
        MemberId,
        ResolverPki<StubTrie>,
    >>::identity_key(&pki_resolver_before, &alice_mid)
    .expect("identity_key before rotation")
    .expect("alice present before rotation");

    // ---- DCGKA layer: epoch-0 group creation (Flow B) ----

    let (mut managers_0, pki_registry_0) =
        build_member_states(&[alice_mid, bob_mid], &rng);

    let alice_keys_0 = managers_0.remove(&alice).expect("alice keys");
    let bob_keys_0 = managers_0.remove(&bob).expect("bob keys");

    let alice_dcgka_0 = init_g3_dcgka_state(alice, alice_keys_0, pki_registry_0.clone());
    let bob_dcgka_0 = init_g3_dcgka_state(bob, bob_keys_0, pki_registry_0);

    let alice_bundle_0 = SecretBundle::init();
    let alice_secret_0 =
        SecretBundle::generate(&alice_bundle_0, &rng).expect("generate epoch-0 secret");

    let (alice_dcgka_1, create_output) =
        Dcgka::create(alice_dcgka_0, vec![alice, bob], &alice_secret_0, &rng)
            .expect("Dcgka::create");

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
    .expect("alice self-process create");
    let alice_bundle_1 = SecretBundle::insert(alice_bundle_0, alice_secret_0.clone());

    // Bob processes create.
    let bob_direct = create_output
        .direct_messages
        .into_iter()
        .find(|dm| dm.recipient == bob)
        .expect("bob direct create message");

    let (bob_dcgka_1, bob_epoch0_out) = Dcgka::process(
        bob_dcgka_0,
        ProcessInput {
            seq: DcgkaOpId::new(0, 0),
            sender: alice,
            control_message: create_output.control_message,
            direct_message: Some(bob_direct),
        },
    )
    .expect("bob process create");

    let GroupSecretOutput::Secret(bob_secret_0) = bob_epoch0_out else {
        panic!("expected epoch-0 secret for bob");
    };

    // Flow B assertion: shared secret at epoch 0.
    assert_eq!(
        alice_secret_0, bob_secret_0,
        "[Flow B] alice and bob must share epoch-0 group secret"
    );

    // ---- Key rotation and recompute (Flow C) ----

    // Fresh PKI simulates "trie observer triggered by alice's key rotation".
    let (mut managers_1, new_pki_registry) =
        build_member_states(&[alice_mid, bob_mid], &rng);
    let alice_keys_1 = managers_1.remove(&alice).expect("alice rotated keys");

    // Inject rotated key manager.
    let mut alice_dcgka_3 = alice_dcgka_2;
    alice_dcgka_3.my_keys = alice_keys_1;

    // trigger_recompute: inject new PKI + call Dcgka::update.
    let (alice_dcgka_4, update_output, _alice_bundle_2, alice_secret_1) =
        trigger_recompute(alice_dcgka_3, alice_bundle_1, new_pki_registry.clone(), &rng)
            .expect("trigger_recompute");

    // Alice self-processes update.
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
    bob_dcgka_2.pki = new_pki_registry;

    let (_, bob_epoch1_out) = process_g3_update(
        bob_dcgka_2,
        ProcessInput {
            seq: DcgkaOpId::new(0, 1),
            sender: alice,
            control_message: update_output.control_message,
            direct_message: Some(bob_direct_update),
        },
    )
    .expect("bob process update");

    let GroupSecretOutput::Secret(bob_secret_1) = bob_epoch1_out else {
        panic!("expected epoch-1 secret for bob");
    };

    // Flow C assertion 1: secret changed after rotation.
    assert_ne!(
        alice_secret_0, alice_secret_1,
        "[Flow C] epoch-1 secret must differ from epoch-0 after rotation"
    );

    // Flow C assertion 2: alice and bob share epoch-1 secret.
    assert_eq!(
        alice_secret_1, bob_secret_1,
        "[Flow C] alice and bob must share epoch-1 group secret after recompute"
    );

    // ---- Resolver layer: Flow C seam check ----
    let trie_after = StubTrie::new()
        .add_member(alice_mid, P2pMemberKey(alice_vk_after), vec![])
        .add_member(bob_mid, P2pMemberKey(make_vk(0x03)), vec![]);

    let pki_resolver_after = ResolverPki::new(trie_after);
    let resolver_key_after = <ResolverPki<StubTrie> as IdentityRegistry<
        MemberId,
        ResolverPki<StubTrie>,
    >>::identity_key(&pki_resolver_after, &alice_mid)
    .expect("identity_key after rotation")
    .expect("alice present after rotation");

    assert_ne!(
        resolver_key_before.as_bytes(),
        resolver_key_after.as_bytes(),
        "[Flow C] resolver identity_key must change after trie rotation"
    );
}
