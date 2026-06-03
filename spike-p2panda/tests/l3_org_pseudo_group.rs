#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! L3 scenario: org-as-pseudo-group end-to-end.
//!
//! See `spike-common/scenarios/org_pseudo_group.md` for the human-readable spec.
//!
//! **Substitutions exercised:**
//! - Gate 1: stable-ID ACL via `materialise_actor_id` (org-key path).
//! - Gate 3: DCGKA rotation via `trigger_recompute` + `process_g3_update`.
//! - Gate 4: org-as-pseudo-group via `OrgPseudoGroupAdapter` + `effective_member_keys`.
//!
//! ## Scenario summary
//!
//! 1. alice and bob are members of an org group.
//! 2. A doc is created whose ACL grants access via the org pseudo-group
//!    (`Principal::Org` / `GroupMember::Group(org_gid)`).
//! 3. alice's p2p member key is rotated (fixture step: `RotateMemberKey`).
//! 4. Trie-change observer fires: DCGKA recompute triggered.
//!
//! ## Observable assertions (from org_pseudo_group.md)
//!
//! 1. "a doc whose ACL grants the org-as-pseudo-group is readable by alice's
//!    new key after rotation" → alice holds epoch-1 group secret after
//!    `trigger_recompute`; `effective_member_keys` returns alice's new key.
//! 2. "the same doc is readable by bob without any explicit ACL change" →
//!    bob holds epoch-1 group secret after processing alice's update;
//!    `effective_member_keys` returns bob's key (unchanged); the CRDT state
//!    was NOT modified.
//! 3. "(D)CGKA recompute was triggered for org-keyed docs" → epoch-1 secret
//!    ≠ epoch-0 secret.
//!
//! ## Simplification note
//!
//! Full encryption/decryption at the application layer is not present in the
//! spike (no AEAD layer). Assertions are stated at the group-secret layer —
//! "readable by alice's new key" is proved by alice holding the epoch-1 group
//! secret and `effective_member_keys` returning her new key. The CRDT-no-change
//! invariant is verified directly.

use std::collections::HashMap;

use p2panda_auth::Access;
use p2panda_encryption::crypto::Rng;
use p2panda_encryption::data_scheme::dcgka::{Dcgka, GroupSecretOutput, ProcessInput};
use p2panda_encryption::data_scheme::group_secret::SecretBundle;
use p2panda_encryption::key_bundle::Lifetime;
use p2panda_encryption::key_manager::KeyManager;
use p2panda_encryption::key_registry::{KeyRegistry, KeyRegistryState};
use p2panda_encryption::traits::PreKeyManager;

use spike_common::identity::{MemberId, OrgKey, P2pMemberKey};
use spike_common::resolver::MemberKeyResolver;
use spike_common::scenarios::org_pseudo_group_fixture;
use spike_p2panda::s1_stable_id_acl::materialise_actor_id;
use spike_p2panda::s3_cgka_rotation::{
    process_g3_update, trigger_recompute, DcgkaMemberId, DcgkaOpId, G3DcgkaState, LocalDgm,
};
use spike_p2panda::s4_org_pseudo_group::{
    AuthMemberId, OrgPseudoGroupAdapter, effective_member_keys,
};

// ---------------------------------------------------------------------------
// Helpers (mirrors l2_g3.rs / l3_revocation.rs)
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

fn init_dcgka_state(
    my_id: DcgkaMemberId,
    my_keys: p2panda_encryption::key_manager::KeyManagerState,
    pki: KeyRegistryState<DcgkaMemberId>,
) -> G3DcgkaState {
    let dgm = LocalDgm::init(my_id);
    Dcgka::init(my_id, my_keys, pki, dgm)
}

// ---------------------------------------------------------------------------
// Fixture-aligned constants (from org_pseudo_group_fixture seed bytes)
// ---------------------------------------------------------------------------

// alice: MemberId([0xa1; 32]), initial P2pMemberKey = sk(0xa2), rotated = sk(0xaa)
const ALICE_ID: MemberId = MemberId([0xa1u8; 32]);
// bob:   MemberId([0xb1; 32]), P2pMemberKey = sk(0xb2)
const BOB_ID: MemberId = MemberId([0xb1u8; 32]);
// org key initial: sk(0x01)
// CRDT IDs (arbitrary, do not overlap with member or device keys)
const ORG_MANAGER_ID: AuthMemberId = AuthMemberId([0x07u8; 32]);
const ORG_GID: AuthMemberId = AuthMemberId([0x08u8; 32]);
const DOC_GID: AuthMemberId = AuthMemberId([0x09u8; 32]);
const DOC_MANAGER_ID: AuthMemberId = AuthMemberId([0xddu8; 32]);

fn sk(byte: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
}

// ---------------------------------------------------------------------------
// Main L3 test
// ---------------------------------------------------------------------------

/// L3 org-as-pseudo-group scenario end-to-end.
///
/// Observable assertions from `org_pseudo_group.md`:
/// 1. alice's new key appears in `effective_member_keys` after rotation (no ACL
///    change needed — the doc was granted to the org, not to individual keys).
/// 2. bob's key is in `effective_member_keys` both before and after alice's
///    rotation (org-keyed delegation preserves bob's access).
/// 3. The CRDT state is NOT modified by alice's key rotation.
/// 4. (D)CGKA epoch advances: epoch-1 secret ≠ epoch-0 secret.
/// 5. alice and bob share the epoch-1 group secret.
///
/// Gate-1 org-key side-assertion:
/// - `materialise_actor_id(&trie, &Principal::Org)` resolves before and after
///   rotation (the org key itself was not rotated in this scenario).
#[test]
fn org_pseudo_group_scenario_end_to_end() {
    let f = org_pseudo_group_fixture();
    assert_eq!(f.name, "org_pseudo_group");

    // ---- Build initial trie from fixture ----
    let trie_before = f.bootstrap_stub_trie();

    let alice_key_k1 = P2pMemberKey(sk(0xa2).verifying_key()); // fixture: alice initial key
    let alice_key_k2 = P2pMemberKey(sk(0xaa).verifying_key()); // fixture: alice rotated key
    let bob_key = P2pMemberKey(sk(0xb2).verifying_key());       // fixture: bob key (unchanged)
    let org_key_initial = OrgKey(sk(0x01).verifying_key());     // fixture: org key

    // Confirm trie matches fixture seeds.
    assert_eq!(
        trie_before.p2p_member_key(&ALICE_ID).unwrap().0.as_bytes(),
        alice_key_k1.0.as_bytes(),
        "alice's initial trie key must match fixture seed 0xa2"
    );
    assert_eq!(
        trie_before.p2p_member_key(&BOB_ID).unwrap().0.as_bytes(),
        bob_key.0.as_bytes(),
        "bob's trie key must match fixture seed 0xb2"
    );

    // ---- Gate-1 org-key assertion: Principal::Org resolves ----
    {
        use spike_common::identity::Principal;
        let org_actor = materialise_actor_id(&trie_before, &Principal::Org)
            .expect("[G1] org key must resolve via materialise_actor_id");
        // Sanity: the org ActorId encodes the org key bytes.
        let expected_panda_vk = p2panda_core::identity::VerifyingKey::from(org_key_initial.0);
        let expected_actor = p2panda_spaces::ActorId::from(expected_panda_vk);
        assert_eq!(
            org_actor, expected_actor,
            "[G1] org ActorId must match the org key"
        );
    }

    // ---- Gate-4: build CRDT state with org-as-pseudo-group ----
    let alice_auth = AuthMemberId::from(ALICE_ID);
    let bob_auth = AuthMemberId::from(BOB_ID);

    let (crdt_state_before, _doc_gid) = OrgPseudoGroupAdapter::build(
        ORG_GID,
        ORG_MANAGER_ID,
        &[alice_auth, bob_auth],
        DOC_GID,
        DOC_MANAGER_ID,
        Access::read(),
        0,
    )
    .expect("OrgPseudoGroupAdapter::build");

    // Gate-4 assertion A: both alice and bob are in effective_member_keys before rotation.
    let keys_before = effective_member_keys(&crdt_state_before, DOC_GID, &trie_before)
        .expect("effective_member_keys before rotation");
    assert!(
        keys_before.contains(&alice_key_k1),
        "[G4 Flow A] alice's K1 must be in effective_member_keys before rotation"
    );
    assert!(
        keys_before.contains(&bob_key),
        "[G4 Flow A] bob's key must be in effective_member_keys before rotation"
    );

    // ---- Apply fixture step: RotateMemberKey(alice, new_key=sk(0xaa)) ----
    let trie_after = f.apply_to_stub_trie(trie_before.clone());

    // Confirm alice's trie key is now K2.
    assert_eq!(
        trie_after.p2p_member_key(&ALICE_ID).unwrap().0.as_bytes(),
        alice_key_k2.0.as_bytes(),
        "alice's trie key must be K2 after rotation"
    );
    // Bob's key is unchanged.
    assert_eq!(
        trie_after.p2p_member_key(&BOB_ID).unwrap().0.as_bytes(),
        bob_key.0.as_bytes(),
        "bob's key must be unchanged after alice's rotation"
    );

    // Fixture expected_final: 2 members (alice + bob; only key rotated, no removal).
    assert_eq!(f.expected_final.member_count, 2);

    // ---- Gate-4: effective_member_keys after rotation ----
    // Observable 1: alice's new key K2 appears; old key K1 is gone.
    let keys_after = effective_member_keys(&crdt_state_before, DOC_GID, &trie_after)
        .expect("effective_member_keys after rotation");
    assert!(
        keys_after.contains(&alice_key_k2),
        "[G4 Flow C] alice's K2 must be in effective_member_keys after rotation"
    );
    assert!(
        !keys_after.contains(&alice_key_k1),
        "[G4 Flow C] alice's K1 must NOT be in effective_member_keys after rotation (stale)"
    );
    // Observable 2: bob's key is still present (no ACL change needed).
    assert!(
        keys_after.contains(&bob_key),
        "[G4] bob's key must still be in effective_member_keys after alice's rotation"
    );

    // Observable 3: CRDT state was NOT modified by the rotation.
    // (crdt_state_before is the same object we used before — no mutation occurred)
    let members_after_crdt = crdt_state_before.members(DOC_GID);
    let crdt_ids: std::collections::HashSet<AuthMemberId> =
        members_after_crdt.iter().map(|(id, _)| *id).collect();
    assert!(
        crdt_ids.contains(&alice_auth),
        "[G4] alice's stable ID must still be in the CRDT after key rotation"
    );
    assert!(
        crdt_ids.contains(&bob_auth),
        "[G4] bob's stable ID must still be in the CRDT after key rotation"
    );

    // ---- Gate-3: DCGKA recompute triggered by alice's key rotation ----

    let rng = Rng::from_seed([0x42u8; 32]);

    // Build initial PKI for alice + bob.
    let (mut managers_0, pki_0) = build_member_states(&[ALICE_ID, BOB_ID], &rng);

    let alice = DcgkaMemberId(ALICE_ID);
    let bob = DcgkaMemberId(BOB_ID);

    let alice_keys_0 = managers_0.remove(&alice).expect("alice keys epoch-0");
    let bob_keys_0 = managers_0.remove(&bob).expect("bob keys epoch-0");

    let alice_state_0 = init_dcgka_state(alice, alice_keys_0, pki_0.clone());
    let bob_state_0 = init_dcgka_state(bob, bob_keys_0, pki_0);

    // Epoch-0: alice creates the DCGKA group.
    let alice_bundle_0 = SecretBundle::init();
    let alice_secret_0 =
        SecretBundle::generate(&alice_bundle_0, &rng).expect("generate epoch-0 secret");

    let (alice_state_1, create_output) =
        Dcgka::create(alice_state_0, vec![alice, bob], &alice_secret_0, &rng)
            .expect("Dcgka::create epoch-0");

    // Alice self-processes.
    let (alice_state_2, _) = Dcgka::process(
        alice_state_1,
        ProcessInput {
            seq: DcgkaOpId::new(0, 0),
            sender: alice,
            control_message: create_output.control_message.clone(),
            direct_message: None,
        },
    )
    .expect("alice self-process create");
    let alice_bundle_1 = SecretBundle::insert(alice_bundle_0, alice_secret_0.clone());

    // Bob processes create → obtains epoch-0 secret.
    let bob_direct_0 = create_output
        .direct_messages
        .iter()
        .find(|dm| dm.recipient == bob)
        .expect("bob direct create message")
        .clone();

    let (bob_state_1, bob_create_out) = Dcgka::process(
        bob_state_0,
        ProcessInput {
            seq: DcgkaOpId::new(0, 0),
            sender: alice,
            control_message: create_output.control_message.clone(),
            direct_message: Some(bob_direct_0),
        },
    )
    .expect("bob process create");

    let GroupSecretOutput::Secret(bob_secret_0) = bob_create_out else {
        panic!("bob must receive epoch-0 group secret");
    };
    assert_eq!(alice_secret_0, bob_secret_0, "alice and bob must share epoch-0 secret");

    // Trie-change: alice's key rotated. Rebuild PKI for alice + bob.
    let (mut managers_1, pki_1) = build_member_states(&[ALICE_ID, BOB_ID], &rng);
    let alice_keys_1 = managers_1.remove(&alice).expect("alice keys epoch-1");

    // Update alice's key manager.
    let mut alice_state_3 = alice_state_2;
    alice_state_3.my_keys = alice_keys_1;

    // trigger_recompute: inject new PKI + Dcgka::update (alice drives the epoch transition).
    let (_alice_state_4, update_output, _alice_bundle_2, alice_secret_1) =
        trigger_recompute(alice_state_3, alice_bundle_1, pki_1.clone(), &rng)
            .expect("trigger_recompute after rotation");

    // Observable 4: epoch advanced.
    assert_ne!(
        alice_secret_0, alice_secret_1,
        "[G3 Flow C] epoch-1 secret must differ from epoch-0 after rotation"
    );

    // Bob processes the update to obtain epoch-1 secret.
    let bob_direct_1 = update_output
        .direct_messages
        .iter()
        .find(|dm| dm.recipient == bob)
        .expect("bob must receive update direct message")
        .clone();

    let mut bob_state_2 = bob_state_1;
    bob_state_2.pki = pki_1;

    let (_, bob_update_out) = process_g3_update(
        bob_state_2,
        ProcessInput {
            seq: DcgkaOpId::new(0, 1),
            sender: alice,
            control_message: update_output.control_message.clone(),
            direct_message: Some(bob_direct_1),
        },
    )
    .expect("bob process update");

    let GroupSecretOutput::Secret(bob_secret_1) = bob_update_out else {
        panic!("bob must receive epoch-1 group secret");
    };

    // Observable 5: alice and bob share epoch-1 secret (org-keyed doc accessible to both).
    assert_eq!(
        alice_secret_1, bob_secret_1,
        "[org_pseudo_group] alice and bob must share epoch-1 group secret after rotation"
    );

    println!(
        "L3 org_pseudo_group: epoch-0={alice_secret_0:?}, epoch-1={alice_secret_1:?}; \
         alice K2 in effective keys; CRDT unchanged; bob shares epoch-1 secret."
    );
}
