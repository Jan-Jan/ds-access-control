//! Integration test: the five user stories via OrgService against MockChainOps
//! + loopback iroh endpoints.  Offline — no live chain, no relay.
//!
//! Stories exercised:
//!   1. A creates a persona and an organisation → epoch 1 in MockChain.
//!   2. B creates a persona; exports a JoinRequest; A imports it.
//!      A exports an Invite; B imports it (persists admin_device_key for cross-check).
//!   3. A admits B (trie add → epoch 2 in MockChain; envelope pushed to B over iroh).
//!   4. B receives and verifies the envelope → B's persona Active, OrgRecord stored.
//!      Cross-check: B asserts sender's QUIC device key == invite's admin_device_key.
//!   5. A revokes B (trie remove → epoch 3); B self-deletes its OrgRecord.
//!
//! The gate: `cargo test -p org-node --features app --test service_stories`

#![cfg(feature = "app")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use org_node::keys::SigningKeypair;
use org_node::service::{MockChainOps, OrgService, SelfDeleteOutcome};
use org_node::store::{PersonaStatus, PersonaStore};
use org_node::transport::endpoint::OrgEndpoint;

// The proper end-to-end test that runs all 5 stories in one function.
// `five_stories_headless` (stories 1-4 only, no invite cross-check) was
// deleted in the Fix 3 cleanup — `five_stories_full_e2e` is the canonical gate.
#[tokio::test(flavor = "multi_thread")]
async fn five_stories_full_e2e() {
    use rand::rngs::OsRng;

    // ---- Shared chain ----
    let chain = MockChainOps::new();
    let chain_a = chain.clone();
    let chain_b_admit = chain.clone();   // for story 3/4
    let chain_b_revoke = chain.clone();  // for story 5

    // B's device keypair (fixed seed so we can reconstruct it for story 5).
    let b_device_kp = SigningKeypair::from_seed([0x22u8; 32]);

    // ---- Bind B's admission endpoint ----
    let ep_b_admit = OrgEndpoint::bind(&b_device_kp).await.unwrap();
    let b_addr_admit = ep_b_admit.inner().addr();

    // ---- Stores ----
    let store_a_path = {
        let dir = std::env::temp_dir().join(format!("ods-e2e-a-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("store.bin")
    };
    let store_b_path = {
        let dir = std::env::temp_dir().join(format!("ods-e2e-b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("store.bin")
    };

    let store_a = PersonaStore::open(store_a_path.clone(), "pw_a").unwrap();
    let store_b = PersonaStore::open(store_b_path.clone(), "pw_b").unwrap();

    // svc_a starts without an endpoint; we bind it below once we know A's device seed.
    let mut svc_a = OrgService::new(store_a, Box::new(chain_a));
    let mut svc_b = OrgService::new(store_b, Box::new(chain_b_admit));

    // ---- Story 1: A creates persona + org ----
    let pid_a = svc_a.create_persona(&mut OsRng, "admin", "Admin", "User").unwrap();
    let org_id = svc_a.create_organisation(&mut OsRng, &pid_a).await.unwrap();

    assert_eq!(chain.get(&org_id).unwrap().epoch, 1);
    assert_eq!(svc_a.list_personas()[0].status, PersonaStatus::Active);

    // Bind A's endpoint from the SAME device seed that `create_persona` generated.
    // This ensures the QUIC-authenticated sender identity on B's side equals the
    // `admin_device_key` that `export_invite` will encode — the cross-check gate.
    let a_device_seed = svc_a.list_personas()
        .iter()
        .find(|p| p.persona_id == pid_a)
        .map(|p| p.device_seed)
        .expect("persona not found after create");
    let a_device_kp = SigningKeypair::from_seed(a_device_seed);
    let ep_a_admit = OrgEndpoint::bind(&a_device_kp).await.unwrap();
    let svc_a = svc_a.with_endpoint(ep_a_admit);
    let mut svc_a = svc_a;

    // ---- Story 2: B creates persona; A exports Invite; B imports it ----
    let pid_b = svc_b.create_persona(&mut OsRng, "bob", "Bob", "Builder").unwrap();

    // A exports the invite (admin_device_key = A's persona device key).
    let invite_blob = svc_a.export_invite(org_id).unwrap();
    // B imports and persists the invite — stores admin_device_key for the cross-check.
    let invite = svc_b.import_invite(&mut OsRng, &invite_blob).unwrap();
    assert_eq!(invite.org_id, org_id);

    // B exports a JoinRequest (includes B's iroh addr so A can dial back if needed).
    let ep_b_for_jr = OrgEndpoint::bind(&b_device_kp).await.unwrap();
    let b_addr_jr = ep_b_for_jr.inner().addr();
    let svc_b = svc_b.with_endpoint(ep_b_for_jr);

    let jr_blob = svc_b.export_join_request(&pid_b).unwrap();
    let join_request = OrgService::import_join_request(&jr_blob).unwrap();
    assert_eq!(join_request.handle, "bob");

    // Rebuild svc_b with ep_b_admit so B can receive A's push.
    let store_b2 = PersonaStore::open(store_b_path.clone(), "pw_b").unwrap();
    let mut svc_b2 = OrgService::new(store_b2, Box::new(chain_b_revoke.clone()))
        .with_endpoint(ep_b_admit);

    // ---- Story 3+4: B spawns recv, A admits ----
    // B receives first — spawn BEFORE A dials.
    let recv_handle = tokio::spawn(async move {
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            svc_b2.receive_and_verify(&mut OsRng),
        )
        .await
        .expect("B receive_and_verify timed out")
        .expect("B receive_and_verify failed");
        (svc_b2, outcome)
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let b_member_id = tokio::time::timeout(
        Duration::from_secs(30),
        svc_a.admit_member(&mut OsRng, org_id, &join_request, b_addr_admit, Some([0xffu8; 32])),
    )
    .await
    .expect("admit_member timed out")
    .expect("admit_member failed");

    // MockChain: epoch 2.
    assert_eq!(chain.get(&org_id).unwrap().epoch, 2, "admit must bump to epoch 2");

    // Collect B's result + svc_b (moved out of the task).
    let (svc_b3, b_outcome) = recv_handle.await.unwrap();

    assert_eq!(b_outcome.org_id, org_id, "B's outcome org_id must match");
    assert_eq!(b_outcome.epoch, 2, "B must commit epoch 2");
    assert_eq!(
        b_outcome.root,
        *chain.get(&org_id).unwrap().root_hash.as_bytes(),
        "B's committed root must match on-chain root"
    );

    // B's persona must be Active.
    assert_eq!(
        svc_b3.list_personas().iter().find(|p| p.persona_id == pid_b).unwrap().status,
        PersonaStatus::Active,
        "B's persona must be Active after successful verification"
    );
    // B must have the OrgRecord.
    assert_eq!(svc_b3.list_orgs().len(), 1, "B must have exactly 1 OrgRecord");
    assert_eq!(svc_b3.list_orgs()[0].epoch, 2);
    assert_eq!(svc_b3.list_orgs()[0].org_secret, Some([0xffu8; 32]));

    // ---- Story 5: A revokes B; B self-deletes ----

    // Bind a fresh B endpoint for receiving the revocation.
    let b_device_kp2 = SigningKeypair::from_seed([0x22u8; 32]);
    let ep_b_revoke = OrgEndpoint::bind(&b_device_kp2).await.unwrap();
    let b_addr_revoke = ep_b_revoke.inner().addr();

    // Replace B's endpoint.
    let mut svc_b3 = svc_b3.with_endpoint(ep_b_revoke);

    // B waits for the revocation message.
    let revoke_recv_handle = tokio::spawn(async move {
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            svc_b3.receive_and_self_delete_if_revoked(&mut OsRng),
        )
        .await
        .expect("B revoke recv timed out")
        .expect("B receive_and_self_delete_if_revoked failed");
        (svc_b3, outcome)
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Rebind A's outbound endpoint for the revocation send.
    let ep_a_revoke = OrgEndpoint::bind(&a_device_kp).await.unwrap();
    let mut svc_a = svc_a.with_endpoint(ep_a_revoke);

    tokio::time::timeout(
        Duration::from_secs(30),
        svc_a.revoke_member(&mut OsRng, org_id, b_member_id, b_addr_revoke),
    )
    .await
    .expect("revoke_member timed out")
    .expect("revoke_member failed");

    // MockChain: epoch 3.
    assert_eq!(chain.get(&org_id).unwrap().epoch, 3, "revoke must bump to epoch 3");

    // Collect B's self-delete result.
    let (svc_b_final, delete_outcome) = revoke_recv_handle.await.unwrap();

    match delete_outcome {
        SelfDeleteOutcome::SelfDeleted { org_id: oid } => {
            assert_eq!(oid, org_id, "self-deleted org_id must match");
        }
        SelfDeleteOutcome::UpdatedNotRevoked { .. } => {
            panic!("expected SelfDeleted but got UpdatedNotRevoked");
        }
    }

    // B must no longer have the OrgRecord.
    assert_eq!(
        svc_b_final.list_orgs().len(),
        0,
        "B must have no OrgRecords after self-delete"
    );

    // B's persona must be Revoked.
    assert_eq!(
        svc_b_final.list_personas().iter().find(|p| p.persona_id == pid_b).unwrap().status,
        PersonaStatus::Revoked,
        "B's persona must be Revoked after self-delete"
    );

    // A still has the org at epoch 3 with only the admin in the trie.
    assert_eq!(svc_a.list_orgs().len(), 1);
    assert_eq!(svc_a.list_orgs()[0].epoch, 3);
    assert_eq!(svc_a.list_orgs()[0].trie_members.len(), 1, "only admin should remain");

    let _ = (pid_b, b_addr_jr, chain_b_revoke); // suppress unused warnings
}
