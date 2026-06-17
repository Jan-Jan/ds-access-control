#![cfg(feature = "transport")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Two real iroh endpoints on loopback. A sends an admit envelope to B; B
//! authenticates A's device key from the connection and verifies against a
//! MockChain. Offline (no relay/internet — loopback direct connect only).
use std::time::Duration;

use org_node::chain::{MockChain, OrgState};
use org_node::ids::OrgId;
use org_node::keys::SigningKeypair;
use org_node::sequence::SeqGuard;
use org_node::transport::endpoint::OrgEndpoint;
use org_node::transport::wire::WireMessage;
use org_node::verify::{VerifyContext, verify_envelope_against_chain};
use org_node::SignedDeltaEnvelope;
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::{MemberId, MemberLeaf};

type Trie = OrgTrie<Blake3Hasher>;

// Inline genesis_and_admit — test_fixtures is lib-private to the crate.
// Matches the fixture convention: admin keypair doubles as device key.
// Returns (genesis_trie, new_trie, delta) where new_trie adds bob.
fn genesis_and_admit(admin: &SigningKeypair) -> (Trie, Trie, org_members::delta::Delta) {
    let admin_leaf = MemberLeaf::new(
        MemberId::new([1u8; 32]),
        "admin",
        admin.member_key(),
        "Admin",
        "User",
        vec![admin.device_key()],
    )
    .unwrap();
    let (genesis, _) = Trie::genesis(vec![admin_leaf])
        .unwrap()
        .recalculate()
        .unwrap();

    let b_member = SigningKeypair::from_seed([2u8; 32]);
    let b_device = SigningKeypair::from_seed([3u8; 32]);
    let b_leaf = MemberLeaf::new(
        MemberId::new([2u8; 32]),
        "bob",
        b_member.member_key(),
        "Bob",
        "User",
        vec![b_device.device_key()],
    )
    .unwrap();
    let (new_trie, delta) = genesis.add_member(b_leaf).unwrap().recalculate().unwrap();
    (genesis, new_trie, delta)
}

#[tokio::test]
async fn delivers_and_verifies_admit_over_iroh() {
    // Admin keypair: MEMBER key signs the envelope (same keypair doubles as
    // device key in our fixture, matching test_fixtures convention).
    let admin = SigningKeypair::from_seed([1u8; 32]);
    // A's iroh identity (device key = iroh EndpointId).
    let a_device = SigningKeypair::from_seed([10u8; 32]);
    // B's iroh identity.
    let b_device = SigningKeypair::from_seed([11u8; 32]);
    let org = OrgId::new([5u8; 20]);

    // Build genesis + admit-bob delta.
    let (genesis, new_trie, delta) = genesis_and_admit(&admin);
    let new_root = new_trie.root_hash().unwrap();
    let env = SignedDeltaEnvelope::build(org, 2, &delta, &admin).unwrap();
    let msg = WireMessage { envelope: env.clone(), org_secret: Some([0xab; 32]), genesis_snapshot: None };

    // Bind both endpoints (relay disabled, loopback only).
    let ep_a = OrgEndpoint::bind(&a_device).await.unwrap();
    let ep_b = OrgEndpoint::bind(&b_device).await.unwrap();
    // Dial via inner().addr(): empirically this is what iroh accepts for the
    // loopback direct connection here (node_addr_for_dial(), built from
    // bound_sockets, does not complete the dial in this setup).
    let b_addr = ep_b.inner().addr();

    // B receives in a background task — spawn before A dials so accept() is
    // already waiting when A's connect() arrives.
    let recv_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), ep_b.recv_one())
            .await
            .expect("recv_one timed out after 10 s")
    });

    // A sends to B's direct address.
    tokio::time::timeout(Duration::from_secs(10), ep_a.send(b_addr, &msg))
        .await
        .expect("send timed out after 10 s")
        .expect("send failed");

    let (remote_device, got) = recv_task
        .await
        .expect("recv task panicked")
        .expect("recv_one failed");

    // 1. The QUIC handshake authenticated A's device key.
    assert_eq!(
        remote_device.as_bytes(),
        a_device.device_key().as_bytes(),
        "authenticated remote device key must equal A's device key"
    );

    // 2. The WireMessage arrived intact.
    assert_eq!(got, msg, "received WireMessage must equal sent WireMessage");

    // 3. B verifies the received envelope against a MockChain seeded with
    //    the new root at epoch 2 (simulating an independent on-chain read).
    let mut chain = MockChain::new();
    chain.set(org, OrgState { root_hash: new_root, org_pub_key: [0u8; 32], epoch: 2 });
    let ctx = VerifyContext {
        expected_org_id: org,
        // admin.member_key().as_bytes() == admin.verifying_key().as_bytes()
        author_member_key: &admin.verifying_key(),
        seq_guard: SeqGuard::from_last_seen(1),
        last_committed_epoch: 1,
    };
    let out = verify_envelope_against_chain(&genesis, &got.envelope, &ctx, &chain)
        .expect("verify_envelope_against_chain must succeed");

    assert_eq!(
        out.trie.root_hash().unwrap(),
        new_root,
        "committed root must equal the expected new root"
    );
    assert_eq!(out.epoch, 2, "committed epoch must be 2");
}
