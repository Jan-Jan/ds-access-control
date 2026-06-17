//! End-to-end chopsticks integration test for the org-node chain path.
//!
//! Drives the full genesis ceremony + an admit-member update against a live
//! chopsticks-Paseo fork, reads state back via OnChainReader, and verifies
//! the received delta using verify_envelope_against_chain against the REAL
//! on-chain root. This is the functional gate for Tasks 5 and 6.
//!
//! Run with:
//!   pkill -f "chopsticks.*--config" 2>/dev/null
//!   CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features chain \
//!     --test chain_genesis_e2e -- --test-threads=1 --nocapture

#![cfg(feature = "chain")]

mod common;

use std::process::Command;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use on_chain_client::OrgRegistryClient;
use org_members::{MemberId, MemberLeaf};
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_node::chain_write::multisig::multi_account_id;
use org_node::chain_write::multisig::{dispatch_threshold_1, fund, FUND_AMOUNT};
use org_node::chain_write::proxy::{proxied, BlockSink};
use org_node::chain_write::calldata::revive_update_runtime_call;
use org_node::chain_write::WriteError;
use org_node::ceremony::genesis_ceremony;
use org_node::{ChainReader, OrgId, SeqGuard, SignedDeltaEnvelope, SigningKeypair, verify_envelope_against_chain, VerifyContext};
use org_node::OnChainReader;
use subxt_signer::sr25519::dev;

type Trie = OrgTrie<Blake3Hasher>;

// ---------------------------------------------------------------------------
// ChopsticksSink: BlockSink implementation for the test harness
// ---------------------------------------------------------------------------

struct ChopsticksSink<'a> {
    handle: &'a common::chopsticks_fork::ChopsticksHandle,
}

#[async_trait::async_trait]
impl<'a> BlockSink for ChopsticksSink<'a> {
    async fn settle(&self) -> Result<[u8; 32], WriteError> {
        let hash_hex = mine_block(self.handle)
            .await
            .map_err(|e| WriteError::Subxt(format!("{e:?}")))?;
        // Parse the 0x-prefixed 32-byte hex into [u8;32] (mirrors how
        // proxy.rs parses block hashes internally).
        let bytes = hex::decode(hash_hex.trim_start_matches("0x"))
            .map_err(|e| WriteError::Subxt(format!("block hash hex decode: {e}")))?;
        if bytes.len() != 32 {
            return Err(WriteError::Subxt(format!(
                "block hash was {} bytes, expected 32",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Contract deployment (same mechanics as off_chain_genesis_ceremony.rs)
// ---------------------------------------------------------------------------

/// Deploy OrgRegistry using the on-chain/scripts/sanity-deploy.mjs script.
/// Returns the deployed contract H160. The script path is resolved relative
/// to the org-node crate's manifest dir (going up to on-chain/).
fn deploy_org_registry() -> [u8; 20] {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let on_chain_dir = std::path::PathBuf::from(&manifest_dir).join("../on-chain");

    let output = Command::new("node")
        .arg("scripts/sanity-deploy.mjs")
        .current_dir(&on_chain_dir)
        .env("RPC_URL", "ws://localhost:8000")
        .env("BLOB_PATH", "tmp/revive/OrgRegistry.sol:OrgRegistry.pvm")
        .output()
        .expect("spawn sanity-deploy.mjs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- sanity-deploy stdout ---\n{stdout}--- end stdout ---");
    if !stderr.is_empty() {
        eprintln!("--- sanity-deploy stderr ---\n{stderr}--- end stderr ---");
    }
    assert!(output.status.success(), "sanity-deploy.mjs exited non-zero");

    let marker_line = stdout
        .lines()
        .find(|l| l.starts_with("DEPLOYED_H160="))
        .expect("DEPLOYED_H160= marker not found in deploy output");
    let hex_str = marker_line
        .trim_start_matches("DEPLOYED_H160=")
        .trim_start_matches("0x");
    let bytes = hex::decode(hex_str).expect("decode H160 hex");
    let mut h160 = [0u8; 20];
    assert_eq!(bytes.len(), 20, "deployed H160 was not 20 bytes");
    h160.copy_from_slice(&bytes);
    h160
}

// ---------------------------------------------------------------------------
// Trie helpers — mirrors test_fixtures.rs but in the integration test
// ---------------------------------------------------------------------------

fn admin_leaf(admin_kp: &SigningKeypair, admin_device: &SigningKeypair) -> MemberLeaf {
    MemberLeaf::new(
        MemberId::new([1u8; 32]),
        "admin",
        admin_kp.member_key(),
        "Admin",
        "User",
        vec![admin_device.device_key()],
    )
    .expect("valid admin leaf")
}

fn member_b_leaf(b_kp: &SigningKeypair, b_device: &SigningKeypair) -> MemberLeaf {
    MemberLeaf::new(
        MemberId::new([2u8; 32]),
        "bob",
        b_kp.member_key(),
        "Bob",
        "Member",
        vec![b_device.device_key()],
    )
    .expect("valid member B leaf")
}

// ---------------------------------------------------------------------------
// The e2e test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn genesis_then_admit_verifies_against_chain() {
    // ------------------------------------------------------------------
    // 1. Fork + contract + client
    // ------------------------------------------------------------------
    let fork = spawn_fork().await.expect("spawn chopsticks fork");
    eprintln!("chopsticks fork ready at {}", fork.ws_url);

    let contract = deploy_org_registry();
    eprintln!("contract deployed: 0x{}", hex::encode(contract));

    let api = legacy_client(&fork.ws_url).await.expect("legacy subxt client");
    let sink = ChopsticksSink { handle: &fork };

    // ------------------------------------------------------------------
    // 2. Dev accounts.
    //    pallet-multisig requires other_signatories to be non-empty
    //    (TooFewSignatories error if [] is passed). We use alice + bob
    //    as a 2-signer 1-of-2 threshold multisig. Alice signs the
    //    as_multi_threshold_1 extrinsics; bob is the other signatory.
    //    The chopsticks config only pre-funds Alice, so Alice funds the
    //    multisig pseudo-account.
    // ------------------------------------------------------------------
    let alice = dev::alice();
    let bob_pub: [u8; 32] = dev::bob().public_key().0;

    // Derive the alice+bob 1-of-2 multisig pseudo-account.
    let alice_pub: [u8; 32] = alice.public_key().0;
    let alice_bob_multi = multi_account_id(&[alice_pub, bob_pub], 1);
    eprintln!("alice+bob multi: 0x{}", hex::encode(alice_bob_multi));

    // Fund the alice+bob multisig account before the genesis ceremony.
    // Mine twice: once to flush the mempool lag, once to confirm inclusion.
    fund(&api, &alice, alice_bob_multi, FUND_AMOUNT * 10)
        .await
        .expect("fund alice+bob multisig");
    sink.settle().await.expect("mine fund-multisig (flush)");
    sink.settle().await.expect("mine fund-multisig (confirm)");

    // ------------------------------------------------------------------
    // 3. Build the genesis trie with one admin member leaf
    // ------------------------------------------------------------------
    let admin_kp = SigningKeypair::from_seed([0xA1u8; 32]);
    let admin_device = SigningKeypair::from_seed([0xA2u8; 32]);
    let org_pub_key: [u8; 32] = admin_kp.verifying_key().to_bytes();

    let leaf_a = admin_leaf(&admin_kp, &admin_device);
    let (genesis_trie, _genesis_delta) = Trie::genesis(vec![leaf_a])
        .expect("genesis trie")
        .recalculate()
        .expect("recalculate genesis");
    let genesis_root = genesis_trie.root_hash().expect("genesis root");
    eprintln!("genesis root: {:?}", genesis_root);

    // ------------------------------------------------------------------
    // 4. Run genesis_ceremony
    // ------------------------------------------------------------------
    let outcome = genesis_ceremony(
        &sink,
        &api,
        contract,
        &alice,     // funder (alice has 10^18 pre-funded by chopsticks config)
        &alice,     // admin signer (threshold-1 multisig: alice signs)
        &[bob_pub], // others (1-of-2 multisig: bob is the co-signatory)
        *genesis_root.as_bytes(),
        org_pub_key,
    )
    .await
    .expect("genesis ceremony");

    let p = outcome.p;
    let org_id: OrgId = outcome.org_id;
    eprintln!("P = 0x{}", hex::encode(p));
    eprintln!("org_id (h160) = 0x{}", hex::encode(org_id.as_bytes()));

    // ------------------------------------------------------------------
    // 5. OnChainReader: refresh and assert epoch 1 + genesis_root
    // ------------------------------------------------------------------
    let occ_client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("OrgRegistryClient");
    let reader = OnChainReader::new(occ_client, org_id);
    reader.refresh().await.expect("reader.refresh after genesis");

    let state_after_genesis = reader
        .get_org_state(&org_id)
        .expect("get_org_state")
        .expect("org state should be Some after genesis");
    eprintln!("on-chain state after genesis: {:?}", state_after_genesis);
    assert_eq!(state_after_genesis.epoch, 1, "epoch should be 1 after genesis");
    assert_eq!(
        state_after_genesis.root_hash.as_bytes(),
        genesis_root.as_bytes(),
        "on-chain root should equal genesis root"
    );

    // ------------------------------------------------------------------
    // 6. ADMIT: add member B, submit update(new_root, org_pub_key, 1)
    // ------------------------------------------------------------------
    let b_kp = SigningKeypair::from_seed([0xB1u8; 32]);
    let b_device = SigningKeypair::from_seed([0xB2u8; 32]);
    let leaf_b = member_b_leaf(&b_kp, &b_device);

    let (new_trie, admit_delta) = genesis_trie
        .add_member(leaf_b)
        .expect("add member B")
        .recalculate()
        .expect("recalculate after admit");
    let new_root = new_trie.root_hash().expect("new root after admit");
    eprintln!("new root after admit: {:?}", new_root);

    // Build the signed delta envelope: parent_seq = 2 (genesis is seq 0→1,
    // the first admin-authored update is seq 2 so it is > last_seen=1).
    let env = SignedDeltaEnvelope::build(
        org_id,
        2, // parent_seq: strictly greater than last_seen=1
        &admit_delta,
        &admin_kp,
    )
    .expect("build signed delta envelope");

    // Submit the update: dispatch via proxied multisig, then settle.
    let update_call = revive_update_runtime_call(
        contract,
        *new_root.as_bytes(),
        org_pub_key,
        1, // expectedEpoch = current epoch = 1
    );
    dispatch_threshold_1(&api, &alice, &[bob_pub], proxied(p, update_call))
        .await
        .expect("submit update via proxied multisig");
    sink.settle().await.expect("mine update block");

    // Refresh the reader — should now be epoch 2, new_root.
    reader.refresh().await.expect("reader.refresh after update");
    let state_after_update = reader
        .get_org_state(&org_id)
        .expect("get_org_state after update")
        .expect("org state should be Some after update");
    eprintln!("on-chain state after update: {:?}", state_after_update);
    assert_eq!(state_after_update.epoch, 2, "epoch should be 2 after update");
    assert_eq!(
        state_after_update.root_hash.as_bytes(),
        new_root.as_bytes(),
        "on-chain root should equal new root after admit"
    );

    // ------------------------------------------------------------------
    // 7. verify_envelope_against_chain: the decisive security check.
    //    The receiver holds the genesis_trie as its committed state.
    //    The envelope carries the admit delta (parent_seq=2).
    //    The on-chain root (epoch 2, new_root) is read via the reader.
    //    verify_envelope_against_chain must return Ok, and the committed
    //    trie root must equal new_root.
    // ------------------------------------------------------------------
    let ctx = VerifyContext {
        expected_org_id: org_id,
        author_member_key: &admin_kp.verifying_key(),
        seq_guard: SeqGuard::from_last_seen(1), // last committed seq was 1
        last_committed_epoch: 1,                // last committed epoch was 1
    };

    let verified = verify_envelope_against_chain(
        &genesis_trie, // local mirror = genesis trie (receiver's committed state)
        &env,
        &ctx,
        &reader,
    )
    .expect("verify_envelope_against_chain must succeed");

    eprintln!("verified epoch: {}", verified.epoch);
    eprintln!("verified seq: {}", verified.seq_guard.last_seen());

    assert_eq!(verified.epoch, 2, "verified epoch should be 2");
    assert_eq!(verified.seq_guard.last_seen(), 2, "seq guard should advance to 2");
    assert_eq!(
        verified.trie.root_hash().expect("committed trie root"),
        new_root,
        "committed trie root must equal the independently-read on-chain root"
    );

    eprintln!("=== chain_genesis_e2e PASSED ===");
}
