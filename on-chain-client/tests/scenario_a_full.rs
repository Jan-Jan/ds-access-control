//! Scenario-A-full: single-org end-to-end over the legacy backend.
//! Extends the old A-lite (event observation at a pinned block) with:
//!
//! - `subscribe()` driving the event observation (verifies subxt's
//!   block stream actually works over the explicit LegacyBackend —
//!   the old CombinedBackend silently yielded zero items against
//!   chopsticks).
//! - `get_org_state` returning the genesis state via the
//!   `ReviveApi::get_storage` runtime API (per the 2026-06-04
//!   amendment; pallet-revive keeps contract slots in a per-contract
//!   child trie, so there is no storage map to read).
//!
//! Multisig + pure-proxy scenarios layer on top in later tasks.

#![cfg(feature = "dev-rpc")]

mod common;

use std::process::Command;
use std::time::Duration;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use common::h160_mapper::h160_of;
use common::submit::submit_update;
use futures_util::StreamExt;
use on_chain_client::{
    Epoch, Event, OnChainRootHash, OrgAdmin, OrgPubKey, OrgRegistryClient, OrgState,
    SubscribedEvent,
};
use subxt_signer::sr25519::dev;

#[tokio::test]
async fn single_org_genesis_event_and_state() {
    let fork = spawn_fork().await.expect("spawn fork");

    let contract = deploy_org_registry();
    eprintln!("deployed OrgRegistry at 0x{}", hex::encode(contract));

    let api = legacy_client(&fork.ws_url).await.expect("legacy client");
    let client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");

    let alice = dev::alice();
    let alice_h160 = h160_of(alice.public_key().0);
    let admin = OrgAdmin(alice_h160);

    // Never-written slot reads as None before genesis.
    let pre = client.get_org_state(admin, None).await.expect("pre-genesis read");
    assert_eq!(pre, None, "state should be empty before genesis");

    let mut stream = client.subscribe(None).await.expect("subscribe");

    let root_hash = [0xaau8; 32];
    let org_pub_key = [0xbbu8; 32];
    submit_update(&api, &alice, contract, root_hash, org_pub_key, 0)
        .await
        .expect("submit update");
    let new_best = mine_block(&fork).await.expect("mine_block");
    eprintln!("mined block: {new_best}");

    // The stream should yield the genesis event from the freshly-mined
    // best block. Loop: a future subscribe() extension also yields
    // FinalisedEvent/Reorged items — skip anything that isn't a
    // best-block event. Timeout guards the old silent-empty-stream
    // failure mode.
    let (event, at) = loop {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("timed out waiting for subscribed event")
            .expect("stream ended")
            .expect("stream item error");
        if let SubscribedEvent::BestBlockEvent { event, at } = item {
            break (event, at);
        }
    };
    eprintln!("event at block #{} ({:?})", at.number, at.hash);
    assert_eq!(
        event,
        Event::Genesis {
            admin,
            root_hash: OnChainRootHash(root_hash),
            org_pub_key: OrgPubKey(org_pub_key),
        },
        "decoded Genesis event should match submitted update",
    );

    // State read via ReviveApi::get_storage: genesis writes epoch 1.
    let state = client
        .get_org_state(admin, None)
        .await
        .expect("get_org_state")
        .expect("state should exist after genesis");
    assert_eq!(
        state,
        OrgState {
            root_hash: OnChainRootHash(root_hash),
            org_pub_key: OrgPubKey(org_pub_key),
            epoch: Epoch(1),
        },
    );
}

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
