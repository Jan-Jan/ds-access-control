//! Scenario B (spec §5.2): off-chain genesis ceremony. A pure proxy P
//! exists but no update() has been called. The admin multisig rotates
//! (M1 {alice,bob} → M2 {charlie,dave}) — P is untouched. The NEW
//! multisig then submits genesis. Asserts: the genesis event's admin is
//! h160_of(P) (the rotation is invisible to the contract), and the old
//! multisig can no longer act through P.
//!
//! NOTE (pallet-revive mapping, pinned by Scenario A): a fresh pure
//! proxy must dispatch `Revive.map_account` as itself before its first
//! contract call; done below right after funding P.

#![cfg(feature = "dev-rpc")]

mod common;

use std::process::Command;
use std::time::Duration;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use common::multisig::{FUND_AMOUNT, dispatch_threshold_1, fund, multi_account_id};
use common::proxy::{create_pure_via_multisig, map_account_call, proxied, rotate};
use common::submit::revive_update_runtime_call;
use futures_util::StreamExt;
use on_chain_client::{
    Epoch, Event, OnChainRootHash, OrgAdmin, OrgPubKey, OrgRegistryClient, OrgState,
    SubscribedEvent, h160_of,
};
use subxt_signer::sr25519::dev;

const ROOT: [u8; 32] = [0x77; 32];
const KEY: [u8; 32] = [0x88; 32];

#[tokio::test]
async fn rotation_before_genesis_is_invisible_to_contract() {
    let fork = spawn_fork().await.expect("spawn fork");
    let contract = deploy_org_registry();
    let api = legacy_client(&fork.ws_url).await.expect("legacy client");
    let client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");

    let alice = dev::alice();
    let bob: [u8; 32] = dev::bob().public_key().0;
    let charlie = dev::charlie();
    let dave: [u8; 32] = dev::dave().public_key().0;
    let funder = dev::eve();

    // M1 {alice, bob} creates P; P funded + revive-mapped.
    let m1 = multi_account_id(&[alice.public_key().0, bob], 1);
    fund(&api, &funder, m1, FUND_AMOUNT).await.expect("fund M1");
    mine_block(&fork).await.expect("mine");
    let p = create_pure_via_multisig(&fork, &api, &alice, &[bob])
        .await
        .expect("create P");
    fund(&api, &funder, p, FUND_AMOUNT).await.expect("fund P");
    mine_block(&fork).await.expect("mine");
    dispatch_threshold_1(&api, &alice, &[bob], proxied(p, map_account_call()))
        .await
        .expect("map_account as P");
    mine_block(&fork).await.expect("mine map_account");
    let admin = OrgAdmin(h160_of(p));

    // Rotate to M2 {charlie, dave}. P unchanged.
    let m2 = multi_account_id(&[charlie.public_key().0, dave], 1);
    fund(&api, &funder, m2, FUND_AMOUNT).await.expect("fund M2");
    mine_block(&fork).await.expect("mine");
    rotate(&fork, &api, p, &alice, &[bob], m1, m2)
        .await
        .expect("rotate M1 -> M2");

    // Genesis from the NEW multisig.
    let mut stream = client.subscribe(None).await.expect("subscribe");
    let call = revive_update_runtime_call(contract, ROOT, KEY, 0);
    dispatch_threshold_1(&api, &charlie, &[dave], proxied(p, call))
        .await
        .expect("genesis via M2");
    mine_block(&fork).await.expect("mine genesis");

    let (event, _at) = loop {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("timed out waiting for subscribed event")
            .expect("stream ended")
            .expect("stream item error");
        if let SubscribedEvent::BestBlockEvent { event, at } = item {
            break (event, at);
        }
    };
    assert_eq!(
        event,
        Event::Genesis {
            admin,
            root_hash: OnChainRootHash(ROOT),
            org_pub_key: OrgPubKey(KEY),
        },
        "genesis admin must be h160_of(P) — rotation invisible to contract",
    );

    let state = client
        .get_org_state(admin, None)
        .await
        .expect("get_org_state")
        .expect("state exists");
    assert_eq!(
        state,
        OrgState {
            root_hash: OnChainRootHash(ROOT),
            org_pub_key: OrgPubKey(KEY),
            epoch: Epoch(1),
        },
    );

    // The OLD multisig can no longer act through P: its proxied update
    // must NOT produce a contract event (Proxy.NotProxy dispatch error).
    // The stale update carries a distinctive root_hash (0x99..) so we can
    // tell it apart from genesis re-deliveries.
    const STALE_ROOT: OnChainRootHash = OnChainRootHash([0x99; 32]);
    let call2 = revive_update_runtime_call(contract, [0x99; 32], KEY, 1);
    dispatch_threshold_1(&api, &alice, &[bob], proxied(p, call2))
        .await
        .expect("submit (expected to fail at dispatch level)");
    mine_block(&fork).await.expect("mine");

    // Negative check. We cannot use a bare `stream.next()` timeout-and-
    // assert-is_err: with the finalised lane merged in, the EARLIER
    // genesis event is re-delivered as a `FinalisedEvent` (and chopsticks
    // may also re-emit it as a best-block event), so the stream is NOT
    // expected to be empty during the window. Instead we drain everything
    // that arrives for up to 10s and fail ONLY if any decoded event
    // carries the stale update's root_hash — that would mean the rotated-
    // out multisig successfully acted through P. Genesis re-deliveries on
    // either lane are tolerated.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.next()).await {
            // Window elapsed with no further item — done.
            Err(_) => break,
            // Stream ended — done.
            Ok(None) => break,
            Ok(Some(item)) => {
                let item = item.expect("stream item error");
                let event = match item {
                    SubscribedEvent::BestBlockEvent { event, .. } => Some(event),
                    SubscribedEvent::FinalisedEvent { event, .. } => Some(event),
                    SubscribedEvent::Reorged { .. } => None,
                };
                if let Some(event) = event {
                    let root = match event {
                        Event::Genesis { root_hash, .. } => root_hash,
                        Event::Update { root_hash, .. } => root_hash,
                    };
                    assert_ne!(
                        root, STALE_ROOT,
                        "old multisig produced a contract event after rotation: {event:?}",
                    );
                }
            }
        }
    }
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
