//! Scenario A (spec §5.2): two orgs, one watcher. Two pure proxies
//! P_a / P_b controlled by distinct 1-of-2 multisigs each submit a
//! genesis update; an unfiltered watcher sees both, a filtered watcher
//! sees only A's. A second update from A arrives as Event::Update with
//! epoch 2 and prev_root_hash = A's genesis root.
//!
//! Real-chain behaviour pinned here (Task 7 finding): a freshly-created
//! pure proxy is NOT auto-mapped in pallet-revive, so its first
//! `Revive.call` reverts (`Proxy.ProxyExecuted { result: Err(Module {
//! index: 100, error: 43 }) }`, no `ContractEmitted`). Each org's pure
//! proxy must therefore dispatch `Revive.map_account` (no args) AS
//! ITSELF, once, after funding, before it can submit
//! `OrgRegistry.update`. See `common::proxy::map_account_call`.

#![cfg(feature = "dev-rpc")]

mod common;

use std::process::Command;
use std::time::Duration;

use common::chopsticks_fork::{ChopsticksHandle, spawn_fork};
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use common::multisig::{FUND_AMOUNT, dispatch_threshold_1, fund, multi_account_id};
use common::proxy::{create_pure_via_multisig, map_account_call, proxied};
use common::submit::revive_update_runtime_call;
use futures_util::StreamExt;
use on_chain_client::{
    Epoch, Event, OnChainRootHash, OrgAdmin, OrgPubKey, OrgRegistryClient, SubscribedEvent,
    h160_of,
};
use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt_signer::sr25519::{Keypair, dev};

const ROOT_A1: [u8; 32] = [0xa1; 32];
const KEY_A: [u8; 32] = [0xaa; 32];
const ROOT_A2: [u8; 32] = [0xa2; 32];
const ROOT_B1: [u8; 32] = [0xb1; 32];
const KEY_B: [u8; 32] = [0xbb; 32];

struct Org {
    signer: Keypair,
    other: [u8; 32],
    pure_proxy: [u8; 32],
    admin: OrgAdmin,
}

#[tokio::test]
async fn two_orgs_one_watcher() {
    let fork = spawn_fork().await.expect("spawn fork");
    let contract = deploy_org_registry();
    let api = legacy_client(&fork.ws_url).await.expect("legacy client");
    let client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");

    // Org A: multisig {alice, bob} → P_a. Org B: multisig {charlie, dave} → P_b.
    let org_a = setup_org(&fork, &api, dev::alice(), dev::bob().public_key().0).await;
    let org_b = setup_org(&fork, &api, dev::charlie(), dev::dave().public_key().0).await;
    assert_ne!(org_a.admin, org_b.admin, "distinct orgs must map to distinct OrgIds");

    let mut watcher_all = client.subscribe(None).await.expect("subscribe all");
    let mut watcher_a = client.subscribe(Some(org_a.admin)).await.expect("subscribe A");

    // Genesis A, then genesis B, in separate blocks (deterministic order).
    genesis(&fork, &api, &org_a, contract, ROOT_A1, KEY_A).await;
    genesis(&fork, &api, &org_b, contract, ROOT_B1, KEY_B).await;

    let ev1 = next_event(&mut watcher_all).await;
    let ev2 = next_event(&mut watcher_all).await;
    assert_eq!(
        ev1,
        Event::Genesis {
            admin: org_a.admin,
            root_hash: OnChainRootHash(ROOT_A1),
            org_pub_key: OrgPubKey(KEY_A),
        },
        "first event should be A's genesis (mined first)",
    );
    assert_eq!(
        ev2,
        Event::Genesis {
            admin: org_b.admin,
            root_hash: OnChainRootHash(ROOT_B1),
            org_pub_key: OrgPubKey(KEY_B),
        },
        "second event should be B's genesis",
    );

    // Second update from A: expected_epoch = 1 → epoch becomes 2.
    let update_call = revive_update_runtime_call(contract, ROOT_A2, KEY_A, 1);
    dispatch_threshold_1(
        &api,
        &org_a.signer,
        &[org_a.other],
        proxied(org_a.pure_proxy, update_call),
    )
    .await
    .expect("submit A update 2");
    mine_block(&fork).await.expect("mine A update 2");

    let ev3 = next_event(&mut watcher_all).await;
    assert_eq!(
        ev3,
        Event::Update {
            admin: org_a.admin,
            epoch: Epoch(2),
            root_hash: OnChainRootHash(ROOT_A2),
            org_pub_key: OrgPubKey(KEY_A),
            prev_root_hash: OnChainRootHash(ROOT_A1),
        },
    );

    // Filtered watcher: sees A's genesis and A's update — never B's.
    let a1 = next_event(&mut watcher_a).await;
    let a2 = next_event(&mut watcher_a).await;
    assert!(matches!(a1, Event::Genesis { admin, .. } if admin == org_a.admin));
    assert!(
        matches!(a2, Event::Update { admin, epoch, .. } if admin == org_a.admin && epoch == Epoch(2)),
        "filtered watcher's second event should be A's epoch-2 update, got {a2:?}",
    );
}

async fn setup_org(
    fork: &ChopsticksHandle,
    api: &OnlineClient<PolkadotConfig>,
    signer: Keypair,
    other: [u8; 32],
) -> Org {
    let funder = dev::eve();
    let multi = multi_account_id(&[signer.public_key().0, other], 1);
    fund(api, &funder, multi, FUND_AMOUNT).await.expect("fund multisig");
    mine_block(fork).await.expect("mine fund");
    let pure_proxy = create_pure_via_multisig(fork, api, &signer, &[other])
        .await
        .expect("create pure proxy");
    fund(api, &funder, pure_proxy, FUND_AMOUNT).await.expect("fund pure proxy");
    mine_block(fork).await.expect("mine fund proxy");
    // map_account: a fresh pure proxy has no pallet-revive address
    // mapping, so a `Revive.call` from it reverts (Revive error 43,
    // pallet 100) before emitting `ContractEmitted` — see the doc-comment
    // on `map_account_call`. Map P AS ITSELF (via the controlling
    // multisig → Proxy.proxy) once, before any genesis update.
    dispatch_threshold_1(api, &signer, &[other], proxied(pure_proxy, map_account_call()))
        .await
        .expect("submit map_account");
    mine_block(fork).await.expect("mine map_account");
    Org {
        admin: OrgAdmin(h160_of(pure_proxy)),
        signer,
        other,
        pure_proxy,
    }
}

async fn genesis(
    fork: &ChopsticksHandle,
    api: &OnlineClient<PolkadotConfig>,
    org: &Org,
    contract: [u8; 20],
    root: [u8; 32],
    key: [u8; 32],
) {
    let call = revive_update_runtime_call(contract, root, key, 0);
    dispatch_threshold_1(api, &org.signer, &[org.other], proxied(org.pure_proxy, call))
        .await
        .expect("submit genesis");
    mine_block(fork).await.expect("mine genesis");
}

async fn next_event(
    stream: &mut on_chain_client::SubscribedEventStream,
) -> Event {
    loop {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("timed out waiting for subscribed event")
            .expect("stream ended")
            .expect("stream item error");
        match item {
            SubscribedEvent::BestBlockEvent { event, .. } => return event,
            // Finalised/Reorged notifications (a later subscribe
            // extension) are skipped — this scenario asserts best-block
            // semantics.
            _ => continue,
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
