//! OrgId invariant (spec Risk #5): h160_of(P) — our offline pallet-revive
//! AccountId32→H160 mapping — must equal the admin the runtime itself
//! puts in the contract event, and must be stable across a multisig
//! rotation. The runtime event is the ground-truth fixture: if
//! pallet-revive's mapping drifts in a future runtime, this test is the
//! tripwire.

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
use on_chain_client::{Event, OrgAdmin, OrgRegistryClient, SubscribedEvent, h160_of};
use subxt_signer::sr25519::dev;

#[tokio::test]
async fn pure_proxy_h160_is_org_id_and_survives_rotation() {
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

    // M1 → P (funded + revive-mapped). Predict the OrgId offline BEFORE
    // the chain confirms it.
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
    let predicted_org_id = h160_of(p);

    // Genesis via M1; capture the runtime's admin from the event.
    let mut stream = client.subscribe(None).await.expect("subscribe");
    dispatch_threshold_1(
        &api,
        &alice,
        &[bob],
        proxied(p, revive_update_runtime_call(contract, [0x11; 32], [0x22; 32], 0)),
    )
    .await
    .expect("genesis");
    mine_block(&fork).await.expect("mine");
    let admin_genesis = next_admin(&mut stream).await;
    assert_eq!(
        admin_genesis,
        OrgAdmin(predicted_org_id),
        "runtime's OrgId (event admin) != our offline h160_of(P) — mapping drift",
    );

    // Rotate M1 → M2, then update via M2: OrgId must be unchanged.
    let m2 = multi_account_id(&[charlie.public_key().0, dave], 1);
    fund(&api, &funder, m2, FUND_AMOUNT).await.expect("fund M2");
    mine_block(&fork).await.expect("mine");
    rotate(&fork, &api, p, &alice, &[bob], m1, m2).await.expect("rotate");

    dispatch_threshold_1(
        &api,
        &charlie,
        &[dave],
        proxied(p, revive_update_runtime_call(contract, [0x33; 32], [0x22; 32], 1)),
    )
    .await
    .expect("update via M2");
    mine_block(&fork).await.expect("mine");
    let admin_update = next_admin(&mut stream).await;
    assert_eq!(
        admin_update,
        OrgAdmin(predicted_org_id),
        "OrgId changed across multisig rotation — invariant broken",
    );
}

async fn next_admin(stream: &mut on_chain_client::SubscribedEventStream) -> OrgAdmin {
    loop {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("timeout")
            .expect("stream ended")
            .expect("stream error");
        if let SubscribedEvent::BestBlockEvent { event, .. } = item {
            return match event {
                Event::Genesis { admin, .. } | Event::Update { admin, .. } => admin,
            };
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
