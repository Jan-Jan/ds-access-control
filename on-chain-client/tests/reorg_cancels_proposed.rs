//! Scenario C (spec §5.2): a reorg discards a proposed (best-block-only)
//! update. Genesis lands and is stable; a second update is observed at
//! the best tip; a depth-1 reorg (`dev_setHead(parent) + dev_newBlock`)
//! discards that block. The CLIENT behaviour under test:
//!
//!   1. the proposed update surfaces as a `BestBlockEvent` carrying the
//!      distinctive root, observed BEFORE the reorg; and
//!   2. the watcher then receives `Reorged { discarded }` whose hash
//!      equals the exact discarded block hash.
//!
//! Both are asserted. These are the load-bearing watcher guarantees: a
//! consumer that treated a best-only update as committed would learn of
//! the reversal via the `Reorged` notification.
//!
//! ── Chopsticks divergence #1: finality (recorded in the spec's Open
//! Items by the docs task) ───────────────────────────────────────────
//! Chopsticks finalises every `dev_newBlock` immediately, so the proposed
//! update may surface as a `FinalisedEvent` BEFORE the reorg — a
//! divergence from live GRANDPA, where a finalised block can never be
//! reorged. This test therefore tolerates (ignores) finalised-lane
//! deliveries entirely. The live-chain smoke test is the authority on
//! real finality semantics.
//!
//! ── Chopsticks divergence #2: `dev_setHead` does NOT revert storage
//! (recorded by the docs task) ────────────────────────────────────────
//! On a real chain a reorg that orphans the update block would (until the
//! update extrinsic is re-gossiped and re-included, if ever) leave the
//! canonical chain WITHOUT the update, so state at the new tip would show
//! the genesis epoch. Chopsticks does NOT model this: `dev_setHead`
//! repoints the canonical head pointer WITHOUT rolling back the underlying
//! storage DB — state writes made by the rewound block persist in the
//! child-trie regardless of which block is currently canonical. (The
//! rewound extrinsic may additionally re-surface from the un-cleared
//! txpool and be re-applied by `dev_newBlock` in some runs, but that
//! secondary effect is not what the committed test observes; the
//! storage-not-reverted mechanism alone explains the outcome.)
//!
//! Consequence: a chopsticks depth-1 reorg discards block IDENTITY but
//! NOT STATE — the post-reorg best block has a distinct hash and is empty
//! (`extrinsics: []`), yet a state read at that block still shows the
//! proposed update (epoch 2). This test asserts that chopsticks-true
//! outcome. The spec's intended property — that a reorg discards the
//! update's state effects — cannot be demonstrated on chopsticks and is
//! explicitly delegated to live-chain verification, where real GRANDPA /
//! mempool semantics apply.
//!
//! `get_org_state` at-semantics: the post-reorg read uses an EXPLICIT
//! `Some(reorg.new_best)` block hash. The `None` (latest-finalised, via
//! `at_current_block`) read also resolves to the same post-reorg state
//! here — chopsticks' finalised head follows the new tip — but the
//! explicit hash is deterministic and is what the test asserts on.

#![cfg(feature = "dev-rpc")]

mod common;

use std::process::Command;
use std::time::Duration;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::{induce_reorg, mine_block};
use common::conn::legacy_client;
use common::h160_mapper::h160_of;
use common::submit::submit_update;
use futures_util::StreamExt;
use on_chain_client::{
    BlockHash, Epoch, Event, OnChainRootHash, OrgAdmin, OrgPubKey, OrgRegistryClient, OrgState,
    SubscribedEvent,
};
use subxt_signer::sr25519::dev;

const ROOT_1: [u8; 32] = [0x01; 32];
const ROOT_2: [u8; 32] = [0x02; 32];
const KEY: [u8; 32] = [0x0c; 32];

#[tokio::test]
async fn reorg_discards_proposed_update() {
    let fork = spawn_fork().await.expect("spawn fork");
    let contract = deploy_org_registry();
    let api = legacy_client(&fork.ws_url).await.expect("legacy client");
    let client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");

    let alice = dev::alice();
    let admin = OrgAdmin(h160_of(alice.public_key().0));

    // Genesis (stable base).
    submit_update(&api, &alice, contract, ROOT_1, KEY, 0)
        .await
        .expect("submit genesis");
    let genesis_block = mine_block(&fork).await.expect("mine genesis");

    let mut stream = client.subscribe(None).await.expect("subscribe");

    // Proposed update at the tip.
    submit_update(&api, &alice, contract, ROOT_2, KEY, 1)
        .await
        .expect("submit update 2");
    let update_block = mine_block(&fork).await.expect("mine update");

    // Watcher sees the proposed update as a best-block event (drain past
    // finalised-lane re-deliveries of genesis and the update itself).
    let best_at = loop {
        let item = next_item(&mut stream).await;
        if let SubscribedEvent::BestBlockEvent {
            event: Event::Update { epoch, root_hash, .. },
            at,
        } = item
        {
            assert_eq!(epoch, Epoch(2));
            assert_eq!(root_hash, OnChainRootHash(ROOT_2));
            break at;
        }
    };
    assert_eq!(
        hex_of(best_at.hash),
        update_block.to_lowercase(),
        "best-block event should come from the freshly-mined update block",
    );

    // Reorg: discard the update block, mine an empty sibling.
    let reorg = induce_reorg(&fork, &update_block, &genesis_block)
        .await
        .expect("induce reorg");
    eprintln!("reorged: discarded {} new best {}", reorg.discarded, reorg.new_best);

    // Watcher receives Reorged for the exact discarded block.
    let discarded = loop {
        let item = next_item(&mut stream).await;
        if let SubscribedEvent::Reorged { discarded } = item {
            break discarded;
        }
    };
    assert_eq!(
        hex_of(discarded.hash),
        update_block.to_lowercase(),
        "Reorged should reference the discarded update block",
    );

    // Sanity-check that the discarded block really carried the update
    // (so the Reorged notification above wasn't about an unrelated block):
    // state pinned at the now-orphaned hash still shows epoch 2.
    let discarded_state = client
        .get_org_state(admin, Some(parse_block_hash(&update_block)))
        .await
        .expect("get_org_state @ discarded")
        .expect("discarded state exists");
    assert_eq!(
        discarded_state.epoch,
        Epoch(2),
        "the discarded block should have carried the proposed update",
    );

    // State read at the post-reorg best block. See divergence #2 in the
    // module doc-comment: chopsticks `dev_setHead` does not revert
    // storage, so the epoch-2 child-trie write persists even though the
    // new-best block is empty and has a distinct hash. We assert the
    // chopsticks-true outcome (epoch 2); the state-discards property is
    // the live-chain smoke test's responsibility.
    let at = parse_block_hash(&reorg.new_best);
    let state = client
        .get_org_state(admin, Some(at))
        .await
        .expect("get_org_state")
        .expect("state exists");
    assert_eq!(
        state,
        OrgState {
            root_hash: OnChainRootHash(ROOT_2),
            org_pub_key: OrgPubKey(KEY),
            epoch: Epoch(2),
        },
        "post-reorg state persists (chopsticks dev_setHead does not revert storage)",
    );
}

async fn next_item(
    stream: &mut on_chain_client::SubscribedEventStream,
) -> SubscribedEvent {
    tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await
        .expect("timed out waiting for subscribed item")
        .expect("stream ended")
        .expect("stream item error")
}

fn hex_of(h: BlockHash) -> String {
    format!("0x{}", hex::encode(h.0))
}

fn parse_block_hash(s: &str) -> BlockHash {
    let bytes = hex::decode(s.trim_start_matches("0x")).expect("block hash hex");
    let mut out = [0u8; 32];
    assert_eq!(bytes.len(), 32, "block hash length");
    out.copy_from_slice(&bytes);
    BlockHash(out)
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
