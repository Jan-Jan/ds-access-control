//! Stage 2 Task 6 gate. Confirms the test harness can spin a
//! chopsticks-Paseo fork up, talk to it, and shut it down cleanly.
//! Numeric `00_` prefix keeps it ordered first under `cargo test`
//! reporting so a broken fork shows here before downstream tests fail
//! for confusing reasons.

#![cfg(feature = "dev-rpc")]

mod common;

use common::chopsticks_fork::spawn_fork;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use serde_json::Value;

#[tokio::test]
async fn fork_spawns_and_serves_rpc() {
    let fork = spawn_fork().await.expect("spawn chopsticks fork");

    let client = WsClientBuilder::default()
        .build(&fork.ws_url)
        .await
        .expect("ws connect");
    let rv: Value = client
        .request("state_getRuntimeVersion", rpc_params![])
        .await
        .expect("state_getRuntimeVersion");
    let spec_version = rv
        .get("specVersion")
        .and_then(Value::as_u64)
        .expect("specVersion field");
    assert!(spec_version > 0, "spec_version was zero");
    // Dropping `fork` here kills chopsticks; no explicit cleanup needed.
}
