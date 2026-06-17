//! AppState: the Tauri-managed state for the ODS PoC app.
//!
//! On startup, `AppState::init` reads env vars to determine:
//!
//! - Data directory: `ODS_DATA_DIR` if set; otherwise Tauri's `app_data_dir`.
//! - Passphrase: `ODS_PASSPHRASE` if set; otherwise `"ods-dev-default"` (S9).
//! - Chain mode: if `ODS_CHAIN_WS` + `ODS_CONTRACT_H160` + `ODS_ADMIN_SEED`
//!   are all set, `build_chain_ops` is called EAGERLY inside `init` via
//!   `block_on`.  If that succeeds a real `SubxtChainOps` is wired in and
//!   `chain_ready` is set to `true`.  If it fails (env vars absent or connect
//!   error) the service falls back to `ChainNotConfigured` and `chain_ready`
//!   remains `false`.
//!
//! `OrgService` is held behind a `tokio::sync::Mutex` so Tauri command
//! handlers can take an async lock without blocking the thread pool.

use std::path::PathBuf;

use org_node::service::{ChainOps, OrgService};
use org_node::store::PersonaStore;
use org_node::transport::TransportMode;
use org_node::OrgNodeError;
use tokio::sync::Mutex;

/// Shared Tauri-managed state.  Tauri's `.manage()` wraps this in `State<T>`;
/// command handlers extract it via `State<'_, AppState>`.
pub struct AppState {
    pub service: Mutex<OrgService>,
    /// `true` only when `build_chain_ops` succeeded during `init` and a real
    /// `SubxtChainOps` was wired into the service.  `false` means the service
    /// is running with `ChainNotConfigured`; chain commands will return errors.
    pub chain_ready: bool,
    /// Guard for `start_receiver`: once set to `true`, additional calls to
    /// `start_receiver` are no-ops so we never spawn duplicate receiver loops.
    pub receiver_started: std::sync::atomic::AtomicBool,
}

/// A `ChainOps` implementation that rejects every call with a clear message
/// indicating that the chain env vars are not configured.  Used when the app
/// starts without `ODS_CHAIN_WS` / `ODS_CONTRACT_H160` / `ODS_ADMIN_SEED`.
struct ChainNotConfigured;

#[async_trait::async_trait]
impl ChainOps for ChainNotConfigured {
    async fn submit_genesis(
        &self,
        _genesis_root: [u8; 32],
        _org_pub_key: [u8; 32],
    ) -> Result<(org_node::OrgId, Option<[u8; 32]>), OrgNodeError> {
        Err(OrgNodeError::Chain(
            "chain not configured: set ODS_CHAIN_WS, ODS_CONTRACT_H160, ODS_ADMIN_SEED"
                .into(),
        ))
    }

    async fn submit_update(
        &self,
        _org_id: org_node::OrgId,
        _new_root: [u8; 32],
        _org_pub_key: [u8; 32],
        _expected_epoch: u64,
        _proxy_account: Option<[u8; 32]>,
    ) -> Result<(), OrgNodeError> {
        Err(OrgNodeError::Chain(
            "chain not configured: set ODS_CHAIN_WS, ODS_CONTRACT_H160, ODS_ADMIN_SEED"
                .into(),
        ))
    }

    async fn read_state(
        &self,
        _org_id: org_node::OrgId,
    ) -> Result<Option<org_node::OrgState>, OrgNodeError> {
        Err(OrgNodeError::Chain(
            "chain not configured: set ODS_CHAIN_WS, ODS_CONTRACT_H160, ODS_ADMIN_SEED"
                .into(),
        ))
    }
}

/// Connection status reported by the `connection_status` command.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionStatus {
    /// `true` only when a real `SubxtChainOps` was successfully constructed
    /// during startup (i.e. env vars were present AND the connection succeeded).
    /// `false` means the service is using `ChainNotConfigured`; chain commands
    /// will return errors even if the env vars look correct.
    pub chain_configured: bool,
    /// The WS endpoint in use (from `ODS_CHAIN_WS`), if set — displayed for
    /// information even when `chain_configured` is false.
    pub chain_ws: Option<String>,
    /// The contract H160 (from `ODS_CONTRACT_H160`), if set.
    pub contract_h160: Option<String>,
    /// The data directory path.
    pub data_dir: String,
}

/// Build a `ConnectionStatus` from the actual runtime state.
///
/// `chain_ready` comes from `AppState::chain_ready` (set at startup based on
/// whether `build_chain_ops` succeeded), not from env-var presence, so the
/// field accurately reflects whether chain ops are actually available.
pub fn connection_status_from_state(data_dir: &PathBuf, chain_ready: bool) -> ConnectionStatus {
    let chain_ws = std::env::var("ODS_CHAIN_WS").ok();
    let contract_h160 = std::env::var("ODS_CONTRACT_H160").ok();
    ConnectionStatus {
        chain_configured: chain_ready,
        chain_ws,
        contract_h160,
        data_dir: data_dir.display().to_string(),
    }
}

impl AppState {
    /// Initialise `AppState` from environment variables.
    ///
    /// `data_dir` comes from the Tauri `app_data_dir` (the caller passes it in
    /// after resolving it from `tauri::Manager::path()`), unless `ODS_DATA_DIR`
    /// overrides it (so two demo instances can coexist).
    pub fn init(tauri_data_dir: PathBuf) -> Result<Self, String> {
        // Data directory override.
        let data_dir = match std::env::var("ODS_DATA_DIR") {
            Ok(d) => PathBuf::from(d),
            Err(_) => tauri_data_dir,
        };
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| format!("create data_dir {}: {e}", data_dir.display()))?;
        let store_path = data_dir.join("persona_store.bin");

        // Passphrase (S9: env var or dev default).
        let passphrase = std::env::var("ODS_PASSPHRASE")
            .unwrap_or_else(|_| "ods-dev-default".to_string());

        let store = PersonaStore::open(store_path, &passphrase)
            .map_err(|e| format!("open store: {e}"))?;

        // Chain ops: try to build SubxtChainOps from env; fall back to ChainNotConfigured.
        // `chain_ready` is true only when build_chain_ops returns Ok — i.e. the
        // env vars were present AND the async connect inside block_on succeeded.
        let (chain, chain_ready): (Box<dyn ChainOps>, bool) = match build_chain_ops() {
            Ok(ops) => (ops, true),
            Err(_) => (Box::new(ChainNotConfigured), false),
        };

        // Transport mode: `ODS_TRANSPORT=loopback` → TransportMode::Loopback (relay
        // disabled, same-machine app run or CI smoke-test); anything else (including
        // unset) → TransportMode::Networked (n0 relay + discovery) — the right choice
        // for two laptops over the internet on live Paseo.
        let transport_mode = match std::env::var("ODS_TRANSPORT").as_deref() {
            Ok("loopback") => TransportMode::Loopback,
            _ => TransportMode::Networked,
        };

        let mut service = OrgService::new(store, chain);
        service.set_transport_mode(transport_mode);

        Ok(Self {
            service: Mutex::new(service),
            chain_ready,
            receiver_started: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

/// Attempt to build a `SubxtChainOps` from `ODS_CHAIN_WS`, `ODS_CONTRACT_H160`,
/// and `ODS_ADMIN_SEED`.  Returns `Err` (without allocating a connection) if any
/// required var is absent or if the async connect fails.
///
/// This function is NOT async — Tauri's `setup` hook is synchronous in Tauri 2.
/// The async connection (OnlineClient::from_url + OrgRegistryClient::from_client)
/// is driven EAGERLY at startup via a `block_on` call here, inside `AppState::init`.
/// There is no lazy / deferred connection path; the `SubxtChainOps` (or the
/// `ChainNotConfigured` fallback) is fully determined before `init` returns.
fn build_chain_ops() -> Result<Box<dyn ChainOps>, String> {
    let ws_url = std::env::var("ODS_CHAIN_WS").map_err(|_| "ODS_CHAIN_WS not set")?;
    let h160_hex =
        std::env::var("ODS_CONTRACT_H160").map_err(|_| "ODS_CONTRACT_H160 not set")?;
    let admin_seed_hex =
        std::env::var("ODS_ADMIN_SEED").map_err(|_| "ODS_ADMIN_SEED not set")?;

    // Parse contract H160 (40 hex chars).
    let h160_str = h160_hex.trim_start_matches("0x");
    if h160_str.len() != 40 {
        return Err(format!(
            "ODS_CONTRACT_H160 must be 20 bytes (40 hex chars), got {} chars",
            h160_str.len()
        ));
    }
    let h160_bytes = hex::decode(h160_str)
        .map_err(|e| format!("ODS_CONTRACT_H160 hex decode: {e}"))?;
    let mut contract_h160 = [0u8; 20];
    contract_h160.copy_from_slice(&h160_bytes);

    // Parse admin seed (64 hex chars = 32 bytes).
    let seed_str = admin_seed_hex.trim_start_matches("0x");
    if seed_str.len() != 64 {
        return Err(format!(
            "ODS_ADMIN_SEED must be 32 bytes (64 hex chars), got {} chars",
            seed_str.len()
        ));
    }
    let seed_bytes =
        hex::decode(seed_str).map_err(|e| format!("ODS_ADMIN_SEED hex decode: {e}"))?;
    let mut admin_seed = [0u8; 32];
    admin_seed.copy_from_slice(&seed_bytes);

    // Optional co-signer pubkey (64 hex chars = 32 bytes).
    let others: Vec<[u8; 32]> = match std::env::var("ODS_COSIGNER_PUB") {
        Ok(s) => {
            let hex_str = s.trim_start_matches("0x");
            let bytes =
                hex::decode(hex_str).map_err(|e| format!("ODS_COSIGNER_PUB decode: {e}"))?;
            if bytes.len() != 32 {
                return Err("ODS_COSIGNER_PUB must be 32 bytes".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            vec![arr]
        }
        Err(_) => vec![],
    };

    // Build SubxtChainOps by connecting to the chain.
    // TODO(demo-wiring): This block_on is valid here because build_chain_ops is
    // called from the Tauri setup hook (synchronous context).  If the setup hook
    // ever becomes async in a future Tauri version, convert to .await directly.
    // Clone before both closures to avoid dual-borrow issues across `map_or_else`.
    let ws_url2 = ws_url.clone();
    let others2 = others.clone();
    let chain = tokio::runtime::Handle::try_current()
        .map_or_else(
            move |_| {
                // No current runtime — build a temporary one for the connect.
                tokio::runtime::Runtime::new()
                    .map_err(|e| format!("tokio rt: {e}"))?
                    .block_on(connect_chain(ws_url, contract_h160, admin_seed, others))
            },
            move |handle| {
                // We're inside an existing runtime — use block_in_place.
                tokio::task::block_in_place(|| {
                    handle.block_on(connect_chain(ws_url2, contract_h160, admin_seed, others2))
                })
            },
        )?;
    Ok(Box::new(chain))
}

/// Async: connect to the chain and build `SubxtChainOps`.
/// Runtime-unverified without a live chain or chopsticks fork.
async fn connect_chain(
    ws_url: String,
    contract_h160: [u8; 20],
    admin_seed: [u8; 32],
    others: Vec<[u8; 32]>,
) -> Result<org_node::SubxtChainOps, String> {
    use subxt::OnlineClient;
    use subxt::config::PolkadotConfig;
    use subxt_signer::sr25519::Keypair;

    let api: OnlineClient<PolkadotConfig> = OnlineClient::from_url(&ws_url)
        .await
        .map_err(|e| format!("subxt connect {ws_url}: {e}"))?;

    let registry_client =
        on_chain_client::OrgRegistryClient::from_client(api.clone(), contract_h160)
            .await
            .map_err(|e| format!("OrgRegistryClient: {e}"))?;

    // Build the admin SR25519 keypair from the raw 32-byte mini-secret seed.
    // subxt_signer::sr25519::SecretKeyBytes = [u8; 32].
    let admin = Keypair::from_secret_key(admin_seed)
        .map_err(|e| format!("admin Keypair: {e}"))?;

    Ok(org_node::SubxtChainOps::new(
        api,
        registry_client,
        contract_h160,
        admin,
        others,
    ))
}
