//! Spawn / teardown a chopsticks-Paseo fork from a Rust test. Mirrors
//! `../on-chain/scripts/chopsticks-sanity.sh`'s startup logic — same
//! config, same HTTP pre-warm (chopsticks's WS metadata path observably
//! doesn't respond reliably until HTTP has been hit once) — and adds the
//! Rust-side conveniences:
//!
//! - tokio `Command` with `kill_on_drop(true)` so a panicking test still
//!   reaps its chopsticks subprocess.
//! - Working directory pinned to `on-chain/` so the relative `db:` path
//!   in `chopsticks-config.yml` resolves the same as in the shell gate.
//! - WS URL + (optional) DB cleanup exposed to the caller.
//!
//! Single fixed port (8000). If integration tests start running in
//! parallel and collide, picking a free port per fork is a trivial
//! extension; not done yet because the Task 5 / 7 tests are serial.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use serde_json::Value;

const PORT: u16 = 8000;
const PREWARM_ATTEMPTS: usize = 30;
const PREWARM_INTERVAL: Duration = Duration::from_secs(2);
const PREWARM_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const EXPECTED_CHAIN: &str = "Paseo Asset Hub";

/// Live chopsticks fork. Drops the subprocess on scope exit via the
/// `Drop` impl below — synchronous SIGKILL + wait, which `tokio::process::
/// Child`'s `kill_on_drop(true)` doesn't reliably guarantee when the
/// tokio runtime is tearing down (a test exit can race the kill and
/// orphan chopsticks on port 8000). Hold this for the lifetime of any
/// tests that talk to the fork.
pub struct ChopsticksHandle {
    /// `Option` so `Drop` can `take()` and consume the Child for
    /// `wait()`, which requires owning the value.
    child: Option<Child>,
    pub ws_url: String,
    pub http_url: String,
    pub port: u16,
}

impl Drop for ChopsticksHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Chopsticks forks a worker process (node uses
            // `child_process.fork` internally for the wasm executor). A
            // plain SIGKILL on the parent leaves the worker orphaned to
            // pid 1, which keeps port 8000 bound and trips the next
            // test's orphan-detection prewarm. We `setsid` in pre_exec
            // so the chopsticks subprocess (and its worker) are their
            // own group; `killpg(pgid, SIGKILL)` then reaps the whole
            // tree. `child.wait()` collects the zombie.
            let pgid = child.id() as libc::pid_t;
            // Safe: standard process-group kill; no Rust invariants at risk.
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
            let _ = child.wait();
        }
    }
}

/// Errors produced by [`spawn_fork`]. Variants carry enough context for a
/// failing CI run to be diagnosed without re-running.
#[derive(Debug)]
pub enum SpawnError {
    /// `../on-chain/scripts/node_modules/.bin/chopsticks` doesn't exist.
    /// Usually means `npm ci` hasn't been run inside `on-chain/scripts/`.
    ChopsticksBinaryMissing(PathBuf),
    /// Something else is already listening on the harness port. Usually
    /// a chopsticks orphan from a prior `cargo test` that didn't reach
    /// its Drop; kill it (`pkill -f chopsticks`) and retry.
    PortAlreadyBound(u16),
    /// Spawning the subprocess failed at the OS level.
    Spawn(std::io::Error),
    /// HTTP pre-warm never saw the expected `system_chain` response.
    Prewarm { tried: usize },
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChopsticksBinaryMissing(p) => write!(
                f,
                "chopsticks binary not found at {}; run `npm ci` in on-chain/scripts/",
                p.display()
            ),
            Self::PortAlreadyBound(p) => write!(
                f,
                "port {p} is already bound; orphan chopsticks? run `pkill -f chopsticks`"
            ),
            Self::Spawn(e) => write!(f, "failed to spawn chopsticks: {e}"),
            Self::Prewarm { tried } => write!(
                f,
                "chopsticks didn't respond to HTTP system_chain after {tried} attempts"
            ),
        }
    }
}

impl std::error::Error for SpawnError {}

/// Start a chopsticks-Paseo fork using `on-chain/scripts/chopsticks-
/// config.yml`. Blocks until HTTP `system_chain` returns "Paseo Asset
/// Hub" (signalling the WS metadata path is ready too — see the
/// empirical note in the shell sanity script).
///
/// Returns when the fork is ready to serve `chainHead_v1_*`. The caller
/// is responsible for any deploy step (Task 5 tests use the existing
/// `on-chain/scripts/sanity-deploy.mjs`).
pub async fn spawn_fork() -> Result<ChopsticksHandle, SpawnError> {
    let on_chain_dir = on_chain_dir();
    let chopsticks_bin = on_chain_dir.join("scripts/node_modules/.bin/chopsticks");
    let config_path = "scripts/chopsticks-config.yml";

    if !chopsticks_bin.exists() {
        return Err(SpawnError::ChopsticksBinaryMissing(chopsticks_bin));
    }

    // Wait briefly for the port to be free. Drop on the previous
    // test's ChopsticksHandle already killed chopsticks, but the OS
    // can take a moment to release the listening socket; this poll
    // bridges that gap. If the port stays bound past the budget,
    // assume it's an orphan from outside this run and fail loudly —
    // silently sharing someone else's fork is worse than a clean error.
    wait_for_port_free(PORT, Duration::from_secs(3))
        .await
        .ok_or(SpawnError::PortAlreadyBound(PORT))?;

    let mut cmd = Command::new(&chopsticks_bin);
    cmd.args(["--config", config_path, "--port", &PORT.to_string()])
        .current_dir(&on_chain_dir)
        // Inherit both streams so chopsticks panics surface in
        // `cargo test`'s captured output rather than vanishing — saves
        // hours when chopsticks gets unhappy mid-run.
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    // setsid moves chopsticks into its own session + process group, so
    // the Drop impl can `killpg` the whole tree. Safe because `setsid`
    // has no Rust-side preconditions.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(SpawnError::Spawn)?;

    let http_url = format!("http://127.0.0.1:{PORT}");
    let ws_url = format!("ws://127.0.0.1:{PORT}");

    // Wrap the Child up-front so the Drop impl reaps chopsticks even if
    // prewarm fails partway through (e.g. orphan-detection path).
    let handle = ChopsticksHandle {
        child: Some(child),
        http_url,
        ws_url,
        port: PORT,
    };

    if let Err(e) = prewarm(&handle.http_url).await {
        drop(handle);
        return Err(e);
    }

    Ok(handle)
}

async fn prewarm(http_url: &str) -> Result<(), SpawnError> {
    for attempt in 1..=PREWARM_ATTEMPTS {
        match probe_chain(http_url).await {
            Ok(chain) if chain == EXPECTED_CHAIN => return Ok(()),
            // A foreign chain name on the configured port almost
            // certainly means a stale orphan from a prior run is still
            // listening. Surface loudly rather than retry.
            Ok(other) => {
                eprintln!(
                    "chopsticks prewarm: port {PORT} responded with chain \
                     {other:?}, expected {EXPECTED_CHAIN:?}; orphan process?",
                );
                return Err(SpawnError::Prewarm { tried: attempt });
            }
            // jsonrpsee returns Err while chopsticks is still booting;
            // that's the common case during the first few seconds.
            Err(_) => {}
        }
        tokio::time::sleep(PREWARM_INTERVAL).await;
    }
    Err(SpawnError::Prewarm {
        tried: PREWARM_ATTEMPTS,
    })
}

async fn probe_chain(http_url: &str) -> Result<String, jsonrpsee::core::ClientError> {
    let client = HttpClientBuilder::default()
        .request_timeout(PREWARM_REQUEST_TIMEOUT)
        .build(http_url)?;
    let chain: Value = client.request("system_chain", rpc_params![]).await?;
    Ok(chain.as_str().unwrap_or("").to_string())
}

fn port_is_bound(port: u16) -> bool {
    std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
}

/// Poll until the port is free or the budget elapses. Returns Some(())
/// on success, None if the port stayed bound the whole time.
async fn wait_for_port_free(port: u16, budget: Duration) -> Option<()> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if !port_is_bound(port) {
            return Some(());
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn on_chain_dir() -> PathBuf {
    // Resolve `../on-chain/` relative to `on-chain-client/`. CARGO_MANIFEST_DIR
    // is set by Cargo when running tests; falling back to `..` keeps the
    // helper usable when invoked outside of cargo.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    manifest_dir.join("..").join("on-chain").canonicalize().unwrap_or_else(|_| {
        // Fall back to a non-canonical path if `on-chain/` doesn't exist
        // yet — the bin-missing check below produces a clearer error.
        Path::new("..").join("on-chain")
    })
}
