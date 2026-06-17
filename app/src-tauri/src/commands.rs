//! Tauri command handlers for the ODS PoC app.
//!
//! Each command locks `AppState.service` (tokio async Mutex), calls the
//! matching `OrgService` method, and maps `OrgNodeError` → `String` for the
//! Tauri `Result<T, String>` convention.
//!
//! ## Event payloads emitted by `start_receiver`:
//!
//! - `"membership-updated"`: `{ org_id: String, epoch: u64, root: String }`
//!   emitted after a successful `receive_and_verify` that keeps the caller
//!   as a member.
//! - `"incoming-verified"`: same payload as `membership-updated` (alias for
//!   the first-admission case; the UI can treat them identically).
//! - `"revoked"`: `{ org_id: String }` emitted when `receive_and_self_delete_if_revoked`
//!   returns `SelfDeleted`.
//! - `"epoch-changed"`: `{ org_id: String, epoch: u64 }` emitted on every
//!   successful verify (superset of the others; useful for epoch-progress bars).
//! - `"receiver-error"`: `{ message: String }` emitted on recoverable errors
//!   (endpoint recv failure, verify failure); the task continues running.

use rand::rngs::OsRng;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use org_node::blobs::JoinRequest;
use org_node::service::SelfDeleteOutcome;
use org_node::store::{OrgRecord, PersonaRecord};
use org_node::OrgId;

use crate::state::{AppState, ConnectionStatus, connection_status_from_state};

// ---------------------------------------------------------------------------
// Serialisable DTOs
// ---------------------------------------------------------------------------

/// A serialisable view of a `PersonaRecord` (no key material).
#[derive(Debug, Serialize)]
pub struct PersonaDto {
    pub persona_id: String,
    pub org_id: Option<String>,
    pub handle: String,
    pub name: String,
    pub surname: String,
    pub status: String,
}

impl From<&PersonaRecord> for PersonaDto {
    fn from(p: &PersonaRecord) -> Self {
        Self {
            persona_id: p.persona_id.clone(),
            org_id: p.org_id.map(|id| hex::encode(id.as_bytes())),
            handle: p.handle.clone(),
            name: p.name.clone(),
            surname: p.surname.clone(),
            status: format!("{:?}", p.status),
        }
    }
}

/// A serialisable view of an `OrgRecord`.
#[derive(Debug, Serialize)]
pub struct OrgDto {
    pub org_id: String,
    pub epoch: u64,
    pub root_hash: String,
    pub member_count: usize,
}

impl From<&OrgRecord> for OrgDto {
    fn from(o: &OrgRecord) -> Self {
        Self {
            org_id: hex::encode(o.org_id.as_bytes()),
            epoch: o.epoch,
            root_hash: hex::encode(o.root_hash),
            member_count: o.trie_members.len(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: parse a hex-encoded OrgId string (40 hex chars = 20 bytes).
// ---------------------------------------------------------------------------

fn parse_org_id(s: &str) -> Result<OrgId, String> {
    let s = s.trim_start_matches("0x");
    if s.len() != 40 {
        return Err(format!("org_id must be 40 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("org_id hex: {e}"))?;
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(OrgId::new(arr))
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Create a new persona (no chain interaction).
#[tauri::command]
pub async fn create_persona(
    state: State<'_, AppState>,
    handle: String,
    name: String,
    surname: String,
) -> Result<String, String> {
    let mut svc = state.service.lock().await;
    svc.create_persona(&mut OsRng, &handle, &name, &surname)
        .map_err(|e| e.to_string())
}

/// Create an organisation: build genesis trie + submit to chain.
/// Returns the org_id (40 hex chars).
#[tauri::command]
pub async fn create_organisation(
    state: State<'_, AppState>,
    persona_id: String,
) -> Result<String, String> {
    let mut svc = state.service.lock().await;
    let org_id = svc
        .create_organisation(&mut OsRng, &persona_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(org_id.as_bytes()))
}

/// Export an invite blob for the given org.
#[tauri::command]
pub async fn export_invite(
    state: State<'_, AppState>,
    org_id: String,
) -> Result<String, String> {
    let oid = parse_org_id(&org_id)?;
    let svc = state.service.lock().await;
    svc.export_invite(oid).map_err(|e| e.to_string())
}

/// Import an invite blob; returns the org_id it's for.
#[tauri::command]
pub async fn import_invite(
    state: State<'_, AppState>,
    blob: String,
) -> Result<String, String> {
    let mut svc = state.service.lock().await;
    let inv = svc.import_invite(&mut OsRng, &blob).map_err(|e| e.to_string())?;
    Ok(hex::encode(inv.org_id.as_bytes()))
}

/// Export a join-request blob for the given persona.
#[tauri::command]
pub async fn export_join_request(
    state: State<'_, AppState>,
    persona_id: String,
) -> Result<String, String> {
    let svc = state.service.lock().await;
    svc.export_join_request(&persona_id).map_err(|e| e.to_string())
}

/// Decode and return the fields of a join-request blob (no persistence).
#[tauri::command]
pub async fn import_join_request(blob: String) -> Result<JoinRequestDto, String> {
    let jr = decode_join_request(&blob)?;
    Ok(JoinRequestDto {
        handle: jr.handle,
        name: jr.name,
        surname: jr.surname,
        member_key: hex::encode(jr.member_key),
        device_key: hex::encode(jr.device_key),
        has_node_addr: !jr.node_addr.is_empty(),
        node_addr_blob: hex::encode(&jr.node_addr),
    })
}

fn decode_join_request(blob: &str) -> Result<JoinRequest, String> {
    org_node::service::OrgService::import_join_request(blob).map_err(|e| e.to_string())
}

/// DTO for an import_join_request response.
#[derive(Debug, Serialize)]
pub struct JoinRequestDto {
    pub handle: String,
    pub name: String,
    pub surname: String,
    pub member_key: String,
    pub device_key: String,
    pub has_node_addr: bool,
    /// The raw node_addr bytes as hex — pass back to admit_member.
    pub node_addr_blob: String,
}

/// Admit a new member from a join-request blob.
///
/// The `node_addr_blob` is the hex-encoded `node_addr` field from the
/// `JoinRequestDto` returned by `import_join_request`. If empty, the peer
/// address is taken from the `join_request_blob` directly (same source).
///
/// Returns the new member_id as 64 hex chars.
#[tauri::command]
pub async fn admit_member(
    state: State<'_, AppState>,
    org_id: String,
    join_request_blob: String,
    org_secret_hex: Option<String>,
) -> Result<String, String> {
    use iroh::EndpointAddr;

    let oid = parse_org_id(&org_id)?;
    let jr = decode_join_request(&join_request_blob)?;

    // Decode the iroh EndpointAddr from the join request's node_addr bytes.
    let peer_addr: EndpointAddr = postcard::from_bytes(&jr.node_addr).map_err(|e| {
        format!("node_addr decode (is the join_request_blob from a bound endpoint?): {e}")
    })?;

    let org_secret: Option<[u8; 32]> = match org_secret_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                .map_err(|e| format!("org_secret hex: {e}"))?;
            if bytes.len() != 32 {
                return Err("org_secret must be 32 bytes".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        None => None,
    };

    let mut svc = state.service.lock().await;
    let member_id = svc
        .admit_member(&mut OsRng, oid, &jr, peer_addr, org_secret)
        .await
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(member_id))
}

/// Revoke a member by member_id (64 hex chars) and a peer_addr_blob (hex-encoded
/// postcard bytes of the iroh EndpointAddr).
#[tauri::command]
pub async fn revoke_member(
    state: State<'_, AppState>,
    org_id: String,
    member_id_hex: String,
    peer_addr_blob: String,
) -> Result<(), String> {
    use iroh::EndpointAddr;

    let oid = parse_org_id(&org_id)?;
    let member_bytes =
        hex::decode(member_id_hex.trim_start_matches("0x")).map_err(|e| format!("member_id hex: {e}"))?;
    if member_bytes.len() != 32 {
        return Err("member_id must be 32 bytes (64 hex chars)".into());
    }
    let mut member_id = [0u8; 32];
    member_id.copy_from_slice(&member_bytes);

    let addr_bytes = hex::decode(peer_addr_blob.trim_start_matches("0x"))
        .map_err(|e| format!("peer_addr_blob hex: {e}"))?;
    let peer_addr: EndpointAddr =
        postcard::from_bytes(&addr_bytes).map_err(|e| format!("peer_addr decode: {e}"))?;

    let mut svc = state.service.lock().await;
    svc.revoke_member(&mut OsRng, oid, member_id, peer_addr)
        .await
        .map_err(|e| e.to_string())
}

/// List all local personas (no key material returned).
#[tauri::command]
pub async fn list_personas(state: State<'_, AppState>) -> Result<Vec<PersonaDto>, String> {
    let svc = state.service.lock().await;
    Ok(svc.list_personas().iter().map(PersonaDto::from).collect())
}

/// List all local org records.
#[tauri::command]
pub async fn list_orgs(state: State<'_, AppState>) -> Result<Vec<OrgDto>, String> {
    let svc = state.service.lock().await;
    Ok(svc.list_orgs().iter().map(OrgDto::from).collect())
}

/// Return the current connection status (chain env vars + data dir).
#[tauri::command]
pub async fn connection_status(
    state: State<'_, AppState>,
    app_handle: AppHandle,
) -> Result<ConnectionStatus, String> {
    // Resolve the data dir from the Tauri path resolver (same logic as AppState::init).
    let data_dir = match std::env::var("ODS_DATA_DIR") {
        Ok(d) => std::path::PathBuf::from(d),
        Err(_) => app_handle
            .path()
            .app_data_dir()
            .map_err(|e| format!("app_data_dir: {e}"))?,
    };
    let chain_ready = state.chain_ready;
    Ok(connection_status_from_state(&data_dir, chain_ready))
}

// ---------------------------------------------------------------------------
// start_receiver: spawns a background task looping receive_and_self_delete_if_revoked
// ---------------------------------------------------------------------------

/// Payload emitted with `membership-updated` / `incoming-verified` events.
#[derive(Debug, Clone, Serialize)]
struct MembershipUpdatedPayload {
    org_id: String,
    epoch: u64,
    root: String,
}

/// Payload emitted with `revoked` events.
#[derive(Debug, Clone, Serialize)]
struct RevokedPayload {
    org_id: String,
}

/// Payload emitted with `epoch-changed` events.
#[derive(Debug, Clone, Serialize)]
struct EpochChangedPayload {
    org_id: String,
    epoch: u64,
}

/// Payload emitted with `receiver-error` events.
#[derive(Debug, Clone, Serialize)]
struct ReceiverErrorPayload {
    message: String,
}

/// Spawn a background tokio task that loops `receive_and_self_delete_if_revoked`
/// and emits Tauri events.  The task runs until the app is closed or the
/// endpoint returns a permanent error (endpoint closed).
///
/// Idempotent: if the receiver task is already running this is a no-op (returns
/// `Ok(())` immediately without spawning a second loop).
///
/// Returns immediately; the task runs in the background.
#[tauri::command]
pub async fn start_receiver(
    state: State<'_, AppState>,
    app_handle: AppHandle,
) -> Result<(), String> {
    use std::sync::atomic::Ordering;

    // Guard: only the first caller spawns the loop; subsequent calls are no-ops.
    if state
        .receiver_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Already started — return silently.
        return Ok(());
    }

    let app_handle_clone = app_handle.clone();

    // Kick off the receiver loop.  Each iteration awaits ONE inbound message.
    // Errors are emitted as `receiver-error` events so the UI can display them
    // without crashing the loop.
    tokio::spawn(async move {
        loop {
            // Re-lock the service each iteration so other commands can proceed
            // between messages (the lock is held only for the duration of one
            // receive + verify).
            let result = {
                let state: State<'_, AppState> =
                    app_handle_clone.state::<AppState>();
                let mut svc = state.service.lock().await;
                svc.receive_and_self_delete_if_revoked(&mut OsRng).await
            };

            match result {
                Ok(SelfDeleteOutcome::SelfDeleted { org_id }) => {
                    let org_id_hex = hex::encode(org_id.as_bytes());
                    let _ = app_handle_clone.emit(
                        "revoked",
                        RevokedPayload { org_id: org_id_hex.clone() },
                    );
                    let _ = app_handle_clone.emit(
                        "epoch-changed",
                        EpochChangedPayload { org_id: org_id_hex, epoch: 0 },
                    );
                }
                Ok(SelfDeleteOutcome::UpdatedNotRevoked { org_id }) => {
                    // Re-read the org record to get the current epoch + root.
                    let (epoch, root) = {
                        let state: State<'_, AppState> =
                            app_handle_clone.state::<AppState>();
                        let svc = state.service.lock().await;
                        svc.list_orgs()
                            .iter()
                            .find(|o| o.org_id == org_id)
                            .map(|o| (o.epoch, hex::encode(o.root_hash)))
                            .unwrap_or((0, String::new()))
                    };
                    let org_id_hex = hex::encode(org_id.as_bytes());
                    let payload = MembershipUpdatedPayload {
                        org_id: org_id_hex.clone(),
                        epoch,
                        root: root.clone(),
                    };
                    let _ = app_handle_clone.emit("membership-updated", payload.clone());
                    let _ = app_handle_clone.emit("incoming-verified", payload);
                    let _ = app_handle_clone.emit(
                        "epoch-changed",
                        EpochChangedPayload { org_id: org_id_hex, epoch },
                    );
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = app_handle_clone.emit(
                        "receiver-error",
                        ReceiverErrorPayload { message: msg.clone() },
                    );
                    // Stop looping on "endpoint not bound" — this is a
                    // configuration error, not a transient failure.
                    if msg.contains("endpoint not bound") {
                        break;
                    }
                    // Other errors (iroh recv, verify failure) are transient;
                    // keep looping.
                }
            }
        }
    });

    Ok(())
}
