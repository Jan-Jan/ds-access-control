/**
 * Typed wrappers around Tauri invoke/listen for all 12 ODS commands + 5 events.
 *
 * Command signatures mirror commands.rs exactly (camelCase arg names per Tauri convention).
 * Return shapes mirror the Rust DTOs (PersonaDto, OrgDto, JoinRequestDto, ConnectionStatus).
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

// ---------------------------------------------------------------------------
// DTOs (mirror Rust structs)
// ---------------------------------------------------------------------------

export interface PersonaDto {
	persona_id: string;
	org_id: string | null;
	handle: string;
	name: string;
	surname: string;
	/** "Proposed" | "Active" | "Revoked" (Debug format of enum) */
	status: string;
}

export interface OrgDto {
	org_id: string;    // 40 hex chars
	epoch: number;
	root_hash: string; // 64 hex chars
	member_count: number;
}

export interface JoinRequestDto {
	handle: string;
	name: string;
	surname: string;
	member_key: string;     // hex
	device_key: string;     // hex
	has_node_addr: boolean;
	node_addr_blob: string; // hex — pass back to admit_member
}

export interface ConnectionStatus {
	chain_configured: boolean;
	chain_ws: string | null;
	contract_h160: string | null;
	data_dir: string;
}

// ---------------------------------------------------------------------------
// Event payloads
// ---------------------------------------------------------------------------

export interface MembershipUpdatedPayload {
	org_id: string;
	epoch: number;
	root: string;
}

export interface RevokedPayload {
	org_id: string;
}

export interface EpochChangedPayload {
	org_id: string;
	epoch: number;
}

export interface ReceiverErrorPayload {
	message: string;
}

// ---------------------------------------------------------------------------
// Commands — all 12
// ---------------------------------------------------------------------------

/** Create a new persona (no chain interaction). Returns persona_id. */
export function createPersona(handle: string, name: string, surname: string): Promise<string> {
	return invoke<string>('create_persona', { handle, name, surname });
}

/**
 * Create an organisation: build genesis trie + submit to chain.
 * Returns org_id (40 hex chars).
 */
export function createOrganisation(personaId: string): Promise<string> {
	return invoke<string>('create_organisation', { personaId });
}

/** Export an invite blob for the given org_id. */
export function exportInvite(orgId: string): Promise<string> {
	return invoke<string>('export_invite', { orgId });
}

/**
 * Import an invite blob; returns the org_id it's for (40 hex chars).
 * Also stores the invite locally.
 */
export function importInvite(blob: string): Promise<string> {
	return invoke<string>('import_invite', { blob });
}

/** Export a join-request blob for the given persona_id. */
export function exportJoinRequest(personaId: string): Promise<string> {
	return invoke<string>('export_join_request', { personaId });
}

/**
 * Decode and return the fields of a join-request blob (no persistence).
 * Returns JoinRequestDto.
 */
export function importJoinRequest(blob: string): Promise<JoinRequestDto> {
	return invoke<JoinRequestDto>('import_join_request', { blob });
}

/**
 * Admit a new member from a join-request blob.
 * org_secret_hex is optional (pass null if not needed).
 * Returns the new member_id as 64 hex chars.
 */
export function admitMember(
	orgId: string,
	joinRequestBlob: string,
	orgSecretHex: string | null = null
): Promise<string> {
	return invoke<string>('admit_member', { orgId, joinRequestBlob, orgSecretHex });
}

/**
 * Revoke a member by member_id_hex (64 hex chars) and peer_addr_blob (hex-encoded
 * postcard bytes of the iroh EndpointAddr from the original join request).
 */
export function revokeMember(
	orgId: string,
	memberIdHex: string,
	peerAddrBlob: string
): Promise<void> {
	return invoke<void>('revoke_member', { orgId, memberIdHex, peerAddrBlob });
}

/** List all local personas (no key material returned). */
export function listPersonas(): Promise<PersonaDto[]> {
	return invoke<PersonaDto[]>('list_personas');
}

/** List all local org records. */
export function listOrgs(): Promise<OrgDto[]> {
	return invoke<OrgDto[]>('list_orgs');
}

/** Return the current connection status (chain env vars + data dir). */
export function connectionStatus(): Promise<ConnectionStatus> {
	return invoke<ConnectionStatus>('connection_status');
}

/**
 * Spawn a background tokio task that loops receive_and_self_delete_if_revoked
 * and emits Tauri events. Returns immediately.
 */
export function startReceiver(): Promise<void> {
	return invoke<void>('start_receiver');
}

// ---------------------------------------------------------------------------
// Events — 5 event types
// ---------------------------------------------------------------------------

/** membership-updated: emitted after a successful receive_and_verify (not revoked). */
export function onMembershipUpdated(
	cb: (payload: MembershipUpdatedPayload) => void
): Promise<UnlistenFn> {
	return listen<MembershipUpdatedPayload>('membership-updated', (e) => cb(e.payload));
}

/**
 * incoming-verified: same payload as membership-updated; alias for first-admission case.
 * UI can treat identically to membership-updated.
 */
export function onIncomingVerified(
	cb: (payload: MembershipUpdatedPayload) => void
): Promise<UnlistenFn> {
	return listen<MembershipUpdatedPayload>('incoming-verified', (e) => cb(e.payload));
}

/** revoked: emitted when receive_and_self_delete_if_revoked returns SelfDeleted. */
export function onRevoked(cb: (payload: RevokedPayload) => void): Promise<UnlistenFn> {
	return listen<RevokedPayload>('revoked', (e) => cb(e.payload));
}

/** epoch-changed: emitted on every successful verify (superset of the others). */
export function onEpochChanged(cb: (payload: EpochChangedPayload) => void): Promise<UnlistenFn> {
	return listen<EpochChangedPayload>('epoch-changed', (e) => cb(e.payload));
}

/** receiver-error: emitted on recoverable errors; task continues running. */
export function onReceiverError(cb: (payload: ReceiverErrorPayload) => void): Promise<UnlistenFn> {
	return listen<ReceiverErrorPayload>('receiver-error', (e) => cb(e.payload));
}
