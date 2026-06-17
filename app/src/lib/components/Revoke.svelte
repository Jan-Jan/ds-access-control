<script lang="ts">
	/**
	 * Story 5: Revoke a member.
	 * A: show member list → enter member_id_hex + peer_addr_blob → "Revoke" → revoke_member.
	 * B: shows "removed & self-deleted" when the "revoked" event fires (monitored via Membership).
	 *
	 * Note: peer_addr_blob must be the hex-encoded postcard bytes of the iroh EndpointAddr
	 * from the original join request (node_addr_blob from JoinRequestDto).
	 */
	import { listOrgs, listPersonas, revokeMember, onRevoked, type OrgDto } from '$lib/api';
	import type { UnlistenFn } from '@tauri-apps/api/event';

	interface Props {
		notifyReload?: () => void;
	}
	let { notifyReload }: Props = $props();

	let orgs = $state<OrgDto[]>([]);
	let selectedOrgId = $state('');
	let memberIdHex = $state('');
	let peerAddrBlob = $state('');

	let revokeBusy = $state(false);
	let revokeErr = $state('');
	let revokeDone = $state(false);

	let revokedEvents = $state<string[]>([]);
	let unlisten: UnlistenFn | null = null;

	async function loadOrgs() {
		try {
			orgs = await listOrgs();
			if (orgs.length > 0 && !selectedOrgId) selectedOrgId = orgs[0].org_id;
		} catch (e) {
			revokeErr = String(e);
		}
	}

	$effect(() => {
		loadOrgs();

		const setup = async () => {
			unlisten = await onRevoked((p) => {
				revokedEvents = [
					`Org …${p.org_id.slice(-12)} — member self-deleted (received revoke, removed self)`,
					...revokedEvents
				];
			});
		};
		setup();

		return () => {
			unlisten?.();
		};
	});

	async function doRevoke() {
		if (!selectedOrgId) { revokeErr = 'Select an org.'; return; }
		if (memberIdHex.trim().length !== 64) { revokeErr = 'Member ID must be 64 hex chars.'; return; }
		if (!peerAddrBlob.trim()) { revokeErr = 'Peer addr blob (hex) is required.'; return; }
		revokeBusy = true;
		revokeErr = '';
		try {
			await revokeMember(selectedOrgId, memberIdHex.trim(), peerAddrBlob.trim());
			revokeDone = true;
			notifyReload?.();
		} catch (e) {
			revokeErr = String(e);
		} finally {
			revokeBusy = false;
		}
	}

	function reset() {
		memberIdHex = '';
		peerAddrBlob = '';
		revokeErr = '';
		revokeDone = false;
	}
</script>

<section class="panel">
	<h2>Story 5: Revoke Member</h2>
	<p class="hint">
		Enter the member ID (64 hex chars) and peer addr blob (hex-encoded postcard EndpointAddr
		from the join request). After revocation, the revoked peer self-deletes and you'll see
		the "revoked" event below.
	</p>

	{#if revokeDone}
		<div class="result-box ok">
			<p>Revocation submitted. Waiting for the remote peer to receive + self-delete…</p>
		</div>
		<button onclick={reset}>Revoke another</button>
	{:else}
		<label>
			Org
			{#if orgs.length === 0}
				<span class="muted">No orgs (create one in Story 1)</span>
			{:else}
				<select bind:value={selectedOrgId}>
					{#each orgs as o (o.org_id)}
						<option value={o.org_id}>…{o.org_id.slice(-12)} (epoch {o.epoch}, {o.member_count} members)</option>
					{/each}
				</select>
			{/if}
		</label>

		<label>
			Member ID (64 hex chars)
			<input
				type="text"
				bind:value={memberIdHex}
				placeholder="0000…(64 hex chars)"
				disabled={revokeBusy}
				class="mono"
			/>
		</label>
		<label>
			Peer addr blob (hex — from join request node_addr_blob)
			<input
				type="text"
				bind:value={peerAddrBlob}
				placeholder="hex-encoded postcard EndpointAddr"
				disabled={revokeBusy}
				class="mono"
			/>
		</label>

		{#if revokeErr}<p class="err">{revokeErr}</p>{/if}

		<button class="revoke-btn" onclick={doRevoke} disabled={revokeBusy || orgs.length === 0}>
			{revokeBusy ? 'Revoking…' : 'Revoke Member'}
		</button>
	{/if}

	<!-- Live revoked events -->
	{#if revokedEvents.length > 0}
		<div class="revoked-log">
			<h3>Revoked events received</h3>
			{#each revokedEvents as msg, i (i)}
				<p class="revoked-entry">{msg}</p>
			{/each}
		</div>
	{/if}
</section>

<style>
	.panel { background: #111; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }
	h2 { margin-top: 0; font-size: 1rem; color: #ddd; }
	h3 { font-size: 0.9rem; color: #aaa; margin: 0.75rem 0 0.4rem; }
	.hint { color: #666; font-size: 0.8rem; margin-bottom: 0.75rem; }
	label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.82rem; color: #888; margin-bottom: 0.4rem; }
	input, select { background: #1a1a1a; border: 1px solid #333; color: #eee; padding: 0.3rem 0.5rem; border-radius: 3px; font-size: 0.82rem; }
	input:disabled { opacity: 0.5; }
	.mono { font-family: monospace; }
	button { cursor: pointer; background: #1a3a5c; color: #7ec8e3; border: 1px solid #2a5f8c; border-radius: 3px; padding: 0.35rem 0.9rem; font-size: 0.85rem; margin-top: 0.25rem; }
	button:disabled { opacity: 0.5; cursor: default; }
	button:not(:disabled):hover { background: #204d7a; }
	.revoke-btn { background: #4a1010; color: #f44336; border-color: #7a1a1a; }
	.revoke-btn:not(:disabled):hover { background: #5c1414; }
	.result-box { background: #0d2f1d; border: 1px solid #1b5e20; border-radius: 4px; padding: 0.75rem; margin-bottom: 0.5rem; }
	.result-box p { margin: 0.2rem 0; font-size: 0.85rem; color: #ccc; }
	.revoked-log { background: #1a0a0a; border: 1px solid #5c1111; border-radius: 4px; padding: 0.5rem 0.75rem; margin-top: 0.75rem; }
	.revoked-entry { color: #f44336; font-size: 0.82rem; margin: 0.15rem 0; }
	.err { color: #f44336; font-size: 0.8rem; }
	.muted { color: #555; font-size: 0.82rem; }
</style>
