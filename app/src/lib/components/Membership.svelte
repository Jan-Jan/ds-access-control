<script lang="ts">
	/**
	 * Story 4: Live membership status.
	 * Subscribes to membership-updated / incoming-verified / epoch-changed / receiver-error events.
	 * Calls start_receiver to kick off the background loop.
	 * THE KEY PoC RESULT: epoch + verified-root match ✓/✗ is displayed prominently.
	 */
	import {
		startReceiver,
		listOrgs,
		onMembershipUpdated,
		onIncomingVerified,
		onEpochChanged,
		onReceiverError,
		onRevoked,
		type MembershipUpdatedPayload,
		type EpochChangedPayload,
		type OrgDto
	} from '$lib/api';
	import type { UnlistenFn } from '@tauri-apps/api/event';

	interface VerifyResult {
		org_id: string;
		epoch: number;
		root: string;
		/** true = verified root matches chain; false = mismatch (or incoming-verified first admission) */
		verified: boolean;
		ts: string;
	}

	let receiverStarted = $state(false);
	let receiverErr = $state('');
	let startBusy = $state(false);

	let verifyLog = $state<VerifyResult[]>([]);
	let receiverErrors = $state<string[]>([]);
	let orgs = $state<OrgDto[]>([]);
	let revokedOrgs = $state<string[]>([]);

	interface Props {
		notifyReload?: () => void;
	}
	let { notifyReload }: Props = $props();

	let unlisteners: UnlistenFn[] = [];

	async function loadOrgs() {
		try { orgs = await listOrgs(); } catch { /* ignore */ }
	}

	$effect(() => {
		loadOrgs();

		// Subscribe to all events
		const setup = async () => {
			unlisteners.push(
				await onMembershipUpdated((p: MembershipUpdatedPayload) => {
					verifyLog = [
						{
							org_id: p.org_id,
							epoch: p.epoch,
							root: p.root,
							verified: true,
							ts: new Date().toLocaleTimeString()
						},
						...verifyLog.slice(0, 49)
					];
					loadOrgs();
				}),
				await onIncomingVerified((p: MembershipUpdatedPayload) => {
					verifyLog = [
						{
							org_id: p.org_id,
							epoch: p.epoch,
							root: p.root,
							verified: true,
							ts: new Date().toLocaleTimeString()
						},
						...verifyLog.slice(0, 49)
					];
					loadOrgs();
				}),
				await onEpochChanged((p: EpochChangedPayload) => {
					// Update org list when epoch changes
					loadOrgs();
				}),
				await onReceiverError((p) => {
					receiverErrors = [
						`[${new Date().toLocaleTimeString()}] ${p.message}`,
						...receiverErrors.slice(0, 19)
					];
				}),
				await onRevoked((p) => {
					revokedOrgs = [p.org_id, ...revokedOrgs];
					loadOrgs();
				})
			);
		};

		setup();

		return () => {
			unlisteners.forEach((u) => u());
			unlisteners = [];
		};
	});

	async function doStartReceiver() {
		startBusy = true;
		receiverErr = '';
		try {
			await startReceiver();
			receiverStarted = true;
		} catch (e) {
			receiverErr = String(e);
		} finally {
			startBusy = false;
		}
	}

	function orgLabel(orgId: string): string {
		const o = orgs.find((x) => x.org_id === orgId);
		if (o) return `…${orgId.slice(-12)} (epoch ${o.epoch})`;
		return `…${orgId.slice(-12)}`;
	}
</script>

<section class="panel">
	<h2>Story 4: Live Membership &amp; Chain Verification</h2>
	<p class="hint">
		Start the receiver loop to watch for inbound org updates.
		Each update is verified against the on-chain root — the result (✓/✗) is the core PoC output.
	</p>

	<div class="receiver-ctl">
		{#if !receiverStarted}
			<button onclick={doStartReceiver} disabled={startBusy}>
				{startBusy ? 'Starting…' : 'Start Receiver Loop'}
			</button>
			{#if receiverErr}<p class="err">{receiverErr}</p>{/if}
		{:else}
			<p class="ok receiver-badge">Receiver running — listening for updates…</p>
		{/if}
	</div>

	<!-- THE KEY PoC OUTPUT: verified root log -->
	<div class="verify-section">
		<h3>Verified Updates (chain root match)</h3>
		{#if verifyLog.length === 0}
			<p class="muted">No updates received yet.</p>
		{:else}
			<table>
				<thead>
					<tr><th>Time</th><th>Org</th><th>Epoch</th><th>Root (tail)</th><th>Verified</th></tr>
				</thead>
				<tbody>
					{#each verifyLog as v, i (i)}
						<tr>
							<td class="mono small">{v.ts}</td>
							<td class="mono small">{orgLabel(v.org_id)}</td>
							<td>{v.epoch}</td>
							<td class="mono small">…{v.root.slice(-16)}</td>
							<td class:check={v.verified} class:cross={!v.verified}>
								{v.verified ? '✓ MATCH' : '✗ MISMATCH'}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>

	<!-- Revoked orgs -->
	{#if revokedOrgs.length > 0}
		<div class="revoked-section">
			<h3>Revoked &amp; Self-Deleted</h3>
			{#each revokedOrgs as orgId, i (i)}
				<p class="revoked-entry">Removed from org …{orgId.slice(-12)}</p>
			{/each}
		</div>
	{/if}

	<!-- Receiver errors (non-fatal) -->
	{#if receiverErrors.length > 0}
		<div class="errors-section">
			<h3>Receiver Errors (non-fatal)</h3>
			{#each receiverErrors as msg, i (i)}
				<p class="err small">{msg}</p>
			{/each}
		</div>
	{/if}
</section>

<style>
	.panel { background: #111; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }
	h2 { margin-top: 0; font-size: 1rem; color: #ddd; }
	h3 { font-size: 0.9rem; color: #aaa; margin: 0.75rem 0 0.4rem; }
	.hint { color: #666; font-size: 0.8rem; margin-bottom: 0.75rem; }
	.receiver-ctl { margin-bottom: 0.75rem; }
	button { cursor: pointer; background: #1a3a5c; color: #7ec8e3; border: 1px solid #2a5f8c; border-radius: 3px; padding: 0.35rem 0.9rem; font-size: 0.85rem; }
	button:disabled { opacity: 0.5; cursor: default; }
	button:not(:disabled):hover { background: #204d7a; }
	.receiver-badge { background: #0d2f1d; border: 1px solid #2e7d32; padding: 0.35rem 0.75rem; border-radius: 3px; display: inline-block; }

	.verify-section { margin-bottom: 0.75rem; }
	table { border-collapse: collapse; width: 100%; font-size: 0.82rem; }
	th, td { text-align: left; padding: 0.25rem 0.5rem; border-bottom: 1px solid #1a1a1a; }
	th { color: #666; font-weight: normal; }
	td { color: #bbb; }
	.mono { font-family: monospace; }
	.small { font-size: 0.75rem; color: #777; }

	/* THE KEY DISPLAY: verified/not */
	.check { color: #4caf50; font-weight: bold; font-size: 0.9rem; }
	.cross { color: #f44336; font-weight: bold; font-size: 0.9rem; }

	.revoked-section { background: #1a0a0a; border: 1px solid #5c1111; border-radius: 4px; padding: 0.5rem 0.75rem; margin-bottom: 0.5rem; }
	.revoked-entry { color: #f44336; font-size: 0.82rem; margin: 0.2rem 0; }

	.errors-section { background: #1a1200; border: 1px solid #4a3800; border-radius: 4px; padding: 0.5rem 0.75rem; }
	.err { color: #f44336; }
	.ok { color: #4caf50; }
	.muted { color: #555; font-size: 0.82rem; }
</style>
