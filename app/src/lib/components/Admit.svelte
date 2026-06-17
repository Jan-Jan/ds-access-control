<script lang="ts">
	/**
	 * Story 3: Admit a member.
	 * A: paste join-request blob → import_join_request (review parsed fields)
	 *    → select org → "Admit" → admit_member → shows member_id + chain update result.
	 */
	import { listOrgs, importJoinRequest, admitMember, type OrgDto, type JoinRequestDto } from '$lib/api';

	interface Props {
		notifyReload?: () => void;
	}
	let { notifyReload }: Props = $props();

	let orgs = $state<OrgDto[]>([]);
	let selectedOrgId = $state('');
	let pastedBlob = $state('');
	let parsed = $state<JoinRequestDto | null>(null);
	let parseErr = $state('');
	let parseBusy = $state(false);

	let admitBusy = $state(false);
	let admitErr = $state('');
	let memberId = $state('');
	let admitted = $state(false);

	async function loadOrgs() {
		try {
			orgs = await listOrgs();
			if (orgs.length > 0 && !selectedOrgId) selectedOrgId = orgs[0].org_id;
		} catch (e) {
			parseErr = String(e);
		}
	}

	$effect(() => { loadOrgs(); });

	async function doParse() {
		if (!pastedBlob.trim()) { parseErr = 'Paste a join-request blob.'; return; }
		parseBusy = true;
		parseErr = '';
		parsed = null;
		try {
			parsed = await importJoinRequest(pastedBlob.trim());
		} catch (e) {
			parseErr = String(e);
		} finally {
			parseBusy = false;
		}
	}

	async function doAdmit() {
		if (!parsed) { admitErr = 'Parse the blob first.'; return; }
		if (!selectedOrgId) { admitErr = 'Select an org.'; return; }
		admitBusy = true;
		admitErr = '';
		try {
			memberId = await admitMember(selectedOrgId, pastedBlob.trim(), null);
			admitted = true;
			notifyReload?.();
		} catch (e) {
			admitErr = String(e);
		} finally {
			admitBusy = false;
		}
	}

	function reset() {
		pastedBlob = '';
		parsed = null;
		parseErr = '';
		admitErr = '';
		memberId = '';
		admitted = false;
	}
</script>

<section class="panel">
	<h2>Story 3: Admit Member</h2>
	<p class="hint">Paste a join-request blob from the joiner, review the fields, then admit.</p>

	{#if admitted}
		<div class="result-box ok">
			<p>Member admitted and chain updated.</p>
			<p>Member ID: <code>{memberId}</code></p>
		</div>
		<button onclick={reset}>Admit another</button>
	{:else}
		<label>
			Join-request blob
			<textarea rows="5" bind:value={pastedBlob} placeholder="Paste join-request blob here…" disabled={parseBusy || admitBusy}></textarea>
		</label>
		<button onclick={doParse} disabled={parseBusy || admitBusy}>
			{parseBusy ? 'Parsing…' : 'Parse'}
		</button>
		{#if parseErr}<p class="err">{parseErr}</p>{/if}

		{#if parsed}
			<div class="parsed-fields">
				<h3>Parsed join request</h3>
				<dl>
					<dt>Handle</dt><dd>{parsed.handle}</dd>
					<dt>Name</dt><dd>{parsed.name} {parsed.surname}</dd>
					<dt>Member key</dt><dd class="mono">…{parsed.member_key.slice(-16)}</dd>
					<dt>Device key</dt><dd class="mono">…{parsed.device_key.slice(-16)}</dd>
					<dt>Has node addr</dt>
					<dd class:ok={parsed.has_node_addr} class:warn={!parsed.has_node_addr}>
						{parsed.has_node_addr ? 'Yes (iroh endpoint present)' : 'No (no p2p addr)'}
					</dd>
				</dl>

				{#if orgs.length === 0}
					<p class="warn">No orgs available — create one in Story 1 first.</p>
				{:else}
					<label>
						Target org
						<select bind:value={selectedOrgId}>
							{#each orgs as o (o.org_id)}
								<option value={o.org_id}>…{o.org_id.slice(-12)} (epoch {o.epoch}, {o.member_count} members)</option>
							{/each}
						</select>
					</label>
					<button class="admit-btn" onclick={doAdmit} disabled={admitBusy}>
						{admitBusy ? 'Admitting…' : 'Admit Member'}
					</button>
				{/if}
				{#if admitErr}<p class="err">{admitErr}</p>{/if}
			</div>
		{/if}
	{/if}
</section>

<style>
	.panel { background: #111; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }
	h2 { margin-top: 0; font-size: 1rem; color: #ddd; }
	h3 { font-size: 0.9rem; color: #aaa; margin: 0.75rem 0 0.4rem; }
	.hint { color: #666; font-size: 0.8rem; margin-bottom: 0.75rem; }
	label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.82rem; color: #888; margin-bottom: 0.4rem; }
	textarea, select { background: #1a1a1a; border: 1px solid #333; color: #eee; padding: 0.3rem 0.5rem; border-radius: 3px; font-family: monospace; font-size: 0.82rem; resize: vertical; }
	textarea:disabled { opacity: 0.5; }
	button { cursor: pointer; background: #1a3a5c; color: #7ec8e3; border: 1px solid #2a5f8c; border-radius: 3px; padding: 0.3rem 0.75rem; font-size: 0.82rem; }
	button:disabled { opacity: 0.5; cursor: default; }
	button:not(:disabled):hover { background: #204d7a; }
	.admit-btn { background: #1b4d1b; color: #81c784; border-color: #2e7d32; margin-top: 0.5rem; }
	.admit-btn:not(:disabled):hover { background: #245a24; }
	.parsed-fields { background: #0d0d1a; border: 1px solid #222; border-radius: 4px; padding: 0.75rem; margin-top: 0.5rem; }
	dl { display: grid; grid-template-columns: 8rem 1fr; gap: 0.2rem 0.5rem; font-size: 0.82rem; margin: 0; }
	dt { color: #666; }
	dd { color: #ccc; margin: 0; word-break: break-all; }
	.mono { font-family: monospace; }
	.result-box { background: #0d2f1d; border: 1px solid #1b5e20; border-radius: 4px; padding: 0.75rem; margin-bottom: 0.5rem; }
	.result-box p { margin: 0.2rem 0; font-size: 0.85rem; color: #ccc; }
	code { font-family: monospace; font-size: 0.78rem; color: #81c784; word-break: break-all; }
	.err { color: #f44336; font-size: 0.8rem; }
	.ok { color: #4caf50; }
	.warn { color: #ff9800; }
</style>
