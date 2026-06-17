<script lang="ts">
	/**
	 * Story 2: Invite flow (two sides).
	 * A (Org Admin): export_invite → show/copy blob.
	 * B (Joiner):   paste invite blob → import_invite → create persona form → export_join_request → show/copy blob.
	 */
	import {
		listOrgs,
		exportInvite,
		importInvite,
		createPersona,
		exportJoinRequest,
		type OrgDto
	} from '$lib/api';

	interface Props {
		notifyReload?: () => void;
	}
	let { notifyReload }: Props = $props();

	// --- Side A: export invite ---
	let orgs = $state<OrgDto[]>([]);
	let selectedOrgId = $state('');
	let inviteBlob = $state('');
	let exportBusy = $state(false);
	let exportErr = $state('');

	async function loadOrgs() {
		try {
			orgs = await listOrgs();
			if (orgs.length > 0 && !selectedOrgId) selectedOrgId = orgs[0].org_id;
		} catch (e) {
			exportErr = String(e);
		}
	}

	$effect(() => { loadOrgs(); });

	async function doExportInvite() {
		if (!selectedOrgId) { exportErr = 'Select an org.'; return; }
		exportBusy = true;
		exportErr = '';
		try {
			inviteBlob = await exportInvite(selectedOrgId);
		} catch (e) {
			exportErr = String(e);
		} finally {
			exportBusy = false;
		}
	}

	function copyInvite() {
		navigator.clipboard.writeText(inviteBlob);
	}

	// --- Side B: import invite → create persona → export join request ---
	let pastedInvite = $state('');
	let importedOrgId = $state('');
	let importBusy = $state(false);
	let importErr = $state('');

	// Persona form (for the joiner)
	let jHandle = $state('');
	let jName = $state('');
	let jSurname = $state('');
	let jPersonaId = $state('');
	let joinRequestBlob = $state('');
	let jrBusy = $state(false);
	let jrErr = $state('');

	async function doImportInvite() {
		if (!pastedInvite.trim()) { importErr = 'Paste invite blob first.'; return; }
		importBusy = true;
		importErr = '';
		try {
			importedOrgId = await importInvite(pastedInvite.trim());
			importErr = '';
		} catch (e) {
			importErr = String(e);
			importedOrgId = '';
		} finally {
			importBusy = false;
		}
	}

	async function doCreatePersonaAndJoinRequest() {
		if (!jHandle.trim() || !jName.trim()) { jrErr = 'Handle and name required.'; return; }
		if (!importedOrgId) { jrErr = 'Import invite first.'; return; }
		jrBusy = true;
		jrErr = '';
		try {
			jPersonaId = await createPersona(jHandle.trim(), jName.trim(), jSurname.trim());
			joinRequestBlob = await exportJoinRequest(jPersonaId);
			notifyReload?.();
		} catch (e) {
			jrErr = String(e);
		} finally {
			jrBusy = false;
		}
	}

	function copyJoinRequest() {
		navigator.clipboard.writeText(joinRequestBlob);
	}
</script>

<section class="panel">
	<h2>Story 2: Invite Flow</h2>

	<div class="two-col">
		<!-- Side A: org admin exports invite -->
		<div class="side">
			<h3>A — Export Invite (Org Admin)</h3>
			{#if orgs.length === 0}
				<p class="muted">No orgs yet (create one in Story 1).</p>
			{:else}
				<label>
					Org
					<select bind:value={selectedOrgId}>
						{#each orgs as o (o.org_id)}
							<option value={o.org_id}>…{o.org_id.slice(-12)} (epoch {o.epoch})</option>
						{/each}
					</select>
				</label>
				<button onclick={doExportInvite} disabled={exportBusy}>
					{exportBusy ? 'Exporting…' : 'Export Invite'}
				</button>
				{#if exportErr}<p class="err">{exportErr}</p>{/if}
				{#if inviteBlob}
					<label>
						Invite blob (copy to joiner)
						<textarea readonly rows="4" value={inviteBlob}></textarea>
					</label>
					<button onclick={copyInvite}>Copy</button>
				{/if}
			{/if}
		</div>

		<!-- Side B: joiner imports invite + creates join request -->
		<div class="side">
			<h3>B — Import Invite + Create Join Request (Joiner)</h3>
			<label>
				Paste invite blob
				<textarea rows="4" bind:value={pastedInvite} placeholder="Paste blob here…"></textarea>
			</label>
			<button onclick={doImportInvite} disabled={importBusy}>
				{importBusy ? 'Importing…' : 'Import Invite'}
			</button>
			{#if importErr}<p class="err">{importErr}</p>{/if}
			{#if importedOrgId}
				<p class="ok">Invite imported for org …{importedOrgId.slice(-12)}</p>
				<h4>Joiner persona</h4>
				<label>Handle <input type="text" bind:value={jHandle} placeholder="bob" disabled={jrBusy} /></label>
				<label>Name <input type="text" bind:value={jName} placeholder="Bob" disabled={jrBusy} /></label>
				<label>Surname <input type="text" bind:value={jSurname} placeholder="Jones" disabled={jrBusy} /></label>
				<button onclick={doCreatePersonaAndJoinRequest} disabled={jrBusy}>
					{jrBusy ? 'Working…' : 'Create Persona + Export Join Request'}
				</button>
				{#if jrErr}<p class="err">{jrErr}</p>{/if}
				{#if joinRequestBlob}
					<label>
						Join-request blob (send to org admin)
						<textarea readonly rows="4" value={joinRequestBlob}></textarea>
					</label>
					<button onclick={copyJoinRequest}>Copy</button>
				{/if}
			{/if}
		</div>
	</div>
</section>

<style>
	.panel { background: #111; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }
	h2 { margin-top: 0; font-size: 1rem; color: #ddd; }
	h3 { font-size: 0.9rem; color: #aaa; margin: 0 0 0.5rem; }
	h4 { font-size: 0.85rem; color: #888; margin: 0.5rem 0 0.25rem; }
	.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
	@media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } }
	.side { display: flex; flex-direction: column; gap: 0.4rem; }
	label { display: flex; flex-direction: column; gap: 0.15rem; font-size: 0.82rem; color: #888; }
	input, select, textarea { background: #1a1a1a; border: 1px solid #333; color: #eee; padding: 0.3rem 0.5rem; border-radius: 3px; font-size: 0.82rem; font-family: monospace; resize: vertical; }
	input:disabled { opacity: 0.5; }
	button { cursor: pointer; background: #1a3a5c; color: #7ec8e3; border: 1px solid #2a5f8c; border-radius: 3px; padding: 0.3rem 0.75rem; font-size: 0.82rem; align-self: flex-start; }
	button:disabled { opacity: 0.5; cursor: default; }
	button:not(:disabled):hover { background: #204d7a; }
	.err { color: #f44336; font-size: 0.8rem; }
	.ok { color: #4caf50; font-size: 0.8rem; }
	.muted { color: #555; font-size: 0.82rem; }
</style>
