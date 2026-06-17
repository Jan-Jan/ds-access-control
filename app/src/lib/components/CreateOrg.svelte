<script lang="ts">
	/**
	 * Story 1: create persona + create organisation.
	 * Persona form → create_persona → create_organisation; shows org_id + epoch.
	 */
	import { createPersona, createOrganisation } from '$lib/api';

	interface Props {
		notifyReload?: () => void;
	}
	let { notifyReload }: Props = $props();

	let handle = $state('');
	let name = $state('');
	let surname = $state('');
	let busy = $state(false);
	let step = $state<'idle' | 'persona-done' | 'org-done'>('idle');
	let personaId = $state('');
	let orgId = $state('');
	let err = $state('');

	async function run() {
		if (!handle.trim() || !name.trim()) {
			err = 'Handle and name are required.';
			return;
		}
		busy = true;
		err = '';
		try {
			// Step 1: create persona
			personaId = await createPersona(handle.trim(), name.trim(), surname.trim());
			step = 'persona-done';

			// Step 2: create organisation
			orgId = await createOrganisation(personaId);
			step = 'org-done';
			notifyReload?.();
		} catch (e) {
			err = String(e);
			step = 'idle';
		} finally {
			busy = false;
		}
	}

	function reset() {
		handle = '';
		name = '';
		surname = '';
		personaId = '';
		orgId = '';
		step = 'idle';
		err = '';
	}
</script>

<section class="panel">
	<h2>Story 1: Create Persona + Organisation</h2>
	<p class="hint">Creates a persona then submits a genesis org to the chain.</p>

	{#if step === 'org-done'}
		<div class="result-box ok">
			<p>Organisation created on chain.</p>
			<p>Persona ID: <code>{personaId}</code></p>
			<p>Org ID: <code>{orgId}</code></p>
		</div>
		<button onclick={reset}>Create another</button>
	{:else}
		<form onsubmit={(e) => { e.preventDefault(); run(); }}>
			<label>
				Handle
				<input type="text" bind:value={handle} placeholder="alice" disabled={busy} />
			</label>
			<label>
				Name
				<input type="text" bind:value={name} placeholder="Alice" disabled={busy} />
			</label>
			<label>
				Surname
				<input type="text" bind:value={surname} placeholder="Smith" disabled={busy} />
			</label>

			{#if step === 'persona-done'}
				<p class="progress">Persona created: <code>…{personaId.slice(-12)}</code>. Creating org…</p>
			{/if}

			{#if err}
				<p class="err">{err}</p>
			{/if}

			<button type="submit" disabled={busy}>
				{busy ? 'Working…' : 'Create Persona + Org'}
			</button>
		</form>
	{/if}
</section>

<style>
	.panel { background: #111; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }
	h2 { margin-top: 0; font-size: 1rem; color: #ddd; }
	.hint { color: #666; font-size: 0.8rem; margin-bottom: 0.75rem; }
	form { display: flex; flex-direction: column; gap: 0.5rem; }
	label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.85rem; color: #aaa; }
	input { background: #1a1a1a; border: 1px solid #333; color: #eee; padding: 0.3rem 0.5rem; border-radius: 3px; font-size: 0.9rem; }
	input:disabled { opacity: 0.5; }
	button { margin-top: 0.25rem; cursor: pointer; background: #1a3a5c; color: #7ec8e3; border: 1px solid #2a5f8c; border-radius: 3px; padding: 0.4rem 1rem; font-size: 0.85rem; align-self: flex-start; }
	button:disabled { opacity: 0.5; cursor: default; }
	button:not(:disabled):hover { background: #204d7a; }
	.result-box { background: #0d2f1d; border: 1px solid #1b5e20; border-radius: 4px; padding: 0.75rem; margin-bottom: 0.5rem; }
	.result-box p { margin: 0.2rem 0; font-size: 0.85rem; color: #ccc; }
	code { font-family: monospace; font-size: 0.8rem; color: #81c784; word-break: break-all; }
	.progress { color: #ff9800; font-size: 0.8rem; }
	.err { color: #f44336; font-size: 0.85rem; }
</style>
