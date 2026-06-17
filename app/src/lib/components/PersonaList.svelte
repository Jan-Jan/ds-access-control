<script lang="ts">
	import { listPersonas, listOrgs, type PersonaDto, type OrgDto } from '$lib/api';

	interface Props {
		/** Increment this to trigger a reload */
		reloadToken?: number;
	}

	let { reloadToken = 0 }: Props = $props();

	let personas = $state<PersonaDto[]>([]);
	let orgs = $state<OrgDto[]>([]);
	let error = $state('');
	let loading = $state(false);

	async function reload() {
		loading = true;
		try {
			[personas, orgs] = await Promise.all([listPersonas(), listOrgs()]);
			error = '';
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		// Re-run whenever reloadToken changes (dependency tracked by Svelte 5 runes)
		reloadToken;
		reload();
	});

	function orgLabel(orgId: string | null): string {
		if (!orgId) return '(unattached)';
		const o = orgs.find((x) => x.org_id === orgId);
		if (o) return `org …${orgId.slice(-8)} epoch=${o.epoch} members=${o.member_count}`;
		return `org …${orgId.slice(-8)}`;
	}

	function statusClass(status: string): string {
		if (status.includes('Active')) return 'active';
		if (status.includes('Revoked')) return 'revoked';
		return 'proposed';
	}
</script>

<section class="panel">
	<h2>Personas &amp; Orgs</h2>
	{#if loading}<p class="muted">loading…</p>{/if}
	{#if error}<p class="err">{error}</p>{/if}

	{#if personas.length === 0 && !loading}
		<p class="muted">No personas yet. Use "Story 1" to create one.</p>
	{:else}
		<table>
			<thead>
				<tr>
					<th>Handle</th>
					<th>Name</th>
					<th>Status</th>
					<th>Org</th>
					<th>Persona ID</th>
				</tr>
			</thead>
			<tbody>
				{#each personas as p (p.persona_id)}
					<tr>
						<td><strong>{p.handle}</strong></td>
						<td>{p.name} {p.surname}</td>
						<td><span class="badge {statusClass(p.status)}">{p.status}</span></td>
						<td class="mono small">{orgLabel(p.org_id)}</td>
						<td class="mono small">…{p.persona_id.slice(-12)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	{#if orgs.length > 0}
		<h3>Orgs</h3>
		<table>
			<thead>
				<tr><th>Org ID</th><th>Epoch</th><th>Members</th><th>Root hash</th></tr>
			</thead>
			<tbody>
				{#each orgs as o (o.org_id)}
					<tr>
						<td class="mono small">…{o.org_id.slice(-12)}</td>
						<td>{o.epoch}</td>
						<td>{o.member_count}</td>
						<td class="mono small">…{o.root_hash.slice(-16)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	<button onclick={reload}>Refresh</button>
</section>

<style>
	.panel { background: #111; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; }
	h2 { margin-top: 0; font-size: 1rem; color: #ddd; }
	h3 { font-size: 0.9rem; color: #bbb; margin-top: 1rem; }
	table { border-collapse: collapse; width: 100%; font-size: 0.85rem; margin-bottom: 0.5rem; }
	th, td { text-align: left; padding: 0.25rem 0.5rem; border-bottom: 1px solid #2a2a2a; }
	th { color: #888; font-weight: normal; }
	td { color: #ccc; }
	.mono { font-family: monospace; }
	.small { font-size: 0.75rem; color: #777; }
	.badge { font-size: 0.7rem; padding: 0.1rem 0.4rem; border-radius: 3px; font-weight: bold; }
	.active { background: #1b4332; color: #4caf50; }
	.revoked { background: #4a1010; color: #f44336; }
	.proposed { background: #2a2a10; color: #ff9800; }
	.err { color: #f44336; font-size: 0.85rem; }
	.muted { color: #555; font-size: 0.85rem; }
	button { margin-top: 0.5rem; cursor: pointer; background: #222; color: #aaa; border: 1px solid #444; border-radius: 3px; padding: 0.25rem 0.75rem; font-size: 0.8rem; }
	button:hover { background: #333; }
</style>
