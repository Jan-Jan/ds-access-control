<script lang="ts">
	import StatusBar from '$lib/components/StatusBar.svelte';
	import PersonaList from '$lib/components/PersonaList.svelte';
	import CreateOrg from '$lib/components/CreateOrg.svelte';
	import Invite from '$lib/components/Invite.svelte';
	import Admit from '$lib/components/Admit.svelte';
	import Membership from '$lib/components/Membership.svelte';
	import Revoke from '$lib/components/Revoke.svelte';

	type TabId = 'personas' | 's1' | 's2' | 's3' | 's4' | 's5';

	let activeTab = $state<TabId>('personas');
	/** Increment to signal PersonaList to reload */
	let reloadToken = $state(0);

	function notifyReload() {
		reloadToken += 1;
	}

	const tabs: { id: TabId; label: string }[] = [
		{ id: 'personas', label: 'Personas / Orgs' },
		{ id: 's1', label: 'S1: Create Org' },
		{ id: 's2', label: 'S2: Invite' },
		{ id: 's3', label: 'S3: Admit' },
		{ id: 's4', label: 'S4: Membership' },
		{ id: 's5', label: 'S5: Revoke' }
	];
</script>

<div class="app-shell">
	<header class="app-header">
		<h1>ODS Phase 2 PoC</h1>
		<span class="subtitle">Organisational Data Sovereignty — five-story demo</span>
	</header>

	<StatusBar />

	<nav class="tab-bar">
		{#each tabs as t (t.id)}
			<button
				class="tab"
				class:active={activeTab === t.id}
				onclick={() => (activeTab = t.id)}
			>
				{t.label}
			</button>
		{/each}
	</nav>

	<div class="content">
		{#if activeTab === 'personas'}
			<PersonaList {reloadToken} />
		{:else if activeTab === 's1'}
			<CreateOrg {notifyReload} />
		{:else if activeTab === 's2'}
			<Invite {notifyReload} />
		{:else if activeTab === 's3'}
			<Admit {notifyReload} />
		{:else if activeTab === 's4'}
			<Membership {notifyReload} />
		{:else if activeTab === 's5'}
			<Revoke {notifyReload} />
		{/if}
	</div>
</div>

<style>
	:global(*, *::before, *::after) { box-sizing: border-box; }
	:global(body) {
		margin: 0;
		background: #0a0a0a;
		color: #ccc;
		font-family: system-ui, -apple-system, sans-serif;
	}

	.app-shell {
		display: flex;
		flex-direction: column;
		min-height: 100vh;
	}

	.app-header {
		background: #0f0f1e;
		border-bottom: 1px solid #222;
		padding: 0.6rem 1rem;
		display: flex;
		align-items: baseline;
		gap: 0.75rem;
	}
	h1 { margin: 0; font-size: 1.1rem; color: #7ec8e3; font-weight: 600; }
	.subtitle { color: #555; font-size: 0.8rem; }

	.tab-bar {
		display: flex;
		gap: 0;
		background: #111;
		border-bottom: 1px solid #222;
		overflow-x: auto;
	}

	.tab {
		background: none;
		border: none;
		border-bottom: 2px solid transparent;
		color: #777;
		cursor: pointer;
		font-size: 0.82rem;
		padding: 0.5rem 0.9rem;
		white-space: nowrap;
		transition: color 0.1s, border-color 0.1s;
	}
	.tab:hover { color: #bbb; background: #181818; }
	.tab.active { color: #7ec8e3; border-bottom-color: #7ec8e3; background: #0d0d18; }

	.content {
		flex: 1;
		padding: 1rem;
		max-width: 900px;
	}
</style>
