<script lang="ts">
	import { connectionStatus, type ConnectionStatus } from '$lib/api';

	let status = $state<ConnectionStatus | null>(null);
	let error = $state('');

	async function refresh() {
		try {
			status = await connectionStatus();
			error = '';
		} catch (e) {
			error = String(e);
		}
	}

	$effect(() => {
		refresh();
	});
</script>

<div class="status-bar">
	<span class="label">Status:</span>
	{#if error}
		<span class="err">connection_status error: {error}</span>
	{:else if status}
		<span class:ok={status.chain_configured} class:warn={!status.chain_configured}>
			{status.chain_configured ? 'Chain OK' : 'Chain NOT configured'}
		</span>
		{#if status.chain_ws}
			<span class="detail">ws: {status.chain_ws}</span>
		{/if}
		{#if status.contract_h160}
			<span class="detail">contract: {status.contract_h160}</span>
		{/if}
		<span class="detail">data: {status.data_dir}</span>
	{:else}
		<span class="muted">loading…</span>
	{/if}
	<button onclick={refresh} style="margin-left:0.5rem;font-size:0.75rem;">refresh</button>
</div>

<style>
	.status-bar {
		background: #1a1a2e;
		color: #ccc;
		padding: 0.3rem 0.75rem;
		font-size: 0.8rem;
		display: flex;
		gap: 0.75rem;
		align-items: center;
		border-bottom: 1px solid #333;
		flex-wrap: wrap;
	}
	.label { font-weight: bold; color: #aaa; }
	.ok { color: #4caf50; font-weight: bold; }
	.warn { color: #ff9800; font-weight: bold; }
	.err { color: #f44336; }
	.detail { color: #888; font-family: monospace; font-size: 0.75rem; }
	.muted { color: #555; }
	button { cursor: pointer; background: #333; color: #ccc; border: 1px solid #555; border-radius: 3px; padding: 0.1rem 0.4rem; }
	button:hover { background: #444; }
</style>
