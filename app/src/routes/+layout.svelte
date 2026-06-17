<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		children: Snippet;
	}

	let { children }: Props = $props();
</script>

<main>
	{@render children()}
</main>

<style>
	main {
		font-family: system-ui, -apple-system, sans-serif;
		padding: 1rem;
	}
</style>
