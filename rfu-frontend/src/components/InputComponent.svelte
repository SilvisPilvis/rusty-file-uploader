<script>
let { type, error, label, value = $bindable() } = $props();
</script>

{#if error}
<div class="grid grid-rows-1">
    <label class="grid grid-cols-1 grid-flow-row">
        {label}
        <input type="{type}" class="bg-primary p-4 rounded-md text-text focus:outline-none" bind:value={value}>
        <p class="text-2xl text-red-600">{error}</p>
    </label>
</div>
{:else}
<div class="grid grid-cols-1">
    <label class="grid grid-cols-1">
        {label}
        <input type="{type}" class="bg-primary p-4 rounded-md text-text focus:outline-none" bind:value={value}>
    </label>
</div>
{/if}
