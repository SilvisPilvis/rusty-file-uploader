<script>
    let {error, label, value = $bindable() } = $props();
</script>
    
{#if error}
<div class="grid grid-rows-1">
    <label class="grid grid-cols-1 grid-flow-row">
        {label}
        <input type="file" multiple class="bg-primary p-4 rounded-md text-text focus:outline-none" bind:files={value} accept="image/*">
        <p class="text-2xl text-red-600">{error}</p>
    </label>
</div>
{:else}
<div class="grid grid-cols-1">
    <label class="grid grid-cols-1">
        {label}
        <input type="file" multiple class="bg-primary p-4 rounded-md text-text focus:outline-none" bind:files={value} accept="image/*">
    </label>
</div>
{/if}
    
    