<script>
let { type = 'text', error = "" } = $props();
</script>

{#if error}
<div class="grid grid-rows-2">
    <input type="{type}" class="bg-primary p-4 rounded-md text-text focus:outline-none">
    {#if error}
        <p class="text-2xl text-red-600">{error}</p>
    {/if}
</div>
{:else}
<div class="grid grid-rows-1">
    <input type="{type}" class="bg-primary p-4 rounded-md text-text focus:outline-none">
</div>
{/if}

