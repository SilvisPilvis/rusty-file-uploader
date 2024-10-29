<script>
import InputComponent from "./InputComponent.svelte";
let { usernameError = '', passwordError = "" } = $state("");
</script>

<form action="" method="post" class="grid grid-rows-3 place-items-center gap-4">
    <InputComponent type="text" error={usernameError} class="text-inherit"/>
    <InputComponent type="password" error={passwordError}/>
    <button class="bg-secondary p-4 rounded-md">Login</button>
</form>