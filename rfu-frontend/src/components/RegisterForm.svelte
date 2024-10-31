<script>
    import InputComponent from "./InputComponent.svelte";
    import axios from "axios";
    import Cookies from "js-cookie";
    
    let { usernameError = '', passwordError = "", repeatError = "", username = "", password = "", repeatPass = "", token } = $state("");
    
    async function submit() {
        usernameError, passwordError, repeatError = "";

        if (password !== repeatPass) {
            repeatError = "Passwords don't match";
            return;
        }

        if (repeatPass === "") {
            repeatError = "This field is required";
            return;
        }

        if(username && password === "") {
            passwordError = "Password can't be empty";
            usernameError = "Username can't be empty";
            return;
        }

        if(password === "") {
            passwordError = "Password can't be empty";
            return;
        }

        if(username === "") {
            usernameError = "Username can't be empty";
            return;
        }

        if(username !== "" && password !== "" && repeatPass !== "" && password === repeatPass){
            axios.post('http://127.0.0.1:3000/register', {
                username: username,
                password: password
            })
            .then(function (response) {
                token = response["data"]["token"];
                Cookies.set("token", token);
            })
            .catch(function (error) {
                console.error(error["response"]["data"]["error"]);
                usernameError = error["response"]["data"]["error"];
                passwordError = error["response"]["data"]["error"];
            });
        }
    
    }
    
    function once(fn) {
        return function (event) {
            if (fn) fn.call(this, event);
            fn = null;
        };
    }
    
    function preventDefault(fn) {
        return function (event) {
            event.preventDefault();
            fn.call(this, event);
        };
    }
</script>
    
    <!-- <form action="" method="post" class="grid grid-rows-3 place-items-center gap-4 outline outline-2 outline-rose-800 p-4 rounded-md" onsubmit={once(preventDefault(submit))}> -->
    <form action="" method="post" class="flex flex-col justify-center align-start gap-4 outline outline-2 outline-rose-800 p-4 rounded-md" onsubmit={preventDefault(submit)}>
        <InputComponent type="text" error={usernameError} label="Username:" class="text-inherit" bind:value={username}/>
        <InputComponent type="password" error={passwordError} label="Password:" bind:value={password}/>
        <InputComponent type="password" error={repeatError} label="Repeat password:" bind:value={repeatPass}/>
        <button class="bg-secondary p-4 rounded-md">Register</button>
    </form> 