<script>
    import InputComponent from "./InputComponent.svelte";
    import axios from "axios";
    import { API_URL } from '../lib/constants';
    let { nameError = '', name } = $state("");
    
    async function submit() {
        nameError = "";
    
        if(name === "") {
            nameError = "Store name can't be empty";
            return;
        }
    
        axios.post(`${API_URL}/store/create`, {
            headers: {
                Authorization: `Bearer ${Cookies.get("token")}`,
            },
            name: name,
        })
        .then(function (response) {
            console.log(response["data"]);
        })
        .catch(function (error) {
            console.error(error);
            console.error(error["response"]["data"]["error"]);
            nameError = error["response"]["data"]["error"];
        });
    
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
        <InputComponent type="text" error={nameError} label="Enter store name:" class="text-inherit" bind:value={name}/>
        <button class="bg-secondary p-4 rounded-md">Create</button>
    </form>