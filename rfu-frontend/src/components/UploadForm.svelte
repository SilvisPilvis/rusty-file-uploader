<script>
    import FileInputComponent from "./FileInputComponent.svelte";
    import axios from "axios";
    let fileError = $state("");
    let files = $state();
    let {storeId = $bindable("")} = $props();

    $effect(() => {
        console.log("Effect called");
        if(files) {
            for (const file of files) {
                // console.log(file);
                console.log(`${file.name}: ${file.size} bytes`);
            }
        }
    });
    
    async function submit() {
        fileError = "";

        console.log(files);
    
        if(files === undefined) {
            fileError = "Choose atleast 1 file";
            return;
        }
    
        axios.post(`http://127.0.0.1:3000/store/${store_id}/upload`, {
            files: files
        })
        .then(function (response) {
            console.log(response["data"]);
        })
        .catch(function (error) {
            console.error(error);
            console.error(error["response"]["data"]["error"]);
            fileError = error["response"]["data"]["error"];
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

<form action="" method="post" class="flex flex-col justify-center align-start gap-4 outline outline-2 outline-rose-800 p-4 rounded-md" onsubmit={preventDefault(submit)}>
    <FileInputComponent error={fileError} label="Choose files to upload:" class="text-inherit" bind:value={files}/>
    <button class="bg-secondary p-4 rounded-md">Upload</button>
</form>