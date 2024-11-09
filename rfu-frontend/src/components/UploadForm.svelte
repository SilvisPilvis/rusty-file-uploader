<script>
    import FileInputComponent from "./FileInputComponent.svelte";
    import axios from "axios";
    import Cookies from "js-cookie";
    let fileError = $state("");
    let { files, uploaded } = $state("");
    let { storeId = $bindable() } = $props();

    uploaded = new FormData();

    $effect(() => {
        console.log("Effect called");
        if (files) {
            // uploaded = files;
            for (const file of files) {
                uploaded.append(file.name, file);
                // console.log(`${file.name}: ${file.size} bytes`);
            }
        }
    });

    async function submit() {
        if (Cookies.get("token") === "" || Cookies.get("token") === undefined) {
            fileError = "No Auth token provided";
            return;
        }

        fileError = "";

        if (files === undefined || uploaded === undefined) {
            fileError = "Choose atleast 1 file";
            return;
        }

        axios.post(
                `http://127.0.0.1:3000/store/${storeId}/upload`, uploaded,
                {
                    // withCredentials: true,
                    headers: {
                        'Content-Type': 'multipart/form-data',
                        Authorization: `Bearer ${Cookies.get("token")}`,
                    },
                },
            )
            .then(
                response => { console.log(response.data);
            })
            .catch(
                error => { console.error('Error:', error);
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

<form
    action=""
    enctype="multipart/form-data"
    method="post"
    class="flex flex-col justify-center align-start gap-4 outline outline-2 outline-rose-800 p-4 rounded-md"
    onsubmit={preventDefault(submit)}
>
    <FileInputComponent
        error={fileError}
        label="Choose files to upload:"
        class="text-inherit"
        bind:value={files}
    />
    <button class="bg-secondary p-4 rounded-md">Upload</button>
</form>
