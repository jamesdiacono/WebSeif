// A WebSeif store implemented using Deno's filesystem capabilities.

/*jslint deno */

import filesystem_store from "./filesystem_store.js";
import store_demo from "./store_demo.js";

function deno_filesystem_store(directory, password, iterations) {
    return filesystem_store(
        Deno.readFile,
        Deno.writeFile,
        Deno.remove,
        Deno.mkdir,
        (
            Deno.build.os === "windows"
            ? "\\"
            : "/"
        ),
        directory,
        password,
        iterations
    );
}

if (import.meta.main) {
    store_demo(deno_filesystem_store("/tmp/denoalice", "secret123", 10000));
}

export default Object.freeze(deno_filesystem_store);
