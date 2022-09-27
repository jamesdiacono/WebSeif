// A WebSeif store implemented using Deno's filesystem capabilities.

/*jslint deno */

import filesystem_store from "./filesystem_store.js";

function deno_filesystem_store(directory, password, iterations) {
    return filesystem_store(
        window.crypto,
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

export default Object.freeze(deno_filesystem_store);
