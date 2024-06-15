// A WebSeif store implemented using Node.js's filesystem capabilities.

/*jslint deno */

import fs from "node:fs";
import path from "node:path";
import filesystem_store from "./filesystem_store.js";
import store_demo from "./store_demo.js";

function node_filesystem_store(directory, password, iterations) {
    return filesystem_store(
        fs.promises.readFile,
        fs.promises.writeFile,
        fs.promises.unlink,
        fs.promises.mkdir,
        path.sep,
        directory,
        password,
        iterations
    );
}

if (import.meta.main) {
    store_demo(node_filesystem_store("/tmp/nodealice", "secret123", 10000));
}

export default Object.freeze(node_filesystem_store);
