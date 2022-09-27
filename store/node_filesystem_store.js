// A WebSeif store implemented using Node.js's filesystem capabilities.

/*jslint deno */

import fs from "node:fs";
import path from "node:path";
import {webcrypto} from "node:crypto";
import filesystem_store from "./filesystem_store.js";

function node_filesystem_store(directory, password, iterations) {
    return filesystem_store(
        webcrypto,
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

export default Object.freeze(node_filesystem_store);
