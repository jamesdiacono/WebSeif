// A WebSeif store implemented using the IndexedDB API.

/*jslint browser */

function opaqify(private_key) {

// The 'opaqify' function returns a Promise that resolves to a non-extractable
// copy of the 'private_key', a CryptoKey instance.

    return crypto.subtle.exportKey(
        "pkcs8",
        private_key
    ).then(function (key_data) {
        return crypto.subtle.importKey(
            "pkcs8",
            key_data,
            private_key.algorithm,
            false,
            private_key.usages
        );
    });
}

function indexeddb_store(db_name) {
    function request(object_store_name, request_factory) {

// The 'request' function provides a Promise-based interface catering to our
// specific usage of IndexedDB.

        return new Promise(function (resolve, reject) {
            const open = window.indexedDB.open(db_name, 1);
            open.onupgradeneeded = function (event) {
                if (event.oldVersion < 1) {

// The database has just been created. Define its "schema".

                    open.result.createObjectStore(
                        "acquaintances",
                        {keyPath: "petname"}
                    );
                    open.result.createObjectStore(
                        "keypairs",
                        {keyPath: "id"}
                    );
                }
            };
            open.onsuccess = function () {

// All IndexedDB requests must take place within a transaction. Create a
// transaction, and within it execute a request to the specified object store.
// Close the database when we're done.

                const transaction = open.result.transaction(
                    object_store_name,
                    "readwrite"
                );
                transaction.oncomplete = function () {
                    return open.result.close();
                };
                transaction.onerror = function (event) {
                    reject(event);
                    return open.result.close();
                };
                const the_request = request_factory(
                    transaction.objectStore(object_store_name)
                );
                the_request.onsuccess = function () {
                    return resolve(the_request.result);
                };
            };
            open.onblocked = reject;
            open.onerror = reject;
        });
    }
    function write_keypair(keypair) {
        return opaqify(keypair.privateKey).then(function (opaque_private_key) {
            return request("keypairs", function (store) {

// The "keypairs" store contains at most 1 entry, which is an object containing
// the keypair. We provide an "id" property just to satisfy IndexedDB.

                return store.put({
                    id: "",
                    keypair: {
                        publicKey: keypair.publicKey,
                        privateKey: opaque_private_key
                    }
                });
            });
        });
    }
    function read_keypair() {
        return request("keypairs", function (store) {
            return store.get("");
        }).then(function (value) {
            return value?.keypair;
        });
    }
    function add_acquaintance(acquaintance) {
        return request("acquaintances", function (store) {
            return store.put(acquaintance);
        });
    }
    function remove_acquaintance(petname) {
        return request("acquaintances", function (store) {
            return store.delete(petname);
        });
    }
    function read_acquaintance(petname) {
        return request("acquaintances", function (store) {
            return store.get(petname);
        });
    }
    return Object.freeze({
        write_keypair,
        read_keypair,
        add_acquaintance,
        remove_acquaintance,
        read_acquaintance
    });
}

export default Object.freeze(indexeddb_store);
