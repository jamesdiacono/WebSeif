// Demonstrates a WebSeif store.

/*jslint browser, devel */

import elliptic from "../elliptic.js";

function store_demo(store) {

// Choose a petname containing characters that are invalid in a filename.

    const petname = "Bob <he/him>";
    return elliptic.generate_keypair().then(function (keypair) {
        return Promise.all([
            store.write_keypair(keypair).then(store.read_keypair),
            store.add_acquaintance({
                petname,
                address: "12.34.56.78:9999",
                public_key: keypair.publicKey
            }).then(function () {
                return store.read_acquaintance(petname);
            })
        ]);
    }).then(function ([keypair, acquaintance]) {
        console.log(keypair);
        console.log(acquaintance);
        console.log(keypair.privateKey.extractable);
        return store.remove_acquaintance(petname);
    }).then(function () {
        return store.read_acquaintance(petname);
    }).then(function (acquaintance) {
        console.log(acquaintance);
    });
}

export default Object.freeze(store_demo);
