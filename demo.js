// A demonstration of two parties communicating via WebSeif over WebSockets. One
// party listens on Deno or Node.js, and the other party connects from a
// browser.

// Firstly, run this script in Node.js or Deno to start the server (Bob). Once
// Bob is listening, run this script in the browser to make a client
// (Alice) connect to Bob. Bob and Alice should then be seen to have a
// conversation, until one of them randomly closes the connection.

/*jslint browser, node, deno, long */

import hex from "./hex.js";
import make_elliptic from "./elliptic.js";
import party from "./party.js";
import indexeddb_store from "./store/indexeddb_store.js";
import websockets_transport from "./transport/websockets_transport.js";

// Once you have run the demo once, you can change the 'initialize_stores'
// variable to 'false'. That will test that the stores really are persistent.

const initialize_stores = true;
const alice_private_key_hex = "3081EE020100301006072A8648CE3D020106052B810400230481D63081D3020101044201BEB663A4C774EB5922BA1C30EC0522B74082B01EB69721EF38EDE41D47DBC00119518FCF8896EBE49220A65873BF5EA75D4456FC97DEE4BD2675C0EBC677E03EB0A18189038186000400A84D1FE2AB031BE95356171FDD33ADA2723A6CC4991ACD5C18979F1F7494B3E8CC336F60D41563A22C59C43E94EA1CA5D99EA118CF041CF4409F13C240033BFD8A003E9A7D4F7A58E347D8AD68F687FA65A79CD118027A88140B07BB3EDCE7900E455E68CDAA95A970FCF52EBF48DEAA391E7DF2CDE6FF199A513B2412B323C0E1DC90";
const alice_public_key_hex = "0400A84D1FE2AB031BE95356171FDD33ADA2723A6CC4991ACD5C18979F1F7494B3E8CC336F60D41563A22C59C43E94EA1CA5D99EA118CF041CF4409F13C240033BFD8A003E9A7D4F7A58E347D8AD68F687FA65A79CD118027A88140B07BB3EDCE7900E455E68CDAA95A970FCF52EBF48DEAA391E7DF2CDE6FF199A513B2412B323C0E1DC90";
const bob_private_key_hex = "3081EE020100301006072A8648CE3D020106052B810400230481D63081D3020101044200E255367406633127A8844DDB697CC3E149B3166BA30DE6F7A4AF203FDF1ECA9031709CFC28C71D4986918D6B8865DC98D60198F0DFC6A999D93B07FC27AE9982D1A18189038186000401D11E26A35297D1F60DD1D252A62859C7B08820B55ABB4C35FF8986FF327B8729B78A41CA4241EFC0C447B22309ECC03C2B48CF32E8578B24C27460BA1AFF050A120000B7A9F9D355F723D279A96D0613C5ECEEC97C3BC668560EBAE6DCC2A8571D9D5FDA9CF1AAD34F585D22AF9A147A0F1E0486E484EE2F02A2ABDF6612CD91D5FB7A";
const bob_public_key_hex = "0401D11E26A35297D1F60DD1D252A62859C7B08820B55ABB4C35FF8986FF327B8729B78A41CA4241EFC0C447B22309ECC03C2B48CF32E8578B24C27460BA1AFF050A120000B7A9F9D355F723D279A96D0613C5ECEEC97C3BC668560EBAE6DCC2A8571D9D5FDA9CF1AAD34F585D22AF9A147A0F1E0486E484EE2F02A2ABDF6612CD91D5FB7A";
const bob_address = "ws://127.0.0.1:6300";

function server_listen(webcrypto, filesystem_store, websockets_transport) {

// Start the listening party. The store is created in the current working
// directory.

    const elliptic = make_elliptic(webcrypto);
    const bob_store = filesystem_store("webseif_demo_bob", "secret123");
    const bob = party(bob_store, websockets_transport(), false, webcrypto);

    function listen() {
        const stop_bob = bob.listen({
            address: bob_address,
            on_open(ignore) {
                console.log("bob on_open");
                setTimeout(
                    function () {
                        console.log("Randomly stopping Bob.");
                        stop_bob("Done");
                    },
                    4000 * (1 + Math.random())
                );
            },
            on_message(connection, message) {
                console.log("bob on_message", message);
                if (message.age >= 10) {
                    console.log("bob connection.close");
                    return connection.close();
                }
                return connection.status_send({age: message.age + 1});
            },
            on_close(connection, reason) {
                console.log("bob on_close", connection, reason);
            }
        });
        console.log("Bob listening.");
    }

    if (initialize_stores) {
        Promise.all([
            elliptic.import_private_key(hex.decode(bob_private_key_hex), true),
            elliptic.import_public_key(hex.decode(bob_public_key_hex))
        ]).then(function ([privateKey, publicKey]) {
            return bob_store.write_keypair({privateKey, publicKey});
        }).then(
            listen
        );
    } else {
        listen();
    }
}

function browser_connect() {

// Connect to the listening party.

    const elliptic = make_elliptic();
    const alice_store = indexeddb_store("webseif_demo_alice");
    const alice = party(alice_store, websockets_transport());

    function connect() {
        const close_alice = alice.connect({
            petname: "bob",
            on_open(connection) {
                connection.status_send({age: 0});
                console.log("alice on_open");
                setTimeout(
                    function () {
                        console.log("Randomly closing Alice.");
                        close_alice("Done");
                    },
                    4000 * (1 + Math.random())
                );
            },
            on_message(connection, message) {
                console.log("alice on_message", message);
                setTimeout(
                    connection.status_send,
                    300,
                    {age: message.age + 1}
                );
            },
            on_close(ignore, reason) {
                console.log("alice on_close", reason);
            }
        });
    }

    if (initialize_stores) {
        Promise.all([
            elliptic.import_private_key(
                hex.decode(alice_private_key_hex),
                true
            ),
            elliptic.import_public_key(hex.decode(alice_public_key_hex)),
            elliptic.import_public_key(hex.decode(bob_public_key_hex))
        ]).then(function ([privateKey, publicKey, bob_public_key]) {
            return Promise.all([
                alice_store.write_keypair({privateKey, publicKey}),
                alice_store.add_acquaintance({
                    petname: "bob",
                    address: bob_address,
                    public_key: bob_public_key
                })
            ]);
        }).then(
            connect
        );
    } else {
        connect();
    }
}

const is_deno = typeof Deno === "object";
const is_browser = typeof window === "object" && !is_deno;

if (is_browser) {
    browser_connect();
} else {
    Promise.all([
        (
            is_deno
            ? Promise.resolve(window.crypto)
            : import("node:crypto").then((module) => module.webcrypto)
        ),
        (
            is_deno
            ? import("./store/deno_filesystem_store.js")
            : import("./store/node_filesystem_store.js")
        ),
        (
            is_deno
            ? import("./transport/websockets_transport.js")
            : import("./transport/node_websockets_transport.js")
        )
    ]).then(function ([webcrypto, filesystem, transport]) {
        return server_listen(webcrypto, filesystem.default, transport.default);
    });
}

