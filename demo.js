// A demonstration of two parties communicating via WebSeif over WebSockets. One
// party listens on Deno or Node.js, and the other party connects from a
// browser.

// Firstly, run this script in Node.js or Deno to start the server (Bob). Once
// Bob is listening, run this script in the browser to make a client
// (Alice) connect to Bob. Bob and Alice should then be seen to have a
// conversation, until one of them randomly closes the connection.

/*jslint browser, node, deno, global, long */

import hex from "./hex.js";
import elliptic from "./elliptic.js";
import party from "./party.js";
import indexeddb_store from "./store/indexeddb_store.js";
import websockets_transport from "./transport/websockets_transport.js";

// Once you have run the demo once, you can change the 'initialize_stores'
// variable to 'false'. That will test that the stores really are persistent.

const initialize_stores = true;
const trace = globalThis.console.log;
const bob_address = "ws://127.0.0.1:6300";

// Uncomment the keys that match the keysize specified in elliptic.js.

const alice_private_key_hex = "3081EE020100301006072A8648CE3D020106052B810400230481D63081D3020101044201BEB663A4C774EB5922BA1C30EC0522B74082B01EB69721EF38EDE41D47DBC00119518FCF8896EBE49220A65873BF5EA75D4456FC97DEE4BD2675C0EBC677E03EB0A18189038186000400A84D1FE2AB031BE95356171FDD33ADA2723A6CC4991ACD5C18979F1F7494B3E8CC336F60D41563A22C59C43E94EA1CA5D99EA118CF041CF4409F13C240033BFD8A003E9A7D4F7A58E347D8AD68F687FA65A79CD118027A88140B07BB3EDCE7900E455E68CDAA95A970FCF52EBF48DEAA391E7DF2CDE6FF199A513B2412B323C0E1DC90";
const alice_public_key_hex = "0400A84D1FE2AB031BE95356171FDD33ADA2723A6CC4991ACD5C18979F1F7494B3E8CC336F60D41563A22C59C43E94EA1CA5D99EA118CF041CF4409F13C240033BFD8A003E9A7D4F7A58E347D8AD68F687FA65A79CD118027A88140B07BB3EDCE7900E455E68CDAA95A970FCF52EBF48DEAA391E7DF2CDE6FF199A513B2412B323C0E1DC90";
const bob_private_key_hex = "3081EE020100301006072A8648CE3D020106052B810400230481D63081D3020101044200E255367406633127A8844DDB697CC3E149B3166BA30DE6F7A4AF203FDF1ECA9031709CFC28C71D4986918D6B8865DC98D60198F0DFC6A999D93B07FC27AE9982D1A18189038186000401D11E26A35297D1F60DD1D252A62859C7B08820B55ABB4C35FF8986FF327B8729B78A41CA4241EFC0C447B22309ECC03C2B48CF32E8578B24C27460BA1AFF050A120000B7A9F9D355F723D279A96D0613C5ECEEC97C3BC668560EBAE6DCC2A8571D9D5FDA9CF1AAD34F585D22AF9A147A0F1E0486E484EE2F02A2ABDF6612CD91D5FB7A";
const bob_public_key_hex = "0401D11E26A35297D1F60DD1D252A62859C7B08820B55ABB4C35FF8986FF327B8729B78A41CA4241EFC0C447B22309ECC03C2B48CF32E8578B24C27460BA1AFF050A120000B7A9F9D355F723D279A96D0613C5ECEEC97C3BC668560EBAE6DCC2A8571D9D5FDA9CF1AAD34F585D22AF9A147A0F1E0486E484EE2F02A2ABDF6612CD91D5FB7A";

//p256 const alice_private_key_hex = "308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B02010104207B95795E0A5D5A04EE3A93DEBBCF155127B76AA1BEDF725838142A78711ABEF7A144034200040E3DE57BB108D8A753AA54C9703FB10416929D54DB1B7CF31B970E9F454313AFED3666625FD37B7EBDBDD1562BD0EFF389BE28CB38F99E05208193291080EF54";
//p256 const alice_public_key_hex = "040E3DE57BB108D8A753AA54C9703FB10416929D54DB1B7CF31B970E9F454313AFED3666625FD37B7EBDBDD1562BD0EFF389BE28CB38F99E05208193291080EF54";
//p256 const bob_private_key_hex = "308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B02010104206DC08E51AFE24C64695984364EFC84F196883E1E66E2B804A62CFE7846097D37A144034200042461B5967B66CFED3D2CB23CC1026CE500191E0CBF9B6D2334E3CA3A855E99E51E95B923A5ECD31CE4F0015FD7EF06237F62FFBF676594F439E47290648C9081";
//p256 const bob_public_key_hex = "042461B5967B66CFED3D2CB23CC1026CE500191E0CBF9B6D2334E3CA3A855E99E51E95B923A5ECD31CE4F0015FD7EF06237F62FFBF676594F439E47290648C9081";

//p384 const alice_private_key_hex = "308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B02010104201E9EC5C89B9036378995BF6D0B1EA14BF881B5DD7C530615B941F1F20400F256A1440342000479CFD0E01E93B3C864EFE092C001923F5442EFC069464B13988E35C0AECB125973C91EEB150D8CD99F1EEDB0C7E1FB2403BE4A800C5852FA14F6744B8304C343";
//p384 const alice_public_key_hex = "0479CFD0E01E93B3C864EFE092C001923F5442EFC069464B13988E35C0AECB125973C91EEB150D8CD99F1EEDB0C7E1FB2403BE4A800C5852FA14F6744B8304C343";
//p384 const bob_private_key_hex = "308187020100301306072A8648CE3D020106082A8648CE3D030107046D306B020101042010B5E47B7D4A4635C06A7D9B62BBC1DA909D2F9DADFA0B03D7D077B4EDEC5263A144034200041854279F2C0AA4057E63722EA03B77EDC04633BA4F6831E8EDD6622AC7E4FB9F3A8407AE680E71AF4DBC1C084C2EC3C2FB84DA7DFB90850022389741457679D0";
//p384 const bob_public_key_hex = "041854279F2C0AA4057E63722EA03B77EDC04633BA4F6831E8EDD6622AC7E4FB9F3A8407AE680E71AF4DBC1C084C2EC3C2FB84DA7DFB90850022389741457679D0";

// Uncomment the following to regenerate the keypairs manually.

// elliptic.generate_keypair().then(function (keypair) {
//     return Promise.all([
//         elliptic.export_private_key(keypair.privateKey),
//         elliptic.export_public_key(keypair.publicKey)
//     ]);
// }).then(function ([private_key_bytes, public_key_bytes]) {
//     trace("private", hex.encode(private_key_bytes));
//     trace("public", hex.encode(public_key_bytes));
// });

function server_listen(filesystem_store, websockets_transport) {

// Start the listening party. The store is created in the current working
// directory.

    const bob_store = filesystem_store("webseif_demo_bob", "secret123");
    const bob = party(bob_store, websockets_transport(), false);

    function listen() {
        const stop_bob = bob.listen({
            address: bob_address,
            on_open() {
                trace("bob on_open");
                setTimeout(
                    function () {
                        trace("Randomly stopping Bob.");
                        stop_bob("Done");
                    },
                    4000 * (1 + Math.random())
                );
            },
            on_message(connection, message) {
                trace("bob on_message", message);
                if (message.age >= 10) {
                    trace("bob connection.close");
                    return connection.close();
                }
                return connection.status_send({age: message.age + 1});
            },
            on_close(connection, reason) {
                trace("bob on_close", connection, reason);
            }
        });
        trace("Bob listening.");
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

    const alice_store = indexeddb_store("webseif_demo_alice");
    const alice = party(alice_store, websockets_transport());

    function connect() {
        const close_alice = alice.connect({
            petname: "bob",
            on_open(connection) {
                connection.status_send({age: 0});
                trace("alice on_open");
                setTimeout(
                    function () {
                        trace("Randomly closing Alice.");
                        close_alice("Done");
                    },
                    4000 * (1 + Math.random())
                );
            },
            on_message(connection, message) {
                trace("alice on_message", message);
                setTimeout(
                    connection.status_send,
                    300,
                    {age: message.age + 1}
                );
            },
            on_close(_, reason) {
                trace("alice on_close", reason);
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
const is_browser = globalThis.window !== undefined && !is_deno;
if (is_browser) {
    browser_connect();
} else {
    Promise.all([
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
    ]).then(function ([filesystem, transport]) {
        return server_listen(filesystem.default, transport.default);
    });
}
