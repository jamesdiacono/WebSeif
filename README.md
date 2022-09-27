# WebSeif

![](https://james.diacono.com.au/files/seif.png)

WebSeif (pronounced "websafe") implements the [Seif Protocol](https://www.crockford.com/seif.html) using the WebCrypto API, available in Node.js, Deno and the browser. The Seif Protocol facilitates secure message-based communication for distributed applications, with minimal network overhead.

WebSeif is in the Public Domain. It does not come with any kind of warranty, so use it at your own risk. For more information about the risks, refer to the Insecurity section at the end of this document.

The communicate using WebSeif, you must first have a __party__.

## Parties
Parties are created using the constructor function exported by party.js.

    import make_party from "./party.js";
    const alice = make_party(alice_store, transport, true);
    const bob = make_party(bob_store, transport, true);

The constructor takes four parameters:

- _store_: The store object to use. See the Stores section.
- _transport_: The transport object to use. See the Transports section.
- _autogenerate_keypair_: Whether the _store_'s keypair should be generated automatically, if missing. Defaults to false.
- _webcrypto_: The WebCrypto object. Defaults to `window.crypto`. On Node.js, pass the `webcrypto` member of the built-in "crypto" module.

An object with two methods, `connect` and `listen`, is returned.

### party.connect(_connect_options_) → _close_
A party can initiate connections with other parties. Messages may then be sent back and forth over a connection, until either party decides to close it.

    const close = alice.connect({
        petname: "Bob",
        on_message(connection, message) {
            if (message.greeting === "Hi, Alice!") {
                connection.status_send({greeting: "Hi, Bob!"});
            }
        }
    });

A _close_ function is returned, which can be called to close the existing connection or, if it isn't open yet, cancel connecting. The value passed to _close_ will be passed to the connection's `close` method as the _reason_.

The _connect_options_ parameter is an object with the following properties, of which only "petname" is required.

#### connect_options.petname
The party to connect to. A petname is a string used to retrieve an acquaintance from the party's store.

#### connect_options.on_open(_connection_)
Called when the connection is successfully created. It may be called again following a redirect. The _connection_ parameter is a connection object, described in the Connections section.

#### connect_options.on_message(_connection_, _message_)
Called each time a message is received over the connection. The _message_ parameter is a clone of the object passed to `connection.send` or `connection.status_send` by the other party.

#### connect_options.on_close(_connection_, _reason_)
Called when the connection is terminated. The exact situation depends on the values of _connection_ and _reason_:

| _connection_ | _reason_       | The situation
| ------------ | -------------- | --------------
| `undefined`  | object         | A connection could not be made.
| object       | `undefined`    | The connection was closed by the listening party.
| object       | `"redirected"` | The connection was redirected by the listening party.
| object       | object         | The connection failed.

In the event of a redirect, `on_close` is always called with the old connection prior to `on_open` being called with the new connection.

#### connect_options.hello_value
A value that is serialized to JSON, encrypted and sent as part of the handshake. This value becomes the _hello_value_ parameter of `listen_options.on_open`.

#### connect_options.connection_info
A value that is serialized to JSON and sent unencrypted as part of the handshake. This value becomes the _connection_info_ parameter of `listen_options.on_open`.

### party.listen(_listen_options_) → _stop_
A party can listen for connections from other parties.

    bob.listen({
        address: "12.34.56.78:9999",
        on_open(connection) {
            connection.status_send({greeting: "Hi, Alice!"});
        }
    });

A _stop_ function is returned, which can be called to close all the connections and stop listening. The value passed to _stop_ is passed to each connection's `close` method as the _reason_.

The _listen_options_ parameter is an object with the following properties, of which only `address` is required.

#### listen_options.address
The address to listen on. This value is passed verbatim to the `listen` method of the party's _transport_.

#### listen_options.on_open(_connection_, _public_key_, _hello_value_, _connection_info_)
Called each time a party successfully connects. The _public_key_ parameter is the verified public key of the connecting party, as a `CryptoKey` instance. The _hello_value_ and _connection_info_ parameters, if defined, are values sent by the connecting party during the handshake (see _connect_options_ above).

#### listen_options.on_message(_connection_, _message_)
Called each time a message is received from a connected party.

#### listen_options.on_close(_connection_, _reason_)
Called each time a connection is terminated. The exact situation depends on the values of _connection_ and _reason_:

| _connection_ | _reason_     | The situation
| ------------ | ------------ | --------------
| `undefined`  | object       | A Seif handshake failed.
| object       | `undefined`  | A connection was closed by the other party.
| object       | object       | An existing connection failed.

## Connections
A connection object is used to send messages over a connection, close a connection, or redirect a connection. Connection objects have the following methods:

### connection.status_send(_message_)
Sends a _message_ over the connection with no guarantee of delivery.

The _message_ parameter is an object containing zero or more properties. If a property's value is an `ArrayBuffer` instance, it is transmitted as binary data. Otherwise, the property's value is serialized with `JSON.stringify`.

    connection.status_send({
        my_json: [0, 1, 2],
        my_buffer: new Uint8Array([3, 4, 5]).buffer
    });

At the other end, the _message_ is reconstituted and passed to `on_message`.

### connection.send(_message_)
Like `status_send`, except that the receiving party is asked to acknowledge delivery of the _message_. A Promise is returned, which resolves upon acknowledgement. If something goes wrong, the Promise rejects. A rejection does not imply that the message was not delivered, just that it was not successfully acknowledged.

### connection.close(_reason_)
Closes the connection. Each pending Promise returned by `connection.send` will be rejected with the _reason_.

### connection.redirect(_petname_, _permanent_, _redirect_context_)
Redirects the connecting party to an acquaintance. The _petname_ parameter is a string identifying the acquaintance. If _permanent_ is `true`, the connecting party will forget about the listening party and connect to the acquaintance in the future. The _redirect_context_ will be sent by the connecting party as the _connection_info_ to the acquaintance, and is optional.

Only a listening party may redirect a connection.

## Stores
A __store__ is responsible for persisting a party's keypair, as well as its acquaintances. Each __acquaintance__ consists of the petname, address and public key of another Seif party. Let's look at an acquaintance of Alice.

    {
        petname: "Bob",
        address: "12.34.56.78:9999",
        public_key: <CryptoKey 04DE1CB534A4D2B2746A755DCDF22C...>
    }

The __petname__, "Bob", is chosen by Alice to be meaningful. The __address__ is global, so Alice can find the server that Bob is listening on. The __public key__ provides a way for Alice to authenticate Bob and negotiate a secure connection. If Alice is ever redirected by Bob, the address and public key will be updated, but the petname will remain the same.

WebSeif provides two categories of stores, each using different strategies for persistence.

The __filesystem stores__ read and write their state to a directory. They are used with Node.js or Deno. The private key is encrypted using a password.

    import make_store from "./store/node_filesystem_store.js";
    const bob_store = make_store("/path/to/directory", "p@ssw0rd");

Both filesystem store constructors take the following parameters:

- _directory_: The path to a directory where the store will read and write its files. The directory is created automatically if it does not exist.
- _password_: The password that encrypts the private key. This can be any string.
- _iterations_: The number of iterations used for encrypting and decrypting the private key. A larger value is more secure, but access to the private key will be slower. The default value is 50,000.

The __IndexedDB store__ reads and writes its state to `window.indexedDB`. It is intended for use in the browser. IndexedDB is used because it is capable of storing the private key as an opaque value. Upon retrieval, the private key can be used to negotiate Seif connections but the key's bits can not be read directly. Malicious code may be able to impersonate a party, but should not be able to exfiltrate their private key.

    import make_store from "./store/indexeddb_store.js";
    const alice_store = make_store("alice");

The IndexedDB store constructor takes a _name_ string, which is the name of an IndexedDB database. If the database does not exist, it is created automatically.

The following modules export store constructors:

- _store/node_filesystem_store.js_: Filesystem store for Node.js.
- _store/deno_filesystem_store.js_: Filesystem store for Deno.
- _store/indexeddb_store.js_: IndexedDB store for the browser.

### The store object
A store object has several methods, some of which take CryptoKey instances that can easily be made with the elliptic.js module. A store can be populated before it is used by a party.

#### store.write_keypair(_keypair_)
Persists the _keypair_, a `CryptoKeyPair`. If the store already has a keypair, it is overwritten. The returned Promise resolves once the keypair has been persisted.

It is crucial to maximise entropy during key generation, but WebCrypto provides no entropy guarantees. You may wish to generate the keypair using an external utility and then use this method to add it to the store yourself. Refer to the Insecurity section below.

#### store.read_keypair()
Returns a Promise that resolves to the store's `CryptoKeyPair`, or `undefined` if there isn't one.

#### store.add_acquaintance(_acquaintance_)
Adds a new acquaintance. The _acquaintance_ parameter is an object with three properties:

- `petname`: A string identifying the acquaintance. This can be any string.
- `address`: The value used by the transport to connect to the acquaintance.
- `public_key`: The public key of the acquaintance, as a `CryptoKey`.

If an acquaintance with the same petname already exists, it is replaced. The returned Promise resolves when done.

#### store.read_acquaintance(_petname_)
Returns a Promise that resolves to the matching acquaintance object, or `undefined` if it is not found.

#### store.remove_acquaintance(_petname_)
Removes the acquaintance with _petname_, if it is found. The returned Promise resolves when done.

## Transports
To quote the Seif Protocol specification,

> The protocol recommends that the secure session be established on top of a highly reliable, persistent network connection with ordered and error-checked delivery of the data stream.

Any network connection with these characteristics can be used as a transport for WebSeif. WebSeif comes with two kinds of transports: TCP and WebSockets.

Because WebSockets is built on top of HTTP, the performance benefits of the Seif Protocol are lost. However, browsers do not generally provide TCP capabilities, so it is offered as a fallback. In non-standard environments (such as browser extensions) you may be able to write your own transport that leverages a more efficient connection.

To make a transport object, import and call the relevant constructor function.

    import make_transport from "./transport/node_tcp_transport.js";
    const transport = make_transport();

The following modules export transport constructors:

- _transport/node_tcp_transport.js_: TCP transport for Node.js.
- _transport/deno_tcp_transport.js_: TCP transport for Deno.
- _transport/websockets_transport.js_: WebSockets transport for Deno and the browser.
- _transport/node_websockets_transport.js_: WebSockets transport for Node.js.

Instructions for writing your own transport can be found in protocol.js.

## Insecurity
I am not a security professional. I may have made terrible mistakes in writing WebSeif. Even if I have made no mistakes, WebSeif still has a known weakness: __weak entropy__. The original Seif Protocol implementation for Node.js [took great pains](https://github.com/paypal/seifrng) to acquire a high-quality source of random numbers, using the device's camera and microphone to maximize entropy. WebSeif relies on WebCrypto, which in turn relies on the operating system for randomness. If you do not have faith in WebCrypto, you can not have faith in WebSeif.

WebSeif's strength is that it is simple, portable and has no dependencies. If you find a weakness in WebSeif, please email me at james@diacono.com.au.
