// This module implements the Seif Protocol Version 0 in two functions,
// 'connect' and 'listen'. These functions are similar to a party's methods, but
// they do not use a store.

// This implementation deviates slightly from the specification, which contains
// a mistake:

//      Seif uses AES-256 in GCM mode to encrypt the communication stream. Since
//      the channel will look exactly the same for an identical stream, the
//      protocol modulates the channel with a random stream of numbers. The
//      random stream is generated using Xorshift+ Random Number Generator
//      (RNG).

// Wrong! Two identical streams of plaintext will never yield the same stream of
// ciphertext in GCM mode, unless an IV were reused. But reuse of an IV
// jeopardises the secrecy of the key, and is easy to avoid because a unique
// symmetric key is negotiated for each Seif session. In order to simplify
// implementation, WebSeif omits this modulation.

// ABOUT TRANSPORTS

// The 'transport_connect' and 'transport_listen' parameters are functions
// providing an ordered, reliable and persistent connection for binary data.
// Both functions take these four parameters:

//  address
//      The address to connect or listen on. Different kinds of transports may
//      format their address differently.

//  on_open(connection)
//      A function that is called when a connection is opened. The 'connection'
//      parameter is an object with two methods:

//          connection.send(chunk)
//              Send a chunk of binary data down the connection. The 'chunk' is
//              an ArrayBuffer.

//          connection.close()
//              Close the connection.

//  on_receive(connection, chunk)
//      A function that is called with each 'chunk' that arrives over a
//      connection. The chunk is an ArrayBuffer.

//  on_close(connection, reason)
//      A function that is called when a connection is closed. If the connection
//      failed, the 'reason' parameter should explain why.

// The 'transport_connect' function returns a 'close' function, which closes the
// connection. The 'transport_listen' funtion returns a 'stop' function, which
// closes every connection and stops listening. Once a transport is closed or
// stopped, the 'on_open', 'on_receive' and 'on_close' callbacks must not be
// called again.

/*jslint browser, bitwise */

import hex from "./hex.js";
import make_elliptic from "./elliptic.js";

function concat_buffers(a, b) {
    let concatenated = new ArrayBuffer(a.byteLength + b.byteLength);
    let array = new Uint8Array(concatenated);
    array.set(new Uint8Array(a), 0);
    array.set(new Uint8Array(b), a.byteLength);
    return concatenated;
}

function encode_json(value) {
    return new TextEncoder().encode(JSON.stringify(value)).buffer;
}

function decode_json(buffer) {
    return JSON.parse(new TextDecoder().decode(buffer));
}

function iv(fixed_field) {

// The 'iv' function returns a generator that produces sequential 96-bit
// initialization vectors, suitable for use with AES-GCM. The AES-GCM
// specification states that IVs must never be reused for a given key,
// otherwise it's game over.

// Exactly two parties share a key. If each party maintains its own counter,
// then we just need to make sure they never encrypt anything using the same
// IV. This is accomplished by concatenating the counter with the 'fixed_field',
// which should be either 0 (for messages originating from initiating parties)
// or 1 (for messages destined for initiating parties).

    let counter = 0;
    return function iv_generator() {
        if (counter > Number.MAX_SAFE_INTEGER) {
            throw new Error("Counter exhausted.");
        }
        const buffer = new ArrayBuffer(12);

// Use a DataView to ensure a uniform endianness within the IVs, regardless of
// the machine's architecture.

        const view = new DataView(buffer);
        view.setUint32(0, fixed_field);
        view.setUint32(4, Math.floor(counter / (2 ** 32)));
        view.setUint32(8, counter % (2 ** 32));
        counter += 1;
        return buffer;
    };
}

function make_record(identifier, message, encrypt_buffer) {

// The 'make_record' function constructs a Seif record, consisting of a binary
// length field, and identifier and any number of blobs. The returned Promise
// resolves to an ArrayBuffer, intended to be put on the wire.

// Properties found on the 'identifier' object are included in the record's
// identifier.

// The 'message' parameter is an object containing the values for the record's
// blobs. The name of each property is the blob ID, and each value is either an
// ArrayBuffer or a JSON-encodable value.

// The 'encrypt_buffer' function takes a plaintext ArrayBuffer and returns
// Promise that resolves to the ciphertext ArrayBuffer.

    if (typeof message !== "object") {
        throw new Error("Bad message.");
    }
    identifier.blobs = [];
    let blob_buffers = Object.keys(
        message
    ).filter(function (id) {
        return message[id] !== undefined;
    }).map(function (id) {
        let buffer;
        let blob_type;

// Determine whether the blob should be transmitted as binary or structured
// data.

        if (message[id]?.constructor === ArrayBuffer) {
            buffer = message[id];
            blob_type = "Buffer";
        } else {
            buffer = encode_json(message[id]);
            blob_type = "JSON";
        }

// Include information about the blob in the identifier, which is sent ahead of
// the blobs. We include the length of the plaintext blob, rather than the
// length of the ciphertext. This is because the blob buffers must be encrypted
// after the identifier, due to the irreversible nature of AES-GCM.

        identifier.blobs.push({
            id,
            type: blob_type,
            length: buffer.byteLength
        });
        return buffer;
    });

// Serialize and encrypt the identifier, then each of the blob buffers.

    const identifier_buffer = encode_json(identifier);
    if (identifier_buffer.byteLength >= 2 ** 16) {
        throw new Error("Identifier too big.");
    }
    return Promise.all(
        [identifier_buffer, ...blob_buffers].map(encrypt_buffer)
    ).then(function (encrypted_buffers) {

// The record begins with the identifier length field, which is a big-endian
// integer sent in the clear.

        let length_buffer = new ArrayBuffer(2);
        let length_view = new DataView(length_buffer);
        length_view.setUint16(0, encrypted_buffers[0].byteLength);

// Finally, we stuff all of the bytes into one big buffer and return that as the
// record.

        const record_buffers = [length_buffer, ...encrypted_buffers];
        return record_buffers.reduce(concat_buffers);
    });
}

function make_aes(webcrypto = window.crypto) {

// The symmetric encryption operations. We use the 256 bit AES-GCM cipher, as
// per the Seif Protocol specification.

// Given the WebCrypto object, the 'make_aes' function returns an object
// containing several methods:

//  generate_key()
//      Generates a new symmetric key. The returned Promise resolves to a
//      CryptoKey.

//  import_key(buffer)
//      Interprets an ArrayBuffer as a symmetric key. The returned Promise
//      resolves to the CryptoKey instance.

//  encrypt(plaintext, key, iv)
//      Encrypt a plaintext ArrayBuffer with a CryptoKey and an initialization
//      vector. The returned Promise resolves to the ciphertext ArrayBuffer.

//  decrypt(ciphertext, key, iv)
//      Decrypt a ciphertext ArrayBuffer with the same CryptoKey and
//      initialization vector that were used to encrypt it. The returned
//      Promise resolves to the plaintext ArrayBuffer.

    return Object.freeze({
        generate_key() {
            return webcrypto.subtle.generateKey(
                {name: "AES-GCM", length: 256},
                true,
                ["encrypt", "decrypt"]
            );
        },
        import_key(buffer) {
            return webcrypto.subtle.importKey(
                "raw",
                buffer,
                {name: "AES-GCM"},
                false,
                ["encrypt", "decrypt"]
            );
        },
        encrypt(plaintext, key, iv) {
            return webcrypto.subtle.encrypt(
                {name: "AES-GCM", iv},
                key,
                plaintext
            );
        },
        decrypt(ciphertext, key, iv) {
            return webcrypto.subtle.decrypt(
                {name: "AES-GCM", iv},
                key,
                ciphertext
            );
        }
    });
}

function hello(
    crypto,
    initiator_public_key,
    receiver_public_key,
    encryption_iv,
    connection_info,
    hello_value
) {

// The 'hello' function produces some values that are required to initiate a
// Seif handshake. It takes the following parameters:

//      crypto: The WebCrypto object.
//      initiator_public_key: The public key of the initiator, as a CryptoKey.
//      receiver_public_key: The public key of the receiver, as a CryptoKey.
//      encryption_iv: An IV to be used for a single encryption.
//      connection_info: An optional JSON-serializable value, sent in the clear.
//      hello_value: A JSON-serializable value to include with the hello data.

// The returned Promise resolves to an object with these properties:

//      hello_record: The Hello record as an ArrayBuffer.
//      handshake_key: The generated handshake key, as a CryptoKey.

// We begin by generating a handshake key, which is then encrypted with the
// receivers public key. Concurrently, the initiator's public key is added to
// the "hello data", which is then encrypted with the handshake key.

    const aes = make_aes(crypto);
    const elliptic = make_elliptic(crypto);
    return Promise.all([
        aes.generate_key(),
        elliptic.export_public_key(initiator_public_key)
    ]).then(function ([handshake_key, initiator_public_key_buffer]) {
        return Promise.all([
            elliptic.export_public_key(
                handshake_key
            ).then(function (handshake_key_buffer) {
                return elliptic.encrypt(
                    handshake_key_buffer,
                    receiver_public_key
                );
            }),
            aes.encrypt(
                encode_json({
                    initiatorPublicKey: hex.encode(initiator_public_key_buffer),
                    value: hello_value
                }),
                handshake_key,
                encryption_iv
            )
        ]).then(function ([
            encrypted_handshake_key_buffer,
            encrypted_hello_data_buffer
        ]) {
            return make_record(
                {type: "Hello"},
                {
                    version: 0,
                    handshakeKey: encrypted_handshake_key_buffer,
                    helloData: encrypted_hello_data_buffer,
                    connectionInfo: connection_info
                },
                function encrypt(buffer) {

// The sensitive parts of the Hello record have already been encrypted, so we
// can skip this step.

                    return buffer;
                }
            );
        }).then(function (hello_record) {
            return {hello_record, handshake_key};
        });
    });
}

function auth_hello(
    crypto,
    hello_message,
    private_key,
    next_decryption_iv,
    next_encryption_iv
) {

// The 'auth_hello' function produces some values that are required to complete
// a Seif handshake. It takes the following parameters:

//      crypto: The WebCrypto object.
//      hello_message: The Hello message as an object.
//      private_key: The listener's private key, as a CryptoKey.
//      next_decryption_iv: An IV generator for decryption.
//      next_encryption_iv: An IV generator for encryption.

// The returned Promise resolves to an object with the following properties:

//      auth_hello_record: An ArrayBuffer containing the AuthHello record.
//      session_key: The negotiated session key, as a CryptoKey.
//      hello_value: The value sent with the Hello message.

    if (hello_message.version !== 0) {
        return Promise.reject(new Error("Unsupported Seif version."));
    }

// The Hello message contains the handshake key encrypted with our public key,
// and the initiator's public key encrypted with the handshake key. Decrypt
// everything, and if it looks good, construct a response containing the session
// key encrypted with the initiator's public key.

    const aes = make_aes(crypto);
    const elliptic = make_elliptic(crypto);
    let hello_value;
    let session_key;
    let initiator_public_key;
    return elliptic.decrypt(
        hello_message.handshakeKey,
        private_key
    ).then(
        aes.import_key
    ).then(function (handshake_key) {
        return aes.decrypt(
            hello_message.helloData,
            handshake_key,
            next_decryption_iv()
        ).then(function (hello_buffer) {
            const {initiatorPublicKey, value} = decode_json(hello_buffer);
            hello_value = value;

// Generate the session key, and meanwhile import the initiator's public key so
// that it can be used to encrypt the session key.

            return Promise.all([
                aes.generate_key(),
                elliptic.import_public_key(hex.decode(initiatorPublicKey))
            ]);
        }).then(function ([the_session_key, the_initiator_public_key]) {
            session_key = the_session_key;
            initiator_public_key = the_initiator_public_key;
            return elliptic.export_public_key(
                the_session_key
            ).then(function (session_key_buffer) {

// Encrypt the session key with the initiator's public key.

                return elliptic.encrypt(
                    session_key_buffer,
                    the_initiator_public_key
                );
            });
        }).then(function (encrypted_session_key) {

// Construct the AuthHello record.

            return make_record(
                {type: "AuthHello"},
                {sessionKey: encrypted_session_key},
                function encrypt(buffer) {
                    return aes.encrypt(
                        buffer,
                        handshake_key,
                        next_encryption_iv()
                    );
                }
            );
        });
    }).then(function (auth_hello_record) {
        return {
            auth_hello_record,
            session_key,
            hello_value,
            initiator_public_key
        };
    });
}

function make_consumer(
    crypto,                          // The WebCrypto object.
    transport_connection,            // The underlying transport connection.
    private_key,                     // Our private key.
    next_encryption_iv,              // Returns the next encryption IV.
    next_decryption_iv,              // Returns the next decryption IV.
    on_open,                         // Called with each new Seif connection.
    on_message,                      // Called with each new Seif message.
    on_close,                        // Called when a Seif connection is closed.
    on_redirect,                     // Called with Seif redirection info.
    handshake_key                    // The symmetric key used during handshake.
) {

// A "consumer" does most of the work in setting up and communicating over a
// Seif connection. It is complex because it must tease messages out of an
// incoming byte stream.

    let session_key;                 // The symmetric key, to encrypt traffic.
    let seif_connection;             // The interface for the Seif connection.

// Incoming state. Bytes are added to the end of a 'buffer', and periodically
// consumed from the start (unless 'busy' is true).

    let buffer = new ArrayBuffer(0); // The incoming bytes left to process.
    let busy = false;                // Busy decrypting.
    let identifier;                  // The parsed Seif record identifier.
    let identifier_length;           // The identifier's length in bytes.
    let blob_buffers = [];           // Decrypted blob buffers.

// Outgoing state. Tasks are then'd to a 'queue', which is a Promise that
// resolves whenever the queue is emptied.

    let queue = Promise.resolve();   // Outgoing message queue.
    let pending_acks = [];           // Pending acknowledgement callbacks.

    const aes = make_aes(crypto);
    const elliptic = make_elliptic(crypto);

    function encrypt(plain) {
        return aes.encrypt(
            plain,
            session_key,
            next_encryption_iv()
        );
    }

    function decrypt(cipher) {
        return aes.decrypt(
            cipher,
            session_key ?? handshake_key,
            next_decryption_iv()
        );
    }

    function destroy(reason, situation_option) {

// The value of 'situation_option' may be one of three values:

//      undefined: There was a problem.
//      true: The connection is no longer required.
//      false: The connection has already been closed.

        if (transport_connection !== undefined) {

// Inform the waiting senders that no more acknowledgements are forthcoming.

            pending_acks.forEach(function (pending) {
                pending.reject(reason);
            });
            if (situation_option !== false) {
                transport_connection.close();
            }
            if (situation_option === undefined) {
                on_close(seif_connection, reason);
            }
            transport_connection = undefined;
        }
    }

    function enqueue(callback) {

// Adds a callback function to the outoing message queue. The callback should
// return a Promise that resolves to a record.

        queue = queue.then(function () {
            if (transport_connection !== undefined) {
                return callback().then(function (record) {
                    if (transport_connection !== undefined) {
                        transport_connection.send(record);
                    }
                });
            }
        }).catch(
            destroy
        );
    }

    function redirect(address, public_key, permanent, redirect_context) {

// Redirect the initiating party to another listening party.

        enqueue(function () {
            return elliptic.export_public_key(
                public_key
            ).then(function (public_key_buffer) {
                return make_record(
                    {type: "Redirect"},
                    {
                        address,
                        publicKey: hex.encode(public_key_buffer),
                        permanent,
                        redirectContext: redirect_context
                    },
                    encrypt
                );
            });
        });
    }

    function send(message) {

// Send a message with the expectation that its delivery will be acknowledged.

        return new Promise(function (resolve, reject) {
            return enqueue(function () {
                pending_acks.push({resolve, reject});
                return make_record({type: "Send"}, message, encrypt);
            });
        });
    }

    function status_send(message) {

// Send a message with no delivery acknowledgement.

        enqueue(function () {
            return make_record({type: "StatusSend"}, message, encrypt);
        });
    }

    function take(nr_bytes) {

// Remove some bytes from the start of the incoming buffer and return them.

        const bytes = buffer.slice(0, nr_bytes);
        buffer = buffer.slice(nr_bytes);
        return bytes;
    }

    function receive() {

// The identifier and blobs of an incoming record are available. Parse them into
// a message and reset the incoming state, ready for the next record.

        let {type} = identifier;
        let message = {};
        try {
            identifier.blobs.forEach(function (blob, blob_nr) {
                message[blob.id] = (
                    blob.type === "JSON"
                    ? decode_json(blob_buffers[blob_nr])
                    : blob_buffers[blob_nr]
                );
            });
        } catch (exception) {
            return destroy(exception);
        }
        identifier = undefined;
        identifier_length = undefined;
        blob_buffers = [];

// Handle the message. Is the handshake still in progress?

        if (session_key === undefined) {
            if (handshake_key === undefined) {

// We have received the Hello message. Respond with an AuthHello message.

                busy = true;
                return auth_hello(
                    crypto,
                    message,
                    private_key,

// Our IV generators are used for both the session and handshake keys. This is
// not a problem, because they remain unique for each key.

                    next_decryption_iv,
                    next_encryption_iv
                ).then(function (result) {
                    if (transport_connection === undefined) {
                        return;
                    }
                    transport_connection.send(result.auth_hello_record);
                    session_key = result.session_key;
                    seif_connection = Object.freeze({
                        send,
                        status_send,
                        redirect,
                        close(reason) {
                            return destroy(reason, true);
                        }
                    });
                    on_open(
                        seif_connection,
                        result.initiator_public_key,
                        result.hello_value,
                        message.connectionInfo
                    );
                    busy = false;
                }).catch(
                    destroy
                );
            }

// We have received the AuthHello message. Decrypt the session key within.

            busy = true;
            return elliptic.decrypt(
                message.sessionKey,
                private_key
            ).then(
                aes.import_key
            ).then(function (the_session_key) {
                session_key = the_session_key;
                seif_connection = Object.freeze({
                    send,
                    status_send,
                    close(reason) {
                        return destroy(reason, true);
                    }
                });
                on_open(seif_connection);
                busy = false;
            }).catch(
                destroy
            );
        }

// The message is not part of the handshake. Handle it with respect to its type.

        if (type === "Redirect") {
            busy = true;
            return elliptic.import_public_key(
                hex.decode(message.publicKey)
            ).then(function (public_key) {
                on_redirect(
                    seif_connection,
                    message.address,
                    public_key,
                    message.permanent,
                    message.redirectContext
                );
                busy = false;
            }).catch(
                destroy
            );
        }
        if (type === "Send") {
            enqueue(function () {
                return make_record({type: "Acknowledge"}, {}, encrypt);
            });
            on_message(seif_connection, message);
            return consume();
        }
        if (type === "Acknowledge") {
            const pending = pending_acks.shift();
            if (pending === undefined) {
                return destroy("Unexpected acknowledgement.");
            }
            pending.resolve();
            return consume();
        }
        if (type === "StatusSend") {
            on_message(seif_connection, message);
            return consume();
        }
        return destroy("Unrecognized message type.");
    }

    function consume() {

// The 'consume' function processes incoming messages as they become available.
// It recurses, working it way thru the 'buffer' until it needs to wait for more
// bytes.

        if (transport_connection === undefined || busy) {
            return;
        }
        if (identifier === undefined) {

// We are at the start of a record, which encodes a Seif message. A record
// is segmented like [identifier_length, identifier, ...blob_buffers].

            if (identifier_length === undefined) {
                if (buffer.byteLength < 2) {
                    return;
                }

// Read and unmask the first two bytes to get the length of the identifier. The
// Seif specification does not specify endianness, so big-endian it is.

                identifier_length = new DataView(take(2)).getUint16(0);
            }
            if (buffer.byteLength < identifier_length) {
                return;
            }
            if (session_key === undefined && handshake_key === undefined) {

// The Hello record is unique in that it sends its identifier in the clear.

                try {
                    identifier = decode_json(take(identifier_length));
                } catch (exception) {
                    return destroy(exception);
                }
                return consume();
            }

// Decrypt and parse the identifier.

            busy = true;
            return decrypt(take(identifier_length)).then(
                function (identifier_buffer) {
                    identifier = decode_json(identifier_buffer);
                    busy = false;
                    return consume();
                }
            ).catch(
                destroy
            );
        }

// Now for the blobs.

        if (blob_buffers.length < identifier.blobs.length) {

// Decrypt the next blob, if it has arrived.

            const blob = identifier.blobs[blob_buffers.length];
            if (session_key === undefined && handshake_key === undefined) {

// We are receving a Hello record, which arrives in the clear.

                if (buffer.byteLength < blob.length) {
                    return;
                }
                blob_buffers.push(take(blob.length));
                return consume();
            }

// A ciphertext is always 16 bytes longer than a plaintext, due to the AES-GCM
// authentication tag.

            const ciphertext_length = blob.length + 16;
            if (buffer.byteLength < ciphertext_length) {
                return;
            }
            busy = true;
            return decrypt(
                take(ciphertext_length)
            ).then(function (decrypted_buffer) {
                blob_buffers.push(decrypted_buffer);
                busy = false;
                return consume();
            }).catch(
                destroy
            );
        }

// The record's identifier and all of its blobs have now arrived and been
// decrypted. Parse it into a message.

        return receive();
    }

    return Object.freeze({
        consume(chunk) {
            buffer = concat_buffers(buffer, chunk);
            consume();
        },
        get_seif_connection() {
            return seif_connection;
        },
        transport_closed(reason) {
            destroy(reason, false);
        }
    });
}

function listen({
    webcrypto,
    keypair,
    transport_listen,
    address,
    on_open,
    on_message,
    on_close
}) {
    let consumer_map = new Map();

    function on_transport_open(transport_connection) {
        consumer_map.set(
            transport_connection,
            make_consumer(
                webcrypto,
                transport_connection,
                keypair.privateKey,
                iv(1),
                iv(0),
                on_open,
                on_message,
                function on_consumer_close(...args) {
                    consumer_map.delete(transport_connection);
                    return on_close(...args);
                }
            )
        );
    }

    function on_transport_receive(transport_connection, chunk) {
        const consumer = consumer_map.get(transport_connection);
        if (consumer !== undefined) {
            return consumer.consume(chunk);
        }
    }

    function on_transport_close(transport_connection, reason) {
        const consumer = consumer_map.get(transport_connection);
        if (consumer !== undefined) {
            consumer.transport_closed(reason);
            consumer_map.delete(transport_connection);
            return on_close(consumer.get_seif_connection(), reason);
        }
    }

    const stop_transport = transport_listen(
        address,
        on_transport_open,
        on_transport_receive,
        on_transport_close
    );
    return function stop(reason) {
        stop_transport();
        consumer_map.forEach(function (consumer) {
            consumer.transport_closed(reason);
        });
        consumer_map = new Map();
    };
}

function connect({
    webcrypto,
    keypair,
    transport_connect,
    address,
    remote_public_key,
    hello_value,
    connection_info,
    on_open,
    on_message,
    on_close
}) {
    let transport_connection;
    let consumer;
    let close_transport;
    let on_redirect;

    function on_transport_receive(ignore, chunk) {
        if (consumer !== undefined) {
            return consumer.consume(chunk);
        }
        close_transport();
        return on_close(undefined, "Unexpected chunk.");
    }

    function on_transport_close(ignore, reason) {
        transport_connection = undefined;
        if (consumer !== undefined) {
            consumer.transport_closed(reason);
            return on_close(consumer.get_seif_connection(), reason);
        }
        return on_close(undefined, reason);
    }

    function on_transport_open(the_transport_connection) {
        transport_connection = the_transport_connection;

// Initiate the handshake.

        const next_encryption_iv = iv(0);
        const next_decryption_iv = iv(1);
        return hello(
            webcrypto,
            keypair.publicKey,
            remote_public_key,
            next_encryption_iv(),
            connection_info,
            hello_value
        ).then(
            function ({hello_record, handshake_key}) {
                if (transport_connection === undefined) {
                    return;
                }
                consumer = make_consumer(
                    webcrypto,
                    transport_connection,
                    keypair.privateKey,
                    next_encryption_iv,
                    next_decryption_iv,
                    on_open,
                    on_message,
                    function on_consumer_close(...args) {
                        transport_connection = undefined;
                        return on_close(...args);
                    },
                    on_redirect,
                    handshake_key
                );
                transport_connection.send(hello_record);
            }
        ).catch(
            function (reason) {
                close_transport();
                on_close(undefined, reason);
            }
        );
    }

    on_redirect = function (
        connection,
        address,
        public_key,
        permanent,
        redirect_context
    ) {

// We have been redirected. Close the current connection and connect to the
// specified party instead.

        close_transport();
        consumer.transport_closed("Redirected.");
        consumer = undefined;
        transport_connection = undefined;
        on_close(
            connection,
            undefined,
            address,
            public_key,
            permanent,
            redirect_context
        );

// Update some of the parameters and start over.

        remote_public_key = public_key;
        connection_info = redirect_context;
        close_transport = transport_connect(
            address,
            on_transport_open,
            on_transport_receive,
            on_transport_close
        );
    };

    close_transport = transport_connect(
        address,
        on_transport_open,
        on_transport_receive,
        on_transport_close
    );
    return function close(reason) {
        transport_connection = undefined;
        if (consumer !== undefined) {
            consumer.transport_closed(reason);
        }
        return close_transport();
    };
}

export default Object.freeze({listen, connect});
