// This module exports a function that makes WebSeif parties.

// A party has an identity (its keypair) and knows about other parties
// (its acquaintences). This information is persisted in its store. A party is
// also supplied with a transport that is used as a basis for communication
// with other parties.

/*jslint browser */

import make_elliptic from "./elliptic.js";
import protocol from "./protocol.js";

function do_nothing() {
    return;
}

function party(
    store,
    transport,
    autogenerate_keypair = false,
    webcrypto = window.crypto
) {
    const elliptic = make_elliptic(webcrypto);

    function get_keypair() {

// Read the keypair from the store, or if it is missing, generate a new one.

        return store.read_keypair().then(function (keypair) {
            if (keypair !== undefined) {
                return keypair;
            }
            if (!autogenerate_keypair) {
                throw new Error("Missing keypair.");
            }
            return elliptic.generate_keypair().then(function (fresh_keypair) {
                return store.write_keypair(fresh_keypair).then(function () {
                    return fresh_keypair;
                });
            });
        });
    }

    function get_acquaintance(petname) {

// Read an acquaintance from the store. Fail if the acquaintance is not found.

        return store.read_acquaintance(petname).then(function (acquaintance) {
            if (acquaintance === undefined) {
                throw new Error("Not acquainted with " + petname + ".");
            }
            return acquaintance;
        });
    }

    function connect({
        petname,
        on_open = do_nothing,
        on_message = do_nothing,
        on_close = do_nothing,
        hello_value,
        connection_info
    }) {
        let protocol_close;

        function destroy(reason) {
            if (protocol_close !== undefined) {
                protocol_close(reason);
                protocol_close = undefined;
            }
            if (on_close !== undefined) {
                on_close(undefined, reason);
                on_close = undefined;
            }
        }

        Promise.all([
            get_keypair(),
            get_acquaintance(petname)
        ]).then(function ([keypair, acquaintance]) {

// Proceed with the connection only if 'close' has not been called.

            if (on_close === undefined) {
                return;
            }
            protocol_close = protocol.connect({
                webcrypto,
                keypair,
                transport_connect: transport.connect,
                address: acquaintance.address,
                remote_public_key: acquaintance.public_key,
                hello_value,
                connection_info,
                on_open,
                on_message,
                on_close: function (
                    connection,
                    reason,
                    address,
                    public_key,
                    permanent
                ) {
                    if (public_key !== undefined) {

// The connection is currently being redirected. If this is a permanent
// redirect, update the store.

                        reason = "redirected";
                        if (permanent) {
                            store.add_acquaintance({
                                petname,
                                address,
                                public_key
                            }).catch(
                                destroy
                            );
                        }
                    }
                    return on_close(connection, reason);
                }
            });
        }).catch(
            destroy
        );
        return function close(reason) {
            on_close = undefined;
            return destroy(reason);
        };
    }

    function listen({
        address,
        on_open = do_nothing,
        on_message = do_nothing,
        on_close = do_nothing
    }) {
        let protocol_stop;
        let connection_weakmap = new WeakMap();

        function destroy(reason) {
            if (protocol_stop !== undefined) {
                protocol_stop(reason);
                protocol_stop = undefined;
            }
            if (on_close !== undefined) {
                on_close(undefined, reason);
                on_close = undefined;
            }
        }

        function swizzle(callback) {

// Connection objects provided by the protocol are not quite the same as those
// provided by the party. The difference is in the 'redirect' method, which
// takes an address instead of a petname.

// Our strategy is to modify 'on_open', 'on_message' and 'on_close', mapping the
// connection objects as necessary. A WeakMap is used to ensure a 1-to-1
// mapping between protocol and party connection objects.

            return function protocol_callback(protocol_connection, ...rest) {
                if (protocol_connection === undefined) {
                    return callback(undefined, ...rest);
                }
                let connection = connection_weakmap.get(protocol_connection);
                if (connection === undefined) {
                    connection = Object.freeze({
                        send: protocol_connection.send,
                        status_send: protocol_connection.status_send,
                        close: protocol_connection.close,
                        redirect(petname, permanent, redirect_context) {
                            get_acquaintance(
                                petname
                            ).then(function (acquaintance) {
                                protocol_connection.redirect(
                                    acquaintance.address,
                                    acquaintance.public_key,
                                    permanent,
                                    redirect_context
                                );
                            }).catch(
                                destroy
                            );
                        }
                    });
                    connection_weakmap.set(protocol_connection, connection);
                }
                return callback(connection, ...rest);
            };
        }

        get_keypair().then(function (keypair) {

// Proceed with listening only if 'stop' has not been called.

            if (on_close === undefined) {
                return;
            }
            protocol_stop = protocol.listen({
                webcrypto,
                keypair,
                transport_listen: transport.listen,
                address,
                on_open: swizzle(on_open),
                on_message: swizzle(on_message),
                on_close: swizzle(on_close)
            });
        }).catch(
            destroy
        );
        return function stop(reason) {
            on_close = undefined;
            return destroy(reason);
        };
    }
    return Object.freeze({connect, listen});
}

export default Object.freeze(party);
