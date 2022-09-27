// A WebSeif transport that uses Deno's TCP capabilities.

// The address parameter of both the 'listen' and 'connect' functions must be a
// string of the form <ip_address>:<port>.

/*jslint deno */

const chunk_size = 8192;

function parse_address(address) {
    const [host, port] = address.split(":");
    return {
        host,
        port: parseInt(port, 10)
    };
}

function connect(address, on_open, on_receive, on_close) {
    let connection;
    Deno.connect(
        parse_address(address)
    ).then(
        function (socket) {
            function fail(reason) {
                if (on_close !== undefined) {
                    socket.close();
                    on_close(connection, reason);
                    on_close = undefined;
                }
            }
            connection = Object.freeze({
                send(buffer) {
                    socket.write(new Uint8Array(buffer)).catch(fail);
                },
                close() {
                    if (on_close !== undefined) {
                        socket.close();
                        on_close = undefined;
                    }
                }
            });
            (function wait_for_next_chunk() {
                const scratch = new Uint8Array(chunk_size);
                return socket.read(scratch).then(function (nr_bytes) {
                    if (nr_bytes) {
                        on_receive(
                            connection,
                            scratch.slice(0, nr_bytes).buffer
                        );
                        wait_for_next_chunk();
                    } else {
                        on_close(connection);
                        on_close = undefined;
                    }
                }).catch(
                    fail
                );
            }());
            return on_open(connection);
        }
    ).catch(function (reason) {
        on_close(undefined, reason);
    });
    return function close() {
        if (on_close !== undefined) {
            if (connection !== undefined) {
                connection.close();
            }
            on_close = undefined;
        }
    };
}

function listen(address, on_open, on_receive, on_close) {
    let listener = Deno.listen(parse_address(address));
    let registrations = [];

    function register(socket) {
        let connection;
        function unregister() {
            registrations = registrations.filter(function (value) {
                return value !== connection;
            });
        }
        function fail(reason) {
            if (registrations.includes(connection)) {
                socket.close();
                on_close(connection, reason);
                unregister();
            }
        }
        connection = Object.freeze({
            send(buffer) {
                socket.write(new Uint8Array(buffer)).catch(fail);
            },
            close() {
                if (registrations.includes(connection)) {
                    socket.close();
                    unregister();
                }
            }
        });
        registrations.push(connection);
        (function wait_for_next_chunk() {
            const scratch = new Uint8Array(chunk_size);
            return socket.read(scratch).then(function (nr_bytes) {
                if (nr_bytes) {
                    on_receive(
                        connection,
                        scratch.slice(0, nr_bytes).buffer
                    );
                    wait_for_next_chunk();
                } else {
                    on_close(connection);
                    unregister();
                }
            }).catch(function () {

// The connection closed during the read.

                return fail();
            });
        }());
        return on_open(connection);
    }

    (function wait_for_next_socket() {
        return listener.accept().then(
            function (socket) {
                wait_for_next_socket();
                register(socket);
            }
        ).catch(
            function (ignore) {

// The listener.close function has just been called. Calling listener.close only
// prevents the listener from accepting new connections. Any open sockets must
// be closed explicitly.

                return registrations.forEach(function (connection) {
                    connection.close();
                });
            }
        );
    }());
    return function stop() {

// Subsequent calls to listener.close throw an exception, but 'stop' is not so
// strict.

        if (listener !== undefined) {
            listener.close();
            listener = undefined;
        }
    };
}

function deno_tcp_transport() {
    return Object.freeze({listen, connect});
}

export default Object.freeze(deno_tcp_transport);
