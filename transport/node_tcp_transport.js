// A WebSeif transport that uses Node.js's TCP capabilities.

// The address parameter of both the 'listen' and 'connect' functions must be a
// string of the form <ip_address>:<port>.

/*jslint node */

import net from "node:net";

function parse_address(address) {
    const [host, port] = address.split(":");
    return {
        host,
        port: parseInt(port, 10)
    };
}

function connect(address, on_open, on_receive, on_close) {
    const {port, host} = parse_address(address);
    let connection;
    let socket = net.connect(
        port,
        host,
        function on_connected(reason) {
            if (reason) {
                return on_close(undefined, reason);
            }
            function fail(reason) {
                if (on_close !== undefined) {
                    socket.destroy();
                    on_close(connection, reason);
                    on_close = undefined;
                }
            }
            connection = Object.freeze({
                send(buffer) {
                    socket.write(new Uint8Array(buffer), function (reason) {
                        if (reason) {
                            return fail(reason);
                        }
                    });
                },
                close() {
                    if (on_close !== undefined) {
                        socket.destroy();
                        on_close = undefined;
                    }
                }
            });
            socket.on("error", fail);
            socket.on("data", function (chunk) {
                on_receive(connection, chunk.buffer);
            });
            socket.on("end", function () {
                on_close(connection);
                on_close = undefined;
            });
            return on_open(connection);
        }
    );
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
    let registrations = [];
    const server = net.createServer(function on_socket_connected(socket) {
        let connection;

        function unregister() {
            registrations = registrations.filter(function (value) {
                return value !== connection;
            });
        }

        function fail(reason) {
            if (registrations.includes(connection)) {
                socket.destroy();
                on_close(connection, reason);
                unregister();
            }
        }

        connection = Object.freeze({
            send(buffer) {
                socket.write(new Uint8Array(buffer), function (reason) {
                    if (reason) {
                        return fail(reason);
                    }
                });
            },
            close() {
                if (registrations.includes(connection)) {
                    socket.destroy();
                    unregister();
                }
            }
        });
        registrations.push(connection);
        socket.on("error", fail);
        socket.on("data", function (chunk) {
            on_receive(connection, chunk.buffer);
        });
        socket.on("end", function () {
            on_close(connection);
        });
        return on_open(connection);
    });
    const {port, host} = parse_address(address);
    server.listen(port, host);
    return function stop() {
        server.close();

// Calling server.close only prevents the server from accepting new connections.
// Any open sockets must be closed explicitly.

        return registrations.forEach(function (connection) {
            connection.close();
        });
    };
}

function node_tcp_transport() {
    return Object.freeze({listen, connect});
}

export default Object.freeze(node_tcp_transport);
