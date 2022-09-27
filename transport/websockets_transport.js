// A WebSeif transport that uses the WebSockets protocol. Listening is only
// supported in Deno, but connecting is supported in both Deno and the
// browser.

// The address parameter of both the 'listen' and 'connect' functions must be a
// string of the form <protocol>://<host>:<port> where <protocol> is
// either "ws" or "wss".

// If 'listen' is called with a wss:// address, then the 'listen_tls_options'
// parameter, specifying the certificate and key, is passed on to
// Deno.listenTls.

/*jslint browser, deno */

function websockets_transport(listen_tls_options) {

    function connect(address, on_open, on_receive, on_close) {
        const socket = new WebSocket(address);
        const connection = Object.freeze({
            send(buffer) {
                socket.send(buffer);
            },
            close() {
                socket.close();
            }
        });
        socket.onopen = function () {
            return on_open(connection);
        };
        socket.onmessage = function (event) {
            const blob = event.data;
            return blob.arrayBuffer().then(
                function (buffer) {
                    if (on_close !== undefined) {
                        on_receive(connection, buffer);
                    }
                }
            );
        };
        socket.onclose = function () {
            if (on_close !== undefined) {
                on_close(connection);
            }
        };
        socket.onerror = function (event) {
            if (on_close !== undefined) {
                on_close(connection, event);
                on_close = undefined;
            }
        };
        return function close() {
            on_close = undefined;
            socket.close();
        };
    }

    function listen(address, on_open, on_receive, on_close) {
        let listener;
        let sockets = [];

        function wait_for_next_connection() {
            return listener.accept().then(
                function (tcp_connection) {
                    wait_for_next_connection();
                    return Deno.serveHttp(tcp_connection).nextRequest();
                }
            ).then(
                function ({request, respondWith}) {
                    const {socket, response} = Deno.upgradeWebSocket(request);
                    function unregister() {
                        sockets = sockets.filter(function (element) {
                            return element !== socket;
                        });
                    }
                    const connection = Object.freeze({
                        send(buffer) {

// The socket.onclose handler seems to be called some time after the socket is
// actually closed. This means that there is potential for an exception to be
// thrown here if 'send' is called on a connection which is thought to be open,
// but is actually closed.

// Until Deno fixes this issue, we silently drop the buffer if the socket is
// closed.

                            if (socket.readyState !== 3) {
                                socket.send(buffer);
                            }
                        },
                        close() {
                            if (sockets.includes(socket)) {
                                unregister();
                                socket.close();
                            }
                        }
                    });
                    socket.onopen = function () {
                        sockets.push(socket);
                        return on_open(connection);
                    };
                    socket.onmessage = function (event) {
                        return on_receive(connection, event.data);
                    };
                    function close_if_open(reason) {
                        if (
                            sockets.includes(socket)
                            && on_close !== undefined
                        ) {
                            unregister();
                            on_close(connection, reason);
                        }
                    }
                    socket.onclose = function () {
                        close_if_open();
                    };
                    socket.onerror = function (event) {
                        close_if_open(event);
                    };
                    return respondWith(response);
                }
            ).catch(
                function (ignore) {

// Either the response could not be sent, or the listener.close function has
// just been called.

                    return;
                }
            );
        }

        const {protocol, hostname, port} = new URL(address);
        const options = {
            hostname,
            port: parseInt(port, 10)
        };
        listener = (
            protocol === "wss:"
            ? Deno.listenTls(Object.assign({}, listen_tls_options, options))
            : Deno.listen(options)
        );
        wait_for_next_connection();
        return function stop() {
            if (on_close !== undefined) {
                listener.close();
                sockets.forEach(function (socket) {
                    socket.close();
                });
                on_close = undefined;
            }
        };
    }
    return Object.freeze({listen, connect});
}

export default Object.freeze(websockets_transport);
