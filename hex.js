// This module exports functions for encoding and decoding ArrayBuffers as
// hexadecimal strings.

function encode(buffer) {

// We can not use the Uint8Array's 'map' method, as it attempts to cast our hex
// pairs back to integers.

    return Array.prototype.map.call(
        new Uint8Array(buffer),
        function hexify(byte) {
            return byte.toString(16).padStart(2, "0");
        }
    ).join("").toUpperCase();
}

function decode(string) {

// Each byte is represented as two hexadecimal digits.

    let bytes = [];
    string.replace(/../g, function (pair) {
        bytes.push(parseInt(pair, 16));
    });
    return new Uint8Array(bytes).buffer;
}

export default Object.freeze({encode, decode});
