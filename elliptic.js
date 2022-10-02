// This module provides some elliptic curve cryptography operations used by
// WebSeif. It uses the NIST P-521 curve (secp521r1) as mandated by the Seif
// Protocol specification. A 521 bit elliptic curve key is said to be
// equivalent in strength to a 256 bit AES key.

// The exported constructor function takes as a single parameter the WebCrypto
// object. It returns an object containing the following methods:

//  generate_keypair()
//      Generates a new public/private keypair. The strength of the keypair is
//      limited by the system's available entropy. The returned Promise
//      resolves to a CryptoKeyPair object containing extractable keys.

//  import_public_key(buffer)
//  import_private_key(buffer, extractable)
//      Constructs a CryptoKey from an ArrayBuffer. The returned Promise
//      resolves to the CryptoKey instance. Private CryptoKeys will be
//      extractable only if the 'extractable' parameter is true.

//  export_public_key(public_key)
//  export_private_key(private_key)
//      Extracts a CryptoKey's raw bytes. The returned Promise resolves to an
//      ArrayBuffer. The 'public_key' and 'private_key' parameters are
//      CryptoKey instances.

/*jslint browser */

// Some WebCrypto implementations may not yet support 521-bit keys. For
// development, the keysize can be downgraded here to 256 or 384 bits.

const keysize = 521;
const curve = "P-" + keysize;

function make_elliptic(webcrypto = window.crypto) {

    function generate_keypair() {
        return webcrypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: curve
            },
            true,
            ["deriveKey", "deriveBits"]
        );
    }

    function import_public_key(buffer) {
        return webcrypto.subtle.importKey(
            "raw",
            buffer,
            {
                name: "ECDH",
                namedCurve: curve
            },
            true,
            []
        );
    }

    function import_private_key(buffer, extractable = false) {
        return webcrypto.subtle.importKey(
            "pkcs8",
            buffer,
            {
                name: "ECDH",
                namedCurve: curve
            },
            extractable,
            ["deriveKey", "deriveBits"]
        );
    }

    function export_public_key(public_key) {
        return webcrypto.subtle.exportKey("raw", public_key);
    }

    function export_private_key(private_key) {
        return webcrypto.subtle.exportKey("pkcs8", private_key);
    }

    return Object.freeze({
        generate_keypair,
        import_public_key,
        import_private_key,
        export_public_key,
        export_private_key
    });
}

export default Object.freeze(make_elliptic);
