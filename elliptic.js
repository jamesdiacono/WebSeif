// This module provides some elliptic curve cryptography operations used by
// WebSeif. It uses the NIST P-521 curve (secp521r1) as mandated by the Seif
// Protocol specification. A 521 bit elliptic curve key is said to be
// equivalent in strength to a 256 bit AES key.

// An object with the following methods is exported:

//  generate_keypair()
//      Generates a new public/private keypair. The strength of the keypair is
//      limited by the system's available entropy. The returned Promise
//      resolves to a CryptoKeyPair object containing extractable keys.

//  import_public_key(bytes)
//  import_private_key(bytes, extractable)
//      Constructs a CryptoKey from a Uint8Array. The returned Promise
//      resolves to the CryptoKey instance. Private CryptoKeys will be
//      extractable only if the 'extractable' parameter is true.

//  export_public_key(public_key)
//  export_private_key(private_key)
//      Extracts a CryptoKey's raw bytes. The returned Promise resolves to a
//      Uint8Array. The 'public_key' and 'private_key' parameters are
//      CryptoKey instances.

/*jslint browser */

// Some WebCrypto implementations may not yet support 521-bit keys. For
// development, the keysize can be downgraded here to 256 or 384 bits.

const keysize = 521;
const curve = "P-" + keysize;

function generate_keypair() {
    return crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: curve
        },
        true,
        ["deriveKey", "deriveBits"]
    );
}

function import_public_key(bytes) {
    return crypto.subtle.importKey(
        "raw",
        bytes,
        {
            name: "ECDH",
            namedCurve: curve
        },
        true,
        []
    );
}

function import_private_key(bytes, extractable = false) {
    return crypto.subtle.importKey(
        "pkcs8",
        bytes,
        {
            name: "ECDH",
            namedCurve: curve
        },
        extractable,
        ["deriveKey", "deriveBits"]
    );
}

function arrayify(buffer) {
    return new Uint8Array(buffer);
}

function export_public_key(public_key) {
    return crypto.subtle.exportKey("raw", public_key).then(arrayify);
}

function export_private_key(private_key) {
    return crypto.subtle.exportKey("pkcs8", private_key).then(arrayify);
}

if (import.meta.main) {
    generate_keypair().then(function ({publicKey, privateKey}) {
        return Promise.all([
            export_public_key(publicKey),
            export_private_key(privateKey)
        ]);
    }).then(function ([public_key_bytes, private_key_bytes]) {
        return Promise.all([
            import_public_key(public_key_bytes),
            import_private_key(private_key_bytes),
            import_private_key(private_key_bytes, true)
        ]);
    }).then(function ([public_key, private_key, extractable_private_key]) {
        if (
            public_key.type !== "public"
            || !public_key.extractable
            || private_key.type !== "private"
            || private_key.extractable
            || extractable_private_key.type !== "private"
            || !extractable_private_key.extractable
        ) {
            throw new Error("FAIL");
        }
    });
}

export default Object.freeze({
    generate_keypair,
    import_public_key,
    import_private_key,
    export_public_key,
    export_private_key
});
