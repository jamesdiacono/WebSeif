// This module provides the elliptic curve cryptography operations used by
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
//      ArrayBuffer.

//  encrypt(plaintext, public_key)
//      Encrypt the given 'plaintext' ArrayBuffer using the 'public_key'. The
//      returned Promise resolves to the ciphertext as an ArrayBuffer.

//  decrypt(ciphertext, private_key)
//      Decrypt the 'ciphertext' ArrayBuffer using the 'private_key'. The
//      returned Promise resolves to the plaintext as an ArrayBuffer.

// The 'public_key' and 'private_key' parameters are CryptoKey instances.

/*jslint browser */

// Some WebCrypto implementations may not yet support 521-bit keys. For
// development, the keysize can be downgraded here to 256 or 384 bits.

const keysize = 521;
const curve = "P-" + keysize;

function elliptic_constructor(webcrypto = window.crypto) {

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

// The 'encrypt' and 'decrypt' functions implement the Elliptic Curve Integrated
// Encryption Scheme (ECIES).

// ECIES is a relatively expensive operation that is used to encrypt small
// amounts of plaintext with a public key. The ciphertext can only be decrypted
// by the matching private key. It is used by WebSeif to communicate a secret
// symmetric encryption key across the network.

// The AES-GCM specification recommends a 96-bit IV. Because the derived
// symmetric key will only be used once, we can safely use a constant IV. We
// arbitrarily choose 96 zero bits.

    const ecies_iv = new Uint8Array(12);

    function encrypt(plaintext, public_key) {

// We begin by generating an ephemeral key pair.

        return generate_keypair().then(function (ephemeral) {

// Then, we export the bytes of the public ephemeral key. Whilst we are doing
// so, we also derive a symmetric key.

            return Promise.all([
                webcrypto.subtle.exportKey("raw", ephemeral.publicKey),
                webcrypto.subtle.deriveBits(
                    {
                        name: "ECDH",
                        public: public_key
                    },
                    ephemeral.privateKey,
                    256
                )
            ]);
        }).then(function ([ephemeral_public_key_buffer, aes_key_buffer]) {

// Now we encrypt the plaintext with the newly generated symmetric key.

            return webcrypto.subtle.importKey(
                "raw",
                aes_key_buffer,
                {name: "AES-GCM"},
                false,
                ["encrypt"]
            ).then(function (aes_key) {
                return webcrypto.subtle.encrypt(
                    {
                        name: "AES-GCM",
                        iv: ecies_iv
                    },
                    aes_key,
                    plaintext
                );
            }).then(function (encrypted_buffer) {

// Finally we construct the ciphertext, consisting of the ephemeral public key
// followed by the encrypted bytes.

                let ciphertext_buffer = new ArrayBuffer(
                    ephemeral_public_key_buffer.byteLength
                    + encrypted_buffer.byteLength
                );
                let view = new Uint8Array(ciphertext_buffer);
                view.set(
                    new Uint8Array(ephemeral_public_key_buffer),
                    0
                );
                view.set(
                    new Uint8Array(encrypted_buffer),
                    ephemeral_public_key_buffer.byteLength
                );
                return ciphertext_buffer;
            });
        });
    }

    function decrypt(ciphertext, private_key) {

// Break the ciphertext into its constituent parts. Import the ephemeral public
// key and, in conjunction with our private key, derive the symmetric key.

// A public key in raw form includes the X and Y values, plus an extra byte for
// good measure.

        const nr_raw_key_bytes = 2 * Math.ceil(keysize / 8) + 1;
        return webcrypto.subtle.importKey(
            "raw",
            ciphertext.slice(0, nr_raw_key_bytes),
            {
                name: "ECDH",
                namedCurve: curve
            },
            false,
            []
        ).then(function (ephemeral_public_key) {
            return webcrypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: ephemeral_public_key
                },
                private_key,
                256
            );
        }).then(function (aes_key_buffer) {
            return webcrypto.subtle.importKey(
                "raw",
                aes_key_buffer,
                {name: "AES-GCM"},
                false,
                ["decrypt"]
            ).then(function (aes_key) {
                return webcrypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: ecies_iv
                    },
                    aes_key,
                    ciphertext.slice(nr_raw_key_bytes)
                );
            });
        });
    }

    return Object.freeze({
        generate_keypair,
        import_public_key,
        import_private_key,
        export_public_key,
        export_private_key,
        encrypt,
        decrypt
    });
}

export default Object.freeze(elliptic_constructor);
