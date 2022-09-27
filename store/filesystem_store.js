// A WebSeif store implemented using generic filesystem capabilities. You
// probably want node_filesystem_store.js or deno_filesystem_store.js instead.

/*jslint node */

import make_elliptic from "../elliptic.js";
import hex from "../hex.js";

function filesystem_store(
    webcrypto,
    read_file,
    write_file,
    remove_file,
    make_directory,
    path_separator,
    directory,
    password,
    iterations = 50000
) {
    function opaqify_keypair(keypair) {

// The 'opaqify_keypair' function returns a Promise that resolves to a
// non-extractable copy of a CryptoKeyPair.

        return webcrypto.subtle.exportKey(
            "pkcs8",
            keypair.privateKey
        ).then(function (key_data) {
            return webcrypto.subtle.importKey(
                "pkcs8",
                key_data,
                keypair.privateKey.algorithm,
                false,
                keypair.privateKey.usages
            );
        }).then(function (opaque_private_key) {
            return {
                publicKey: keypair.publicKey,
                privateKey: opaque_private_key
            };
        });
    }
    function keyify_password(salt) {

// Derives a symmetric encryption key from the 'password' string. The returned
// Promise resolves to the CryptoKey.

// The password is first imported as a CryptoKey. Then it is used to derive the
// AES key. The key can be hardened by increasing the number of iterations, at
// the cost of CPU time.

// Note that the hashing algorithm we are using (SHA-256) is weaker than the
// algorithm required by the Seif Protocol (SHA3-256) but it is the best that
// WebCrypto offers.

        return webcrypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            "PBKDF2",
            false,
            ["deriveKey", "deriveBits"]
        ).then(function (password_key) {
            return webcrypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt,
                    iterations,
                    hash: "SHA-256"
                },
                password_key,
                {
                    name: "AES-GCM",
                    length: 256
                },
                false,
                ["encrypt", "decrypt"]
            );
        });
    }
    function ensure_directory() {
        return make_directory(directory, {recursive: true}).catch(function () {

// The directory could not be created, but perhaps that is because it already
// exists. We give it the benefit of the doubt.

            return;
        });
    }
    function file_path(name) {

// We want to include the petname in the acquaintance's filename, but it may
// contain illegal characters. To be safe, we escape any funky characters. For
// example "/" becomes "%25".

        return directory + path_separator + encodeURIComponent(name);
    }
    function write(name, buffer) {

// Write the given 'buffer' to a file with 'name' within 'directory'. The file's
// owner is given permission to read and write, but nobody else is given any
// permissions.

        return write_file(file_path(name), buffer, {mode: 0o600});
    }
    function read(name) {
        return read_file(file_path(name)).catch(function (error) {
            if (error.code !== "ENOENT") {
                throw error;
            }
        });
    }

// Decrypting a keypair can be a very expensive operation. We cache the result
// to avoid crippling delays when the keypair is read at frequent intervals.

    let read_keypair_promise;
    const elliptic = make_elliptic(webcrypto);
    const salt_length = 256 / 8;
    const iv_length = 96 / 8;
    function write_keypair(keypair) {

// Encrypt the private key with the password, then write both keys to disk.

        const salt = new Uint8Array(salt_length);
        webcrypto.getRandomValues(salt);
        const iv = new Uint8Array(iv_length);
        webcrypto.getRandomValues(iv);
        return Promise.all([
            elliptic.export_private_key(keypair.privateKey),
            keyify_password(salt)
        ]).then(function ([private_key_buffer, encryption_key]) {
            return Promise.all([
                webcrypto.subtle.encrypt(
                    {
                        name: "AES-GCM",
                        iv
                    },
                    encryption_key,
                    private_key_buffer
                ),
                elliptic.export_public_key(keypair.publicKey),
                ensure_directory()
            ]);
        }).then(function ([encrypted_private_key_buffer, public_key_buffer]) {

// Bundle up the salt, IV and encrypted private key into a binary buffer, and
// write it to disk alongside the unencrypted public key.

            const ciphered = new Uint8Array(
                salt_length
                + iv_length
                + encrypted_private_key_buffer.byteLength
            );
            ciphered.set(salt, 0);
            ciphered.set(iv, salt_length);
            ciphered.set(
                new Uint8Array(encrypted_private_key_buffer),
                salt_length + iv_length
            );

// The private key is stored as a binary file, as it is meant to be opaque. The
// public key is hex encoded and stored as a string, making it easier for a
// human to inspect.

            const public_key_hex = new TextEncoder().encode(
                hex.encode(public_key_buffer)
            );
            return Promise.all([
                write("private", ciphered),
                write("public", public_key_hex)
            ]);
        }).then(function on_success() {

// After being written, the keypair is stored in memory to speed up future
// reads. We take care that the private key is in non-extractable form.

            read_keypair_promise = opaqify_keypair(keypair);
        });
    }
    function read_keypair() {
        if (read_keypair_promise !== undefined) {
            return read_keypair_promise;
        }
        read_keypair_promise = Promise.all([
            read("private"),
            read("public")
        ]).then(function ([ciphered, public_key_buffer]) {
            if (ciphered === undefined) {
                return;
            }

// Split the buffer into the salt, the IV and the encrypted private key. Derive
// the decryption key the same way we derived the encryption key.

            const salt = ciphered.slice(0, salt_length);
            const iv = ciphered.slice(salt_length, salt_length + iv_length);
            const encrypted_private_key_buffer = ciphered.slice(
                salt_length + iv_length
            );
            return keyify_password(salt).then(function (decryption_key) {

// Decrypt the private key.

                return webcrypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv
                    },
                    decryption_key,
                    encrypted_private_key_buffer
                );
            }).then(function (private_key_buffer) {

// Import the private and public keys as CryptoKey instances. The private key is
// not extractable.

                return Promise.all([
                    elliptic.import_private_key(private_key_buffer),
                    elliptic.import_public_key(hex.decode(
                        new TextDecoder().decode(public_key_buffer)
                    ))
                ]);
            }).then(function ([privateKey, publicKey]) {
                return {privateKey, publicKey};
            });
        }).catch(function (ignore) {

// Something probably went wrong decrypting the private key. This could be due
// to a change in 'iterations' or some other parameter.

            return Promise.reject(new Error("Bad keypair."));
        });
        return read_keypair_promise;
    }
    function add_acquaintance(acquaintance) {
        return Promise.all([
            elliptic.export_public_key(acquaintance.public_key),
            ensure_directory()
        ]).then(function ([public_key_buffer]) {
            return write(
                "acquaintance_" + acquaintance.petname,
                new TextEncoder().encode(JSON.stringify({
                    address: acquaintance.address,
                    public_key: hex.encode(public_key_buffer)
                }))
            );
        });
    }
    function remove_acquaintance(petname) {
        return remove_file(
            file_path("acquaintance_" + petname)
        ).catch(function (error) {
            if (error.code !== "ENOENT") {
                throw error;
            }
        });
    }
    function read_acquaintance(petname) {
        return read("acquaintance_" + petname).then(function (buffer) {
            if (buffer === undefined) {
                return;
            }
            const object = JSON.parse(new TextDecoder().decode(buffer));
            return elliptic.import_public_key(
                hex.decode(object.public_key)
            ).then(function (public_key) {
                object.public_key = public_key;
                return {
                    petname,
                    address: object.address,
                    public_key
                };
            });
        });
    }
    return Object.freeze({
        write_keypair,
        read_keypair,
        add_acquaintance,
        remove_acquaintance,
        read_acquaintance
    });
}

export default Object.freeze(filesystem_store);
