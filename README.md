# cryp-to-go

## What is it?

- easy to use high-level crypto library for encrypted data storage/exchange
- can use derived encryption keys from password + salt
- can generate random keys and encrypt them by SSL public key (one or multiple)
- can handle HMAC signatures of encrypted data
- store multiple files in SQLite (ORM via peewee)
- store all necessary information and data in a single SQLite file
- store encrypted key/value pairs in SQLite (for usage in other python programs)
- allow encryption/decryption of streams (for usage in python programs that handle large data)
- CLI for file -> SQLite encryption
- based on cryptography and pynacl libraries

## Usage

### CLI

The CLI provides one part of the functionailty: 
Store encrypted files in a SQLite database file. This is intended for quick file storage (key derivation) 
or file exchange over insecure channels (public/private key).
Multiple files are stored inside the same database. They are identified by their relativ path 
(on encryption: relative to CWD), and all paths are stored encrypted. Asymmetric keys are
never stored, and symmetric encryption keys:
- are stored asymmetrically encrypted.
- and/or derived from a key derivation setup, that is stored in the database and 
 requires the correct password.

The command `cryp-to-go` should be accessable from the command line. 
- The parameter `-s` sets the file name to use for the database. It defaults to `cryp-to-go-safe.sqlite`.
- Always choose an action: encrypt files `--encrypt`/`-e`, decrypt files `--decrypt`/`-d`, list files `--list`/`-l`.
- You can provide asymmetric keys:
  - public key via `--pubkey` or `-p` as string or file path
  - private key via `--private_key` or `-k` as path to a PEM file. A passphrase will be requested, when it is necessary.
- Encryption keys can either be restored by public key, or by password for key derivation.
 If a new database file is created, the encryption keys will be created randomly, 
 if a public key is provided, and the `--always_derive` derive flag is not set. Otherwise
 a key derivation setup will be created and a password requested.
- The public key is used to encrypt symmetric encryption keys. 
 It needs to be provided on `--encrypt` operations. It is possible to encrypt symmetric keys
 with multiple public keys, so multiple recepients get access.
 This is done via the `--append_key` parameter with any action.
- The files to encrypt/decrypt are the trailing arguments. List operation does not use them.
- Only files below CWD are allowed. This does not apply to the database file.

#### example
```bash
cryp-to-go --encrypt -s /tmp/ctg_example.sqlite -p ~/.ssh/id_rsa.pub README.md setup.py
cryp-to-go --list -s /tmp/ctg_example.sqlite -k ~/.ssh/id_rsa
cd /tmp
cryp-to-go --decrypt -s ctg_Example.sqlite -k ~/.ssh/id_rsa README.md
```
- The first line encrypts two files into a new container in `/tmp`. A public key is provided,
so the owner of the private key can access the container. As the `--always_derive` flag is not set,
the encryptions keys are not derivable. This saves time, but means that the private key is the
only way to access the decrypted content.
- The second line lists the files contained. The private key is necessary. 
It's passphrase will be requested.
- The third line switches to a different directory, as we don't want to overwrite files in the 
original folder. Decryption is written relative to CWD!
- The last line executes the decryption of only one of the files. Again, the private key is required.

### Core

The `core` module provides the lowest level functions and is intended for usage inside
other python modules. Besides some auxiliary functions (`hexlify`, `unhexlify`), 
there are two auxiliary classes that might become relevant:
- `KeyDerivationSetup` creates and stores the settings for key derivation including salt.
 It is fully configurable and uses `nacl.pwhash.argon2i`, but you will likely either use
 `create_default` (always), or `create_minimal` (unit tests only!). The latter makes key 
 derivation very cheap and is therefore not suitable for anything else than tests. It 
 provides serialization methods to be jsonifiable, and creates a `CryptoHandler` with
 derived encyption keys with the `generate_keys` method.
- `AsymKey` is a wrapper for asymmetric keys -- public or private -- that provides
 easy access to encryption and decryption of short data fragments 
 (like symmetric encryption keys).

The central class is the `CryptoHandler`. It holds symmetric encryption and signature keys
and provides methods to encrypt, decrypt, sign and verify. Also, the `create_random` factory
creates a new instance with random keys.
- `encrypt_stream` and `decrypt_stream` are generators that iterate over a stream and
 yield the encrypted/decrypted content. They work in encryption chunks and use the 
 `encrypt_chunk` and `decrypt_chunk` methods. They are at the core of most encryption
 operations and suitable to process large data.
- `encrypt_snippet` and `decrypt_snippet` do the same, but without the streaming. 
 They are intended for small pieces of data, like paths or dataset keys.
- if the `CryptoHandler` has a signing key `key_sign` (usually set on creation via 
 argument in factory methods), a signature can be calculated for the encrypted data.
 This happens on the fly, as the stream is encrypted, and only requires wrapping 
 it in the `create_signature` context manager. It can be accessed afterwards as the
 `signature` property. The encryption method already provides signatures for all
 chunks, so a total signature ensures only correct order, which is in most cases
 not a necessary increase in security, but might help with data integrity. To verify
 encrypted data, just wrap the decryption in the `verify_signature` context manager.
 It ignores `None` signatures, so you don't need to worry about missing isgnatures.
 
### Interface

The `interface` module contains interface(s) that provide core functionality in an 
extended context. Currently only `SQLiteFileInterface` exists. If another one is
added, a base class will be extracted.

The `SQLiteFileInterface` handles encryption/decryption in the context of a SQLite
database. It manages storage of the key derivation setup 
(`store_key_derivation_setup` with counterpart `load_crypto_handler`), 
of pubkey-encrypted keys (`store_keys_asymmetric` with `load_crypto_handler_async`), 
encrypted files (`store_files` and `restore_files`), and -- as additional 
feature for potential usage in
other projects -- encrypted key-value pairs (`store_values` with `restore_files` 
(shared with file storage)).

It is the backbone of the CLI.
