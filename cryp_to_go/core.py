""" Handles encryption/decryption tasks.

Inspired by Ynon Perek:
https://www.ynonperek.com/2017/12/11/how-to-encrypt-large-files-with-python-and-pynacl/
"""
import os
from typing import Union, Dict, Iterator
from contextlib import contextmanager
import binascii
import io
import random
import nacl.secret
import nacl.utils
import nacl.encoding
import nacl.signing
import nacl.pwhash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

CHUNK_SIZE = 16 * 1024
        

class AsymKey:

    PRIVATE_KEY_DEFAULTS = [
        'id_dsa',
        'id_ecdsa',
        'id_ed25519',
        'id_rsa',
    ]

    def __init__(self, key):
        """ Handles asymmetric encription of small data fragments.

        Intended for safe exchange of small data objects (like symmetric keys).
        Key must be either private (encryption) or public (decryption) SSL key
        as cryptography library compatible RSA (or similar) key objects.
        """
        self.key = key
        self.padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

    def encrypt(self, message: bytes) -> bytes:
        """ Encrypt by public key. """
        enc = self.key.encrypt(
            message,
            self.padding,
        )
        return enc

    def decrypt(self, encrypted: bytes) -> bytes:
        """ Decrypt by private key. """
        original_message = self.key.decrypt(
            encrypted,
            self.padding,
        )
        return original_message

    @classmethod
    def from_pubkey_string(cls, pubkey_str):
        """ Constructor from a public key string.

        :param str pubkey_str: public key string
        """
        return cls(
            key=serialization.load_ssh_public_key(
                data=pubkey_str.encode(),
                backend=default_backend()
            )
        )

    @classmethod
    def from_pubkey_file(cls, path):
        """ Constructor from a public key file.

        :param str path: public key filepath
        """
        with open(path, 'r') as f_in:
            return cls.from_pubkey_string(f_in.read())

    @classmethod
    def privkey_from_pemfile(cls, path=None, password=None):
        """ Constructor from a PEM file (default SSH).

        :param str path: filepath, defaults to ~/.ssh/id_rsa
            defaults to (SSH documentation):
                ~/.ssh/id_dsa, ~/.ssh/id_ecdsa, ~/.ssh/id_ed25519 or ~/.ssh/id_rsa
        :param bytearray password: private key passphrase (bytearray!
            Use getpass.getpass().encode() or similar, might not be hidden in ipython session!)
        """
        if not path:
            # try default paths
            for default_file in cls.PRIVATE_KEY_DEFAULTS:
                default_path = os.path.expanduser(os.path.join('~', '.ssh', default_file))
                if os.path.exists(default_path):
                    path = default_path
                    break
        if not path or not os.path.exists(path):
            raise OSError('no file found at: %r' % path)
        with open(path, 'rb') as f_in:
            return cls(
                key=serialization.load_pem_private_key(
                    data=f_in.read(),
                    password=password,
                    backend=default_backend(),
                )
            )


class CryptoHandler:

    def __init__(self, key_enc: bytes, key_sign: Union[None, bytes] = None):
        """ Handle symmetric encryption of data of any size.

        :param bytes key_enc: encryption key
        :param bytes key_sign: optional key for signing output with HMAC
        """
        self._secret_box = None
        self._key_enc = None
        self.key_enc = key_enc
        self._hmac = None
        self.key_sign = key_sign  # for signing
        self._signature = None

    @property
    def secret_box(self) -> nacl.secret.SecretBox:
        """ Provides the NaCl SecretBox instance for using the encryption key. """
        if self._secret_box is None:
            self._secret_box = nacl.secret.SecretBox(self.key_enc)
        return self._secret_box

    @property
    def key_enc(self) -> bytes:
        """ Secret encryption key.

        :rtype: bytes
        """
        return self._key_enc

    @key_enc.setter
    def key_enc(self, val: bytes):
        """ Set encryption key. Also changes the SecretBox for crypto-operations.

        :param bytes val: new encryption key
        """
        self._key_enc = val
        self._secret_box = None

    @property
    def hmac(self) -> hmac.HMAC:
        if self._hmac is None:
            if self.key_sign:
                self._hmac = hmac.HMAC(
                    self.key_sign,
                    hashes.SHA512(),
                    backend=default_backend()
                )
            else:
                class HMACDummy:
                    """ A dummy that ignores the applied actions. """
                    update = staticmethod(lambda data: None)
                    finalize = staticmethod(lambda: None)
                    verify = staticmethod(lambda data: True)
                self._hmac = HMACDummy()
        return self._hmac

    def reset_signature(self):
        self._hmac = None
        self._signature = None

    @property
    def signature(self) -> Union[None, bytes]:
        if self._hmac is None:
            return None
        if self._signature is None:
            self._signature = self.hmac.finalize()
        return self._signature

    @classmethod
    def create_random(cls, enable_signature_key: bool = False) -> "CryptoHandler":
        key_enc = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        key_sign = nacl.utils.random(size=64) if enable_signature_key else None
        return cls(key_enc, key_sign)

    @contextmanager
    def create_signature(self):
        self.reset_signature()
        yield
        # access signature as self.signature here

    @contextmanager
    def verify_signature(self, signature: Union[bytes, None] = None):
        self.reset_signature()
        yield
        if signature:
            self.hmac.verify(signature)

    def encrypt_stream(self, plain_file_object, read_total: Union[int, None] = None) -> Iterator[bytes]:
        """ Here the encryption happens in chunks (generator).

        The output size is the CHUNK SIZE, the chunks read are 40 bytes smaller to add nonce and chunk
        signature. HMAC signing of the full encrypted data is only done, if an auth_key is provided.
        The signature is then available in `self.last_signature`.

        :param BytesIO plain_file_object: input file
        :param int read_total: maximum bytes to read
        :return: encrypted chunks
        """
        # default way of creating a nonce in nacl
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        # nacl adds nonce (24bytes) and signature (16 bytes),
        # so read 40 bytes less than desired output size
        for index, chunk in enumerate(_read_in_chunks(
                plain_file_object, chunk_size=CHUNK_SIZE - 40, read_total=read_total)
        ):
            enc = self.secret_box.encrypt(chunk, _get_chunk_nonce(nonce, index))
            self.hmac.update(enc)
            yield enc

    def decrypt_stream(self, enc_file_object, read_total: Union[int, None] = None) -> Iterator[bytes]:
        """ Decrypt encrypted stream. (generator)

        If auth_key and signature is provided, HMAC verification is done automatically.

        :param BytesIO enc_file_object: encrypted data stream
        :param int read_total: maximum bytes to read
        :return: plain data in chunks
        :rtype: Iterator[:class:`bytes`]
        """
        for chunk in _read_in_chunks(enc_file_object, read_total=read_total):
            yield self.decrypt_chunk(chunk)

    def decrypt_chunk(self, chunk: bytes) -> bytes:
        """ Decrypt a single encrypted chunk.

        :param bytes chunk: encrypted fixed-size chunk
        :rtype: bytes
        """
        self.hmac.update(chunk)
        return self.secret_box.decrypt(chunk)

    def encrypt_snippet(self, content: bytes) -> bytes:
        """ Convenience method to encrypt small chunks of binary data.

        Wraps encrypt_stream to avoid iterator handling. Not suitable for
        large data chunks.

        :param bytes content: binary content to encrypt
        :returns: encrypted content as bytes
        :rtype: bytes
        """
        buffer_in = io.BytesIO(content)
        buffer_in.seek(0)
        buffer_out = io.BytesIO()
        with self.create_signature():
            for enc_chunk in self.encrypt_stream(buffer_in):
                buffer_out.write(enc_chunk)
        return buffer_out.getvalue()

    def decrypt_snippet(self, enc_content: bytes, signature: Union[bytes, None] = None) -> bytes:
        """ Inverse of encrypt_snippet.

        :param bytes enc_content: binary content to decrypt
        :param bytes signature: optional signature
        :returns: encrypted content as bytes
        :rtype: bytes
        """
        buffer_in = io.BytesIO(enc_content)
        buffer_in.seek(0)
        buffer_out = io.BytesIO()
        with self.verify_signature(signature):
            for chunk in self.decrypt_stream(buffer_in):
                buffer_out.write(chunk)
        return buffer_out.getvalue()

    def to_decrypt_info(self, public_key, skip_signature=False) -> Dict[str, Union[None, str]]:
        """ Use public key from asymmetric keypair to encrypt symmetric keys.

        Generates hexlified strings, so it's JSONifiable.

        :param AsymKey public_key: cryptography SSL RSA key (from pair) or similar, see AsymKey
        :param bool skip_signature: ignore current encryption signature
        :returns: Dict[str, Union[None, str]]
        """
        info = {
            'key_enc': self.key_enc,
            'key_sign': self.key_sign,
            'signature': None if skip_signature else self.signature,
        }
        info_enc = {}
        for key, val in info.items():
            if val is None:
                continue
            info_enc[key] = hexlify(public_key.encrypt(val))
        return info_enc

    @staticmethod
    def decode_info(decrypt_info, private_key):
        info = {
            key: private_key.decrypt(unhexlify(val))
            for key, val in decrypt_info.items()
        }
        return info

    @classmethod
    @contextmanager
    def decryptor_from_info(cls, decrypt_info, private_key):
        info = cls.decode_info(decrypt_info, private_key)
        inst = cls(key_enc=info['key_enc'], key_sign=info.get('key_sign'))
        with inst.verify_signature(info.get('signature')):
            yield inst

    @classmethod
    def from_info(cls, decrypt_info, private_key):
        info = cls.decode_info(decrypt_info, private_key)
        inst = cls(key_enc=info['key_enc'], key_sign=info.get('key_sign'))
        return inst


class KeyDerivationSetup:

    def __init__(
            self,
            construct: str,
            ops: int,
            mem: int,
            key_size_enc: int,
            salt_key_enc: bytes,
            key_size_sig: int,
            salt_key_sig: bytes,
    ):
        self.construct = construct
        self.ops = ops
        self.mem = mem
        self.key_size_enc = key_size_enc
        self.key_size_sig = key_size_sig
        self.salt_key_enc = salt_key_enc
        self.salt_key_sig = salt_key_sig

    def to_dict(self) -> dict:
        return {
            'construct': self.construct,
            'ops': self.ops,
            'mem': self.mem,
            'key_size_enc': self.key_size_enc,
            'key_size_sig': self.key_size_sig,
            'salt_key_enc': binascii.hexlify(self.salt_key_enc).decode(),
            'salt_key_sig': binascii.hexlify(self.salt_key_sig).decode(),
        }

    @classmethod
    def from_dict(cls, serialized: dict) -> "KeyDerivationSetup":
        return cls(
            construct=serialized['construct'],
            ops=serialized['ops'],
            mem=serialized['mem'],
            key_size_enc=serialized['key_size_enc'],
            key_size_sig=serialized['key_size_sig'],
            salt_key_enc=binascii.unhexlify(serialized['salt_key_enc'].encode()),
            salt_key_sig=binascii.unhexlify(serialized['salt_key_sig'].encode()),
        )

    def copy(self) -> "KeyDerivationSetup":
        return KeyDerivationSetup.from_dict(self.to_dict())

    @classmethod
    def create_default(cls, enable_signature_key: bool = False) -> "KeyDerivationSetup":
        """ Create default settings for encryption key derivation from password.

        original source:
        https://pynacl.readthedocs.io/en/stable/password_hashing/#key-derivation

        :param bool enable_signature_key: generate a key for full data signatures via HMAC.
            Usually not necessary, as each block is automatically signed. The only danger
            is block loss and block order manipulation. Key generation is not free
            (that's the idea), so it depends on your use case, whether it hurts usability.

        :rtype: KeyDerivationSetup
        """
        return cls(
            ops=nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,
            mem=nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE,
            construct='argon2i',
            salt_key_enc=nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES),
            salt_key_sig=nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES)
            if enable_signature_key else b'',
            key_size_enc=nacl.secret.SecretBox.KEY_SIZE,
            key_size_sig=64 if enable_signature_key else 0
        )

    @classmethod
    def create_minimal(cls, enable_signature_key: bool = False) -> "KeyDerivationSetup":
        """ Use minimal settings for key derivation.

        Intended for testing purposes only!
        """
        inst = cls.create_default(
            enable_signature_key=enable_signature_key
        )
        inst.ops = nacl.pwhash.argon2i.OPSLIMIT_MIN
        inst.mem = nacl.pwhash.argon2i.MEMLIMIT_MIN
        return inst

    def generate_keys(self, password: bytes) -> CryptoHandler:
        """ Create encryption and signature keys from a password.

        Uses salt and resilient hashing. Returns the hashing settings, so the keys can be
        recreated with the same password.

        original source:
        https://pynacl.readthedocs.io/en/stable/password_hashing/#key-derivation

        :param bytes password: password as bytestring
        :rtype: DerivedKey
        """
        kdf = None
        if self.construct == 'argon2i':
            kdf = nacl.pwhash.argon2i.kdf
        if kdf is None:
            raise AttributeError('construct %s is not implemented' % self.construct)
        key_enc = kdf(self.key_size_enc, password, self.salt_key_enc,
                      opslimit=self.ops, memlimit=self.mem)
        key_sign = kdf(self.key_size_sig, password, self.salt_key_sig,
                       opslimit=self.ops, memlimit=self.mem) if self.key_size_sig else None
        return CryptoHandler(key_enc, key_sign)


def get_unenc_block_size(enc_block_size):
    """ Calculate how many unencrypted bytes amount to the desired encrypted amount.

    An encrypted chunk is 40 Bytes longer than its unencrypted content.
    Sometimes you need to create the encryption on the fly in larger chunks,
    e.g. for an upload to cloud storage with much larger chunk size (N). So
    if you aim for chunks of size N composed of chunks of size n with
    (n - 40) Bytes of the orginal content you
    can use the `read_total` argument of the encryption methods with the
    size determined by this method: how often do I have to read (n - 40)
    Bytes to get an encrypted size of N?

    :param enc_block_size: desired encrypted number of bytes
    :return: size of unencrypted data
    :rtype: int
    :raises ValueError: if the target block size can not be created from the encryption chunk size.
    """
    if enc_block_size % CHUNK_SIZE:
        raise ValueError('can not divide %i by %i!' % (enc_block_size, CHUNK_SIZE))
    n_chunks = enc_block_size // CHUNK_SIZE
    return n_chunks * (CHUNK_SIZE - 40)


def hexlify(binarray: bytes) -> str:
    """ Binary to hex-string conversion. """
    return binascii.hexlify(binarray).decode()


def unhexlify(hexstr: str) -> bytes:
    """ Hex-string to binary conversion. """
    return binascii.unhexlify(hexstr.encode())


def _get_chunk_nonce(base: bytes, index: int) -> bytes:
    """ Creates incrementing nonces. Make sure that the base is different for each reset of index!

    :param bytes base: random base for the nonces
    :param int index: offset for the nonce
    :rtype: bytes
    """
    size = nacl.secret.SecretBox.NONCE_SIZE
    return int.to_bytes(
        int.from_bytes(base, byteorder='big') + index,
        length=size,
        byteorder='big'
    )


def _read_in_chunks(
        file_object,
        chunk_size: Union[int, None] = None,
        read_total: Union[int, None] = None
) -> Iterator[bytes]:
    """ Generator to read a stream piece by piece with a given chunk size.
    Total read size may be given. Only read() is used on the stream.

    :param BytesIO file_object: readable stream
    :param int chunk_size: chunk read size
    :param int read_total: maximum amount to read in total
    :rtype: Iterator[bytes]
    :returns: data as bytes and index as int
    """
    chunk_size = chunk_size or CHUNK_SIZE
    read_size = chunk_size
    read_yet = 0
    while True:
        if read_total is not None:
            read_size = min(read_total - read_yet, chunk_size)
        data = file_object.read(read_size)
        if not data:
            break
        yield data
        read_yet += read_size


def sign_stream(key_sign: bytes, enc_file_object, read_total: Union[int, None] = None) -> bytes:
    """ Sign a stream with a given HMAC handler. Suitable for large amounts of data.

    :param bytes key_sign: signing key for HMAC
    :param BytesIO enc_file_object: encrypted stream
    :param int read_total: optional size limit for read().
    :returns: signature
    :rtype: bytes
    """
    auth_hmac = hmac.HMAC(
        key_sign,
        hashes.SHA512(),
        backend=default_backend()
    )
    for chunk in _read_in_chunks(enc_file_object, read_total=read_total):
        auth_hmac.update(chunk)
    return auth_hmac.finalize()


def verify_stream(key_sign, enc_file_object, signature, read_total=None):
    """ Verify signed encrypted stream. Suitable for large amounts of data.

    :param bytes key_sign: signing key for HMAC
    :param BytesIO enc_file_object: encrypted byte stream
    :param bytes signature: signature
    :param int read_total: maximum bytes to read
    :return: whether signature is valid
    :rtype: bool
    """
    auth_hmac = hmac.HMAC(
        key_sign,
        hashes.SHA512(),
        backend=default_backend()
    )
    for chunk in _read_in_chunks(enc_file_object, read_total=read_total):
        auth_hmac.update(chunk)
    try:
        auth_hmac.verify(signature)
        return True
    except InvalidSignature:
        return False


def inflate_string(string: str, min_len: int = 64, variance: int = 32) -> bytes:
    """ Extend a string by an arbitrary number of bytes.

    - Actually converts to bytes, adds random stuff and separates by 0 char.
    - Intended for preventing identification of files by path length.
    - 0 char is invalid in paths, so should be safe here.
    - No guarantees for other use cases. Some operations may get confused.
    """
    if string.find('\0') >= 0:
        raise ValueError(r'Zero character is illegal in this operation.')
    as_bytes = string.encode()
    final_size = (
            min_len
            + ((len(as_bytes) + variance) // min_len) * min_len
            + random.choice(range(2 * variance + 1)) - variance
    )
    n_append = final_size - len(as_bytes)
    if not n_append:
        return as_bytes
    as_bytes += '\0'.encode()
    return as_bytes + nacl.utils.random(max(0, final_size - len(as_bytes)))


def deflate_string(as_bytes: bytes) -> str:
    """ Inverse of inflate_string.

    Takes the undecoded binary string.
    """
    zero_loc = as_bytes.find(0)
    if zero_loc < 0:
        return as_bytes.decode()
    return as_bytes[:zero_loc].decode()
