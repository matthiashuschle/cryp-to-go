""" Handles encryption/decryption tasks.

Inspired by Ynon Perek:
https://www.ynonperek.com/2017/12/11/how-to-encrypt-large-files-with-python-and-pynacl/
"""
import os
from typing import Union, Dict
from contextlib import contextmanager
from collections import namedtuple
import binascii
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
DerivedKey = namedtuple('DerivedKey', ['enc_key', 'sign_key', 'setup'])


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

    def encrypt(self, message):
        enc = self.key.encrypt(
            message,
            self.padding,
        )
        return enc

    def decrypt(self, encrypted):
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


class DerivedKeySetup:
    
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
    def from_dict(cls, serialized: dict) -> "DerivedKeySetup":
        return cls(
            construct=serialized['construct'],
            ops=serialized['ops'],
            mem=serialized['mem'],
            key_size_enc=serialized['key_size_enc'],
            key_size_sig=serialized['key_size_sig'],
            salt_key_enc=binascii.unhexlify(serialized['salt_key_enc'].encode()),
            salt_key_sig=binascii.unhexlify(serialized['salt_key_sig'].encode()),
        )

    def copy(self) -> "DerivedKeySetup":
        return DerivedKeySetup.from_dict(self.to_dict())

    @classmethod
    def create_default(cls, enable_signature_key: bool = False) -> "DerivedKeySetup":
        """ Create default settings for encryption key derivation from password.

        original source:
        https://pynacl.readthedocs.io/en/stable/password_hashing/#key-derivation

        :param bool enable_signature_key: generate a key for full data signatures via HMAC.
            Usually not necessary, as each block is automatically signed. The only danger
            is block loss and block order manipulation. Key generation is not free
            (that's the idea), so it depends on your use case, whether it hurts usability.

        :rtype: DerivedKeySetup
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
    
    def generate_keys(self, password: bytes) -> DerivedKey:
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
        key_sig = kdf(self.key_size_sig, password, self.salt_key_sig,
                      opslimit=self.ops, memlimit=self.mem) if self.key_size_sig else b''
        # set setup to a copy of self
        return DerivedKey(
            enc_key=key_enc,
            sign_key=key_sig,
            setup=self.copy(),
        )


class CryptoHandler:

    def __init__(self, enc_key: bytes, sign_key: Union[None, bytes] = None):
        """ Handle symmetric encryption of data of any size.

        :param bytes enc_key: encryption key
        :param bytes sign_key: optional key for signing output with HMAC
        """
        self._secret_box = None
        self._enc_key = None
        self.enc_key = enc_key
        self._hmac = None
        self.sign_key = sign_key  # for signing
        self._signature = None
        self.derivation_info = None

    @property
    def secret_box(self) -> nacl.secret.SecretBox:
        """ Provides the NaCl SecretBox instance for using the encryption key. """
        if self._secret_box is None:
            self._secret_box = nacl.secret.SecretBox(self.enc_key)
        return self._secret_box

    @property
    def enc_key(self) -> bytes:
        """ Secret encryption key.

        :rtype: bytes
        """
        return self._enc_key

    @enc_key.setter
    def enc_key(self, val: bytes):
        """ Set encryption key. Also changes the SecretBox for crypto-operations.

        :param bytes val: new encryption key
        """
        self._enc_key = val
        self._secret_box = None

    @property
    def hmac(self) -> hmac.HMAC:
        if self._hmac is None:
            if self.sign_key:
                self._hmac = hmac.HMAC(
                    self.sign_key,
                    hashes.SHA512(),
                    backend=default_backend()
                )
            else:
                class HMACDummy:
                    """ A dummy that ignores the applied actions. """
                    update = staticmethod(lambda data: None)
                    finalize = staticmethod(lambda: b'')
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
    def from_random(cls, enable_signature_key: bool = False) -> "CryptoHandler":
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        sign_key = nacl.utils.random(size=64) if enable_signature_key else None
        return cls(key, sign_key)

    @classmethod
    def from_derived_key_setup(
            cls, derived_key_setup: DerivedKeySetup, password: bytes
    ) -> "CryptoHandler":
        """ Constructor from a DerivedKeySetup.

        :param DerivedKeySetup derived_key_setup: derivation setup
        :param bytes password: initial password for key generation
        :rtype: CryptoHandler
        """
        derived_keys = derived_key_setup.generate_keys(password)
        inst = cls(enc_key=derived_keys.enc_key, sign_key=derived_keys.sign_key)
        inst.derivation_info = derived_keys.setup
        return inst

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

    def encrypt_stream(self, plain_file_object, read_total=None):
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

    def decrypt_stream(self, enc_file_object, read_total=None):
        """ Decrypt encrypted stream. (generator)

        If auth_key and signature is provided, HMAC verification is done automatically.

        :param BytesIO enc_file_object: encrypted data stream
        :param int read_total: maximum bytes to read
        :return: plain data in chunks
        :rtype: bytes
        """
        for chunk in _read_in_chunks(enc_file_object, read_total=read_total):
            self.hmac.update(chunk)
            yield self.secret_box.decrypt(chunk)

    def to_decrypt_info(self, public_key) -> Dict[str, Union[None, str]]:
        """ Use public key from asymmetric keypair to encrypt symmetric keys.

        Generates hexlified strings, so it's JSONifiable.

        :param AsymKey public_key: cryptography SSL RSA key (from pair) or similar, see AsymKey
        :returns: Dict[str, Union[None, str]]
        """
        info = {
            'enc_key': self.enc_key,
            'sign_key': self.sign_key,
            'signature': self.signature,
        }
        info_enc = {}
        for key, val in info.items():
            if val is None:
                continue
            info_enc[key] = hexlify(public_key.encrypt(val))
        return info_enc

    @classmethod
    @contextmanager
    def decryptor_from_info(cls, decrypt_info, private_key):
        info = {
            key: private_key.decrypt(unhexlify(val))
            for key, val in decrypt_info.items()
        }
        inst = cls(enc_key=info['enc_key'], sign_key=info.get('sign_key'))
        with inst.verify_signature(info.get('signature')):
            yield inst


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


def hexlify(binarray):
    """ Binary to hex-string conversion. """
    return binascii.hexlify(binarray).decode()


def unhexlify(hexstr):
    """ Hex-string to binary conversion. """
    return binascii.unhexlify(hexstr.encode())


def _get_chunk_nonce(base, index):
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


def _read_in_chunks(file_object, chunk_size=None, read_total=None):
    """ Generator to read a stream piece by piece with a given chunk size.
    Total read size may be given. Only read() is used on the stream.

    :param BytesIO file_object: readable stream
    :param int chunk_size: chunk read size
    :param int read_total: maximum amount to read in total
    :rtype: tuple
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


def sign_stream(sign_key, enc_file_object, read_total=None):
    """ Sign a stream with a given HMAC handler. Suitable for large amounts of data.

    :param bytes sign_key: signing key for HMAC
    :param BytesIO enc_file_object: encrypted stream
    :param int read_total: optional size limit for read().
    :returns: signature
    :rtype: bytes
    """
    auth_hmac = hmac.HMAC(
        sign_key,
        hashes.SHA512(),
        backend=default_backend()
    )
    for chunk in _read_in_chunks(enc_file_object, read_total=read_total):
        auth_hmac.update(chunk)
    return auth_hmac.finalize()


def verify_stream(sign_key, enc_file_object, signature, read_total=None):
    """ Verify signed encrypted stream. Suitable for large amounts of data.

    :param bytes sign_key: signing key for HMAC
    :param BytesIO enc_file_object: encrypted byte stream
    :param bytes signature: signature
    :param int read_total: maximum bytes to read
    :return: whether signature is valid
    :rtype: bool
    """
    auth_hmac = hmac.HMAC(
        sign_key,
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


def demo_asym():
    import json
    from io import BytesIO
    # 1. create a file to be encrypted
    # 2. create an asymmetric keypair to exchange the encryption keys
    # 3. encrypt the file
    # 4. provide the encryption info
    # 5. decrypt
    path_private_key, path_public_key, path_to_encrypt = _prepare_demo()
    # encrypt, using generated symmetric keys and public key
    pubkey = AsymKey.from_pubkey_file(path_public_key)
    # signature key is optional
    handler = CryptoHandler.from_random(enable_signature_key=True)
    with open(path_to_encrypt + '.enc', 'wb+') as f_out:
        with open(path_to_encrypt, 'rb') as f_in:
            with handler.create_signature():
                for chunk in handler.encrypt_stream(f_in):
                    f_out.write(chunk)
        f_out.seek(0)
        print('encrypted (first 20):', binascii.hexlify(f_out.read(20)).decode())
    # exchange only enc_info (JSONifiable)
    decrypt_info = handler.to_decrypt_info(pubkey)
    del pubkey
    del handler
    print(json.dumps(decrypt_info, indent=4))
    # decrypt, using symmetric keys retrieved via private key
    privkey = AsymKey.privkey_from_pemfile(path_private_key)
    buffer = BytesIO()  # use BytesIO instead of yet another file
    with CryptoHandler.decryptor_from_info(decrypt_info, privkey) as handler:
        with open(path_to_encrypt + '.enc', 'rb') as f_in:
            for chunk in handler.decrypt_stream(f_in):
                buffer.write(chunk)
    buffer.seek(0)
    decrypted = buffer.read().decode()
    assert decrypted == 'The cake is a lie!\n' * 10000
    import os
    for path in [path_private_key, path_public_key, path_to_encrypt]:
        os.remove(path)


def _prepare_demo():
    import os
    import tempfile
    from cryptography.hazmat.primitives.asymmetric import rsa

    # create temporary file and close
    def _touch():
        fd, path = tempfile.mkstemp()
        os.close(fd)
        return path

    # create file to encrypt
    path_to_encrypt = _touch()
    with open(path_to_encrypt, 'w') as f_out:
        f_out.write('The cake is a lie!\n' * 10000)
    # generate a keypair
    asym_key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    path_private_key = _touch()
    with open(path_private_key, 'wb') as f_out:
        f_out.write(
            asym_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
        )
    path_public_key = _touch()
    with open(path_public_key, 'wb') as f_out:
        f_out.write(
            asym_key.public_key().public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH
            )
        )
    return path_private_key, path_public_key, path_to_encrypt


def demo_sym():
    import os
    from io import BytesIO
    path_private_key, path_public_key, path_to_encrypt = _prepare_demo()
    # we don't need the keypair
    os.remove(path_private_key)
    os.remove(path_public_key)
    # pick any password
    password = "supersecret".encode()
    # enable_signature_key is optional
    key_setup = DerivedKeySetup.create_default(enable_signature_key=True)
    handler = CryptoHandler.from_derived_key_setup(
        key_setup,
        password,
    )
    with open(path_to_encrypt + '.enc', 'wb+') as f_out:
        with open(path_to_encrypt, 'rb') as f_in:
            with handler.create_signature():
                for chunk in handler.encrypt_stream(f_in):
                    f_out.write(chunk)
            f_out.seek(0)
            print('encrypted (first 20):', binascii.hexlify(f_out.read(20)).decode())
    # store public information
    signature = hexlify(handler.signature)  # for validation
    key_setup_dict = key_setup.to_dict()
    # remove handler
    del handler
    del key_setup
    # decrypt
    handler = CryptoHandler.from_derived_key_setup(
        DerivedKeySetup.from_dict(key_setup_dict),
        password,
    )
    # use BytesIO instead of yet another file
    buffer = BytesIO()
    with open(path_to_encrypt + '.enc', 'rb') as f_in:
        with handler.verify_signature(unhexlify(signature)):
            for chunk in handler.decrypt_stream(f_in):
                buffer.write(chunk)
    buffer.seek(0)
    decrypted = buffer.read().decode()
    assert decrypted == 'The cake is a lie!\n' * 10000
    os.remove(path_to_encrypt)


if __name__ == '__main__':
    demo_asym()
    demo_sym()
