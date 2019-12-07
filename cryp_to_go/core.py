"""
Handles encryption. Based on the post of Ynon Perek:
https://www.ynonperek.com/2017/12/11/how-to-encrypt-large-files-with-python-and-pynacl/
"""
from collections import namedtuple, OrderedDict
import binascii
import nacl.secret
import nacl.utils
import nacl.encoding
import nacl.signing
import nacl.pwhash
from nacl.exceptions import BadSignatureError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

CHUNK_SIZE = 16 * 1024
DerivedKey = namedtuple('DerivedKey', ['key_enc', 'key_sig', 'setup'])


class AsymKeyPair:

    def __init__(self, pubkey=None, privkey=None):
        """ Handles SSL key pair as cryptography object.

        Intended for safe exchange of small data objects (like symmetric keys).
        Both arguments must be cryptography library compatible RSA (or similar) Key
        objects.
        """
        self.pubkey = pubkey
        self.privkey = privkey
        self.last_enc_info = None

    def encrypt(self, message, to_str=True):
        enc = self.pubkey.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        if to_str:
            return binascii.hexlify(enc).decode()
        return enc

    def decrypt(self, encrypted):
        try:
            encrypted = binascii.unhexlify(encrypted.encode())
        except AttributeError:
            # already bytes
            pass
        original_message = self.privkey.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message

    def encrypt_stream(self, stream_in, crypto_handler=None, enable_auth_key=False):
        crypto_handler = crypto_handler or CryptoHandler.from_random(enable_auth_key)
        yield from crypto_handler.encrypt_stream(stream_in)
        self.last_enc_info = crypto_handler.create_info(keypair=self)

    def decrypt_stream(self, stream_in, enc_info):
        handler = CryptoHandler.from_info(enc_info, keypair=self)
        yield from handler.decrypt_stream(stream_in, signature=handler.last_signature)


class DerivedKeySetup:
    def __init__(self, construct, ops, mem, key_size_enc, salt_key_enc,
                 key_size_sig=None, salt_key_sig=None):
        self.construct = construct
        self.ops = ops
        self.mem = mem
        self.key_size_enc = key_size_enc
        self.key_size_sig = key_size_sig
        self.salt_key_enc = salt_key_enc
        self.salt_key_sig = salt_key_sig

    @classmethod
    def create_default(cls, enable_auth_key=False):
        """ Create default settings for encryption key derivation from password.

        original source: https://pynacl.readthedocs.io/en/stable/password_hashing/#key-derivation
        :param bool enable_auth_key: generate a key for full data signatures via HMAC
        :rtype: DerivedKeySetup
        """
        return cls(
            ops=nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,
            mem=nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE,
            construct='argon2i',
            salt_key_enc=nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES),
            salt_key_sig=nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES) if enable_auth_key else b'',
            key_size_enc=nacl.secret.SecretBox.KEY_SIZE,
            key_size_sig=64 if enable_auth_key else 0
        )


def create_keys_from_password(password, setup=None, enable_auth_key=False):
    """ Create encryption and signature keys from a password.

    Uses salt and resilient hashing. Returns the hashing settings, so the keys can be recreated with the same password.
    original source: https://pynacl.readthedocs.io/en/stable/password_hashing/#key-derivation

    :param bytes password: password as bytestring
    :param DerivedKeySetup setup: settings for the hashing
    :param bool enable_auth_key: generate a key for full data signatures via HMAC. Usually not necessary, as each block
        is automatically signed. The only danger is block loss and block order manipulation.
    :rtype: DerivedKey
    """
    setup = setup or DerivedKeySetup.create_default(enable_auth_key=enable_auth_key)
    kdf = None
    if setup.construct == 'argon2i':
        kdf = nacl.pwhash.argon2i.kdf
    if kdf is None:
        raise AttributeError('construct %s is not implemented' % setup.construct)
    key_enc = kdf(setup.key_size_enc, password, setup.salt_key_enc,
                  opslimit=setup.ops, memlimit=setup.mem)
    key_sig = kdf(setup.key_size_sig, password, setup.salt_key_sig,
                  opslimit=setup.ops, memlimit=setup.mem) if setup.key_size_sig else b''
    return DerivedKey(
        key_enc=key_enc,
        key_sig=key_sig,
        setup=setup)


def _chunk_nonce(base, index):
    """ Creates incrementing nonces. Make sure that the base is different for each reset of index!

    :param bytes base: random base for the nonces
    :param int index: offset for the nonce
    :rtype: bytes
    """
    size = nacl.secret.SecretBox.NONCE_SIZE
    return int.to_bytes(int.from_bytes(base, byteorder='big') + index, length=size, byteorder='big')


class CryptoHandler:

    def __init__(self, secret_key, auth_key=None):
        """ Handle symmetric encryption of data of any size.

        :param bytes secret_key: encryption key
        :param bytes auth_key: optional key for signing output with HMAC
        """
        self.secret_box = None
        self._secret_key = None
        self.secret_key = secret_key
        self.auth_key = auth_key  # for signing
        self._last_signature = None

    @classmethod
    def from_random(cls, enable_auth_key=False):
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        auth_key = nacl.utils.random(size=64) if enable_auth_key else None
        return cls(key, auth_key)

    @classmethod
    def from_derived_keys(cls, derived_key):
        """ Create encryption and signature keys from a DerivedKey isntance.

        :param DerivedKey derived_key: created via password and settings
        :rtype: CryptoHandler
        """
        inst = cls(secret_key=derived_key.key_enc, auth_key=derived_key.key_sig or None)
        return inst

    @property
    def last_signature(self):
        """ After finalizing encryption, holds a signature, if auth_key is available.

        :rtype: bytes
        """
        return self._last_signature

    @last_signature.setter
    def last_signature(self, val):
        """ Set signature, ignore if signing via HMAC is disabled.

        :param bytes val: new signature
        """
        if self.auth_key:
            self._last_signature = binascii.hexlify(val)
        else:
            self._last_signature = None

    @property
    def secret_key(self):
        """ Secret encryption key.

        :rtype: bytes
        """
        return self._secret_key

    @secret_key.setter
    def secret_key(self, val):
        """ Set encryption key. Also changes the SecretBox for crypto-operations.

        :param bytes val: new encryption key
        """
        self._secret_key = val
        self.secret_box = nacl.secret.SecretBox(val)

    def init_hmac(self, force=False, dummy=False):
        """ Creates a new HMAC instance if possible.

        :param bool force: must return an HMAC handler, fails if not possible
        :param bool dummy: force return of dummy handler
        :rtype: hmac.HMAC
        :raises RuntimeError if force is True, but no auth_key available
        """
        if force and dummy:
            raise AttributeError('must not set both, force and dummy')
        if self.auth_key and not dummy:
            return get_auth_hmac_from_key(self.auth_key)
        else:
            if force:
                raise RuntimeError('no signature key given, but HMAC requested!')

            class HMACDummy:
                """ A dummy that ignores the applied actions. """
                update = staticmethod(lambda data: None)
                finalize = staticmethod(lambda: None)
                verify = staticmethod(lambda data: True)
            return HMACDummy

    def encrypt_stream(self, plain_file_object, read_total=None):
        """ Here the encryption happens in chunks (generator).

        The output size is the CHUNK SIZE, the chunks read are 40 bytes smaller to add nonce and chunk
        signature. HMAC signing of the full encrypted data is only done, if an auth_key is provided.
        The signature is then available in `self.last_signature`.

        :param BytesIO plain_file_object: input file
        :param int read_total: maximum bytes to read
        :return: encrypted chunks
        :rtype: bytes
        """
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)  # default way of creating a nonce in nacl
        auth_hmac = self.init_hmac()
        # nacl adds nonce (24bytes) and signature (16 bytes), so read 40 bytes less than desired output size
        for index, chunk in enumerate(_read_in_chunks(
                plain_file_object, chunk_size=CHUNK_SIZE - 40, read_total=read_total)
        ):
            enc = self.secret_box.encrypt(chunk, _chunk_nonce(nonce, index))
            auth_hmac.update(enc)
            yield enc
        self.last_signature = auth_hmac.finalize()

    def sign_stream(self, enc_file_object, read_total=None):
        """ Create HMAC for existing encrypted data stream.

        :param BytesIO enc_file_object: encrypted data
        :param int read_total: maximum bytes to read
        :return: signature, hex-serialized
        :rtype: bytes
        """
        auth_hmac = self.init_hmac(force=True)
        return sign_stream(auth_hmac, enc_file_object, read_total=read_total)

    def verify_stream(self, enc_file_object, signature, read_total=None):
        """ Verify HMAC signature for encrypted data stream.

        :param BytesIO enc_file_object: encrypted data
        :param bytes signature: hex-serialized signature
        :param int read_total: maximum bytes to read
        :return: validity
        :rtype: bool
        """
        auth_hmac = self.init_hmac(force=True)
        return verify_stream(auth_hmac, enc_file_object, signature, read_total=read_total)

    def decrypt_stream(self, enc_file_object, read_total=None, signature=None):
        """ Decrypt encrypted stream. (generator)

        If auth_key and signature is provided, HMAC verification is done automatically.

        :param BytesIO enc_file_object: encrypted data stream
        :param int read_total: maximum bytes to read
        :param signature: hex-serialized signature
        :return: plain data in chunks
        :rtype: bytes
        """
        sig_bytes = binascii.unhexlify(signature) if signature else None
        auth_hmac = self.init_hmac(force=signature is not None, dummy=signature is None)
        for chunk in _read_in_chunks(enc_file_object, read_total=read_total):
            auth_hmac.update(chunk)
            yield self.secret_box.decrypt(chunk)
        auth_hmac.verify(sig_bytes)

    @staticmethod
    def get_unenc_block_size(enc_block_size):
        """ Calculate how many unencrypted bytes amount to the desired encrypted amount.

        :param enc_block_size: desired encrypted number of bytes
        :return: size of unencrypted data
        :rtype: int
        :raises ValueError: if the target block size can not be created from the encryption chunk size.
        """
        if enc_block_size % CHUNK_SIZE:
            raise ValueError('can not divide %i by %i!' % (enc_block_size, CHUNK_SIZE))
        n_chunks = enc_block_size // CHUNK_SIZE
        return n_chunks * (CHUNK_SIZE - 40)

    def encrypt_keys_asymmetric(self, keypair):
        """ Use public key from asymmetric keypair to encrypt symmetric keys.

        Use `to_str=False` to generate binary instead of hexlified.

        :param AsymKeyPair keypair: cryptography SSL RSA key pair or similar, see AsymKeyPair
        :returns: tuple (encrypted secret key, encrypted auth key) where the latter might be None
        """
        enc_auth_key = None if not self.auth_key else keypair.encrypt(self.auth_key)
        enc_secret_key = keypair.encrypt(self.secret_key)
        return enc_secret_key, enc_auth_key

    def create_info(self, keypair=None):
        """ Create info dictionary, JSONifiable.

        Should it store unencrypted keys?
        If keypair is provided, they are encrypted by the public key.
        """
        enc_secret, enc_auth, signature = None, None, None
        if self.last_signature:
            signature = self.last_signature.decode()
        if keypair:
            enc_secret, enc_auth = self.encrypt_keys_asymmetric(keypair=keypair)
        info = OrderedDict([
            ('secret_key', enc_secret),
            ('auth_key', enc_auth),
            ('signature', signature),
        ])
        return info

    @classmethod
    def from_info(cls, info: dict, keypair: AsymKeyPair):
        """ Create handler from info dict. """
        auth_key = keypair.decrypt(info['auth_key']) if info['auth_key'] is not None else None
        secret_key = keypair.decrypt(info['secret_key'])
        inst = cls(secret_key, auth_key)
        inst._last_signature = info['signature'].encode()
        return inst


def pubkey_from_string(pubkey_str):
    """ Create a cryptography public SSL key instance from a public key string.

    :param str pubkey_str: public key string
    """
    return serialization.load_ssh_public_key(
        data=pubkey_str.encode(),
        backend=default_backend()
    )


def pubkey_from_file(path):
    """ Create a cryptography public SSL key instance from a public key file.

    :param str path: public key filepath
    """
    with open(path, 'r') as f_in:
        return pubkey_from_string(f_in.read())


def privkey_from_pemfile(path, password=None):
    """ Create a cryptography SSL private key instance from a PEM file (default SSH).

    :param str path: filepath
    :param bytearray password: private key passphrase (bytearray! Use getpass.getpass().encode() or similar)
    """
    with open(path, 'rb') as f_in:
        return serialization.load_pem_private_key(
            data=f_in.read(),
            password=password,
            backend=default_backend(),
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


def get_auth_hmac_from_key(auth_key):
    """ Default instanciation of HMAC

    :param bytes auth_key: secret key for signing data
    :rtype: hmac.HMAC
    """
    return hmac.HMAC(auth_key, hashes.SHA512(), backend=default_backend())


def sign_stream(auth_hmac, enc_file_object, read_total=None):
    """ Sign a stream with a given HMAC handler. Suitable for large amounts of data.

    :param hmac.HMAC auth_hmac: HMAC handler
    :param BytesIO enc_file_object: encrypted stream
    :param int read_total: optional size limit for read().
    :returns: hex-serialized signature
    :rtype: bytes
    """
    for chunk in _read_in_chunks(enc_file_object, read_total=read_total):
        auth_hmac.update(chunk)
    return binascii.hexlify(auth_hmac.finalize())


def verify_stream(auth_hmac, enc_file_object, signature, read_total=None):
    """ Verify signed encrypted stream. Suitable for large amounts of data.

    :param hmac.HMAC auth_hmac: HMAC handler
    :param BytesIO enc_file_object: encrypted byte stream
    :param bytes signature: hex-serialized signature
    :param int read_total: maximum bytes to read
    :return: whether signature is valid
    :rtype: bool
    """
    sig_bytes = binascii.unhexlify(signature)
    for chunk in _read_in_chunks(enc_file_object, read_total=read_total):
        auth_hmac.update(chunk)
    try:
        auth_hmac.verify(sig_bytes)
        return True
    except InvalidSignature:
        return False


def sign_bytesio(enc_message):
    """ Sign small and medium sized objects.

    Uses public/private keys, but the private keys is thrown away, as it is cheap to produce and
    there is no need to reuse.

    :param bytes enc_message: encrypted data
    :returns: hex-serialized verification key, signature
    :rtype: tuple
    """
    signing_key = nacl.signing.SigningKey.generate()  # throwaway, I verify_keys are stored locally
    signature = signing_key.sign(enc_message).signature
    verify_key_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    return verify_key_hex, signature


def verify_bytesio(enc_message, verify_key_hex, signature):
    """ Verify asymmetrically signed bytesreams.

    :param bytes enc_message: encrypted data
    :param bytes verify_key_hex: serialized verification key
    :param bytes signature: signature
    """
    verify_key = nacl.signing.VerifyKey(verify_key_hex, encoder=nacl.encoding.HexEncoder)
    try:
        verify_key.verify(enc_message, signature)
    except BadSignatureError:
        return False
    return True


def demo_asym_long():
    import json
    from io import BytesIO

    # 1. create a file to be encrypted
    # 2. create an asymmetric keypair to exchange the encryption keys
    # 3. encrypt the file
    # 4. provide the encryption info
    # 5. decrypt

    path_private_key, path_public_key, path_to_encrypt = _prepare_demo()

    # load the keypair - public needed for encryption, private for decryption
    keypair = AsymKeyPair(pubkey=pubkey_from_file(path_public_key))
    # or: keypair = AsymKeyPair(pubkey=pubkey_from_string(pubkey_string))
    # create CryptoHandler using throwaway keys. (alternative is derived key from password)
    handler = CryptoHandler.from_random(enable_auth_key=True)
    with open(path_to_encrypt + '.enc', 'wb') as f_out:
        with open(path_to_encrypt, 'rb') as f_in:
            for chunk in handler.encrypt_stream(f_in):
                f_out.write(chunk)
    # keypair is needed to encrypt the symmetric keys
    enc_info = handler.create_info(keypair=keypair)
    print(json.dumps(enc_info, indent=4))
    # print the real keys for comparison
    print('secret_key unencrypted:', binascii.hexlify(handler.secret_key).decode())
    print('auth_key unencrypted:', binascii.hexlify(handler.auth_key).decode())
    # delete all traces
    del keypair
    del handler
    # decrypt
    keypair = AsymKeyPair(privkey=privkey_from_pemfile(path_private_key))
    handler = CryptoHandler.from_info(enc_info, keypair=keypair)
    assert handler.last_signature is not None
    buffer = BytesIO()
    with open(path_to_encrypt + '.enc', 'rb') as f_in:
        for chunk in handler.decrypt_stream(f_in, signature=handler.last_signature):
            buffer.write(chunk)
    buffer.seek(0)
    decrypted = buffer.read().decode()
    assert decrypted == 'The cake is a lie!\n' * 10000
    import os
    for path in [path_private_key, path_public_key, path_to_encrypt]:
        os.remove(path)


def demo_asym_short():
    import json
    from io import BytesIO
    path_private_key, path_public_key, path_to_encrypt = _prepare_demo()
    # encrypt, using generated symmetric keys and public key
    keypair = AsymKeyPair(pubkey=pubkey_from_file(path_public_key))
    with open(path_to_encrypt + '.enc', 'wb+') as f_out:
        with open(path_to_encrypt, 'rb') as f_in:
            # enable_auth_key is optional. Check create_keys_from_password for more info
            for chunk in keypair.encrypt_stream(f_in, enable_auth_key=True):
                f_out.write(chunk)
        f_out.seek(0)
        print('encrypted (first 20):', binascii.hexlify(f_out.read(20)).decode())
    # exchange only enc_info (JSONifiable)
    enc_info = keypair.last_enc_info
    del keypair
    print(json.dumps(enc_info, indent=4))
    # decrypt, using symmetric keys retrieved via private key
    keypair = AsymKeyPair(privkey=privkey_from_pemfile(path_private_key))
    buffer = BytesIO()  # use BytesIO instead of yet another file
    with open(path_to_encrypt + '.enc', 'rb') as f_in:
        for chunk in keypair.decrypt_stream(f_in, enc_info):
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
    # enable_auth_key is optional
    derived_keys = create_keys_from_password(password, enable_auth_key=True)
    handler = CryptoHandler.from_derived_keys(derived_keys)
    with open(path_to_encrypt + '.enc', 'wb+') as f_out:
        with open(path_to_encrypt, 'rb') as f_in:
            for chunk in handler.encrypt_stream(f_in):
                f_out.write(chunk)
        f_out.seek(0)
        print('encrypted (first 20):', binascii.hexlify(f_out.read(20)).decode())
    # store public information
    signature = handler.last_signature  # for validation
    key_setup = derived_keys.setup  # for key creation
    # remove handler
    del handler
    del derived_keys
    # decrypt
    derived_keys = create_keys_from_password(
        password, enable_auth_key=True, setup=key_setup)
    handler = CryptoHandler.from_derived_keys(derived_keys)
    buffer = BytesIO()  # use BytesIO instead of yet another file
    with open(path_to_encrypt + '.enc', 'rb') as f_in:
        for chunk in handler.decrypt_stream(f_in, signature=signature):
            buffer.write(chunk)
    buffer.seek(0)
    decrypted = buffer.read().decode()
    assert decrypted == 'The cake is a lie!\n' * 10000
    os.remove(path_to_encrypt)


if __name__ == '__main__':
    demo_asym_long()
    demo_asym_short()
    demo_sym()
