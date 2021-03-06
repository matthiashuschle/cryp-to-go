import pytest
from unittest.mock import patch
from io import BytesIO
import os
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import nacl.utils
import nacl.secret
import nacl.pwhash
from cryp_to_go import core

SIZE_BUFFER_A = 1200


@pytest.fixture
def content_a():
    return 'IDDQD\n'.encode() * 200


@pytest.fixture
def buffer_a(content_a):
    content = content_a
    buffer = BytesIO()
    buffer.write(content)
    total_size = buffer.tell()
    assert total_size == SIZE_BUFFER_A
    return buffer


def test_get_unenc_block_size():
    # if block_size == chunk size, it must be chunk_size - 40
    assert core.get_unenc_block_size(core.CHUNK_SIZE) == core.CHUNK_SIZE - 40
    # try chunk size 100 and block size 2000. That's 20 blocks of 60 unencrypted
    with patch('cryp_to_go.core.CHUNK_SIZE', 100):
        assert core.get_unenc_block_size(2000) == SIZE_BUFFER_A
    # impossible task: read block size not alignable with chunk size
    with patch('cryp_to_go.core.CHUNK_SIZE', 100):
        with pytest.raises(ValueError):
            core.get_unenc_block_size(150)


def test_hexlify():
    assert b'foo\0' == core.unhexlify(core.hexlify(b'foo\0'))
    assert 'abacadae' == core.hexlify(core.unhexlify('abacadae'))


def test_get_chunk_nonce():
    base = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    assert core._get_chunk_nonce(base, 0) != core._get_chunk_nonce(base, 1)
    assert core._get_chunk_nonce(base, 0) == core._get_chunk_nonce(base, 0)
    assert core._get_chunk_nonce(base, 0) == base
    assert core._get_chunk_nonce(base, 1) != base
    assert len(core._get_chunk_nonce(base, 1)) == len(base)


def test_read_in_chunks(content_a, buffer_a):
    buffer = buffer_a
    content = content_a
    # read with different chunk sizes
    for chunk_size in [None, 10, 100, 10000]:
        buffer.seek(0)
        chunks = [x for x in core._read_in_chunks(buffer, chunk_size=chunk_size)]
        assert all(len(x) == chunk_size for x in chunks[:-1])
        assert sum(len(x) for x in chunks) == SIZE_BUFFER_A
        assert b''.join(chunks) == content
    # try different read_total
    buffer.seek(0)
    chunks = [x for x in core._read_in_chunks(buffer, chunk_size=100, read_total=80)]
    assert len(chunks) == 1
    assert len(chunks[0]) == 80
    assert buffer.tell() == 80
    assert b''.join(chunks) == content[:80]
    buffer.seek(0)
    chunks = [x for x in core._read_in_chunks(buffer, chunk_size=100, read_total=250)]
    assert len(chunks) == 3
    assert len(chunks[0]) == 100
    assert len(chunks[1]) == 100
    assert len(chunks[2]) == 50
    assert buffer.tell() == 250
    assert b''.join(chunks) == content[:250]
    buffer.seek(0)
    chunks = [x for x in core._read_in_chunks(buffer, chunk_size=10000, read_total=250)]
    assert len(chunks) == 1
    assert len(chunks[0]) == 250
    assert buffer.tell() == 250
    assert b''.join(chunks) == content[:250]


def test_sign_verify(content_a, buffer_a):
    content, buffer = content_a, buffer_a
    # succeed unlimited read
    buffer.seek(0)
    key_sign = core.CryptoHandler.create_random(enable_signature_key=True).key_sign
    signature = core.sign_stream(key_sign, buffer)
    buffer.seek(0)
    core.verify_stream(key_sign, buffer, signature)
    # repeat, should create same signature
    buffer.seek(0)
    assert signature == core.sign_stream(key_sign, buffer)
    # try different sign key
    buffer.seek(0)
    sign_key_2 = core.CryptoHandler.create_random(enable_signature_key=True).key_sign
    signature_2 = core.sign_stream(sign_key_2, buffer)
    assert signature_2 != signature
    # use wrong signature
    buffer.seek(0)
    assert not core.verify_stream(key_sign, buffer, signature_2)
    buffer.seek(0)
    assert not core.verify_stream(sign_key_2, buffer, signature)
    # succeed limited read
    buffer.seek(0)
    signature_3 = core.sign_stream(key_sign, buffer, read_total=600)
    buffer.seek(0)
    core.verify_stream(key_sign, buffer, signature_3, read_total=600)
    # check if signature differs
    assert signature_3 != signature
    buffer.seek(0)
    # read wrong size -> fail
    assert not core.verify_stream(key_sign, buffer, signature_3, read_total=599)


def _touch_temp_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return path


def test_inflate_string():
    test_str = 'abcdefgh'
    inflated = core.inflate_string(test_str)
    assert inflated[:8] == b'abcdefgh'
    assert inflated[8] == 0
    assert len(inflated) > 30
    test_str = 'abcdefgh' * 10
    inflated = core.inflate_string(test_str)
    assert inflated[:80] == b'abcdefgh' * 10
    assert inflated[80] == 0
    assert len(inflated) > 90


def test_deflate_string():
    test_str = 'abcdefgh'
    inflated = core.inflate_string(test_str)
    assert core.deflate_string(inflated) == test_str
    test_str = 'abcdefgh' * 10
    inflated = core.inflate_string(test_str)
    assert core.deflate_string(inflated) == test_str


@pytest.fixture()
def path_asym_keys():
    # generate a keypair
    asym_key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    path_private_key = _touch_temp_file()
    with open(path_private_key, 'wb') as f_out:
        f_out.write(
            asym_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
        )
    path_public_key = _touch_temp_file()
    with open(path_public_key, 'wb') as f_out:
        f_out.write(
            asym_key.public_key().public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH
            )
        )
    return path_private_key, path_public_key


class TestAsymKey:

    def test_constructors(self, path_asym_keys):
        path_privkey, path_pubkey = path_asym_keys
        privkey = core.AsymKey.privkey_from_pemfile(path_privkey)
        pubkey = core.AsymKey.from_pubkey_file(path_pubkey)
        assert privkey.key is not None
        assert pubkey.key is not None
        with open(path_pubkey, 'r') as f_in:
            pubkey_2 = core.AsymKey.from_pubkey_string(f_in.read())
        assert pubkey_2.key.public_numbers() == pubkey.key.public_numbers()
        assert pubkey.key.public_numbers() == privkey.key.public_key().public_numbers()

    def test_encrypt_decrypt(self, path_asym_keys):
        path_privkey, path_pubkey = path_asym_keys
        privkey = core.AsymKey.privkey_from_pemfile(path_privkey)
        pubkey = core.AsymKey.from_pubkey_file(path_pubkey)
        assert privkey.decrypt(pubkey.encrypt(b'foobar')) == b'foobar'


class TestDerivedKeySetup:

    def test_general(self):
        dks = core.KeyDerivationSetup.create_default(enable_signature_key=True)
        # override defaults for faster tests
        dks.ops = nacl.pwhash.argon2i.OPSLIMIT_MIN
        dks.mem = nacl.pwhash.argon2i.MEMLIMIT_MIN
        password_1 = b'supersecret_1'
        password_2 = b'supersecret_2'
        derived_keys = dks.generate_keys(password_1)
        derived_keys_1b = dks.generate_keys(password_1)
        assert derived_keys.key_enc == derived_keys_1b.key_enc
        assert derived_keys.key_sign == derived_keys_1b.key_sign
        assert dks.to_dict() == core.KeyDerivationSetup.from_dict(dks.to_dict()).to_dict()
        derived_keys_2 = dks.generate_keys(password_2)
        assert derived_keys_2.key_enc != derived_keys.key_enc
        assert derived_keys_2.key_sign != derived_keys.key_sign
        assert derived_keys.key_enc != derived_keys.key_sign
        # create with a different salt
        dks2 = core.KeyDerivationSetup.create_default(enable_signature_key=False)
        # override defaults for faster tests
        dks2.ops = nacl.pwhash.argon2i.OPSLIMIT_MIN
        dks2.mem = nacl.pwhash.argon2i.MEMLIMIT_MIN
        assert dks2.generate_keys(password_1).key_enc != derived_keys.key_enc
        # serialize and deserialize
        dks3 = core.KeyDerivationSetup.from_dict(dks.to_dict())
        assert dks3.generate_keys(password_1).key_enc == derived_keys.key_enc


class TestCryptoHandler:

    def test_init(self):
        # no signature key
        handler = core.CryptoHandler.create_random(enable_signature_key=False)
        assert len(handler.key_enc)
        assert handler.key_sign is None
        # with signature key
        handler = core.CryptoHandler.create_random(enable_signature_key=True)
        assert len(handler.key_enc)
        assert handler.key_sign is not None and len(handler.key_sign)
        handler2 = core.CryptoHandler(handler.key_enc, handler.key_sign)
        assert handler.key_enc == handler2.key_enc
        assert handler.key_sign == handler2.key_sign

    def test_de_encrypt(self, buffer_a, content_a):
        # no signature key
        handler = core.CryptoHandler.create_random(enable_signature_key=False)
        buffer_a.seek(0)
        buffer_out = BytesIO()
        for chunk in handler.encrypt_stream(buffer_a):
            buffer_out.write(chunk)
        buffer_out.seek(0)
        assert b''.join(handler.decrypt_stream(buffer_out)) == content_a
        assert handler.signature is None
        # use signature key
        buffer_a.seek(0)
        buffer_out = BytesIO()
        for chunk in handler.encrypt_stream(buffer_a):
            buffer_out.write(chunk)
        buffer_out.seek(0)
        assert b''.join(handler.decrypt_stream(buffer_out)) == content_a
        assert handler.signature is None
        # create signature
        buffer_a.seek(0)
        buffer_out = BytesIO()
        with handler.create_signature():
            for chunk in handler.encrypt_stream(buffer_a):
                buffer_out.write(chunk)
        buffer_out.seek(0)
        assert b''.join(handler.decrypt_stream(buffer_out)) == content_a
        assert handler.signature is None

    def test_signature(self, buffer_a, content_a):
        # no signature key
        handler = core.CryptoHandler.create_random(enable_signature_key=False)
        buffer_a.seek(0)
        buffer_out = BytesIO()
        with handler.create_signature():
            for chunk in handler.encrypt_stream(buffer_a):
                buffer_out.write(chunk)
        signature = handler.signature
        assert signature is None
        # use signature key
        handler = core.CryptoHandler.create_random(enable_signature_key=True)
        buffer_a.seek(0)
        buffer_out_1 = BytesIO()
        with handler.create_signature():
            for chunk in handler.encrypt_stream(buffer_a):
                buffer_out_1.write(chunk)
        signature_1 = handler.signature
        assert signature_1 is not None
        buffer_a.seek(0)
        buffer_out_2 = BytesIO()
        with handler.create_signature():
            for chunk in handler.encrypt_stream(buffer_a, read_total=SIZE_BUFFER_A - 100):
                buffer_out_2.write(chunk)
        signature_2 = handler.signature
        assert signature_2 is not None
        assert signature_1 != signature_2
        with handler.verify_signature(signature_1):
            buffer_out_1.seek(0)
            decrypted_1 = b''.join(handler.decrypt_stream(buffer_out_1))
        assert decrypted_1 == content_a
        with handler.verify_signature(signature_2):
            buffer_out_2.seek(0)
            decrypted_2 = b''.join(handler.decrypt_stream(buffer_out_2))
        assert decrypted_2 == content_a[:SIZE_BUFFER_A - 100]
        with pytest.raises(InvalidSignature):
            # wrong signature
            with handler.verify_signature(signature_1):
                buffer_out_2.seek(0)
                b''.join(handler.decrypt_stream(buffer_out_2))

    def test_decrypt_info(self, content_a, buffer_a, path_asym_keys):
        privkey = core.AsymKey.privkey_from_pemfile(path_asym_keys[0])
        pubkey = core.AsymKey.from_pubkey_file(path_asym_keys[1])
        # no signature key
        handler = core.CryptoHandler.create_random(enable_signature_key=False)
        buffer_a.seek(0)
        buffer_out = BytesIO()
        with handler.create_signature():
            for chunk in handler.encrypt_stream(buffer_a):
                buffer_out.write(chunk)
        decrypt_info = handler.to_decrypt_info(pubkey)
        buffer_out.seek(0)
        with handler.decryptor_from_info(decrypt_info, privkey) as handler_decrypt:
            assert b''.join(handler_decrypt.decrypt_stream(buffer_out)) == content_a
        # with signature key, same usage, automatic checks
        handler = core.CryptoHandler.create_random(enable_signature_key=True)
        buffer_a.seek(0)
        buffer_out = BytesIO()
        with handler.create_signature():
            for chunk in handler.encrypt_stream(buffer_a):
                buffer_out.write(chunk)
        decrypt_info = handler.to_decrypt_info(pubkey)
        buffer_out.seek(0)
        with handler.decryptor_from_info(decrypt_info, privkey) as handler_decrypt:
            assert b''.join(handler_decrypt.decrypt_stream(buffer_out)) == content_a
        # wrong signature
        buffer_a.seek(0)
        buffer_out = BytesIO()
        with handler.create_signature():
            for chunk in handler.encrypt_stream(buffer_a, read_total=SIZE_BUFFER_A - 100):
                buffer_out.write(chunk)
        with pytest.raises(InvalidSignature):
            buffer_out.seek(0)
            with handler.decryptor_from_info(decrypt_info, privkey) as handler_decrypt:
                assert b''.join(handler_decrypt.decrypt_stream(buffer_out)) == content_a[:SIZE_BUFFER_A - 100]

    def test_de_encrypt_snippets(self, buffer_a, content_a):
        handler = core.CryptoHandler.create_random(enable_signature_key=False)
        assert handler.decrypt_snippet(handler.encrypt_snippet(content_a)) == content_a
        assert handler.signature is None
        # use signature key
        handler = core.CryptoHandler.create_random(enable_signature_key=True)
        enc = handler.encrypt_snippet(content_a)
        signature = handler.signature
        assert signature is not None
        assert handler.decrypt_snippet(enc, signature=signature) == content_a
        # wrong signature - re-encrypting uses different nonces
        enc_anew = handler.encrypt_snippet(content_a)
        with pytest.raises(InvalidSignature):
            handler.decrypt_snippet(enc_anew, signature=signature)
