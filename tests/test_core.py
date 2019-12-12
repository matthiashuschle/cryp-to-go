import pytest
from unittest.mock import patch
from io import BytesIO
import os
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import nacl.utils
import nacl.secret
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
    sign_key = core.CryptoHandler.from_random(enable_signature_key=True).sign_key
    signature = core.sign_stream(sign_key, buffer)
    buffer.seek(0)
    core.verify_stream(sign_key, buffer, signature)
    # repeat, should create same signature
    buffer.seek(0)
    assert signature == core.sign_stream(sign_key, buffer)
    # try different sign key
    buffer.seek(0)
    sign_key_2 = core.CryptoHandler.from_random(enable_signature_key=True).sign_key
    signature_2 = core.sign_stream(sign_key_2, buffer)
    assert signature_2 != signature
    # use wrong signature
    buffer.seek(0)
    assert not core.verify_stream(sign_key, buffer, signature_2)
    buffer.seek(0)
    assert not core.verify_stream(sign_key_2, buffer, signature)
    # succeed limited read
    buffer.seek(0)
    signature_3 = core.sign_stream(sign_key, buffer, read_total=600)
    buffer.seek(0)
    core.verify_stream(sign_key, buffer, signature_3, read_total=600)
    # check if signature differs
    assert signature_3 != signature
    buffer.seek(0)
    # read wrong size -> fail
    assert not core.verify_stream(sign_key, buffer, signature_3, read_total=599)


def _touch_temp_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return path

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

    pass


# @pytest.fixture(scope='module')
# def encrypt_file_path():
#     # create file to encrypt
#     path_to_encrypt = _touch()
#     with open(path_to_encrypt, 'w') as f_out:
#         f_out.write('The cake is a lie!\n' * 10000)
#     # generate a keypair
#     asym_key = rsa.generate_private_key(
#         backend=default_backend(),
#         public_exponent=65537,
#         key_size=2048
#     )
#     path_private_key = _touch()
#     with open(path_private_key, 'wb') as f_out:
#         f_out.write(
#             asym_key.private_bytes(
#                 serialization.Encoding.PEM,
#                 serialization.PrivateFormat.PKCS8,
#                 serialization.NoEncryption()
#             )
#         )
#     path_public_key = _touch()
#     with open(path_public_key, 'wb') as f_out:
#         f_out.write(
#             asym_key.public_key().public_bytes(
#                 serialization.Encoding.OpenSSH,
#                 serialization.PublicFormat.OpenSSH
#             )
#         )
#     return path_private_key, path_public_key, path_to_encrypt
#
#
# @pytest.fixture(scope='module')
# def _keypair():
#     # create temporary file and close
#     def _touch():
#         fd, path = tempfile.mkstemp()
#         os.close(fd)
#         return path
#
#
#
# @pytest.fixture(scope='module')
# def keypair():
#
# class MyTestCase(unittest.TestCase):
#     def test_something(self):
#         self.assertEqual(True, False)
#
#
# if __name__ == '__main__':
#     unittest.main()
# #