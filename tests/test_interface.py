import os
from contextlib import contextmanager
import pytest
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from peewee import IntegrityError
from cryp_to_go import interface, core


CONTENT = """\
Im Frühtau zu Berge wir ziehn,fallera,
es grünen alle Wälder, alle Höh'n, fallera.
"""


@pytest.fixture
def temp_sqlite_path():
    path = os.path.join(tempfile.gettempdir(), 'temp_testdb.sqlite')
    try:
        os.remove(path)
    except OSError:
        if os.path.exists(path):
            raise
    return path


def generate_keypair():
    # create temporary file and close
    def _touch():
        fd, path = tempfile.mkstemp()
        os.close(fd)
        return path

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
    return path_private_key, path_public_key

@contextmanager
def temporary_file_structure():
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = None
    with tempfile.TemporaryDirectory() as path:
        os.chdir(path)
        with open(os.path.join(path, 'foo100.dat'), 'w') as f_out:
            f_out.write(CONTENT * 100)
        with open(os.path.join(path, 'foo200.dat'), 'w') as f_out:
            f_out.write(CONTENT * 200)
        open(os.path.join(path, 'foo_empty.dat'), 'wb').close()
        os.makedirs(os.path.join(path, 'subdir'))
        with open(os.path.join(path, 'subdir', 'foo300.dat'), 'w') as f_out:
            f_out.write(CONTENT * 300)
        yield path
        if cwd:
            os.chdir(cwd)


class TestSQLiteFileInterface:

    @pytest.mark.parametrize("use_signatures", [(True,), (False,)])
    def test_key_storage(self, temp_sqlite_path, use_signatures):
        inst = interface.SQLiteFileInterface(
            temp_sqlite_path
        )
        kds = core.KeyDerivationSetup.create_minimal(enable_signature_key=use_signatures)
        inst.store_key_derivation_setup(kds)
        crypto_handler_a = kds.generate_keys(b'foo')
        del kds
        del inst
        inst = interface.SQLiteFileInterface(
            temp_sqlite_path
        )
        inst.load_crypto_handler(b'foo')
        assert inst.crypto_handler.key_enc == crypto_handler_a.key_enc
        assert inst.crypto_handler.key_sign == crypto_handler_a.key_sign
        kds2 = core.KeyDerivationSetup.create_minimal(enable_signature_key=use_signatures)
        with pytest.raises(IntegrityError):
            # storing two setups fails due to UNIQUE constraint
            inst.store_key_derivation_setup(kds2)

    @pytest.mark.parametrize("use_signatures", [(True,), (False,)])
    def test_new_crypto_handler(self, temp_sqlite_path, use_signatures):
        inst = interface.SQLiteFileInterface(
            temp_sqlite_path
        )
        inst._key_derivation_factory = core.KeyDerivationSetup.create_minimal
        inst.use_new_crypto_handler(b'foo', use_signatures=use_signatures)
        crypto_handler_a = inst.crypto_handler
        del inst
        inst = interface.SQLiteFileInterface(
            temp_sqlite_path
        )
        inst.load_crypto_handler(b'foo')
        assert inst.crypto_handler.key_enc == crypto_handler_a.key_enc
        assert inst.crypto_handler.key_sign == crypto_handler_a.key_sign

    def test_chunked(self):
        class SingleUseIterator:

            def __init__(self, size):
                self.values = list(range(size))
                self.done = False
                self.current = 0

            def __iter__(self):
                if self.done:
                    raise RuntimeError('iterator is consumed')
                return self

            def __next__(self):
                try:
                    val = self.values[self.current]
                except IndexError:
                    self.done = True
                    raise StopIteration
                self.current += 1
                return val

        sui = SingleUseIterator(6)
        for i_chunk, chunk in enumerate(interface.SQLiteFileInterface._chunked(sui, 2)):
            assert not sui.done
            assert chunk == [i_chunk * 2, i_chunk * 2 + 1]
        assert sui.done
        sui = SingleUseIterator(5)
        for i_chunk, chunk in enumerate(interface.SQLiteFileInterface._chunked(sui, 3)):
            if i_chunk == 0:
                assert not sui.done
                assert chunk == [0, 1, 2]
            else:
                assert sui.done
                assert chunk == [3, 4]
        assert sui.done

    @pytest.mark.parametrize("use_signatures", [(True,), (False,)])
    def test_file_storage(self, use_signatures, temp_sqlite_path):
        crypto_handler = core.CryptoHandler.create_random(enable_signature_key=use_signatures)
        with temporary_file_structure() as dirname:
            sqlite_path = os.path.join(dirname, 'test_sqlite_file_storage.sqlite')
            try:
                os.remove(sqlite_path)
            except OSError:
                if os.path.exists(sqlite_path):
                    raise
            inst = interface.SQLiteFileInterface(temp_sqlite_path, crypto_handler)

            def resolve(basename):
                return os.path.join(dirname, basename)

            # test exceptions for invalid paths/files
            with pytest.raises(ValueError, match='does not start with'):
                inst.store_files([tempfile.gettempdir()])
            with pytest.raises(OSError, match='missing file') as exc_info:
                inst.store_files([resolve('foo_idonotexist.weirdfileending'), resolve('foo100.dat')])
            assert 'foo_idonotexist.weirdfileending' in exc_info.value.args[0]
            assert 'foo100' not in exc_info.value.args[0]
            with pytest.raises(OSError, match='target is not a file: ') as exc_info:
                inst.store_files([resolve('subdir'), resolve('foo100.dat')])
            assert 'subdir' in exc_info.value.args[0]
            assert 'foo100' not in exc_info.value.args[0]
            with pytest.raises(ValueError, match='not allowed') as exc_info:
                inst.store_files([resolve(os.path.join('subdir', '..', 'subdir', 'foo300.dat')), resolve('foo100.dat')])
            assert '..' in exc_info.value.args[0]
            assert 'foo100' not in exc_info.value.args[0]

            # test actual file storage
            inst.store_files([
                resolve('foo100.dat'),
                resolve(os.path.join('subdir', 'foo300.dat')),
                resolve('foo_empty.dat')
            ])
            del inst
        inst = interface.SQLiteFileInterface(temp_sqlite_path, crypto_handler)
        files = [x['path'] for x in inst.read_file_index()]
        with tempfile.TemporaryDirectory() as path:
            os.chdir(path)
            inst.restore_files(files)
            assert os.path.exists('foo100.dat')
            assert not os.path.exists('foo200.dat')
            assert os.path.exists(os.path.join('subdir', 'foo300.dat'))
            with open('foo100.dat', 'r') as f_in:
                assert f_in.read() == CONTENT * 100
            with open(os.path.join('subdir', 'foo300.dat'), 'r') as f_in:
                assert f_in.read() == CONTENT * 300

    @pytest.mark.parametrize("use_signatures", [(True,), (False,)])
    def test_value_storage(self, use_signatures, temp_sqlite_path):
        crypto_handler = core.CryptoHandler.create_random(enable_signature_key=use_signatures)
        inst = interface.SQLiteFileInterface(temp_sqlite_path, crypto_handler)
        inst.store_single_value('foo', b'bar')
        ix = inst.read_file_index()
        assert len(ix) == 1
        assert 'foo' in {x['path'] for x in ix}
        inst.store_values({
            'fooo': b'baar',
            'foooo': b'baaar',
        })
        ix = inst.read_file_index()
        assert len(ix) == 3
        assert {'foo', 'fooo', 'foooo'} == {x['path'] for x in ix}
        inst.store_single_value('foo', b'baz', replace=True)
        ix = inst.read_file_index()
        assert len(ix) == 3
        assert {'foo', 'fooo', 'foooo'} == {x['path'] for x in ix}
        with pytest.raises(RuntimeError):
            inst.store_single_value('foo', b'baaz', replace=False)
        ix = inst.read_file_index()
        assert len(ix) == 3
        assert {'foo', 'fooo', 'foooo'} == {x['path'] for x in ix}
        assert inst.restore_single_file(ix[0]['file_id']) == b'baar'
        assert inst.restore_files(['foo', 'fooo']) == {
            'foo': b'baz',
            'fooo': b'baar',
        }

    @pytest.mark.parametrize("use_signatures", [(True,), (False,)])
    def test_key_storage_async(self, use_signatures, temp_sqlite_path):
        path_privkey_1, path_pubkey_1 = generate_keypair()
        path_privkey_2, path_pubkey_2 = generate_keypair()
        privkey_1 = core.AsymKey.privkey_from_pemfile(path_privkey_1)
        privkey_2 = core.AsymKey.privkey_from_pemfile(path_privkey_2)
        pubkey_1 = core.AsymKey.from_pubkey_file(path_pubkey_1)
        pubkey_2 = core.AsymKey.from_pubkey_file(path_pubkey_2)
        inst = interface.SQLiteFileInterface(
            temp_sqlite_path,
            core.CryptoHandler.create_random(use_signatures),
        )
        # store single key
        inst.store_single_value('foo', b'bar')
        inst.store_keys_asymmetric(pubkey_1)
        t_key_enc = inst.crypto_handler.key_enc
        t_key_sign = inst.crypto_handler.key_sign
        del inst
        inst = interface.SQLiteFileInterface(
            temp_sqlite_path,
        )
        inst.load_crypto_handler_async(privkey_1)
        assert inst.crypto_handler.key_enc == t_key_enc
        assert inst.crypto_handler.key_sign == t_key_sign
        # store another key
        inst.store_keys_asymmetric(pubkey_2)
        del inst
        inst = interface.SQLiteFileInterface(
            temp_sqlite_path,
        )
        inst.load_crypto_handler_async(privkey_1)
        assert inst.crypto_handler.key_enc == t_key_enc
        assert inst.crypto_handler.key_sign == t_key_sign
        del inst
        inst = interface.SQLiteFileInterface(
            temp_sqlite_path,
        )
        inst.load_crypto_handler_async(privkey_2)
        assert inst.crypto_handler.key_enc == t_key_enc
        assert inst.crypto_handler.key_sign == t_key_sign
