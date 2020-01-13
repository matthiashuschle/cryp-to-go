import os
import pytest
import tempfile
from peewee import IntegrityError
from cryp_to_go import interface, core


@pytest.fixture
def temp_sqlite_path():
    path = os.path.join(tempfile.gettempdir(), 'temp_testdb.sqlite')
    try:
        os.remove(path)
    except OSError:
        if os.path.exists(path):
            raise
    return path


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
