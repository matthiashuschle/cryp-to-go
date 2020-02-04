import os
import pathlib
import json
from io import BytesIO
from contextlib import contextmanager
from typing import Union, Tuple, Iterable, Generator, TypeVar, Sequence, Mapping, BinaryIO, Any
from peewee import SqliteDatabase, DoesNotExist
from .database import SQLiteHandler
from .db_models import Settings, Files, Chunks, AsymKeys
from .core import (
    KeyDerivationSetup,
    inflate_string,
    deflate_string,
    CryptoHandler,
    AsymKey,
)

T = TypeVar('T')
_KEY_DERIVATION_SETUP = 'key_derivation_setup'


class SQLiteFileInterface:

    def __init__(self, sqlite_file: str, crypto_handler: Union[None, CryptoHandler] = None):
        """ Abstraction layer for SQLite storage. """
        self.sql_handler = SQLiteHandler(sqlite_file)
        self.crypto_handler = crypto_handler
        self._key_derivation_factory = KeyDerivationSetup.create_default

    def store_key_derivation_setup(self, kds: KeyDerivationSetup) -> None:
        """ Save the setup of the key derivation in the Settings table. """
        with self.sql_handler.open_db() as database:
            with database.atomic():
                Settings.create(
                    key=_KEY_DERIVATION_SETUP,
                    value=json.dumps(kds.to_dict())
                )

    def has_key_derivation_info(self) -> bool:
        """ Checks if key derivation info is available. """
        with self.sql_handler.open_db():
            try:
                Settings.get(Settings.key == _KEY_DERIVATION_SETUP)
                return True
            except DoesNotExist:
                return False

    def store_keys_asymmetric(self, pubkey: AsymKey) -> None:
        """ Save the encryption and signature keys asymmetrically.

        They are stored hexlified and in a JSON-string in the AsymKeys table.
        """
        with self.sql_handler.open_db() as database:
            with database.atomic():
                AsymKeys.create(
                    value=json.dumps(self.crypto_handler.to_decrypt_info(pubkey, skip_signature=True)),
                )

    def load_crypto_handler_async(self, privkey: AsymKey) -> None:
        """ Load encryption and signature keys from the AsymKeys table.

        - Sets `self.crypto_handler`
        - Tries all existing entries until one does not raise an exception on decryption.
        """
        with self.sql_handler.open_db():
            for row in AsymKeys.select(AsymKeys.value):
                try:
                    self.crypto_handler = CryptoHandler.from_info(json.loads(row.value), privkey)
                    break
                except ValueError as exc:
                    if exc.args[0] != "Decryption failed.":
                        raise

    def load_crypto_handler(self, password: bytes) -> None:
        """ Creates handler from the key derivation settings and password.

        - settings are loaded from the Settings table
        - sets `self.crypto_handler`
        """
        with self.sql_handler.open_db():
            kds = KeyDerivationSetup.from_dict(
                json.loads(Settings.get(Settings.key == _KEY_DERIVATION_SETUP).value)
            )
        self.crypto_handler = kds.generate_keys(password)

    def use_new_crypto_handler(self, password: bytes, use_signatures: bool = False) -> None:
        """ Create new crypto handler with keys derived via password.

        - sets `self.crypto_handler`
        - creates new key derivations setup (default) and stores it in Settings table
        """
        kds = self._key_derivation_factory(enable_signature_key=use_signatures)
        self.store_key_derivation_setup(kds)
        self.crypto_handler = kds.generate_keys(password)

    def assert_crypto_handler(self) -> None:
        if self.crypto_handler is None:
            raise RuntimeError('crypto_handler must be set for this operation. '
                               'Set in constructor, manually, or per load_crypto_handler '
                               'or use_new_crypto_handler.')

    def store_values(self, value_dict: Mapping[str, bytes], replace: bool = False) -> Mapping[str, Tuple[int, bytes]]:
        """ Store the key-value pairs of `value_dict` encrypted.

        - Stored along physical files in the Files and Chunks tables
        - attribute `is_physical_file` is `False`
        - `replace` needs to be `True` to replace existing keys
        - raises RuntimeError otherwise
        - return dict maps keys from `value_dict` to pairs of `Files.file_id`
            and signature (`None` if no `self.crypto_handler.key_sign`)
        """
        enc_info = {}
        for key, value in value_dict.items():
            file_id = self.store_single_value(key, value, replace=replace)
            enc_info[key] = (file_id, self.crypto_handler.signature)
        return enc_info

    def store_files(self, file_list: Sequence[str]) -> Mapping[str, Tuple[int, bytes]]:
        """ Store encrypted files.

        - elements of `file_list` must be absolute file paths
        - only paths in or below current working directory are allowed
        """
        cwd = pathlib.PurePath(os.getcwd())
        file_list = [os.path.join(str(cwd), x) if not os.path.isabs(x) else x for x in file_list]
        paths = [pathlib.Path(x) for x in file_list]
        if not all(x.exists() for x in paths):
            raise OSError(
                'missing file: ' + repr([x for x in file_list if not pathlib.Path(x).exists()]))
        relative_paths = [pathlib.PurePath(x).relative_to(cwd) for x in file_list]
        if any(x.is_dir() for x in paths):
            raise OSError(
                'target is not a file: ' + repr([x for x in paths if x.is_dir()]))
        if any('..' in x.parts for x in relative_paths):
            raise ValueError(
                '".." not allowed in target path: '
                + repr([x for x in relative_paths if '..' in x.parts])
            )
        enc_info = {}
        for file in relative_paths:
            file_id = self.store_single_file(file)
            enc_info[file] = (file_id, self.crypto_handler.signature)
        return enc_info

    @contextmanager
    def _reader_encrypt_file(
            self,
            file: str,
            outfile: Union[str, None] = None
    ) -> Generator[Tuple[SqliteDatabase, Files, BinaryIO], None, None]:
        """ Context manager for file encryption stream to Chunks table.
        """
        with self.sql_handler.open_db() as db:
            with db.atomic():
                file_entry = Files.create(
                    path=self.crypto_handler.encrypt_snippet(inflate_string(str(file))),
                    encrypted_file_path=outfile,
                )
            with open(file, 'rb') as stream_in:
                with self.crypto_handler.create_signature():
                    yield db, file_entry, stream_in

    def _generate_enc_chunks(self, stream_in: BinaryIO, file_id: int) -> Generator[Chunks, None, None]:
        """ Transform the chunk stream from CryptoHandler to Chunk table row. """
        for i_chunk, enc_chunk in enumerate(self.crypto_handler.encrypt_stream(stream_in)):
            yield Chunks(
                fk_file_id=file_id,
                i_chunk=i_chunk,
                content=enc_chunk,
            )

    @staticmethod
    def _chunked(it: Iterable[T], chunk_size: int) -> Generator[Sequence[T], None, None]:
        """ Lazily create chunks from an iterator.

        Used to enable batch inserts to Chunks table without
        actually reading the full streams first.

        :param it: any iterable. Will be consumed step by step once.
        :param chunk_size: how many elements to group in a single chunk.
        """
        current_chunk = []
        for element in it:
            current_chunk.append(element)
            if len(current_chunk) == chunk_size:
                yield current_chunk
                current_chunk = []
        if len(current_chunk):
            yield current_chunk

    def drop_file(self, file_id: int) -> None:
        """ Delete a file from Fiels and Chunks tables. """
        with self.sql_handler.open_db() as db:
            with db.atomic():
                Chunks.delete().where(Chunks.fk_file_id == file_id).execute()
                Files.delete().where(Files.file_id == file_id).execute()

    def store_single_value(self, key: str, value: bytes, replace: bool = False) -> int:
        """ Store value as file with key as path.

        Returns created Files.file_id.
        """
        file_index = self.read_file_index()
        for file in file_index:
            if file['path'] == key:
                if replace:
                    self.drop_file(file['file_id'])
                else:
                    raise RuntimeError('file with key %s already exists.' % key)
        with self.sql_handler.open_db() as db:
            with db.atomic():
                file_entry = Files.create(
                    path=self.crypto_handler.encrypt_snippet(inflate_string(str(key))),
                    is_physical_file=False,
                )
            stream = BytesIO(value)
            stream.seek(0)
            with self.crypto_handler.create_signature():
                self._db_store_enc_stream_in(file_entry, stream, db)
            return file_entry.file_id

    def _db_store_enc_stream_in(self, file_entry: Files, stream_in: BinaryIO, db: SqliteDatabase) -> None:
        """ Store stream as encrypted chunks in Chunks table."""
        n_chunks = 0
        with db.atomic():
            for chunk_group in self._chunked(self._generate_enc_chunks(stream_in, file_entry.file_id), 20):
                Chunks.bulk_create(chunk_group)
                n_chunks += len(chunk_group)
            file_entry.n_chunks = n_chunks
            file_entry.save()

    def store_single_file(self, file: str, outfile: Union[str, None] = None) -> int:
        """ Store encrypted file content in Files and Chunks.

        Returns created Files.file_id.
        """
        with self._reader_encrypt_file(file, outfile) as (db, file_entry, stream_in):
            if outfile:
                stream_out = open(outfile, 'wb')
                for enc_chunk in self.crypto_handler.encrypt_stream(stream_in):
                    stream_out.write(enc_chunk)
            else:
                self._db_store_enc_stream_in(file_entry, stream_in, db)
            return file_entry.file_id

    def read_file_index(self) -> Sequence[Mapping[str, Any]]:
        """ Load all entries in Files as dictionary. """
        files = []
        with self.sql_handler.open_db():
            for row in Files.select():
                assert isinstance(row, Files)
                row_dict = row.to_dict()
                row_dict['path'] = deflate_string(self.crypto_handler.decrypt_snippet(row.path))
                files.append(row_dict)
        return files

    def get_file_ids(self, file_list: Sequence[str]) -> Mapping[str, int]:
        """ Get mapping of path(or key) to Files.file_id. """
        file_index = self.read_file_index()
        return {file['path']: file['file_id'] for file in file_index if file['path'] in file_list}

    def restore_files(self, file_list: Sequence[str]) -> Mapping[str, Union[str, bytes]]:
        """ Decrypt stored files or values.

        Returns a list of restored items as mapping of path(key) to
        either str (path of decrypted file) or bytes (decrypted value)
        """
        file_index = self.get_file_ids(file_list)
        result = {}
        for path, file_id in file_index.items():
            result[path] = self.restore_single_file(file_id)
        return result

    def restore_single_file(self, file_id: int, signature: Union[None, bytes] = None) -> Union[str, bytes]:
        """ Decrypt single stored file or value.

        Returns either str (path of decrypted file) or bytes (decrypted value).
        """
        with self.sql_handler.open_db():
            file = Files.get_by_id(file_id)
            assert isinstance(file, Files)
            if file.is_physical_file:
                return self._restore_single_file_physical(file, signature)
            else:
                return self._restore_single_file_virtual(file, signature)

    def _restore_single_file_physical(self, file: Files, signature: Union[None, bytes]) -> str:
        """ Decrypt stored file to its original relative path.

        Returns path.
        """
        target_path = deflate_string(self.crypto_handler.decrypt_snippet(file.path))
        dirname = os.path.dirname(target_path)
        if len(dirname):
            os.makedirs(dirname, exist_ok=True)
        with open(target_path, 'wb') as f_out:
            with self.crypto_handler.verify_signature(signature):
                if file.encrypted_file_path:
                    with open(file.encrypted_file_path, 'rb') as f_in:
                        for chunk in self.crypto_handler.decrypt_stream(f_in):
                            f_out.write(chunk)
                else:
                    for row in self._iter_file_chunks(file):
                        f_out.write(self.crypto_handler.decrypt_chunk(row.content))
        return target_path

    @staticmethod
    def _iter_file_chunks(file: Files) -> Generator[Chunks, None, None]:
        """ Iterate over chunks of file in correct order. """
        yield from Chunks \
            .select(Chunks.content) \
            .where(Chunks.fk_file_id == file.file_id) \
            .order_by(Chunks.i_chunk)

    def _restore_single_file_virtual(self, file: Files, signature: Union[None, bytes]) -> bytes:
        """ Decrypt single key/value pair. """
        buffer = BytesIO()
        with self.crypto_handler.verify_signature(signature):
            for row in self._iter_file_chunks(file):
                buffer.write(self.crypto_handler.decrypt_chunk(row.content))
        return buffer.getvalue()
