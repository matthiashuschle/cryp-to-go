import os
import pathlib
import json
from contextlib import contextmanager
from typing import Union, List, Tuple, Dict
from .database import SQLiteHandler
from .db_models import Settings, Files, Chunks
from .core import KeyDerivationSetup, inflate_string, deflate_string, CryptoHandler


_KEY_DERIVATION_SETUP = 'key_derivation_setup'


class SQLiteFileInterface:

    def __init__(self, sqlite_file: str, crypto_handler: Union[None, CryptoHandler] = None):
        self.sql_handler = SQLiteHandler(sqlite_file)
        self.crypto_handler = crypto_handler
        self._key_derivation_factory = KeyDerivationSetup.create_default

    def store_key_derivation_setup(self, kds: KeyDerivationSetup):
        with self.sql_handler.open_db() as database:
            with database.atomic():
                Settings.create(
                    key=_KEY_DERIVATION_SETUP,
                    value=json.dumps(kds.to_dict())
                )

    def load_crypto_handler(self, password):
        with self.sql_handler.open_db():
            kds = KeyDerivationSetup.from_dict(
                json.loads(Settings.get(Settings.key == _KEY_DERIVATION_SETUP).value)
            )
        self.crypto_handler = kds.generate_keys(password)

    def use_new_crypto_handler(self, password, use_signatures=False):
        kds = self._key_derivation_factory(enable_signature_key=use_signatures)
        self.store_key_derivation_setup(kds)
        self.crypto_handler = kds.generate_keys(password)

    def assert_crypto_handler(self):
        if self.crypto_handler is None:
            raise RuntimeError('crypto_handler must be set for this operation. '
                               'Set in constructor, manually, or per load_crypto_handler '
                               'or use_new_crypto_handler.')

    def store_files(self, file_list: List[str]) -> Dict[str, Tuple[int, bytes]]:
        cwd = pathlib.PurePath(os.getcwd())
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
    def _reader_encrypt_file(self, file: str, outfile: Union[str, None] = None):
        with self.sql_handler.open_db() as db:
            with db.atomic():
                file_entry = Files.create(
                    path=self.crypto_handler.encrypt_snippet(inflate_string(str(file))),
                    encrypted_file_path=outfile,
                )
            with open(file, 'rb') as stream_in:
                with self.crypto_handler.create_signature():
                    yield db, file_entry, stream_in

    def _generate_enc_chunks(self, stream_in, file_id):
        for i_chunk, enc_chunk in enumerate(self.crypto_handler.encrypt_stream(stream_in)):
            yield Chunks(
                fk_file_id=file_id,
                i_chunk=i_chunk,
                content=enc_chunk,
            )

    @staticmethod
    def _chunked(it, n):
        """ Lazily create chunks from an iterator. """
        current_chunk = []
        for element in it:
            current_chunk.append(element)
            if len(current_chunk) == n:
                yield current_chunk
                current_chunk = []
        if len(current_chunk):
            yield current_chunk

    def store_single_file(self, file: str, outfile: Union[str, None] = None):
        with self._reader_encrypt_file(file, outfile) as (db, file_entry, stream_in):
            if outfile:
                stream_out = open(outfile, 'wb')
                for enc_chunk in self.crypto_handler.encrypt_stream(stream_in):
                    stream_out.write(enc_chunk)
            else:
                n_chunks = 0
                with db.atomic():
                    for chunk_group in self._chunked(self._generate_enc_chunks(stream_in, file_entry.file_id), 20):
                        Chunks.bulk_create(chunk_group)
                        n_chunks += len(chunk_group)
                    file_entry.n_chunks = n_chunks
                    file_entry.save()
            return file_entry.file_id

    def read_file_index(self):
        files = []
        with self.sql_handler.open_db():
            for row in Files.select(Files.file_id, Files.path, Files.encrypted_file_path):
                assert isinstance(row, Files)
                row_dict = row.to_dict()
                row_dict['path'] = deflate_string(self.crypto_handler.decrypt_snippet(row.path))
                files.append(row_dict)
        return files

    def get_file_ids(self, file_list):
        file_index = self.read_file_index()
        return {file['path']: file['file_id'] for file in file_index if file['path'] in file_list}

    def restore_files(self, file_list):
        file_index = self.get_file_ids(file_list)
        for file_id in file_index.values():
            self.restore_single_file(file_id)

    def restore_single_file(self, file_id, signature=None):
        with self.sql_handler.open_db():
            file = Files.get_by_id(file_id)
            assert isinstance(file, Files)
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
                        for row in Chunks\
                                .select(Chunks.content)\
                                .where(Chunks.fk_file_id == file_id)\
                                .order_by(Chunks.i_chunk):
                            f_out.write(self.crypto_handler.decrypt_chunk(row.content))
        return target_path
