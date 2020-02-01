from contextlib import contextmanager
from typing import Any, MutableMapping
import peewee as pw


@contextmanager
def bind_all(database: pw.Database):
    with database.bind_ctx(ALL_TABLES):
        yield


class Settings(pw.Model):
    """
    ORM model of the Settings table

    - may contain info about key derivation
    - version info?
    - values are text (unicode)
    - store complex values as json
    """
    key = pw.CharField(unique=True)
    value = pw.TextField()


class AsymKeys(pw.Model):
    """ ORM model for asymmetrically encrypted keys.
    """
    key_id = pw.AutoField()
    value = pw.TextField()


class Files(pw.Model):
    file_id = pw.AutoField()
    path = pw.BlobField()
    encrypted_file_path = pw.TextField(null=True)
    n_chunks = pw.IntegerField(default=-1)
    is_physical_file = pw.BooleanField(default=True)

    def to_dict(self) -> MutableMapping[str, Any]:
        return {
            'file_id': self.file_id,
            'path': self.path,
            'encrypted_file_path': self.encrypted_file_path,
            'n_chunks': self.n_chunks,
            'is_physical_file': self.is_physical_file
        }


class Chunks(pw.Model):
    fk_file_id = pw.ForeignKeyField(Files, field='file_id')
    i_chunk = pw.IntegerField()
    content = pw.BlobField()


ALL_TABLES = [Settings, Files, AsymKeys, Chunks]
