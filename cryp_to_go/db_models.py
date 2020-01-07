from contextlib import contextmanager
import peewee as pw


@contextmanager
def bind_all(database: pw.Database):
    with database.bind_ctx([Settings, Files, Chunks]):
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


class Files(pw.Model):
    file_id = pw.AutoField()
    path = pw.TextField()
    encrypted_file_path = pw.TextField(null=True)
    n_chunks = pw.IntegerField(default=-1)


class Chunks(pw.Model):
    fk_file_id = pw.ForeignKeyField(Files, field='file_id', backref='chunks')
    i_chunk = pw.IntegerField()
    content = pw.BlobField()
