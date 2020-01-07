from contextlib import contextmanager
import peewee as pw
from . import db_models


@contextmanager
def use_sqlite_file(path):
    database = pw.SqliteDatabase(path)
    with db_models.bind_all(database):
        yield
