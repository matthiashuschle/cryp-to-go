from contextlib import contextmanager
import peewee as pw
from . import db_models


class SQLiteHandler:

    def __init__(self, path):
        self._path = path
        self._database = pw.SqliteDatabase(
            self._path,
            pragmas={
                'journal_mode': 'wal',
                'cache_size': -64 * 2 ** 10,  # 64MB
                'foreign_keys': 1,
                'ignore_check_constraints': 0,
                'synchronous': 0
            }
        )
        self._create_tables()

    def _create_tables(self):
        with self.open_db() as database:
            if not database.table_exists('Settings'):
                database.create_tables([db_models.Settings, db_models.Files, db_models.Chunks])

    @contextmanager
    def open_db(self):
        with db_models.bind_all(self._database):
            self._database.connect()
            yield self._database
            self._database.close()
