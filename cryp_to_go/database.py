from contextlib import contextmanager
from typing import ContextManager
import peewee as pw
from . import db_models
from . import __version__


class SQLiteHandler:

    def __init__(self, path: str):
        self._path = path
        self._database = pw.SqliteDatabase(
            self._path,
            pragmas={
                'journal_mode': 'wal',
                'cache_size': -64 * 2 ** 10,  # 64MB
                'foreign_keys': 1,
                'ignore_check_constraints': 0,
                'synchronous': 0
            },
        )
        self._create_tables()
        self._store_version()

    def _store_version(self) -> None:
        with self.open_db():
            db_models.Settings.get_or_create(
                key='VERSION',
                value=__version__,
            )

    def _create_tables(self) -> None:
        with self.open_db() as database:
            if not database.table_exists('Settings'):
                database.create_tables(db_models.ALL_TABLES)

    @contextmanager
    def open_db(self) -> ContextManager[pw.SqliteDatabase]:
        with db_models.bind_all(self._database):
            self._database.connect()
            yield self._database
            self._database.close()
