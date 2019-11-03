import sqlite3
import typing
import collections

# TODO: use hmac instead of simple digest
FileMeta = collections.namedtuple(
    "FileMeta",
    ["rel_path", "size", "st_mtime", "digest_type", "digest_hex", "etag"],
)


class Manifest:
    _TABLE_FIELDS = ", ".join("`{}`".format(f) for f in FileMeta._fields)

    def __init__(self, path):
        self._conn = sqlite3.connect(path, isolation_level=None)

        cursor = self._conn.cursor()
        cursor.execute(_FILE_META_SCHEMA)

    def close(self):
        self._conn.close()

    def query_file(self, rel_path) -> typing.Optional[FileMeta]:
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT " + self._TABLE_FIELDS
            + " FROM `file_meta` WHERE `rel_path` = ?", (str(rel_path), ))
        row = cursor.fetchone()
        return FileMeta(*row) if row else None

    def set_file(self, file_meta: FileMeta):
        cursor = self._conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO `file_meta` (" + self._TABLE_FIELDS
            + ") VALUES (?, ?, ?, ?, ?, ?)", file_meta)


_FILE_META_SCHEMA = """
CREATE TABLE IF NOT EXISTS `file_meta` (
  `rel_path` TEXT PRIMARY KEY,
  `size` INTEGER NOT NULL,
  `st_mtime` INTEGER NOT NULL,
  `digest_type` TEXT NOT NULL,
  `digest_hex` TEXT NOT NULL,
  `etag` TEXT NOT NULL,
  `last_modified` INTEGER NOT NULL DEFAULT(strftime('%s','now'))
) WITHOUT ROWID
"""
