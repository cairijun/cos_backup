import io
import os
import sqlite3
import typing
from hashlib import blake2b

DEFAULT_FILE_HASH_SIZE = 4


class FileMeta(typing.NamedTuple):
    rel_path: str
    size: int
    st_mtime: int
    blake2b_hash: str
    blake2b_salt: str
    etag: str


def hash_file(fobj: io.BufferedIOBase,
              blake2b_salt: str = None,
              hash_size_bytes: int = DEFAULT_FILE_HASH_SIZE) -> (str, str):
    if blake2b_salt is None:
        salt = os.urandom(blake2b.SALT_SIZE)
        blake2b_salt = salt.hex()
    else:
        salt = bytes.fromhex(blake2b_salt)
    h = blake2b(digest_size=hash_size_bytes, salt=salt)
    MAX_BUFFER = 1024 * 1024
    while True:
        buf = fobj.read1(MAX_BUFFER)
        if not buf:
            break
        h.update(buf)
    return h.hexdigest(), blake2b_salt


class Manifest:
    _TABLE_FIELDS = ", ".join("`{}`".format(f) for f in FileMeta._fields)
    _FIELD_PLACEHOLDERS = ", ".join("?" for _ in range(len(FileMeta._fields)))

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
            + ") VALUES (" + self._FIELD_PLACEHOLDERS + ")", file_meta)

    @classmethod
    def migrate(cls, manifest_path, base_path):
        conn = sqlite3.connect(manifest_path)
        cursor = conn.cursor()
        cursor.execute("BEGIN")
        cursor.execute("ALTER TABLE `file_meta` RENAME TO `file_meta_old`")
        cursor.execute(_FILE_META_SCHEMA)
        cursor.execute("SELECT `rel_path`, `size`, `st_mtime`, `etag` "
                       "FROM `file_meta_old`")
        insert_sql = ("INSERT OR REPLACE INTO `file_meta` ("
                      + cls._TABLE_FIELDS + ") VALUES ("
                      + cls._FIELD_PLACEHOLDERS + ")")
        for rel_path, size, st_mtime, etag in cursor.fetchall():
            full_path = os.path.join(base_path, rel_path)
            try:
                st = os.stat(full_path)
            except OSError as e:
                print("Unable to access file {}: {}".format(rel_path, e))
                continue
            if st.st_size != size:
                print("Size not match: {}".format(rel_path))
                continue
            if st.st_mtime != st_mtime:
                print("MTime not match: {}".format(rel_path))
                continue
            with open(full_path, "rb") as fobj:
                hash, salt = hash_file(fobj)
            cursor.execute(
                insert_sql,
                FileMeta(rel_path=rel_path,
                         size=size,
                         st_mtime=st_mtime,
                         blake2b_hash=hash,
                         blake2b_salt=salt,
                         etag=etag))
        cursor.execute("COMMIT")


_FILE_META_SCHEMA = """
CREATE TABLE IF NOT EXISTS `file_meta` (
  `rel_path` TEXT PRIMARY KEY,
  `size` INTEGER NOT NULL,
  `st_mtime` INTEGER NOT NULL,
  `blake2b_hash` TEXT NOT NULL,
  `blake2b_salt` TEXT NOT NULL,
  `etag` TEXT NOT NULL,
  `last_modified` INTEGER NOT NULL DEFAULT(strftime('%s','now'))
) WITHOUT ROWID
"""
