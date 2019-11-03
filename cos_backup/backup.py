import fnmatch
import tempfile
import hashlib
import logging
import os
import stat

from qcloud_cos import CosS3Client, CosServiceError

from .config import BackupConfig, CommonConfig
from .manifest import FileMeta, Manifest
from .archive import Archive


class UploadSetTooLarge(RuntimeError):
    pass


class Backup:
    MANIFEST_FILE = 'manifest.db'
    _DATA_DIR = 'data/'

    def __init__(self,
                 local_run_dir,
                 common_config: CommonConfig,
                 backup_config: BackupConfig,
                 cos_cli: CosS3Client,
                 force_upload=False):
        self._local_run_dir = local_run_dir
        self._common_config = common_config
        self._backup_config = backup_config
        self._cos_cli = cos_cli
        self._force_upload = force_upload

        self._local_manifest_db = os.path.join(self._local_run_dir,
                                               self.MANIFEST_FILE)
        self._manifest_cos_key = self._cos_object_key(self.MANIFEST_FILE)
        self._archive = (Archive(backup_config.archive)
                         if backup_config.archive else None)

        self._extra_upload_args = {}
        if self._backup_config.cos_sse:
            self._extra_upload_args['ServerSideEncryption'] = 'AES256'
        if self._archive:
            self._extra_upload_args['Metadata'] = {
                'x-cos-meta-archive': 'Enabled'
            }

    def run(self):
        logging.warning('start backup')
        UPLOAD_SIZE_LIMIT = self._common_config.max_upload_mib * 1024 * 1024
        upload_size = 0
        upload_list = []
        manifest = self._fetch_manifest()
        for (rel_path, st) in self._walk_local_path():
            file_meta = manifest.query_file(rel_path)
            if not file_meta:
                logging.info('file not exist in backup: %s', rel_path)
            elif not self._need_upload(rel_path, st, file_meta):
                logging.debug('not need to upload: %s', rel_path)
                continue
            logging.warning('ready to upload: %s, size: %d', rel_path,
                            st.st_size)
            upload_size += st.st_size
            if not self._force_upload and upload_size > UPLOAD_SIZE_LIMIT:
                logging.error('upload set too large: %d bytes', upload_size)
                raise UploadSetTooLarge
            upload_list.append((rel_path, st))

        for (rel_path, st) in upload_list:
            logging.warning('uploading %s', rel_path)
            etag = self._upload_file(rel_path)
            logging.info('done, etag: %s', etag)
            manifest.set_file(self._make_file_meta(rel_path, st, etag))

        manifest.close()
        if upload_list:
            logging.info('uploading manifest: %s', self._local_manifest_db)
            self._cos_cli.upload_file(Bucket=self._backup_config.cos_bucket,
                                      Key=self._manifest_cos_key,
                                      LocalFilePath=self._local_manifest_db,
                                      EnableMD5=True,
                                      **self._extra_upload_args)
        os.replace(self._local_manifest_db, self._local_manifest_db + '.done')
        logging.warning('backup done')

    def _walk_local_path(self):
        base = self._backup_config.local_path
        dirs = [base]
        while dirs:
            current_dir = dirs.pop()
            newly_found_dirs = []
            for entry in current_dir.iterdir():
                rel_path = entry.relative_to(base)
                if self._should_exclude(rel_path):
                    logging.debug('exclude %s', rel_path)
                    continue
                st = entry.lstat()
                if stat.S_ISDIR(st.st_mode):
                    newly_found_dirs.append(entry)
                elif stat.S_ISREG(st.st_mode):
                    yield (rel_path, st)
                else:  # unsupported file
                    logging.debug('unsupported file type: %s of type %s',
                                  rel_path, stat.S_IFMT(st.st_mode))
            dirs.extend(reversed(newly_found_dirs))

    def _should_exclude(self, rel_path):
        if (self._backup_config.exclude_hidden
                and rel_path.name.startswith('.')):
            return True
        for pattern in self._backup_config.excludes:
            if fnmatch.fnmatch(rel_path, pattern):
                return True
        return False

    def _fetch_manifest(self) -> Manifest:
        if os.path.exists(self._local_manifest_db):
            logging.warning('local manifest db found: %s',
                            self._local_manifest_db)
            # TODO: validate against the remote data
            return Manifest(self._local_manifest_db)
        try:
            resp = self._cos_cli.get_object(self._backup_config.cos_bucket,
                                            self._manifest_cos_key)
            resp['Body'].get_stream_to_file(self._local_manifest_db)
        except CosServiceError as e:
            if e.get_error_code() != 'NoSuchKey':
                logging.warning('manifest not found: %s',
                                self._manifest_cos_key)
                raise
            # no manifest, create one
        return Manifest(self._local_manifest_db)

    def _need_upload(self, rel_path, st, file_meta):
        if st.st_size != file_meta.size:
            return True
        if st.st_mtime == file_meta.st_mtime:
            return False
        digest_hex = self._digest_file(
            self._backup_config.local_path.joinpath(rel_path),
            file_meta.digest_type)
        return digest_hex != file_meta.digest_hex

    def _upload_file(self, rel_path):
        local_path = self._backup_config.local_path.joinpath(rel_path)
        cos_key = self._cos_object_key(self._DATA_DIR, rel_path)

        def upload(path):
            return self._cos_cli.upload_file(
                Bucket=self._backup_config.cos_bucket,
                Key=cos_key,
                LocalFilePath=path,
                **self._extra_upload_args)

        if self._archive:
            try:
                fd, archive_path = tempfile.mkstemp()
                with os.fdopen(fd, 'wb') as fobj:
                    logging.info('archive file %s to %s', local_path,
                                 archive_path)
                    for chunk in self._archive.store_file(str(local_path)):
                        fobj.write(chunk)
                logging.debug('uploading archive %s', archive_path)
                resp = upload(archive_path)
            finally:
                os.remove(archive_path)
        else:
            resp = upload(local_path)
        return resp['ETag']

    def _cos_object_key(self, *parts):
        path = self._backup_config.cos_path
        for p in parts:
            path = path.joinpath(str(p).lstrip('/'))
        return str(path)

    def _make_file_meta(self, rel_path, st, etag):
        digest_type = self._common_config.default_manifest_digest
        digest_hex = self._digest_file(
            self._backup_config.local_path.joinpath(rel_path), digest_type)
        return FileMeta(rel_path=str(rel_path),
                        size=st.st_size,
                        st_mtime=st.st_mtime,
                        digest_type=digest_type,
                        digest_hex=digest_hex,
                        etag=etag)

    @staticmethod
    def _digest_file(path, digest_type):
        MAX_BUFFER = 1024 * 1024
        h = hashlib.new(digest_type)
        with open(path, 'rb') as fobj:
            while True:
                buf = fobj.read1(MAX_BUFFER)
                if not buf:
                    break
                h.update(buf)
        return h.hexdigest()
