import shutil
import unittest
from unittest import mock

from qcloud_cos import CosS3Client, CosServiceError

from cos_backup.backup import Backup, UploadSetTooLarge
from cos_backup.config import ArchiveConfig, BackupConfig, CommonConfig

from . import TmpfsMixin


def mock_cos_error(error_code, http_method='POST', http_status=400):
    return CosServiceError(
        http_method, '''<?xml version='1.0' encoding='utf-8' ?>
<Error>
    <Code>{}</Code>
    <Message>TestMessage</Message>
    <Resource>TestResource</Resource>
    <RequestId>TestRequestId</RequestId>
    <TraceId>TestTraceId</TraceId>
</Error>'''.format(error_code), http_status)


class TestBackup(unittest.TestCase, TmpfsMixin):
    def setUp(self):
        self.init_tmpfs()

        self._Archive_patcher = mock.patch('cos_backup.backup.Archive',
                                           autospec=True)
        self.mock_Archive = self._Archive_patcher.start()

        self.run_dir = self.mock_dir('run')
        self.common_config = CommonConfig({'run_dir': self.run_dir})

        self.data_dir = self.mock_dir('ldata')
        self.backup_config = BackupConfig({
            'local_path': self.data_dir,
            'cos_bucket': 'mock_bucket',
            'cos_path': 'cos_dir',
        })

        self.mock_cli = mock.MagicMock(spec=CosS3Client)

    def assert_upload(self, remote_file, local_file, sse=True, **extra_args):
        if sse:
            extra_args.setdefault('ServerSideEncryption', 'AES256')
        self.mock_cli.upload_file.assert_any_call(
            Bucket='mock_bucket',
            Key='cos_dir/' + remote_file,
            LocalFilePath=str(local_file),
            **extra_args)

    def tearDown(self):
        self._Archive_patcher.stop()

    def test_upload(self):
        self.mock_file('ldata/file1', content=b'content1')
        self.mock_file('ldata/file2', content=b'content2')
        self.mock_file('ldata/dir1/file3', content=b'content3')
        self.mock_file('ldata/dir1/dir2/file4', content=b'content4')
        self.mock_dir('ldata/empty_dir')

        self.mock_cli.get_object.side_effect = mock_cos_error('NoSuchKey', 404)
        self.mock_cli.upload_file.side_effect = lambda Key, **_: {
            'ETag': 'ETagOf_' + Key
        }
        b = Backup(self.run_dir, self.common_config, self.backup_config,
                   self.mock_cli)
        b.run()
        self.mock_cli.get_object.assert_called_once_with(
            'mock_bucket', 'cos_dir/manifest.db')
        self.assert_upload('data/file1', self.data_dir / 'file1')
        self.assert_upload('data/file2', self.data_dir / 'file2')
        self.assert_upload('data/dir1/file3', self.data_dir / 'dir1/file3')
        self.assert_upload('data/dir1/dir2/file4',
                           self.data_dir / 'dir1/dir2/file4')
        self.assert_upload('manifest.db',
                           self.run_dir / 'manifest.db',
                           EnableMD5=True)
        self.assertFalse((self.run_dir / 'manifest.db').exists())
        self.assertTrue((self.run_dir / 'manifest.db.done').exists())

        self.mock_file('ldata/file1', content=b'content1')
        self.mock_file('ldata/file2', content=b'CONTENT2')
        self.mock_file('ldata/new_file', content=b'new_content')
        self.mock_path('ldata/dir1/file3').unlink()

        self.mock_cli.get_object.reset_mock(return_value=True,
                                            side_effect=True)
        self.mock_cli.get_object.return_value[
            'Body'].get_stream_to_file.side_effect = lambda f: shutil.copy(
                self.run_dir / 'manifest.db.done', f)
        self.mock_cli.upload_file.reset_mock()
        b.run()
        self.assert_upload('data/file2', self.data_dir / 'file2')
        self.assert_upload('data/new_file', self.data_dir / 'new_file')
        self.assert_upload('manifest.db',
                           self.run_dir / 'manifest.db',
                           EnableMD5=True)
        self.assertEqual(3, self.mock_cli.upload_file.call_count)
        self.assertFalse((self.run_dir / 'manifest.db').exists())
        self.assertTrue((self.run_dir / 'manifest.db.done').exists())

    def test_upload_archive(self):
        self.backup_config.archive = ArchiveConfig({})
        self.mock_file('ldata/file1', content=b'content1')
        self.mock_file('ldata/file2', content=b'content2')

        def mock_upload_file(Bucket, Key, LocalFilePath, **kwargs):
            self.assertEqual('mock_bucket', Bucket)
            with open(LocalFilePath) as fobj:
                if Key == 'cos_dir/data/file1':
                    self.assertEqual(
                        'ArchiveOf_' + str(self.data_dir / 'file1'),
                        fobj.read())
                elif Key == 'cos_dir/data/file2':
                    self.assertEqual(
                        'ArchiveOf_' + str(self.data_dir / 'file2'),
                        fobj.read())
            return {'ETag': 'ETagOf_' + Key}

        self.mock_cli.upload_file.side_effect = mock_upload_file
        self.mock_cli.get_object.side_effect = mock_cos_error('NoSuchKey', 404)

        mock_archive = self.mock_Archive.return_value
        mock_archive.store_file.side_effect = (
            lambda f: [b'ArchiveOf_', str(f).encode()])
        b = Backup(self.run_dir, self.common_config, self.backup_config,
                   self.mock_cli)
        b.run()
        self.assertEqual(2, mock_archive.store_file.call_count)
        mock_archive.store_file.assert_any_call(str(self.data_dir / 'file1'))
        mock_archive.store_file.assert_any_call(str(self.data_dir / 'file2'))
        self.assertEqual(3, self.mock_cli.upload_file.call_count)

    def test_exclude(self):
        self.mock_file('ldata/.hidden_file')
        self.mock_file('ldata/.hidden_dir/file')
        self.mock_file('ldata/file')
        self.mock_file('ldata/1/file')
        self.mock_file('ldata/2/file')
        self.mock_file('ldata/3')

        self.mock_cli.get_object.side_effect = mock_cos_error('NoSuchKey', 404)
        self.mock_cli.upload_file.side_effect = lambda Key, **_: {
            'ETag': 'ETagOf_' + Key
        }
        b = Backup(self.run_dir, self.common_config, self.backup_config,
                   self.mock_cli)
        b.run()
        self.assert_upload('data/file', self.data_dir / 'file')
        self.assert_upload('data/1/file', self.data_dir / '1/file')
        self.assert_upload('data/2/file', self.data_dir / '2/file')
        self.assert_upload('data/3', self.data_dir / '3')
        self.assertEqual(5, self.mock_cli.upload_file.call_count)

        self.mock_cli.upload_file.reset_mock()
        self.backup_config.exclude_hidden = False
        self.backup_config.excludes = ['?/*', 'fi*']
        b = Backup(self.run_dir, self.common_config, self.backup_config,
                   self.mock_cli)
        b.run()
        self.assert_upload('data/.hidden_file', self.data_dir / '.hidden_file')
        self.assert_upload('data/.hidden_dir/file',
                           self.data_dir / '.hidden_dir/file')
        self.assert_upload('data/3', self.data_dir / '3')
        self.assertEqual(4, self.mock_cli.upload_file.call_count)

    def test_failure_resume(self):
        self.mock_file('ldata/file1')
        self.mock_file('ldata/file2')

        self.mock_cli.get_object.side_effect = mock_cos_error('NoSuchKey', 404)
        self.mock_cli.upload_file.side_effect = [
            dict(ETag='ETag1'),
            mock_cos_error('SomeError', 400),
        ]
        b = Backup(self.run_dir, self.common_config, self.backup_config,
                   self.mock_cli)
        self.assertRaises(CosServiceError, b.run)
        self.assertEqual(2, self.mock_cli.upload_file.call_count)

        self.mock_cli.upload_file.side_effect = None
        self.mock_cli.upload_file.return_value = dict(ETag='ETag2')
        b.run()
        self.assert_upload('data/file1', self.data_dir / 'file1')
        self.assert_upload('data/file2', self.data_dir / 'file2')
        self.assertEqual(4, self.mock_cli.upload_file.call_count)

    def test_too_large(self):
        self.mock_file('ldata/file1', rand_len=512 * 1024)

        self.mock_cli.get_object.side_effect = mock_cos_error('NoSuchKey', 404)
        self.mock_cli.upload_file.side_effect = lambda Key, **_: {
            'ETag': 'ETagOf_' + Key
        }
        self.common_config.max_upload_mib = 1
        b = Backup(self.run_dir, self.common_config, self.backup_config,
                   self.mock_cli)
        b.run()
        self.assert_upload('data/file1', self.data_dir / 'file1')

        self.mock_cli.get_object.side_effect = None
        self.mock_cli.get_object.return_value[
            'Body'].get_stream_to_file.side_effect = lambda f: shutil.copy(
                self.run_dir / 'manifest.db.done', f)

        self.mock_file('ldata/file2', rand_len=512 * 1024 + 1)
        b.run()
        self.assert_upload('data/file2', self.data_dir / 'file2')

        self.mock_cli.upload_file.reset_mock()
        self.mock_file('ldata/file1', rand_len=512 * 1024)
        self.mock_file('ldata/file4', rand_len=512 * 1024 + 1)
        self.assertRaises(UploadSetTooLarge, b.run)
        self.mock_cli.upload_file.assert_not_called()
        (self.run_dir / 'manifest.db').unlink()

        b = Backup(self.run_dir,
                   self.common_config,
                   self.backup_config,
                   self.mock_cli,
                   force_upload=True)
        b.run()
        self.assert_upload('data/file1', self.data_dir / 'file1')
        self.assert_upload('data/file4', self.data_dir / 'file4')
        self.assertEqual(3, self.mock_cli.upload_file.call_count)
