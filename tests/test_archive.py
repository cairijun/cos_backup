import os
import unittest

from cos_backup.archive import Archive, MasterKey
from cos_backup.config import ArchiveConfig

from . import TmpfsMixin


class TestArchive(unittest.TestCase, TmpfsMixin):
    def setUp(self):
        self.init_tmpfs()

    def test_no_comp_no_enc(self):
        ar = Archive(ArchiveConfig({}), chunk_size=32)
        data = os.urandom(1024)
        file_path = self.mock_file(content=data)
        result = b''.join(ar.store_file(file_path))
        self.assertGreater(len(result), 3)
        self.assertEqual(b'\x00\x00\x00', result[:3])
        self.assertEqual(data, result[3:])

        result_file = self.mock_file(content=result)
        self.assertEqual(data, b''.join(Archive.unarchive(result_file)))

    def test_comp_no_enc(self):
        cfg = ArchiveConfig({'compression': {'min_size': 512}})
        ar = Archive(cfg, chunk_size=32)
        data = os.urandom(32) * 32
        file_path = self.mock_file(content=data)
        result = b''.join(ar.store_file(file_path))
        self.assertGreater(len(result), 3)
        self.assertEqual(b'\x00\x01\x00', result[:3])
        self.assertLess(len(result), len(data))

        result_file = self.mock_file(content=result)
        self.assertEqual(data, b''.join(Archive.unarchive(result_file)))

    def test_comp_no_enc_too_small(self):
        cfg = ArchiveConfig({'compression': {'min_size': 2048}})
        ar = Archive(cfg, chunk_size=32)
        data = os.urandom(32) * 32
        file_path = self.mock_file(content=data)
        result = b''.join(ar.store_file(file_path))
        self.assertGreater(len(result), 3)
        self.assertEqual(b'\x00\x00\x00', result[:3])
        self.assertEqual(data, result[3:])

        result_file = self.mock_file(content=result)
        self.assertEqual(data, b''.join(Archive.unarchive(result_file)))

    def test_no_comp_enc(self):
        master_key = MasterKey.generate()
        master_key_file = self.mock_file()
        master_key.save_public(master_key_file)
        cfg = ArchiveConfig({'encryption': {'public_key': master_key_file}})
        ar = Archive(cfg, chunk_size=32)
        data = os.urandom(32) * 32
        file_path = self.mock_file(content=data)
        result = b''.join(ar.store_file(file_path))
        self.assertGreater(len(result), 3)
        self.assertEqual(b'\x00\x00\x01', result[:3])
        self.assertNotEqual(data, result[3:])

        result_file = self.mock_file(content=result)
        unarchived = Archive.unarchive(result_file,
                                       enc_privkey=master_key.private)
        self.assertEqual(data, b''.join(unarchived))

    def test_comp_enc(self):
        master_key = MasterKey.generate()
        master_key_file = self.mock_file()
        master_key.save_public(master_key_file)
        cfg = ArchiveConfig({
            'encryption': {
                'public_key': master_key_file
            },
            'compression': {
                'min_size': 512
            },
        })
        ar = Archive(cfg, chunk_size=32)
        data = os.urandom(32) * 32
        file_path = self.mock_file(content=data)
        result = b''.join(ar.store_file(file_path))
        self.assertGreater(len(result), 3)
        self.assertEqual(b'\x00\x01\x01', result[:3])
        self.assertLess(len(result), len(data))
        self.assertNotEqual(data, result[3:])

        result_file = self.mock_file(content=result)
        unarchived = Archive.unarchive(result_file,
                                       enc_privkey=master_key.private)
        self.assertEqual(data, b''.join(unarchived))
