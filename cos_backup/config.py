import pathlib

import toml


class Config:
    @classmethod
    def from_toml(cls, toml_file):
        return cls(toml.load(toml_file))

    def __init__(self, d):
        self.common = CommonConfig(d.get('common', {}))
        self.cos = CosConfig(d['cos'])
        backups = d.get('backups', {})
        self.backups = {
            name: BackupConfig(cfg_dict)
            for (name, cfg_dict) in backups.items()
        }


class CommonConfig:
    def __init__(self, d):
        self.default_manifest_digest = d.get('default_manifest_digest', 'sha1')
        self.max_upload_mib = d.get('max_upload_mib', 1024)
        self.run_dir = pathlib.Path(d.get('run_dir', '.'))


class CosConfig:
    def __init__(self, d):
        self.secret_id = d['secret_id']
        self.secret_key = d['secret_key']
        self.region = d['region']


class BackupConfig:
    def __init__(self, d):
        self.local_path = pathlib.Path(d['local_path'])
        if not self.local_path.is_dir():
            raise ValueError('local_path is not a directory')

        self.excludes = d.get('excludes', [])
        try:
            iter(self.excludes)
        except TypeError:
            self.excludes = [self.excludes]

        self.exclude_hidden = d.get('exclude_hidden', True)
        if not isinstance(self.exclude_hidden, bool):
            raise TypeError('exclude_hidden must be a boolean')

        self.cos_bucket = d['cos_bucket']
        self.cos_path = pathlib.PurePosixPath(d.get('cos_path', ''))
        self.cos_sse = d.get('cos_sse', True)

        self.archive = d.get('archive', None)
        if self.archive:
            self.archive = ArchiveConfig(self.archive)


class ArchiveConfig:
    def __init__(self, d):
        self.compression = d.get('compression', None)
        if self.compression:
            self.compression = CompressionConfig(self.compression)

        self.encryption = d.get('encryption', None)
        if self.encryption:
            self.encryption = EncryptionConfig(self.encryption)


class EncryptionConfig:
    def __init__(self, d):
        self.public_key = d['public_key']


class CompressionConfig:
    def __init__(self, d):
        self.min_size = d.get('min_size', 0)
