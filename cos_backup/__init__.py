import argparse
import logging
import sys

from qcloud_cos import CosConfig, CosS3Client

from .archive import Archive, MasterKey
from .backup import Backup
from .config import Config
from .manifest import Manifest


def gen_master_key(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-k',
                        '--private_key',
                        required=True,
                        help='path to store the private key')
    parser.add_argument('-p',
                        '--public_key',
                        required=True,
                        help='path to store the public key')
    args = parser.parse_args(argv)
    key = MasterKey.generate()
    key.save_private(args.private_key)
    key.save_public(args.public_key)


def unarchive(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--private_key', help='the private key file')
    parser.add_argument('-o',
                        '--output',
                        required=True,
                        help='the output file')
    parser.add_argument('file', help='the file to unarchive')
    args = parser.parse_args(argv)

    if args.private_key:
        private_key = MasterKey.load_from_file(args.private_key).private
    else:
        private_key = None

    with open(args.output, 'wb') as fobj:
        for chunk in Archive.unarchive(args.file, enc_privkey=private_key):
            fobj.write(chunk)


def run_backup(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', required=True, help='config file')
    parser.add_argument('-f', '--force', help='forcibly the given upload task')
    parser.add_argument('-l',
                        '--logging',
                        help='logging level',
                        default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING'])
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.logging)
    config = Config.from_toml(args.config)
    cos_config = CosConfig(SecretId=config.cos.secret_id,
                           SecretKey=config.cos.secret_key,
                           Region=config.cos.region)
    cos_cli = CosS3Client(cos_config)

    for (name, cfg) in config.backups.items():
        run_dir = config.common.run_dir.joinpath(name)
        run_dir.mkdir(parents=True, exist_ok=True)
        Backup(run_dir, config.common, cfg, cos_cli, name == args.force).run()


def migrate_manifest(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-i',
                        '--input',
                        required=True,
                        help='the manifest file')
    parser.add_argument('-b', '--base', required=True, help='the base path')
    args = parser.parse_args(argv)
    Manifest.migrate(args.input, args.base)


def usage():
    print('{} (backup|gen_master_key|unarchive|migrate_manifest) [ARGS...]'.
          format(sys.argv[0]))


def main():
    if len(sys.argv) == 1:
        usage()
    else:
        cmd, argv = sys.argv[1], sys.argv[2:]
        if cmd == 'gen_master_key':
            gen_master_key(argv)
        elif cmd == 'unarchive':
            unarchive(argv)
        elif cmd == 'backup':
            run_backup(argv)
        elif cmd == 'migrate_manifest':
            migrate_manifest(argv)
        else:
            print('Invalid command:', cmd)
            usage()
            sys.exit(1)


__all__ = ('main', )
