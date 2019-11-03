import base64
import getpass
import io
import json
import os
import struct
import typing

from cryptography.hazmat.backends import default_backend as crypto_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from lz4.frame import LZ4FrameCompressor, LZ4FrameDecompressor

from .config import ArchiveConfig

DEFAULT_CHUNK_SIZE = 512 * 1024


class MasterKey:
    _ENC_PBKDF2_HASH = hashes.SHA256
    _ENC_PBKDF2_LEN_BYTES = 32
    _ENC_PBKDF2_SALT_LEN_BYTES = 16
    _ENC_PBKDF2_ITERS = 10000
    _ENC_CIPHER = AESGCM
    _ENC_CIPHER_NAME = 'AESGCM'
    _ENC_CIPHER_SALT_LEN_BYTES = 12

    class _SerializedKey(typing.NamedTuple):
        pbkdf2_hash: str
        pbkdf2_len_bytes: int
        pbkdf2_iters: int
        pbkdf2_salt: str
        cipher: str
        cipher_iv: str
        private_key: str

    def __init__(self, privkey: x25519.X25519PrivateKey):
        self._privkey = privkey

    @property
    def private(self) -> x25519.X25519PrivateKey:
        return self._privkey

    @property
    def public(self) -> x25519.X25519PublicKey:
        return self._privkey.public_key()

    def save_private(self, path, *, password: str = None):
        if password is None:
            password = getpass.getpass()
            confirm = getpass.getpass('Confirm: ')
            if confirm != password:
                raise RuntimeError('password not match')
        private_key = self.private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
        kdf_salt = os.urandom(self._ENC_PBKDF2_SALT_LEN_BYTES)
        cipher_iv = os.urandom(self._ENC_CIPHER_SALT_LEN_BYTES)
        cipher = self._ENC_CIPHER(self._key_from_password(password, kdf_salt))
        encrypted = cipher.encrypt(nonce=cipher_iv,
                                   data=private_key,
                                   associated_data=None)

        serialized = self._SerializedKey(
            pbkdf2_hash=self._ENC_PBKDF2_HASH.name,
            pbkdf2_len_bytes=self._ENC_PBKDF2_LEN_BYTES,
            pbkdf2_iters=self._ENC_PBKDF2_ITERS,
            pbkdf2_salt=base64.standard_b64encode(kdf_salt).decode(),
            cipher=self._ENC_CIPHER_NAME,
            cipher_iv=base64.standard_b64encode(cipher_iv).decode(),
            private_key=base64.standard_b64encode(encrypted).decode(),
        )

        with open(path, 'w') as fobj:
            json.dump(serialized._asdict(), fobj, indent=2)

    def save_public(self, path):
        with open(path, 'wb') as fobj:
            fobj.write(
                base64.standard_b64encode(
                    self.public.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw)))

    @classmethod
    def generate(cls):
        return cls(x25519.X25519PrivateKey.generate())

    @classmethod
    def load_from_file(cls, path, *, password: str = None):
        with open(path) as fobj:
            d = json.load(fobj)

        serialized = cls._SerializedKey(**d)
        if serialized.pbkdf2_hash != cls._ENC_PBKDF2_HASH.name:
            raise RuntimeError('unsupported hash: ' + serialized.pbkdf2_hash)
        if serialized.cipher != cls._ENC_CIPHER_NAME:
            raise RuntimeError('unsupported cipher: ' + serialized.cipher)

        if password is None:
            password = getpass.getpass()
        kdf_salt = base64.standard_b64decode(serialized.pbkdf2_salt.encode())
        key = cls._key_from_password(password,
                                     kdf_salt,
                                     length=serialized.pbkdf2_len_bytes,
                                     iterations=serialized.pbkdf2_iters)

        cipher = cls._ENC_CIPHER(key)
        cipher_iv = base64.standard_b64decode(serialized.cipher_iv.encode())
        encrypted = base64.standard_b64decode(serialized.private_key.encode())
        decrypted = cipher.decrypt(cipher_iv, encrypted, None)

        return cls(x25519.X25519PrivateKey.from_private_bytes(decrypted))

    @classmethod
    def _key_from_password(cls,
                           password: str,
                           salt: bytes,
                           *,
                           length=_ENC_PBKDF2_LEN_BYTES,
                           iterations=_ENC_PBKDF2_ITERS) -> bytes:
        return PBKDF2HMAC(algorithm=cls._ENC_PBKDF2_HASH,
                          length=length,
                          salt=salt,
                          iterations=iterations,
                          backend=crypto_backend()).derive(
                              password.encode('UTF-8'))


class Archive:
    VERSION = 0x0
    _COMP_MODE = 0x1
    _ENC_MODE = 0x1
    _HEADER_FORMAT = '!BBB'

    _CRYPTO_BACKEND = crypto_backend()
    _PUBKEY_SIZE_BYTES = 32
    _IV_SIZE_BYTES = 16
    _CIPHER = AES
    _CIPHER_KEY_SIZE_BYTES = 32
    _CIPHER_IV_SIZE_BYTES = 12
    _AUTH_TAG_SIZE_BYTES = 16
    _KEY_DERIVATION_HASH = hashes.SHA256

    def __init__(self, cfg: ArchiveConfig, *, chunk_size=DEFAULT_CHUNK_SIZE):
        self._comp_cfg = cfg.compression
        self._enc_cfg = cfg.encryption
        self._chunk_size = chunk_size
        self._enc_pubkey = (self._load_pubkey(self._enc_cfg.public_key)
                            if self._enc_cfg else None)

    def store_file(self, file_or_path) -> typing.Iterable[bytes]:
        if isinstance(file_or_path, io.BufferedIOBase):
            yield from self._store_file(file_or_path)
        else:
            with open(file_or_path, 'rb') as fobj:
                yield from self._store_file(fobj)

    @classmethod
    def unarchive(cls,
                  file_or_path,
                  *,
                  input_size: typing.Optional[int] = None,
                  enc_privkey: typing.Optional[x25519.X25519PrivateKey] = None,
                  chunk_size=DEFAULT_CHUNK_SIZE) -> typing.Iterable[bytes]:
        if isinstance(file_or_path, io.BufferedIOBase):
            yield from cls._unarchive(file_or_path, input_size, enc_privkey,
                                      chunk_size)
        else:
            with open(file_or_path, 'rb') as fobj:
                yield from cls._unarchive(fobj, input_size, enc_privkey,
                                          chunk_size)

    def _store_file(self, fobj: io.BufferedIOBase) -> typing.Iterable[bytes]:
        need_compression = self._comp_cfg is not None
        orig_size = None
        if need_compression and fobj.seekable():
            orig_size = self._get_size_till_eof(fobj)
            if orig_size < self._comp_cfg.min_size:
                need_compression = False

        need_encryption = self._enc_cfg is not None
        yield self._make_header(comp=need_compression, enc=need_encryption)

        chunks = self._iter_file_chunk(fobj, self._chunk_size)
        if need_compression:
            chunks = self._compress(chunks, orig_size)
        if need_encryption:
            chunks = self._encrypt(chunks)
        yield from chunks

    @classmethod
    def _unarchive(cls, fobj: io.BufferedIOBase,
                   input_size: typing.Optional[int],
                   enc_privkey: typing.Optional[x25519.X25519PrivateKey],
                   chunk_size: int) -> typing.Iterable[bytes]:
        header = cls._parse_header(cls._read_exact(fobj, 3))
        if not header:
            raise RuntimeError('invalid archive')
        compression, encryption = header
        if encryption:
            if enc_privkey is None:
                raise RuntimeError('enc_privkey is required')
            if input_size is not None:
                input_size -= 3  # the header
            chunks = cls._decrypt(fobj, input_size, enc_privkey, chunk_size)
        else:
            chunks = cls._iter_file_chunk(fobj, chunk_size)
        if compression:
            chunks = cls._decompress(chunks)
        yield from chunks

    @classmethod
    def _iter_file_chunk(cls, fobj: io.BufferedIOBase,
                         chunk_size: int) -> typing.Iterable[bytes]:
        while True:
            data = fobj.read(chunk_size)
            if len(data) == 0:
                break
            yield data

    def _compress(self, data: typing.Iterable[bytes],
                  orig_size=None) -> typing.Iterable[bytes]:
        with LZ4FrameCompressor(auto_flush=True) as comp:
            yield comp.begin(orig_size or 0)
            for chunk in data:
                yield comp.compress(chunk)
            yield comp.flush()

    @classmethod
    def _decompress(cls,
                    data: typing.Iterable[bytes]) -> typing.Iterable[bytes]:
        with LZ4FrameDecompressor() as decomp:
            for chunk in data:
                if not chunk:
                    break
                yield decomp.decompress(chunk)
            assert decomp.eof

    def _encrypt(self, data: typing.Iterable[bytes]) -> typing.Iterable[bytes]:
        eprikey = x25519.X25519PrivateKey.generate()
        epubkey_bytes = eprikey.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        yield epubkey_bytes
        assert self._PUBKEY_SIZE_BYTES == len(epubkey_bytes)

        iv = os.urandom(self._IV_SIZE_BYTES)
        yield iv

        shared_secret = eprikey.exchange(self._enc_pubkey)
        cipher_key = self._derive_keys(shared_secret, iv)
        cipher_iv = iv[:self._CIPHER_IV_SIZE_BYTES]
        encryptor = Cipher(algorithm=self._CIPHER(cipher_key),
                           mode=GCM(cipher_iv),
                           backend=self._CRYPTO_BACKEND).encryptor()

        for chunk in data:
            yield encryptor.update(chunk)
        yield encryptor.finalize()
        yield encryptor.tag

    @classmethod
    def _decrypt(cls, fobj: io.BufferedIOBase,
                 input_size: typing.Optional[int],
                 privkey: x25519.X25519PrivateKey,
                 chunk_size: int) -> typing.Iterable[bytes]:
        if input_size is None:
            input_size = cls._get_size_till_eof(fobj)

        epubkey = x25519.X25519PublicKey.from_public_bytes(
            cls._read_exact(fobj, cls._PUBKEY_SIZE_BYTES))
        input_size -= cls._PUBKEY_SIZE_BYTES
        shared_secret = privkey.exchange(epubkey)
        iv = cls._read_exact(fobj, cls._IV_SIZE_BYTES)
        input_size -= cls._IV_SIZE_BYTES
        cipher_key = cls._derive_keys(shared_secret, iv)
        cipher_iv = iv[:cls._CIPHER_IV_SIZE_BYTES]
        decryptor = Cipher(algorithm=cls._CIPHER(cipher_key),
                           mode=GCM(cipher_iv),
                           backend=cls._CRYPTO_BACKEND).decryptor()

        if input_size < cls._AUTH_TAG_SIZE_BYTES:
            raise RuntimeError('input_size is too short')
        bufmv = memoryview(bytearray(chunk_size))
        auth_tag = b''
        while input_size > 0:
            bytes_read = fobj.readinto(bufmv)
            if bytes_read == 0:
                break
            input_size -= bytes_read
            if input_size <= cls._AUTH_TAG_SIZE_BYTES:
                auth_tag_part_len = cls._AUTH_TAG_SIZE_BYTES - input_size
                auth_tag += bufmv[bytes_read - auth_tag_part_len:bytes_read]
                auth_tag += fobj.read()
                yield decryptor.update(bufmv[:bytes_read - auth_tag_part_len])
            else:
                yield decryptor.update(bufmv[:bytes_read])
        yield decryptor.finalize_with_tag(auth_tag)

    @classmethod
    def _make_header(cls, *, comp: bool, enc: bool) -> bytes:
        return struct.pack(cls._HEADER_FORMAT, cls.VERSION,
                           cls._COMP_MODE if comp else 0,
                           cls._ENC_MODE if enc else 0)

    @classmethod
    def _parse_header(cls, header: bytes
                      ) -> typing.Optional[typing.Tuple[bool, bool]]:
        ver, comp, enc = struct.unpack(cls._HEADER_FORMAT, header)
        if ver != cls.VERSION:
            return None
        return comp, enc

    @classmethod
    def _load_pubkey(cls, pubkey_file) -> x25519.X25519PublicKey:
        with open(pubkey_file, 'rb') as fobj:
            b = base64.standard_b64decode(fobj.read())
            return x25519.X25519PublicKey.from_public_bytes(b)

    @classmethod
    def _derive_keys(cls, shared_secret, iv) -> bytes:
        return HKDF(algorithm=cls._KEY_DERIVATION_HASH(),
                    length=cls._CIPHER_KEY_SIZE_BYTES,
                    salt=iv,
                    info=None,
                    backend=cls._CRYPTO_BACKEND).derive(shared_secret)

    @staticmethod
    def _get_size_till_eof(fobj: io.IOBase) -> int:
        start = fobj.tell()
        end = fobj.seek(0, io.SEEK_END)
        fobj.seek(start)
        return end - start

    @staticmethod
    def _read_exact(fobj: io.BufferedIOBase, size: int) -> bytes:
        buf = bytearray(size)
        bufmv = memoryview(buf)
        while size > 0:
            bytes_read = fobj.readinto(bufmv[-size:])
            if bytes_read == 0:
                raise RuntimeError('EOF occurred')
            size -= bytes_read
        return bytes(buf)
