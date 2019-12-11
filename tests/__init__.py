import os
import pathlib
import tempfile


class TmpfsMixin:
    def init_tmpfs(self):
        self.__tmpdir_obj = tempfile.TemporaryDirectory()
        self.__tmpdir = self.__tmpdir_obj.name

    def mock_file(self, path=None, *, content=b'', rand_len=0) -> pathlib.Path:
        if content and rand_len:
            raise ValueError('content and rand_len cannot be used together')
        if path is None:
            fd, full_path = tempfile.mkstemp(dir=self.__tmpdir)
            os.close(fd)
            full_path = pathlib.Path(full_path)
        else:
            full_path = pathlib.Path(self.__tmpdir, path)
            full_path.parent.mkdir(parents=True, exist_ok=True)
        with full_path.open('wb') as fobj:
            if content:
                fobj.write(content)
            elif rand_len:
                fobj.write(os.urandom(rand_len))
        return full_path

    def mock_dir(self, path) -> pathlib.Path:
        full_path = pathlib.Path(self.__tmpdir, path)
        full_path.mkdir(parents=True, exist_ok=True)
        return full_path

    def mock_path(self, path) -> pathlib.Path:
        return pathlib.Path(self.__tmpdir, path)
