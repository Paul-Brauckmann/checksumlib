# -*- coding: utf-8 -*-
import hashlib
import zlib

from pathlib import Path, PosixPath, WindowsPath
from typing import Union, Tuple, List

from ._checksumlib import Checksum, _Checksum


class FileChecksum:
    """
    This module is to create and validate checksums of files
    """
    _DEFAULT_CHUNK_SIZE = 2048

    def __init__(self, algorithm: str = '', chunk_size: int = 0):
        """
        :param algorithm: the algorithm that is used to create the checksum
        :param chunk_size: the size of the chunks that is used to read files
        """
        if not algorithm:
            algorithm = Checksum.DEFAULT_ALGORITHMS
        if not isinstance(algorithm, str):
            raise TypeError('algorithm should be from type str')
        if algorithm not in self.available_algorithms():
            raise ValueError('algorithm is not a valid checksum algorithm')
        self._algorithm = algorithm

        if not chunk_size:
            chunk_size = self._DEFAULT_CHUNK_SIZE
        if not isinstance(chunk_size, int):
            raise TypeError('chunk_size should be from type int')
        if chunk_size <= 0:
            raise ValueError('the chunk_size must be greater than 0')
        self._chunk_size = chunk_size

    @staticmethod
    def available_algorithms() -> set:
        """
        this method will return a set of available hashing algorithms for creating checksums
        :return: returns a set of hash algorithms that are allowed
        """
        return Checksum.available_algorithms()

    def create_checksum_file(self, file_path: Union[str, Path]) -> Union[hash, int]:
        """
        this method will create a checksum for a specified file
        :param file_path: path to the file
        :return: returns a hash object in case of an hashlib or OpenSSL algorithm and an int if its from zlib
        """
        file = self._validate_file_path(file_path),
        return self._get_checksum(file)

    def create_checksum_files(self, dir_path: Union[str, Path],
                              pattern: str = '*') -> List[Tuple[Path, Union[hash, int]]]:
        """
        this method will create checksum for all files in a directory
        :param dir_path: path to the dir
        :param pattern: pattern to filter for files
        :return: returns a list of tuples where the first is the Path to the file and the second the checksum
        """
        if not isinstance(pattern, str):
            TypeError('patter should be from type str')

        filesdir = self._validate_dir_path(dir_path)
        return [(file, self._get_checksum((file,))) for file in filesdir.rglob(pattern) if file.is_file()]

    def create_checksum_dir(self, dir_path: Union[str, Path], pattern: str = '*') -> Union[hash, int]:
        """
        this method will create checksum for a directory
        :param dir_path: path to the dir
        :param pattern: pattern to filter for files
        :return:
        """
        if not isinstance(pattern, str):
            TypeError('patter should be from type str')

        filesdir = self._validate_dir_path(dir_path)
        return self._get_checksum(filesdir.rglob(pattern))

    def verify_checksum_file(self, file_path: Union[str, Path], checksum: Union[int, bytes, str, _Checksum]) -> bool:
        """
        this method is to validate whether a checksum for a file is valid or not
        :param file_path: path to the file
        :param checksum: a representation of a checksum
        :param length: specifies the length if the shake algorithms are used
        :return: returns a bool that represents if the checksum is valid
        """
        file = self._validate_file_path(file_path),
        file_checksum = self._get_checksum(file)
        return self._verify_checksum(checksum, file_checksum)

    def verify_checksum_files(self, checksums: List[Tuple[Path, Union[int, bytes, str, _Checksum]]]) -> List[Tuple[Path, bool]]:
        """
        this method will validate a list of files with their corresponding checksum
        :param checksum: list of checksums with path to the file
        :param length: specifies the length if the shake algorithms are used
        :return: a list with path to the and a bool as a tuple
        """
        result = []
        for file_path, checksum in checksums:
            file = self._validate_file_path(file_path),
            file_checksum = self._get_checksum(file)
            result.append((file, self._verify_checksum(checksum, file_checksum)))
        return result

    def verify_checksum_dir(self, dir_path: Union[str, Path], checksum: Union[int, bytes, str, _Checksum],
                            pattern: str = '*') -> bool:
        """
        this method will validate a checksum of a dir
        :param dir_path: path to the dir
        :param checksum:
        :param length:
        :param pattern: pattern to filter for files
        :return:
        """
        if not isinstance(pattern, str):
            TypeError('patter should be from type str')

        filesdir = self._validate_dir_path(dir_path)
        return self._verify_checksum(checksum, self._get_checksum(filesdir.rglob(pattern)))


    def _verify_checksum(self, checksum: Union[int, bytes, str, _Checksum], self_checksum: _Checksum) -> bool:
        return self_checksum == checksum

    def _validate_file_path(self, file_path: Union[str, Path]) -> Path:
        file_path = self._validate_path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f'the specified file {file_path} does not exists')
        return file_path

    def _validate_dir_path(self, dir_path: Union[str, Path]) -> Path:
        dir_path = self._validate_path(dir_path)
        if not dir_path.is_dir():
            raise FileNotFoundError('the specified dir does not exists')
        return dir_path

    def _validate_path(self, path: Union[str, Path]) -> Path:
        if isinstance(path, str):
            path = Path(path)
        if not isinstance(path, (PosixPath, WindowsPath)):
            raise TypeError(f'file_path should be from type Path but is from type {type(path)}')
        return path

    def _get_checksum(self, files: Path) -> _Checksum:
        c = Checksum(self._algorithm)

        for chunk in self._get_data(files):
            c.update(chunk)
        return c

    def _get_data(self, files: List[Path]) -> bytes:
        for file in files:
            with open(file, 'rb') as f:
                for chunk in iter(lambda: f.read(self._chunk_size), b''):
                    yield chunk
