# -*- coding: utf-8 -*-

import hashlib
import zlib

from pathlib import Path
from typing import Union, Tuple, List


class FileChecksum:
    """
    This module is to create and validate checksums of files
    """

    _DEFAULT_CHUNK_SIZE = 2048
    _DEFAULT_ALGORITHMS = 'sha1'
    _ZLIB_ALGORITHMS = {'adler32', 'crc32'}

    def __init__(self, algorithm: str = '', chunk_size: int = 0):
        """
        :param algorithm: the algorithm that is used to create the checksum
        :param chunk_size: the size of the chunks that is used to read files
        """
        if not algorithm:
            algorithm = self._DEFAULT_ALGORITHMS
        if type(algorithm) is not str:
            raise TypeError('algorithm should be from type str')
        if algorithm not in self.available_algorithms():
            raise ValueError('algorithm is not a valid checksum algorithm')
        self._algorithm = algorithm

        if not chunk_size:
            chunk_size = self._DEFAULT_CHUNK_SIZE
        if type(chunk_size) is not int:
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
        return hashlib.algorithms_available | FileChecksum._ZLIB_ALGORITHMS

    def create_checksum_file(self, file_path: Union[str, Path]) -> Union[hash, int]:
        """
        this method will create a checksum for a specified file
        :param file_path: path to the file
        :return: returns a hash object in case of an hashlib or OpenSSL algorithm and an int if its from zlib
        """
        file = self._validate_file_path(file_path)
        return self._get_checksum(file)

    def create_checksum_files(self, dir_path: Union[str, Path],
                              pattern: str = '*') -> List[Tuple[Path, Union[hash, int]]]:
        """
        this method will create checksum for all files in a directory
        :param dir_path: path to the dir
        :param pattern: pattern to filter for files
        :return: returns a list of tuples where the first is the Path to the file and the second the checksum
        """
        if type(pattern) is not str:
            TypeError('patter should be from type str')

        filesdir = self._validate_dir_path(dir_path)
        return [(file, self._get_checksum(file) for file in filesdir.rglob(pattern) if file.is_file())]

    def create_checksum_dir(self, dir_path: Union[str, Path], pattern: str = '*') -> Union[hash, int]:
        """

        :param dir_path: path to the dir
        :param pattern: pattern to filter for files
        :return:
        """
        if type(pattern) is not str:
            TypeError('patter should be from type str')

        filesdir = self._validate_dir_path(dir_path)

    def verify_checksum_file(self, file_path: Union[str, Path], checksum: Union[int, bytes, str, hash],
                             length: int = 0) -> bool:
        """
        this method is to validate whether a checksum for a file is valid or not
        :param file_path: path to the file
        :param checksum: a representation of a checksum
        :param length: specifies the length if the shake algorithms are used
        :return: returns a bool that represents if the checksum is valid
        """
        file = self._validate_file_path(file_path)
        file_checksum = self._get_checksum(file)
        return self._verify_checksum(checksum, file_checksum, length)

    def verify_checksum_files(self, checksum: List[Tuple[Path, Union[int, bytes, str, hash]]],
                              length: int = 0) -> List[Tuple[Path, bool]]:
        """
        this method will validate a list of files with their corresponding checksum
        :param checksum: list of checksums with path to the file
        :param length: specifies the length if the shake algorithms are used
        :return: a list with path to the and a bool as a tuple
        """
        return [(file, self.verify_checksum_file(file, checksum, length)) for file, checksum in checksum]

    def verify_checksum_dir(self, dir_path: Union[str, Path], checksum: Union[int, bytes, str, hash],
                            length: int = 0, pattern: str = '*') -> bool:
        """

        :param dir_path: path to the dir
        :param checksum:
        :param length:
        :param pattern: pattern to filter for files
        :return:
        """
        if type(pattern) is not str:
            TypeError('patter should be from type str')

        filesdir = self._validate_dir_path(dir_path)

    def _verify_checksum(self, checksum: Union[int, bytes, str, hash], self_checksum: hash, length: int = 0) -> bool:
        _SHAKE = {'shake_128', 'shake_256'}
        args = []

        if self._algorithm in _SHAKE:
            if type(length) is not int:
                TypeError('length should be from type int')
            if length <= 0:
                raise ValueError('the length must be greater than 0')
            args.append(length)

        if type(checksum) is int and self._algorithm in self._ZLIB_ALGORITHMS:
            return checksum == self_checksum

        if isinstance(checksum, type(hashlib.new(self._algorithm))):
            return checksum.digest(*args) == self_checksum.digest(*args)
        if type(checksum) is bytes:
            return checksum == self_checksum.digest(*args)
        if type(checksum) is str:
            return checksum == self_checksum.hexdigest(*args)

        return False

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
        if type(path) is str:
            path = Path(path)
        if Path not in path.__class__.__mro__:
            raise TypeError(f'file_path should be from type Path but is from type {type(path)}')
        return path

    def _get_checksum(self, file: Path) -> Union[hash, int]:
        def _hashlib() -> hash:
            h = hashlib.new(self._algorithm)
            for chunk in self._get_file(file):
                h.update(chunk)
            return h

        def _zlib() -> int:
            h, c = getattr(zlib, self._algorithm), 0
            for chunk in self._get_file(file):
                c = h(chunk, c) & 0xffffffff
            return c

        if self._algorithm in self._ZLIB_ALGORITHMS:
            return _zlib()
        return _hashlib()

    def _get_file(self, file: Path) -> bytes:
        with open(file, 'rb') as f:
            for chunk in iter(lambda: f.read(self._chunk_size), b''):
                yield chunk
