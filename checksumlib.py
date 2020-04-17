# -*- coding: utf-8 -*-

import hashlib
import zlib

from pathlib import Path
from typing import Union

import _hashlib
import _sha3


class FileChecksum:
    """
    This module is to create and validate checksums of files
    """

    _DEFAULT_CHUNK_SIZE = 1024
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
            raise TypeError('algorithm is not type str')
        if algorithm not in self.available_algorithms():
            raise ValueError('algorithm is not a valid checksum algorithm')
        self._algorithm = algorithm

        if not chunk_size:
            chunk_size = self._DEFAULT_CHUNK_SIZE
        if type(chunk_size) is not int:
            raise TypeError('chunk_size is not type int')
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

    def create_checksum(self, file_path: Union[str, Path]) -> Union[hash, int]:
        """
        this method will create a checksum for a specified file
        :param file_path: path to the file
        :return: returns a hash object in case of an hashlib or OpenSSL algorithm and an int if its from zlib
        """
        file = self._valdate_file_path(file_path)
        return self._get_checksum(file)

    def verify_checksum(self, file_path: Union[str, Path], checksum: Union[int, bytes, str, hash], length: int = 0) -> bool:
        """
        this method is to validate whether a checksum for a file is valid or not
        :param file_path: path to the file
        :param checksum: a representation of a checksum
        :param length: specifies the length when the shake algorithms are used
        :return: returns a bool that represents if the checksum is valid
        """
        _SHAKE = {'shake_128', 'shake_256'}
        args = []

        if self._algorithm in _SHAKE:
            if length <= 0:
                raise ValueError('the length must be greater than 0')
            args.append(length)

        file = self._valdate_file_path(file_path)
        file_checksum = self._get_checksum(file)

        if type(checksum) is int and self._algorithm in self._ZLIB_ALGORITHMS:
            return checksum == file_checksum

        if isinstance(checksum, type(hashlib.new(self._algorithm))):
            return checksum.digest(*args) == file_checksum.digest(*args)
        if type(checksum) is bytes:
            return checksum == file_checksum.digest(*args)
        if type(checksum) is str:
            return checksum == file_checksum.hexdigest(*args)

        return False

    def _valdate_file_path(self, file_path: Union[str, Path]) -> Path:
        """
        Validates if there is an file that corresponds with the path
        :param file_path: path to the file
        :return: returns the path as an Path object
        """
        if type(file_path) is str:
            file_path = Path(file_path)
        if Path not in file_path.__class__.__mro__:
            raise TypeError(f'file_path should be from type Path but is from type {type(file_path)}')
        if not file_path.is_file():
            raise FileNotFoundError('the specified file does not exists')
        return file_path

    def _get_checksum(self, file: Path) -> Union[hash, int]:
        """
        this method will create the checksum for a file
        :param file: Path object that represents the file
        :return: returns a checksum
        """
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
        """
        this method will yield a specified file in the defined chunk size
        :param file: Path object that represents the file
        :return: yields the data of a files as bytes in the specified chunk size
        """
        with open(file, 'rb') as f:
            for chunk in iter(lambda: f.read(self._chunk_size), b''):
                yield chunk
