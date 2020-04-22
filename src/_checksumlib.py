import hashlib
import zlib


def _validate_algorithm(func):
    def wrapper(cls, algorithm: str, *args, **kwargs):
        if not isinstance(algorithm, str):
            raise TypeError('algorithm should be from type str')

        algorithms = cls.get_algorithms() if not isinstance(cls, MetaChecksum) else _Checksum.get_algorithms()
        if algorithm not in algorithms:
            raise ValueError('algorithm is not a valid _Checksum algorithm')
        return func(cls, algorithm, *args, **kwargs)
    return wrapper


class MetaChecksum(type):

    @_validate_algorithm
    def __call__(self, algorithm: str = '', *args, **kwargs):
        if not algorithm:
            algorithm = self._DEFAULT_ALGORITHMS

        for cls in _Checksum.__subclasses__():
            if algorithm in cls.get_algorithms():
                return cls(algorithm, *args, **kwargs)


class Checksum(metaclass=MetaChecksum):

    _DEFAULT_ALGORITHMS = 'sha1'


class _Checksum:

    @_validate_algorithm
    def __init__(self, algorithm: str = ''):
        self._algorithm = algorithm

    def __eq__(self, checksum) -> bool:
        if isinstance(checksum, bytes):
            return self.to_bytes() == checksum
        if isinstance(checksum, int):
            return self.to_int() == checksum
        if isinstance(checksum, str):
            return self.to_str() == checksum
        if isinstance(checksum, self.__class__):
            return self.to_int() == checksum.to_int()
        return False

    def __bytes__(self):
        return self.to_bytes()

    def __int__(self):
        return self.to_int()

    def __str__(self):
        return self.to_str()

    def __add__(self, data: bytes):
        self.update(data)

    def get_algorithm(self):
        return self._algorithm

    @staticmethod
    def get_algorithms() -> set:
        algorithms = set()
        for cls in _Checksum.__subclasses__():
            algorithms |= cls.get_algorithms()
        return algorithms

    def to_bytes(self):
        raise NotImplementedError

    def to_int(self):
        raise NotImplementedError

    def to_str(self):
        raise NotImplementedError

    def update(self, data: bytes):
        raise NotImplementedError


class CRCChecksum(_Checksum):

    def __init__(self, algorithm: str = ''):
        super().__init__(algorithm)
        self._crc = getattr(zlib, self._algorithm)
        self._c = 0

    @staticmethod
    def get_algorithms() -> set:
        return {'adler32', 'crc32'}

    def to_bytes(self) -> bytes:
        return self._c.to_bytes(length=4, byteorder='big')

    def to_int(self) -> int:
        return self._c

    def to_str(self) -> str:
        return hex(self._c)

    def update(self, data: bytes):
        self._c = self._crc(data, self._c) & 0xffffffff


class HashChecksum(_Checksum):
    
    _SHAKE = {'shake_128', 'shake_256'}
    _DEFAULT_SHAKE_LENGTH = 32

    def __init__(self, algorithm: str = '', length: int = 0):
        super().__init__(algorithm)
        self._hash = hashlib.new(algorithm)

        if not length:
            length = self._DEFAULT_SHAKE_LENGTH
        if not isinstance(length, int):
            TypeError('length should be from type int')
        if length <= 0:
            raise ValueError('the length must be greater than 0')
        self._length = length

    @staticmethod
    def get_algorithms() -> set:
        return hashlib.algorithms_available

    def to_bytes(self) -> bytes:
        return self._hash.digest(*self._get_args())

    def to_int(self) -> int:
        return int.from_bytes(self._hash.digest(*self._get_args()), 'big')

    def to_str(self) -> str:
        return f'0x{self._hash.hexdigest(*self._get_args())}'

    def update(self, data: bytes):
        self._hash.update(data)

    def _get_args(self) -> list:
        if self._algorithm not in self._SHAKE:
            return []
        return [self._length]
