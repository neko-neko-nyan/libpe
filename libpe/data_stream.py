import struct

import typing.io

_FORMAT = "BH I   Q"


class DataInput:
    __slots__ = ('_fp', )

    def __init__(self, fp: typing.io.BinaryIO):
        self._fp = fp

    @property
    def pos(self) -> int:
        return self._fp.tell()

    @pos.setter
    def pos(self, value: int):
        self._fp.seek(value)

    def read_int(self, size: int) -> int:
        size //= 8
        assert size in (1, 2, 4, 8)
        return struct.unpack("=" + _FORMAT[size - 1], self._fp.read(size))[0]

    def read(self, count: int) -> bytes:
        return self._fp.read(count)
