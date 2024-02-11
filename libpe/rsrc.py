import dataclasses
import datetime
import pathlib
import typing

from libpe.data_stream import DataInput
from libpe.enums import ResourceType
from libpe.exceptions import PEFormatException
from libpe.structs import SectionHeader


@dataclasses.dataclass
class Resource:
    type: ResourceType = ResourceType.UNKNOWN
    name: str = None
    language: int = 0
    size: int = 0
    codepage: int = 0
    offset: int = 0


class ResourceManager:
    def __init__(self, fp: DataInput, s: SectionHeader):
        self.resources = []
        self._dirs = []
        self._section = s
        self._base = fp.pos
        self._fp = fp
        self._add_resource_directory(ResourceDirectory.read(fp))

    def _add_resource_directory(self, dir):
        for e in dir.name_entries.values():
            self._add_entry(e)

        for e in dir.id_entries.values():
            self._add_entry(e)

    def _add_entry(self, e):
        if e.directory is None:
            self.resources.append(Resource(
                ResourceType(self._dirs[0]),
                self._dirs[1],
                e.name or hex(e.id)[2:],
                e.data.size, e.data.codepage,
                e.data.rva + self._base - self._section.virtual_address
            ))
        else:
            self._dirs.append(e.name or e.id)
            self._add_resource_directory(e.directory)
            self._dirs.pop(-1)

    def extract(self, out: pathlib.Path):
        for i in self.resources:
            dir = out / str(i.type).removeprefix('ResourceType.')
            dir.mkdir(exist_ok=True, parents=True)
            file = dir / f"{i.name}.{i.language}"
            self._fp.pos = i.offset
            file.write_bytes(self._fp.read(i.size))


@dataclasses.dataclass
class ResourceDataEntry:
    rva: int = 0
    size: int = 0
    codepage: int = 0

    @classmethod
    def read(cls, fp: DataInput):
        self = cls()
        self.rva = fp.read_int(32)
        self.size = fp.read_int(32)
        self.codepage = fp.read_int(32)
        reserved = fp.read_int(32)
        if reserved != 0:
            raise PEFormatException(fp, -4, "reserved != 0")

        return self


@dataclasses.dataclass
class ResourceDirectoryEntry:
    name: typing.Optional[str] = None
    id: typing.Optional[int] = None
    data: typing.Optional[ResourceDataEntry] = None
    directory: typing.Optional['ResourceDirectory'] = None

    @classmethod
    def read(cls, fp: DataInput, base, is_named):
        self = cls()
        name = fp.read_int(32)
        if is_named != bool(name >> 31):
            raise PEFormatException(fp, -4, "Named/unnamed missmatch")

        if is_named:
            tmp = fp.pos
            fp.pos = base + (name & 0x7FFFFFFF)
            size = fp.read_int(16)
            self.name = fp.read(size * 2).decode('UTF-16', 'backslashreplace')
            fp.pos = tmp
        else:
            self.id = name

        offset = fp.read_int(32)
        is_directory = bool(offset >> 31)
        offset = offset & 0x7FFFFFFF

        tmp = fp.pos
        fp.pos = base + offset
        if is_directory:
            self.directory = ResourceDirectory.read(fp, base)
        else:
            self.data = ResourceDataEntry.read(fp)

        fp.pos = tmp

        return self


@dataclasses.dataclass
class ResourceDirectory:
    time_date_stamp: datetime.datetime = datetime.datetime.min
    major_version: int = 0
    minor_version: int = 0
    name_entries: dict[str, ResourceDirectoryEntry] = dataclasses.field(default_factory=dict)
    id_entries: dict[int, ResourceDirectoryEntry] = dataclasses.field(default_factory=dict)

    @classmethod
    def read(cls, fp: DataInput, base=None):
        if base is None:
            base = fp.pos

        characteristics = fp.read_int(32)
        if characteristics != 0:
            raise PEFormatException(fp, -4, "characteristics != 0")

        self = cls()
        self.time_date_stamp = datetime.datetime.fromtimestamp(fp.read_int(32))
        self.major_version = fp.read_int(16)
        self.minor_version = fp.read_int(16)
        number_of_named_entries = fp.read_int(16)
        number_of_id_entries = fp.read_int(16)

        for _ in range(number_of_named_entries):
            e = ResourceDirectoryEntry.read(fp, base, True)
            self.name_entries[e.name] = e

        for _ in range(number_of_id_entries):
            e = ResourceDirectoryEntry.read(fp, base, False)
            self.id_entries[e.id] = e

        return self
