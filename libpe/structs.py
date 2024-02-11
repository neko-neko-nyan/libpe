import dataclasses
import datetime
import typing

from libpe.data_stream import DataInput
from libpe.enums import NtMachine, NtCharacteristics, NtSubsystem, DllCharacteristics, SectionCharacteristics
from libpe.exceptions import PEFormatException
from libpe.output import Output


@dataclasses.dataclass
class DOSHeader:
    cblp: int = 0
    cp: int = 0
    crlc: int = 0
    cparhdr: int = 0
    minalloc: int = 0
    maxalloc: int = 0
    ss: int = 0
    sp: int = 0
    csum: int = 0
    ip: int = 0
    cs: int = 0
    lfarlc: int = 0
    ovno: int = 0
    res: list[int] = dataclasses.field(default_factory=list)
    oemid: int = 0
    oeminfo: int = 0
    res2: list[int] = dataclasses.field(default_factory=list)
    lfanew: int = 0

    @classmethod
    def read(cls, fp: DataInput):
        magic = fp.read_int(16)
        if magic != 0x5A4D:
            raise PEFormatException(fp, -2, "Invalid DOS magic number")

        self = cls()
        self.cblp = fp.read_int(16)
        self.cp = fp.read_int(16)
        self.crlc = fp.read_int(16)
        self.cparhdr = fp.read_int(16)
        self.minalloc = fp.read_int(16)
        self.maxalloc = fp.read_int(16)
        self.ss = fp.read_int(16)
        self.sp = fp.read_int(16)
        self.csum = fp.read_int(16)
        self.ip = fp.read_int(16)
        self.cs = fp.read_int(16)
        self.lfarlc = fp.read_int(16)
        self.ovno = fp.read_int(16)
        self.res = [fp.read_int(16) for _ in range(4)]
        self.oemid = fp.read_int(16)
        self.oeminfo = fp.read_int(16)
        self.res2 = [fp.read_int(16) for _ in range(10)]

        self.lfanew = fp.read_int(32)
        if self.lfanew < 62:
            raise PEFormatException(fp, -4, "Overlapping DOS and PE headers")

        return self

    def print_info(self, output: Output):
        output.begin('DOS Header')
        output.write('cblp', self.cblp, 'address')
        output.write('cp', self.cp, 'address')
        output.write('crlc', self.crlc, 'address')
        output.write('cparhdr', self.cparhdr, 'address')
        output.write('minalloc', self.minalloc, 'address')
        output.write('maxalloc', self.maxalloc, 'address')
        output.write('ss', self.ss, 'address')
        output.write('sp', self.sp, 'address')
        output.write('csum', self.csum, 'address')
        output.write('ip', self.ip, 'address')
        output.write('cs', self.cs, 'address')
        output.write('lfarlc', self.lfarlc, 'address')
        output.write('ovno', self.ovno, 'address')
        output.write('res', self.res, 'count')
        output.write('oemid', self.oemid, 'address')
        output.write('oeminfo', self.oeminfo, 'address')
        output.write('res2', self.res2, 'count')
        output.write('lfanew', self.lfanew, 'address')
        output.end()


@dataclasses.dataclass
class PEHeader:
    machine: NtMachine = NtMachine.UNKNOWN
    number_of_sections = 0
    time_date_stamp: datetime.datetime = datetime.datetime.min
    pointer_to_symbol_table: int = 0
    number_of_symbols: int = 0
    size_of_optional_header: int = 0
    characteristics: NtCharacteristics = NtCharacteristics(0)

    @classmethod
    def read(cls, fp: DataInput):
        signature = fp.read_int(32)
        if signature != 0x4550:
            raise PEFormatException(fp, -4, "Invalid PE magic number")

        self = cls()
        self.machine = NtMachine(fp.read_int(16))  # TODO: validate machine
        self.number_of_sections = fp.read_int(16)
        self.time_date_stamp = datetime.datetime.fromtimestamp(fp.read_int(32))
        self.pointer_to_symbol_table = fp.read_int(32)
        self.number_of_symbols = fp.read_int(32)
        self.size_of_optional_header = fp.read_int(16)
        self.characteristics = NtCharacteristics(fp.read_int(16))  # TODO: validate characteristics
        return self

    def print_info(self, output: Output):
        output.begin("PE Header")

        output.write("Machine", self.machine, 'enum')
        output.write("Compilation time", self.time_date_stamp, 'datetime')
        output.write("Characteristics", self.characteristics, 'flags')

        if self.pointer_to_symbol_table == 0:
            output.write("Symbol table", None, 'raw')
        else:
            output.write("Symbol table", f"with {self.number_of_symbols} entries", 'raw')

        output.end()


@dataclasses.dataclass
class OptionalHeader:
    is_pe_plus: bool = False
    subsystem: NtSubsystem = NtSubsystem.UNKNOWN
    dll_characteristics: DllCharacteristics = DllCharacteristics(0)
    check_sum: int = 0
    address_of_entry_point: int = 0
    base_of_code: int = 0
    base_of_data: int = 0
    image_base: int = 0

    number_of_rva_and_sizes: int = 0

    section_alignment: int = 0
    file_alignment: int = 0

    size_of_code: int = 0
    size_of_initialized_data: int = 0
    size_of_uninitialized_data: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    size_of_stack_reserve: int = 0
    size_of_stack_commit: int = 0
    size_of_heap_reserve: int = 0
    size_of_heap_commit: int = 0

    major_linker_version: int = 0
    minor_linker_version: int = 0
    major_operating_system_version: int = 0
    minor_operating_system_version: int = 0
    major_image_version: int = 0
    minor_image_version: int = 0
    major_subsystem_version: int = 0
    minor_subsystem_version: int = 0

    @classmethod
    def read(cls, fp: DataInput, size):
        if size == 0:
            return None

        if size < 24:
            raise PEFormatException(fp, 0, "Optional header too short (universal)")

        magic = fp.read_int(16)
        if magic not in {0x10B, 0x20B}:
            raise PEFormatException(fp, -4, "Invalid PE optional header magic number")

        self = cls()
        self.is_pe_plus = magic == 0x20B
        self.major_linker_version = fp.read_int(8)
        self.minor_linker_version = fp.read_int(8)
        self.size_of_code = fp.read_int(32)
        self.size_of_initialized_data = fp.read_int(32)
        self.size_of_uninitialized_data = fp.read_int(32)
        self.address_of_entry_point = fp.read_int(32)
        self.base_of_code = fp.read_int(32)

        if self.is_pe_plus:
            self.base_of_data = 0
            bits = 64
        elif size < 28:
            raise PEFormatException(fp, 0, "Optional header too short (universal, PE)")
        else:
            self.base_of_data = fp.read_int(32)
            bits = 32

        if size == (24 if self.is_pe_plus else 28):
            return self

        data_dirs_size = size - (96 if bits == 32 else 112)
        if data_dirs_size < 0:
            raise PEFormatException(fp, 0, "Optional header too short (windows)")

        self.image_base = fp.read_int(bits)
        self.section_alignment = fp.read_int(32)
        self.file_alignment = fp.read_int(32)
        self.major_operating_system_version = fp.read_int(16)
        self.minor_operating_system_version = fp.read_int(16)
        self.major_image_version = fp.read_int(16)
        self.minor_image_version = fp.read_int(16)
        self.major_subsystem_version = fp.read_int(16)
        self.minor_subsystem_version = fp.read_int(16)

        win32_version_value = fp.read_int(32)
        if win32_version_value != 0:
            raise PEFormatException(fp, -4, "win32_version_value must be zero")

        self.size_of_image = fp.read_int(32)
        self.size_of_headers = fp.read_int(32)
        self.check_sum = fp.read_int(32)
        self.subsystem = NtSubsystem(fp.read_int(16))
        self.dll_characteristics = DllCharacteristics(fp.read_int(16))
        self.size_of_stack_reserve = fp.read_int(bits)
        self.size_of_stack_commit = fp.read_int(bits)
        self.size_of_heap_reserve = fp.read_int(bits)
        self.size_of_heap_commit = fp.read_int(bits)

        loader_flags = fp.read_int(32)
        if loader_flags != 0:
            raise PEFormatException(fp, -4, "loader_flags must be zero")

        self.number_of_rva_and_sizes = fp.read_int(32)
        if data_dirs_size != self.number_of_rva_and_sizes * 8:
            raise PEFormatException(fp, 0, "Optional header size does not match count of data dirs")

        return self

    def print_info(self, output: Output):
        output.begin(f"NT Optional {'Plus ' if self.is_pe_plus else ''}Header")
        output.write("Subsystem", self.subsystem, 'enum')
        output.write("DLL Characteristics", self.dll_characteristics, 'flags')
        output.write("Checksum", self.check_sum, 'address')
        output.write("Entry point", self.address_of_entry_point, 'address')
        output.write("Base of code", self.base_of_code, 'address')

        if self.base_of_data:
            output.write("Base of data", self.base_of_data, 'address')

        output.write("Image base", self.image_base, 'address')

        output.begin("Alignment")
        output.write("Section", self.section_alignment, 'alignment')
        output.write("File", self.file_alignment, 'alignment')
        output.end()

        output.begin("Versions")
        output.write("Linker", (self.major_linker_version, self.minor_linker_version), 'version')
        output.write("OS", (self.major_operating_system_version, self.minor_operating_system_version), 'version')
        output.write("Image", (self.major_image_version, self.minor_image_version), 'version')
        output.write("Subsystem", (self.major_subsystem_version, self.minor_subsystem_version), 'version')
        output.end()

        output.begin("Size")
        output.write("Code", self.size_of_code, 'size')
        output.write("Initialized data", self.size_of_initialized_data, 'size')
        output.write("Uninitialized data", self.size_of_uninitialized_data, 'size')
        output.write("Image", self.size_of_image, 'size')
        output.write("Headers", self.size_of_headers, 'size')
        output.write("Stack reserve", self.size_of_stack_reserve, 'size')
        output.write("Stack commit", self.size_of_stack_commit, 'size')
        output.write("Heap reserve", self.size_of_heap_reserve, 'size')
        output.write("Heap commit", self.size_of_heap_commit, 'size')
        output.end()
        output.end()


@dataclasses.dataclass
class SectionHeader:
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    pointer_to_raw_data: int = 0
    size_of_raw_data: int = 0
    pointer_to_relocations: int = 0
    number_of_relocations: int = 0
    pointer_to_line_numbers: int = 0
    number_of_line_numbers: int = 0
    characteristics: SectionCharacteristics = SectionCharacteristics(0)

    @classmethod
    def read(cls, fp: DataInput):
        name = fp.read(8)
        i = name.find(b'\x00')
        if i >= 0:
            name = name[:i]

        self = cls()
        self.name = name.decode('UTF-8', 'backslashreplace')
        self.virtual_size = fp.read_int(32)
        self.virtual_address = fp.read_int(32)
        self.size_of_raw_data = fp.read_int(32)
        self.pointer_to_raw_data = fp.read_int(32)
        self.pointer_to_relocations = fp.read_int(32)
        self.pointer_to_line_numbers = fp.read_int(32)
        self.number_of_relocations = fp.read_int(16)
        self.number_of_line_numbers = fp.read_int(16)
        self.characteristics = SectionCharacteristics(fp.read_int(32))
        return self

    def print_info(self, output: Output):
        output.begin(self.name)
        output.write("Virtual address", self.virtual_address, 'address')
        output.write("Virtual size", self.virtual_size, 'size')
        output.write("Data address", self.pointer_to_raw_data, 'address')
        output.write("Data size", self.size_of_raw_data, 'size')
        output.write("Relocations address", self.pointer_to_relocations, 'address')
        output.write("Relocations size", self.number_of_relocations, 'size')
        output.write("Line numbers address", self.pointer_to_line_numbers, 'address')
        output.write("Line numbers size", self.number_of_line_numbers, 'size')
        output.write("Characteristics", self.characteristics, 'flags')
        output.end()


@dataclasses.dataclass
class PEFile:
    dos_header: DOSHeader = DOSHeader()
    dos_code: bytes = b''
    pe_header: PEHeader = PEHeader()
    optional_header: typing.Optional[OptionalHeader] = None
    data_directories: list[tuple[int, int]] = dataclasses.field(default_factory=lambda: [(0, 0) for _ in range(16)])
    sections: dict[str, SectionHeader] = dataclasses.field(default_factory=dict)

    @classmethod
    def read(cls, fp: DataInput):
        dos_header = DOSHeader.read(fp)
        dos_code_size = dos_header.lfanew - fp.pos
        dos_code = fp.read(dos_code_size)

        pe_header = PEHeader.read(fp)
        optional_header = OptionalHeader.read(fp, pe_header.size_of_optional_header)

        data_directories = []
        if optional_header is not None:
            for _ in range(optional_header.number_of_rva_and_sizes):
                base = fp.read_int(32)
                size = fp.read_int(32)
                data_directories.append((base, size))

        sections = {}
        for _ in range(pe_header.number_of_sections):
            s = SectionHeader.read(fp)
            sections[s.name] = s

        return cls(dos_header, dos_code, pe_header, optional_header, data_directories, sections)

    def print_info(self, output: Output):
        self.dos_header.print_info(output)
        output.write('DOS Code', self.dos_code.decode('ascii', 'backslashreplace'), 'raw')
        self.pe_header.print_info(output)

        if self.optional_header is not None:
            self.optional_header.print_info(output)

        output.begin('Data Directories')
        for i, (base, size) in enumerate(self.data_directories):
            output.begin(f'Data Directory {i}')
            output.write('Base', base, 'address')
            output.write('Size', size, 'size')
            output.end()
        output.end()

        output.begin('Sections')
        for i in self.sections.values():
            i.print_info(output)
        output.end()


