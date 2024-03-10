import argparse
import json
import pathlib

from libpe.data_stream import DataInput
from libpe.output import TextOutput, JsonOutput
from libpe.rsrc import ResourceDirectory, ResourceManager
from libpe.structs import PEFile

_FORMAT = "BH I   Q"
_SIZES = ('', 'K', 'M', 'G', 'T')
_DATA_DIRECTORY_NAMES = [
    ".edata",
    ".idata",
    ".rsrc",
    ".pdata",
    "Certificate",
    ".reloc",
    ".debug",
    "Architecture",
    "Global Ptr",
    ".tls",
    "Load Config",
    "Bound Import",
    "IAT",
    "Delay Import Descriptor",
    ".cormeta",
    "Zero",
]


def main():
    parser = argparse.ArgumentParser(description='Windows PE file reader.')
    parser.add_argument('file', metavar='FILE', type=argparse.FileType('rb'),
                        help='Path to .exe, .dll or .efi file')

    parser.add_argument('--dump', '-d', action='store_true',
                        help='Dump file info')

    parser.add_argument('--json', '-J', action='store_true',
                        help='JSON output (with --dump)')

    parser.add_argument('--unpack-dos-code', action='store_true',
                        help='Extract DOS code to file')

    parser.add_argument('--unpack-data-directory', '-F', metavar='NUMBER', type=int,
                        help='Extract data directory contents with given NUMBER to file')

    parser.add_argument('--unpack-section', '-S', metavar='NAME', type=str,
                        help='Extract section contents with given NAME to file')

    parser.add_argument('--unpack-resources', '-R', metavar='NAME', type=str,
                        help='Extract resources from section with given NAME')

    parser.add_argument('--output', '-O', metavar='FILE', type=argparse.FileType('wb'),
                        help='Path to file for -F and -S commands')

    args = parser.parse_args()

    fp = DataInput(args.file)
    pe_file = PEFile.read(fp)

    if args.unpack_dos_code:
        args.output.write(pe_file.dos_code)

    if args.unpack_data_directory is not None:
        base, size = pe_file.data_directories[args.unpack_data_directory]
        args.file.seek(base)
        args.output.write(args.file.read(size))

    if args.unpack_section is not None:
        s = pe_file.sections[args.unpack_section]
        ib = 0 if pe_file.optional_header is None else pe_file.optional_header.image_base
        if ib > s.pointer_to_raw_data:
            args.file.seek(s.pointer_to_raw_data)
        else:
            args.file.seek(s.pointer_to_raw_data - ib)

        args.output.write(args.file.read(s.size_of_raw_data))

    if args.unpack_resources is not None:
        s = pe_file.sections[args.unpack_resources]
        ib = 0 if pe_file.optional_header is None else pe_file.optional_header.image_base
        if ib > s.pointer_to_raw_data:
            args.file.seek(s.pointer_to_raw_data)
        else:
            args.file.seek(s.pointer_to_raw_data - ib)

        out_path = pathlib.Path(args.output.raw.name)
        args.output.close()
        out_path.unlink()

        rm = ResourceManager(fp, s)
        rm.extract(out_path)

    if args.dump:
        if args.json:
            out = JsonOutput()
            pe_file.print_info(out)
            print(json.dumps(out.result))

        else:
            out = TextOutput()
            pe_file.print_info(out)


if __name__ == '__main__':
    main()
