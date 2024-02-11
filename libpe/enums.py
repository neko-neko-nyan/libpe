import enum


class NtMachine(enum.Enum):
    UNKNOWN = 0  # The content of this field is assumed to be applicable to any machine type
    AM33 = 0x1D3  # Matsushita AM33
    AMD64 = 0x8664  # x86-64
    ARM = 0x1c0  # ARM little endian
    ARM64 = 0xaa64  # ARM64 little endian
    ARMNT = 0x1c4  # ARM Thumb-2 little endian
    EBC = 0xebc  # EFI byte code
    I386 = 0x14c  # Intel 386 or later processors and compatible processors
    IA64 = 0x200  # Intel Itanium processor family
    M32R = 0x9041  # Mitsubishi M32R little endian
    MIPS16 = 0x266  # MIPS16
    MIPSFPU = 0x366  # MIPS with FPU
    MIPSFPU16 = 0x466  # MIPS16 with FPU
    POWERPC = 0x1f0  # Power PC little endian
    POWERPCFP = 0x1f1  # Power PC with floating point support
    R4000 = 0x166  # MIPS little endian
    RISCV32 = 0x5032  # RISC-V 32-bit address space
    RISCV64 = 0x5064  # RISC-V 64-bit address space
    RISCV128 = 0x5128  # RISC-V 128-bit address space
    SH3 = 0x1a2  # Hitachi SH3
    SH3DSP = 0x1a3  # Hitachi SH3 DSP
    SH4 = 0x1a6  # Hitachi SH4
    SH5 = 0x1a8  # Hitachi SH5
    THUMB = 0x1c2  # Thumb
    WCEMIPSV2 = 0x169  # MIPS little-endian WCE v2


class NtCharacteristics(enum.IntFlag):
    RELOCS_STRIPPED = 0x0001  # This indicates that the file does not contain base relocations and must therefore be
    # loaded at its preferred base address. If the base address is not available, the loader reports an error.
    # The default behavior of the linker is to strip base relocations from executable (EXE) files.
    EXECUTABLE_IMAGE = 0x0002  # This indicates that the image file is valid and can be run.
    LINE_NUMS_STRIPPED = 0x0004  # COFF line numbers have been removed. This flag is deprecated and should be zero.
    LOCAL_SYMS_STRIPPED = 0x0008  # This flag is deprecated and should be zero.
    AGGRESSIVE_WS_TRIM = 0x0010  # This flag is deprecated for Windows 2000 and later and must be zero.
    LARGE_ADDRESS_AWARE = 0x0020  # Application can handle > 2-GB addresses.
    RESERVED = 0x0040  # This flag is reserved for future use.
    BYTES_REVERSED_LO = 0x0080  # This flag is deprecated and should be zero.
    MACHINE_32BIT = 0x0100  # Machine is based on a 32-bit-word architecture.
    DEBUG_STRIPPED = 0x0200  # Debugging information is removed from the image file.
    REMOVABLE_RUN_FROM_SWAP = 0x0400  # If the image is on removable media, fully load it and copy it to the swap file.
    NET_RUN_FROM_SWAP = 0x0800  # If the image is on network media, fully load it and copy it to the swap file.
    SYSTEM = 0x1000  # The image file is a system file, not a user program.
    DLL = 0x2000  # The image file is a dynamic-link library (DLL).
    UP_SYSTEM_ONLY = 0x4000  # The file should be run only on a uniprocessor machine.
    BYTES_REVERSED_HI = 0x8000  # This flag is deprecated and should be zero.


class NtSubsystem(enum.Enum):
    UNKNOWN = 0  # An unknown subsystem
    NATIVE = 1  # Device drivers and native Windows processes
    WINDOWS_GUI = 2  # The Windows graphical user interface (GUI) subsystem
    WINDOWS_CUI = 3  # The Windows character subsystem
    OS2_CUI = 5  # The OS/2 character subsystem
    POSIX_CUI = 7  # The Posix character subsystem
    NATIVE_WINDOWS = 8  # Native Win9x driver
    WINDOWS_CE_GUI = 9  # Windows CE
    EFI_APPLICATION = 10  # An Extensible Firmware Interface (EFI) application
    EFI_BOOT_SERVICE_DRIVER = 11  # An EFI driver with boot services
    EFI_RUNTIME_DRIVER = 12  # An EFI driver with run-time services
    EFI_ROM = 13  # An EFI ROM image
    XBOX = 14  # XBOX
    WINDOWS_BOOT_APPLICATION = 16  # Windows boot application.


class DllCharacteristics(enum.IntFlag):
    HIGH_ENTROPY_VA = 0x0020  # Image can handle a high entropy 64-bit virtual address space.
    DYNAMIC_BASE = 0x0040  # DLL can be relocated at load time.
    FORCE_INTEGRITY = 0x0080  # Code Integrity checks are enforced.
    NX_COMPAT = 0x0100  # Image is NX compatible.
    NO_ISOLATION = 0x0200  # Isolation aware, but do not isolate the image.
    NO_SEH = 0x0400  # Does not use structured exception (SE) handling. No SE handler may be called in this image.
    NO_BIND = 0x0800  # Do not bind the image.
    APPCONTAINER = 0x1000  # Image must execute in an AppContainer.
    WDM_DRIVER = 0x2000  # A WDM driver.
    GUARD_CF = 0x4000  # Image supports Control Flow Guard.
    TERMINAL_SERVER_AWARE = 0x8000  # Terminal Server aware.


class SectionCharacteristics(enum.IntFlag):
    TYPE_NO_PAD = 0x00000008  # The section should not be padded to the next boundary. This flag is obsolete.
    CNT_CODE = 0x00000020  # The section contains executable code.
    CNT_INITIALIZED_DATA = 0x00000040  # The section contains initialized data.
    CNT_UNINITIALIZED_DATA = 0x00000080  # The section contains uninitialized data.
    LNK_OTHER = 0x00000100  # Reserved for future use.
    LNK_INFO = 0x00000200  # The section contains comments or other information. The .drectve section has this type.
    LNK_REMOVE = 0x00000800  # The section will not become part of the image. This is valid only for object files.
    LNK_COMDAT = 0x00001000  # The section contains COMDAT data. For more information, see COMDAT Sections.
    GPREL = 0x00008000  # The section contains data referenced through the global pointer (GP).
    MEM_PURGEABLE = 0x00020000  # Reserved for future use.
    MEM_16BIT = 0x00020000  # Reserved for future use.
    MEM_LOCKED = 0x00040000  # Reserved for future use.
    MEM_PRELOAD = 0x00080000  # Reserved for future use.
    ALIGN_1BYTES = 0x00100000  # Align data on a 1-byte boundary. Valid only for object files.
    ALIGN_2BYTES = 0x00200000  # Align data on a 2-byte boundary. Valid only for object files.
    ALIGN_4BYTES = 0x00300000  # Align data on a 4-byte boundary. Valid only for object files.
    ALIGN_8BYTES = 0x00400000  # Align data on an 8-byte boundary. Valid only for object files.
    ALIGN_16BYTES = 0x00500000  # Align data on a 16-byte boundary. Valid only for object files.
    ALIGN_32BYTES = 0x00600000  # Align data on a 32-byte boundary. Valid only for object files.
    ALIGN_64BYTES = 0x00700000  # Align data on a 64-byte boundary. Valid only for object files.
    ALIGN_128BYTES = 0x00800000  # Align data on a 128-byte boundary. Valid only for object files.
    ALIGN_256BYTES = 0x00900000  # Align data on a 256-byte boundary. Valid only for object files.
    ALIGN_512BYTES = 0x00A00000  # Align data on a 512-byte boundary. Valid only for object files.
    ALIGN_1024BYTES = 0x00B00000  # Align data on a 1024-byte boundary. Valid only for object files.
    ALIGN_2048BYTES = 0x00C00000  # Align data on a 2048-byte boundary. Valid only for object files.
    ALIGN_4096BYTES = 0x00D00000  # Align data on a 4096-byte boundary. Valid only for object files.
    ALIGN_8192BYTES = 0x00E00000  # Align data on an 8192-byte boundary. Valid only for object files.
    LNK_NRELOC_OVFL = 0x01000000  # The section contains extended relocations.
    MEM_DISCARDABLE = 0x02000000  # The section can be discarded as needed.
    MEM_NOT_CACHED = 0x04000000  # The section cannot be cached.
    MEM_NOT_PAGED = 0x08000000  # The section is not pageable.
    MEM_SHARED = 0x10000000  # The section can be shared in memory.
    MEM_EXECUTE = 0x20000000  # The section can be executed as code.
    MEM_READ = 0x40000000  # The section can be read.
    MEM_WRITE = 0x80000000  # The section can be written to.


class ResourceType(enum.Enum):
    UNKNOWN = 0
    CURSOR = 1
    BITMAP = 2
    ICON = 3
    MENU = 4
    DIALOG = 5
    STRING = 6
    FONTDIR = 7
    FONT = 8
    ACCELERATOR = 9
    RCDATA = 10
    MESSAGETABLE = 11
    GROUP_CURSOR = 12

    GROUP_ICON = 14

    VERSION = 16
    DLGINCLUDE = 17

    PLUGPLAY = 19
    VXD = 20
    ANICURSOR = 21
    ANIICON = 22
    HTML = 23
    MANIFEST = 24
