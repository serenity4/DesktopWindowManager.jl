using CEnum

const ULONG = Culong

const USHORT = Cushort

const UCHAR = Cuchar

const BYTE = Cuchar

const WORD = Cushort

const DWORD = Culong

const PBYTE = Ptr{BYTE}

const LPBYTE = Ptr{BYTE}

const LPINT = Ptr{Cint}

const LPWORD = Ptr{WORD}

const PDWORD = Ptr{DWORD}

const LPDWORD = Ptr{DWORD}

const LPVOID = Ptr{Cvoid}

const UINT = Cuint

const PUINT = Ptr{Cuint}

const INT8 = Int8

const INT16 = Cshort

const INT32 = Cint

const INT64 = Clonglong

const UINT8 = Cuchar

const UINT16 = Cushort

const UINT32 = Cuint

const UINT64 = Culonglong

const INT_PTR = Clonglong

const UINT_PTR = Culonglong

const LONG_PTR = Clonglong

const ULONG_PTR = Culonglong

const SIZE_T = ULONG_PTR

const PDWORD_PTR = Ptr{ULONG_PTR}

const LONG64 = Clonglong

const PLONG64 = Ptr{Clonglong}

const DWORD64 = Culonglong

const PDWORD64 = Ptr{Culonglong}

const KAFFINITY = ULONG_PTR

struct _GUID
    Data1::Culong
    Data2::Cushort
    Data3::Cushort
    Data4::NTuple{8, Cuchar}
end

const GUID = _GUID

const LPCGUID = Ptr{GUID}

const CLSID = GUID

const WPARAM = UINT_PTR

const LPARAM = LONG_PTR

const LRESULT = LONG_PTR

const HANDLE = Ptr{Cvoid}

const HGLOBAL = HANDLE

# typedef INT_PTR ( WINAPI * FARPROC ) ( )
const FARPROC = Ptr{Cvoid}

const ATOM = WORD

struct HINSTANCE__
    unused::Cint
end

const HINSTANCE = Ptr{HINSTANCE__}

struct HKL__
    unused::Cint
end

const HKL = Ptr{HKL__}

const HMODULE = HINSTANCE

struct HRGN__
    unused::Cint
end

const HRGN = Ptr{HRGN__}

struct HRSRC__
    unused::Cint
end

const HRSRC = Ptr{HRSRC__}

struct HWINSTA__
    unused::Cint
end

const HWINSTA = Ptr{HWINSTA__}

struct _FILETIME
    dwLowDateTime::DWORD
    dwHighDateTime::DWORD
end

const FILETIME = _FILETIME

const ULONGLONG = Culonglong

const LONG = Clong

const __C_ASSERT__ = NTuple{1, Cchar}

const HRESULT = Clong

function _rotl8(Value, Shift)
    @ccall user32._rotl8(Value::Cuchar, Shift::Cuchar)::Cuchar
end

function _rotl16(Value, Shift)
    @ccall user32._rotl16(Value::Cushort, Shift::Cuchar)::Cushort
end

function _rotr8(Value, Shift)
    @ccall user32._rotr8(Value::Cuchar, Shift::Cuchar)::Cuchar
end

function _rotr16(Value, Shift)
    @ccall user32._rotr16(Value::Cushort, Shift::Cuchar)::Cushort
end

const CHAR = Cchar

const WCHAR = Cwchar_t

const PCHAR = Ptr{CHAR}

function ReadULong64Acquire(DWORD64_)
    @ccall user32.ReadULong64Acquire(DWORD64_::Cint)::DWORD64
end

function ReadULong64NoFence(DWORD64_)
    @ccall user32.ReadULong64NoFence(DWORD64_::Cint)::DWORD64
end

function ReadULong64Raw(DWORD64_)
    @ccall user32.ReadULong64Raw(DWORD64_::Cint)::DWORD64
end

function WriteULong64Release(DWORD64_)
    @ccall user32.WriteULong64Release(DWORD64_::Cint)::Cvoid
end

function WriteULong64NoFence(DWORD64_)
    @ccall user32.WriteULong64NoFence(DWORD64_::Cint)::Cvoid
end

function WriteULong64Raw(DWORD64_)
    @ccall user32.WriteULong64Raw(DWORD64_::Cint)::Cvoid
end

function ReadAcquire64(LONG64_)
    @ccall user32.ReadAcquire64(LONG64_::Cint)::LONG64
end

function ReadNoFence64(LONG64_)
    @ccall user32.ReadNoFence64(LONG64_::Cint)::LONG64
end

function ReadRaw64(LONG64_)
    @ccall user32.ReadRaw64(LONG64_::Cint)::LONG64
end

function WriteRelease64(LONG64_)
    @ccall user32.WriteRelease64(LONG64_::Cint)::Cvoid
end

function WriteNoFence64(LONG64_)
    @ccall user32.WriteNoFence64(LONG64_::Cint)::Cvoid
end

function WriteRaw64(LONG64_)
    @ccall user32.WriteRaw64(LONG64_::Cint)::Cvoid
end

struct _SID_IDENTIFIER_AUTHORITY
    Value::NTuple{6, BYTE}
end

const SID_IDENTIFIER_AUTHORITY = _SID_IDENTIFIER_AUTHORITY

struct _SID
    Revision::BYTE
    SubAuthorityCount::BYTE
    IdentifierAuthority::SID_IDENTIFIER_AUTHORITY
    SubAuthority::NTuple{1, DWORD}
end

const SID = _SID

const SECURITY_DESCRIPTOR_CONTROL = WORD

const PVOID = Ptr{Cvoid}

const PSID = PVOID

struct _ACL
    AclRevision::BYTE
    Sbz1::BYTE
    AclSize::WORD
    AceCount::WORD
    Sbz2::WORD
end

const ACL = _ACL

const PACL = Ptr{ACL}

struct _SECURITY_DESCRIPTOR
    Revision::BYTE
    Sbz1::BYTE
    Control::SECURITY_DESCRIPTOR_CONTROL
    Owner::PSID
    Group::PSID
    Sacl::PACL
    Dacl::PACL
end

const SECURITY_DESCRIPTOR = _SECURITY_DESCRIPTOR

struct _SID_AND_ATTRIBUTES
    Sid::PSID
    Attributes::DWORD
end

const SID_AND_ATTRIBUTES = _SID_AND_ATTRIBUTES

struct _TOKEN_USER
    User::SID_AND_ATTRIBUTES
end

const TOKEN_USER = _TOKEN_USER

struct _TOKEN_OWNER
    Owner::PSID
end

const TOKEN_OWNER = _TOKEN_OWNER

struct _TOKEN_MANDATORY_LABEL
    Label::SID_AND_ATTRIBUTES
end

const TOKEN_MANDATORY_LABEL = _TOKEN_MANDATORY_LABEL

struct _TOKEN_APPCONTAINER_INFORMATION
    TokenAppContainer::PSID
end

const TOKEN_APPCONTAINER_INFORMATION = _TOKEN_APPCONTAINER_INFORMATION

const LONGLONG = Clonglong

struct __JL_Ctag_88
    DataBuffer::NTuple{1, BYTE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_88}, f::Symbol)
    f === :DataBuffer && return Ptr{NTuple{1, BYTE}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_88, f::Symbol)
    r = Ref{__JL_Ctag_88}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_88}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_88}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct _REPARSE_GUID_DATA_BUFFER
    data::NTuple{28, UInt8}
end

function Base.getproperty(x::Ptr{_REPARSE_GUID_DATA_BUFFER}, f::Symbol)
    f === :ReparseTag && return Ptr{DWORD}(x + 0)
    f === :ReparseDataLength && return Ptr{WORD}(x + 4)
    f === :Reserved && return Ptr{WORD}(x + 6)
    f === :ReparseGuid && return Ptr{GUID}(x + 8)
    f === :GenericReparseBuffer && return Ptr{__JL_Ctag_88}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_REPARSE_GUID_DATA_BUFFER, f::Symbol)
    r = Ref{_REPARSE_GUID_DATA_BUFFER}(x)
    ptr = Base.unsafe_convert(Ptr{_REPARSE_GUID_DATA_BUFFER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_REPARSE_GUID_DATA_BUFFER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _REPARSE_GUID_DATA_BUFFER(ReparseTag::DWORD, ReparseDataLength::WORD, Reserved::WORD, ReparseGuid::GUID, GenericReparseBuffer::__JL_Ctag_88)
    ref = Ref{_REPARSE_GUID_DATA_BUFFER}()
    ptr = Base.unsafe_convert(Ptr{_REPARSE_GUID_DATA_BUFFER}, ref)
    ptr.ReparseTag = ReparseTag
    ptr.ReparseDataLength = ReparseDataLength
    ptr.Reserved = Reserved
    ptr.ReparseGuid = ReparseGuid
    ptr.GenericReparseBuffer = GenericReparseBuffer
    ref[]
end

const REPARSE_GUID_DATA_BUFFER = _REPARSE_GUID_DATA_BUFFER

struct __JL_Ctag_79
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_79}, f::Symbol)
    f === :PhysicalAddress && return Ptr{DWORD}(x + 0)
    f === :VirtualSize && return Ptr{DWORD}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_79, f::Symbol)
    r = Ref{__JL_Ctag_79}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_79}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_79}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_79 = Union{DWORD, DWORD}

function __JL_Ctag_79(val::__U___JL_Ctag_79)
    ref = Ref{__JL_Ctag_79}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_79}, ref)
    if val isa DWORD
        ptr.PhysicalAddress = val
    elseif val isa DWORD
        ptr.VirtualSize = val
    end
    ref[]
end

struct _IMAGE_SECTION_HEADER
    data::NTuple{40, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_SECTION_HEADER}, f::Symbol)
    f === :Name && return Ptr{NTuple{8, BYTE}}(x + 0)
    f === :Misc && return Ptr{__JL_Ctag_79}(x + 8)
    f === :VirtualAddress && return Ptr{DWORD}(x + 12)
    f === :SizeOfRawData && return Ptr{DWORD}(x + 16)
    f === :PointerToRawData && return Ptr{DWORD}(x + 20)
    f === :PointerToRelocations && return Ptr{DWORD}(x + 24)
    f === :PointerToLinenumbers && return Ptr{DWORD}(x + 28)
    f === :NumberOfRelocations && return Ptr{WORD}(x + 32)
    f === :NumberOfLinenumbers && return Ptr{WORD}(x + 34)
    f === :Characteristics && return Ptr{DWORD}(x + 36)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_SECTION_HEADER, f::Symbol)
    r = Ref{_IMAGE_SECTION_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SECTION_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_SECTION_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_SECTION_HEADER(Name::NTuple{8, BYTE}, Misc::__JL_Ctag_79, VirtualAddress::DWORD, SizeOfRawData::DWORD, PointerToRawData::DWORD, PointerToRelocations::DWORD, PointerToLinenumbers::DWORD, NumberOfRelocations::WORD, NumberOfLinenumbers::WORD, Characteristics::DWORD)
    ref = Ref{_IMAGE_SECTION_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SECTION_HEADER}, ref)
    ptr.Name = Name
    ptr.Misc = Misc
    ptr.VirtualAddress = VirtualAddress
    ptr.SizeOfRawData = SizeOfRawData
    ptr.PointerToRawData = PointerToRawData
    ptr.PointerToRelocations = PointerToRelocations
    ptr.PointerToLinenumbers = PointerToLinenumbers
    ptr.NumberOfRelocations = NumberOfRelocations
    ptr.NumberOfLinenumbers = NumberOfLinenumbers
    ptr.Characteristics = Characteristics
    ref[]
end

const PIMAGE_SECTION_HEADER = Ptr{_IMAGE_SECTION_HEADER}

struct _IMAGE_FILE_HEADER
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_FILE_HEADER}, f::Symbol)
    f === :Machine && return Ptr{WORD}(x + 0)
    f === :NumberOfSections && return Ptr{WORD}(x + 2)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 4)
    f === :PointerToSymbolTable && return Ptr{DWORD}(x + 8)
    f === :NumberOfSymbols && return Ptr{DWORD}(x + 12)
    f === :SizeOfOptionalHeader && return Ptr{WORD}(x + 16)
    f === :Characteristics && return Ptr{WORD}(x + 18)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_FILE_HEADER, f::Symbol)
    r = Ref{_IMAGE_FILE_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FILE_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_FILE_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_FILE_HEADER(Machine::WORD, NumberOfSections::WORD, TimeDateStamp::DWORD, PointerToSymbolTable::DWORD, NumberOfSymbols::DWORD, SizeOfOptionalHeader::WORD, Characteristics::WORD)
    ref = Ref{_IMAGE_FILE_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FILE_HEADER}, ref)
    ptr.Machine = Machine
    ptr.NumberOfSections = NumberOfSections
    ptr.TimeDateStamp = TimeDateStamp
    ptr.PointerToSymbolTable = PointerToSymbolTable
    ptr.NumberOfSymbols = NumberOfSymbols
    ptr.SizeOfOptionalHeader = SizeOfOptionalHeader
    ptr.Characteristics = Characteristics
    ref[]
end

const IMAGE_FILE_HEADER = _IMAGE_FILE_HEADER

struct _IMAGE_DATA_DIRECTORY
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DATA_DIRECTORY}, f::Symbol)
    f === :VirtualAddress && return Ptr{DWORD}(x + 0)
    f === :Size && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DATA_DIRECTORY, f::Symbol)
    r = Ref{_IMAGE_DATA_DIRECTORY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DATA_DIRECTORY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DATA_DIRECTORY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DATA_DIRECTORY(VirtualAddress::DWORD, Size::DWORD)
    ref = Ref{_IMAGE_DATA_DIRECTORY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DATA_DIRECTORY}, ref)
    ptr.VirtualAddress = VirtualAddress
    ptr.Size = Size
    ref[]
end

const IMAGE_DATA_DIRECTORY = _IMAGE_DATA_DIRECTORY

struct _IMAGE_OPTIONAL_HEADER64
    data::NTuple{240, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_OPTIONAL_HEADER64}, f::Symbol)
    f === :Magic && return Ptr{WORD}(x + 0)
    f === :MajorLinkerVersion && return Ptr{BYTE}(x + 2)
    f === :MinorLinkerVersion && return Ptr{BYTE}(x + 3)
    f === :SizeOfCode && return Ptr{DWORD}(x + 4)
    f === :SizeOfInitializedData && return Ptr{DWORD}(x + 8)
    f === :SizeOfUninitializedData && return Ptr{DWORD}(x + 12)
    f === :AddressOfEntryPoint && return Ptr{DWORD}(x + 16)
    f === :BaseOfCode && return Ptr{DWORD}(x + 20)
    f === :ImageBase && return Ptr{ULONGLONG}(x + 24)
    f === :SectionAlignment && return Ptr{DWORD}(x + 32)
    f === :FileAlignment && return Ptr{DWORD}(x + 36)
    f === :MajorOperatingSystemVersion && return Ptr{WORD}(x + 40)
    f === :MinorOperatingSystemVersion && return Ptr{WORD}(x + 42)
    f === :MajorImageVersion && return Ptr{WORD}(x + 44)
    f === :MinorImageVersion && return Ptr{WORD}(x + 46)
    f === :MajorSubsystemVersion && return Ptr{WORD}(x + 48)
    f === :MinorSubsystemVersion && return Ptr{WORD}(x + 50)
    f === :Win32VersionValue && return Ptr{DWORD}(x + 52)
    f === :SizeOfImage && return Ptr{DWORD}(x + 56)
    f === :SizeOfHeaders && return Ptr{DWORD}(x + 60)
    f === :CheckSum && return Ptr{DWORD}(x + 64)
    f === :Subsystem && return Ptr{WORD}(x + 68)
    f === :DllCharacteristics && return Ptr{WORD}(x + 70)
    f === :SizeOfStackReserve && return Ptr{ULONGLONG}(x + 72)
    f === :SizeOfStackCommit && return Ptr{ULONGLONG}(x + 80)
    f === :SizeOfHeapReserve && return Ptr{ULONGLONG}(x + 88)
    f === :SizeOfHeapCommit && return Ptr{ULONGLONG}(x + 96)
    f === :LoaderFlags && return Ptr{DWORD}(x + 104)
    f === :NumberOfRvaAndSizes && return Ptr{DWORD}(x + 108)
    f === :DataDirectory && return Ptr{NTuple{16, IMAGE_DATA_DIRECTORY}}(x + 112)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_OPTIONAL_HEADER64, f::Symbol)
    r = Ref{_IMAGE_OPTIONAL_HEADER64}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_OPTIONAL_HEADER64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_OPTIONAL_HEADER64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_OPTIONAL_HEADER64(Magic::WORD, MajorLinkerVersion::BYTE, MinorLinkerVersion::BYTE, SizeOfCode::DWORD, SizeOfInitializedData::DWORD, SizeOfUninitializedData::DWORD, AddressOfEntryPoint::DWORD, BaseOfCode::DWORD, ImageBase::ULONGLONG, SectionAlignment::DWORD, FileAlignment::DWORD, MajorOperatingSystemVersion::WORD, MinorOperatingSystemVersion::WORD, MajorImageVersion::WORD, MinorImageVersion::WORD, MajorSubsystemVersion::WORD, MinorSubsystemVersion::WORD, Win32VersionValue::DWORD, SizeOfImage::DWORD, SizeOfHeaders::DWORD, CheckSum::DWORD, Subsystem::WORD, DllCharacteristics::WORD, SizeOfStackReserve::ULONGLONG, SizeOfStackCommit::ULONGLONG, SizeOfHeapReserve::ULONGLONG, SizeOfHeapCommit::ULONGLONG, LoaderFlags::DWORD, NumberOfRvaAndSizes::DWORD, DataDirectory::NTuple{16, IMAGE_DATA_DIRECTORY})
    ref = Ref{_IMAGE_OPTIONAL_HEADER64}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_OPTIONAL_HEADER64}, ref)
    ptr.Magic = Magic
    ptr.MajorLinkerVersion = MajorLinkerVersion
    ptr.MinorLinkerVersion = MinorLinkerVersion
    ptr.SizeOfCode = SizeOfCode
    ptr.SizeOfInitializedData = SizeOfInitializedData
    ptr.SizeOfUninitializedData = SizeOfUninitializedData
    ptr.AddressOfEntryPoint = AddressOfEntryPoint
    ptr.BaseOfCode = BaseOfCode
    ptr.ImageBase = ImageBase
    ptr.SectionAlignment = SectionAlignment
    ptr.FileAlignment = FileAlignment
    ptr.MajorOperatingSystemVersion = MajorOperatingSystemVersion
    ptr.MinorOperatingSystemVersion = MinorOperatingSystemVersion
    ptr.MajorImageVersion = MajorImageVersion
    ptr.MinorImageVersion = MinorImageVersion
    ptr.MajorSubsystemVersion = MajorSubsystemVersion
    ptr.MinorSubsystemVersion = MinorSubsystemVersion
    ptr.Win32VersionValue = Win32VersionValue
    ptr.SizeOfImage = SizeOfImage
    ptr.SizeOfHeaders = SizeOfHeaders
    ptr.CheckSum = CheckSum
    ptr.Subsystem = Subsystem
    ptr.DllCharacteristics = DllCharacteristics
    ptr.SizeOfStackReserve = SizeOfStackReserve
    ptr.SizeOfStackCommit = SizeOfStackCommit
    ptr.SizeOfHeapReserve = SizeOfHeapReserve
    ptr.SizeOfHeapCommit = SizeOfHeapCommit
    ptr.LoaderFlags = LoaderFlags
    ptr.NumberOfRvaAndSizes = NumberOfRvaAndSizes
    ptr.DataDirectory = DataDirectory
    ref[]
end

const IMAGE_OPTIONAL_HEADER64 = _IMAGE_OPTIONAL_HEADER64

struct _IMAGE_NT_HEADERS64
    data::NTuple{264, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_NT_HEADERS64}, f::Symbol)
    f === :Signature && return Ptr{DWORD}(x + 0)
    f === :FileHeader && return Ptr{IMAGE_FILE_HEADER}(x + 4)
    f === :OptionalHeader && return Ptr{IMAGE_OPTIONAL_HEADER64}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_NT_HEADERS64, f::Symbol)
    r = Ref{_IMAGE_NT_HEADERS64}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_NT_HEADERS64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_NT_HEADERS64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_NT_HEADERS64(Signature::DWORD, FileHeader::IMAGE_FILE_HEADER, OptionalHeader::IMAGE_OPTIONAL_HEADER64)
    ref = Ref{_IMAGE_NT_HEADERS64}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_NT_HEADERS64}, ref)
    ptr.Signature = Signature
    ptr.FileHeader = FileHeader
    ptr.OptionalHeader = OptionalHeader
    ref[]
end

const IMAGE_NT_HEADERS64 = _IMAGE_NT_HEADERS64

const IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64

const SHORT = Cshort

struct _IMAGE_ENCLAVE_CONFIG64
    data::NTuple{80, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ENCLAVE_CONFIG64}, f::Symbol)
    f === :Size && return Ptr{DWORD}(x + 0)
    f === :MinimumRequiredConfigSize && return Ptr{DWORD}(x + 4)
    f === :PolicyFlags && return Ptr{DWORD}(x + 8)
    f === :NumberOfImports && return Ptr{DWORD}(x + 12)
    f === :ImportList && return Ptr{DWORD}(x + 16)
    f === :ImportEntrySize && return Ptr{DWORD}(x + 20)
    f === :FamilyID && return Ptr{NTuple{16, BYTE}}(x + 24)
    f === :ImageID && return Ptr{NTuple{16, BYTE}}(x + 40)
    f === :ImageVersion && return Ptr{DWORD}(x + 56)
    f === :SecurityVersion && return Ptr{DWORD}(x + 60)
    f === :EnclaveSize && return Ptr{ULONGLONG}(x + 64)
    f === :NumberOfThreads && return Ptr{DWORD}(x + 72)
    f === :EnclaveFlags && return Ptr{DWORD}(x + 76)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ENCLAVE_CONFIG64, f::Symbol)
    r = Ref{_IMAGE_ENCLAVE_CONFIG64}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ENCLAVE_CONFIG64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ENCLAVE_CONFIG64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ENCLAVE_CONFIG64(Size::DWORD, MinimumRequiredConfigSize::DWORD, PolicyFlags::DWORD, NumberOfImports::DWORD, ImportList::DWORD, ImportEntrySize::DWORD, FamilyID::NTuple{16, BYTE}, ImageID::NTuple{16, BYTE}, ImageVersion::DWORD, SecurityVersion::DWORD, EnclaveSize::ULONGLONG, NumberOfThreads::DWORD, EnclaveFlags::DWORD)
    ref = Ref{_IMAGE_ENCLAVE_CONFIG64}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ENCLAVE_CONFIG64}, ref)
    ptr.Size = Size
    ptr.MinimumRequiredConfigSize = MinimumRequiredConfigSize
    ptr.PolicyFlags = PolicyFlags
    ptr.NumberOfImports = NumberOfImports
    ptr.ImportList = ImportList
    ptr.ImportEntrySize = ImportEntrySize
    ptr.FamilyID = FamilyID
    ptr.ImageID = ImageID
    ptr.ImageVersion = ImageVersion
    ptr.SecurityVersion = SecurityVersion
    ptr.EnclaveSize = EnclaveSize
    ptr.NumberOfThreads = NumberOfThreads
    ptr.EnclaveFlags = EnclaveFlags
    ref[]
end

const IMAGE_ENCLAVE_CONFIG64 = _IMAGE_ENCLAVE_CONFIG64

const IMAGE_ENCLAVE_CONFIG = IMAGE_ENCLAVE_CONFIG64

function VerSetConditionMask(ConditionMask, TypeMask, Condition)
    @ccall user32.VerSetConditionMask(ConditionMask::ULONGLONG, TypeMask::DWORD, Condition::BYTE)::ULONGLONG
end

@cenum _ACTIVATION_CONTEXT_INFO_CLASS::UInt32 begin
    ActivationContextBasicInformation = 1
    ActivationContextDetailedInformation = 2
    AssemblyDetailedInformationInActivationContext = 3
    FileInformationInAssemblyOfAssemblyInActivationContext = 4
    RunlevelInformationInActivationContext = 5
    CompatibilityInformationInActivationContext = 6
    ActivationContextManifestResourceName = 7
    MaxActivationContextInfoClass = 8
    AssemblyDetailedInformationInActivationContxt = 3
    FileInformationInAssemblyOfAssemblyInActivationContxt = 4
end

const ACTIVATION_CONTEXT_INFO_CLASS = _ACTIVATION_CONTEXT_INFO_CLASS

const PCWSTR = Ptr{WCHAR}

struct _ASSEMBLY_FILE_DETAILED_INFORMATION
    ulFlags::DWORD
    ulFilenameLength::DWORD
    ulPathLength::DWORD
    lpFileName::PCWSTR
    lpFilePath::PCWSTR
end

const ASSEMBLY_FILE_DETAILED_INFORMATION = _ASSEMBLY_FILE_DETAILED_INFORMATION

const PASSEMBLY_FILE_DETAILED_INFORMATION = Ptr{_ASSEMBLY_FILE_DETAILED_INFORMATION}

const PCASSEMBLY_FILE_DETAILED_INFORMATION = Ptr{ASSEMBLY_FILE_DETAILED_INFORMATION}

# typedef BOOL ( CALLBACK * ENUMRESLANGPROCA ) ( _In_opt_ HMODULE hModule , _In_ LPCSTR lpType , _In_ LPCSTR lpName , _In_ WORD wLanguage , _In_ LONG_PTR lParam )
const ENUMRESLANGPROCA = Ptr{Cvoid}

# typedef BOOL ( CALLBACK * ENUMRESNAMEPROCA ) ( _In_opt_ HMODULE hModule , _In_ LPCSTR lpType , _In_ LPSTR lpName , _In_ LONG_PTR lParam )
const ENUMRESNAMEPROCA = Ptr{Cvoid}

# typedef BOOL ( CALLBACK * ENUMRESTYPEPROCA ) ( _In_opt_ HMODULE hModule , _In_ LPSTR lpType , _In_ LONG_PTR lParam )
const ENUMRESTYPEPROCA = Ptr{Cvoid}

const LPSTR = Ptr{CHAR}

function GetModuleFileNameA(hModule, lpFilename, nSize)
    @ccall user32.GetModuleFileNameA(hModule::HMODULE, lpFilename::LPSTR, nSize::DWORD)::DWORD
end

const LPCSTR = Ptr{CHAR}

function GetModuleHandleA(lpModuleName)
    @ccall user32.GetModuleHandleA(lpModuleName::LPCSTR)::HMODULE
end

# typedef BOOL ( WINAPI * PGET_MODULE_HANDLE_EXA ) ( _In_ DWORD dwFlags , _In_opt_ LPCSTR lpModuleName , _Outptr_ HMODULE * phModule )
const PGET_MODULE_HANDLE_EXA = Ptr{Cvoid}

function GetModuleHandleExA(dwFlags, lpModuleName, phModule)
    @ccall user32.GetModuleHandleExA(dwFlags::DWORD, lpModuleName::LPCSTR, phModule::Ptr{HMODULE})::BOOL
end

function LoadLibraryExA(lpLibFileName, hFile, dwFlags)
    @ccall user32.LoadLibraryExA(lpLibFileName::LPCSTR, hFile::HANDLE, dwFlags::DWORD)::HMODULE
end

function LoadStringA(hInstance, uID, lpBuffer, cchBufferMax)
    @ccall user32.LoadStringA(hInstance::HINSTANCE, uID::UINT, lpBuffer::LPSTR, cchBufferMax::Cint)::Cint
end

function LoadLibraryA(lpLibFileName)
    @ccall user32.LoadLibraryA(lpLibFileName::LPCSTR)::HMODULE
end

function EnumResourceNamesA(hModule, lpType, lpEnumFunc, lParam)
    @ccall user32.EnumResourceNamesA(hModule::HMODULE, lpType::LPCSTR, lpEnumFunc::ENUMRESNAMEPROCA, lParam::LONG_PTR)::BOOL
end

const LPWSTR = Ptr{WCHAR}

function LoadKeyboardLayoutA(pwszKLID, Flags)
    @ccall user32.LoadKeyboardLayoutA(pwszKLID::LPCSTR, Flags::UINT)::HKL
end

function GetKeyboardLayoutNameA(pwszKLID)
    @ccall user32.GetKeyboardLayoutNameA(pwszKLID::LPSTR)::BOOL
end

const ACCESS_MASK = DWORD

function OpenDesktopA(lpszDesktop, dwFlags, fInherit, dwDesiredAccess)
    @ccall user32.OpenDesktopA(lpszDesktop::LPCSTR, dwFlags::DWORD, fInherit::BOOL, dwDesiredAccess::ACCESS_MASK)::Cint
end

# typedef BOOL ( CALLBACK * NAMEENUMPROCA ) ( LPSTR , LPARAM )
const NAMEENUMPROCA = Ptr{Cvoid}

const DESKTOPENUMPROCA = NAMEENUMPROCA

function EnumDesktopsA(hwinsta, lpEnumFunc, lParam)
    @ccall user32.EnumDesktopsA(hwinsta::HWINSTA, lpEnumFunc::DESKTOPENUMPROCA, lParam::LPARAM)::BOOL
end

struct _SECURITY_ATTRIBUTES
    nLength::DWORD
    lpSecurityDescriptor::LPVOID
    bInheritHandle::BOOL
end

const LPSECURITY_ATTRIBUTES = Ptr{_SECURITY_ATTRIBUTES}

function CreateWindowStationA(lpwinsta, dwFlags, dwDesiredAccess, lpsa)
    @ccall user32.CreateWindowStationA(lpwinsta::LPCSTR, dwFlags::DWORD, dwDesiredAccess::ACCESS_MASK, lpsa::LPSECURITY_ATTRIBUTES)::HWINSTA
end

function OpenWindowStationA(lpszWinSta, fInherit, dwDesiredAccess)
    @ccall user32.OpenWindowStationA(lpszWinSta::LPCSTR, fInherit::BOOL, dwDesiredAccess::ACCESS_MASK)::HWINSTA
end

const WINSTAENUMPROCA = NAMEENUMPROCA

function EnumWindowStationsA(lpEnumFunc, lParam)
    @ccall user32.EnumWindowStationsA(lpEnumFunc::WINSTAENUMPROCA, lParam::LPARAM)::BOOL
end

function GetUserObjectInformationA(hObj, nIndex, pvInfo, nLength, lpnLengthNeeded)
    @ccall user32.GetUserObjectInformationA(hObj::HANDLE, nIndex::Cint, pvInfo::PVOID, nLength::DWORD, lpnLengthNeeded::LPDWORD)::BOOL
end

function SetUserObjectInformationA(hObj, nIndex, pvInfo, nLength)
    @ccall user32.SetUserObjectInformationA(hObj::HANDLE, nIndex::Cint, pvInfo::PVOID, nLength::DWORD)::BOOL
end

function RegisterWindowMessageA(lpString)
    @ccall user32.RegisterWindowMessageA(lpString::LPCSTR)::UINT
end

struct tagMSG
    hwnd::Cint
    message::UINT
    wParam::WPARAM
    lParam::LPARAM
    time::DWORD
    pt::Cint
end

const LPMSG = Ptr{tagMSG}

function GetMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax)
    @ccall user32.GetMessageA(lpMsg::LPMSG, hWnd::Cint, wMsgFilterMin::UINT, wMsgFilterMax::UINT)::BOOL
end

const MSG = tagMSG

function DispatchMessageA(lpMsg)
    @ccall user32.DispatchMessageA(lpMsg::Ptr{MSG})::LRESULT
end

function PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg)
    @ccall user32.PeekMessageA(lpMsg::LPMSG, hWnd::Cint, wMsgFilterMin::UINT, wMsgFilterMax::UINT, wRemoveMsg::UINT)::BOOL
end

function ExitWindowsEx(uFlags, dwReason)
    @ccall user32.ExitWindowsEx(uFlags::UINT, dwReason::DWORD)::BOOL
end

function SendMessageA(hWnd, Msg, _Post_valid_)
    @ccall user32.SendMessageA(hWnd::Cint, Msg::UINT, _Post_valid_::Cint)::LRESULT
end

function SendMessageTimeoutA(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult)
    @ccall user32.SendMessageTimeoutA(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM, fuFlags::UINT, uTimeout::UINT, lpdwResult::PDWORD_PTR)::LRESULT
end

function SendNotifyMessageA(hWnd, Msg, wParam, lParam)
    @ccall user32.SendNotifyMessageA(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::BOOL
end

function SendMessageCallbackA(hWnd, Msg, wParam, lParam, lpResultCallBack, dwData)
    @ccall user32.SendMessageCallbackA(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM, lpResultCallBack::SENDASYNCPROC, dwData::ULONG_PTR)::BOOL
end

struct _LUID
    LowPart::DWORD
    HighPart::LONG
end

const LUID = _LUID

struct __JL_Ctag_40
    cbSize::UINT
    hdesk::Cint
    hwnd::Cint
    luid::LUID
end
function Base.getproperty(x::Ptr{__JL_Ctag_40}, f::Symbol)
    f === :cbSize && return Ptr{UINT}(x + 0)
    f === :hdesk && return Ptr{Cint}(x + 0)
    f === :hwnd && return Ptr{Cint}(x + 0)
    f === :luid && return Ptr{LUID}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_40, f::Symbol)
    r = Ref{__JL_Ctag_40}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_40}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_40}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PBSMINFO = Ptr{__JL_Ctag_40}

function BroadcastSystemMessageExA(flags, lpInfo, Msg, wParam, lParam, pbsmInfo)
    @ccall user32.BroadcastSystemMessageExA(flags::DWORD, lpInfo::LPDWORD, Msg::UINT, wParam::WPARAM, lParam::LPARAM, pbsmInfo::PBSMINFO)::Clong
end

function BroadcastSystemMessageA(flags, lpInfo, Msg, wParam, lParam)
    @ccall user32.BroadcastSystemMessageA(flags::DWORD, lpInfo::LPDWORD, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::Clong
end

const HDEVNOTIFY = PVOID

function RegisterDeviceNotificationA(hRecipient, NotificationFilter, Flags)
    @ccall user32.RegisterDeviceNotificationA(hRecipient::HANDLE, NotificationFilter::LPVOID, Flags::DWORD)::HDEVNOTIFY
end

function PostMessageA(hWnd, Msg, wParam, lParam)
    @ccall user32.PostMessageA(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::BOOL
end

function PostThreadMessageA(idThread, Msg, wParam, lParam)
    @ccall user32.PostThreadMessageA(idThread::DWORD, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::BOOL
end

function PostThreadMessageW(idThread, Msg, wParam, lParam)
    @ccall user32.PostThreadMessageW(idThread::DWORD, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::BOOL
end

function DefWindowProcA(hWnd, Msg, wParam, lParam)
    @ccall user32.DefWindowProcA(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function CallWindowProcA(lpPrevWndFunc, hWnd, Msg, wParam, lParam)
    @ccall user32.CallWindowProcA(lpPrevWndFunc::WNDPROC, hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

struct tagWNDCLASSA
    style::UINT
    lpfnWndProc::WNDPROC
    cbClsExtra::Cint
    cbWndExtra::Cint
    hInstance::HINSTANCE
    hIcon::Cint
    hCursor::Cint
    hbrBackground::Cint
    lpszMenuName::LPCSTR
    lpszClassName::LPCSTR
end

const WNDCLASSA = tagWNDCLASSA

function RegisterClassA(lpWndClass)
    @ccall user32.RegisterClassA(lpWndClass::Ptr{WNDCLASSA})::ATOM
end

function UnregisterClassA(lpClassName, hInstance)
    @ccall user32.UnregisterClassA(lpClassName::LPCSTR, hInstance::HINSTANCE)::BOOL
end

const LPWNDCLASSA = Ptr{tagWNDCLASSA}

function GetClassInfoA(hInstance, lpClassName, lpWndClass)
    @ccall user32.GetClassInfoA(hInstance::HINSTANCE, lpClassName::LPCSTR, lpWndClass::LPWNDCLASSA)::BOOL
end

struct tagWNDCLASSEXA
    cbSize::UINT
    style::UINT
    lpfnWndProc::WNDPROC
    cbClsExtra::Cint
    cbWndExtra::Cint
    hInstance::HINSTANCE
    hIcon::Cint
    hCursor::Cint
    hbrBackground::Cint
    lpszMenuName::LPCSTR
    lpszClassName::LPCSTR
    hIconSm::Cint
end

const WNDCLASSEXA = tagWNDCLASSEXA

function RegisterClassExA(arg1)
    @ccall user32.RegisterClassExA(arg1::Ptr{WNDCLASSEXA})::ATOM
end

const LPWNDCLASSEXA = Ptr{tagWNDCLASSEXA}

function GetClassInfoExA(hInstance, lpszClass, lpwcx)
    @ccall user32.GetClassInfoExA(hInstance::HINSTANCE, lpszClass::LPCSTR, lpwcx::LPWNDCLASSEXA)::BOOL
end

function CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam)
    @ccall user32.CreateWindowExA(dwExStyle::DWORD, lpClassName::LPCSTR, lpWindowName::LPCSTR, dwStyle::DWORD, X::Cint, Y::Cint, nWidth::Cint, nHeight::Cint, hWndParent::Cint, hMenu::Cint, hInstance::HINSTANCE, lpParam::LPVOID)::Cint
end

const LPCWSTR = Ptr{WCHAR}

function CreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam)
    @ccall user32.CreateWindowExW(dwExStyle::DWORD, lpClassName::LPCWSTR, lpWindowName::LPCWSTR, dwStyle::DWORD, X::Cint, Y::Cint, nWidth::Cint, nHeight::Cint, hWndParent::Cint, hMenu::Cint, hInstance::HINSTANCE, lpParam::LPVOID)::Cint
end

function CreateDialogParamA(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam)
    @ccall user32.CreateDialogParamA(hInstance::HINSTANCE, lpTemplateName::LPCSTR, hWndParent::Cint, lpDialogFunc::DLGPROC, dwInitParam::LPARAM)::Cint
end

struct DLGTEMPLATE
    style::DWORD
    dwExtendedStyle::DWORD
    cdit::WORD
    x::Cshort
    y::Cshort
    cx::Cshort
    cy::Cshort
end

const LPCDLGTEMPLATEA = Ptr{DLGTEMPLATE}

function CreateDialogIndirectParamA(hInstance, lpTemplate, hWndParent, lpDialogFunc, dwInitParam)
    @ccall user32.CreateDialogIndirectParamA(hInstance::HINSTANCE, lpTemplate::LPCDLGTEMPLATEA, hWndParent::Cint, lpDialogFunc::DLGPROC, dwInitParam::LPARAM)::Cint
end

function CreateDialogParamW(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam)
    @ccall user32.CreateDialogParamW(hInstance::HINSTANCE, lpTemplateName::LPCWSTR, hWndParent::Cint, lpDialogFunc::DLGPROC, dwInitParam::LPARAM)::Cint
end

const LPCDLGTEMPLATEW = Ptr{DLGTEMPLATE}

function CreateDialogIndirectParamW(hInstance, lpTemplate, hWndParent, lpDialogFunc, dwInitParam)
    @ccall user32.CreateDialogIndirectParamW(hInstance::HINSTANCE, lpTemplate::LPCDLGTEMPLATEW, hWndParent::Cint, lpDialogFunc::DLGPROC, dwInitParam::LPARAM)::Cint
end

function DialogBoxParamA(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam)
    @ccall user32.DialogBoxParamA(hInstance::HINSTANCE, lpTemplateName::LPCSTR, hWndParent::Cint, lpDialogFunc::DLGPROC, dwInitParam::LPARAM)::INT_PTR
end

function DialogBoxIndirectParamA(hInstance, hDialogTemplate, hWndParent, lpDialogFunc, dwInitParam)
    @ccall user32.DialogBoxIndirectParamA(hInstance::HINSTANCE, hDialogTemplate::LPCDLGTEMPLATEA, hWndParent::Cint, lpDialogFunc::DLGPROC, dwInitParam::LPARAM)::INT_PTR
end

function DialogBoxParamW(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam)
    @ccall user32.DialogBoxParamW(hInstance::HINSTANCE, lpTemplateName::LPCWSTR, hWndParent::Cint, lpDialogFunc::DLGPROC, dwInitParam::LPARAM)::INT_PTR
end

function DialogBoxIndirectParamW(hInstance, hDialogTemplate, hWndParent, lpDialogFunc, dwInitParam)
    @ccall user32.DialogBoxIndirectParamW(hInstance::HINSTANCE, hDialogTemplate::LPCDLGTEMPLATEW, hWndParent::Cint, lpDialogFunc::DLGPROC, dwInitParam::LPARAM)::INT_PTR
end

function SetDlgItemTextA(hDlg, nIDDlgItem, lpString)
    @ccall user32.SetDlgItemTextA(hDlg::Cint, nIDDlgItem::Cint, lpString::LPCSTR)::BOOL
end

function GetDlgItemTextA(hDlg, nIDDlgItem, lpString, cchMax)
    @ccall user32.GetDlgItemTextA(hDlg::Cint, nIDDlgItem::Cint, lpString::LPSTR, cchMax::Cint)::UINT
end

function SendDlgItemMessageA(hDlg, nIDDlgItem, Msg, wParam, lParam)
    @ccall user32.SendDlgItemMessageA(hDlg::Cint, nIDDlgItem::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function DefDlgProcA(hDlg, Msg, wParam, lParam)
    @ccall user32.DefDlgProcA(hDlg::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function CallMsgFilterA(lpMsg, nCode)
    @ccall user32.CallMsgFilterA(lpMsg::LPMSG, nCode::Cint)::BOOL
end

function RegisterClipboardFormatA(lpszFormat)
    @ccall user32.RegisterClipboardFormatA(lpszFormat::LPCSTR)::UINT
end

function GetClipboardFormatNameA(format, lpszFormatName, cchMaxCount)
    @ccall user32.GetClipboardFormatNameA(format::UINT, lpszFormatName::LPSTR, cchMaxCount::Cint)::Cint
end

function CharToOemA(pSrc, pDst)
    @ccall user32.CharToOemA(pSrc::LPCSTR, pDst::LPSTR)::BOOL
end

function OemToCharA(pSrc, pDst)
    @ccall user32.OemToCharA(pSrc::LPCSTR, pDst::LPSTR)::BOOL
end

function CharToOemBuffA(lpszSrc, lpszDst, cchDstLength)
    @ccall user32.CharToOemBuffA(lpszSrc::LPCSTR, lpszDst::LPSTR, cchDstLength::DWORD)::BOOL
end

function OemToCharBuffA(lpszSrc, lpszDst, cchDstLength)
    @ccall user32.OemToCharBuffA(lpszSrc::LPCSTR, lpszDst::LPSTR, cchDstLength::DWORD)::BOOL
end

function CharUpperA(lpsz)
    @ccall user32.CharUpperA(lpsz::LPSTR)::LPSTR
end

function CharUpperBuffA(lpsz, cchLength)
    @ccall user32.CharUpperBuffA(lpsz::LPSTR, cchLength::DWORD)::DWORD
end

function CharLowerA(lpsz)
    @ccall user32.CharLowerA(lpsz::LPSTR)::LPSTR
end

function CharLowerBuffA(lpsz, cchLength)
    @ccall user32.CharLowerBuffA(lpsz::LPSTR, cchLength::DWORD)::DWORD
end

function CharNextA(lpsz)
    @ccall user32.CharNextA(lpsz::LPCSTR)::LPSTR
end

function CharPrevA(lpszStart, lpszCurrent)
    @ccall user32.CharPrevA(lpszStart::LPCSTR, lpszCurrent::LPCSTR)::LPSTR
end

function IsCharAlphaA(ch)
    @ccall user32.IsCharAlphaA(ch::CHAR)::BOOL
end

function IsCharAlphaNumericA(ch)
    @ccall user32.IsCharAlphaNumericA(ch::CHAR)::BOOL
end

function IsCharUpperA(ch)
    @ccall user32.IsCharUpperA(ch::CHAR)::BOOL
end

function IsCharLowerA(ch)
    @ccall user32.IsCharLowerA(ch::CHAR)::BOOL
end

function GetKeyNameTextA(lParam, lpString, cchSize)
    @ccall user32.GetKeyNameTextA(lParam::LONG, lpString::LPSTR, cchSize::Cint)::Cint
end

function VkKeyScanA(ch)
    @ccall user32.VkKeyScanA(ch::CHAR)::SHORT
end

function VkKeyScanExA(ch, dwhkl)
    @ccall user32.VkKeyScanExA(ch::CHAR, dwhkl::HKL)::SHORT
end

function MapVirtualKeyA(uCode, uMapType)
    @ccall user32.MapVirtualKeyA(uCode::UINT, uMapType::UINT)::UINT
end

function MapVirtualKeyExA(uCode, uMapType, dwhkl)
    @ccall user32.MapVirtualKeyExA(uCode::UINT, uMapType::UINT, dwhkl::HKL)::UINT
end

function LoadAcceleratorsA(hInstance, lpTableName)
    @ccall user32.LoadAcceleratorsA(hInstance::HINSTANCE, lpTableName::LPCSTR)::Cint
end

struct tagACCEL
    fVirt::BYTE
    key::WORD
    cmd::WORD
end

const LPACCEL = Ptr{tagACCEL}

function CreateAcceleratorTableA(paccel, cAccel)
    @ccall user32.CreateAcceleratorTableA(paccel::LPACCEL, cAccel::Cint)::Cint
end

function CopyAcceleratorTableA(hAccelSrc, lpAccelDst, cAccelEntries)
    @ccall user32.CopyAcceleratorTableA(hAccelSrc::Cint, lpAccelDst::LPACCEL, cAccelEntries::Cint)::Cint
end

function TranslateAcceleratorA(hWnd, hAccTable, lpMsg)
    @ccall user32.TranslateAcceleratorA(hWnd::Cint, hAccTable::Cint, lpMsg::LPMSG)::Cint
end

function LoadMenuA(hInstance, lpMenuName)
    @ccall user32.LoadMenuA(hInstance::HINSTANCE, lpMenuName::LPCSTR)::Cint
end

const MENUTEMPLATEA = Cvoid

function LoadMenuIndirectA(lpMenuTemplate)
    @ccall user32.LoadMenuIndirectA(lpMenuTemplate::Ptr{MENUTEMPLATEA})::Cint
end

function ChangeMenuA(hMenu, cmd, lpszNewItem, cmdInsert, flags)
    @ccall user32.ChangeMenuA(hMenu::Cint, cmd::UINT, lpszNewItem::LPCSTR, cmdInsert::UINT, flags::UINT)::BOOL
end

function GetMenuStringA(hMenu, uIDItem, lpString, cchMax, flags)
    @ccall user32.GetMenuStringA(hMenu::Cint, uIDItem::UINT, lpString::LPSTR, cchMax::Cint, flags::UINT)::Cint
end

function InsertMenuA(hMenu, uPosition, uFlags, uIDNewItem, lpNewItem)
    @ccall user32.InsertMenuA(hMenu::Cint, uPosition::UINT, uFlags::UINT, uIDNewItem::UINT_PTR, lpNewItem::LPCSTR)::BOOL
end

function AppendMenuA(hMenu, uFlags, uIDNewItem, lpNewItem)
    @ccall user32.AppendMenuA(hMenu::Cint, uFlags::UINT, uIDNewItem::UINT_PTR, lpNewItem::LPCSTR)::BOOL
end

function ModifyMenuA(hMnu, uPosition, uFlags, uIDNewItem, lpNewItem)
    @ccall user32.ModifyMenuA(hMnu::Cint, uPosition::UINT, uFlags::UINT, uIDNewItem::UINT_PTR, lpNewItem::LPCSTR)::BOOL
end

struct tagMENUITEMINFOA
    cbSize::UINT
    fMask::UINT
    fType::UINT
    fState::UINT
    wID::UINT
    hSubMenu::Cint
    hbmpChecked::Cint
    hbmpUnchecked::Cint
    dwItemData::ULONG_PTR
    dwTypeData::LPSTR
    cch::UINT
    hbmpItem::Cint
end

const MENUITEMINFOA = tagMENUITEMINFOA

const LPCMENUITEMINFOA = Ptr{MENUITEMINFOA}

function InsertMenuItemA(hmenu, item, fByPosition, lpmi)
    @ccall user32.InsertMenuItemA(hmenu::Cint, item::UINT, fByPosition::BOOL, lpmi::LPCMENUITEMINFOA)::BOOL
end

const LPMENUITEMINFOA = Ptr{tagMENUITEMINFOA}

function GetMenuItemInfoA(hmenu, item, fByPosition, lpmii)
    @ccall user32.GetMenuItemInfoA(hmenu::Cint, item::UINT, fByPosition::BOOL, lpmii::LPMENUITEMINFOA)::BOOL
end

function SetMenuItemInfoA(hmenu, item, fByPositon, lpmii)
    @ccall user32.SetMenuItemInfoA(hmenu::Cint, item::UINT, fByPositon::BOOL, lpmii::LPCMENUITEMINFOA)::BOOL
end

function DrawTextA(hdc, lpchText, cchText, lprc, format)
    @ccall user32.DrawTextA(hdc::Cint, lpchText::LPCSTR, cchText::Cint, lprc::Cint, format::UINT)::Cint
end

struct tagDRAWTEXTPARAMS
    cbSize::UINT
    iTabLength::Cint
    iLeftMargin::Cint
    iRightMargin::Cint
    uiLengthDrawn::UINT
end

const LPDRAWTEXTPARAMS = Ptr{tagDRAWTEXTPARAMS}

function DrawTextExA(hdc, lpchText, cchText, lprc, format, lpdtp)
    @ccall user32.DrawTextExA(hdc::Cint, lpchText::LPSTR, cchText::Cint, lprc::Cint, format::UINT, lpdtp::LPDRAWTEXTPARAMS)::Cint
end

function GrayStringA(hDC, hBrush, lpOutputFunc, lpData, nCount, X, Y, nWidth, nHeight)
    @ccall user32.GrayStringA(hDC::Cint, hBrush::Cint, lpOutputFunc::GRAYSTRINGPROC, lpData::LPARAM, nCount::Cint, X::Cint, Y::Cint, nWidth::Cint, nHeight::Cint)::BOOL
end

# typedef BOOL ( CALLBACK * DRAWSTATEPROC ) ( HDC hdc , LPARAM lData , WPARAM wData , int cx , int cy )
const DRAWSTATEPROC = Ptr{Cvoid}

function DrawStateA(hdc, hbrFore, qfnCallBack, lData, wData, x, y, cx, cy, uFlags)
    @ccall user32.DrawStateA(hdc::Cint, hbrFore::Cint, qfnCallBack::DRAWSTATEPROC, lData::LPARAM, wData::WPARAM, x::Cint, y::Cint, cx::Cint, cy::Cint, uFlags::UINT)::BOOL
end

const INT = Cint

function TabbedTextOutA(hdc, x, y, lpString, chCount, nTabPositions, lpnTabStopPositions, nTabOrigin)
    @ccall user32.TabbedTextOutA(hdc::Cint, x::Cint, y::Cint, lpString::LPCSTR, chCount::Cint, nTabPositions::Cint, lpnTabStopPositions::Ptr{INT}, nTabOrigin::Cint)::LONG
end

function GetTabbedTextExtentA(hdc, lpString, chCount, nTabPositions, lpnTabStopPositions)
    @ccall user32.GetTabbedTextExtentA(hdc::Cint, lpString::LPCSTR, chCount::Cint, nTabPositions::Cint, lpnTabStopPositions::Ptr{INT})::DWORD
end

function SetPropA(hWnd, lpString, hData)
    @ccall user32.SetPropA(hWnd::Cint, lpString::LPCSTR, hData::HANDLE)::BOOL
end

function GetPropA(hWnd, lpString)
    @ccall user32.GetPropA(hWnd::Cint, lpString::LPCSTR)::HANDLE
end

function RemovePropA(hWnd, lpString)
    @ccall user32.RemovePropA(hWnd::Cint, lpString::LPCSTR)::HANDLE
end

function EnumPropsExA(hWnd, lpEnumFunc, lParam)
    @ccall user32.EnumPropsExA(hWnd::Cint, lpEnumFunc::PROPENUMPROCEXA, lParam::LPARAM)::Cint
end

function EnumPropsA(hWnd, lpEnumFunc)
    @ccall user32.EnumPropsA(hWnd::Cint, lpEnumFunc::PROPENUMPROCA)::Cint
end

function SetWindowTextA(hWnd, lpString)
    @ccall user32.SetWindowTextA(hWnd::Cint, lpString::LPCSTR)::BOOL
end

function GetWindowTextA(hWnd, lpString, nMaxCount)
    @ccall user32.GetWindowTextA(hWnd::Cint, lpString::LPSTR, nMaxCount::Cint)::Cint
end

function GetWindowTextLengthA(hWnd)
    @ccall user32.GetWindowTextLengthA(hWnd::Cint)::Cint
end

function MessageBoxA(hWnd, lpText, lpCaption, uType)
    @ccall user32.MessageBoxA(hWnd::Cint, lpText::LPCSTR, lpCaption::LPCSTR, uType::UINT)::Cint
end

function MessageBoxExA(hWnd, lpText, lpCaption, uType, wLanguageId)
    @ccall user32.MessageBoxExA(hWnd::Cint, lpText::LPCSTR, lpCaption::LPCSTR, uType::UINT, wLanguageId::WORD)::Cint
end

# typedef VOID ( CALLBACK * MSGBOXCALLBACK ) ( LPHELPINFO lpHelpInfo )
const MSGBOXCALLBACK = Ptr{Cvoid}

struct tagMSGBOXPARAMSA
    cbSize::UINT
    hwndOwner::Cint
    hInstance::HINSTANCE
    lpszText::LPCSTR
    lpszCaption::LPCSTR
    dwStyle::DWORD
    lpszIcon::LPCSTR
    dwContextHelpId::DWORD_PTR
    lpfnMsgBoxCallback::MSGBOXCALLBACK
    dwLanguageId::DWORD
end

const MSGBOXPARAMSA = tagMSGBOXPARAMSA

function MessageBoxIndirectA(lpmbp)
    @ccall user32.MessageBoxIndirectA(lpmbp::Ptr{MSGBOXPARAMSA})::Cint
end

function GetWindowLongA(hWnd, nIndex)
    @ccall user32.GetWindowLongA(hWnd::Cint, nIndex::Cint)::LONG
end

function SetWindowLongA(hWnd, nIndex, dwNewLong)
    @ccall user32.SetWindowLongA(hWnd::Cint, nIndex::Cint, dwNewLong::LONG)::LONG
end

function GetWindowLongPtrA(hWnd, nIndex)
    @ccall user32.GetWindowLongPtrA(hWnd::Cint, nIndex::Cint)::LONG_PTR
end

function SetWindowLongPtrA(hWnd, nIndex, dwNewLong)
    @ccall user32.SetWindowLongPtrA(hWnd::Cint, nIndex::Cint, dwNewLong::LONG_PTR)::LONG_PTR
end

function GetClassLongA(hWnd, nIndex)
    @ccall user32.GetClassLongA(hWnd::Cint, nIndex::Cint)::DWORD
end

function SetClassLongA(hWnd, nIndex, dwNewLong)
    @ccall user32.SetClassLongA(hWnd::Cint, nIndex::Cint, dwNewLong::LONG)::DWORD
end

function GetClassLongPtrA(hWnd, nIndex)
    @ccall user32.GetClassLongPtrA(hWnd::Cint, nIndex::Cint)::ULONG_PTR
end

function SetClassLongPtrA(hWnd, nIndex, dwNewLong)
    @ccall user32.SetClassLongPtrA(hWnd::Cint, nIndex::Cint, dwNewLong::LONG_PTR)::ULONG_PTR
end

function FindWindowA(lpClassName, lpWindowName)
    @ccall user32.FindWindowA(lpClassName::LPCSTR, lpWindowName::LPCSTR)::Cint
end

function FindWindowExA(hWndParent, hWndChildAfter, lpszClass, lpszWindow)
    @ccall user32.FindWindowExA(hWndParent::Cint, hWndChildAfter::Cint, lpszClass::LPCSTR, lpszWindow::LPCSTR)::Cint
end

function EnumThreadWindows(dwThreadId, lpfn, lParam)
    @ccall user32.EnumThreadWindows(dwThreadId::DWORD, lpfn::WNDENUMPROC, lParam::LPARAM)::BOOL
end

function GetClassNameA(hWnd, lpClassName, nMaxCount)
    @ccall user32.GetClassNameA(hWnd::Cint, lpClassName::LPSTR, nMaxCount::Cint)::Cint
end

function GetWindow(hWnd, uCmd)
    @ccall user32.GetWindow(hWnd::Cint, uCmd::UINT)::Cint
end

function GetWindowThreadProcessId(hWnd, lpdwProcessId)
    @ccall user32.GetWindowThreadProcessId(hWnd::Cint, lpdwProcessId::LPDWORD)::DWORD
end

function SetWindowsHookA(nFilterType, pfnFilterProc)
    @ccall user32.SetWindowsHookA(nFilterType::Cint, pfnFilterProc::HOOKPROC)::Cint
end

function SetWindowsHookExA(idHook, lpfn, hmod, dwThreadId)
    @ccall user32.SetWindowsHookExA(idHook::Cint, lpfn::HOOKPROC, hmod::HINSTANCE, dwThreadId::DWORD)::Cint
end

function CallNextHookEx(hhk, nCode, wParam, lParam)
    @ccall user32.CallNextHookEx(hhk::Cint, nCode::Cint, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function LoadBitmapA(hInstance, lpBitmapName)
    @ccall user32.LoadBitmapA(hInstance::HINSTANCE, lpBitmapName::LPCSTR)::Cint
end

function LoadCursorA(hInstance, lpCursorName)
    @ccall user32.LoadCursorA(hInstance::HINSTANCE, lpCursorName::LPCSTR)::Cint
end

function LoadCursorFromFileA(lpFileName)
    @ccall user32.LoadCursorFromFileA(lpFileName::LPCSTR)::Cint
end

function CopyIcon(hIcon)
    @ccall user32.CopyIcon(hIcon::Cint)::Cint
end

function LoadIconA(hInstance, lpIconName)
    @ccall user32.LoadIconA(hInstance::HINSTANCE, lpIconName::LPCSTR)::Cint
end

function PrivateExtractIconsA(szFileName, nIconIndex, cxIcon, cyIcon, phicon, piconid, nIcons, flags)
    @ccall user32.PrivateExtractIconsA(szFileName::LPCSTR, nIconIndex::Cint, cxIcon::Cint, cyIcon::Cint, phicon::Ptr{Cint}, piconid::Ptr{UINT}, nIcons::UINT, flags::UINT)::UINT
end

function LoadImageA(hInst, name, type, cx, cy, fuLoad)
    @ccall user32.LoadImageA(hInst::HINSTANCE, name::LPCSTR, type::UINT, cx::Cint, cy::Cint, fuLoad::UINT)::HANDLE
end

function IsDialogMessageA(hDlg, lpMsg)
    @ccall user32.IsDialogMessageA(hDlg::Cint, lpMsg::LPMSG)::BOOL
end

function DlgDirListA(hDlg, lpPathSpec, nIDListBox, nIDStaticPath, uFileType)
    @ccall user32.DlgDirListA(hDlg::Cint, lpPathSpec::LPSTR, nIDListBox::Cint, nIDStaticPath::Cint, uFileType::UINT)::Cint
end

function DlgDirSelectExA(hwndDlg, lpString, chCount, idListBox)
    @ccall user32.DlgDirSelectExA(hwndDlg::Cint, lpString::LPSTR, chCount::Cint, idListBox::Cint)::BOOL
end

function DlgDirListComboBoxA(hDlg, lpPathSpec, nIDComboBox, nIDStaticPath, uFiletype)
    @ccall user32.DlgDirListComboBoxA(hDlg::Cint, lpPathSpec::LPSTR, nIDComboBox::Cint, nIDStaticPath::Cint, uFiletype::UINT)::Cint
end

function DlgDirSelectComboBoxExA(hwndDlg, lpString, cchOut, idComboBox)
    @ccall user32.DlgDirSelectComboBoxExA(hwndDlg::Cint, lpString::LPSTR, cchOut::Cint, idComboBox::Cint)::BOOL
end

function DefFrameProcA(hWnd, hWndMDIClient, uMsg, wParam, lParam)
    @ccall user32.DefFrameProcA(hWnd::Cint, hWndMDIClient::Cint, uMsg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function DefMDIChildProcA(hWnd, uMsg, wParam, lParam)
    @ccall user32.DefMDIChildProcA(hWnd::Cint, uMsg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function CreateMDIWindowA(lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hInstance, lParam)
    @ccall user32.CreateMDIWindowA(lpClassName::LPCSTR, lpWindowName::LPCSTR, dwStyle::DWORD, X::Cint, Y::Cint, nWidth::Cint, nHeight::Cint, hWndParent::Cint, hInstance::HINSTANCE, lParam::LPARAM)::Cint
end

function WinHelpA(hWndMain, lpszHelp, uCommand, dwData)
    @ccall user32.WinHelpA(hWndMain::Cint, lpszHelp::LPCSTR, uCommand::UINT, dwData::ULONG_PTR)::BOOL
end

function SystemParametersInfoA(uiAction, uiParam, _Post_valid_)
    @ccall user32.SystemParametersInfoA(uiAction::UINT, uiParam::UINT, _Post_valid_::Cint)::BOOL
end

struct tagMONITORINFO
    cbSize::DWORD
    rcMonitor::Cint
    rcWork::Cint
    dwFlags::DWORD
end

const LPMONITORINFO = Ptr{tagMONITORINFO}

function GetMonitorInfoA(hMonitor, lpmi)
    @ccall user32.GetMonitorInfoA(hMonitor::Cint, lpmi::LPMONITORINFO)::BOOL
end

function GetWindowModuleFileNameA(hwnd, pszFileName, cchFileNameMax)
    @ccall user32.GetWindowModuleFileNameA(hwnd::Cint, pszFileName::LPSTR, cchFileNameMax::UINT)::UINT
end

function RealGetWindowClassA(hwnd, ptszClassName, cchClassNameMax)
    @ccall user32.RealGetWindowClassA(hwnd::Cint, ptszClassName::LPSTR, cchClassNameMax::UINT)::UINT
end

struct tagALTTABINFO
    cbSize::DWORD
    cItems::Cint
    cColumns::Cint
    cRows::Cint
    iColFocus::Cint
    iRowFocus::Cint
    cxItem::Cint
    cyItem::Cint
    ptStart::Cint
end

const PALTTABINFO = Ptr{tagALTTABINFO}

function GetAltTabInfoA(hwnd, iItem, pati, pszItemText, cchItemText)
    @ccall user32.GetAltTabInfoA(hwnd::Cint, iItem::Cint, pati::PALTTABINFO, pszItemText::LPSTR, cchItemText::UINT)::BOOL
end

struct tagRAWINPUTHEADER
    dwType::DWORD
    dwSize::DWORD
    hDevice::HANDLE
    wParam::WPARAM
end

const RAWINPUTHEADER = tagRAWINPUTHEADER

struct tagRAWMOUSE
    data::NTuple{24, UInt8}
end

function Base.getproperty(x::Ptr{tagRAWMOUSE}, f::Symbol)
    f === :usFlags && return Ptr{USHORT}(x + 0)
    f === :ulButtons && return Ptr{ULONG}(x + 4)
    f === :usButtonFlags && return Ptr{USHORT}(x + 4)
    f === :usButtonData && return Ptr{USHORT}(x + 6)
    f === :ulRawButtons && return Ptr{ULONG}(x + 8)
    f === :lLastX && return Ptr{LONG}(x + 12)
    f === :lLastY && return Ptr{LONG}(x + 16)
    f === :ulExtraInformation && return Ptr{ULONG}(x + 20)
    return getfield(x, f)
end

function Base.getproperty(x::tagRAWMOUSE, f::Symbol)
    r = Ref{tagRAWMOUSE}(x)
    ptr = Base.unsafe_convert(Ptr{tagRAWMOUSE}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{tagRAWMOUSE}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function tagRAWMOUSE(usFlags::USHORT, ulRawButtons::ULONG, lLastX::LONG, lLastY::LONG, ulExtraInformation::ULONG)
    ref = Ref{tagRAWMOUSE}()
    ptr = Base.unsafe_convert(Ptr{tagRAWMOUSE}, ref)
    ptr.usFlags = usFlags
    ptr.ulRawButtons = ulRawButtons
    ptr.lLastX = lLastX
    ptr.lLastY = lLastY
    ptr.ulExtraInformation = ulExtraInformation
    ref[]
end

const RAWMOUSE = tagRAWMOUSE

struct tagRAWKEYBOARD
    MakeCode::USHORT
    Flags::USHORT
    Reserved::USHORT
    VKey::USHORT
    Message::UINT
    ExtraInformation::ULONG
end

const RAWKEYBOARD = tagRAWKEYBOARD

struct tagRAWHID
    dwSizeHid::DWORD
    dwCount::DWORD
    bRawData::NTuple{1, BYTE}
end

const RAWHID = tagRAWHID

struct __JL_Ctag_78
    data::NTuple{24, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_78}, f::Symbol)
    f === :mouse && return Ptr{RAWMOUSE}(x + 0)
    f === :keyboard && return Ptr{RAWKEYBOARD}(x + 0)
    f === :hid && return Ptr{RAWHID}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_78, f::Symbol)
    r = Ref{__JL_Ctag_78}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_78}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_78}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_78 = Union{RAWMOUSE, RAWKEYBOARD, RAWHID}

function __JL_Ctag_78(val::__U___JL_Ctag_78)
    ref = Ref{__JL_Ctag_78}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_78}, ref)
    if val isa RAWMOUSE
        ptr.mouse = val
    elseif val isa RAWKEYBOARD
        ptr.keyboard = val
    elseif val isa RAWHID
        ptr.hid = val
    end
    ref[]
end

struct tagRAWINPUT
    data::NTuple{48, UInt8}
end

function Base.getproperty(x::Ptr{tagRAWINPUT}, f::Symbol)
    f === :header && return Ptr{RAWINPUTHEADER}(x + 0)
    f === :data && return Ptr{__JL_Ctag_78}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::tagRAWINPUT, f::Symbol)
    r = Ref{tagRAWINPUT}(x)
    ptr = Base.unsafe_convert(Ptr{tagRAWINPUT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{tagRAWINPUT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function tagRAWINPUT(header::RAWINPUTHEADER, data::__JL_Ctag_78)
    ref = Ref{tagRAWINPUT}()
    ptr = Base.unsafe_convert(Ptr{tagRAWINPUT}, ref)
    ptr.header = header
    ptr.data = data
    ref[]
end

const PRAWINPUT = Ptr{tagRAWINPUT}

function GetRawInputDeviceInfoA(hDevice, uiCommand, pData, pcbSize)
    @ccall user32.GetRawInputDeviceInfoA(hDevice::HANDLE, uiCommand::UINT, pData::LPVOID, pcbSize::PUINT)::UINT
end

const PVOID64 = Ptr{Cvoid}

const PWCHAR = Ptr{WCHAR}

const LPWCH = Ptr{WCHAR}

const PWCH = Ptr{WCHAR}

const LPCWCH = Ptr{WCHAR}

const PCWCH = Ptr{WCHAR}

const NWPSTR = Ptr{WCHAR}

const PWSTR = Ptr{WCHAR}

const PZPWSTR = Ptr{PWSTR}

const PCZPWSTR = Ptr{PWSTR}

const LPUWSTR = Ptr{WCHAR}

const PUWSTR = Ptr{WCHAR}

const PZPCWSTR = Ptr{PCWSTR}

const PCZPCWSTR = Ptr{PCWSTR}

const LPCUWSTR = Ptr{WCHAR}

const PCUWSTR = Ptr{WCHAR}

const PZZWSTR = Ptr{WCHAR}

const PCZZWSTR = Ptr{WCHAR}

const PUZZWSTR = Ptr{WCHAR}

const PCUZZWSTR = Ptr{WCHAR}

const PNZWCH = Ptr{WCHAR}

const PCNZWCH = Ptr{WCHAR}

const PUNZWCH = Ptr{WCHAR}

const PCUNZWCH = Ptr{WCHAR}

const LPCH = Ptr{CHAR}

const PCH = Ptr{CHAR}

const LPCCH = Ptr{CHAR}

const PCCH = Ptr{CHAR}

const NPSTR = Ptr{CHAR}

const PSTR = Ptr{CHAR}

const PZPSTR = Ptr{PSTR}

const PCZPSTR = Ptr{PSTR}

const PCSTR = Ptr{CHAR}

const PZPCSTR = Ptr{PCSTR}

const PCZPCSTR = Ptr{PCSTR}

const PZZSTR = Ptr{CHAR}

const PCZZSTR = Ptr{CHAR}

const PNZCH = Ptr{CHAR}

const PCNZCH = Ptr{CHAR}

const TCHAR = Cchar

const PTCHAR = Ptr{Cchar}

const TBYTE = Cuchar

const PTBYTE = Ptr{Cuchar}

const LPTCH = LPCH

const PTCH = LPCH

const LPCTCH = LPCCH

const PCTCH = LPCCH

const PTSTR = LPSTR

const LPTSTR = LPSTR

const PUTSTR = LPSTR

const LPUTSTR = LPSTR

const PCTSTR = LPCSTR

const LPCTSTR = LPCSTR

const PCUTSTR = LPCSTR

const LPCUTSTR = LPCSTR

const PZZTSTR = PZZSTR

const PUZZTSTR = PZZSTR

const PCZZTSTR = PCZZSTR

const PCUZZTSTR = PCZZSTR

const PZPTSTR = PZPSTR

const PNZTCH = PNZCH

const PUNZTCH = PNZCH

const PCNZTCH = PCNZCH

const PCUNZTCH = PCNZCH

const PSHORT = Ptr{SHORT}

const PLONG = Ptr{LONG}

struct _PROCESSOR_NUMBER
    Group::WORD
    Number::BYTE
    Reserved::BYTE
end

const PROCESSOR_NUMBER = _PROCESSOR_NUMBER

const PPROCESSOR_NUMBER = Ptr{_PROCESSOR_NUMBER}

struct _GROUP_AFFINITY
    Mask::KAFFINITY
    Group::WORD
    Reserved::NTuple{3, WORD}
end

const GROUP_AFFINITY = _GROUP_AFFINITY

const PGROUP_AFFINITY = Ptr{_GROUP_AFFINITY}

const PHANDLE = Ptr{HANDLE}

const FCHAR = BYTE

const FSHORT = WORD

const FLONG = DWORD

const CCHAR = Cchar

const LCID = DWORD

const PLCID = PDWORD

const LANGID = WORD

@cenum __JL_Ctag_1::UInt32 begin
    UNSPECIFIED_COMPARTMENT_ID = 0
    DEFAULT_COMPARTMENT_ID = 1
end

const COMPARTMENT_ID = Cvoid

const PCOMPARTMENT_ID = Ptr{Cvoid}

struct _FLOAT128
    LowPart::Clonglong
    HighPart::Clonglong
end

const FLOAT128 = _FLOAT128

const PFLOAT128 = Ptr{FLOAT128}

const PLONGLONG = Ptr{LONGLONG}

const PULONGLONG = Ptr{ULONGLONG}

const USN = LONGLONG

struct __JL_Ctag_86
    LowPart::DWORD
    HighPart::LONG
end
function Base.getproperty(x::Ptr{__JL_Ctag_86}, f::Symbol)
    f === :LowPart && return Ptr{DWORD}(x + 0)
    f === :HighPart && return Ptr{LONG}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_86, f::Symbol)
    r = Ref{__JL_Ctag_86}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_86}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_86}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct _LARGE_INTEGER
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_LARGE_INTEGER}, f::Symbol)
    f === :LowPart && return Ptr{DWORD}(x + 0)
    f === :HighPart && return Ptr{LONG}(x + 4)
    f === :u && return Ptr{__JL_Ctag_86}(x + 0)
    f === :QuadPart && return Ptr{LONGLONG}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_LARGE_INTEGER, f::Symbol)
    r = Ref{_LARGE_INTEGER}(x)
    ptr = Base.unsafe_convert(Ptr{_LARGE_INTEGER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_LARGE_INTEGER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__LARGE_INTEGER = Union{__JL_Ctag_86, LONGLONG}

function _LARGE_INTEGER(val::__U__LARGE_INTEGER)
    ref = Ref{_LARGE_INTEGER}()
    ptr = Base.unsafe_convert(Ptr{_LARGE_INTEGER}, ref)
    if val isa __JL_Ctag_86
        ptr.u = val
    elseif val isa LONGLONG
        ptr.QuadPart = val
    end
    ref[]
end

const LARGE_INTEGER = _LARGE_INTEGER

const PLARGE_INTEGER = Ptr{LARGE_INTEGER}

struct __JL_Ctag_80
    LowPart::DWORD
    HighPart::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_80}, f::Symbol)
    f === :LowPart && return Ptr{DWORD}(x + 0)
    f === :HighPart && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_80, f::Symbol)
    r = Ref{__JL_Ctag_80}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_80}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_80}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct _ULARGE_INTEGER
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_ULARGE_INTEGER}, f::Symbol)
    f === :LowPart && return Ptr{DWORD}(x + 0)
    f === :HighPart && return Ptr{DWORD}(x + 4)
    f === :u && return Ptr{__JL_Ctag_80}(x + 0)
    f === :QuadPart && return Ptr{ULONGLONG}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_ULARGE_INTEGER, f::Symbol)
    r = Ref{_ULARGE_INTEGER}(x)
    ptr = Base.unsafe_convert(Ptr{_ULARGE_INTEGER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_ULARGE_INTEGER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__ULARGE_INTEGER = Union{__JL_Ctag_80, ULONGLONG}

function _ULARGE_INTEGER(val::__U__ULARGE_INTEGER)
    ref = Ref{_ULARGE_INTEGER}()
    ptr = Base.unsafe_convert(Ptr{_ULARGE_INTEGER}, ref)
    if val isa __JL_Ctag_80
        ptr.u = val
    elseif val isa ULONGLONG
        ptr.QuadPart = val
    end
    ref[]
end

const ULARGE_INTEGER = _ULARGE_INTEGER

const PULARGE_INTEGER = Ptr{ULARGE_INTEGER}

const RTL_REFERENCE_COUNT = LONG_PTR

const PRTL_REFERENCE_COUNT = Ptr{LONG_PTR}

const RTL_REFERENCE_COUNT32 = LONG

const PRTL_REFERENCE_COUNT32 = Ptr{LONG}

const PLUID = Ptr{_LUID}

const DWORDLONG = ULONGLONG

const PDWORDLONG = Ptr{DWORDLONG}

const BOOLEAN = BYTE

const PBOOLEAN = Ptr{BOOLEAN}

struct _LIST_ENTRY
    Flink::Ptr{_LIST_ENTRY}
    Blink::Ptr{_LIST_ENTRY}
end

const LIST_ENTRY = _LIST_ENTRY

const PLIST_ENTRY = Ptr{_LIST_ENTRY}

const PRLIST_ENTRY = Ptr{_LIST_ENTRY}

struct _SINGLE_LIST_ENTRY
    Next::Ptr{_SINGLE_LIST_ENTRY}
end

const SINGLE_LIST_ENTRY = _SINGLE_LIST_ENTRY

const PSINGLE_LIST_ENTRY = Ptr{_SINGLE_LIST_ENTRY}

struct LIST_ENTRY32
    Flink::DWORD
    Blink::DWORD
end

const PLIST_ENTRY32 = Ptr{LIST_ENTRY32}

struct LIST_ENTRY64
    Flink::ULONGLONG
    Blink::ULONGLONG
end

const PLIST_ENTRY64 = Ptr{LIST_ENTRY64}

struct _OBJECTID
    Lineage::GUID
    Uniquifier::DWORD
end

const OBJECTID = _OBJECTID

# typedef EXCEPTION_ROUTINE * PEXCEPTION_ROUTINE
const PEXCEPTION_ROUTINE = Ptr{EXCEPTION_ROUTINE}

const KSPIN_LOCK = ULONG_PTR

const PKSPIN_LOCK = Ptr{KSPIN_LOCK}

struct _M128A
    Low::ULONGLONG
    High::LONGLONG
end

const M128A = _M128A

const PM128A = Ptr{_M128A}

struct _XSAVE_FORMAT
    ControlWord::WORD
    StatusWord::WORD
    TagWord::BYTE
    Reserved1::BYTE
    ErrorOpcode::WORD
    ErrorOffset::DWORD
    ErrorSelector::WORD
    Reserved2::WORD
    DataOffset::DWORD
    DataSelector::WORD
    Reserved3::WORD
    MxCsr::DWORD
    MxCsr_Mask::DWORD
    FloatRegisters::NTuple{8, M128A}
    XmmRegisters::NTuple{16, M128A}
    Reserved4::NTuple{96, BYTE}
end

const XSAVE_FORMAT = _XSAVE_FORMAT

const PXSAVE_FORMAT = Ptr{_XSAVE_FORMAT}

struct _XSAVE_CET_U_FORMAT
    Ia32CetUMsr::DWORD64
    Ia32Pl3SspMsr::DWORD64
end

const XSAVE_CET_U_FORMAT = _XSAVE_CET_U_FORMAT

const PXSAVE_CET_U_FORMAT = Ptr{_XSAVE_CET_U_FORMAT}

struct _XSAVE_AREA_HEADER
    Mask::DWORD64
    CompactionMask::DWORD64
    Reserved2::NTuple{6, DWORD64}
end

const XSAVE_AREA_HEADER = _XSAVE_AREA_HEADER

const PXSAVE_AREA_HEADER = Ptr{_XSAVE_AREA_HEADER}

struct _XSAVE_AREA
    LegacyState::XSAVE_FORMAT
    Header::XSAVE_AREA_HEADER
end

const XSAVE_AREA = _XSAVE_AREA

const PXSAVE_AREA = Ptr{_XSAVE_AREA}

struct _XSTATE_CONTEXT
    Mask::DWORD64
    Length::DWORD
    Reserved1::DWORD
    Area::PXSAVE_AREA
    Buffer::PVOID
end

const XSTATE_CONTEXT = _XSTATE_CONTEXT

const PXSTATE_CONTEXT = Ptr{_XSTATE_CONTEXT}

struct _KERNEL_CET_CONTEXT
    data::NTuple{24, UInt8}
end

function Base.getproperty(x::Ptr{_KERNEL_CET_CONTEXT}, f::Symbol)
    f === :Ssp && return Ptr{DWORD64}(x + 0)
    f === :Rip && return Ptr{DWORD64}(x + 8)
    f === :SegCs && return Ptr{WORD}(x + 16)
    f === :AllFlags && return Ptr{WORD}(x + 18)
    f === :UseWrss && return (Ptr{WORD}(x + 16), 16, 1)
    f === :PopShadowStackOne && return (Ptr{WORD}(x + 16), 17, 1)
    f === :Unused && return (Ptr{WORD}(x + 16), 18, 14)
    f === :Fill && return Ptr{NTuple{2, WORD}}(x + 20)
    return getfield(x, f)
end

function Base.getproperty(x::_KERNEL_CET_CONTEXT, f::Symbol)
    r = Ref{_KERNEL_CET_CONTEXT}(x)
    ptr = Base.unsafe_convert(Ptr{_KERNEL_CET_CONTEXT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_KERNEL_CET_CONTEXT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _KERNEL_CET_CONTEXT(Ssp::DWORD64, Rip::DWORD64, SegCs::WORD, Fill::NTuple{2, WORD})
    ref = Ref{_KERNEL_CET_CONTEXT}()
    ptr = Base.unsafe_convert(Ptr{_KERNEL_CET_CONTEXT}, ref)
    ptr.Ssp = Ssp
    ptr.Rip = Rip
    ptr.SegCs = SegCs
    ptr.Fill = Fill
    ref[]
end

const KERNEL_CET_CONTEXT = _KERNEL_CET_CONTEXT

const PKERNEL_CET_CONTEXT = Ptr{_KERNEL_CET_CONTEXT}

struct __JL_Ctag_75
    BeginAddress::DWORD
    EndAddress::DWORD
    HandlerAddress::DWORD
    JumpTarget::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_75}, f::Symbol)
    f === :BeginAddress && return Ptr{DWORD}(x + 0)
    f === :EndAddress && return Ptr{DWORD}(x + 4)
    f === :HandlerAddress && return Ptr{DWORD}(x + 8)
    f === :JumpTarget && return Ptr{DWORD}(x + 12)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_75, f::Symbol)
    r = Ref{__JL_Ctag_75}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_75}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_75}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct _SCOPE_TABLE_AMD64
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_SCOPE_TABLE_AMD64}, f::Symbol)
    f === :Count && return Ptr{DWORD}(x + 0)
    f === :ScopeRecord && return Ptr{NTuple{1, __JL_Ctag_75}}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_SCOPE_TABLE_AMD64, f::Symbol)
    r = Ref{_SCOPE_TABLE_AMD64}(x)
    ptr = Base.unsafe_convert(Ptr{_SCOPE_TABLE_AMD64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_SCOPE_TABLE_AMD64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _SCOPE_TABLE_AMD64(Count::DWORD, ScopeRecord::NTuple{1, __JL_Ctag_75})
    ref = Ref{_SCOPE_TABLE_AMD64}()
    ptr = Base.unsafe_convert(Ptr{_SCOPE_TABLE_AMD64}, ref)
    ptr.Count = Count
    ptr.ScopeRecord = ScopeRecord
    ref[]
end

const SCOPE_TABLE_AMD64 = _SCOPE_TABLE_AMD64

const PSCOPE_TABLE_AMD64 = Ptr{_SCOPE_TABLE_AMD64}

struct __JL_Ctag_47
    BeginAddress::DWORD
    EndAddress::DWORD
    HandlerAddress::DWORD
    JumpTarget::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_47}, f::Symbol)
    f === :BeginAddress && return Ptr{DWORD}(x + 0)
    f === :EndAddress && return Ptr{DWORD}(x + 4)
    f === :HandlerAddress && return Ptr{DWORD}(x + 8)
    f === :JumpTarget && return Ptr{DWORD}(x + 12)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_47, f::Symbol)
    r = Ref{__JL_Ctag_47}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_47}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_47}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct _SCOPE_TABLE_ARM
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_SCOPE_TABLE_ARM}, f::Symbol)
    f === :Count && return Ptr{DWORD}(x + 0)
    f === :ScopeRecord && return Ptr{NTuple{1, __JL_Ctag_47}}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_SCOPE_TABLE_ARM, f::Symbol)
    r = Ref{_SCOPE_TABLE_ARM}(x)
    ptr = Base.unsafe_convert(Ptr{_SCOPE_TABLE_ARM}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_SCOPE_TABLE_ARM}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _SCOPE_TABLE_ARM(Count::DWORD, ScopeRecord::NTuple{1, __JL_Ctag_47})
    ref = Ref{_SCOPE_TABLE_ARM}()
    ptr = Base.unsafe_convert(Ptr{_SCOPE_TABLE_ARM}, ref)
    ptr.Count = Count
    ptr.ScopeRecord = ScopeRecord
    ref[]
end

const SCOPE_TABLE_ARM = _SCOPE_TABLE_ARM

const PSCOPE_TABLE_ARM = Ptr{_SCOPE_TABLE_ARM}

struct __JL_Ctag_69
    BeginAddress::DWORD
    EndAddress::DWORD
    HandlerAddress::DWORD
    JumpTarget::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_69}, f::Symbol)
    f === :BeginAddress && return Ptr{DWORD}(x + 0)
    f === :EndAddress && return Ptr{DWORD}(x + 4)
    f === :HandlerAddress && return Ptr{DWORD}(x + 8)
    f === :JumpTarget && return Ptr{DWORD}(x + 12)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_69, f::Symbol)
    r = Ref{__JL_Ctag_69}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_69}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_69}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct _SCOPE_TABLE_ARM64
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_SCOPE_TABLE_ARM64}, f::Symbol)
    f === :Count && return Ptr{DWORD}(x + 0)
    f === :ScopeRecord && return Ptr{NTuple{1, __JL_Ctag_69}}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_SCOPE_TABLE_ARM64, f::Symbol)
    r = Ref{_SCOPE_TABLE_ARM64}(x)
    ptr = Base.unsafe_convert(Ptr{_SCOPE_TABLE_ARM64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_SCOPE_TABLE_ARM64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _SCOPE_TABLE_ARM64(Count::DWORD, ScopeRecord::NTuple{1, __JL_Ctag_69})
    ref = Ref{_SCOPE_TABLE_ARM64}()
    ptr = Base.unsafe_convert(Ptr{_SCOPE_TABLE_ARM64}, ref)
    ptr.Count = Count
    ptr.ScopeRecord = ScopeRecord
    ref[]
end

const SCOPE_TABLE_ARM64 = _SCOPE_TABLE_ARM64

const PSCOPE_TABLE_ARM64 = Ptr{_SCOPE_TABLE_ARM64}

struct _ARM64_NT_NEON128
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{_ARM64_NT_NEON128}, f::Symbol)
    f === :Low && return Ptr{ULONGLONG}(x + 0)
    f === :High && return Ptr{LONGLONG}(x + 8)
    f === :D && return Ptr{NTuple{2, Cdouble}}(x + 0)
    f === :S && return Ptr{NTuple{4, Cfloat}}(x + 0)
    f === :H && return Ptr{NTuple{8, WORD}}(x + 0)
    f === :B && return Ptr{NTuple{16, BYTE}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_ARM64_NT_NEON128, f::Symbol)
    r = Ref{_ARM64_NT_NEON128}(x)
    ptr = Base.unsafe_convert(Ptr{_ARM64_NT_NEON128}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_ARM64_NT_NEON128}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__ARM64_NT_NEON128 = Union{NTuple{2, Cdouble}, NTuple{4, Cfloat}, NTuple{8, WORD}, NTuple{16, BYTE}}

function _ARM64_NT_NEON128(val::__U__ARM64_NT_NEON128)
    ref = Ref{_ARM64_NT_NEON128}()
    ptr = Base.unsafe_convert(Ptr{_ARM64_NT_NEON128}, ref)
    if val isa NTuple{2, Cdouble}
        ptr.D = val
    elseif val isa NTuple{4, Cfloat}
        ptr.S = val
    elseif val isa NTuple{8, WORD}
        ptr.H = val
    elseif val isa NTuple{16, BYTE}
        ptr.B = val
    end
    ref[]
end

const ARM64_NT_NEON128 = _ARM64_NT_NEON128

const PARM64_NT_NEON128 = Ptr{_ARM64_NT_NEON128}

struct _ARM64_NT_CONTEXT
    data::NTuple{912, UInt8}
end

function Base.getproperty(x::Ptr{_ARM64_NT_CONTEXT}, f::Symbol)
    f === :ContextFlags && return Ptr{DWORD}(x + 0)
    f === :Cpsr && return Ptr{DWORD}(x + 4)
    f === :X0 && return Ptr{DWORD64}(x + 8)
    f === :X1 && return Ptr{DWORD64}(x + 16)
    f === :X2 && return Ptr{DWORD64}(x + 24)
    f === :X3 && return Ptr{DWORD64}(x + 32)
    f === :X4 && return Ptr{DWORD64}(x + 40)
    f === :X5 && return Ptr{DWORD64}(x + 48)
    f === :X6 && return Ptr{DWORD64}(x + 56)
    f === :X7 && return Ptr{DWORD64}(x + 64)
    f === :X8 && return Ptr{DWORD64}(x + 72)
    f === :X9 && return Ptr{DWORD64}(x + 80)
    f === :X10 && return Ptr{DWORD64}(x + 88)
    f === :X11 && return Ptr{DWORD64}(x + 96)
    f === :X12 && return Ptr{DWORD64}(x + 104)
    f === :X13 && return Ptr{DWORD64}(x + 112)
    f === :X14 && return Ptr{DWORD64}(x + 120)
    f === :X15 && return Ptr{DWORD64}(x + 128)
    f === :X16 && return Ptr{DWORD64}(x + 136)
    f === :X17 && return Ptr{DWORD64}(x + 144)
    f === :X18 && return Ptr{DWORD64}(x + 152)
    f === :X19 && return Ptr{DWORD64}(x + 160)
    f === :X20 && return Ptr{DWORD64}(x + 168)
    f === :X21 && return Ptr{DWORD64}(x + 176)
    f === :X22 && return Ptr{DWORD64}(x + 184)
    f === :X23 && return Ptr{DWORD64}(x + 192)
    f === :X24 && return Ptr{DWORD64}(x + 200)
    f === :X25 && return Ptr{DWORD64}(x + 208)
    f === :X26 && return Ptr{DWORD64}(x + 216)
    f === :X27 && return Ptr{DWORD64}(x + 224)
    f === :X28 && return Ptr{DWORD64}(x + 232)
    f === :Fp && return Ptr{DWORD64}(x + 240)
    f === :Lr && return Ptr{DWORD64}(x + 248)
    f === :X && return Ptr{NTuple{31, DWORD64}}(x + 8)
    f === :Sp && return Ptr{DWORD64}(x + 256)
    f === :Pc && return Ptr{DWORD64}(x + 264)
    f === :V && return Ptr{NTuple{32, ARM64_NT_NEON128}}(x + 272)
    f === :Fpcr && return Ptr{DWORD}(x + 784)
    f === :Fpsr && return Ptr{DWORD}(x + 788)
    f === :Bcr && return Ptr{NTuple{8, DWORD}}(x + 792)
    f === :Bvr && return Ptr{NTuple{8, DWORD64}}(x + 824)
    f === :Wcr && return Ptr{NTuple{2, DWORD}}(x + 888)
    f === :Wvr && return Ptr{NTuple{2, DWORD64}}(x + 896)
    return getfield(x, f)
end

function Base.getproperty(x::_ARM64_NT_CONTEXT, f::Symbol)
    r = Ref{_ARM64_NT_CONTEXT}(x)
    ptr = Base.unsafe_convert(Ptr{_ARM64_NT_CONTEXT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_ARM64_NT_CONTEXT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _ARM64_NT_CONTEXT(ContextFlags::DWORD, Cpsr::DWORD, Sp::DWORD64, Pc::DWORD64, V::NTuple{32, ARM64_NT_NEON128}, Fpcr::DWORD, Fpsr::DWORD, Bcr::NTuple{8, DWORD}, Bvr::NTuple{8, DWORD64}, Wcr::NTuple{2, DWORD}, Wvr::NTuple{2, DWORD64})
    ref = Ref{_ARM64_NT_CONTEXT}()
    ptr = Base.unsafe_convert(Ptr{_ARM64_NT_CONTEXT}, ref)
    ptr.ContextFlags = ContextFlags
    ptr.Cpsr = Cpsr
    ptr.Sp = Sp
    ptr.Pc = Pc
    ptr.V = V
    ptr.Fpcr = Fpcr
    ptr.Fpsr = Fpsr
    ptr.Bcr = Bcr
    ptr.Bvr = Bvr
    ptr.Wcr = Wcr
    ptr.Wvr = Wvr
    ref[]
end

const ARM64_NT_CONTEXT = _ARM64_NT_CONTEXT

const PARM64_NT_CONTEXT = Ptr{_ARM64_NT_CONTEXT}

struct _ARM64EC_NT_CONTEXT
    data::NTuple{1232, UInt8}
end

function Base.getproperty(x::Ptr{_ARM64EC_NT_CONTEXT}, f::Symbol)
    f === :AMD64_P1Home && return Ptr{DWORD64}(x + 0)
    f === :AMD64_P2Home && return Ptr{DWORD64}(x + 8)
    f === :AMD64_P3Home && return Ptr{DWORD64}(x + 16)
    f === :AMD64_P4Home && return Ptr{DWORD64}(x + 24)
    f === :AMD64_P5Home && return Ptr{DWORD64}(x + 32)
    f === :AMD64_P6Home && return Ptr{DWORD64}(x + 40)
    f === :ContextFlags && return Ptr{DWORD}(x + 48)
    f === :AMD64_MxCsr_copy && return Ptr{DWORD}(x + 52)
    f === :AMD64_SegCs && return Ptr{WORD}(x + 56)
    f === :AMD64_SegDs && return Ptr{WORD}(x + 58)
    f === :AMD64_SegEs && return Ptr{WORD}(x + 60)
    f === :AMD64_SegFs && return Ptr{WORD}(x + 62)
    f === :AMD64_SegGs && return Ptr{WORD}(x + 64)
    f === :AMD64_SegSs && return Ptr{WORD}(x + 66)
    f === :AMD64_EFlags && return Ptr{DWORD}(x + 68)
    f === :AMD64_Dr0 && return Ptr{DWORD64}(x + 72)
    f === :AMD64_Dr1 && return Ptr{DWORD64}(x + 80)
    f === :AMD64_Dr2 && return Ptr{DWORD64}(x + 88)
    f === :AMD64_Dr3 && return Ptr{DWORD64}(x + 96)
    f === :AMD64_Dr6 && return Ptr{DWORD64}(x + 104)
    f === :AMD64_Dr7 && return Ptr{DWORD64}(x + 112)
    f === :X8 && return Ptr{DWORD64}(x + 120)
    f === :X0 && return Ptr{DWORD64}(x + 128)
    f === :X1 && return Ptr{DWORD64}(x + 136)
    f === :X27 && return Ptr{DWORD64}(x + 144)
    f === :Sp && return Ptr{DWORD64}(x + 152)
    f === :Fp && return Ptr{DWORD64}(x + 160)
    f === :X25 && return Ptr{DWORD64}(x + 168)
    f === :X26 && return Ptr{DWORD64}(x + 176)
    f === :X2 && return Ptr{DWORD64}(x + 184)
    f === :X3 && return Ptr{DWORD64}(x + 192)
    f === :X4 && return Ptr{DWORD64}(x + 200)
    f === :X5 && return Ptr{DWORD64}(x + 208)
    f === :X19 && return Ptr{DWORD64}(x + 216)
    f === :X20 && return Ptr{DWORD64}(x + 224)
    f === :X21 && return Ptr{DWORD64}(x + 232)
    f === :X22 && return Ptr{DWORD64}(x + 240)
    f === :Pc && return Ptr{DWORD64}(x + 248)
    f === :AMD64_ControlWord && return Ptr{WORD}(x + 256)
    f === :AMD64_StatusWord && return Ptr{WORD}(x + 258)
    f === :AMD64_TagWord && return Ptr{BYTE}(x + 260)
    f === :AMD64_Reserved1 && return Ptr{BYTE}(x + 261)
    f === :AMD64_ErrorOpcode && return Ptr{WORD}(x + 262)
    f === :AMD64_ErrorOffset && return Ptr{DWORD}(x + 264)
    f === :AMD64_ErrorSelector && return Ptr{WORD}(x + 268)
    f === :AMD64_Reserved2 && return Ptr{WORD}(x + 270)
    f === :AMD64_DataOffset && return Ptr{DWORD}(x + 272)
    f === :AMD64_DataSelector && return Ptr{WORD}(x + 276)
    f === :AMD64_Reserved3 && return Ptr{WORD}(x + 278)
    f === :AMD64_MxCsr && return Ptr{DWORD}(x + 280)
    f === :AMD64_MxCsr_Mask && return Ptr{DWORD}(x + 284)
    f === :Lr && return Ptr{DWORD64}(x + 288)
    f === :X16_0 && return Ptr{WORD}(x + 296)
    f === :AMD64_St0_Reserved1 && return Ptr{WORD}(x + 298)
    f === :AMD64_St0_Reserved2 && return Ptr{DWORD}(x + 300)
    f === :X6 && return Ptr{DWORD64}(x + 304)
    f === :X16_1 && return Ptr{WORD}(x + 312)
    f === :AMD64_St1_Reserved1 && return Ptr{WORD}(x + 314)
    f === :AMD64_St1_Reserved2 && return Ptr{DWORD}(x + 316)
    f === :X7 && return Ptr{DWORD64}(x + 320)
    f === :X16_2 && return Ptr{WORD}(x + 328)
    f === :AMD64_St2_Reserved1 && return Ptr{WORD}(x + 330)
    f === :AMD64_St2_Reserved2 && return Ptr{DWORD}(x + 332)
    f === :X9 && return Ptr{DWORD64}(x + 336)
    f === :X16_3 && return Ptr{WORD}(x + 344)
    f === :AMD64_St3_Reserved1 && return Ptr{WORD}(x + 346)
    f === :AMD64_St3_Reserved2 && return Ptr{DWORD}(x + 348)
    f === :X10 && return Ptr{DWORD64}(x + 352)
    f === :X17_0 && return Ptr{WORD}(x + 360)
    f === :AMD64_St4_Reserved1 && return Ptr{WORD}(x + 362)
    f === :AMD64_St4_Reserved2 && return Ptr{DWORD}(x + 364)
    f === :X11 && return Ptr{DWORD64}(x + 368)
    f === :X17_1 && return Ptr{WORD}(x + 376)
    f === :AMD64_St5_Reserved1 && return Ptr{WORD}(x + 378)
    f === :AMD64_St5_Reserved2 && return Ptr{DWORD}(x + 380)
    f === :X12 && return Ptr{DWORD64}(x + 384)
    f === :X17_2 && return Ptr{WORD}(x + 392)
    f === :AMD64_St6_Reserved1 && return Ptr{WORD}(x + 394)
    f === :AMD64_St6_Reserved2 && return Ptr{DWORD}(x + 396)
    f === :X15 && return Ptr{DWORD64}(x + 400)
    f === :X17_3 && return Ptr{WORD}(x + 408)
    f === :AMD64_St7_Reserved1 && return Ptr{WORD}(x + 410)
    f === :AMD64_St7_Reserved2 && return Ptr{DWORD}(x + 412)
    f === :V && return Ptr{NTuple{16, ARM64_NT_NEON128}}(x + 416)
    f === :AMD64_XSAVE_FORMAT_Reserved4 && return Ptr{NTuple{96, BYTE}}(x + 672)
    f === :AMD64_VectorRegister && return Ptr{NTuple{26, ARM64_NT_NEON128}}(x + 768)
    f === :AMD64_VectorControl && return Ptr{DWORD64}(x + 1184)
    f === :AMD64_DebugControl && return Ptr{DWORD64}(x + 1192)
    f === :AMD64_LastBranchToRip && return Ptr{DWORD64}(x + 1200)
    f === :AMD64_LastBranchFromRip && return Ptr{DWORD64}(x + 1208)
    f === :AMD64_LastExceptionToRip && return Ptr{DWORD64}(x + 1216)
    f === :AMD64_LastExceptionFromRip && return Ptr{DWORD64}(x + 1224)
    return getfield(x, f)
end

function Base.getproperty(x::_ARM64EC_NT_CONTEXT, f::Symbol)
    r = Ref{_ARM64EC_NT_CONTEXT}(x)
    ptr = Base.unsafe_convert(Ptr{_ARM64EC_NT_CONTEXT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_ARM64EC_NT_CONTEXT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _ARM64EC_NT_CONTEXT()
    ref = Ref{_ARM64EC_NT_CONTEXT}()
    ptr = Base.unsafe_convert(Ptr{_ARM64EC_NT_CONTEXT}, ref)
    ref[]
end

const ARM64EC_NT_CONTEXT = _ARM64EC_NT_CONTEXT

const PARM64EC_NT_CONTEXT = Ptr{_ARM64EC_NT_CONTEXT}

struct _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY}, f::Symbol)
    f === :BeginAddress && return Ptr{DWORD}(x + 0)
    f === :UnwindData && return Ptr{DWORD}(x + 4)
    f === :Flag && return (Ptr{DWORD}(x + 4), 0, 2)
    f === :FunctionLength && return (Ptr{DWORD}(x + 4), 2, 11)
    f === :RegF && return (Ptr{DWORD}(x + 4), 13, 3)
    f === :RegI && return (Ptr{DWORD}(x + 4), 16, 4)
    f === :H && return (Ptr{DWORD}(x + 4), 20, 1)
    f === :CR && return (Ptr{DWORD}(x + 4), 21, 2)
    f === :FrameSize && return (Ptr{DWORD}(x + 4), 23, 9)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY, f::Symbol)
    r = Ref{_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY(BeginAddress::DWORD)
    ref = Ref{_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY}, ref)
    ptr.BeginAddress = BeginAddress
    ref[]
end

const ARM64_RUNTIME_FUNCTION = _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY

const PARM64_RUNTIME_FUNCTION = Ptr{_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY}

struct _DISPATCHER_CONTEXT_NONVOLREG_ARM64
    data::NTuple{152, UInt8}
end

function Base.getproperty(x::Ptr{_DISPATCHER_CONTEXT_NONVOLREG_ARM64}, f::Symbol)
    f === :Buffer && return Ptr{NTuple{152, BYTE}}(x + 0)
    f === :GpNvRegs && return Ptr{NTuple{11, DWORD64}}(x + 0)
    f === :FpNvRegs && return Ptr{NTuple{8, Cdouble}}(x + 88)
    return getfield(x, f)
end

function Base.getproperty(x::_DISPATCHER_CONTEXT_NONVOLREG_ARM64, f::Symbol)
    r = Ref{_DISPATCHER_CONTEXT_NONVOLREG_ARM64}(x)
    ptr = Base.unsafe_convert(Ptr{_DISPATCHER_CONTEXT_NONVOLREG_ARM64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_DISPATCHER_CONTEXT_NONVOLREG_ARM64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__DISPATCHER_CONTEXT_NONVOLREG_ARM64 = Union{NTuple{152, BYTE}}

function _DISPATCHER_CONTEXT_NONVOLREG_ARM64(val::__U__DISPATCHER_CONTEXT_NONVOLREG_ARM64)
    ref = Ref{_DISPATCHER_CONTEXT_NONVOLREG_ARM64}()
    ptr = Base.unsafe_convert(Ptr{_DISPATCHER_CONTEXT_NONVOLREG_ARM64}, ref)
    if val isa NTuple{152, BYTE}
        ptr.Buffer = val
    end
    ref[]
end

const DISPATCHER_CONTEXT_NONVOLREG_ARM64 = _DISPATCHER_CONTEXT_NONVOLREG_ARM64

const _UNWIND_HISTORY_TABLE = Cvoid

struct _DISPATCHER_CONTEXT_ARM64
    ControlPc::ULONG_PTR
    ImageBase::ULONG_PTR
    FunctionEntry::PARM64_RUNTIME_FUNCTION
    EstablisherFrame::ULONG_PTR
    TargetPc::ULONG_PTR
    ContextRecord::PARM64_NT_CONTEXT
    LanguageHandler::PEXCEPTION_ROUTINE
    HandlerData::PVOID
    HistoryTable::Ptr{_UNWIND_HISTORY_TABLE}
    ScopeIndex::DWORD
    ControlPcIsUnwound::BOOLEAN
    NonVolatileRegisters::PBYTE
end

const DISPATCHER_CONTEXT_ARM64 = _DISPATCHER_CONTEXT_ARM64

const PDISPATCHER_CONTEXT_ARM64 = Ptr{_DISPATCHER_CONTEXT_ARM64}

struct _KNONVOLATILE_CONTEXT_POINTERS_ARM64
    X19::PDWORD64
    X20::PDWORD64
    X21::PDWORD64
    X22::PDWORD64
    X23::PDWORD64
    X24::PDWORD64
    X25::PDWORD64
    X26::PDWORD64
    X27::PDWORD64
    X28::PDWORD64
    Fp::PDWORD64
    Lr::PDWORD64
    D8::PDWORD64
    D9::PDWORD64
    D10::PDWORD64
    D11::PDWORD64
    D12::PDWORD64
    D13::PDWORD64
    D14::PDWORD64
    D15::PDWORD64
end

const KNONVOLATILE_CONTEXT_POINTERS_ARM64 = _KNONVOLATILE_CONTEXT_POINTERS_ARM64

const PKNONVOLATILE_CONTEXT_POINTERS_ARM64 = Ptr{_KNONVOLATILE_CONTEXT_POINTERS_ARM64}

struct __JL_Ctag_83
    BaseMid::BYTE
    Flags1::BYTE
    Flags2::BYTE
    BaseHi::BYTE
end
function Base.getproperty(x::Ptr{__JL_Ctag_83}, f::Symbol)
    f === :BaseMid && return Ptr{BYTE}(x + 0)
    f === :Flags1 && return Ptr{BYTE}(x + 1)
    f === :Flags2 && return Ptr{BYTE}(x + 2)
    f === :BaseHi && return Ptr{BYTE}(x + 3)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_83, f::Symbol)
    r = Ref{__JL_Ctag_83}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_83}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_83}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_84
    BaseMid::DWORD
    Type::DWORD
    Dpl::DWORD
    Pres::DWORD
    LimitHi::DWORD
    Sys::DWORD
    Reserved_0::DWORD
    Default_Big::DWORD
    Granularity::DWORD
    BaseHi::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_84}, f::Symbol)
    f === :BaseMid && return (Ptr{DWORD}(x + 0), 0, 8)
    f === :Type && return (Ptr{DWORD}(x + 0), 8, 5)
    f === :Dpl && return (Ptr{DWORD}(x + 0), 13, 2)
    f === :Pres && return (Ptr{DWORD}(x + 0), 15, 1)
    f === :LimitHi && return (Ptr{DWORD}(x + 0), 16, 4)
    f === :Sys && return (Ptr{DWORD}(x + 0), 20, 1)
    f === :Reserved_0 && return (Ptr{DWORD}(x + 0), 21, 1)
    f === :Default_Big && return (Ptr{DWORD}(x + 0), 22, 1)
    f === :Granularity && return (Ptr{DWORD}(x + 0), 23, 1)
    f === :BaseHi && return (Ptr{DWORD}(x + 0), 24, 8)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_84, f::Symbol)
    r = Ref{__JL_Ctag_84}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_84}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_84}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_82
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_82}, f::Symbol)
    f === :Bytes && return Ptr{__JL_Ctag_83}(x + 0)
    f === :Bits && return Ptr{__JL_Ctag_84}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_82, f::Symbol)
    r = Ref{__JL_Ctag_82}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_82}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_82}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_82 = Union{__JL_Ctag_83, __JL_Ctag_84}

function __JL_Ctag_82(val::__U___JL_Ctag_82)
    ref = Ref{__JL_Ctag_82}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_82}, ref)
    if val isa __JL_Ctag_83
        ptr.Bytes = val
    elseif val isa __JL_Ctag_84
        ptr.Bits = val
    end
    ref[]
end

struct _LDT_ENTRY
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_LDT_ENTRY}, f::Symbol)
    f === :LimitLow && return Ptr{WORD}(x + 0)
    f === :BaseLow && return Ptr{WORD}(x + 2)
    f === :HighWord && return Ptr{__JL_Ctag_82}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_LDT_ENTRY, f::Symbol)
    r = Ref{_LDT_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_LDT_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_LDT_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _LDT_ENTRY(LimitLow::WORD, BaseLow::WORD, HighWord::__JL_Ctag_82)
    ref = Ref{_LDT_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_LDT_ENTRY}, ref)
    ptr.LimitLow = LimitLow
    ptr.BaseLow = BaseLow
    ptr.HighWord = HighWord
    ref[]
end

const LDT_ENTRY = _LDT_ENTRY

const PLDT_ENTRY = Ptr{_LDT_ENTRY}

function ReadAcquire8(CHAR_)
    @ccall user32.ReadAcquire8(CHAR_::Cint)::CHAR
end

function ReadNoFence8(CHAR_)
    @ccall user32.ReadNoFence8(CHAR_::Cint)::CHAR
end

function WriteRelease8(CHAR_)
    @ccall user32.WriteRelease8(CHAR_::Cint)::Cvoid
end

function WriteNoFence8(CHAR_)
    @ccall user32.WriteNoFence8(CHAR_::Cint)::Cvoid
end

function ReadAcquire16(SHORT_)
    @ccall user32.ReadAcquire16(SHORT_::Cint)::SHORT
end

function ReadNoFence16(SHORT_)
    @ccall user32.ReadNoFence16(SHORT_::Cint)::SHORT
end

function WriteRelease16(SHORT_)
    @ccall user32.WriteRelease16(SHORT_::Cint)::Cvoid
end

function WriteNoFence16(SHORT_)
    @ccall user32.WriteNoFence16(SHORT_::Cint)::Cvoid
end

function ReadAcquire(LONG_)
    @ccall user32.ReadAcquire(LONG_::Cint)::LONG
end

function ReadNoFence(LONG_)
    @ccall user32.ReadNoFence(LONG_::Cint)::LONG
end

function WriteRelease(LONG_)
    @ccall user32.WriteRelease(LONG_::Cint)::Cvoid
end

function WriteNoFence(LONG_)
    @ccall user32.WriteNoFence(LONG_::Cint)::Cvoid
end

function BarrierAfterRead()
    @ccall user32.BarrierAfterRead()::Cvoid
end

function ReadRaw8(CHAR_)
    @ccall user32.ReadRaw8(CHAR_::Cint)::CHAR
end

function WriteRaw8(CHAR_)
    @ccall user32.WriteRaw8(CHAR_::Cint)::Cvoid
end

function ReadRaw16(SHORT_)
    @ccall user32.ReadRaw16(SHORT_::Cint)::SHORT
end

function WriteRaw16(SHORT_)
    @ccall user32.WriteRaw16(SHORT_::Cint)::Cvoid
end

function ReadRaw(LONG_)
    @ccall user32.ReadRaw(LONG_::Cint)::LONG
end

function WriteRaw(LONG_)
    @ccall user32.WriteRaw(LONG_::Cint)::Cvoid
end

function ReadUCharAcquire(BYTE_)
    @ccall user32.ReadUCharAcquire(BYTE_::Cint)::BYTE
end

function ReadUCharNoFence(BYTE_)
    @ccall user32.ReadUCharNoFence(BYTE_::Cint)::BYTE
end

function ReadBooleanAcquire(BOOLEAN_)
    @ccall user32.ReadBooleanAcquire(BOOLEAN_::Cint)::BYTE
end

function ReadBooleanNoFence(BOOLEAN_)
    @ccall user32.ReadBooleanNoFence(BOOLEAN_::Cint)::BYTE
end

function ReadBooleanRaw(BOOLEAN_)
    @ccall user32.ReadBooleanRaw(BOOLEAN_::Cint)::BYTE
end

function ReadUCharRaw(BYTE_)
    @ccall user32.ReadUCharRaw(BYTE_::Cint)::BYTE
end

function WriteUCharRelease(BYTE_)
    @ccall user32.WriteUCharRelease(BYTE_::Cint)::Cvoid
end

function WriteUCharNoFence(BYTE_)
    @ccall user32.WriteUCharNoFence(BYTE_::Cint)::Cvoid
end

function WriteBooleanRelease(BOOLEAN_)
    @ccall user32.WriteBooleanRelease(BOOLEAN_::Cint)::Cvoid
end

function WriteBooleanNoFence(BOOLEAN_)
    @ccall user32.WriteBooleanNoFence(BOOLEAN_::Cint)::Cvoid
end

function WriteUCharRaw(BYTE_)
    @ccall user32.WriteUCharRaw(BYTE_::Cint)::Cvoid
end

function ReadUShortAcquire(WORD_)
    @ccall user32.ReadUShortAcquire(WORD_::Cint)::WORD
end

function ReadUShortNoFence(WORD_)
    @ccall user32.ReadUShortNoFence(WORD_::Cint)::WORD
end

function ReadUShortRaw(WORD_)
    @ccall user32.ReadUShortRaw(WORD_::Cint)::WORD
end

function WriteUShortRelease(WORD_)
    @ccall user32.WriteUShortRelease(WORD_::Cint)::Cvoid
end

function WriteUShortNoFence(WORD_)
    @ccall user32.WriteUShortNoFence(WORD_::Cint)::Cvoid
end

function WriteUShortRaw(WORD_)
    @ccall user32.WriteUShortRaw(WORD_::Cint)::Cvoid
end

function ReadULongAcquire(DWORD_)
    @ccall user32.ReadULongAcquire(DWORD_::Cint)::DWORD
end

function ReadULongNoFence(DWORD_)
    @ccall user32.ReadULongNoFence(DWORD_::Cint)::DWORD
end

function ReadULongRaw(DWORD_)
    @ccall user32.ReadULongRaw(DWORD_::Cint)::DWORD
end

function WriteULongRelease(DWORD_)
    @ccall user32.WriteULongRelease(DWORD_::Cint)::Cvoid
end

function WriteULongNoFence(DWORD_)
    @ccall user32.WriteULongNoFence(DWORD_::Cint)::Cvoid
end

function WriteULongRaw(DWORD_)
    @ccall user32.WriteULongRaw(DWORD_::Cint)::Cvoid
end

function ReadInt32Acquire(INT32_)
    @ccall user32.ReadInt32Acquire(INT32_::Cint)::INT32
end

function ReadInt32NoFence(INT32_)
    @ccall user32.ReadInt32NoFence(INT32_::Cint)::INT32
end

function ReadInt32Raw(INT32_)
    @ccall user32.ReadInt32Raw(INT32_::Cint)::INT32
end

function WriteInt32Release(INT32_)
    @ccall user32.WriteInt32Release(INT32_::Cint)::Cvoid
end

function WriteInt32NoFence(INT32_)
    @ccall user32.WriteInt32NoFence(INT32_::Cint)::Cvoid
end

function WriteInt32Raw(INT32_)
    @ccall user32.WriteInt32Raw(INT32_::Cint)::Cvoid
end

function ReadUInt32Acquire(UINT32_)
    @ccall user32.ReadUInt32Acquire(UINT32_::Cint)::UINT32
end

function ReadUInt32NoFence(UINT32_)
    @ccall user32.ReadUInt32NoFence(UINT32_::Cint)::UINT32
end

function ReadUInt32Raw(UINT32_)
    @ccall user32.ReadUInt32Raw(UINT32_::Cint)::UINT32
end

function WriteUInt32Release(UINT32_)
    @ccall user32.WriteUInt32Release(UINT32_::Cint)::Cvoid
end

function WriteUInt32NoFence(UINT32_)
    @ccall user32.WriteUInt32NoFence(UINT32_::Cint)::Cvoid
end

function WriteUInt32Raw(UINT32_)
    @ccall user32.WriteUInt32Raw(UINT32_::Cint)::Cvoid
end

function ReadPointerAcquire(PVOID_)
    @ccall user32.ReadPointerAcquire(PVOID_::Cint)::PVOID
end

function ReadPointerNoFence(PVOID_)
    @ccall user32.ReadPointerNoFence(PVOID_::Cint)::PVOID
end

function ReadPointerRaw(PVOID_)
    @ccall user32.ReadPointerRaw(PVOID_::Cint)::PVOID
end

function WritePointerRelease(PVOID_)
    @ccall user32.WritePointerRelease(PVOID_::Cint)::Cvoid
end

function WritePointerNoFence(PVOID_)
    @ccall user32.WritePointerNoFence(PVOID_::Cint)::Cvoid
end

function WritePointerRaw(PVOID_)
    @ccall user32.WritePointerRaw(PVOID_::Cint)::Cvoid
end

struct _WOW64_FLOATING_SAVE_AREA
    ControlWord::DWORD
    StatusWord::DWORD
    TagWord::DWORD
    ErrorOffset::DWORD
    ErrorSelector::DWORD
    DataOffset::DWORD
    DataSelector::DWORD
    RegisterArea::NTuple{80, BYTE}
    Cr0NpxState::DWORD
end

const WOW64_FLOATING_SAVE_AREA = _WOW64_FLOATING_SAVE_AREA

const PWOW64_FLOATING_SAVE_AREA = Ptr{WOW64_FLOATING_SAVE_AREA}

struct _WOW64_CONTEXT
    data::NTuple{716, UInt8}
end

function Base.getproperty(x::Ptr{_WOW64_CONTEXT}, f::Symbol)
    f === :ContextFlags && return Ptr{DWORD}(x + 0)
    f === :Dr0 && return Ptr{DWORD}(x + 4)
    f === :Dr1 && return Ptr{DWORD}(x + 8)
    f === :Dr2 && return Ptr{DWORD}(x + 12)
    f === :Dr3 && return Ptr{DWORD}(x + 16)
    f === :Dr6 && return Ptr{DWORD}(x + 20)
    f === :Dr7 && return Ptr{DWORD}(x + 24)
    f === :FloatSave && return Ptr{WOW64_FLOATING_SAVE_AREA}(x + 28)
    f === :SegGs && return Ptr{DWORD}(x + 140)
    f === :SegFs && return Ptr{DWORD}(x + 144)
    f === :SegEs && return Ptr{DWORD}(x + 148)
    f === :SegDs && return Ptr{DWORD}(x + 152)
    f === :Edi && return Ptr{DWORD}(x + 156)
    f === :Esi && return Ptr{DWORD}(x + 160)
    f === :Ebx && return Ptr{DWORD}(x + 164)
    f === :Edx && return Ptr{DWORD}(x + 168)
    f === :Ecx && return Ptr{DWORD}(x + 172)
    f === :Eax && return Ptr{DWORD}(x + 176)
    f === :Ebp && return Ptr{DWORD}(x + 180)
    f === :Eip && return Ptr{DWORD}(x + 184)
    f === :SegCs && return Ptr{DWORD}(x + 188)
    f === :EFlags && return Ptr{DWORD}(x + 192)
    f === :Esp && return Ptr{DWORD}(x + 196)
    f === :SegSs && return Ptr{DWORD}(x + 200)
    f === :ExtendedRegisters && return Ptr{NTuple{512, BYTE}}(x + 204)
    return getfield(x, f)
end

function Base.getproperty(x::_WOW64_CONTEXT, f::Symbol)
    r = Ref{_WOW64_CONTEXT}(x)
    ptr = Base.unsafe_convert(Ptr{_WOW64_CONTEXT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_WOW64_CONTEXT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _WOW64_CONTEXT(ContextFlags::DWORD, Dr0::DWORD, Dr1::DWORD, Dr2::DWORD, Dr3::DWORD, Dr6::DWORD, Dr7::DWORD, FloatSave::WOW64_FLOATING_SAVE_AREA, SegGs::DWORD, SegFs::DWORD, SegEs::DWORD, SegDs::DWORD, Edi::DWORD, Esi::DWORD, Ebx::DWORD, Edx::DWORD, Ecx::DWORD, Eax::DWORD, Ebp::DWORD, Eip::DWORD, SegCs::DWORD, EFlags::DWORD, Esp::DWORD, SegSs::DWORD, ExtendedRegisters::NTuple{512, BYTE})
    ref = Ref{_WOW64_CONTEXT}()
    ptr = Base.unsafe_convert(Ptr{_WOW64_CONTEXT}, ref)
    ptr.ContextFlags = ContextFlags
    ptr.Dr0 = Dr0
    ptr.Dr1 = Dr1
    ptr.Dr2 = Dr2
    ptr.Dr3 = Dr3
    ptr.Dr6 = Dr6
    ptr.Dr7 = Dr7
    ptr.FloatSave = FloatSave
    ptr.SegGs = SegGs
    ptr.SegFs = SegFs
    ptr.SegEs = SegEs
    ptr.SegDs = SegDs
    ptr.Edi = Edi
    ptr.Esi = Esi
    ptr.Ebx = Ebx
    ptr.Edx = Edx
    ptr.Ecx = Ecx
    ptr.Eax = Eax
    ptr.Ebp = Ebp
    ptr.Eip = Eip
    ptr.SegCs = SegCs
    ptr.EFlags = EFlags
    ptr.Esp = Esp
    ptr.SegSs = SegSs
    ptr.ExtendedRegisters = ExtendedRegisters
    ref[]
end

const WOW64_CONTEXT = _WOW64_CONTEXT

const PWOW64_CONTEXT = Ptr{WOW64_CONTEXT}

struct __JL_Ctag_63
    BaseMid::BYTE
    Flags1::BYTE
    Flags2::BYTE
    BaseHi::BYTE
end
function Base.getproperty(x::Ptr{__JL_Ctag_63}, f::Symbol)
    f === :BaseMid && return Ptr{BYTE}(x + 0)
    f === :Flags1 && return Ptr{BYTE}(x + 1)
    f === :Flags2 && return Ptr{BYTE}(x + 2)
    f === :BaseHi && return Ptr{BYTE}(x + 3)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_63, f::Symbol)
    r = Ref{__JL_Ctag_63}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_63}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_63}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_64
    BaseMid::DWORD
    Type::DWORD
    Dpl::DWORD
    Pres::DWORD
    LimitHi::DWORD
    Sys::DWORD
    Reserved_0::DWORD
    Default_Big::DWORD
    Granularity::DWORD
    BaseHi::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_64}, f::Symbol)
    f === :BaseMid && return (Ptr{DWORD}(x + 0), 0, 8)
    f === :Type && return (Ptr{DWORD}(x + 0), 8, 5)
    f === :Dpl && return (Ptr{DWORD}(x + 0), 13, 2)
    f === :Pres && return (Ptr{DWORD}(x + 0), 15, 1)
    f === :LimitHi && return (Ptr{DWORD}(x + 0), 16, 4)
    f === :Sys && return (Ptr{DWORD}(x + 0), 20, 1)
    f === :Reserved_0 && return (Ptr{DWORD}(x + 0), 21, 1)
    f === :Default_Big && return (Ptr{DWORD}(x + 0), 22, 1)
    f === :Granularity && return (Ptr{DWORD}(x + 0), 23, 1)
    f === :BaseHi && return (Ptr{DWORD}(x + 0), 24, 8)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_64, f::Symbol)
    r = Ref{__JL_Ctag_64}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_62
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_62}, f::Symbol)
    f === :Bytes && return Ptr{__JL_Ctag_63}(x + 0)
    f === :Bits && return Ptr{__JL_Ctag_64}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_62, f::Symbol)
    r = Ref{__JL_Ctag_62}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_62}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_62}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_62 = Union{__JL_Ctag_63, __JL_Ctag_64}

function __JL_Ctag_62(val::__U___JL_Ctag_62)
    ref = Ref{__JL_Ctag_62}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_62}, ref)
    if val isa __JL_Ctag_63
        ptr.Bytes = val
    elseif val isa __JL_Ctag_64
        ptr.Bits = val
    end
    ref[]
end

struct _WOW64_LDT_ENTRY
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_WOW64_LDT_ENTRY}, f::Symbol)
    f === :LimitLow && return Ptr{WORD}(x + 0)
    f === :BaseLow && return Ptr{WORD}(x + 2)
    f === :HighWord && return Ptr{__JL_Ctag_62}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_WOW64_LDT_ENTRY, f::Symbol)
    r = Ref{_WOW64_LDT_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_WOW64_LDT_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_WOW64_LDT_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _WOW64_LDT_ENTRY(LimitLow::WORD, BaseLow::WORD, HighWord::__JL_Ctag_62)
    ref = Ref{_WOW64_LDT_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_WOW64_LDT_ENTRY}, ref)
    ptr.LimitLow = LimitLow
    ptr.BaseLow = BaseLow
    ptr.HighWord = HighWord
    ref[]
end

const WOW64_LDT_ENTRY = _WOW64_LDT_ENTRY

const PWOW64_LDT_ENTRY = Ptr{_WOW64_LDT_ENTRY}

struct _WOW64_DESCRIPTOR_TABLE_ENTRY
    Selector::DWORD
    Descriptor::WOW64_LDT_ENTRY
end

const WOW64_DESCRIPTOR_TABLE_ENTRY = _WOW64_DESCRIPTOR_TABLE_ENTRY

const PWOW64_DESCRIPTOR_TABLE_ENTRY = Ptr{_WOW64_DESCRIPTOR_TABLE_ENTRY}

struct _EXCEPTION_RECORD
    ExceptionCode::DWORD
    ExceptionFlags::DWORD
    ExceptionRecord::Ptr{_EXCEPTION_RECORD}
    ExceptionAddress::PVOID
    NumberParameters::DWORD
    ExceptionInformation::NTuple{15, ULONG_PTR}
end

const EXCEPTION_RECORD = _EXCEPTION_RECORD

const PEXCEPTION_RECORD = Ptr{EXCEPTION_RECORD}

struct _EXCEPTION_RECORD32
    ExceptionCode::DWORD
    ExceptionFlags::DWORD
    ExceptionRecord::DWORD
    ExceptionAddress::DWORD
    NumberParameters::DWORD
    ExceptionInformation::NTuple{15, DWORD}
end

const EXCEPTION_RECORD32 = _EXCEPTION_RECORD32

const PEXCEPTION_RECORD32 = Ptr{_EXCEPTION_RECORD32}

struct _EXCEPTION_RECORD64
    ExceptionCode::DWORD
    ExceptionFlags::DWORD
    ExceptionRecord::DWORD64
    ExceptionAddress::DWORD64
    NumberParameters::DWORD
    __unusedAlignment::DWORD
    ExceptionInformation::NTuple{15, DWORD64}
end

const EXCEPTION_RECORD64 = _EXCEPTION_RECORD64

const PEXCEPTION_RECORD64 = Ptr{_EXCEPTION_RECORD64}

struct _EXCEPTION_POINTERS
    ExceptionRecord::PEXCEPTION_RECORD
    ContextRecord::Cint
end

const EXCEPTION_POINTERS = _EXCEPTION_POINTERS

const PEXCEPTION_POINTERS = Ptr{_EXCEPTION_POINTERS}

const PACCESS_TOKEN = PVOID

const PSECURITY_DESCRIPTOR = PVOID

const PCLAIMS_BLOB = PVOID

const PACCESS_MASK = Ptr{ACCESS_MASK}

struct _GENERIC_MAPPING
    GenericRead::ACCESS_MASK
    GenericWrite::ACCESS_MASK
    GenericExecute::ACCESS_MASK
    GenericAll::ACCESS_MASK
end

const GENERIC_MAPPING = _GENERIC_MAPPING

const PGENERIC_MAPPING = Ptr{GENERIC_MAPPING}

struct _LUID_AND_ATTRIBUTES
    data::NTuple{12, UInt8}
end

function Base.getproperty(x::Ptr{_LUID_AND_ATTRIBUTES}, f::Symbol)
    f === :Luid && return Ptr{LUID}(x + 0)
    f === :Attributes && return Ptr{DWORD}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_LUID_AND_ATTRIBUTES, f::Symbol)
    r = Ref{_LUID_AND_ATTRIBUTES}(x)
    ptr = Base.unsafe_convert(Ptr{_LUID_AND_ATTRIBUTES}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_LUID_AND_ATTRIBUTES}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _LUID_AND_ATTRIBUTES(Luid::LUID, Attributes::DWORD)
    ref = Ref{_LUID_AND_ATTRIBUTES}()
    ptr = Base.unsafe_convert(Ptr{_LUID_AND_ATTRIBUTES}, ref)
    ptr.Luid = Luid
    ptr.Attributes = Attributes
    ref[]
end

const LUID_AND_ATTRIBUTES = _LUID_AND_ATTRIBUTES

const PLUID_AND_ATTRIBUTES = Ptr{_LUID_AND_ATTRIBUTES}

const LUID_AND_ATTRIBUTES_ARRAY = NTuple{1, LUID_AND_ATTRIBUTES}

const PLUID_AND_ATTRIBUTES_ARRAY = Ptr{LUID_AND_ATTRIBUTES_ARRAY}

const PSID_IDENTIFIER_AUTHORITY = Ptr{_SID_IDENTIFIER_AUTHORITY}

const PISID = Ptr{_SID}

struct _SE_SID
    data::NTuple{68, UInt8}
end

function Base.getproperty(x::Ptr{_SE_SID}, f::Symbol)
    f === :Sid && return Ptr{SID}(x + 0)
    f === :Buffer && return Ptr{NTuple{68, BYTE}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_SE_SID, f::Symbol)
    r = Ref{_SE_SID}(x)
    ptr = Base.unsafe_convert(Ptr{_SE_SID}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_SE_SID}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__SE_SID = Union{SID, NTuple{68, BYTE}}

function _SE_SID(val::__U__SE_SID)
    ref = Ref{_SE_SID}()
    ptr = Base.unsafe_convert(Ptr{_SE_SID}, ref)
    if val isa SID
        ptr.Sid = val
    elseif val isa NTuple{68, BYTE}
        ptr.Buffer = val
    end
    ref[]
end

const SE_SID = _SE_SID

const PSE_SID = Ptr{_SE_SID}

@cenum _SID_NAME_USE::UInt32 begin
    SidTypeUser = 1
    SidTypeGroup = 2
    SidTypeDomain = 3
    SidTypeAlias = 4
    SidTypeWellKnownGroup = 5
    SidTypeDeletedAccount = 6
    SidTypeInvalid = 7
    SidTypeUnknown = 8
    SidTypeComputer = 9
    SidTypeLabel = 10
    SidTypeLogonSession = 11
end

const SID_NAME_USE = _SID_NAME_USE

const PSID_NAME_USE = Ptr{_SID_NAME_USE}

const PSID_AND_ATTRIBUTES = Ptr{_SID_AND_ATTRIBUTES}

const SID_AND_ATTRIBUTES_ARRAY = NTuple{1, SID_AND_ATTRIBUTES}

const PSID_AND_ATTRIBUTES_ARRAY = Ptr{SID_AND_ATTRIBUTES_ARRAY}

const SID_HASH_ENTRY = ULONG_PTR

const PSID_HASH_ENTRY = Ptr{ULONG_PTR}

struct _SID_AND_ATTRIBUTES_HASH
    SidCount::DWORD
    SidAttr::PSID_AND_ATTRIBUTES
    Hash::NTuple{32, SID_HASH_ENTRY}
end

const SID_AND_ATTRIBUTES_HASH = _SID_AND_ATTRIBUTES_HASH

const PSID_AND_ATTRIBUTES_HASH = Ptr{_SID_AND_ATTRIBUTES_HASH}

@cenum WELL_KNOWN_SID_TYPE::UInt32 begin
    WinNullSid = 0
    WinWorldSid = 1
    WinLocalSid = 2
    WinCreatorOwnerSid = 3
    WinCreatorGroupSid = 4
    WinCreatorOwnerServerSid = 5
    WinCreatorGroupServerSid = 6
    WinNtAuthoritySid = 7
    WinDialupSid = 8
    WinNetworkSid = 9
    WinBatchSid = 10
    WinInteractiveSid = 11
    WinServiceSid = 12
    WinAnonymousSid = 13
    WinProxySid = 14
    WinEnterpriseControllersSid = 15
    WinSelfSid = 16
    WinAuthenticatedUserSid = 17
    WinRestrictedCodeSid = 18
    WinTerminalServerSid = 19
    WinRemoteLogonIdSid = 20
    WinLogonIdsSid = 21
    WinLocalSystemSid = 22
    WinLocalServiceSid = 23
    WinNetworkServiceSid = 24
    WinBuiltinDomainSid = 25
    WinBuiltinAdministratorsSid = 26
    WinBuiltinUsersSid = 27
    WinBuiltinGuestsSid = 28
    WinBuiltinPowerUsersSid = 29
    WinBuiltinAccountOperatorsSid = 30
    WinBuiltinSystemOperatorsSid = 31
    WinBuiltinPrintOperatorsSid = 32
    WinBuiltinBackupOperatorsSid = 33
    WinBuiltinReplicatorSid = 34
    WinBuiltinPreWindows2000CompatibleAccessSid = 35
    WinBuiltinRemoteDesktopUsersSid = 36
    WinBuiltinNetworkConfigurationOperatorsSid = 37
    WinAccountAdministratorSid = 38
    WinAccountGuestSid = 39
    WinAccountKrbtgtSid = 40
    WinAccountDomainAdminsSid = 41
    WinAccountDomainUsersSid = 42
    WinAccountDomainGuestsSid = 43
    WinAccountComputersSid = 44
    WinAccountControllersSid = 45
    WinAccountCertAdminsSid = 46
    WinAccountSchemaAdminsSid = 47
    WinAccountEnterpriseAdminsSid = 48
    WinAccountPolicyAdminsSid = 49
    WinAccountRasAndIasServersSid = 50
    WinNTLMAuthenticationSid = 51
    WinDigestAuthenticationSid = 52
    WinSChannelAuthenticationSid = 53
    WinThisOrganizationSid = 54
    WinOtherOrganizationSid = 55
    WinBuiltinIncomingForestTrustBuildersSid = 56
    WinBuiltinPerfMonitoringUsersSid = 57
    WinBuiltinPerfLoggingUsersSid = 58
    WinBuiltinAuthorizationAccessSid = 59
    WinBuiltinTerminalServerLicenseServersSid = 60
    WinBuiltinDCOMUsersSid = 61
    WinBuiltinIUsersSid = 62
    WinIUserSid = 63
    WinBuiltinCryptoOperatorsSid = 64
    WinUntrustedLabelSid = 65
    WinLowLabelSid = 66
    WinMediumLabelSid = 67
    WinHighLabelSid = 68
    WinSystemLabelSid = 69
    WinWriteRestrictedCodeSid = 70
    WinCreatorOwnerRightsSid = 71
    WinCacheablePrincipalsGroupSid = 72
    WinNonCacheablePrincipalsGroupSid = 73
    WinEnterpriseReadonlyControllersSid = 74
    WinAccountReadonlyControllersSid = 75
    WinBuiltinEventLogReadersGroup = 76
    WinNewEnterpriseReadonlyControllersSid = 77
    WinBuiltinCertSvcDComAccessGroup = 78
    WinMediumPlusLabelSid = 79
    WinLocalLogonSid = 80
    WinConsoleLogonSid = 81
    WinThisOrganizationCertificateSid = 82
    WinApplicationPackageAuthoritySid = 83
    WinBuiltinAnyPackageSid = 84
    WinCapabilityInternetClientSid = 85
    WinCapabilityInternetClientServerSid = 86
    WinCapabilityPrivateNetworkClientServerSid = 87
    WinCapabilityPicturesLibrarySid = 88
    WinCapabilityVideosLibrarySid = 89
    WinCapabilityMusicLibrarySid = 90
    WinCapabilityDocumentsLibrarySid = 91
    WinCapabilitySharedUserCertificatesSid = 92
    WinCapabilityEnterpriseAuthenticationSid = 93
    WinCapabilityRemovableStorageSid = 94
    WinBuiltinRDSRemoteAccessServersSid = 95
    WinBuiltinRDSEndpointServersSid = 96
    WinBuiltinRDSManagementServersSid = 97
    WinUserModeDriversSid = 98
    WinBuiltinHyperVAdminsSid = 99
    WinAccountCloneableControllersSid = 100
    WinBuiltinAccessControlAssistanceOperatorsSid = 101
    WinBuiltinRemoteManagementUsersSid = 102
    WinAuthenticationAuthorityAssertedSid = 103
    WinAuthenticationServiceAssertedSid = 104
    WinLocalAccountSid = 105
    WinLocalAccountAndAdministratorSid = 106
    WinAccountProtectedUsersSid = 107
    WinCapabilityAppointmentsSid = 108
    WinCapabilityContactsSid = 109
    WinAccountDefaultSystemManagedSid = 110
    WinBuiltinDefaultSystemManagedGroupSid = 111
    WinBuiltinStorageReplicaAdminsSid = 112
    WinAccountKeyAdminsSid = 113
    WinAccountEnterpriseKeyAdminsSid = 114
    WinAuthenticationKeyTrustSid = 115
    WinAuthenticationKeyPropertyMFASid = 116
    WinAuthenticationKeyPropertyAttestationSid = 117
    WinAuthenticationFreshKeyAuthSid = 118
    WinBuiltinDeviceOwnersSid = 119
end

struct _ACE_HEADER
    AceType::BYTE
    AceFlags::BYTE
    AceSize::WORD
end

const ACE_HEADER = _ACE_HEADER

const PACE_HEADER = Ptr{ACE_HEADER}

struct _ACCESS_ALLOWED_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const ACCESS_ALLOWED_ACE = _ACCESS_ALLOWED_ACE

const PACCESS_ALLOWED_ACE = Ptr{ACCESS_ALLOWED_ACE}

struct _ACCESS_DENIED_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const ACCESS_DENIED_ACE = _ACCESS_DENIED_ACE

const PACCESS_DENIED_ACE = Ptr{ACCESS_DENIED_ACE}

struct _SYSTEM_AUDIT_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const SYSTEM_AUDIT_ACE = _SYSTEM_AUDIT_ACE

const PSYSTEM_AUDIT_ACE = Ptr{SYSTEM_AUDIT_ACE}

struct _SYSTEM_ALARM_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const SYSTEM_ALARM_ACE = _SYSTEM_ALARM_ACE

const PSYSTEM_ALARM_ACE = Ptr{SYSTEM_ALARM_ACE}

struct _SYSTEM_RESOURCE_ATTRIBUTE_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const SYSTEM_RESOURCE_ATTRIBUTE_ACE = _SYSTEM_RESOURCE_ATTRIBUTE_ACE

const PSYSTEM_RESOURCE_ATTRIBUTE_ACE = Ptr{_SYSTEM_RESOURCE_ATTRIBUTE_ACE}

struct _SYSTEM_SCOPED_POLICY_ID_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const SYSTEM_SCOPED_POLICY_ID_ACE = _SYSTEM_SCOPED_POLICY_ID_ACE

const PSYSTEM_SCOPED_POLICY_ID_ACE = Ptr{_SYSTEM_SCOPED_POLICY_ID_ACE}

struct _SYSTEM_MANDATORY_LABEL_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const SYSTEM_MANDATORY_LABEL_ACE = _SYSTEM_MANDATORY_LABEL_ACE

const PSYSTEM_MANDATORY_LABEL_ACE = Ptr{_SYSTEM_MANDATORY_LABEL_ACE}

struct _SYSTEM_PROCESS_TRUST_LABEL_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const SYSTEM_PROCESS_TRUST_LABEL_ACE = _SYSTEM_PROCESS_TRUST_LABEL_ACE

const PSYSTEM_PROCESS_TRUST_LABEL_ACE = Ptr{_SYSTEM_PROCESS_TRUST_LABEL_ACE}

struct _SYSTEM_ACCESS_FILTER_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const SYSTEM_ACCESS_FILTER_ACE = _SYSTEM_ACCESS_FILTER_ACE

const PSYSTEM_ACCESS_FILTER_ACE = Ptr{_SYSTEM_ACCESS_FILTER_ACE}

struct _ACCESS_ALLOWED_OBJECT_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    Flags::DWORD
    ObjectType::GUID
    InheritedObjectType::GUID
    SidStart::DWORD
end

const ACCESS_ALLOWED_OBJECT_ACE = _ACCESS_ALLOWED_OBJECT_ACE

const PACCESS_ALLOWED_OBJECT_ACE = Ptr{_ACCESS_ALLOWED_OBJECT_ACE}

struct _ACCESS_DENIED_OBJECT_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    Flags::DWORD
    ObjectType::GUID
    InheritedObjectType::GUID
    SidStart::DWORD
end

const ACCESS_DENIED_OBJECT_ACE = _ACCESS_DENIED_OBJECT_ACE

const PACCESS_DENIED_OBJECT_ACE = Ptr{_ACCESS_DENIED_OBJECT_ACE}

struct _SYSTEM_AUDIT_OBJECT_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    Flags::DWORD
    ObjectType::GUID
    InheritedObjectType::GUID
    SidStart::DWORD
end

const SYSTEM_AUDIT_OBJECT_ACE = _SYSTEM_AUDIT_OBJECT_ACE

const PSYSTEM_AUDIT_OBJECT_ACE = Ptr{_SYSTEM_AUDIT_OBJECT_ACE}

struct _SYSTEM_ALARM_OBJECT_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    Flags::DWORD
    ObjectType::GUID
    InheritedObjectType::GUID
    SidStart::DWORD
end

const SYSTEM_ALARM_OBJECT_ACE = _SYSTEM_ALARM_OBJECT_ACE

const PSYSTEM_ALARM_OBJECT_ACE = Ptr{_SYSTEM_ALARM_OBJECT_ACE}

struct _ACCESS_ALLOWED_CALLBACK_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const ACCESS_ALLOWED_CALLBACK_ACE = _ACCESS_ALLOWED_CALLBACK_ACE

const PACCESS_ALLOWED_CALLBACK_ACE = Ptr{_ACCESS_ALLOWED_CALLBACK_ACE}

struct _ACCESS_DENIED_CALLBACK_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const ACCESS_DENIED_CALLBACK_ACE = _ACCESS_DENIED_CALLBACK_ACE

const PACCESS_DENIED_CALLBACK_ACE = Ptr{_ACCESS_DENIED_CALLBACK_ACE}

struct _SYSTEM_AUDIT_CALLBACK_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const SYSTEM_AUDIT_CALLBACK_ACE = _SYSTEM_AUDIT_CALLBACK_ACE

const PSYSTEM_AUDIT_CALLBACK_ACE = Ptr{_SYSTEM_AUDIT_CALLBACK_ACE}

struct _SYSTEM_ALARM_CALLBACK_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    SidStart::DWORD
end

const SYSTEM_ALARM_CALLBACK_ACE = _SYSTEM_ALARM_CALLBACK_ACE

const PSYSTEM_ALARM_CALLBACK_ACE = Ptr{_SYSTEM_ALARM_CALLBACK_ACE}

struct _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    Flags::DWORD
    ObjectType::GUID
    InheritedObjectType::GUID
    SidStart::DWORD
end

const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE = _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE

const PACCESS_ALLOWED_CALLBACK_OBJECT_ACE = Ptr{_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE}

struct _ACCESS_DENIED_CALLBACK_OBJECT_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    Flags::DWORD
    ObjectType::GUID
    InheritedObjectType::GUID
    SidStart::DWORD
end

const ACCESS_DENIED_CALLBACK_OBJECT_ACE = _ACCESS_DENIED_CALLBACK_OBJECT_ACE

const PACCESS_DENIED_CALLBACK_OBJECT_ACE = Ptr{_ACCESS_DENIED_CALLBACK_OBJECT_ACE}

struct _SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    Flags::DWORD
    ObjectType::GUID
    InheritedObjectType::GUID
    SidStart::DWORD
end

const SYSTEM_AUDIT_CALLBACK_OBJECT_ACE = _SYSTEM_AUDIT_CALLBACK_OBJECT_ACE

const PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE = Ptr{_SYSTEM_AUDIT_CALLBACK_OBJECT_ACE}

struct _SYSTEM_ALARM_CALLBACK_OBJECT_ACE
    Header::ACE_HEADER
    Mask::ACCESS_MASK
    Flags::DWORD
    ObjectType::GUID
    InheritedObjectType::GUID
    SidStart::DWORD
end

const SYSTEM_ALARM_CALLBACK_OBJECT_ACE = _SYSTEM_ALARM_CALLBACK_OBJECT_ACE

const PSYSTEM_ALARM_CALLBACK_OBJECT_ACE = Ptr{_SYSTEM_ALARM_CALLBACK_OBJECT_ACE}

@cenum _ACL_INFORMATION_CLASS::UInt32 begin
    AclRevisionInformation = 1
    AclSizeInformation = 2
end

const ACL_INFORMATION_CLASS = _ACL_INFORMATION_CLASS

struct _ACL_REVISION_INFORMATION
    AclRevision::DWORD
end

const ACL_REVISION_INFORMATION = _ACL_REVISION_INFORMATION

const PACL_REVISION_INFORMATION = Ptr{ACL_REVISION_INFORMATION}

struct _ACL_SIZE_INFORMATION
    AceCount::DWORD
    AclBytesInUse::DWORD
    AclBytesFree::DWORD
end

const ACL_SIZE_INFORMATION = _ACL_SIZE_INFORMATION

const PACL_SIZE_INFORMATION = Ptr{ACL_SIZE_INFORMATION}

const PSECURITY_DESCRIPTOR_CONTROL = Ptr{WORD}

struct _SECURITY_DESCRIPTOR_RELATIVE
    Revision::BYTE
    Sbz1::BYTE
    Control::SECURITY_DESCRIPTOR_CONTROL
    Owner::DWORD
    Group::DWORD
    Sacl::DWORD
    Dacl::DWORD
end

const SECURITY_DESCRIPTOR_RELATIVE = _SECURITY_DESCRIPTOR_RELATIVE

const PISECURITY_DESCRIPTOR_RELATIVE = Ptr{_SECURITY_DESCRIPTOR_RELATIVE}

const PISECURITY_DESCRIPTOR = Ptr{_SECURITY_DESCRIPTOR}

struct _SECURITY_OBJECT_AI_PARAMS
    Size::DWORD
    ConstraintMask::DWORD
end

const SECURITY_OBJECT_AI_PARAMS = _SECURITY_OBJECT_AI_PARAMS

const PSECURITY_OBJECT_AI_PARAMS = Ptr{_SECURITY_OBJECT_AI_PARAMS}

struct _OBJECT_TYPE_LIST
    Level::WORD
    Sbz::WORD
    ObjectType::Ptr{GUID}
end

const OBJECT_TYPE_LIST = _OBJECT_TYPE_LIST

const POBJECT_TYPE_LIST = Ptr{_OBJECT_TYPE_LIST}

@cenum _AUDIT_EVENT_TYPE::UInt32 begin
    AuditEventObjectAccess = 0
    AuditEventDirectoryServiceAccess = 1
end

const AUDIT_EVENT_TYPE = _AUDIT_EVENT_TYPE

const PAUDIT_EVENT_TYPE = Ptr{_AUDIT_EVENT_TYPE}

struct _PRIVILEGE_SET
    PrivilegeCount::DWORD
    Control::DWORD
    Privilege::NTuple{1, LUID_AND_ATTRIBUTES}
end

const PRIVILEGE_SET = _PRIVILEGE_SET

const PPRIVILEGE_SET = Ptr{_PRIVILEGE_SET}

@cenum _ACCESS_REASON_TYPE::UInt32 begin
    AccessReasonNone = 0
    AccessReasonAllowedAce = 65536
    AccessReasonDeniedAce = 131072
    AccessReasonAllowedParentAce = 196608
    AccessReasonDeniedParentAce = 262144
    AccessReasonNotGrantedByCape = 327680
    AccessReasonNotGrantedByParentCape = 393216
    AccessReasonNotGrantedToAppContainer = 458752
    AccessReasonMissingPrivilege = 1048576
    AccessReasonFromPrivilege = 2097152
    AccessReasonIntegrityLevel = 3145728
    AccessReasonOwnership = 4194304
    AccessReasonNullDacl = 5242880
    AccessReasonEmptyDacl = 6291456
    AccessReasonNoSD = 7340032
    AccessReasonNoGrant = 8388608
    AccessReasonTrustLabel = 9437184
    AccessReasonFilterAce = 10485760
end

const ACCESS_REASON_TYPE = _ACCESS_REASON_TYPE

const ACCESS_REASON = DWORD

struct _ACCESS_REASONS
    Data::NTuple{32, ACCESS_REASON}
end

const ACCESS_REASONS = _ACCESS_REASONS

const PACCESS_REASONS = Ptr{_ACCESS_REASONS}

struct _SE_SECURITY_DESCRIPTOR
    Size::DWORD
    Flags::DWORD
    SecurityDescriptor::PSECURITY_DESCRIPTOR
end

const SE_SECURITY_DESCRIPTOR = _SE_SECURITY_DESCRIPTOR

const PSE_SECURITY_DESCRIPTOR = Ptr{_SE_SECURITY_DESCRIPTOR}

struct _SE_ACCESS_REQUEST
    Size::DWORD
    SeSecurityDescriptor::PSE_SECURITY_DESCRIPTOR
    DesiredAccess::ACCESS_MASK
    PreviouslyGrantedAccess::ACCESS_MASK
    PrincipalSelfSid::PSID
    GenericMapping::PGENERIC_MAPPING
    ObjectTypeListCount::DWORD
    ObjectTypeList::POBJECT_TYPE_LIST
end

const SE_ACCESS_REQUEST = _SE_ACCESS_REQUEST

const PSE_ACCESS_REQUEST = Ptr{_SE_ACCESS_REQUEST}

struct _SE_ACCESS_REPLY
    Size::DWORD
    ResultListCount::DWORD
    GrantedAccess::PACCESS_MASK
    AccessStatus::PDWORD
    AccessReason::PACCESS_REASONS
    Privileges::Ptr{PPRIVILEGE_SET}
end

const SE_ACCESS_REPLY = _SE_ACCESS_REPLY

const PSE_ACCESS_REPLY = Ptr{_SE_ACCESS_REPLY}

@cenum _SECURITY_IMPERSONATION_LEVEL::UInt32 begin
    SecurityAnonymous = 0
    SecurityIdentification = 1
    SecurityImpersonation = 2
    SecurityDelegation = 3
end

const SECURITY_IMPERSONATION_LEVEL = _SECURITY_IMPERSONATION_LEVEL

const PSECURITY_IMPERSONATION_LEVEL = Ptr{_SECURITY_IMPERSONATION_LEVEL}

@cenum _TOKEN_TYPE::UInt32 begin
    TokenPrimary = 1
    TokenImpersonation = 2
end

const TOKEN_TYPE = _TOKEN_TYPE

const PTOKEN_TYPE = Ptr{TOKEN_TYPE}

@cenum _TOKEN_ELEVATION_TYPE::UInt32 begin
    TokenElevationTypeDefault = 1
    TokenElevationTypeFull = 2
    TokenElevationTypeLimited = 3
end

const TOKEN_ELEVATION_TYPE = _TOKEN_ELEVATION_TYPE

const PTOKEN_ELEVATION_TYPE = Ptr{_TOKEN_ELEVATION_TYPE}

@cenum _TOKEN_INFORMATION_CLASS::UInt32 begin
    TokenUser = 1
    TokenGroups = 2
    TokenPrivileges = 3
    TokenOwner = 4
    TokenPrimaryGroup = 5
    TokenDefaultDacl = 6
    TokenSource = 7
    TokenType = 8
    TokenImpersonationLevel = 9
    TokenStatistics = 10
    TokenRestrictedSids = 11
    TokenSessionId = 12
    TokenGroupsAndPrivileges = 13
    TokenSessionReference = 14
    TokenSandBoxInert = 15
    TokenAuditPolicy = 16
    TokenOrigin = 17
    TokenElevationType = 18
    TokenLinkedToken = 19
    TokenElevation = 20
    TokenHasRestrictions = 21
    TokenAccessInformation = 22
    TokenVirtualizationAllowed = 23
    TokenVirtualizationEnabled = 24
    TokenIntegrityLevel = 25
    TokenUIAccess = 26
    TokenMandatoryPolicy = 27
    TokenLogonSid = 28
    TokenIsAppContainer = 29
    TokenCapabilities = 30
    TokenAppContainerSid = 31
    TokenAppContainerNumber = 32
    TokenUserClaimAttributes = 33
    TokenDeviceClaimAttributes = 34
    TokenRestrictedUserClaimAttributes = 35
    TokenRestrictedDeviceClaimAttributes = 36
    TokenDeviceGroups = 37
    TokenRestrictedDeviceGroups = 38
    TokenSecurityAttributes = 39
    TokenIsRestricted = 40
    TokenProcessTrustLevel = 41
    TokenPrivateNameSpace = 42
    TokenSingletonAttributes = 43
    TokenBnoIsolation = 44
    TokenChildProcessFlags = 45
    TokenIsLessPrivilegedAppContainer = 46
    TokenIsSandboxed = 47
    TokenIsAppSilo = 48
    MaxTokenInfoClass = 49
end

const TOKEN_INFORMATION_CLASS = _TOKEN_INFORMATION_CLASS

const PTOKEN_INFORMATION_CLASS = Ptr{_TOKEN_INFORMATION_CLASS}

const PTOKEN_USER = Ptr{_TOKEN_USER}

struct _SE_TOKEN_USER
    data::NTuple{88, UInt8}
end

function Base.getproperty(x::Ptr{_SE_TOKEN_USER}, f::Symbol)
    f === :TokenUser && return Ptr{TOKEN_USER}(x + 0)
    f === :User && return Ptr{SID_AND_ATTRIBUTES}(x + 0)
    f === :Sid && return Ptr{SID}(x + 16)
    f === :Buffer && return Ptr{NTuple{68, BYTE}}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_SE_TOKEN_USER, f::Symbol)
    r = Ref{_SE_TOKEN_USER}(x)
    ptr = Base.unsafe_convert(Ptr{_SE_TOKEN_USER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_SE_TOKEN_USER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _SE_TOKEN_USER()
    ref = Ref{_SE_TOKEN_USER}()
    ptr = Base.unsafe_convert(Ptr{_SE_TOKEN_USER}, ref)
    ref[]
end

const SE_TOKEN_USER = _SE_TOKEN_USER

const PSE_TOKEN_USER = _SE_TOKEN_USER

struct _TOKEN_GROUPS
    GroupCount::DWORD
    Groups::NTuple{1, SID_AND_ATTRIBUTES}
end

const TOKEN_GROUPS = _TOKEN_GROUPS

const PTOKEN_GROUPS = Ptr{_TOKEN_GROUPS}

struct _TOKEN_PRIVILEGES
    PrivilegeCount::DWORD
    Privileges::NTuple{1, LUID_AND_ATTRIBUTES}
end

const TOKEN_PRIVILEGES = _TOKEN_PRIVILEGES

const PTOKEN_PRIVILEGES = Ptr{_TOKEN_PRIVILEGES}

const PTOKEN_OWNER = Ptr{_TOKEN_OWNER}

struct _TOKEN_PRIMARY_GROUP
    PrimaryGroup::PSID
end

const TOKEN_PRIMARY_GROUP = _TOKEN_PRIMARY_GROUP

const PTOKEN_PRIMARY_GROUP = Ptr{_TOKEN_PRIMARY_GROUP}

struct _TOKEN_DEFAULT_DACL
    DefaultDacl::PACL
end

const TOKEN_DEFAULT_DACL = _TOKEN_DEFAULT_DACL

const PTOKEN_DEFAULT_DACL = Ptr{_TOKEN_DEFAULT_DACL}

struct _TOKEN_USER_CLAIMS
    UserClaims::PCLAIMS_BLOB
end

const TOKEN_USER_CLAIMS = _TOKEN_USER_CLAIMS

const PTOKEN_USER_CLAIMS = Ptr{_TOKEN_USER_CLAIMS}

struct _TOKEN_DEVICE_CLAIMS
    DeviceClaims::PCLAIMS_BLOB
end

const TOKEN_DEVICE_CLAIMS = _TOKEN_DEVICE_CLAIMS

const PTOKEN_DEVICE_CLAIMS = Ptr{_TOKEN_DEVICE_CLAIMS}

struct _TOKEN_GROUPS_AND_PRIVILEGES
    SidCount::DWORD
    SidLength::DWORD
    Sids::PSID_AND_ATTRIBUTES
    RestrictedSidCount::DWORD
    RestrictedSidLength::DWORD
    RestrictedSids::PSID_AND_ATTRIBUTES
    PrivilegeCount::DWORD
    PrivilegeLength::DWORD
    Privileges::PLUID_AND_ATTRIBUTES
    AuthenticationId::LUID
end

const TOKEN_GROUPS_AND_PRIVILEGES = _TOKEN_GROUPS_AND_PRIVILEGES

const PTOKEN_GROUPS_AND_PRIVILEGES = Ptr{_TOKEN_GROUPS_AND_PRIVILEGES}

struct _TOKEN_LINKED_TOKEN
    LinkedToken::HANDLE
end

const TOKEN_LINKED_TOKEN = _TOKEN_LINKED_TOKEN

const PTOKEN_LINKED_TOKEN = Ptr{_TOKEN_LINKED_TOKEN}

struct _TOKEN_ELEVATION
    TokenIsElevated::DWORD
end

const TOKEN_ELEVATION = _TOKEN_ELEVATION

const PTOKEN_ELEVATION = Ptr{_TOKEN_ELEVATION}

const PTOKEN_MANDATORY_LABEL = Ptr{_TOKEN_MANDATORY_LABEL}

struct _TOKEN_MANDATORY_POLICY
    Policy::DWORD
end

const TOKEN_MANDATORY_POLICY = _TOKEN_MANDATORY_POLICY

const PTOKEN_MANDATORY_POLICY = Ptr{_TOKEN_MANDATORY_POLICY}

const PSECURITY_ATTRIBUTES_OPAQUE = PVOID

struct _TOKEN_ACCESS_INFORMATION
    SidHash::PSID_AND_ATTRIBUTES_HASH
    RestrictedSidHash::PSID_AND_ATTRIBUTES_HASH
    Privileges::PTOKEN_PRIVILEGES
    AuthenticationId::LUID
    TokenType::TOKEN_TYPE
    ImpersonationLevel::SECURITY_IMPERSONATION_LEVEL
    MandatoryPolicy::TOKEN_MANDATORY_POLICY
    Flags::DWORD
    AppContainerNumber::DWORD
    PackageSid::PSID
    CapabilitiesHash::PSID_AND_ATTRIBUTES_HASH
    TrustLevelSid::PSID
    SecurityAttributes::PSECURITY_ATTRIBUTES_OPAQUE
end

const TOKEN_ACCESS_INFORMATION = _TOKEN_ACCESS_INFORMATION

const PTOKEN_ACCESS_INFORMATION = Ptr{_TOKEN_ACCESS_INFORMATION}

struct _TOKEN_AUDIT_POLICY
    PerUserPolicy::NTuple{30, BYTE}
end

const TOKEN_AUDIT_POLICY = _TOKEN_AUDIT_POLICY

const PTOKEN_AUDIT_POLICY = Ptr{_TOKEN_AUDIT_POLICY}

struct _TOKEN_SOURCE
    SourceName::NTuple{8, CHAR}
    SourceIdentifier::LUID
end

const TOKEN_SOURCE = _TOKEN_SOURCE

const PTOKEN_SOURCE = Ptr{_TOKEN_SOURCE}

struct _TOKEN_STATISTICS
    TokenId::LUID
    AuthenticationId::LUID
    ExpirationTime::LARGE_INTEGER
    TokenType::TOKEN_TYPE
    ImpersonationLevel::SECURITY_IMPERSONATION_LEVEL
    DynamicCharged::DWORD
    DynamicAvailable::DWORD
    GroupCount::DWORD
    PrivilegeCount::DWORD
    ModifiedId::LUID
end

const TOKEN_STATISTICS = _TOKEN_STATISTICS

const PTOKEN_STATISTICS = Ptr{_TOKEN_STATISTICS}

struct _TOKEN_CONTROL
    TokenId::LUID
    AuthenticationId::LUID
    ModifiedId::LUID
    TokenSource::TOKEN_SOURCE
end

const TOKEN_CONTROL = _TOKEN_CONTROL

const PTOKEN_CONTROL = Ptr{_TOKEN_CONTROL}

struct _TOKEN_ORIGIN
    OriginatingLogonSession::LUID
end

const TOKEN_ORIGIN = _TOKEN_ORIGIN

const PTOKEN_ORIGIN = Ptr{_TOKEN_ORIGIN}

@cenum _MANDATORY_LEVEL::UInt32 begin
    MandatoryLevelUntrusted = 0
    MandatoryLevelLow = 1
    MandatoryLevelMedium = 2
    MandatoryLevelHigh = 3
    MandatoryLevelSystem = 4
    MandatoryLevelSecureProcess = 5
    MandatoryLevelCount = 6
end

const MANDATORY_LEVEL = _MANDATORY_LEVEL

const PMANDATORY_LEVEL = Ptr{_MANDATORY_LEVEL}

const PTOKEN_APPCONTAINER_INFORMATION = Ptr{_TOKEN_APPCONTAINER_INFORMATION}

struct _TOKEN_SID_INFORMATION
    Sid::PSID
end

const TOKEN_SID_INFORMATION = _TOKEN_SID_INFORMATION

const PTOKEN_SID_INFORMATION = Ptr{_TOKEN_SID_INFORMATION}

struct _TOKEN_BNO_ISOLATION_INFORMATION
    IsolationPrefix::PWSTR
    IsolationEnabled::BOOLEAN
end

const TOKEN_BNO_ISOLATION_INFORMATION = _TOKEN_BNO_ISOLATION_INFORMATION

const PTOKEN_BNO_ISOLATION_INFORMATION = Ptr{_TOKEN_BNO_ISOLATION_INFORMATION}

struct _CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE
    Version::DWORD64
    Name::PWSTR
end

const CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE = _CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE

const PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE = Ptr{_CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE}

struct _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
    pValue::PVOID
    ValueLength::DWORD
end

const CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE = _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE

const PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE = Ptr{_CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE}

struct __JL_Ctag_46
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_46}, f::Symbol)
    f === :pInt64 && return Ptr{PLONG64}(x + 0)
    f === :pUint64 && return Ptr{PDWORD64}(x + 0)
    f === :ppString && return Ptr{Ptr{PWSTR}}(x + 0)
    f === :pFqbn && return Ptr{PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE}(x + 0)
    f === :pOctetString && return Ptr{PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_46, f::Symbol)
    r = Ref{__JL_Ctag_46}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_46}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_46}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_46 = Union{PLONG64, PDWORD64, Ptr{PWSTR}, PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE, PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE}

function __JL_Ctag_46(val::__U___JL_Ctag_46)
    ref = Ref{__JL_Ctag_46}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_46}, ref)
    if val isa PLONG64
        ptr.pInt64 = val
    elseif val isa PDWORD64
        ptr.pUint64 = val
    elseif val isa Ptr{PWSTR}
        ptr.ppString = val
    elseif val isa PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE
        ptr.pFqbn = val
    elseif val isa PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
        ptr.pOctetString = val
    end
    ref[]
end

struct _CLAIM_SECURITY_ATTRIBUTE_V1
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_CLAIM_SECURITY_ATTRIBUTE_V1}, f::Symbol)
    f === :Name && return Ptr{PWSTR}(x + 0)
    f === :ValueType && return Ptr{WORD}(x + 8)
    f === :Reserved && return Ptr{WORD}(x + 10)
    f === :Flags && return Ptr{DWORD}(x + 12)
    f === :ValueCount && return Ptr{DWORD}(x + 16)
    f === :Values && return Ptr{__JL_Ctag_46}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_CLAIM_SECURITY_ATTRIBUTE_V1, f::Symbol)
    r = Ref{_CLAIM_SECURITY_ATTRIBUTE_V1}(x)
    ptr = Base.unsafe_convert(Ptr{_CLAIM_SECURITY_ATTRIBUTE_V1}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_CLAIM_SECURITY_ATTRIBUTE_V1}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _CLAIM_SECURITY_ATTRIBUTE_V1(Name::PWSTR, ValueType::WORD, Reserved::WORD, Flags::DWORD, ValueCount::DWORD, Values::__JL_Ctag_46)
    ref = Ref{_CLAIM_SECURITY_ATTRIBUTE_V1}()
    ptr = Base.unsafe_convert(Ptr{_CLAIM_SECURITY_ATTRIBUTE_V1}, ref)
    ptr.Name = Name
    ptr.ValueType = ValueType
    ptr.Reserved = Reserved
    ptr.Flags = Flags
    ptr.ValueCount = ValueCount
    ptr.Values = Values
    ref[]
end

const CLAIM_SECURITY_ATTRIBUTE_V1 = _CLAIM_SECURITY_ATTRIBUTE_V1

const PCLAIM_SECURITY_ATTRIBUTE_V1 = Ptr{_CLAIM_SECURITY_ATTRIBUTE_V1}

struct __JL_Ctag_67
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_67}, f::Symbol)
    f === :pInt64 && return Ptr{NTuple{1, DWORD}}(x + 0)
    f === :pUint64 && return Ptr{NTuple{1, DWORD}}(x + 0)
    f === :ppString && return Ptr{NTuple{1, DWORD}}(x + 0)
    f === :pFqbn && return Ptr{NTuple{1, DWORD}}(x + 0)
    f === :pOctetString && return Ptr{NTuple{1, DWORD}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_67, f::Symbol)
    r = Ref{__JL_Ctag_67}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_67}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_67}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_67 = Union{NTuple{1, DWORD}, NTuple{1, DWORD}, NTuple{1, DWORD}, NTuple{1, DWORD}, NTuple{1, DWORD}}

function __JL_Ctag_67(val::__U___JL_Ctag_67)
    ref = Ref{__JL_Ctag_67}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_67}, ref)
    if val isa NTuple{1, DWORD}
        ptr.pInt64 = val
    elseif val isa NTuple{1, DWORD}
        ptr.pUint64 = val
    elseif val isa NTuple{1, DWORD}
        ptr.ppString = val
    elseif val isa NTuple{1, DWORD}
        ptr.pFqbn = val
    elseif val isa NTuple{1, DWORD}
        ptr.pOctetString = val
    end
    ref[]
end

struct _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1}, f::Symbol)
    f === :Name && return Ptr{DWORD}(x + 0)
    f === :ValueType && return Ptr{WORD}(x + 4)
    f === :Reserved && return Ptr{WORD}(x + 6)
    f === :Flags && return Ptr{DWORD}(x + 8)
    f === :ValueCount && return Ptr{DWORD}(x + 12)
    f === :Values && return Ptr{__JL_Ctag_67}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, f::Symbol)
    r = Ref{_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1}(x)
    ptr = Base.unsafe_convert(Ptr{_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1(Name::DWORD, ValueType::WORD, Reserved::WORD, Flags::DWORD, ValueCount::DWORD, Values::__JL_Ctag_67)
    ref = Ref{_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1}()
    ptr = Base.unsafe_convert(Ptr{_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1}, ref)
    ptr.Name = Name
    ptr.ValueType = ValueType
    ptr.Reserved = Reserved
    ptr.Flags = Flags
    ptr.ValueCount = ValueCount
    ptr.Values = Values
    ref[]
end

const CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 = _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1

const PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 = Ptr{_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1}

struct __JL_Ctag_81
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_81}, f::Symbol)
    f === :pAttributeV1 && return Ptr{PCLAIM_SECURITY_ATTRIBUTE_V1}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_81, f::Symbol)
    r = Ref{__JL_Ctag_81}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_81}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_81}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_81 = Union{PCLAIM_SECURITY_ATTRIBUTE_V1}

function __JL_Ctag_81(val::__U___JL_Ctag_81)
    ref = Ref{__JL_Ctag_81}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_81}, ref)
    if val isa PCLAIM_SECURITY_ATTRIBUTE_V1
        ptr.pAttributeV1 = val
    end
    ref[]
end

struct _CLAIM_SECURITY_ATTRIBUTES_INFORMATION
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{_CLAIM_SECURITY_ATTRIBUTES_INFORMATION}, f::Symbol)
    f === :Version && return Ptr{WORD}(x + 0)
    f === :Reserved && return Ptr{WORD}(x + 2)
    f === :AttributeCount && return Ptr{DWORD}(x + 4)
    f === :Attribute && return Ptr{__JL_Ctag_81}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_CLAIM_SECURITY_ATTRIBUTES_INFORMATION, f::Symbol)
    r = Ref{_CLAIM_SECURITY_ATTRIBUTES_INFORMATION}(x)
    ptr = Base.unsafe_convert(Ptr{_CLAIM_SECURITY_ATTRIBUTES_INFORMATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_CLAIM_SECURITY_ATTRIBUTES_INFORMATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _CLAIM_SECURITY_ATTRIBUTES_INFORMATION(Version::WORD, Reserved::WORD, AttributeCount::DWORD, Attribute::__JL_Ctag_81)
    ref = Ref{_CLAIM_SECURITY_ATTRIBUTES_INFORMATION}()
    ptr = Base.unsafe_convert(Ptr{_CLAIM_SECURITY_ATTRIBUTES_INFORMATION}, ref)
    ptr.Version = Version
    ptr.Reserved = Reserved
    ptr.AttributeCount = AttributeCount
    ptr.Attribute = Attribute
    ref[]
end

const CLAIM_SECURITY_ATTRIBUTES_INFORMATION = _CLAIM_SECURITY_ATTRIBUTES_INFORMATION

const PCLAIM_SECURITY_ATTRIBUTES_INFORMATION = Ptr{_CLAIM_SECURITY_ATTRIBUTES_INFORMATION}

const SECURITY_CONTEXT_TRACKING_MODE = BOOLEAN

const PSECURITY_CONTEXT_TRACKING_MODE = Ptr{BOOLEAN}

struct _SECURITY_QUALITY_OF_SERVICE
    Length::DWORD
    ImpersonationLevel::SECURITY_IMPERSONATION_LEVEL
    ContextTrackingMode::SECURITY_CONTEXT_TRACKING_MODE
    EffectiveOnly::BOOLEAN
end

const SECURITY_QUALITY_OF_SERVICE = _SECURITY_QUALITY_OF_SERVICE

const PSECURITY_QUALITY_OF_SERVICE = Ptr{_SECURITY_QUALITY_OF_SERVICE}

struct _SE_IMPERSONATION_STATE
    Token::PACCESS_TOKEN
    CopyOnOpen::BOOLEAN
    EffectiveOnly::BOOLEAN
    Level::SECURITY_IMPERSONATION_LEVEL
end

const SE_IMPERSONATION_STATE = _SE_IMPERSONATION_STATE

const PSE_IMPERSONATION_STATE = Ptr{_SE_IMPERSONATION_STATE}

const SECURITY_INFORMATION = DWORD

const PSECURITY_INFORMATION = Ptr{DWORD}

const SE_SIGNING_LEVEL = BYTE

const PSE_SIGNING_LEVEL = Ptr{BYTE}

@cenum _SE_IMAGE_SIGNATURE_TYPE::UInt32 begin
    SeImageSignatureNone = 0
    SeImageSignatureEmbedded = 1
    SeImageSignatureCache = 2
    SeImageSignatureCatalogCached = 3
    SeImageSignatureCatalogNotCached = 4
    SeImageSignatureCatalogHint = 5
    SeImageSignaturePackageCatalog = 6
    SeImageSignaturePplMitigated = 7
end

const SE_IMAGE_SIGNATURE_TYPE = _SE_IMAGE_SIGNATURE_TYPE

const PSE_IMAGE_SIGNATURE_TYPE = Ptr{_SE_IMAGE_SIGNATURE_TYPE}

struct _SECURITY_CAPABILITIES
    AppContainerSid::PSID
    Capabilities::PSID_AND_ATTRIBUTES
    CapabilityCount::DWORD
    Reserved::DWORD
end

const SECURITY_CAPABILITIES = _SECURITY_CAPABILITIES

const PSECURITY_CAPABILITIES = Ptr{_SECURITY_CAPABILITIES}

const LPSECURITY_CAPABILITIES = Ptr{_SECURITY_CAPABILITIES}

struct _JOB_SET_ARRAY
    JobHandle::HANDLE
    MemberLevel::DWORD
    Flags::DWORD
end

const JOB_SET_ARRAY = _JOB_SET_ARRAY

const PJOB_SET_ARRAY = Ptr{_JOB_SET_ARRAY}

struct _EXCEPTION_REGISTRATION_RECORD
    Next::Ptr{_EXCEPTION_REGISTRATION_RECORD}
    Handler::PEXCEPTION_ROUTINE
end

const EXCEPTION_REGISTRATION_RECORD = _EXCEPTION_REGISTRATION_RECORD

const PEXCEPTION_REGISTRATION_RECORD = Ptr{EXCEPTION_REGISTRATION_RECORD}

struct _NT_TIB
    ExceptionList::Ptr{_EXCEPTION_REGISTRATION_RECORD}
    StackBase::PVOID
    StackLimit::PVOID
    SubSystemTib::PVOID
    FiberData::PVOID
    ArbitraryUserPointer::PVOID
    Self::Ptr{_NT_TIB}
end

const NT_TIB = _NT_TIB

const PNT_TIB = Ptr{NT_TIB}

struct _NT_TIB32
    ExceptionList::DWORD
    StackBase::DWORD
    StackLimit::DWORD
    SubSystemTib::DWORD
    FiberData::DWORD
    ArbitraryUserPointer::DWORD
    Self::DWORD
end

const NT_TIB32 = _NT_TIB32

const PNT_TIB32 = Ptr{_NT_TIB32}

struct _NT_TIB64
    ExceptionList::DWORD64
    StackBase::DWORD64
    StackLimit::DWORD64
    SubSystemTib::DWORD64
    FiberData::DWORD64
    ArbitraryUserPointer::DWORD64
    Self::DWORD64
end

const NT_TIB64 = _NT_TIB64

const PNT_TIB64 = Ptr{_NT_TIB64}

struct _UMS_CREATE_THREAD_ATTRIBUTES
    UmsVersion::DWORD
    UmsContext::PVOID
    UmsCompletionList::PVOID
end

const UMS_CREATE_THREAD_ATTRIBUTES = _UMS_CREATE_THREAD_ATTRIBUTES

const PUMS_CREATE_THREAD_ATTRIBUTES = Ptr{_UMS_CREATE_THREAD_ATTRIBUTES}

struct _COMPONENT_FILTER
    ComponentFlags::DWORD
end

const COMPONENT_FILTER = _COMPONENT_FILTER

const PCOMPONENT_FILTER = Ptr{_COMPONENT_FILTER}

struct _PROCESS_DYNAMIC_EH_CONTINUATION_TARGET
    TargetAddress::ULONG_PTR
    Flags::ULONG_PTR
end

const PROCESS_DYNAMIC_EH_CONTINUATION_TARGET = _PROCESS_DYNAMIC_EH_CONTINUATION_TARGET

const PPROCESS_DYNAMIC_EH_CONTINUATION_TARGET = Ptr{_PROCESS_DYNAMIC_EH_CONTINUATION_TARGET}

struct _PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    NumberOfTargets::WORD
    Reserved::WORD
    Reserved2::DWORD
    Targets::PPROCESS_DYNAMIC_EH_CONTINUATION_TARGET
end

const PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION = _PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION

const PPROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION = Ptr{_PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION}

struct _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE
    BaseAddress::ULONG_PTR
    Size::SIZE_T
    Flags::DWORD
end

const PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE = _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE

const PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE = Ptr{_PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE}

struct _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION
    NumberOfRanges::WORD
    Reserved::WORD
    Reserved2::DWORD
    Ranges::PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE
end

const PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION = _PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION

const PPROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION = Ptr{_PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGES_INFORMATION}

struct _QUOTA_LIMITS
    PagedPoolLimit::SIZE_T
    NonPagedPoolLimit::SIZE_T
    MinimumWorkingSetSize::SIZE_T
    MaximumWorkingSetSize::SIZE_T
    PagefileLimit::SIZE_T
    TimeLimit::LARGE_INTEGER
end

const QUOTA_LIMITS = _QUOTA_LIMITS

const PQUOTA_LIMITS = Ptr{_QUOTA_LIMITS}

struct _RATE_QUOTA_LIMIT
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_RATE_QUOTA_LIMIT}, f::Symbol)
    f === :RateData && return Ptr{DWORD}(x + 0)
    f === :RatePercent && return (Ptr{DWORD}(x + 0), 0, 7)
    f === :Reserved0 && return (Ptr{DWORD}(x + 0), 7, 25)
    return getfield(x, f)
end

function Base.getproperty(x::_RATE_QUOTA_LIMIT, f::Symbol)
    r = Ref{_RATE_QUOTA_LIMIT}(x)
    ptr = Base.unsafe_convert(Ptr{_RATE_QUOTA_LIMIT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_RATE_QUOTA_LIMIT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__RATE_QUOTA_LIMIT = Union{DWORD}

function _RATE_QUOTA_LIMIT(val::__U__RATE_QUOTA_LIMIT)
    ref = Ref{_RATE_QUOTA_LIMIT}()
    ptr = Base.unsafe_convert(Ptr{_RATE_QUOTA_LIMIT}, ref)
    if val isa DWORD
        ptr.RateData = val
    end
    ref[]
end

const RATE_QUOTA_LIMIT = _RATE_QUOTA_LIMIT

const PRATE_QUOTA_LIMIT = Ptr{_RATE_QUOTA_LIMIT}

struct _QUOTA_LIMITS_EX
    PagedPoolLimit::SIZE_T
    NonPagedPoolLimit::SIZE_T
    MinimumWorkingSetSize::SIZE_T
    MaximumWorkingSetSize::SIZE_T
    PagefileLimit::SIZE_T
    TimeLimit::LARGE_INTEGER
    WorkingSetLimit::SIZE_T
    Reserved2::SIZE_T
    Reserved3::SIZE_T
    Reserved4::SIZE_T
    Flags::DWORD
    CpuRateLimit::RATE_QUOTA_LIMIT
end

const QUOTA_LIMITS_EX = _QUOTA_LIMITS_EX

const PQUOTA_LIMITS_EX = Ptr{_QUOTA_LIMITS_EX}

struct _IO_COUNTERS
    ReadOperationCount::ULONGLONG
    WriteOperationCount::ULONGLONG
    OtherOperationCount::ULONGLONG
    ReadTransferCount::ULONGLONG
    WriteTransferCount::ULONGLONG
    OtherTransferCount::ULONGLONG
end

const IO_COUNTERS = _IO_COUNTERS

const PIO_COUNTERS = Ptr{IO_COUNTERS}

@cenum _HARDWARE_COUNTER_TYPE::UInt32 begin
    PMCCounter = 0
    MaxHardwareCounterType = 1
end

const HARDWARE_COUNTER_TYPE = _HARDWARE_COUNTER_TYPE

const PHARDWARE_COUNTER_TYPE = Ptr{_HARDWARE_COUNTER_TYPE}

@cenum _PROCESS_MITIGATION_POLICY::UInt32 begin
    ProcessDEPPolicy = 0
    ProcessASLRPolicy = 1
    ProcessDynamicCodePolicy = 2
    ProcessStrictHandleCheckPolicy = 3
    ProcessSystemCallDisablePolicy = 4
    ProcessMitigationOptionsMask = 5
    ProcessExtensionPointDisablePolicy = 6
    ProcessControlFlowGuardPolicy = 7
    ProcessSignaturePolicy = 8
    ProcessFontDisablePolicy = 9
    ProcessImageLoadPolicy = 10
    ProcessSystemCallFilterPolicy = 11
    ProcessPayloadRestrictionPolicy = 12
    ProcessChildProcessPolicy = 13
    ProcessSideChannelIsolationPolicy = 14
    ProcessUserShadowStackPolicy = 15
    ProcessRedirectionTrustPolicy = 16
    ProcessUserPointerAuthPolicy = 17
    ProcessSEHOPPolicy = 18
    ProcessActivationContextTrustPolicy = 19
    MaxProcessMitigationPolicy = 20
end

const PROCESS_MITIGATION_POLICY = _PROCESS_MITIGATION_POLICY

const PPROCESS_MITIGATION_POLICY = Ptr{_PROCESS_MITIGATION_POLICY}

struct _PROCESS_MITIGATION_ASLR_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_ASLR_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :EnableBottomUpRandomization && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :EnableForceRelocateImages && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :EnableHighEntropy && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :DisallowStrippedImages && return (Ptr{DWORD}(x + 0), 3, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 4, 28)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_ASLR_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_ASLR_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_ASLR_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_ASLR_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_ASLR_POLICY()
    ref = Ref{_PROCESS_MITIGATION_ASLR_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_ASLR_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_ASLR_POLICY = _PROCESS_MITIGATION_ASLR_POLICY

const PPROCESS_MITIGATION_ASLR_POLICY = Ptr{_PROCESS_MITIGATION_ASLR_POLICY}

struct _PROCESS_MITIGATION_DEP_POLICY
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_DEP_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :Enable && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :DisableAtlThunkEmulation && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 2, 30)
    f === :Permanent && return Ptr{BOOLEAN}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_DEP_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_DEP_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_DEP_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_DEP_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_DEP_POLICY(Permanent::BOOLEAN)
    ref = Ref{_PROCESS_MITIGATION_DEP_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_DEP_POLICY}, ref)
    ptr.Permanent = Permanent
    ref[]
end

const PROCESS_MITIGATION_DEP_POLICY = _PROCESS_MITIGATION_DEP_POLICY

const PPROCESS_MITIGATION_DEP_POLICY = Ptr{_PROCESS_MITIGATION_DEP_POLICY}

struct _PROCESS_MITIGATION_SEHOP_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_SEHOP_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :EnableSehop && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 1, 31)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_SEHOP_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_SEHOP_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_SEHOP_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_SEHOP_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_SEHOP_POLICY()
    ref = Ref{_PROCESS_MITIGATION_SEHOP_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_SEHOP_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_SEHOP_POLICY = _PROCESS_MITIGATION_SEHOP_POLICY

const PPROCESS_MITIGATION_SEHOP_POLICY = Ptr{_PROCESS_MITIGATION_SEHOP_POLICY}

struct _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :RaiseExceptionOnInvalidHandleReference && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :HandleExceptionsPermanentlyEnabled && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 2, 30)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY()
    ref = Ref{_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY = _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY

const PPROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY = Ptr{_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY}

struct _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :DisallowWin32kSystemCalls && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :AuditDisallowWin32kSystemCalls && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :DisallowFsctlSystemCalls && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :AuditDisallowFsctlSystemCalls && return (Ptr{DWORD}(x + 0), 3, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 4, 28)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY()
    ref = Ref{_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY

const PPROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY}

struct _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :DisableExtensionPoints && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 1, 31)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY()
    ref = Ref{_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY = _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY

const PPROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY = Ptr{_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY}

struct _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :ProhibitDynamicCode && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :AllowThreadOptOut && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :AllowRemoteDowngrade && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :AuditProhibitDynamicCode && return (Ptr{DWORD}(x + 0), 3, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 4, 28)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY()
    ref = Ref{_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY

const PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY = Ptr{_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY}

struct _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :EnableControlFlowGuard && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :EnableExportSuppression && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :StrictMode && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :EnableXfg && return (Ptr{DWORD}(x + 0), 3, 1)
    f === :EnableXfgAuditMode && return (Ptr{DWORD}(x + 0), 4, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 5, 27)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY()
    ref = Ref{_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY

const PPROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = Ptr{_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY}

struct _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :MicrosoftSignedOnly && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :StoreSignedOnly && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :MitigationOptIn && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :AuditMicrosoftSignedOnly && return (Ptr{DWORD}(x + 0), 3, 1)
    f === :AuditStoreSignedOnly && return (Ptr{DWORD}(x + 0), 4, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 5, 27)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY()
    ref = Ref{_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY

const PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = Ptr{_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY}

struct _PROCESS_MITIGATION_FONT_DISABLE_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_FONT_DISABLE_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :DisableNonSystemFonts && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :AuditNonSystemFontLoading && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 2, 30)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_FONT_DISABLE_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_FONT_DISABLE_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_FONT_DISABLE_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_FONT_DISABLE_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_FONT_DISABLE_POLICY()
    ref = Ref{_PROCESS_MITIGATION_FONT_DISABLE_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_FONT_DISABLE_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_FONT_DISABLE_POLICY = _PROCESS_MITIGATION_FONT_DISABLE_POLICY

const PPROCESS_MITIGATION_FONT_DISABLE_POLICY = Ptr{_PROCESS_MITIGATION_FONT_DISABLE_POLICY}

struct _PROCESS_MITIGATION_IMAGE_LOAD_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_IMAGE_LOAD_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :NoRemoteImages && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :NoLowMandatoryLabelImages && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :PreferSystem32Images && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :AuditNoRemoteImages && return (Ptr{DWORD}(x + 0), 3, 1)
    f === :AuditNoLowMandatoryLabelImages && return (Ptr{DWORD}(x + 0), 4, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 5, 27)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_IMAGE_LOAD_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_IMAGE_LOAD_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_IMAGE_LOAD_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_IMAGE_LOAD_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_IMAGE_LOAD_POLICY()
    ref = Ref{_PROCESS_MITIGATION_IMAGE_LOAD_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_IMAGE_LOAD_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_IMAGE_LOAD_POLICY = _PROCESS_MITIGATION_IMAGE_LOAD_POLICY

const PPROCESS_MITIGATION_IMAGE_LOAD_POLICY = Ptr{_PROCESS_MITIGATION_IMAGE_LOAD_POLICY}

struct _PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :FilterId && return (Ptr{DWORD}(x + 0), 0, 4)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 4, 28)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY()
    ref = Ref{_PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY = _PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY

const PPROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY = Ptr{_PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY}

struct _PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :EnableExportAddressFilter && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :AuditExportAddressFilter && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :EnableExportAddressFilterPlus && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :AuditExportAddressFilterPlus && return (Ptr{DWORD}(x + 0), 3, 1)
    f === :EnableImportAddressFilter && return (Ptr{DWORD}(x + 0), 4, 1)
    f === :AuditImportAddressFilter && return (Ptr{DWORD}(x + 0), 5, 1)
    f === :EnableRopStackPivot && return (Ptr{DWORD}(x + 0), 6, 1)
    f === :AuditRopStackPivot && return (Ptr{DWORD}(x + 0), 7, 1)
    f === :EnableRopCallerCheck && return (Ptr{DWORD}(x + 0), 8, 1)
    f === :AuditRopCallerCheck && return (Ptr{DWORD}(x + 0), 9, 1)
    f === :EnableRopSimExec && return (Ptr{DWORD}(x + 0), 10, 1)
    f === :AuditRopSimExec && return (Ptr{DWORD}(x + 0), 11, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 12, 20)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY()
    ref = Ref{_PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY = _PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY

const PPROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY = Ptr{_PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY}

struct _PROCESS_MITIGATION_CHILD_PROCESS_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_CHILD_PROCESS_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :NoChildProcessCreation && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :AuditNoChildProcessCreation && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :AllowSecureProcessCreation && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 3, 29)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_CHILD_PROCESS_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_CHILD_PROCESS_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_CHILD_PROCESS_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_CHILD_PROCESS_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_CHILD_PROCESS_POLICY()
    ref = Ref{_PROCESS_MITIGATION_CHILD_PROCESS_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_CHILD_PROCESS_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_CHILD_PROCESS_POLICY = _PROCESS_MITIGATION_CHILD_PROCESS_POLICY

const PPROCESS_MITIGATION_CHILD_PROCESS_POLICY = Ptr{_PROCESS_MITIGATION_CHILD_PROCESS_POLICY}

struct _PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :SmtBranchTargetIsolation && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :IsolateSecurityDomain && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :DisablePageCombine && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :SpeculativeStoreBypassDisable && return (Ptr{DWORD}(x + 0), 3, 1)
    f === :RestrictCoreSharing && return (Ptr{DWORD}(x + 0), 4, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 5, 27)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY()
    ref = Ref{_PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY = _PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY

const PPROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY = Ptr{_PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY}

struct _PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :EnableUserShadowStack && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :AuditUserShadowStack && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :SetContextIpValidation && return (Ptr{DWORD}(x + 0), 2, 1)
    f === :AuditSetContextIpValidation && return (Ptr{DWORD}(x + 0), 3, 1)
    f === :EnableUserShadowStackStrictMode && return (Ptr{DWORD}(x + 0), 4, 1)
    f === :BlockNonCetBinaries && return (Ptr{DWORD}(x + 0), 5, 1)
    f === :BlockNonCetBinariesNonEhcont && return (Ptr{DWORD}(x + 0), 6, 1)
    f === :AuditBlockNonCetBinaries && return (Ptr{DWORD}(x + 0), 7, 1)
    f === :CetDynamicApisOutOfProcOnly && return (Ptr{DWORD}(x + 0), 8, 1)
    f === :SetContextIpValidationRelaxedMode && return (Ptr{DWORD}(x + 0), 9, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 10, 22)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY()
    ref = Ref{_PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY = _PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY

const PPROCESS_MITIGATION_USER_SHADOW_STACK_POLICY = Ptr{_PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY}

struct _PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :EnablePointerAuthUserIp && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 1, 31)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY()
    ref = Ref{_PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY = _PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY

const PPROCESS_MITIGATION_USER_POINTER_AUTH_POLICY = Ptr{_PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY}

struct _PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :EnforceRedirectionTrust && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :AuditRedirectionTrust && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 2, 30)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY()
    ref = Ref{_PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY = _PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY

const PPROCESS_MITIGATION_REDIRECTION_TRUST_POLICY = Ptr{_PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY}

struct _PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :AssemblyManifestRedirectionTrust && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :ReservedFlags && return (Ptr{DWORD}(x + 0), 1, 31)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY, f::Symbol)
    r = Ref{_PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY()
    ref = Ref{_PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY}, ref)
    ref[]
end

const PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY = _PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY

const PPROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY = Ptr{_PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY}

struct _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    TotalUserTime::LARGE_INTEGER
    TotalKernelTime::LARGE_INTEGER
    ThisPeriodTotalUserTime::LARGE_INTEGER
    ThisPeriodTotalKernelTime::LARGE_INTEGER
    TotalPageFaultCount::DWORD
    TotalProcesses::DWORD
    ActiveProcesses::DWORD
    TotalTerminatedProcesses::DWORD
end

const JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION

const PJOBOBJECT_BASIC_ACCOUNTING_INFORMATION = Ptr{_JOBOBJECT_BASIC_ACCOUNTING_INFORMATION}

struct _JOBOBJECT_BASIC_LIMIT_INFORMATION
    PerProcessUserTimeLimit::LARGE_INTEGER
    PerJobUserTimeLimit::LARGE_INTEGER
    LimitFlags::DWORD
    MinimumWorkingSetSize::SIZE_T
    MaximumWorkingSetSize::SIZE_T
    ActiveProcessLimit::DWORD
    Affinity::ULONG_PTR
    PriorityClass::DWORD
    SchedulingClass::DWORD
end

const JOBOBJECT_BASIC_LIMIT_INFORMATION = _JOBOBJECT_BASIC_LIMIT_INFORMATION

const PJOBOBJECT_BASIC_LIMIT_INFORMATION = Ptr{_JOBOBJECT_BASIC_LIMIT_INFORMATION}

struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    BasicLimitInformation::JOBOBJECT_BASIC_LIMIT_INFORMATION
    IoInfo::IO_COUNTERS
    ProcessMemoryLimit::SIZE_T
    JobMemoryLimit::SIZE_T
    PeakProcessMemoryUsed::SIZE_T
    PeakJobMemoryUsed::SIZE_T
end

const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION

const PJOBOBJECT_EXTENDED_LIMIT_INFORMATION = Ptr{_JOBOBJECT_EXTENDED_LIMIT_INFORMATION}

struct _JOBOBJECT_BASIC_PROCESS_ID_LIST
    NumberOfAssignedProcesses::DWORD
    NumberOfProcessIdsInList::DWORD
    ProcessIdList::NTuple{1, ULONG_PTR}
end

const JOBOBJECT_BASIC_PROCESS_ID_LIST = _JOBOBJECT_BASIC_PROCESS_ID_LIST

const PJOBOBJECT_BASIC_PROCESS_ID_LIST = Ptr{_JOBOBJECT_BASIC_PROCESS_ID_LIST}

struct _JOBOBJECT_BASIC_UI_RESTRICTIONS
    UIRestrictionsClass::DWORD
end

const JOBOBJECT_BASIC_UI_RESTRICTIONS = _JOBOBJECT_BASIC_UI_RESTRICTIONS

const PJOBOBJECT_BASIC_UI_RESTRICTIONS = Ptr{_JOBOBJECT_BASIC_UI_RESTRICTIONS}

struct _JOBOBJECT_SECURITY_LIMIT_INFORMATION
    SecurityLimitFlags::DWORD
    JobToken::HANDLE
    SidsToDisable::PTOKEN_GROUPS
    PrivilegesToDelete::PTOKEN_PRIVILEGES
    RestrictedSids::PTOKEN_GROUPS
end

const JOBOBJECT_SECURITY_LIMIT_INFORMATION = _JOBOBJECT_SECURITY_LIMIT_INFORMATION

const PJOBOBJECT_SECURITY_LIMIT_INFORMATION = Ptr{_JOBOBJECT_SECURITY_LIMIT_INFORMATION}

struct _JOBOBJECT_END_OF_JOB_TIME_INFORMATION
    EndOfJobTimeAction::DWORD
end

const JOBOBJECT_END_OF_JOB_TIME_INFORMATION = _JOBOBJECT_END_OF_JOB_TIME_INFORMATION

const PJOBOBJECT_END_OF_JOB_TIME_INFORMATION = Ptr{_JOBOBJECT_END_OF_JOB_TIME_INFORMATION}

struct _JOBOBJECT_ASSOCIATE_COMPLETION_PORT
    CompletionKey::PVOID
    CompletionPort::HANDLE
end

const JOBOBJECT_ASSOCIATE_COMPLETION_PORT = _JOBOBJECT_ASSOCIATE_COMPLETION_PORT

const PJOBOBJECT_ASSOCIATE_COMPLETION_PORT = Ptr{_JOBOBJECT_ASSOCIATE_COMPLETION_PORT}

struct _JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
    BasicInfo::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    IoInfo::IO_COUNTERS
end

const JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION = _JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION

const PJOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION = Ptr{_JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION}

struct _JOBOBJECT_JOBSET_INFORMATION
    MemberLevel::DWORD
end

const JOBOBJECT_JOBSET_INFORMATION = _JOBOBJECT_JOBSET_INFORMATION

const PJOBOBJECT_JOBSET_INFORMATION = Ptr{_JOBOBJECT_JOBSET_INFORMATION}

@cenum _JOBOBJECT_RATE_CONTROL_TOLERANCE::UInt32 begin
    ToleranceLow = 1
    ToleranceMedium = 2
    ToleranceHigh = 3
end

const JOBOBJECT_RATE_CONTROL_TOLERANCE = _JOBOBJECT_RATE_CONTROL_TOLERANCE

const PJOBOBJECT_RATE_CONTROL_TOLERANCE = Ptr{_JOBOBJECT_RATE_CONTROL_TOLERANCE}

@cenum _JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL::UInt32 begin
    ToleranceIntervalShort = 1
    ToleranceIntervalMedium = 2
    ToleranceIntervalLong = 3
end

const JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL = _JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL

const PJOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL = Ptr{_JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL}

struct _JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION
    IoReadBytesLimit::DWORD64
    IoWriteBytesLimit::DWORD64
    PerJobUserTimeLimit::LARGE_INTEGER
    JobMemoryLimit::DWORD64
    RateControlTolerance::JOBOBJECT_RATE_CONTROL_TOLERANCE
    RateControlToleranceInterval::JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL
    LimitFlags::DWORD
end

const JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION = _JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION

const PJOBOBJECT_NOTIFICATION_LIMIT_INFORMATION = Ptr{_JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION}

struct JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2
    data::NTuple{72, UInt8}
end

function Base.getproperty(x::Ptr{JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2}, f::Symbol)
    f === :IoReadBytesLimit && return Ptr{DWORD64}(x + 0)
    f === :IoWriteBytesLimit && return Ptr{DWORD64}(x + 8)
    f === :PerJobUserTimeLimit && return Ptr{LARGE_INTEGER}(x + 16)
    f === :JobHighMemoryLimit && return Ptr{DWORD64}(x + 24)
    f === :JobMemoryLimit && return Ptr{DWORD64}(x + 24)
    f === :RateControlTolerance && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 32)
    f === :CpuRateControlTolerance && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 32)
    f === :RateControlToleranceInterval && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL}(x + 36)
    f === :CpuRateControlToleranceInterval && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL}(x + 36)
    f === :LimitFlags && return Ptr{DWORD}(x + 40)
    f === :IoRateControlTolerance && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 44)
    f === :JobLowMemoryLimit && return Ptr{DWORD64}(x + 48)
    f === :IoRateControlToleranceInterval && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL}(x + 56)
    f === :NetRateControlTolerance && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 60)
    f === :NetRateControlToleranceInterval && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL}(x + 64)
    return getfield(x, f)
end

function Base.getproperty(x::JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2, f::Symbol)
    r = Ref{JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2}(x)
    ptr = Base.unsafe_convert(Ptr{JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2(IoReadBytesLimit::DWORD64, IoWriteBytesLimit::DWORD64, PerJobUserTimeLimit::LARGE_INTEGER, LimitFlags::DWORD, IoRateControlTolerance::JOBOBJECT_RATE_CONTROL_TOLERANCE, JobLowMemoryLimit::DWORD64, IoRateControlToleranceInterval::JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL, NetRateControlTolerance::JOBOBJECT_RATE_CONTROL_TOLERANCE, NetRateControlToleranceInterval::JOBOBJECT_RATE_CONTROL_TOLERANCE_INTERVAL)
    ref = Ref{JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2}()
    ptr = Base.unsafe_convert(Ptr{JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2}, ref)
    ptr.IoReadBytesLimit = IoReadBytesLimit
    ptr.IoWriteBytesLimit = IoWriteBytesLimit
    ptr.PerJobUserTimeLimit = PerJobUserTimeLimit
    ptr.LimitFlags = LimitFlags
    ptr.IoRateControlTolerance = IoRateControlTolerance
    ptr.JobLowMemoryLimit = JobLowMemoryLimit
    ptr.IoRateControlToleranceInterval = IoRateControlToleranceInterval
    ptr.NetRateControlTolerance = NetRateControlTolerance
    ptr.NetRateControlToleranceInterval = NetRateControlToleranceInterval
    ref[]
end

struct _JOBOBJECT_LIMIT_VIOLATION_INFORMATION
    LimitFlags::DWORD
    ViolationLimitFlags::DWORD
    IoReadBytes::DWORD64
    IoReadBytesLimit::DWORD64
    IoWriteBytes::DWORD64
    IoWriteBytesLimit::DWORD64
    PerJobUserTime::LARGE_INTEGER
    PerJobUserTimeLimit::LARGE_INTEGER
    JobMemory::DWORD64
    JobMemoryLimit::DWORD64
    RateControlTolerance::JOBOBJECT_RATE_CONTROL_TOLERANCE
    RateControlToleranceLimit::JOBOBJECT_RATE_CONTROL_TOLERANCE
end

const JOBOBJECT_LIMIT_VIOLATION_INFORMATION = _JOBOBJECT_LIMIT_VIOLATION_INFORMATION

const PJOBOBJECT_LIMIT_VIOLATION_INFORMATION = Ptr{_JOBOBJECT_LIMIT_VIOLATION_INFORMATION}

struct JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2
    data::NTuple{104, UInt8}
end

function Base.getproperty(x::Ptr{JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2}, f::Symbol)
    f === :LimitFlags && return Ptr{DWORD}(x + 0)
    f === :ViolationLimitFlags && return Ptr{DWORD}(x + 4)
    f === :IoReadBytes && return Ptr{DWORD64}(x + 8)
    f === :IoReadBytesLimit && return Ptr{DWORD64}(x + 16)
    f === :IoWriteBytes && return Ptr{DWORD64}(x + 24)
    f === :IoWriteBytesLimit && return Ptr{DWORD64}(x + 32)
    f === :PerJobUserTime && return Ptr{LARGE_INTEGER}(x + 40)
    f === :PerJobUserTimeLimit && return Ptr{LARGE_INTEGER}(x + 48)
    f === :JobMemory && return Ptr{DWORD64}(x + 56)
    f === :JobHighMemoryLimit && return Ptr{DWORD64}(x + 64)
    f === :JobMemoryLimit && return Ptr{DWORD64}(x + 64)
    f === :RateControlTolerance && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 72)
    f === :CpuRateControlTolerance && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 72)
    f === :RateControlToleranceLimit && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 76)
    f === :CpuRateControlToleranceLimit && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 76)
    f === :JobLowMemoryLimit && return Ptr{DWORD64}(x + 80)
    f === :IoRateControlTolerance && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 88)
    f === :IoRateControlToleranceLimit && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 92)
    f === :NetRateControlTolerance && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 96)
    f === :NetRateControlToleranceLimit && return Ptr{JOBOBJECT_RATE_CONTROL_TOLERANCE}(x + 100)
    return getfield(x, f)
end

function Base.getproperty(x::JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2, f::Symbol)
    r = Ref{JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2}(x)
    ptr = Base.unsafe_convert(Ptr{JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2(LimitFlags::DWORD, ViolationLimitFlags::DWORD, IoReadBytes::DWORD64, IoReadBytesLimit::DWORD64, IoWriteBytes::DWORD64, IoWriteBytesLimit::DWORD64, PerJobUserTime::LARGE_INTEGER, PerJobUserTimeLimit::LARGE_INTEGER, JobMemory::DWORD64, JobLowMemoryLimit::DWORD64, IoRateControlTolerance::JOBOBJECT_RATE_CONTROL_TOLERANCE, IoRateControlToleranceLimit::JOBOBJECT_RATE_CONTROL_TOLERANCE, NetRateControlTolerance::JOBOBJECT_RATE_CONTROL_TOLERANCE, NetRateControlToleranceLimit::JOBOBJECT_RATE_CONTROL_TOLERANCE)
    ref = Ref{JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2}()
    ptr = Base.unsafe_convert(Ptr{JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2}, ref)
    ptr.LimitFlags = LimitFlags
    ptr.ViolationLimitFlags = ViolationLimitFlags
    ptr.IoReadBytes = IoReadBytes
    ptr.IoReadBytesLimit = IoReadBytesLimit
    ptr.IoWriteBytes = IoWriteBytes
    ptr.IoWriteBytesLimit = IoWriteBytesLimit
    ptr.PerJobUserTime = PerJobUserTime
    ptr.PerJobUserTimeLimit = PerJobUserTimeLimit
    ptr.JobMemory = JobMemory
    ptr.JobLowMemoryLimit = JobLowMemoryLimit
    ptr.IoRateControlTolerance = IoRateControlTolerance
    ptr.IoRateControlToleranceLimit = IoRateControlToleranceLimit
    ptr.NetRateControlTolerance = NetRateControlTolerance
    ptr.NetRateControlToleranceLimit = NetRateControlToleranceLimit
    ref[]
end

struct _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION}, f::Symbol)
    f === :ControlFlags && return Ptr{DWORD}(x + 0)
    f === :CpuRate && return Ptr{DWORD}(x + 4)
    f === :Weight && return Ptr{DWORD}(x + 4)
    f === :MinRate && return Ptr{WORD}(x + 4)
    f === :MaxRate && return Ptr{WORD}(x + 6)
    return getfield(x, f)
end

function Base.getproperty(x::_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, f::Symbol)
    r = Ref{_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION}(x)
    ptr = Base.unsafe_convert(Ptr{_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ControlFlags::DWORD)
    ref = Ref{_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION}()
    ptr = Base.unsafe_convert(Ptr{_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION}, ref)
    ptr.ControlFlags = ControlFlags
    ref[]
end

const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION

const PJOBOBJECT_CPU_RATE_CONTROL_INFORMATION = Ptr{_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION}

@cenum JOB_OBJECT_NET_RATE_CONTROL_FLAGS::UInt32 begin
    JOB_OBJECT_NET_RATE_CONTROL_ENABLE = 1
    JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH = 2
    JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG = 4
    JOB_OBJECT_NET_RATE_CONTROL_VALID_FLAGS = 7
end

struct JOBOBJECT_NET_RATE_CONTROL_INFORMATION
    MaxBandwidth::DWORD64
    ControlFlags::JOB_OBJECT_NET_RATE_CONTROL_FLAGS
    DscpTag::BYTE
end

@cenum JOB_OBJECT_IO_RATE_CONTROL_FLAGS::UInt32 begin
    JOB_OBJECT_IO_RATE_CONTROL_ENABLE = 1
    JOB_OBJECT_IO_RATE_CONTROL_STANDALONE_VOLUME = 2
    JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ALL = 4
    JOB_OBJECT_IO_RATE_CONTROL_FORCE_UNIT_ACCESS_ON_SOFT_CAP = 8
    JOB_OBJECT_IO_RATE_CONTROL_VALID_FLAGS = 15
end

struct JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE
    MaxIops::LONG64
    MaxBandwidth::LONG64
    ReservationIops::LONG64
    VolumeName::PWSTR
    BaseIoSize::DWORD
    ControlFlags::JOB_OBJECT_IO_RATE_CONTROL_FLAGS
    VolumeNameLength::WORD
end

const JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V1 = JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE

struct JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V2
    MaxIops::LONG64
    MaxBandwidth::LONG64
    ReservationIops::LONG64
    VolumeName::PWSTR
    BaseIoSize::DWORD
    ControlFlags::JOB_OBJECT_IO_RATE_CONTROL_FLAGS
    VolumeNameLength::WORD
    CriticalReservationIops::LONG64
    ReservationBandwidth::LONG64
    CriticalReservationBandwidth::LONG64
    MaxTimePercent::LONG64
    ReservationTimePercent::LONG64
    CriticalReservationTimePercent::LONG64
end

struct JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V3
    MaxIops::LONG64
    MaxBandwidth::LONG64
    ReservationIops::LONG64
    VolumeName::PWSTR
    BaseIoSize::DWORD
    ControlFlags::JOB_OBJECT_IO_RATE_CONTROL_FLAGS
    VolumeNameLength::WORD
    CriticalReservationIops::LONG64
    ReservationBandwidth::LONG64
    CriticalReservationBandwidth::LONG64
    MaxTimePercent::LONG64
    ReservationTimePercent::LONG64
    CriticalReservationTimePercent::LONG64
    SoftMaxIops::LONG64
    SoftMaxBandwidth::LONG64
    SoftMaxTimePercent::LONG64
    LimitExcessNotifyIops::LONG64
    LimitExcessNotifyBandwidth::LONG64
    LimitExcessNotifyTimePercent::LONG64
end

@cenum JOBOBJECT_IO_ATTRIBUTION_CONTROL_FLAGS::UInt32 begin
    JOBOBJECT_IO_ATTRIBUTION_CONTROL_ENABLE = 1
    JOBOBJECT_IO_ATTRIBUTION_CONTROL_DISABLE = 2
    JOBOBJECT_IO_ATTRIBUTION_CONTROL_VALID_FLAGS = 3
end

struct _JOBOBJECT_IO_ATTRIBUTION_STATS
    IoCount::ULONG_PTR
    TotalNonOverlappedQueueTime::ULONGLONG
    TotalNonOverlappedServiceTime::ULONGLONG
    TotalSize::ULONGLONG
end

const JOBOBJECT_IO_ATTRIBUTION_STATS = _JOBOBJECT_IO_ATTRIBUTION_STATS

const PJOBOBJECT_IO_ATTRIBUTION_STATS = Ptr{_JOBOBJECT_IO_ATTRIBUTION_STATS}

struct _JOBOBJECT_IO_ATTRIBUTION_INFORMATION
    ControlFlags::DWORD
    ReadStats::JOBOBJECT_IO_ATTRIBUTION_STATS
    WriteStats::JOBOBJECT_IO_ATTRIBUTION_STATS
end

const JOBOBJECT_IO_ATTRIBUTION_INFORMATION = _JOBOBJECT_IO_ATTRIBUTION_INFORMATION

const PJOBOBJECT_IO_ATTRIBUTION_INFORMATION = Ptr{_JOBOBJECT_IO_ATTRIBUTION_INFORMATION}

@cenum _JOBOBJECTINFOCLASS::UInt32 begin
    JobObjectBasicAccountingInformation = 1
    JobObjectBasicLimitInformation = 2
    JobObjectBasicProcessIdList = 3
    JobObjectBasicUIRestrictions = 4
    JobObjectSecurityLimitInformation = 5
    JobObjectEndOfJobTimeInformation = 6
    JobObjectAssociateCompletionPortInformation = 7
    JobObjectBasicAndIoAccountingInformation = 8
    JobObjectExtendedLimitInformation = 9
    JobObjectJobSetInformation = 10
    JobObjectGroupInformation = 11
    JobObjectNotificationLimitInformation = 12
    JobObjectLimitViolationInformation = 13
    JobObjectGroupInformationEx = 14
    JobObjectCpuRateControlInformation = 15
    JobObjectCompletionFilter = 16
    JobObjectCompletionCounter = 17
    JobObjectReserved1Information = 18
    JobObjectReserved2Information = 19
    JobObjectReserved3Information = 20
    JobObjectReserved4Information = 21
    JobObjectReserved5Information = 22
    JobObjectReserved6Information = 23
    JobObjectReserved7Information = 24
    JobObjectReserved8Information = 25
    JobObjectReserved9Information = 26
    JobObjectReserved10Information = 27
    JobObjectReserved11Information = 28
    JobObjectReserved12Information = 29
    JobObjectReserved13Information = 30
    JobObjectReserved14Information = 31
    JobObjectNetRateControlInformation = 32
    JobObjectNotificationLimitInformation2 = 33
    JobObjectLimitViolationInformation2 = 34
    JobObjectCreateSilo = 35
    JobObjectSiloBasicInformation = 36
    JobObjectReserved15Information = 37
    JobObjectReserved16Information = 38
    JobObjectReserved17Information = 39
    JobObjectReserved18Information = 40
    JobObjectReserved19Information = 41
    JobObjectReserved20Information = 42
    JobObjectReserved21Information = 43
    JobObjectReserved22Information = 44
    JobObjectReserved23Information = 45
    JobObjectReserved24Information = 46
    JobObjectReserved25Information = 47
    JobObjectReserved26Information = 48
    JobObjectReserved27Information = 49
    MaxJobObjectInfoClass = 50
end

const JOBOBJECTINFOCLASS = _JOBOBJECTINFOCLASS

struct _SILOOBJECT_BASIC_INFORMATION
    SiloId::DWORD
    SiloParentId::DWORD
    NumberOfProcesses::DWORD
    IsInServerSilo::BOOLEAN
    Reserved::NTuple{3, BYTE}
end

const SILOOBJECT_BASIC_INFORMATION = _SILOOBJECT_BASIC_INFORMATION

const PSILOOBJECT_BASIC_INFORMATION = Ptr{_SILOOBJECT_BASIC_INFORMATION}

@cenum _SERVERSILO_STATE::UInt32 begin
    SERVERSILO_INITING = 0
    SERVERSILO_STARTED = 1
    SERVERSILO_SHUTTING_DOWN = 2
    SERVERSILO_TERMINATING = 3
    SERVERSILO_TERMINATED = 4
end

const SERVERSILO_STATE = _SERVERSILO_STATE

const PSERVERSILO_STATE = Ptr{_SERVERSILO_STATE}

struct _SERVERSILO_BASIC_INFORMATION
    ServiceSessionId::DWORD
    State::SERVERSILO_STATE
    ExitStatus::DWORD
    IsDownlevelContainer::BOOLEAN
    ApiSetSchema::PVOID
    HostApiSetSchema::PVOID
end

const SERVERSILO_BASIC_INFORMATION = _SERVERSILO_BASIC_INFORMATION

const PSERVERSILO_BASIC_INFORMATION = Ptr{_SERVERSILO_BASIC_INFORMATION}

@cenum _FIRMWARE_TYPE::UInt32 begin
    FirmwareTypeUnknown = 0
    FirmwareTypeBios = 1
    FirmwareTypeUefi = 2
    FirmwareTypeMax = 3
end

const FIRMWARE_TYPE = _FIRMWARE_TYPE

const PFIRMWARE_TYPE = Ptr{_FIRMWARE_TYPE}

@cenum _LOGICAL_PROCESSOR_RELATIONSHIP::UInt32 begin
    RelationProcessorCore = 0
    RelationNumaNode = 1
    RelationCache = 2
    RelationProcessorPackage = 3
    RelationGroup = 4
    RelationProcessorDie = 5
    RelationNumaNodeEx = 6
    RelationProcessorModule = 7
    RelationAll = 65535
end

const LOGICAL_PROCESSOR_RELATIONSHIP = _LOGICAL_PROCESSOR_RELATIONSHIP

@cenum _PROCESSOR_CACHE_TYPE::UInt32 begin
    CacheUnified = 0
    CacheInstruction = 1
    CacheData = 2
    CacheTrace = 3
end

const PROCESSOR_CACHE_TYPE = _PROCESSOR_CACHE_TYPE

struct _CACHE_DESCRIPTOR
    Level::BYTE
    Associativity::BYTE
    LineSize::WORD
    Size::DWORD
    Type::PROCESSOR_CACHE_TYPE
end

const CACHE_DESCRIPTOR = _CACHE_DESCRIPTOR

const PCACHE_DESCRIPTOR = Ptr{_CACHE_DESCRIPTOR}

struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION}, f::Symbol)
    f === :ProcessorMask && return Ptr{ULONG_PTR}(x + 0)
    f === :Relationship && return Ptr{LOGICAL_PROCESSOR_RELATIONSHIP}(x + 8)
    f === :ProcessorCore && return Ptr{Cvoid}(x + 16)
    f === :NumaNode && return Ptr{Cvoid}(x + 16)
    f === :Cache && return Ptr{CACHE_DESCRIPTOR}(x + 16)
    f === :Reserved && return Ptr{NTuple{2, ULONGLONG}}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_SYSTEM_LOGICAL_PROCESSOR_INFORMATION, f::Symbol)
    r = Ref{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION}(x)
    ptr = Base.unsafe_convert(Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _SYSTEM_LOGICAL_PROCESSOR_INFORMATION(ProcessorMask::ULONG_PTR, Relationship::LOGICAL_PROCESSOR_RELATIONSHIP)
    ref = Ref{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION}()
    ptr = Base.unsafe_convert(Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION}, ref)
    ptr.ProcessorMask = ProcessorMask
    ptr.Relationship = Relationship
    ref[]
end

const SYSTEM_LOGICAL_PROCESSOR_INFORMATION = _SYSTEM_LOGICAL_PROCESSOR_INFORMATION

const PSYSTEM_LOGICAL_PROCESSOR_INFORMATION = Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION}

struct _PROCESSOR_RELATIONSHIP
    Flags::BYTE
    EfficiencyClass::BYTE
    Reserved::NTuple{20, BYTE}
    GroupCount::WORD
    GroupMask::NTuple{1, GROUP_AFFINITY}
end

const PROCESSOR_RELATIONSHIP = _PROCESSOR_RELATIONSHIP

const PPROCESSOR_RELATIONSHIP = Ptr{_PROCESSOR_RELATIONSHIP}

struct _NUMA_NODE_RELATIONSHIP
    data::NTuple{40, UInt8}
end

function Base.getproperty(x::Ptr{_NUMA_NODE_RELATIONSHIP}, f::Symbol)
    f === :NodeNumber && return Ptr{DWORD}(x + 0)
    f === :Reserved && return Ptr{NTuple{18, BYTE}}(x + 4)
    f === :GroupCount && return Ptr{WORD}(x + 22)
    f === :GroupMask && return Ptr{GROUP_AFFINITY}(x + 24)
    f === :GroupMasks && return Ptr{NTuple{1, GROUP_AFFINITY}}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_NUMA_NODE_RELATIONSHIP, f::Symbol)
    r = Ref{_NUMA_NODE_RELATIONSHIP}(x)
    ptr = Base.unsafe_convert(Ptr{_NUMA_NODE_RELATIONSHIP}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_NUMA_NODE_RELATIONSHIP}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _NUMA_NODE_RELATIONSHIP(NodeNumber::DWORD, Reserved::NTuple{18, BYTE}, GroupCount::WORD)
    ref = Ref{_NUMA_NODE_RELATIONSHIP}()
    ptr = Base.unsafe_convert(Ptr{_NUMA_NODE_RELATIONSHIP}, ref)
    ptr.NodeNumber = NodeNumber
    ptr.Reserved = Reserved
    ptr.GroupCount = GroupCount
    ref[]
end

const NUMA_NODE_RELATIONSHIP = _NUMA_NODE_RELATIONSHIP

const PNUMA_NODE_RELATIONSHIP = Ptr{_NUMA_NODE_RELATIONSHIP}

struct _CACHE_RELATIONSHIP
    data::NTuple{48, UInt8}
end

function Base.getproperty(x::Ptr{_CACHE_RELATIONSHIP}, f::Symbol)
    f === :Level && return Ptr{BYTE}(x + 0)
    f === :Associativity && return Ptr{BYTE}(x + 1)
    f === :LineSize && return Ptr{WORD}(x + 2)
    f === :CacheSize && return Ptr{DWORD}(x + 4)
    f === :Type && return Ptr{PROCESSOR_CACHE_TYPE}(x + 8)
    f === :Reserved && return Ptr{NTuple{18, BYTE}}(x + 12)
    f === :GroupCount && return Ptr{WORD}(x + 30)
    f === :GroupMask && return Ptr{GROUP_AFFINITY}(x + 32)
    f === :GroupMasks && return Ptr{NTuple{1, GROUP_AFFINITY}}(x + 32)
    return getfield(x, f)
end

function Base.getproperty(x::_CACHE_RELATIONSHIP, f::Symbol)
    r = Ref{_CACHE_RELATIONSHIP}(x)
    ptr = Base.unsafe_convert(Ptr{_CACHE_RELATIONSHIP}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_CACHE_RELATIONSHIP}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _CACHE_RELATIONSHIP(Level::BYTE, Associativity::BYTE, LineSize::WORD, CacheSize::DWORD, Type::PROCESSOR_CACHE_TYPE, Reserved::NTuple{18, BYTE}, GroupCount::WORD)
    ref = Ref{_CACHE_RELATIONSHIP}()
    ptr = Base.unsafe_convert(Ptr{_CACHE_RELATIONSHIP}, ref)
    ptr.Level = Level
    ptr.Associativity = Associativity
    ptr.LineSize = LineSize
    ptr.CacheSize = CacheSize
    ptr.Type = Type
    ptr.Reserved = Reserved
    ptr.GroupCount = GroupCount
    ref[]
end

const CACHE_RELATIONSHIP = _CACHE_RELATIONSHIP

const PCACHE_RELATIONSHIP = Ptr{_CACHE_RELATIONSHIP}

struct _PROCESSOR_GROUP_INFO
    MaximumProcessorCount::BYTE
    ActiveProcessorCount::BYTE
    Reserved::NTuple{38, BYTE}
    ActiveProcessorMask::KAFFINITY
end

const PROCESSOR_GROUP_INFO = _PROCESSOR_GROUP_INFO

const PPROCESSOR_GROUP_INFO = Ptr{_PROCESSOR_GROUP_INFO}

struct _GROUP_RELATIONSHIP
    MaximumGroupCount::WORD
    ActiveGroupCount::WORD
    Reserved::NTuple{20, BYTE}
    GroupInfo::NTuple{1, PROCESSOR_GROUP_INFO}
end

const GROUP_RELATIONSHIP = _GROUP_RELATIONSHIP

const PGROUP_RELATIONSHIP = Ptr{_GROUP_RELATIONSHIP}

struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
    data::NTuple{80, UInt8}
end

function Base.getproperty(x::Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX}, f::Symbol)
    f === :Relationship && return Ptr{LOGICAL_PROCESSOR_RELATIONSHIP}(x + 0)
    f === :Size && return Ptr{DWORD}(x + 4)
    f === :Processor && return Ptr{PROCESSOR_RELATIONSHIP}(x + 8)
    f === :NumaNode && return Ptr{NUMA_NODE_RELATIONSHIP}(x + 8)
    f === :Cache && return Ptr{CACHE_RELATIONSHIP}(x + 8)
    f === :Group && return Ptr{GROUP_RELATIONSHIP}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, f::Symbol)
    r = Ref{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX}(x)
    ptr = Base.unsafe_convert(Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX(Relationship::LOGICAL_PROCESSOR_RELATIONSHIP, Size::DWORD)
    ref = Ref{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX}()
    ptr = Base.unsafe_convert(Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX}, ref)
    ptr.Relationship = Relationship
    ptr.Size = Size
    ref[]
end

const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX = _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX

const PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX = Ptr{_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX}

@cenum _CPU_SET_INFORMATION_TYPE::UInt32 begin
    CpuSetInformation = 0
end

const CPU_SET_INFORMATION_TYPE = _CPU_SET_INFORMATION_TYPE

const PCPU_SET_INFORMATION_TYPE = Ptr{_CPU_SET_INFORMATION_TYPE}

struct _SYSTEM_CPU_SET_INFORMATION
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_SYSTEM_CPU_SET_INFORMATION}, f::Symbol)
    f === :Size && return Ptr{DWORD}(x + 0)
    f === :Type && return Ptr{CPU_SET_INFORMATION_TYPE}(x + 4)
    f === :CpuSet && return Ptr{Cvoid}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_SYSTEM_CPU_SET_INFORMATION, f::Symbol)
    r = Ref{_SYSTEM_CPU_SET_INFORMATION}(x)
    ptr = Base.unsafe_convert(Ptr{_SYSTEM_CPU_SET_INFORMATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_SYSTEM_CPU_SET_INFORMATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _SYSTEM_CPU_SET_INFORMATION(Size::DWORD, Type::CPU_SET_INFORMATION_TYPE)
    ref = Ref{_SYSTEM_CPU_SET_INFORMATION}()
    ptr = Base.unsafe_convert(Ptr{_SYSTEM_CPU_SET_INFORMATION}, ref)
    ptr.Size = Size
    ptr.Type = Type
    ref[]
end

const SYSTEM_CPU_SET_INFORMATION = _SYSTEM_CPU_SET_INFORMATION

const PSYSTEM_CPU_SET_INFORMATION = Ptr{_SYSTEM_CPU_SET_INFORMATION}

struct _SYSTEM_POOL_ZEROING_INFORMATION
    PoolZeroingSupportPresent::BOOLEAN
end

const SYSTEM_POOL_ZEROING_INFORMATION = _SYSTEM_POOL_ZEROING_INFORMATION

const PSYSTEM_POOL_ZEROING_INFORMATION = Ptr{_SYSTEM_POOL_ZEROING_INFORMATION}

struct _SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION
    CycleTime::DWORD64
end

const SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION = _SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION

const PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION = Ptr{_SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION}

struct _SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION}, f::Symbol)
    f === :Machine && return (Ptr{DWORD}(x + 0), 0, 16)
    f === :KernelMode && return (Ptr{DWORD}(x + 0), 16, 1)
    f === :UserMode && return (Ptr{DWORD}(x + 0), 17, 1)
    f === :Native && return (Ptr{DWORD}(x + 0), 18, 1)
    f === :Process && return (Ptr{DWORD}(x + 0), 19, 1)
    f === :WoW64Container && return (Ptr{DWORD}(x + 0), 20, 1)
    f === :ReservedZero0 && return (Ptr{DWORD}(x + 0), 21, 11)
    return getfield(x, f)
end

function Base.getproperty(x::_SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION, f::Symbol)
    r = Ref{_SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION}(x)
    ptr = Base.unsafe_convert(Ptr{_SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{_SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function _SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION(Machine::DWORD, KernelMode::DWORD, UserMode::DWORD, Native::DWORD, Process::DWORD, WoW64Container::DWORD, ReservedZero0::DWORD)
    ref = Ref{_SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION}()
    ptr = Base.unsafe_convert(Ptr{_SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION}, ref)
    ptr.Machine = Machine
    ptr.KernelMode = KernelMode
    ptr.UserMode = UserMode
    ptr.Native = Native
    ptr.Process = Process
    ptr.WoW64Container = WoW64Container
    ptr.ReservedZero0 = ReservedZero0
    ref[]
end

const SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION = _SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION

struct _XSTATE_FEATURE
    Offset::DWORD
    Size::DWORD
end

const XSTATE_FEATURE = _XSTATE_FEATURE

const PXSTATE_FEATURE = Ptr{_XSTATE_FEATURE}

struct _XSTATE_CONFIGURATION
    data::NTuple{840, UInt8}
end

function Base.getproperty(x::Ptr{_XSTATE_CONFIGURATION}, f::Symbol)
    f === :EnabledFeatures && return Ptr{DWORD64}(x + 0)
    f === :EnabledVolatileFeatures && return Ptr{DWORD64}(x + 8)
    f === :Size && return Ptr{DWORD}(x + 16)
    f === :ControlFlags && return Ptr{DWORD}(x + 20)
    f === :OptimizedSave && return (Ptr{DWORD}(x + 20), 0, 1)
    f === :CompactionEnabled && return (Ptr{DWORD}(x + 20), 1, 1)
    f === :ExtendedFeatureDisable && return (Ptr{DWORD}(x + 20), 2, 1)
    f === :Features && return Ptr{NTuple{64, XSTATE_FEATURE}}(x + 24)
    f === :EnabledSupervisorFeatures && return Ptr{DWORD64}(x + 536)
    f === :AlignedFeatures && return Ptr{DWORD64}(x + 544)
    f === :AllFeatureSize && return Ptr{DWORD}(x + 552)
    f === :AllFeatures && return Ptr{NTuple{64, DWORD}}(x + 556)
    f === :EnabledUserVisibleSupervisorFeatures && return Ptr{DWORD64}(x + 816)
    f === :ExtendedFeatureDisableFeatures && return Ptr{DWORD64}(x + 824)
    f === :AllNonLargeFeatureSize && return Ptr{DWORD}(x + 832)
    f === :Spare && return Ptr{DWORD}(x + 836)
    return getfield(x, f)
end

function Base.getproperty(x::_XSTATE_CONFIGURATION, f::Symbol)
    r = Ref{_XSTATE_CONFIGURATION}(x)
    ptr = Base.unsafe_convert(Ptr{_XSTATE_CONFIGURATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_XSTATE_CONFIGURATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _XSTATE_CONFIGURATION(EnabledFeatures::DWORD64, EnabledVolatileFeatures::DWORD64, Size::DWORD, Features::NTuple{64, XSTATE_FEATURE}, EnabledSupervisorFeatures::DWORD64, AlignedFeatures::DWORD64, AllFeatureSize::DWORD, AllFeatures::NTuple{64, DWORD}, EnabledUserVisibleSupervisorFeatures::DWORD64, ExtendedFeatureDisableFeatures::DWORD64, AllNonLargeFeatureSize::DWORD, Spare::DWORD)
    ref = Ref{_XSTATE_CONFIGURATION}()
    ptr = Base.unsafe_convert(Ptr{_XSTATE_CONFIGURATION}, ref)
    ptr.EnabledFeatures = EnabledFeatures
    ptr.EnabledVolatileFeatures = EnabledVolatileFeatures
    ptr.Size = Size
    ptr.Features = Features
    ptr.EnabledSupervisorFeatures = EnabledSupervisorFeatures
    ptr.AlignedFeatures = AlignedFeatures
    ptr.AllFeatureSize = AllFeatureSize
    ptr.AllFeatures = AllFeatures
    ptr.EnabledUserVisibleSupervisorFeatures = EnabledUserVisibleSupervisorFeatures
    ptr.ExtendedFeatureDisableFeatures = ExtendedFeatureDisableFeatures
    ptr.AllNonLargeFeatureSize = AllNonLargeFeatureSize
    ptr.Spare = Spare
    ref[]
end

const XSTATE_CONFIGURATION = _XSTATE_CONFIGURATION

const PXSTATE_CONFIGURATION = Ptr{_XSTATE_CONFIGURATION}

struct _MEMORY_BASIC_INFORMATION
    BaseAddress::PVOID
    AllocationBase::PVOID
    AllocationProtect::DWORD
    PartitionId::WORD
    RegionSize::SIZE_T
    State::DWORD
    Protect::DWORD
    Type::DWORD
end

const MEMORY_BASIC_INFORMATION = _MEMORY_BASIC_INFORMATION

const PMEMORY_BASIC_INFORMATION = Ptr{_MEMORY_BASIC_INFORMATION}

struct _MEMORY_BASIC_INFORMATION32
    BaseAddress::DWORD
    AllocationBase::DWORD
    AllocationProtect::DWORD
    RegionSize::DWORD
    State::DWORD
    Protect::DWORD
    Type::DWORD
end

const MEMORY_BASIC_INFORMATION32 = _MEMORY_BASIC_INFORMATION32

const PMEMORY_BASIC_INFORMATION32 = Ptr{_MEMORY_BASIC_INFORMATION32}

struct _MEMORY_BASIC_INFORMATION64
    BaseAddress::ULONGLONG
    AllocationBase::ULONGLONG
    AllocationProtect::DWORD
    __alignment1::DWORD
    RegionSize::ULONGLONG
    State::DWORD
    Protect::DWORD
    Type::DWORD
    __alignment2::DWORD
end

const MEMORY_BASIC_INFORMATION64 = _MEMORY_BASIC_INFORMATION64

const PMEMORY_BASIC_INFORMATION64 = Ptr{_MEMORY_BASIC_INFORMATION64}

struct _CFG_CALL_TARGET_INFO
    Offset::ULONG_PTR
    Flags::ULONG_PTR
end

const CFG_CALL_TARGET_INFO = _CFG_CALL_TARGET_INFO

const PCFG_CALL_TARGET_INFO = Ptr{_CFG_CALL_TARGET_INFO}

struct _MEM_ADDRESS_REQUIREMENTS
    LowestStartingAddress::PVOID
    HighestEndingAddress::PVOID
    Alignment::SIZE_T
end

const MEM_ADDRESS_REQUIREMENTS = _MEM_ADDRESS_REQUIREMENTS

const PMEM_ADDRESS_REQUIREMENTS = Ptr{_MEM_ADDRESS_REQUIREMENTS}

@cenum MEM_EXTENDED_PARAMETER_TYPE::UInt32 begin
    MemExtendedParameterInvalidType = 0
    MemExtendedParameterAddressRequirements = 1
    MemExtendedParameterNumaNode = 2
    MemExtendedParameterPartitionHandle = 3
    MemExtendedParameterUserPhysicalHandle = 4
    MemExtendedParameterAttributeFlags = 5
    MemExtendedParameterImageMachine = 6
    MemExtendedParameterMax = 7
end

const PMEM_EXTENDED_PARAMETER_TYPE = Ptr{MEM_EXTENDED_PARAMETER_TYPE}

struct MEM_EXTENDED_PARAMETER
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{MEM_EXTENDED_PARAMETER}, f::Symbol)
    f === :Type && return (Ptr{DWORD64}(x + 0), 0, 8)
    f === :Reserved && return (Ptr{DWORD64}(x + 0), 8, 56)
    f === :ULong64 && return Ptr{DWORD64}(x + 8)
    f === :Pointer && return Ptr{PVOID}(x + 8)
    f === :Size && return Ptr{SIZE_T}(x + 8)
    f === :Handle && return Ptr{HANDLE}(x + 8)
    f === :ULong && return Ptr{DWORD}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::MEM_EXTENDED_PARAMETER, f::Symbol)
    r = Ref{MEM_EXTENDED_PARAMETER}(x)
    ptr = Base.unsafe_convert(Ptr{MEM_EXTENDED_PARAMETER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{MEM_EXTENDED_PARAMETER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function MEM_EXTENDED_PARAMETER()
    ref = Ref{MEM_EXTENDED_PARAMETER}()
    ptr = Base.unsafe_convert(Ptr{MEM_EXTENDED_PARAMETER}, ref)
    ref[]
end

const PMEM_EXTENDED_PARAMETER = Ptr{MEM_EXTENDED_PARAMETER}

@cenum _MEM_DEDICATED_ATTRIBUTE_TYPE::UInt32 begin
    MemDedicatedAttributeReadBandwidth = 0
    MemDedicatedAttributeReadLatency = 1
    MemDedicatedAttributeWriteBandwidth = 2
    MemDedicatedAttributeWriteLatency = 3
    MemDedicatedAttributeMax = 4
end

const MEM_DEDICATED_ATTRIBUTE_TYPE = _MEM_DEDICATED_ATTRIBUTE_TYPE

const PMEM_DEDICATED_ATTRIBUTE_TYPE = Ptr{_MEM_DEDICATED_ATTRIBUTE_TYPE}

@cenum MEM_SECTION_EXTENDED_PARAMETER_TYPE::UInt32 begin
    MemSectionExtendedParameterInvalidType = 0
    MemSectionExtendedParameterUserPhysicalFlags = 1
    MemSectionExtendedParameterNumaNode = 2
    MemSectionExtendedParameterSigningLevel = 3
    MemSectionExtendedParameterMax = 4
end

const PMEM_SECTION_EXTENDED_PARAMETER_TYPE = Ptr{MEM_SECTION_EXTENDED_PARAMETER_TYPE}

struct _ENCLAVE_CREATE_INFO_SGX
    Secs::NTuple{4096, BYTE}
end

const ENCLAVE_CREATE_INFO_SGX = _ENCLAVE_CREATE_INFO_SGX

const PENCLAVE_CREATE_INFO_SGX = Ptr{_ENCLAVE_CREATE_INFO_SGX}

struct _ENCLAVE_INIT_INFO_SGX
    SigStruct::NTuple{1808, BYTE}
    Reserved1::NTuple{240, BYTE}
    EInitToken::NTuple{304, BYTE}
    Reserved2::NTuple{1744, BYTE}
end

const ENCLAVE_INIT_INFO_SGX = _ENCLAVE_INIT_INFO_SGX

const PENCLAVE_INIT_INFO_SGX = Ptr{_ENCLAVE_INIT_INFO_SGX}

struct _ENCLAVE_CREATE_INFO_VBS
    Flags::DWORD
    OwnerID::NTuple{32, BYTE}
end

const ENCLAVE_CREATE_INFO_VBS = _ENCLAVE_CREATE_INFO_VBS

const PENCLAVE_CREATE_INFO_VBS = Ptr{_ENCLAVE_CREATE_INFO_VBS}

struct _ENCLAVE_CREATE_INFO_VBS_BASIC
    Flags::DWORD
    OwnerID::NTuple{32, BYTE}
end

const ENCLAVE_CREATE_INFO_VBS_BASIC = _ENCLAVE_CREATE_INFO_VBS_BASIC

const PENCLAVE_CREATE_INFO_VBS_BASIC = Ptr{_ENCLAVE_CREATE_INFO_VBS_BASIC}

struct _ENCLAVE_LOAD_DATA_VBS_BASIC
    PageType::DWORD
end

const ENCLAVE_LOAD_DATA_VBS_BASIC = _ENCLAVE_LOAD_DATA_VBS_BASIC

const PENCLAVE_LOAD_DATA_VBS_BASIC = Ptr{_ENCLAVE_LOAD_DATA_VBS_BASIC}

struct _ENCLAVE_INIT_INFO_VBS_BASIC
    data::NTuple{56, UInt8}
end

function Base.getproperty(x::Ptr{_ENCLAVE_INIT_INFO_VBS_BASIC}, f::Symbol)
    f === :FamilyId && return Ptr{NTuple{16, BYTE}}(x + 0)
    f === :ImageId && return Ptr{NTuple{16, BYTE}}(x + 16)
    f === :EnclaveSize && return Ptr{ULONGLONG}(x + 32)
    f === :EnclaveSvn && return Ptr{DWORD}(x + 40)
    f === :Reserved && return Ptr{DWORD}(x + 44)
    f === :SignatureInfoHandle && return Ptr{HANDLE}(x + 48)
    f === :Unused && return Ptr{ULONGLONG}(x + 48)
    return getfield(x, f)
end

function Base.getproperty(x::_ENCLAVE_INIT_INFO_VBS_BASIC, f::Symbol)
    r = Ref{_ENCLAVE_INIT_INFO_VBS_BASIC}(x)
    ptr = Base.unsafe_convert(Ptr{_ENCLAVE_INIT_INFO_VBS_BASIC}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_ENCLAVE_INIT_INFO_VBS_BASIC}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _ENCLAVE_INIT_INFO_VBS_BASIC(FamilyId::NTuple{16, BYTE}, ImageId::NTuple{16, BYTE}, EnclaveSize::ULONGLONG, EnclaveSvn::DWORD, Reserved::DWORD)
    ref = Ref{_ENCLAVE_INIT_INFO_VBS_BASIC}()
    ptr = Base.unsafe_convert(Ptr{_ENCLAVE_INIT_INFO_VBS_BASIC}, ref)
    ptr.FamilyId = FamilyId
    ptr.ImageId = ImageId
    ptr.EnclaveSize = EnclaveSize
    ptr.EnclaveSvn = EnclaveSvn
    ptr.Reserved = Reserved
    ref[]
end

const ENCLAVE_INIT_INFO_VBS_BASIC = _ENCLAVE_INIT_INFO_VBS_BASIC

const PENCLAVE_INIT_INFO_VBS_BASIC = Ptr{_ENCLAVE_INIT_INFO_VBS_BASIC}

struct _ENCLAVE_INIT_INFO_VBS
    Length::DWORD
    ThreadCount::DWORD
end

const ENCLAVE_INIT_INFO_VBS = _ENCLAVE_INIT_INFO_VBS

const PENCLAVE_INIT_INFO_VBS = Ptr{_ENCLAVE_INIT_INFO_VBS}

# typedef PVOID ( ENCLAVE_TARGET_FUNCTION ) ( PVOID )
const ENCLAVE_TARGET_FUNCTION = Cvoid

# typedef ENCLAVE_TARGET_FUNCTION ( * PENCLAVE_TARGET_FUNCTION )
const PENCLAVE_TARGET_FUNCTION = Ptr{ENCLAVE_TARGET_FUNCTION}

const LPENCLAVE_TARGET_FUNCTION = PENCLAVE_TARGET_FUNCTION

struct _MEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE
    Type::MEM_DEDICATED_ATTRIBUTE_TYPE
    Reserved::DWORD
    Value::DWORD64
end

const MEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE = _MEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE

const PMEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE = Ptr{_MEMORY_PARTITION_DEDICATED_MEMORY_ATTRIBUTE}

struct _MEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION
    NextEntryOffset::DWORD
    SizeOfInformation::DWORD
    Flags::DWORD
    AttributesOffset::DWORD
    AttributeCount::DWORD
    Reserved::DWORD
    TypeId::DWORD64
end

const MEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION = _MEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION

const PMEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION = Ptr{_MEMORY_PARTITION_DEDICATED_MEMORY_INFORMATION}

struct _FILE_ID_128
    Identifier::NTuple{16, BYTE}
end

const FILE_ID_128 = _FILE_ID_128

const PFILE_ID_128 = Ptr{_FILE_ID_128}

struct _FILE_NOTIFY_INFORMATION
    NextEntryOffset::DWORD
    Action::DWORD
    FileNameLength::DWORD
    FileName::NTuple{1, WCHAR}
end

const FILE_NOTIFY_INFORMATION = _FILE_NOTIFY_INFORMATION

const PFILE_NOTIFY_INFORMATION = Ptr{_FILE_NOTIFY_INFORMATION}

struct _FILE_NOTIFY_EXTENDED_INFORMATION
    data::NTuple{88, UInt8}
end

function Base.getproperty(x::Ptr{_FILE_NOTIFY_EXTENDED_INFORMATION}, f::Symbol)
    f === :NextEntryOffset && return Ptr{DWORD}(x + 0)
    f === :Action && return Ptr{DWORD}(x + 4)
    f === :CreationTime && return Ptr{LARGE_INTEGER}(x + 8)
    f === :LastModificationTime && return Ptr{LARGE_INTEGER}(x + 16)
    f === :LastChangeTime && return Ptr{LARGE_INTEGER}(x + 24)
    f === :LastAccessTime && return Ptr{LARGE_INTEGER}(x + 32)
    f === :AllocatedLength && return Ptr{LARGE_INTEGER}(x + 40)
    f === :FileSize && return Ptr{LARGE_INTEGER}(x + 48)
    f === :FileAttributes && return Ptr{DWORD}(x + 56)
    f === :ReparsePointTag && return Ptr{DWORD}(x + 60)
    f === :EaSize && return Ptr{DWORD}(x + 60)
    f === :FileId && return Ptr{LARGE_INTEGER}(x + 64)
    f === :ParentFileId && return Ptr{LARGE_INTEGER}(x + 72)
    f === :FileNameLength && return Ptr{DWORD}(x + 80)
    f === :FileName && return Ptr{NTuple{1, WCHAR}}(x + 84)
    return getfield(x, f)
end

function Base.getproperty(x::_FILE_NOTIFY_EXTENDED_INFORMATION, f::Symbol)
    r = Ref{_FILE_NOTIFY_EXTENDED_INFORMATION}(x)
    ptr = Base.unsafe_convert(Ptr{_FILE_NOTIFY_EXTENDED_INFORMATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_FILE_NOTIFY_EXTENDED_INFORMATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _FILE_NOTIFY_EXTENDED_INFORMATION(NextEntryOffset::DWORD, Action::DWORD, CreationTime::LARGE_INTEGER, LastModificationTime::LARGE_INTEGER, LastChangeTime::LARGE_INTEGER, LastAccessTime::LARGE_INTEGER, AllocatedLength::LARGE_INTEGER, FileSize::LARGE_INTEGER, FileAttributes::DWORD, FileId::LARGE_INTEGER, ParentFileId::LARGE_INTEGER, FileNameLength::DWORD, FileName::NTuple{1, WCHAR})
    ref = Ref{_FILE_NOTIFY_EXTENDED_INFORMATION}()
    ptr = Base.unsafe_convert(Ptr{_FILE_NOTIFY_EXTENDED_INFORMATION}, ref)
    ptr.NextEntryOffset = NextEntryOffset
    ptr.Action = Action
    ptr.CreationTime = CreationTime
    ptr.LastModificationTime = LastModificationTime
    ptr.LastChangeTime = LastChangeTime
    ptr.LastAccessTime = LastAccessTime
    ptr.AllocatedLength = AllocatedLength
    ptr.FileSize = FileSize
    ptr.FileAttributes = FileAttributes
    ptr.FileId = FileId
    ptr.ParentFileId = ParentFileId
    ptr.FileNameLength = FileNameLength
    ptr.FileName = FileName
    ref[]
end

const FILE_NOTIFY_EXTENDED_INFORMATION = _FILE_NOTIFY_EXTENDED_INFORMATION

const PFILE_NOTIFY_EXTENDED_INFORMATION = Ptr{_FILE_NOTIFY_EXTENDED_INFORMATION}

struct _FILE_NOTIFY_FULL_INFORMATION
    data::NTuple{88, UInt8}
end

function Base.getproperty(x::Ptr{_FILE_NOTIFY_FULL_INFORMATION}, f::Symbol)
    f === :NextEntryOffset && return Ptr{DWORD}(x + 0)
    f === :Action && return Ptr{DWORD}(x + 4)
    f === :CreationTime && return Ptr{LARGE_INTEGER}(x + 8)
    f === :LastModificationTime && return Ptr{LARGE_INTEGER}(x + 16)
    f === :LastChangeTime && return Ptr{LARGE_INTEGER}(x + 24)
    f === :LastAccessTime && return Ptr{LARGE_INTEGER}(x + 32)
    f === :AllocatedLength && return Ptr{LARGE_INTEGER}(x + 40)
    f === :FileSize && return Ptr{LARGE_INTEGER}(x + 48)
    f === :FileAttributes && return Ptr{DWORD}(x + 56)
    f === :ReparsePointTag && return Ptr{DWORD}(x + 60)
    f === :EaSize && return Ptr{DWORD}(x + 60)
    f === :FileId && return Ptr{LARGE_INTEGER}(x + 64)
    f === :ParentFileId && return Ptr{LARGE_INTEGER}(x + 72)
    f === :FileNameLength && return Ptr{WORD}(x + 80)
    f === :FileNameFlags && return Ptr{BYTE}(x + 82)
    f === :Reserved && return Ptr{BYTE}(x + 83)
    f === :FileName && return Ptr{NTuple{1, WCHAR}}(x + 84)
    return getfield(x, f)
end

function Base.getproperty(x::_FILE_NOTIFY_FULL_INFORMATION, f::Symbol)
    r = Ref{_FILE_NOTIFY_FULL_INFORMATION}(x)
    ptr = Base.unsafe_convert(Ptr{_FILE_NOTIFY_FULL_INFORMATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_FILE_NOTIFY_FULL_INFORMATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _FILE_NOTIFY_FULL_INFORMATION(NextEntryOffset::DWORD, Action::DWORD, CreationTime::LARGE_INTEGER, LastModificationTime::LARGE_INTEGER, LastChangeTime::LARGE_INTEGER, LastAccessTime::LARGE_INTEGER, AllocatedLength::LARGE_INTEGER, FileSize::LARGE_INTEGER, FileAttributes::DWORD, FileId::LARGE_INTEGER, ParentFileId::LARGE_INTEGER, FileNameLength::WORD, FileNameFlags::BYTE, Reserved::BYTE, FileName::NTuple{1, WCHAR})
    ref = Ref{_FILE_NOTIFY_FULL_INFORMATION}()
    ptr = Base.unsafe_convert(Ptr{_FILE_NOTIFY_FULL_INFORMATION}, ref)
    ptr.NextEntryOffset = NextEntryOffset
    ptr.Action = Action
    ptr.CreationTime = CreationTime
    ptr.LastModificationTime = LastModificationTime
    ptr.LastChangeTime = LastChangeTime
    ptr.LastAccessTime = LastAccessTime
    ptr.AllocatedLength = AllocatedLength
    ptr.FileSize = FileSize
    ptr.FileAttributes = FileAttributes
    ptr.FileId = FileId
    ptr.ParentFileId = ParentFileId
    ptr.FileNameLength = FileNameLength
    ptr.FileNameFlags = FileNameFlags
    ptr.Reserved = Reserved
    ptr.FileName = FileName
    ref[]
end

const FILE_NOTIFY_FULL_INFORMATION = _FILE_NOTIFY_FULL_INFORMATION

const PFILE_NOTIFY_FULL_INFORMATION = Ptr{_FILE_NOTIFY_FULL_INFORMATION}

struct _FILE_SEGMENT_ELEMENT
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_FILE_SEGMENT_ELEMENT}, f::Symbol)
    f === :Buffer && return Ptr{PVOID64}(x + 0)
    f === :Alignment && return Ptr{ULONGLONG}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_FILE_SEGMENT_ELEMENT, f::Symbol)
    r = Ref{_FILE_SEGMENT_ELEMENT}(x)
    ptr = Base.unsafe_convert(Ptr{_FILE_SEGMENT_ELEMENT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_FILE_SEGMENT_ELEMENT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__FILE_SEGMENT_ELEMENT = Union{PVOID64, ULONGLONG}

function _FILE_SEGMENT_ELEMENT(val::__U__FILE_SEGMENT_ELEMENT)
    ref = Ref{_FILE_SEGMENT_ELEMENT}()
    ptr = Base.unsafe_convert(Ptr{_FILE_SEGMENT_ELEMENT}, ref)
    if val isa PVOID64
        ptr.Buffer = val
    elseif val isa ULONGLONG
        ptr.Alignment = val
    end
    ref[]
end

const FILE_SEGMENT_ELEMENT = _FILE_SEGMENT_ELEMENT

const PFILE_SEGMENT_ELEMENT = Ptr{_FILE_SEGMENT_ELEMENT}

const PREPARSE_GUID_DATA_BUFFER = Ptr{_REPARSE_GUID_DATA_BUFFER}

struct _REARRANGE_FILE_DATA
    SourceStartingOffset::ULONGLONG
    TargetOffset::ULONGLONG
    SourceFileHandle::HANDLE
    Length::DWORD
    Flags::DWORD
end

const REARRANGE_FILE_DATA = _REARRANGE_FILE_DATA

const PREARRANGE_FILE_DATA = Ptr{_REARRANGE_FILE_DATA}

struct _REARRANGE_FILE_DATA32
    SourceStartingOffset::ULONGLONG
    TargetOffset::ULONGLONG
    SourceFileHandle::UINT32
    Length::DWORD
    Flags::DWORD
end

const REARRANGE_FILE_DATA32 = _REARRANGE_FILE_DATA32

const PREARRANGE_FILE_DATA32 = Ptr{_REARRANGE_FILE_DATA32}

@cenum _SYSTEM_POWER_STATE::UInt32 begin
    PowerSystemUnspecified = 0
    PowerSystemWorking = 1
    PowerSystemSleeping1 = 2
    PowerSystemSleeping2 = 3
    PowerSystemSleeping3 = 4
    PowerSystemHibernate = 5
    PowerSystemShutdown = 6
    PowerSystemMaximum = 7
end

const SYSTEM_POWER_STATE = _SYSTEM_POWER_STATE

const PSYSTEM_POWER_STATE = Ptr{_SYSTEM_POWER_STATE}

@cenum __JL_Ctag_3::UInt32 begin
    PowerActionNone = 0
    PowerActionReserved = 1
    PowerActionSleep = 2
    PowerActionHibernate = 3
    PowerActionShutdown = 4
    PowerActionShutdownReset = 5
    PowerActionShutdownOff = 6
    PowerActionWarmEject = 7
    PowerActionDisplayOff = 8
end

const POWER_ACTION = Cvoid

const PPOWER_ACTION = Ptr{Cvoid}

@cenum _DEVICE_POWER_STATE::UInt32 begin
    PowerDeviceUnspecified = 0
    PowerDeviceD0 = 1
    PowerDeviceD1 = 2
    PowerDeviceD2 = 3
    PowerDeviceD3 = 4
    PowerDeviceMaximum = 5
end

const DEVICE_POWER_STATE = _DEVICE_POWER_STATE

const PDEVICE_POWER_STATE = Ptr{_DEVICE_POWER_STATE}

@cenum _MONITOR_DISPLAY_STATE::UInt32 begin
    PowerMonitorOff = 0
    PowerMonitorOn = 1
    PowerMonitorDim = 2
end

const MONITOR_DISPLAY_STATE = _MONITOR_DISPLAY_STATE

const PMONITOR_DISPLAY_STATE = Ptr{_MONITOR_DISPLAY_STATE}

@cenum _USER_ACTIVITY_PRESENCE::UInt32 begin
    PowerUserPresent = 0
    PowerUserNotPresent = 1
    PowerUserInactive = 2
    PowerUserMaximum = 3
    PowerUserInvalid = 3
end

const USER_ACTIVITY_PRESENCE = _USER_ACTIVITY_PRESENCE

const PUSER_ACTIVITY_PRESENCE = Ptr{_USER_ACTIVITY_PRESENCE}

const EXECUTION_STATE = DWORD

const PEXECUTION_STATE = Ptr{DWORD}

@cenum LATENCY_TIME::UInt32 begin
    LT_DONT_CARE = 0
    LT_LOWEST_LATENCY = 1
end

@cenum _POWER_REQUEST_TYPE::UInt32 begin
    PowerRequestDisplayRequired = 0
    PowerRequestSystemRequired = 1
    PowerRequestAwayModeRequired = 2
    PowerRequestExecutionRequired = 3
end

const POWER_REQUEST_TYPE = _POWER_REQUEST_TYPE

const PPOWER_REQUEST_TYPE = Ptr{_POWER_REQUEST_TYPE}

struct CM_Power_Data_s
    PD_Size::DWORD
    PD_MostRecentPowerState::DEVICE_POWER_STATE
    PD_Capabilities::DWORD
    PD_D1Latency::DWORD
    PD_D2Latency::DWORD
    PD_D3Latency::DWORD
    PD_PowerStateMapping::NTuple{7, DEVICE_POWER_STATE}
    PD_DeepestSystemWake::SYSTEM_POWER_STATE
end

const CM_POWER_DATA = CM_Power_Data_s

const PCM_POWER_DATA = Ptr{CM_Power_Data_s}

@cenum POWER_INFORMATION_LEVEL::UInt32 begin
    SystemPowerPolicyAc = 0
    SystemPowerPolicyDc = 1
    VerifySystemPolicyAc = 2
    VerifySystemPolicyDc = 3
    SystemPowerCapabilities = 4
    SystemBatteryState = 5
    SystemPowerStateHandler = 6
    ProcessorStateHandler = 7
    SystemPowerPolicyCurrent = 8
    AdministratorPowerPolicy = 9
    SystemReserveHiberFile = 10
    ProcessorInformation = 11
    SystemPowerInformation = 12
    ProcessorStateHandler2 = 13
    LastWakeTime = 14
    LastSleepTime = 15
    SystemExecutionState = 16
    SystemPowerStateNotifyHandler = 17
    ProcessorPowerPolicyAc = 18
    ProcessorPowerPolicyDc = 19
    VerifyProcessorPowerPolicyAc = 20
    VerifyProcessorPowerPolicyDc = 21
    ProcessorPowerPolicyCurrent = 22
    SystemPowerStateLogging = 23
    SystemPowerLoggingEntry = 24
    SetPowerSettingValue = 25
    NotifyUserPowerSetting = 26
    PowerInformationLevelUnused0 = 27
    SystemMonitorHiberBootPowerOff = 28
    SystemVideoState = 29
    TraceApplicationPowerMessage = 30
    TraceApplicationPowerMessageEnd = 31
    ProcessorPerfStates = 32
    ProcessorIdleStates = 33
    ProcessorCap = 34
    SystemWakeSource = 35
    SystemHiberFileInformation = 36
    TraceServicePowerMessage = 37
    ProcessorLoad = 38
    PowerShutdownNotification = 39
    MonitorCapabilities = 40
    SessionPowerInit = 41
    SessionDisplayState = 42
    PowerRequestCreate = 43
    PowerRequestAction = 44
    GetPowerRequestList = 45
    ProcessorInformationEx = 46
    NotifyUserModeLegacyPowerEvent = 47
    GroupPark = 48
    ProcessorIdleDomains = 49
    WakeTimerList = 50
    SystemHiberFileSize = 51
    ProcessorIdleStatesHv = 52
    ProcessorPerfStatesHv = 53
    ProcessorPerfCapHv = 54
    ProcessorSetIdle = 55
    LogicalProcessorIdling = 56
    UserPresence = 57
    PowerSettingNotificationName = 58
    GetPowerSettingValue = 59
    IdleResiliency = 60
    SessionRITState = 61
    SessionConnectNotification = 62
    SessionPowerCleanup = 63
    SessionLockState = 64
    SystemHiberbootState = 65
    PlatformInformation = 66
    PdcInvocation = 67
    MonitorInvocation = 68
    FirmwareTableInformationRegistered = 69
    SetShutdownSelectedTime = 70
    SuspendResumeInvocation = 71
    PlmPowerRequestCreate = 72
    ScreenOff = 73
    CsDeviceNotification = 74
    PlatformRole = 75
    LastResumePerformance = 76
    DisplayBurst = 77
    ExitLatencySamplingPercentage = 78
    RegisterSpmPowerSettings = 79
    PlatformIdleStates = 80
    ProcessorIdleVeto = 81
    PlatformIdleVeto = 82
    SystemBatteryStatePrecise = 83
    ThermalEvent = 84
    PowerRequestActionInternal = 85
    BatteryDeviceState = 86
    PowerInformationInternal = 87
    ThermalStandby = 88
    SystemHiberFileType = 89
    PhysicalPowerButtonPress = 90
    QueryPotentialDripsConstraint = 91
    EnergyTrackerCreate = 92
    EnergyTrackerQuery = 93
    UpdateBlackBoxRecorder = 94
    SessionAllowExternalDmaDevices = 95
    SendSuspendResumeNotification = 96
    BlackBoxRecorderDirectAccessBuffer = 97
    PowerInformationLevelMaximum = 98
end

@cenum __JL_Ctag_6::UInt32 begin
    UserNotPresent = 0
    UserPresent = 1
    UserUnknown = 255
end

const POWER_USER_PRESENCE_TYPE = Cvoid

const PPOWER_USER_PRESENCE_TYPE = Ptr{Cvoid}

struct _POWER_USER_PRESENCE
    UserPresence::POWER_USER_PRESENCE_TYPE
end

const POWER_USER_PRESENCE = _POWER_USER_PRESENCE

const PPOWER_USER_PRESENCE = Ptr{_POWER_USER_PRESENCE}

struct _POWER_SESSION_CONNECT
    Connected::BOOLEAN
    Console::BOOLEAN
end

const POWER_SESSION_CONNECT = _POWER_SESSION_CONNECT

const PPOWER_SESSION_CONNECT = Ptr{_POWER_SESSION_CONNECT}

struct _POWER_SESSION_TIMEOUTS
    InputTimeout::DWORD
    DisplayTimeout::DWORD
end

const POWER_SESSION_TIMEOUTS = _POWER_SESSION_TIMEOUTS

const PPOWER_SESSION_TIMEOUTS = Ptr{_POWER_SESSION_TIMEOUTS}

struct _POWER_SESSION_RIT_STATE
    Active::BOOLEAN
    LastInputTime::DWORD64
end

const POWER_SESSION_RIT_STATE = _POWER_SESSION_RIT_STATE

const PPOWER_SESSION_RIT_STATE = Ptr{_POWER_SESSION_RIT_STATE}

struct _POWER_SESSION_WINLOGON
    SessionId::DWORD
    Console::BOOLEAN
    Locked::BOOLEAN
end

const POWER_SESSION_WINLOGON = _POWER_SESSION_WINLOGON

const PPOWER_SESSION_WINLOGON = Ptr{_POWER_SESSION_WINLOGON}

struct _POWER_SESSION_ALLOW_EXTERNAL_DMA_DEVICES
    IsAllowed::BOOLEAN
end

const POWER_SESSION_ALLOW_EXTERNAL_DMA_DEVICES = _POWER_SESSION_ALLOW_EXTERNAL_DMA_DEVICES

const PPOWER_SESSION_ALLOW_EXTERNAL_DMA_DEVICES = Ptr{_POWER_SESSION_ALLOW_EXTERNAL_DMA_DEVICES}

struct _POWER_IDLE_RESILIENCY
    CoalescingTimeout::DWORD
    IdleResiliencyPeriod::DWORD
end

const POWER_IDLE_RESILIENCY = _POWER_IDLE_RESILIENCY

const PPOWER_IDLE_RESILIENCY = Ptr{_POWER_IDLE_RESILIENCY}

@cenum POWER_MONITOR_REQUEST_REASON::UInt32 begin
    MonitorRequestReasonUnknown = 0
    MonitorRequestReasonPowerButton = 1
    MonitorRequestReasonRemoteConnection = 2
    MonitorRequestReasonScMonitorpower = 3
    MonitorRequestReasonUserInput = 4
    MonitorRequestReasonAcDcDisplayBurst = 5
    MonitorRequestReasonUserDisplayBurst = 6
    MonitorRequestReasonPoSetSystemState = 7
    MonitorRequestReasonSetThreadExecutionState = 8
    MonitorRequestReasonFullWake = 9
    MonitorRequestReasonSessionUnlock = 10
    MonitorRequestReasonScreenOffRequest = 11
    MonitorRequestReasonIdleTimeout = 12
    MonitorRequestReasonPolicyChange = 13
    MonitorRequestReasonSleepButton = 14
    MonitorRequestReasonLid = 15
    MonitorRequestReasonBatteryCountChange = 16
    MonitorRequestReasonGracePeriod = 17
    MonitorRequestReasonPnP = 18
    MonitorRequestReasonDP = 19
    MonitorRequestReasonSxTransition = 20
    MonitorRequestReasonSystemIdle = 21
    MonitorRequestReasonNearProximity = 22
    MonitorRequestReasonThermalStandby = 23
    MonitorRequestReasonResumePdc = 24
    MonitorRequestReasonResumeS4 = 25
    MonitorRequestReasonTerminal = 26
    MonitorRequestReasonPdcSignal = 27
    MonitorRequestReasonAcDcDisplayBurstSuppressed = 28
    MonitorRequestReasonSystemStateEntered = 29
    MonitorRequestReasonWinrt = 30
    MonitorRequestReasonUserInputKeyboard = 31
    MonitorRequestReasonUserInputMouse = 32
    MonitorRequestReasonUserInputTouchpad = 33
    MonitorRequestReasonUserInputPen = 34
    MonitorRequestReasonUserInputAccelerometer = 35
    MonitorRequestReasonUserInputHid = 36
    MonitorRequestReasonUserInputPoUserPresent = 37
    MonitorRequestReasonUserInputSessionSwitch = 38
    MonitorRequestReasonUserInputInitialization = 39
    MonitorRequestReasonPdcSignalWindowsMobilePwrNotif = 40
    MonitorRequestReasonPdcSignalWindowsMobileShell = 41
    MonitorRequestReasonPdcSignalHeyCortana = 42
    MonitorRequestReasonPdcSignalHolographicShell = 43
    MonitorRequestReasonPdcSignalFingerprint = 44
    MonitorRequestReasonDirectedDrips = 45
    MonitorRequestReasonDim = 46
    MonitorRequestReasonBuiltinPanel = 47
    MonitorRequestReasonDisplayRequiredUnDim = 48
    MonitorRequestReasonBatteryCountChangeSuppressed = 49
    MonitorRequestReasonResumeModernStandby = 50
    MonitorRequestReasonTerminalInit = 51
    MonitorRequestReasonPdcSignalSensorsHumanPresence = 52
    MonitorRequestReasonBatteryPreCritical = 53
    MonitorRequestReasonUserInputTouch = 54
    MonitorRequestReasonMax = 55
end

@cenum _POWER_MONITOR_REQUEST_TYPE::UInt32 begin
    MonitorRequestTypeOff = 0
    MonitorRequestTypeOnAndPresent = 1
    MonitorRequestTypeToggleOn = 2
end

const POWER_MONITOR_REQUEST_TYPE = _POWER_MONITOR_REQUEST_TYPE

struct _POWER_MONITOR_INVOCATION
    Console::BOOLEAN
    RequestReason::POWER_MONITOR_REQUEST_REASON
end

const POWER_MONITOR_INVOCATION = _POWER_MONITOR_INVOCATION

const PPOWER_MONITOR_INVOCATION = Ptr{_POWER_MONITOR_INVOCATION}

struct _RESUME_PERFORMANCE
    PostTimeMs::DWORD
    TotalResumeTimeMs::ULONGLONG
    ResumeCompleteTimestamp::ULONGLONG
end

const RESUME_PERFORMANCE = _RESUME_PERFORMANCE

const PRESUME_PERFORMANCE = Ptr{_RESUME_PERFORMANCE}

@cenum SYSTEM_POWER_CONDITION::UInt32 begin
    PoAc = 0
    PoDc = 1
    PoHot = 2
    PoConditionMaximum = 3
end

struct __JL_Ctag_9
    Version::DWORD
    Guid::GUID
    PowerCondition::SYSTEM_POWER_CONDITION
    DataLength::DWORD
    Data::NTuple{1, BYTE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_9}, f::Symbol)
    f === :Version && return Ptr{DWORD}(x + 0)
    f === :Guid && return Ptr{GUID}(x + 4)
    f === :PowerCondition && return Ptr{SYSTEM_POWER_CONDITION}(x + 20)
    f === :DataLength && return Ptr{DWORD}(x + 24)
    f === :Data && return Ptr{NTuple{1, BYTE}}(x + 28)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_9, f::Symbol)
    r = Ref{__JL_Ctag_9}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_9}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_9}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const SET_POWER_SETTING_VALUE = __JL_Ctag_9

const PSET_POWER_SETTING_VALUE = Ptr{__JL_Ctag_9}

struct __JL_Ctag_10
    Guid::GUID
end
function Base.getproperty(x::Ptr{__JL_Ctag_10}, f::Symbol)
    f === :Guid && return Ptr{GUID}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_10, f::Symbol)
    r = Ref{__JL_Ctag_10}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_10}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_10}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const NOTIFY_USER_POWER_SETTING = __JL_Ctag_10

const PNOTIFY_USER_POWER_SETTING = Ptr{__JL_Ctag_10}

struct _APPLICATIONLAUNCH_SETTING_VALUE
    ActivationTime::LARGE_INTEGER
    Flags::DWORD
    ButtonInstanceID::DWORD
end

const APPLICATIONLAUNCH_SETTING_VALUE = _APPLICATIONLAUNCH_SETTING_VALUE

const PAPPLICATIONLAUNCH_SETTING_VALUE = Ptr{_APPLICATIONLAUNCH_SETTING_VALUE}

@cenum _POWER_PLATFORM_ROLE::UInt32 begin
    PlatformRoleUnspecified = 0
    PlatformRoleDesktop = 1
    PlatformRoleMobile = 2
    PlatformRoleWorkstation = 3
    PlatformRoleEnterpriseServer = 4
    PlatformRoleSOHOServer = 5
    PlatformRoleAppliancePC = 6
    PlatformRolePerformanceServer = 7
    PlatformRoleSlate = 8
    PlatformRoleMaximum = 9
end

const POWER_PLATFORM_ROLE = _POWER_PLATFORM_ROLE

const PPOWER_PLATFORM_ROLE = Ptr{_POWER_PLATFORM_ROLE}

struct _POWER_PLATFORM_INFORMATION
    AoAc::BOOLEAN
end

const POWER_PLATFORM_INFORMATION = _POWER_PLATFORM_INFORMATION

const PPOWER_PLATFORM_INFORMATION = Ptr{_POWER_PLATFORM_INFORMATION}

@cenum POWER_SETTING_ALTITUDE::UInt32 begin
    ALTITUDE_GROUP_POLICY = 0
    ALTITUDE_USER = 1
    ALTITUDE_RUNTIME_OVERRIDE = 2
    ALTITUDE_PROVISIONING = 3
    ALTITUDE_OEM_CUSTOMIZATION = 4
    ALTITUDE_INTERNAL_OVERRIDE = 5
    ALTITUDE_OS_DEFAULT = 6
end

const PPOWER_SETTING_ALTITUDE = Ptr{POWER_SETTING_ALTITUDE}

struct __JL_Ctag_11
    Granularity::DWORD
    Capacity::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_11}, f::Symbol)
    f === :Granularity && return Ptr{DWORD}(x + 0)
    f === :Capacity && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_11, f::Symbol)
    r = Ref{__JL_Ctag_11}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_11}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_11}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const BATTERY_REPORTING_SCALE = __JL_Ctag_11

const PBATTERY_REPORTING_SCALE = Ptr{__JL_Ctag_11}

struct __JL_Ctag_12
    Frequency::DWORD
    Flags::DWORD
    PercentFrequency::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_12}, f::Symbol)
    f === :Frequency && return Ptr{DWORD}(x + 0)
    f === :Flags && return Ptr{DWORD}(x + 4)
    f === :PercentFrequency && return Ptr{DWORD}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_12, f::Symbol)
    r = Ref{__JL_Ctag_12}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_12}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_12}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_WMI_LEGACY_PERFSTATE = __JL_Ctag_12

const PPPM_WMI_LEGACY_PERFSTATE = Ptr{__JL_Ctag_12}

struct __JL_Ctag_13
    Latency::DWORD
    Power::DWORD
    TimeCheck::DWORD
    PromotePercent::BYTE
    DemotePercent::BYTE
    StateType::BYTE
    Reserved::BYTE
    StateFlags::DWORD
    Context::DWORD
    IdleHandler::DWORD
    Reserved1::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_13}, f::Symbol)
    f === :Latency && return Ptr{DWORD}(x + 0)
    f === :Power && return Ptr{DWORD}(x + 4)
    f === :TimeCheck && return Ptr{DWORD}(x + 8)
    f === :PromotePercent && return Ptr{BYTE}(x + 12)
    f === :DemotePercent && return Ptr{BYTE}(x + 13)
    f === :StateType && return Ptr{BYTE}(x + 14)
    f === :Reserved && return Ptr{BYTE}(x + 15)
    f === :StateFlags && return Ptr{DWORD}(x + 16)
    f === :Context && return Ptr{DWORD}(x + 20)
    f === :IdleHandler && return Ptr{DWORD}(x + 24)
    f === :Reserved1 && return Ptr{DWORD}(x + 28)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_13, f::Symbol)
    r = Ref{__JL_Ctag_13}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_13}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_13}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_WMI_IDLE_STATE = __JL_Ctag_13

const PPPM_WMI_IDLE_STATE = Ptr{__JL_Ctag_13}

struct __JL_Ctag_14
    Type::DWORD
    Count::DWORD
    TargetState::DWORD
    OldState::DWORD
    TargetProcessors::DWORD64
    State::NTuple{1, PPM_WMI_IDLE_STATE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_14}, f::Symbol)
    f === :Type && return Ptr{DWORD}(x + 0)
    f === :Count && return Ptr{DWORD}(x + 4)
    f === :TargetState && return Ptr{DWORD}(x + 8)
    f === :OldState && return Ptr{DWORD}(x + 12)
    f === :TargetProcessors && return Ptr{DWORD64}(x + 16)
    f === :State && return Ptr{NTuple{1, PPM_WMI_IDLE_STATE}}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_14, f::Symbol)
    r = Ref{__JL_Ctag_14}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_14}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_14}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_WMI_IDLE_STATES = __JL_Ctag_14

const PPPM_WMI_IDLE_STATES = Ptr{__JL_Ctag_14}

struct __JL_Ctag_15
    Type::DWORD
    Count::DWORD
    TargetState::DWORD
    OldState::DWORD
    TargetProcessors::PVOID
    State::NTuple{1, PPM_WMI_IDLE_STATE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_15}, f::Symbol)
    f === :Type && return Ptr{DWORD}(x + 0)
    f === :Count && return Ptr{DWORD}(x + 4)
    f === :TargetState && return Ptr{DWORD}(x + 8)
    f === :OldState && return Ptr{DWORD}(x + 12)
    f === :TargetProcessors && return Ptr{PVOID}(x + 16)
    f === :State && return Ptr{NTuple{1, PPM_WMI_IDLE_STATE}}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_15, f::Symbol)
    r = Ref{__JL_Ctag_15}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_15}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_15}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_WMI_IDLE_STATES_EX = __JL_Ctag_15

const PPPM_WMI_IDLE_STATES_EX = Ptr{__JL_Ctag_15}

struct __JL_Ctag_16
    Frequency::DWORD
    Power::DWORD
    PercentFrequency::BYTE
    IncreaseLevel::BYTE
    DecreaseLevel::BYTE
    Type::BYTE
    IncreaseTime::DWORD
    DecreaseTime::DWORD
    Control::DWORD64
    Status::DWORD64
    HitCount::DWORD
    Reserved1::DWORD
    Reserved2::DWORD64
    Reserved3::DWORD64
end
function Base.getproperty(x::Ptr{__JL_Ctag_16}, f::Symbol)
    f === :Frequency && return Ptr{DWORD}(x + 0)
    f === :Power && return Ptr{DWORD}(x + 4)
    f === :PercentFrequency && return Ptr{BYTE}(x + 8)
    f === :IncreaseLevel && return Ptr{BYTE}(x + 9)
    f === :DecreaseLevel && return Ptr{BYTE}(x + 10)
    f === :Type && return Ptr{BYTE}(x + 11)
    f === :IncreaseTime && return Ptr{DWORD}(x + 12)
    f === :DecreaseTime && return Ptr{DWORD}(x + 16)
    f === :Control && return Ptr{DWORD64}(x + 24)
    f === :Status && return Ptr{DWORD64}(x + 32)
    f === :HitCount && return Ptr{DWORD}(x + 40)
    f === :Reserved1 && return Ptr{DWORD}(x + 44)
    f === :Reserved2 && return Ptr{DWORD64}(x + 48)
    f === :Reserved3 && return Ptr{DWORD64}(x + 56)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_16, f::Symbol)
    r = Ref{__JL_Ctag_16}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_16}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_16}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_WMI_PERF_STATE = __JL_Ctag_16

const PPPM_WMI_PERF_STATE = Ptr{__JL_Ctag_16}

struct __JL_Ctag_17
    Count::DWORD
    MaxFrequency::DWORD
    CurrentState::DWORD
    MaxPerfState::DWORD
    MinPerfState::DWORD
    LowestPerfState::DWORD
    ThermalConstraint::DWORD
    BusyAdjThreshold::BYTE
    PolicyType::BYTE
    Type::BYTE
    Reserved::BYTE
    TimerInterval::DWORD
    TargetProcessors::DWORD64
    PStateHandler::DWORD
    PStateContext::DWORD
    TStateHandler::DWORD
    TStateContext::DWORD
    FeedbackHandler::DWORD
    Reserved1::DWORD
    Reserved2::DWORD64
    State::NTuple{1, PPM_WMI_PERF_STATE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_17}, f::Symbol)
    f === :Count && return Ptr{DWORD}(x + 0)
    f === :MaxFrequency && return Ptr{DWORD}(x + 4)
    f === :CurrentState && return Ptr{DWORD}(x + 8)
    f === :MaxPerfState && return Ptr{DWORD}(x + 12)
    f === :MinPerfState && return Ptr{DWORD}(x + 16)
    f === :LowestPerfState && return Ptr{DWORD}(x + 20)
    f === :ThermalConstraint && return Ptr{DWORD}(x + 24)
    f === :BusyAdjThreshold && return Ptr{BYTE}(x + 28)
    f === :PolicyType && return Ptr{BYTE}(x + 29)
    f === :Type && return Ptr{BYTE}(x + 30)
    f === :Reserved && return Ptr{BYTE}(x + 31)
    f === :TimerInterval && return Ptr{DWORD}(x + 32)
    f === :TargetProcessors && return Ptr{DWORD64}(x + 40)
    f === :PStateHandler && return Ptr{DWORD}(x + 48)
    f === :PStateContext && return Ptr{DWORD}(x + 52)
    f === :TStateHandler && return Ptr{DWORD}(x + 56)
    f === :TStateContext && return Ptr{DWORD}(x + 60)
    f === :FeedbackHandler && return Ptr{DWORD}(x + 64)
    f === :Reserved1 && return Ptr{DWORD}(x + 68)
    f === :Reserved2 && return Ptr{DWORD64}(x + 72)
    f === :State && return Ptr{NTuple{1, PPM_WMI_PERF_STATE}}(x + 80)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_17, f::Symbol)
    r = Ref{__JL_Ctag_17}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_17}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_17}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_WMI_PERF_STATES = __JL_Ctag_17

const PPPM_WMI_PERF_STATES = Ptr{__JL_Ctag_17}

struct __JL_Ctag_18
    Count::DWORD
    MaxFrequency::DWORD
    CurrentState::DWORD
    MaxPerfState::DWORD
    MinPerfState::DWORD
    LowestPerfState::DWORD
    ThermalConstraint::DWORD
    BusyAdjThreshold::BYTE
    PolicyType::BYTE
    Type::BYTE
    Reserved::BYTE
    TimerInterval::DWORD
    TargetProcessors::PVOID
    PStateHandler::DWORD
    PStateContext::DWORD
    TStateHandler::DWORD
    TStateContext::DWORD
    FeedbackHandler::DWORD
    Reserved1::DWORD
    Reserved2::DWORD64
    State::NTuple{1, PPM_WMI_PERF_STATE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_18}, f::Symbol)
    f === :Count && return Ptr{DWORD}(x + 0)
    f === :MaxFrequency && return Ptr{DWORD}(x + 4)
    f === :CurrentState && return Ptr{DWORD}(x + 8)
    f === :MaxPerfState && return Ptr{DWORD}(x + 12)
    f === :MinPerfState && return Ptr{DWORD}(x + 16)
    f === :LowestPerfState && return Ptr{DWORD}(x + 20)
    f === :ThermalConstraint && return Ptr{DWORD}(x + 24)
    f === :BusyAdjThreshold && return Ptr{BYTE}(x + 28)
    f === :PolicyType && return Ptr{BYTE}(x + 29)
    f === :Type && return Ptr{BYTE}(x + 30)
    f === :Reserved && return Ptr{BYTE}(x + 31)
    f === :TimerInterval && return Ptr{DWORD}(x + 32)
    f === :TargetProcessors && return Ptr{PVOID}(x + 40)
    f === :PStateHandler && return Ptr{DWORD}(x + 48)
    f === :PStateContext && return Ptr{DWORD}(x + 52)
    f === :TStateHandler && return Ptr{DWORD}(x + 56)
    f === :TStateContext && return Ptr{DWORD}(x + 60)
    f === :FeedbackHandler && return Ptr{DWORD}(x + 64)
    f === :Reserved1 && return Ptr{DWORD}(x + 68)
    f === :Reserved2 && return Ptr{DWORD64}(x + 72)
    f === :State && return Ptr{NTuple{1, PPM_WMI_PERF_STATE}}(x + 80)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_18, f::Symbol)
    r = Ref{__JL_Ctag_18}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_18}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_18}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_WMI_PERF_STATES_EX = __JL_Ctag_18

const PPPM_WMI_PERF_STATES_EX = Ptr{__JL_Ctag_18}

struct __JL_Ctag_19
    IdleTransitions::DWORD
    FailedTransitions::DWORD
    InvalidBucketIndex::DWORD
    TotalTime::DWORD64
    IdleTimeBuckets::NTuple{6, DWORD}
end
function Base.getproperty(x::Ptr{__JL_Ctag_19}, f::Symbol)
    f === :IdleTransitions && return Ptr{DWORD}(x + 0)
    f === :FailedTransitions && return Ptr{DWORD}(x + 4)
    f === :InvalidBucketIndex && return Ptr{DWORD}(x + 8)
    f === :TotalTime && return Ptr{DWORD64}(x + 16)
    f === :IdleTimeBuckets && return Ptr{NTuple{6, DWORD}}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_19, f::Symbol)
    r = Ref{__JL_Ctag_19}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_19}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_19}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_IDLE_STATE_ACCOUNTING = __JL_Ctag_19

const PPPM_IDLE_STATE_ACCOUNTING = Ptr{__JL_Ctag_19}

struct __JL_Ctag_20
    StateCount::DWORD
    TotalTransitions::DWORD
    ResetCount::DWORD
    StartTime::DWORD64
    State::NTuple{1, PPM_IDLE_STATE_ACCOUNTING}
end
function Base.getproperty(x::Ptr{__JL_Ctag_20}, f::Symbol)
    f === :StateCount && return Ptr{DWORD}(x + 0)
    f === :TotalTransitions && return Ptr{DWORD}(x + 4)
    f === :ResetCount && return Ptr{DWORD}(x + 8)
    f === :StartTime && return Ptr{DWORD64}(x + 16)
    f === :State && return Ptr{NTuple{1, PPM_IDLE_STATE_ACCOUNTING}}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_20, f::Symbol)
    r = Ref{__JL_Ctag_20}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_20}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_20}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_IDLE_ACCOUNTING = __JL_Ctag_20

const PPPM_IDLE_ACCOUNTING = Ptr{__JL_Ctag_20}

struct __JL_Ctag_21
    TotalTimeUs::DWORD64
    MinTimeUs::DWORD
    MaxTimeUs::DWORD
    Count::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_21}, f::Symbol)
    f === :TotalTimeUs && return Ptr{DWORD64}(x + 0)
    f === :MinTimeUs && return Ptr{DWORD}(x + 8)
    f === :MaxTimeUs && return Ptr{DWORD}(x + 12)
    f === :Count && return Ptr{DWORD}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_21, f::Symbol)
    r = Ref{__JL_Ctag_21}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_21}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_21}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_IDLE_STATE_BUCKET_EX = __JL_Ctag_21

const PPPM_IDLE_STATE_BUCKET_EX = Ptr{__JL_Ctag_21}

struct __JL_Ctag_22
    TotalTime::DWORD64
    IdleTransitions::DWORD
    FailedTransitions::DWORD
    InvalidBucketIndex::DWORD
    MinTimeUs::DWORD
    MaxTimeUs::DWORD
    CancelledTransitions::DWORD
    IdleTimeBuckets::NTuple{16, PPM_IDLE_STATE_BUCKET_EX}
end
function Base.getproperty(x::Ptr{__JL_Ctag_22}, f::Symbol)
    f === :TotalTime && return Ptr{DWORD64}(x + 0)
    f === :IdleTransitions && return Ptr{DWORD}(x + 8)
    f === :FailedTransitions && return Ptr{DWORD}(x + 12)
    f === :InvalidBucketIndex && return Ptr{DWORD}(x + 16)
    f === :MinTimeUs && return Ptr{DWORD}(x + 20)
    f === :MaxTimeUs && return Ptr{DWORD}(x + 24)
    f === :CancelledTransitions && return Ptr{DWORD}(x + 28)
    f === :IdleTimeBuckets && return Ptr{NTuple{16, PPM_IDLE_STATE_BUCKET_EX}}(x + 32)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_22, f::Symbol)
    r = Ref{__JL_Ctag_22}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_22}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_22}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_IDLE_STATE_ACCOUNTING_EX = __JL_Ctag_22

const PPPM_IDLE_STATE_ACCOUNTING_EX = Ptr{__JL_Ctag_22}

struct __JL_Ctag_23
    StateCount::DWORD
    TotalTransitions::DWORD
    ResetCount::DWORD
    AbortCount::DWORD
    StartTime::DWORD64
    State::NTuple{1, PPM_IDLE_STATE_ACCOUNTING_EX}
end
function Base.getproperty(x::Ptr{__JL_Ctag_23}, f::Symbol)
    f === :StateCount && return Ptr{DWORD}(x + 0)
    f === :TotalTransitions && return Ptr{DWORD}(x + 4)
    f === :ResetCount && return Ptr{DWORD}(x + 8)
    f === :AbortCount && return Ptr{DWORD}(x + 12)
    f === :StartTime && return Ptr{DWORD64}(x + 16)
    f === :State && return Ptr{NTuple{1, PPM_IDLE_STATE_ACCOUNTING_EX}}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_23, f::Symbol)
    r = Ref{__JL_Ctag_23}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_23}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_23}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_IDLE_ACCOUNTING_EX = __JL_Ctag_23

const PPPM_IDLE_ACCOUNTING_EX = Ptr{__JL_Ctag_23}

struct __JL_Ctag_24
    State::DWORD
    Status::DWORD
    Latency::DWORD
    Speed::DWORD
    Processor::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_24}, f::Symbol)
    f === :State && return Ptr{DWORD}(x + 0)
    f === :Status && return Ptr{DWORD}(x + 4)
    f === :Latency && return Ptr{DWORD}(x + 8)
    f === :Speed && return Ptr{DWORD}(x + 12)
    f === :Processor && return Ptr{DWORD}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_24, f::Symbol)
    r = Ref{__JL_Ctag_24}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_24}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_24}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_PERFSTATE_EVENT = __JL_Ctag_24

const PPPM_PERFSTATE_EVENT = Ptr{__JL_Ctag_24}

struct __JL_Ctag_25
    State::DWORD
    Latency::DWORD
    Speed::DWORD
    Processors::DWORD64
end
function Base.getproperty(x::Ptr{__JL_Ctag_25}, f::Symbol)
    f === :State && return Ptr{DWORD}(x + 0)
    f === :Latency && return Ptr{DWORD}(x + 4)
    f === :Speed && return Ptr{DWORD}(x + 8)
    f === :Processors && return Ptr{DWORD64}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_25, f::Symbol)
    r = Ref{__JL_Ctag_25}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_25}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_25}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_PERFSTATE_DOMAIN_EVENT = __JL_Ctag_25

const PPPM_PERFSTATE_DOMAIN_EVENT = Ptr{__JL_Ctag_25}

struct __JL_Ctag_26
    NewState::DWORD
    OldState::DWORD
    Processors::DWORD64
end
function Base.getproperty(x::Ptr{__JL_Ctag_26}, f::Symbol)
    f === :NewState && return Ptr{DWORD}(x + 0)
    f === :OldState && return Ptr{DWORD}(x + 4)
    f === :Processors && return Ptr{DWORD64}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_26, f::Symbol)
    r = Ref{__JL_Ctag_26}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_26}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_26}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_IDLESTATE_EVENT = __JL_Ctag_26

const PPPM_IDLESTATE_EVENT = Ptr{__JL_Ctag_26}

struct __JL_Ctag_27
    ThermalConstraint::DWORD
    Processors::DWORD64
end
function Base.getproperty(x::Ptr{__JL_Ctag_27}, f::Symbol)
    f === :ThermalConstraint && return Ptr{DWORD}(x + 0)
    f === :Processors && return Ptr{DWORD64}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_27, f::Symbol)
    r = Ref{__JL_Ctag_27}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_27}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_27}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_THERMALCHANGE_EVENT = __JL_Ctag_27

const PPPM_THERMALCHANGE_EVENT = Ptr{__JL_Ctag_27}

struct __JL_Ctag_28
    Mode::BYTE
    Processors::DWORD64
end
function Base.getproperty(x::Ptr{__JL_Ctag_28}, f::Symbol)
    f === :Mode && return Ptr{BYTE}(x + 0)
    f === :Processors && return Ptr{DWORD64}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_28, f::Symbol)
    r = Ref{__JL_Ctag_28}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_28}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_28}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PPM_THERMAL_POLICY_EVENT = __JL_Ctag_28

const PPPM_THERMAL_POLICY_EVENT = Ptr{__JL_Ctag_28}

struct __JL_Ctag_29
    Action::POWER_ACTION
    Flags::DWORD
    EventCode::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_29}, f::Symbol)
    f === :Action && return Ptr{POWER_ACTION}(x + 0)
    f === :Flags && return Ptr{DWORD}(x + 4)
    f === :EventCode && return Ptr{DWORD}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_29, f::Symbol)
    r = Ref{__JL_Ctag_29}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_29}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_29}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const POWER_ACTION_POLICY = __JL_Ctag_29

const PPOWER_ACTION_POLICY = Ptr{__JL_Ctag_29}

struct __JL_Ctag_30
    Enable::BOOLEAN
    Spare::NTuple{3, BYTE}
    BatteryLevel::DWORD
    PowerPolicy::POWER_ACTION_POLICY
    MinSystemState::SYSTEM_POWER_STATE
end
function Base.getproperty(x::Ptr{__JL_Ctag_30}, f::Symbol)
    f === :Enable && return Ptr{BOOLEAN}(x + 0)
    f === :Spare && return Ptr{NTuple{3, BYTE}}(x + 1)
    f === :BatteryLevel && return Ptr{DWORD}(x + 4)
    f === :PowerPolicy && return Ptr{POWER_ACTION_POLICY}(x + 8)
    f === :MinSystemState && return Ptr{SYSTEM_POWER_STATE}(x + 20)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_30, f::Symbol)
    r = Ref{__JL_Ctag_30}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_30}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_30}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const SYSTEM_POWER_LEVEL = __JL_Ctag_30

const PSYSTEM_POWER_LEVEL = Ptr{__JL_Ctag_30}

struct _SYSTEM_POWER_POLICY
    Revision::DWORD
    PowerButton::POWER_ACTION_POLICY
    SleepButton::POWER_ACTION_POLICY
    LidClose::POWER_ACTION_POLICY
    LidOpenWake::SYSTEM_POWER_STATE
    Reserved::DWORD
    Idle::POWER_ACTION_POLICY
    IdleTimeout::DWORD
    IdleSensitivity::BYTE
    DynamicThrottle::BYTE
    Spare2::NTuple{2, BYTE}
    MinSleep::SYSTEM_POWER_STATE
    MaxSleep::SYSTEM_POWER_STATE
    ReducedLatencySleep::SYSTEM_POWER_STATE
    WinLogonFlags::DWORD
    Spare3::DWORD
    DozeS4Timeout::DWORD
    BroadcastCapacityResolution::DWORD
    DischargePolicy::NTuple{4, SYSTEM_POWER_LEVEL}
    VideoTimeout::DWORD
    VideoDimDisplay::BOOLEAN
    VideoReserved::NTuple{3, DWORD}
    SpindownTimeout::DWORD
    OptimizeForPower::BOOLEAN
    FanThrottleTolerance::BYTE
    ForcedThrottle::BYTE
    MinThrottle::BYTE
    OverThrottled::POWER_ACTION_POLICY
end

const SYSTEM_POWER_POLICY = _SYSTEM_POWER_POLICY

const PSYSTEM_POWER_POLICY = Ptr{_SYSTEM_POWER_POLICY}

struct __JL_Ctag_31
    TimeCheck::DWORD
    DemotePercent::BYTE
    PromotePercent::BYTE
    Spare::NTuple{2, BYTE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_31}, f::Symbol)
    f === :TimeCheck && return Ptr{DWORD}(x + 0)
    f === :DemotePercent && return Ptr{BYTE}(x + 4)
    f === :PromotePercent && return Ptr{BYTE}(x + 5)
    f === :Spare && return Ptr{NTuple{2, BYTE}}(x + 6)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_31, f::Symbol)
    r = Ref{__JL_Ctag_31}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_31}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_31}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const PROCESSOR_IDLESTATE_INFO = __JL_Ctag_31

const PPROCESSOR_IDLESTATE_INFO = Ptr{__JL_Ctag_31}

struct __JL_Ctag_70
    data::NTuple{2, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_70}, f::Symbol)
    f === :AsWORD && return Ptr{WORD}(x + 0)
    f === :AllowScaling && return (Ptr{WORD}(x + 0), 0, 1)
    f === :Disabled && return (Ptr{WORD}(x + 0), 1, 1)
    f === :Reserved && return (Ptr{WORD}(x + 0), 2, 14)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_70, f::Symbol)
    r = Ref{__JL_Ctag_70}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_70}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_70}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_70 = Union{WORD}

function __JL_Ctag_70(val::__U___JL_Ctag_70)
    ref = Ref{__JL_Ctag_70}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_70}, ref)
    if val isa WORD
        ptr.AsWORD = val
    end
    ref[]
end

struct __JL_Ctag_32
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_32}, f::Symbol)
    f === :Revision && return Ptr{WORD}(x + 0)
    f === :Flags && return Ptr{__JL_Ctag_70}(x + 2)
    f === :PolicyCount && return Ptr{DWORD}(x + 4)
    f === :Policy && return Ptr{NTuple{3, PROCESSOR_IDLESTATE_INFO}}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_32, f::Symbol)
    r = Ref{__JL_Ctag_32}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_32}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_32}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function __JL_Ctag_32(Revision::WORD, Flags::__JL_Ctag_70, PolicyCount::DWORD, Policy::NTuple{3, PROCESSOR_IDLESTATE_INFO})
    ref = Ref{__JL_Ctag_32}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_32}, ref)
    ptr.Revision = Revision
    ptr.Flags = Flags
    ptr.PolicyCount = PolicyCount
    ptr.Policy = Policy
    ref[]
end

const PROCESSOR_IDLESTATE_POLICY = Cvoid

const PPROCESSOR_IDLESTATE_POLICY = Ptr{Cvoid}

struct _PROCESSOR_POWER_POLICY_INFO
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESSOR_POWER_POLICY_INFO}, f::Symbol)
    f === :TimeCheck && return Ptr{DWORD}(x + 0)
    f === :DemoteLimit && return Ptr{DWORD}(x + 4)
    f === :PromoteLimit && return Ptr{DWORD}(x + 8)
    f === :DemotePercent && return Ptr{BYTE}(x + 12)
    f === :PromotePercent && return Ptr{BYTE}(x + 13)
    f === :Spare && return Ptr{NTuple{2, BYTE}}(x + 14)
    f === :AllowDemotion && return (Ptr{DWORD}(x + 16), 0, 1)
    f === :AllowPromotion && return (Ptr{DWORD}(x + 16), 1, 1)
    f === :Reserved && return (Ptr{DWORD}(x + 16), 2, 30)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESSOR_POWER_POLICY_INFO, f::Symbol)
    r = Ref{_PROCESSOR_POWER_POLICY_INFO}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESSOR_POWER_POLICY_INFO}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{_PROCESSOR_POWER_POLICY_INFO}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function _PROCESSOR_POWER_POLICY_INFO(TimeCheck::DWORD, DemoteLimit::DWORD, PromoteLimit::DWORD, DemotePercent::BYTE, PromotePercent::BYTE, Spare::NTuple{2, BYTE}, AllowDemotion::DWORD, AllowPromotion::DWORD, Reserved::DWORD)
    ref = Ref{_PROCESSOR_POWER_POLICY_INFO}()
    ptr = Base.unsafe_convert(Ptr{_PROCESSOR_POWER_POLICY_INFO}, ref)
    ptr.TimeCheck = TimeCheck
    ptr.DemoteLimit = DemoteLimit
    ptr.PromoteLimit = PromoteLimit
    ptr.DemotePercent = DemotePercent
    ptr.PromotePercent = PromotePercent
    ptr.Spare = Spare
    ptr.AllowDemotion = AllowDemotion
    ptr.AllowPromotion = AllowPromotion
    ptr.Reserved = Reserved
    ref[]
end

const PROCESSOR_POWER_POLICY_INFO = _PROCESSOR_POWER_POLICY_INFO

const PPROCESSOR_POWER_POLICY_INFO = Ptr{_PROCESSOR_POWER_POLICY_INFO}

struct _PROCESSOR_POWER_POLICY
    data::NTuple{76, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESSOR_POWER_POLICY}, f::Symbol)
    f === :Revision && return Ptr{DWORD}(x + 0)
    f === :DynamicThrottle && return Ptr{BYTE}(x + 4)
    f === :Spare && return Ptr{NTuple{3, BYTE}}(x + 5)
    f === :DisableCStates && return (Ptr{DWORD}(x + 8), 0, 1)
    f === :Reserved && return (Ptr{DWORD}(x + 8), 1, 31)
    f === :PolicyCount && return Ptr{DWORD}(x + 12)
    f === :Policy && return Ptr{NTuple{3, PROCESSOR_POWER_POLICY_INFO}}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESSOR_POWER_POLICY, f::Symbol)
    r = Ref{_PROCESSOR_POWER_POLICY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESSOR_POWER_POLICY}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{_PROCESSOR_POWER_POLICY}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function _PROCESSOR_POWER_POLICY(Revision::DWORD, DynamicThrottle::BYTE, Spare::NTuple{3, BYTE}, DisableCStates::DWORD, Reserved::DWORD, PolicyCount::DWORD, Policy::NTuple{3, PROCESSOR_POWER_POLICY_INFO})
    ref = Ref{_PROCESSOR_POWER_POLICY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESSOR_POWER_POLICY}, ref)
    ptr.Revision = Revision
    ptr.DynamicThrottle = DynamicThrottle
    ptr.Spare = Spare
    ptr.DisableCStates = DisableCStates
    ptr.Reserved = Reserved
    ptr.PolicyCount = PolicyCount
    ptr.Policy = Policy
    ref[]
end

const PROCESSOR_POWER_POLICY = _PROCESSOR_POWER_POLICY

const PPROCESSOR_POWER_POLICY = Ptr{_PROCESSOR_POWER_POLICY}

struct __JL_Ctag_33
    data::NTuple{28, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_33}, f::Symbol)
    f === :Revision && return Ptr{DWORD}(x + 0)
    f === :MaxThrottle && return Ptr{BYTE}(x + 4)
    f === :MinThrottle && return Ptr{BYTE}(x + 5)
    f === :BusyAdjThreshold && return Ptr{BYTE}(x + 6)
    f === :Spare && return Ptr{BYTE}(x + 7)
    f === :Flags && return Ptr{Cvoid}(x + 7)
    f === :TimeCheck && return Ptr{DWORD}(x + 8)
    f === :IncreaseTime && return Ptr{DWORD}(x + 12)
    f === :DecreaseTime && return Ptr{DWORD}(x + 16)
    f === :IncreasePercent && return Ptr{DWORD}(x + 20)
    f === :DecreasePercent && return Ptr{DWORD}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_33, f::Symbol)
    r = Ref{__JL_Ctag_33}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_33}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_33}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function __JL_Ctag_33(Revision::DWORD, MaxThrottle::BYTE, MinThrottle::BYTE, BusyAdjThreshold::BYTE, TimeCheck::DWORD, IncreaseTime::DWORD, DecreaseTime::DWORD, IncreasePercent::DWORD, DecreasePercent::DWORD)
    ref = Ref{__JL_Ctag_33}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_33}, ref)
    ptr.Revision = Revision
    ptr.MaxThrottle = MaxThrottle
    ptr.MinThrottle = MinThrottle
    ptr.BusyAdjThreshold = BusyAdjThreshold
    ptr.TimeCheck = TimeCheck
    ptr.IncreaseTime = IncreaseTime
    ptr.DecreaseTime = DecreaseTime
    ptr.IncreasePercent = IncreasePercent
    ptr.DecreasePercent = DecreasePercent
    ref[]
end

const PROCESSOR_PERFSTATE_POLICY = Cvoid

const PPROCESSOR_PERFSTATE_POLICY = Ptr{Cvoid}

struct _ADMINISTRATOR_POWER_POLICY
    MinSleep::SYSTEM_POWER_STATE
    MaxSleep::SYSTEM_POWER_STATE
    MinVideoTimeout::DWORD
    MaxVideoTimeout::DWORD
    MinSpindownTimeout::DWORD
    MaxSpindownTimeout::DWORD
end

const ADMINISTRATOR_POWER_POLICY = _ADMINISTRATOR_POWER_POLICY

const PADMINISTRATOR_POWER_POLICY = Ptr{_ADMINISTRATOR_POWER_POLICY}

@cenum _HIBERFILE_BUCKET_SIZE::UInt32 begin
    HiberFileBucket1GB = 0
    HiberFileBucket2GB = 1
    HiberFileBucket4GB = 2
    HiberFileBucket8GB = 3
    HiberFileBucket16GB = 4
    HiberFileBucket32GB = 5
    HiberFileBucketUnlimited = 6
    HiberFileBucketMax = 7
end

const HIBERFILE_BUCKET_SIZE = _HIBERFILE_BUCKET_SIZE

const PHIBERFILE_BUCKET_SIZE = Ptr{_HIBERFILE_BUCKET_SIZE}

struct _HIBERFILE_BUCKET
    MaxPhysicalMemory::DWORD64
    PhysicalMemoryPercent::NTuple{3, DWORD}
end

const HIBERFILE_BUCKET = _HIBERFILE_BUCKET

const PHIBERFILE_BUCKET = Ptr{_HIBERFILE_BUCKET}

struct __JL_Ctag_34
    PowerButtonPresent::BOOLEAN
    SleepButtonPresent::BOOLEAN
    LidPresent::BOOLEAN
    SystemS1::BOOLEAN
    SystemS2::BOOLEAN
    SystemS3::BOOLEAN
    SystemS4::BOOLEAN
    SystemS5::BOOLEAN
    HiberFilePresent::BOOLEAN
    FullWake::BOOLEAN
    VideoDimPresent::BOOLEAN
    ApmPresent::BOOLEAN
    UpsPresent::BOOLEAN
    ThermalControl::BOOLEAN
    ProcessorThrottle::BOOLEAN
    ProcessorMinThrottle::BYTE
    ProcessorMaxThrottle::BYTE
    FastSystemS4::BOOLEAN
    Hiberboot::BOOLEAN
    WakeAlarmPresent::BOOLEAN
    AoAc::BOOLEAN
    DiskSpinDown::BOOLEAN
    spare3::NTuple{8, BYTE}
    SystemBatteriesPresent::BOOLEAN
    BatteriesAreShortTerm::BOOLEAN
    BatteryScale::NTuple{3, BATTERY_REPORTING_SCALE}
    AcOnLineWake::SYSTEM_POWER_STATE
    SoftLidWake::SYSTEM_POWER_STATE
    RtcWake::SYSTEM_POWER_STATE
    MinDeviceWakeState::SYSTEM_POWER_STATE
    DefaultLowLatencyWake::SYSTEM_POWER_STATE
end
function Base.getproperty(x::Ptr{__JL_Ctag_34}, f::Symbol)
    f === :PowerButtonPresent && return Ptr{BOOLEAN}(x + 0)
    f === :SleepButtonPresent && return Ptr{BOOLEAN}(x + 1)
    f === :LidPresent && return Ptr{BOOLEAN}(x + 2)
    f === :SystemS1 && return Ptr{BOOLEAN}(x + 3)
    f === :SystemS2 && return Ptr{BOOLEAN}(x + 4)
    f === :SystemS3 && return Ptr{BOOLEAN}(x + 5)
    f === :SystemS4 && return Ptr{BOOLEAN}(x + 6)
    f === :SystemS5 && return Ptr{BOOLEAN}(x + 7)
    f === :HiberFilePresent && return Ptr{BOOLEAN}(x + 8)
    f === :FullWake && return Ptr{BOOLEAN}(x + 9)
    f === :VideoDimPresent && return Ptr{BOOLEAN}(x + 10)
    f === :ApmPresent && return Ptr{BOOLEAN}(x + 11)
    f === :UpsPresent && return Ptr{BOOLEAN}(x + 12)
    f === :ThermalControl && return Ptr{BOOLEAN}(x + 13)
    f === :ProcessorThrottle && return Ptr{BOOLEAN}(x + 14)
    f === :ProcessorMinThrottle && return Ptr{BYTE}(x + 15)
    f === :ProcessorMaxThrottle && return Ptr{BYTE}(x + 16)
    f === :FastSystemS4 && return Ptr{BOOLEAN}(x + 17)
    f === :Hiberboot && return Ptr{BOOLEAN}(x + 18)
    f === :WakeAlarmPresent && return Ptr{BOOLEAN}(x + 19)
    f === :AoAc && return Ptr{BOOLEAN}(x + 20)
    f === :DiskSpinDown && return Ptr{BOOLEAN}(x + 21)
    f === :spare3 && return Ptr{NTuple{8, BYTE}}(x + 22)
    f === :SystemBatteriesPresent && return Ptr{BOOLEAN}(x + 30)
    f === :BatteriesAreShortTerm && return Ptr{BOOLEAN}(x + 31)
    f === :BatteryScale && return Ptr{NTuple{3, BATTERY_REPORTING_SCALE}}(x + 32)
    f === :AcOnLineWake && return Ptr{SYSTEM_POWER_STATE}(x + 56)
    f === :SoftLidWake && return Ptr{SYSTEM_POWER_STATE}(x + 60)
    f === :RtcWake && return Ptr{SYSTEM_POWER_STATE}(x + 64)
    f === :MinDeviceWakeState && return Ptr{SYSTEM_POWER_STATE}(x + 68)
    f === :DefaultLowLatencyWake && return Ptr{SYSTEM_POWER_STATE}(x + 72)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_34, f::Symbol)
    r = Ref{__JL_Ctag_34}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_34}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_34}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const SYSTEM_POWER_CAPABILITIES = __JL_Ctag_34

const PSYSTEM_POWER_CAPABILITIES = Ptr{__JL_Ctag_34}

struct __JL_Ctag_35
    AcOnLine::BOOLEAN
    BatteryPresent::BOOLEAN
    Charging::BOOLEAN
    Discharging::BOOLEAN
    Spare1::NTuple{3, BOOLEAN}
    Tag::BYTE
    MaxCapacity::DWORD
    RemainingCapacity::DWORD
    Rate::DWORD
    EstimatedTime::DWORD
    DefaultAlert1::DWORD
    DefaultAlert2::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_35}, f::Symbol)
    f === :AcOnLine && return Ptr{BOOLEAN}(x + 0)
    f === :BatteryPresent && return Ptr{BOOLEAN}(x + 1)
    f === :Charging && return Ptr{BOOLEAN}(x + 2)
    f === :Discharging && return Ptr{BOOLEAN}(x + 3)
    f === :Spare1 && return Ptr{NTuple{3, BOOLEAN}}(x + 4)
    f === :Tag && return Ptr{BYTE}(x + 7)
    f === :MaxCapacity && return Ptr{DWORD}(x + 8)
    f === :RemainingCapacity && return Ptr{DWORD}(x + 12)
    f === :Rate && return Ptr{DWORD}(x + 16)
    f === :EstimatedTime && return Ptr{DWORD}(x + 20)
    f === :DefaultAlert1 && return Ptr{DWORD}(x + 24)
    f === :DefaultAlert2 && return Ptr{DWORD}(x + 28)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_35, f::Symbol)
    r = Ref{__JL_Ctag_35}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_35}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_35}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const SYSTEM_BATTERY_STATE = __JL_Ctag_35

const PSYSTEM_BATTERY_STATE = Ptr{__JL_Ctag_35}

struct _IMAGE_DOS_HEADER
    data::NTuple{64, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DOS_HEADER}, f::Symbol)
    f === :e_magic && return Ptr{WORD}(x + 0)
    f === :e_cblp && return Ptr{WORD}(x + 2)
    f === :e_cp && return Ptr{WORD}(x + 4)
    f === :e_crlc && return Ptr{WORD}(x + 6)
    f === :e_cparhdr && return Ptr{WORD}(x + 8)
    f === :e_minalloc && return Ptr{WORD}(x + 10)
    f === :e_maxalloc && return Ptr{WORD}(x + 12)
    f === :e_ss && return Ptr{WORD}(x + 14)
    f === :e_sp && return Ptr{WORD}(x + 16)
    f === :e_csum && return Ptr{WORD}(x + 18)
    f === :e_ip && return Ptr{WORD}(x + 20)
    f === :e_cs && return Ptr{WORD}(x + 22)
    f === :e_lfarlc && return Ptr{WORD}(x + 24)
    f === :e_ovno && return Ptr{WORD}(x + 26)
    f === :e_res && return Ptr{NTuple{4, WORD}}(x + 28)
    f === :e_oemid && return Ptr{WORD}(x + 36)
    f === :e_oeminfo && return Ptr{WORD}(x + 38)
    f === :e_res2 && return Ptr{NTuple{10, WORD}}(x + 40)
    f === :e_lfanew && return Ptr{LONG}(x + 60)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DOS_HEADER, f::Symbol)
    r = Ref{_IMAGE_DOS_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DOS_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DOS_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DOS_HEADER(e_magic::WORD, e_cblp::WORD, e_cp::WORD, e_crlc::WORD, e_cparhdr::WORD, e_minalloc::WORD, e_maxalloc::WORD, e_ss::WORD, e_sp::WORD, e_csum::WORD, e_ip::WORD, e_cs::WORD, e_lfarlc::WORD, e_ovno::WORD, e_res::NTuple{4, WORD}, e_oemid::WORD, e_oeminfo::WORD, e_res2::NTuple{10, WORD}, e_lfanew::LONG)
    ref = Ref{_IMAGE_DOS_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DOS_HEADER}, ref)
    ptr.e_magic = e_magic
    ptr.e_cblp = e_cblp
    ptr.e_cp = e_cp
    ptr.e_crlc = e_crlc
    ptr.e_cparhdr = e_cparhdr
    ptr.e_minalloc = e_minalloc
    ptr.e_maxalloc = e_maxalloc
    ptr.e_ss = e_ss
    ptr.e_sp = e_sp
    ptr.e_csum = e_csum
    ptr.e_ip = e_ip
    ptr.e_cs = e_cs
    ptr.e_lfarlc = e_lfarlc
    ptr.e_ovno = e_ovno
    ptr.e_res = e_res
    ptr.e_oemid = e_oemid
    ptr.e_oeminfo = e_oeminfo
    ptr.e_res2 = e_res2
    ptr.e_lfanew = e_lfanew
    ref[]
end

const IMAGE_DOS_HEADER = _IMAGE_DOS_HEADER

const PIMAGE_DOS_HEADER = Ptr{_IMAGE_DOS_HEADER}

struct _IMAGE_OS2_HEADER
    data::NTuple{64, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_OS2_HEADER}, f::Symbol)
    f === :ne_magic && return Ptr{WORD}(x + 0)
    f === :ne_ver && return Ptr{CHAR}(x + 2)
    f === :ne_rev && return Ptr{CHAR}(x + 3)
    f === :ne_enttab && return Ptr{WORD}(x + 4)
    f === :ne_cbenttab && return Ptr{WORD}(x + 6)
    f === :ne_crc && return Ptr{LONG}(x + 8)
    f === :ne_flags && return Ptr{WORD}(x + 12)
    f === :ne_autodata && return Ptr{WORD}(x + 14)
    f === :ne_heap && return Ptr{WORD}(x + 16)
    f === :ne_stack && return Ptr{WORD}(x + 18)
    f === :ne_csip && return Ptr{LONG}(x + 20)
    f === :ne_sssp && return Ptr{LONG}(x + 24)
    f === :ne_cseg && return Ptr{WORD}(x + 28)
    f === :ne_cmod && return Ptr{WORD}(x + 30)
    f === :ne_cbnrestab && return Ptr{WORD}(x + 32)
    f === :ne_segtab && return Ptr{WORD}(x + 34)
    f === :ne_rsrctab && return Ptr{WORD}(x + 36)
    f === :ne_restab && return Ptr{WORD}(x + 38)
    f === :ne_modtab && return Ptr{WORD}(x + 40)
    f === :ne_imptab && return Ptr{WORD}(x + 42)
    f === :ne_nrestab && return Ptr{LONG}(x + 44)
    f === :ne_cmovent && return Ptr{WORD}(x + 48)
    f === :ne_align && return Ptr{WORD}(x + 50)
    f === :ne_cres && return Ptr{WORD}(x + 52)
    f === :ne_exetyp && return Ptr{BYTE}(x + 54)
    f === :ne_flagsothers && return Ptr{BYTE}(x + 55)
    f === :ne_pretthunks && return Ptr{WORD}(x + 56)
    f === :ne_psegrefbytes && return Ptr{WORD}(x + 58)
    f === :ne_swaparea && return Ptr{WORD}(x + 60)
    f === :ne_expver && return Ptr{WORD}(x + 62)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_OS2_HEADER, f::Symbol)
    r = Ref{_IMAGE_OS2_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_OS2_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_OS2_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_OS2_HEADER(ne_magic::WORD, ne_ver::CHAR, ne_rev::CHAR, ne_enttab::WORD, ne_cbenttab::WORD, ne_crc::LONG, ne_flags::WORD, ne_autodata::WORD, ne_heap::WORD, ne_stack::WORD, ne_csip::LONG, ne_sssp::LONG, ne_cseg::WORD, ne_cmod::WORD, ne_cbnrestab::WORD, ne_segtab::WORD, ne_rsrctab::WORD, ne_restab::WORD, ne_modtab::WORD, ne_imptab::WORD, ne_nrestab::LONG, ne_cmovent::WORD, ne_align::WORD, ne_cres::WORD, ne_exetyp::BYTE, ne_flagsothers::BYTE, ne_pretthunks::WORD, ne_psegrefbytes::WORD, ne_swaparea::WORD, ne_expver::WORD)
    ref = Ref{_IMAGE_OS2_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_OS2_HEADER}, ref)
    ptr.ne_magic = ne_magic
    ptr.ne_ver = ne_ver
    ptr.ne_rev = ne_rev
    ptr.ne_enttab = ne_enttab
    ptr.ne_cbenttab = ne_cbenttab
    ptr.ne_crc = ne_crc
    ptr.ne_flags = ne_flags
    ptr.ne_autodata = ne_autodata
    ptr.ne_heap = ne_heap
    ptr.ne_stack = ne_stack
    ptr.ne_csip = ne_csip
    ptr.ne_sssp = ne_sssp
    ptr.ne_cseg = ne_cseg
    ptr.ne_cmod = ne_cmod
    ptr.ne_cbnrestab = ne_cbnrestab
    ptr.ne_segtab = ne_segtab
    ptr.ne_rsrctab = ne_rsrctab
    ptr.ne_restab = ne_restab
    ptr.ne_modtab = ne_modtab
    ptr.ne_imptab = ne_imptab
    ptr.ne_nrestab = ne_nrestab
    ptr.ne_cmovent = ne_cmovent
    ptr.ne_align = ne_align
    ptr.ne_cres = ne_cres
    ptr.ne_exetyp = ne_exetyp
    ptr.ne_flagsothers = ne_flagsothers
    ptr.ne_pretthunks = ne_pretthunks
    ptr.ne_psegrefbytes = ne_psegrefbytes
    ptr.ne_swaparea = ne_swaparea
    ptr.ne_expver = ne_expver
    ref[]
end

const IMAGE_OS2_HEADER = _IMAGE_OS2_HEADER

const PIMAGE_OS2_HEADER = Ptr{_IMAGE_OS2_HEADER}

struct _IMAGE_VXD_HEADER
    data::NTuple{196, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_VXD_HEADER}, f::Symbol)
    f === :e32_magic && return Ptr{WORD}(x + 0)
    f === :e32_border && return Ptr{BYTE}(x + 2)
    f === :e32_worder && return Ptr{BYTE}(x + 3)
    f === :e32_level && return Ptr{DWORD}(x + 4)
    f === :e32_cpu && return Ptr{WORD}(x + 8)
    f === :e32_os && return Ptr{WORD}(x + 10)
    f === :e32_ver && return Ptr{DWORD}(x + 12)
    f === :e32_mflags && return Ptr{DWORD}(x + 16)
    f === :e32_mpages && return Ptr{DWORD}(x + 20)
    f === :e32_startobj && return Ptr{DWORD}(x + 24)
    f === :e32_eip && return Ptr{DWORD}(x + 28)
    f === :e32_stackobj && return Ptr{DWORD}(x + 32)
    f === :e32_esp && return Ptr{DWORD}(x + 36)
    f === :e32_pagesize && return Ptr{DWORD}(x + 40)
    f === :e32_lastpagesize && return Ptr{DWORD}(x + 44)
    f === :e32_fixupsize && return Ptr{DWORD}(x + 48)
    f === :e32_fixupsum && return Ptr{DWORD}(x + 52)
    f === :e32_ldrsize && return Ptr{DWORD}(x + 56)
    f === :e32_ldrsum && return Ptr{DWORD}(x + 60)
    f === :e32_objtab && return Ptr{DWORD}(x + 64)
    f === :e32_objcnt && return Ptr{DWORD}(x + 68)
    f === :e32_objmap && return Ptr{DWORD}(x + 72)
    f === :e32_itermap && return Ptr{DWORD}(x + 76)
    f === :e32_rsrctab && return Ptr{DWORD}(x + 80)
    f === :e32_rsrccnt && return Ptr{DWORD}(x + 84)
    f === :e32_restab && return Ptr{DWORD}(x + 88)
    f === :e32_enttab && return Ptr{DWORD}(x + 92)
    f === :e32_dirtab && return Ptr{DWORD}(x + 96)
    f === :e32_dircnt && return Ptr{DWORD}(x + 100)
    f === :e32_fpagetab && return Ptr{DWORD}(x + 104)
    f === :e32_frectab && return Ptr{DWORD}(x + 108)
    f === :e32_impmod && return Ptr{DWORD}(x + 112)
    f === :e32_impmodcnt && return Ptr{DWORD}(x + 116)
    f === :e32_impproc && return Ptr{DWORD}(x + 120)
    f === :e32_pagesum && return Ptr{DWORD}(x + 124)
    f === :e32_datapage && return Ptr{DWORD}(x + 128)
    f === :e32_preload && return Ptr{DWORD}(x + 132)
    f === :e32_nrestab && return Ptr{DWORD}(x + 136)
    f === :e32_cbnrestab && return Ptr{DWORD}(x + 140)
    f === :e32_nressum && return Ptr{DWORD}(x + 144)
    f === :e32_autodata && return Ptr{DWORD}(x + 148)
    f === :e32_debuginfo && return Ptr{DWORD}(x + 152)
    f === :e32_debuglen && return Ptr{DWORD}(x + 156)
    f === :e32_instpreload && return Ptr{DWORD}(x + 160)
    f === :e32_instdemand && return Ptr{DWORD}(x + 164)
    f === :e32_heapsize && return Ptr{DWORD}(x + 168)
    f === :e32_res3 && return Ptr{NTuple{12, BYTE}}(x + 172)
    f === :e32_winresoff && return Ptr{DWORD}(x + 184)
    f === :e32_winreslen && return Ptr{DWORD}(x + 188)
    f === :e32_devid && return Ptr{WORD}(x + 192)
    f === :e32_ddkver && return Ptr{WORD}(x + 194)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_VXD_HEADER, f::Symbol)
    r = Ref{_IMAGE_VXD_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_VXD_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_VXD_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_VXD_HEADER(e32_magic::WORD, e32_border::BYTE, e32_worder::BYTE, e32_level::DWORD, e32_cpu::WORD, e32_os::WORD, e32_ver::DWORD, e32_mflags::DWORD, e32_mpages::DWORD, e32_startobj::DWORD, e32_eip::DWORD, e32_stackobj::DWORD, e32_esp::DWORD, e32_pagesize::DWORD, e32_lastpagesize::DWORD, e32_fixupsize::DWORD, e32_fixupsum::DWORD, e32_ldrsize::DWORD, e32_ldrsum::DWORD, e32_objtab::DWORD, e32_objcnt::DWORD, e32_objmap::DWORD, e32_itermap::DWORD, e32_rsrctab::DWORD, e32_rsrccnt::DWORD, e32_restab::DWORD, e32_enttab::DWORD, e32_dirtab::DWORD, e32_dircnt::DWORD, e32_fpagetab::DWORD, e32_frectab::DWORD, e32_impmod::DWORD, e32_impmodcnt::DWORD, e32_impproc::DWORD, e32_pagesum::DWORD, e32_datapage::DWORD, e32_preload::DWORD, e32_nrestab::DWORD, e32_cbnrestab::DWORD, e32_nressum::DWORD, e32_autodata::DWORD, e32_debuginfo::DWORD, e32_debuglen::DWORD, e32_instpreload::DWORD, e32_instdemand::DWORD, e32_heapsize::DWORD, e32_res3::NTuple{12, BYTE}, e32_winresoff::DWORD, e32_winreslen::DWORD, e32_devid::WORD, e32_ddkver::WORD)
    ref = Ref{_IMAGE_VXD_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_VXD_HEADER}, ref)
    ptr.e32_magic = e32_magic
    ptr.e32_border = e32_border
    ptr.e32_worder = e32_worder
    ptr.e32_level = e32_level
    ptr.e32_cpu = e32_cpu
    ptr.e32_os = e32_os
    ptr.e32_ver = e32_ver
    ptr.e32_mflags = e32_mflags
    ptr.e32_mpages = e32_mpages
    ptr.e32_startobj = e32_startobj
    ptr.e32_eip = e32_eip
    ptr.e32_stackobj = e32_stackobj
    ptr.e32_esp = e32_esp
    ptr.e32_pagesize = e32_pagesize
    ptr.e32_lastpagesize = e32_lastpagesize
    ptr.e32_fixupsize = e32_fixupsize
    ptr.e32_fixupsum = e32_fixupsum
    ptr.e32_ldrsize = e32_ldrsize
    ptr.e32_ldrsum = e32_ldrsum
    ptr.e32_objtab = e32_objtab
    ptr.e32_objcnt = e32_objcnt
    ptr.e32_objmap = e32_objmap
    ptr.e32_itermap = e32_itermap
    ptr.e32_rsrctab = e32_rsrctab
    ptr.e32_rsrccnt = e32_rsrccnt
    ptr.e32_restab = e32_restab
    ptr.e32_enttab = e32_enttab
    ptr.e32_dirtab = e32_dirtab
    ptr.e32_dircnt = e32_dircnt
    ptr.e32_fpagetab = e32_fpagetab
    ptr.e32_frectab = e32_frectab
    ptr.e32_impmod = e32_impmod
    ptr.e32_impmodcnt = e32_impmodcnt
    ptr.e32_impproc = e32_impproc
    ptr.e32_pagesum = e32_pagesum
    ptr.e32_datapage = e32_datapage
    ptr.e32_preload = e32_preload
    ptr.e32_nrestab = e32_nrestab
    ptr.e32_cbnrestab = e32_cbnrestab
    ptr.e32_nressum = e32_nressum
    ptr.e32_autodata = e32_autodata
    ptr.e32_debuginfo = e32_debuginfo
    ptr.e32_debuglen = e32_debuglen
    ptr.e32_instpreload = e32_instpreload
    ptr.e32_instdemand = e32_instdemand
    ptr.e32_heapsize = e32_heapsize
    ptr.e32_res3 = e32_res3
    ptr.e32_winresoff = e32_winresoff
    ptr.e32_winreslen = e32_winreslen
    ptr.e32_devid = e32_devid
    ptr.e32_ddkver = e32_ddkver
    ref[]
end

const IMAGE_VXD_HEADER = _IMAGE_VXD_HEADER

const PIMAGE_VXD_HEADER = Ptr{_IMAGE_VXD_HEADER}

const PIMAGE_FILE_HEADER = Ptr{_IMAGE_FILE_HEADER}

const PIMAGE_DATA_DIRECTORY = Ptr{_IMAGE_DATA_DIRECTORY}

struct _IMAGE_OPTIONAL_HEADER
    data::NTuple{224, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_OPTIONAL_HEADER}, f::Symbol)
    f === :Magic && return Ptr{WORD}(x + 0)
    f === :MajorLinkerVersion && return Ptr{BYTE}(x + 2)
    f === :MinorLinkerVersion && return Ptr{BYTE}(x + 3)
    f === :SizeOfCode && return Ptr{DWORD}(x + 4)
    f === :SizeOfInitializedData && return Ptr{DWORD}(x + 8)
    f === :SizeOfUninitializedData && return Ptr{DWORD}(x + 12)
    f === :AddressOfEntryPoint && return Ptr{DWORD}(x + 16)
    f === :BaseOfCode && return Ptr{DWORD}(x + 20)
    f === :BaseOfData && return Ptr{DWORD}(x + 24)
    f === :ImageBase && return Ptr{DWORD}(x + 28)
    f === :SectionAlignment && return Ptr{DWORD}(x + 32)
    f === :FileAlignment && return Ptr{DWORD}(x + 36)
    f === :MajorOperatingSystemVersion && return Ptr{WORD}(x + 40)
    f === :MinorOperatingSystemVersion && return Ptr{WORD}(x + 42)
    f === :MajorImageVersion && return Ptr{WORD}(x + 44)
    f === :MinorImageVersion && return Ptr{WORD}(x + 46)
    f === :MajorSubsystemVersion && return Ptr{WORD}(x + 48)
    f === :MinorSubsystemVersion && return Ptr{WORD}(x + 50)
    f === :Win32VersionValue && return Ptr{DWORD}(x + 52)
    f === :SizeOfImage && return Ptr{DWORD}(x + 56)
    f === :SizeOfHeaders && return Ptr{DWORD}(x + 60)
    f === :CheckSum && return Ptr{DWORD}(x + 64)
    f === :Subsystem && return Ptr{WORD}(x + 68)
    f === :DllCharacteristics && return Ptr{WORD}(x + 70)
    f === :SizeOfStackReserve && return Ptr{DWORD}(x + 72)
    f === :SizeOfStackCommit && return Ptr{DWORD}(x + 76)
    f === :SizeOfHeapReserve && return Ptr{DWORD}(x + 80)
    f === :SizeOfHeapCommit && return Ptr{DWORD}(x + 84)
    f === :LoaderFlags && return Ptr{DWORD}(x + 88)
    f === :NumberOfRvaAndSizes && return Ptr{DWORD}(x + 92)
    f === :DataDirectory && return Ptr{NTuple{16, IMAGE_DATA_DIRECTORY}}(x + 96)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_OPTIONAL_HEADER, f::Symbol)
    r = Ref{_IMAGE_OPTIONAL_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_OPTIONAL_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_OPTIONAL_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_OPTIONAL_HEADER(Magic::WORD, MajorLinkerVersion::BYTE, MinorLinkerVersion::BYTE, SizeOfCode::DWORD, SizeOfInitializedData::DWORD, SizeOfUninitializedData::DWORD, AddressOfEntryPoint::DWORD, BaseOfCode::DWORD, BaseOfData::DWORD, ImageBase::DWORD, SectionAlignment::DWORD, FileAlignment::DWORD, MajorOperatingSystemVersion::WORD, MinorOperatingSystemVersion::WORD, MajorImageVersion::WORD, MinorImageVersion::WORD, MajorSubsystemVersion::WORD, MinorSubsystemVersion::WORD, Win32VersionValue::DWORD, SizeOfImage::DWORD, SizeOfHeaders::DWORD, CheckSum::DWORD, Subsystem::WORD, DllCharacteristics::WORD, SizeOfStackReserve::DWORD, SizeOfStackCommit::DWORD, SizeOfHeapReserve::DWORD, SizeOfHeapCommit::DWORD, LoaderFlags::DWORD, NumberOfRvaAndSizes::DWORD, DataDirectory::NTuple{16, IMAGE_DATA_DIRECTORY})
    ref = Ref{_IMAGE_OPTIONAL_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_OPTIONAL_HEADER}, ref)
    ptr.Magic = Magic
    ptr.MajorLinkerVersion = MajorLinkerVersion
    ptr.MinorLinkerVersion = MinorLinkerVersion
    ptr.SizeOfCode = SizeOfCode
    ptr.SizeOfInitializedData = SizeOfInitializedData
    ptr.SizeOfUninitializedData = SizeOfUninitializedData
    ptr.AddressOfEntryPoint = AddressOfEntryPoint
    ptr.BaseOfCode = BaseOfCode
    ptr.BaseOfData = BaseOfData
    ptr.ImageBase = ImageBase
    ptr.SectionAlignment = SectionAlignment
    ptr.FileAlignment = FileAlignment
    ptr.MajorOperatingSystemVersion = MajorOperatingSystemVersion
    ptr.MinorOperatingSystemVersion = MinorOperatingSystemVersion
    ptr.MajorImageVersion = MajorImageVersion
    ptr.MinorImageVersion = MinorImageVersion
    ptr.MajorSubsystemVersion = MajorSubsystemVersion
    ptr.MinorSubsystemVersion = MinorSubsystemVersion
    ptr.Win32VersionValue = Win32VersionValue
    ptr.SizeOfImage = SizeOfImage
    ptr.SizeOfHeaders = SizeOfHeaders
    ptr.CheckSum = CheckSum
    ptr.Subsystem = Subsystem
    ptr.DllCharacteristics = DllCharacteristics
    ptr.SizeOfStackReserve = SizeOfStackReserve
    ptr.SizeOfStackCommit = SizeOfStackCommit
    ptr.SizeOfHeapReserve = SizeOfHeapReserve
    ptr.SizeOfHeapCommit = SizeOfHeapCommit
    ptr.LoaderFlags = LoaderFlags
    ptr.NumberOfRvaAndSizes = NumberOfRvaAndSizes
    ptr.DataDirectory = DataDirectory
    ref[]
end

const IMAGE_OPTIONAL_HEADER32 = _IMAGE_OPTIONAL_HEADER

const PIMAGE_OPTIONAL_HEADER32 = Ptr{_IMAGE_OPTIONAL_HEADER}

struct _IMAGE_ROM_OPTIONAL_HEADER
    data::NTuple{56, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ROM_OPTIONAL_HEADER}, f::Symbol)
    f === :Magic && return Ptr{WORD}(x + 0)
    f === :MajorLinkerVersion && return Ptr{BYTE}(x + 2)
    f === :MinorLinkerVersion && return Ptr{BYTE}(x + 3)
    f === :SizeOfCode && return Ptr{DWORD}(x + 4)
    f === :SizeOfInitializedData && return Ptr{DWORD}(x + 8)
    f === :SizeOfUninitializedData && return Ptr{DWORD}(x + 12)
    f === :AddressOfEntryPoint && return Ptr{DWORD}(x + 16)
    f === :BaseOfCode && return Ptr{DWORD}(x + 20)
    f === :BaseOfData && return Ptr{DWORD}(x + 24)
    f === :BaseOfBss && return Ptr{DWORD}(x + 28)
    f === :GprMask && return Ptr{DWORD}(x + 32)
    f === :CprMask && return Ptr{NTuple{4, DWORD}}(x + 36)
    f === :GpValue && return Ptr{DWORD}(x + 52)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ROM_OPTIONAL_HEADER, f::Symbol)
    r = Ref{_IMAGE_ROM_OPTIONAL_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ROM_OPTIONAL_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ROM_OPTIONAL_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ROM_OPTIONAL_HEADER(Magic::WORD, MajorLinkerVersion::BYTE, MinorLinkerVersion::BYTE, SizeOfCode::DWORD, SizeOfInitializedData::DWORD, SizeOfUninitializedData::DWORD, AddressOfEntryPoint::DWORD, BaseOfCode::DWORD, BaseOfData::DWORD, BaseOfBss::DWORD, GprMask::DWORD, CprMask::NTuple{4, DWORD}, GpValue::DWORD)
    ref = Ref{_IMAGE_ROM_OPTIONAL_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ROM_OPTIONAL_HEADER}, ref)
    ptr.Magic = Magic
    ptr.MajorLinkerVersion = MajorLinkerVersion
    ptr.MinorLinkerVersion = MinorLinkerVersion
    ptr.SizeOfCode = SizeOfCode
    ptr.SizeOfInitializedData = SizeOfInitializedData
    ptr.SizeOfUninitializedData = SizeOfUninitializedData
    ptr.AddressOfEntryPoint = AddressOfEntryPoint
    ptr.BaseOfCode = BaseOfCode
    ptr.BaseOfData = BaseOfData
    ptr.BaseOfBss = BaseOfBss
    ptr.GprMask = GprMask
    ptr.CprMask = CprMask
    ptr.GpValue = GpValue
    ref[]
end

const IMAGE_ROM_OPTIONAL_HEADER = _IMAGE_ROM_OPTIONAL_HEADER

const PIMAGE_ROM_OPTIONAL_HEADER = Ptr{_IMAGE_ROM_OPTIONAL_HEADER}

const PIMAGE_OPTIONAL_HEADER64 = Ptr{_IMAGE_OPTIONAL_HEADER64}

const IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER64

const PIMAGE_OPTIONAL_HEADER = PIMAGE_OPTIONAL_HEADER64

const PIMAGE_NT_HEADERS64 = Ptr{_IMAGE_NT_HEADERS64}

struct _IMAGE_NT_HEADERS
    data::NTuple{248, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_NT_HEADERS}, f::Symbol)
    f === :Signature && return Ptr{DWORD}(x + 0)
    f === :FileHeader && return Ptr{IMAGE_FILE_HEADER}(x + 4)
    f === :OptionalHeader && return Ptr{IMAGE_OPTIONAL_HEADER32}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_NT_HEADERS, f::Symbol)
    r = Ref{_IMAGE_NT_HEADERS}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_NT_HEADERS}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_NT_HEADERS}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_NT_HEADERS(Signature::DWORD, FileHeader::IMAGE_FILE_HEADER, OptionalHeader::IMAGE_OPTIONAL_HEADER32)
    ref = Ref{_IMAGE_NT_HEADERS}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_NT_HEADERS}, ref)
    ptr.Signature = Signature
    ptr.FileHeader = FileHeader
    ptr.OptionalHeader = OptionalHeader
    ref[]
end

const IMAGE_NT_HEADERS32 = _IMAGE_NT_HEADERS

const PIMAGE_NT_HEADERS32 = Ptr{_IMAGE_NT_HEADERS}

struct _IMAGE_ROM_HEADERS
    data::NTuple{76, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ROM_HEADERS}, f::Symbol)
    f === :FileHeader && return Ptr{IMAGE_FILE_HEADER}(x + 0)
    f === :OptionalHeader && return Ptr{IMAGE_ROM_OPTIONAL_HEADER}(x + 20)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ROM_HEADERS, f::Symbol)
    r = Ref{_IMAGE_ROM_HEADERS}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ROM_HEADERS}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ROM_HEADERS}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ROM_HEADERS(FileHeader::IMAGE_FILE_HEADER, OptionalHeader::IMAGE_ROM_OPTIONAL_HEADER)
    ref = Ref{_IMAGE_ROM_HEADERS}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ROM_HEADERS}, ref)
    ptr.FileHeader = FileHeader
    ptr.OptionalHeader = OptionalHeader
    ref[]
end

const IMAGE_ROM_HEADERS = _IMAGE_ROM_HEADERS

const PIMAGE_ROM_HEADERS = Ptr{_IMAGE_ROM_HEADERS}

const PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS64

struct ANON_OBJECT_HEADER
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{ANON_OBJECT_HEADER}, f::Symbol)
    f === :Sig1 && return Ptr{WORD}(x + 0)
    f === :Sig2 && return Ptr{WORD}(x + 2)
    f === :Version && return Ptr{WORD}(x + 4)
    f === :Machine && return Ptr{WORD}(x + 6)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 8)
    f === :ClassID && return Ptr{CLSID}(x + 12)
    f === :SizeOfData && return Ptr{DWORD}(x + 28)
    return getfield(x, f)
end

function Base.getproperty(x::ANON_OBJECT_HEADER, f::Symbol)
    r = Ref{ANON_OBJECT_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{ANON_OBJECT_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{ANON_OBJECT_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function ANON_OBJECT_HEADER(Sig1::WORD, Sig2::WORD, Version::WORD, Machine::WORD, TimeDateStamp::DWORD, ClassID::CLSID, SizeOfData::DWORD)
    ref = Ref{ANON_OBJECT_HEADER}()
    ptr = Base.unsafe_convert(Ptr{ANON_OBJECT_HEADER}, ref)
    ptr.Sig1 = Sig1
    ptr.Sig2 = Sig2
    ptr.Version = Version
    ptr.Machine = Machine
    ptr.TimeDateStamp = TimeDateStamp
    ptr.ClassID = ClassID
    ptr.SizeOfData = SizeOfData
    ref[]
end

struct ANON_OBJECT_HEADER_V2
    data::NTuple{44, UInt8}
end

function Base.getproperty(x::Ptr{ANON_OBJECT_HEADER_V2}, f::Symbol)
    f === :Sig1 && return Ptr{WORD}(x + 0)
    f === :Sig2 && return Ptr{WORD}(x + 2)
    f === :Version && return Ptr{WORD}(x + 4)
    f === :Machine && return Ptr{WORD}(x + 6)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 8)
    f === :ClassID && return Ptr{CLSID}(x + 12)
    f === :SizeOfData && return Ptr{DWORD}(x + 28)
    f === :Flags && return Ptr{DWORD}(x + 32)
    f === :MetaDataSize && return Ptr{DWORD}(x + 36)
    f === :MetaDataOffset && return Ptr{DWORD}(x + 40)
    return getfield(x, f)
end

function Base.getproperty(x::ANON_OBJECT_HEADER_V2, f::Symbol)
    r = Ref{ANON_OBJECT_HEADER_V2}(x)
    ptr = Base.unsafe_convert(Ptr{ANON_OBJECT_HEADER_V2}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{ANON_OBJECT_HEADER_V2}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function ANON_OBJECT_HEADER_V2(Sig1::WORD, Sig2::WORD, Version::WORD, Machine::WORD, TimeDateStamp::DWORD, ClassID::CLSID, SizeOfData::DWORD, Flags::DWORD, MetaDataSize::DWORD, MetaDataOffset::DWORD)
    ref = Ref{ANON_OBJECT_HEADER_V2}()
    ptr = Base.unsafe_convert(Ptr{ANON_OBJECT_HEADER_V2}, ref)
    ptr.Sig1 = Sig1
    ptr.Sig2 = Sig2
    ptr.Version = Version
    ptr.Machine = Machine
    ptr.TimeDateStamp = TimeDateStamp
    ptr.ClassID = ClassID
    ptr.SizeOfData = SizeOfData
    ptr.Flags = Flags
    ptr.MetaDataSize = MetaDataSize
    ptr.MetaDataOffset = MetaDataOffset
    ref[]
end

struct ANON_OBJECT_HEADER_BIGOBJ
    data::NTuple{56, UInt8}
end

function Base.getproperty(x::Ptr{ANON_OBJECT_HEADER_BIGOBJ}, f::Symbol)
    f === :Sig1 && return Ptr{WORD}(x + 0)
    f === :Sig2 && return Ptr{WORD}(x + 2)
    f === :Version && return Ptr{WORD}(x + 4)
    f === :Machine && return Ptr{WORD}(x + 6)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 8)
    f === :ClassID && return Ptr{CLSID}(x + 12)
    f === :SizeOfData && return Ptr{DWORD}(x + 28)
    f === :Flags && return Ptr{DWORD}(x + 32)
    f === :MetaDataSize && return Ptr{DWORD}(x + 36)
    f === :MetaDataOffset && return Ptr{DWORD}(x + 40)
    f === :NumberOfSections && return Ptr{DWORD}(x + 44)
    f === :PointerToSymbolTable && return Ptr{DWORD}(x + 48)
    f === :NumberOfSymbols && return Ptr{DWORD}(x + 52)
    return getfield(x, f)
end

function Base.getproperty(x::ANON_OBJECT_HEADER_BIGOBJ, f::Symbol)
    r = Ref{ANON_OBJECT_HEADER_BIGOBJ}(x)
    ptr = Base.unsafe_convert(Ptr{ANON_OBJECT_HEADER_BIGOBJ}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{ANON_OBJECT_HEADER_BIGOBJ}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function ANON_OBJECT_HEADER_BIGOBJ(Sig1::WORD, Sig2::WORD, Version::WORD, Machine::WORD, TimeDateStamp::DWORD, ClassID::CLSID, SizeOfData::DWORD, Flags::DWORD, MetaDataSize::DWORD, MetaDataOffset::DWORD, NumberOfSections::DWORD, PointerToSymbolTable::DWORD, NumberOfSymbols::DWORD)
    ref = Ref{ANON_OBJECT_HEADER_BIGOBJ}()
    ptr = Base.unsafe_convert(Ptr{ANON_OBJECT_HEADER_BIGOBJ}, ref)
    ptr.Sig1 = Sig1
    ptr.Sig2 = Sig2
    ptr.Version = Version
    ptr.Machine = Machine
    ptr.TimeDateStamp = TimeDateStamp
    ptr.ClassID = ClassID
    ptr.SizeOfData = SizeOfData
    ptr.Flags = Flags
    ptr.MetaDataSize = MetaDataSize
    ptr.MetaDataOffset = MetaDataOffset
    ptr.NumberOfSections = NumberOfSections
    ptr.PointerToSymbolTable = PointerToSymbolTable
    ptr.NumberOfSymbols = NumberOfSymbols
    ref[]
end

const IMAGE_SECTION_HEADER = _IMAGE_SECTION_HEADER

struct __JL_Ctag_77
    Short::DWORD
    Long::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_77}, f::Symbol)
    f === :Short && return Ptr{DWORD}(x + 0)
    f === :Long && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_77, f::Symbol)
    r = Ref{__JL_Ctag_77}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_77}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_77}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_76
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_76}, f::Symbol)
    f === :ShortName && return Ptr{NTuple{8, BYTE}}(x + 0)
    f === :Name && return Ptr{__JL_Ctag_77}(x + 0)
    f === :LongName && return Ptr{NTuple{2, DWORD}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_76, f::Symbol)
    r = Ref{__JL_Ctag_76}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_76}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_76}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_76 = Union{NTuple{8, BYTE}, __JL_Ctag_77, NTuple{2, DWORD}}

function __JL_Ctag_76(val::__U___JL_Ctag_76)
    ref = Ref{__JL_Ctag_76}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_76}, ref)
    if val isa NTuple{8, BYTE}
        ptr.ShortName = val
    elseif val isa __JL_Ctag_77
        ptr.Name = val
    elseif val isa NTuple{2, DWORD}
        ptr.LongName = val
    end
    ref[]
end

struct _IMAGE_SYMBOL
    data::NTuple{18, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_SYMBOL}, f::Symbol)
    f === :N && return Ptr{__JL_Ctag_76}(x + 0)
    f === :Value && return Ptr{DWORD}(x + 8)
    f === :SectionNumber && return Ptr{SHORT}(x + 12)
    f === :Type && return Ptr{WORD}(x + 14)
    f === :StorageClass && return Ptr{BYTE}(x + 16)
    f === :NumberOfAuxSymbols && return Ptr{BYTE}(x + 17)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_SYMBOL, f::Symbol)
    r = Ref{_IMAGE_SYMBOL}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SYMBOL}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_SYMBOL}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_SYMBOL(N::__JL_Ctag_76, Value::DWORD, SectionNumber::SHORT, Type::WORD, StorageClass::BYTE, NumberOfAuxSymbols::BYTE)
    ref = Ref{_IMAGE_SYMBOL}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SYMBOL}, ref)
    ptr.N = N
    ptr.Value = Value
    ptr.SectionNumber = SectionNumber
    ptr.Type = Type
    ptr.StorageClass = StorageClass
    ptr.NumberOfAuxSymbols = NumberOfAuxSymbols
    ref[]
end

const IMAGE_SYMBOL = _IMAGE_SYMBOL

const PIMAGE_SYMBOL = Ptr{IMAGE_SYMBOL}

struct __JL_Ctag_50
    Short::DWORD
    Long::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_50}, f::Symbol)
    f === :Short && return Ptr{DWORD}(x + 0)
    f === :Long && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_50, f::Symbol)
    r = Ref{__JL_Ctag_50}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_50}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_50}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_49
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_49}, f::Symbol)
    f === :ShortName && return Ptr{NTuple{8, BYTE}}(x + 0)
    f === :Name && return Ptr{__JL_Ctag_50}(x + 0)
    f === :LongName && return Ptr{NTuple{2, DWORD}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_49, f::Symbol)
    r = Ref{__JL_Ctag_49}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_49}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_49}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_49 = Union{NTuple{8, BYTE}, __JL_Ctag_50, NTuple{2, DWORD}}

function __JL_Ctag_49(val::__U___JL_Ctag_49)
    ref = Ref{__JL_Ctag_49}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_49}, ref)
    if val isa NTuple{8, BYTE}
        ptr.ShortName = val
    elseif val isa __JL_Ctag_50
        ptr.Name = val
    elseif val isa NTuple{2, DWORD}
        ptr.LongName = val
    end
    ref[]
end

struct _IMAGE_SYMBOL_EX
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_SYMBOL_EX}, f::Symbol)
    f === :N && return Ptr{__JL_Ctag_49}(x + 0)
    f === :Value && return Ptr{DWORD}(x + 8)
    f === :SectionNumber && return Ptr{LONG}(x + 12)
    f === :Type && return Ptr{WORD}(x + 16)
    f === :StorageClass && return Ptr{BYTE}(x + 18)
    f === :NumberOfAuxSymbols && return Ptr{BYTE}(x + 19)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_SYMBOL_EX, f::Symbol)
    r = Ref{_IMAGE_SYMBOL_EX}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SYMBOL_EX}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_SYMBOL_EX}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_SYMBOL_EX(N::__JL_Ctag_49, Value::DWORD, SectionNumber::LONG, Type::WORD, StorageClass::BYTE, NumberOfAuxSymbols::BYTE)
    ref = Ref{_IMAGE_SYMBOL_EX}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SYMBOL_EX}, ref)
    ptr.N = N
    ptr.Value = Value
    ptr.SectionNumber = SectionNumber
    ptr.Type = Type
    ptr.StorageClass = StorageClass
    ptr.NumberOfAuxSymbols = NumberOfAuxSymbols
    ref[]
end

const IMAGE_SYMBOL_EX = _IMAGE_SYMBOL_EX

const PIMAGE_SYMBOL_EX = Ptr{IMAGE_SYMBOL_EX}

struct IMAGE_AUX_SYMBOL_TOKEN_DEF
    data::NTuple{18, UInt8}
end

function Base.getproperty(x::Ptr{IMAGE_AUX_SYMBOL_TOKEN_DEF}, f::Symbol)
    f === :bAuxType && return Ptr{BYTE}(x + 0)
    f === :bReserved && return Ptr{BYTE}(x + 1)
    f === :SymbolTableIndex && return Ptr{DWORD}(x + 2)
    f === :rgbReserved && return Ptr{NTuple{12, BYTE}}(x + 6)
    return getfield(x, f)
end

function Base.getproperty(x::IMAGE_AUX_SYMBOL_TOKEN_DEF, f::Symbol)
    r = Ref{IMAGE_AUX_SYMBOL_TOKEN_DEF}(x)
    ptr = Base.unsafe_convert(Ptr{IMAGE_AUX_SYMBOL_TOKEN_DEF}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{IMAGE_AUX_SYMBOL_TOKEN_DEF}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function IMAGE_AUX_SYMBOL_TOKEN_DEF(bAuxType::BYTE, bReserved::BYTE, SymbolTableIndex::DWORD, rgbReserved::NTuple{12, BYTE})
    ref = Ref{IMAGE_AUX_SYMBOL_TOKEN_DEF}()
    ptr = Base.unsafe_convert(Ptr{IMAGE_AUX_SYMBOL_TOKEN_DEF}, ref)
    ptr.bAuxType = bAuxType
    ptr.bReserved = bReserved
    ptr.SymbolTableIndex = SymbolTableIndex
    ptr.rgbReserved = rgbReserved
    ref[]
end

const PIMAGE_AUX_SYMBOL_TOKEN_DEF = Ptr{IMAGE_AUX_SYMBOL_TOKEN_DEF}

struct __JL_Ctag_55
    Linenumber::WORD
    Size::WORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_55}, f::Symbol)
    f === :Linenumber && return Ptr{WORD}(x + 0)
    f === :Size && return Ptr{WORD}(x + 2)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_55, f::Symbol)
    r = Ref{__JL_Ctag_55}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_55}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_55}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_54
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_54}, f::Symbol)
    f === :LnSz && return Ptr{__JL_Ctag_55}(x + 0)
    f === :TotalSize && return Ptr{DWORD}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_54, f::Symbol)
    r = Ref{__JL_Ctag_54}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_54}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_54}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_54 = Union{__JL_Ctag_55, DWORD}

function __JL_Ctag_54(val::__U___JL_Ctag_54)
    ref = Ref{__JL_Ctag_54}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_54}, ref)
    if val isa __JL_Ctag_55
        ptr.LnSz = val
    elseif val isa DWORD
        ptr.TotalSize = val
    end
    ref[]
end

struct __JL_Ctag_57
    PointerToLinenumber::DWORD
    PointerToNextFunction::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_57}, f::Symbol)
    f === :PointerToLinenumber && return Ptr{DWORD}(x + 0)
    f === :PointerToNextFunction && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_57, f::Symbol)
    r = Ref{__JL_Ctag_57}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_57}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_57}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_58
    Dimension::NTuple{4, WORD}
end
function Base.getproperty(x::Ptr{__JL_Ctag_58}, f::Symbol)
    f === :Dimension && return Ptr{NTuple{4, WORD}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_58, f::Symbol)
    r = Ref{__JL_Ctag_58}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_58}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_58}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_56
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_56}, f::Symbol)
    f === :Function && return Ptr{__JL_Ctag_57}(x + 0)
    f === :Array && return Ptr{__JL_Ctag_58}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_56, f::Symbol)
    r = Ref{__JL_Ctag_56}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_56}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_56}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_56 = Union{__JL_Ctag_57, __JL_Ctag_58}

function __JL_Ctag_56(val::__U___JL_Ctag_56)
    ref = Ref{__JL_Ctag_56}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_56}, ref)
    if val isa __JL_Ctag_57
        ptr.Function = val
    elseif val isa __JL_Ctag_58
        ptr.Array = val
    end
    ref[]
end

struct __JL_Ctag_53
    data::NTuple{18, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_53}, f::Symbol)
    f === :TagIndex && return Ptr{DWORD}(x + 0)
    f === :Misc && return Ptr{__JL_Ctag_54}(x + 4)
    f === :FcnAry && return Ptr{__JL_Ctag_56}(x + 8)
    f === :TvIndex && return Ptr{WORD}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_53, f::Symbol)
    r = Ref{__JL_Ctag_53}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_53}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_53}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function __JL_Ctag_53(TagIndex::DWORD, Misc::__JL_Ctag_54, FcnAry::__JL_Ctag_56, TvIndex::WORD)
    ref = Ref{__JL_Ctag_53}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_53}, ref)
    ptr.TagIndex = TagIndex
    ptr.Misc = Misc
    ptr.FcnAry = FcnAry
    ptr.TvIndex = TvIndex
    ref[]
end

struct __JL_Ctag_59
    Name::NTuple{18, BYTE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_59}, f::Symbol)
    f === :Name && return Ptr{NTuple{18, BYTE}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_59, f::Symbol)
    r = Ref{__JL_Ctag_59}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_59}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_59}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_60
    Length::DWORD
    NumberOfRelocations::WORD
    NumberOfLinenumbers::WORD
    CheckSum::DWORD
    Number::SHORT
    Selection::BYTE
    bReserved::BYTE
    HighNumber::SHORT
end
function Base.getproperty(x::Ptr{__JL_Ctag_60}, f::Symbol)
    f === :Length && return Ptr{DWORD}(x + 0)
    f === :NumberOfRelocations && return Ptr{WORD}(x + 4)
    f === :NumberOfLinenumbers && return Ptr{WORD}(x + 6)
    f === :CheckSum && return Ptr{DWORD}(x + 8)
    f === :Number && return Ptr{SHORT}(x + 12)
    f === :Selection && return Ptr{BYTE}(x + 14)
    f === :bReserved && return Ptr{BYTE}(x + 15)
    f === :HighNumber && return Ptr{SHORT}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_60, f::Symbol)
    r = Ref{__JL_Ctag_60}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_60}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_60}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_61
    crc::DWORD
    rgbReserved::NTuple{14, BYTE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_61}, f::Symbol)
    f === :crc && return Ptr{DWORD}(x + 0)
    f === :rgbReserved && return Ptr{NTuple{14, BYTE}}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_61, f::Symbol)
    r = Ref{__JL_Ctag_61}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_61}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_61}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct _IMAGE_AUX_SYMBOL
    data::NTuple{18, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_AUX_SYMBOL}, f::Symbol)
    f === :Sym && return Ptr{Cvoid}(x + 0)
    f === :File && return Ptr{__JL_Ctag_59}(x + 0)
    f === :Section && return Ptr{__JL_Ctag_60}(x + 0)
    f === :TokenDef && return Ptr{IMAGE_AUX_SYMBOL_TOKEN_DEF}(x + 0)
    f === :CRC && return Ptr{__JL_Ctag_61}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_AUX_SYMBOL, f::Symbol)
    r = Ref{_IMAGE_AUX_SYMBOL}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_AUX_SYMBOL}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_AUX_SYMBOL}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__IMAGE_AUX_SYMBOL = Union{Cvoid, __JL_Ctag_59, __JL_Ctag_60, IMAGE_AUX_SYMBOL_TOKEN_DEF, __JL_Ctag_61}

function _IMAGE_AUX_SYMBOL(val::__U__IMAGE_AUX_SYMBOL)
    ref = Ref{_IMAGE_AUX_SYMBOL}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_AUX_SYMBOL}, ref)
    if val isa Cvoid
        ptr.Sym = val
    elseif val isa __JL_Ctag_59
        ptr.File = val
    elseif val isa __JL_Ctag_60
        ptr.Section = val
    elseif val isa IMAGE_AUX_SYMBOL_TOKEN_DEF
        ptr.TokenDef = val
    elseif val isa __JL_Ctag_61
        ptr.CRC = val
    end
    ref[]
end

const IMAGE_AUX_SYMBOL = _IMAGE_AUX_SYMBOL

const PIMAGE_AUX_SYMBOL = Ptr{IMAGE_AUX_SYMBOL}

struct __JL_Ctag_71
    WeakDefaultSymIndex::DWORD
    WeakSearchType::DWORD
    rgbReserved::NTuple{12, BYTE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_71}, f::Symbol)
    f === :WeakDefaultSymIndex && return Ptr{DWORD}(x + 0)
    f === :WeakSearchType && return Ptr{DWORD}(x + 4)
    f === :rgbReserved && return Ptr{NTuple{12, BYTE}}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_71, f::Symbol)
    r = Ref{__JL_Ctag_71}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_71}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_71}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_72
    Name::NTuple{20, BYTE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_72}, f::Symbol)
    f === :Name && return Ptr{NTuple{20, BYTE}}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_72, f::Symbol)
    r = Ref{__JL_Ctag_72}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_72}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_72}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_73
    Length::DWORD
    NumberOfRelocations::WORD
    NumberOfLinenumbers::WORD
    CheckSum::DWORD
    Number::SHORT
    Selection::BYTE
    bReserved::BYTE
    HighNumber::SHORT
    rgbReserved::NTuple{2, BYTE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_73}, f::Symbol)
    f === :Length && return Ptr{DWORD}(x + 0)
    f === :NumberOfRelocations && return Ptr{WORD}(x + 4)
    f === :NumberOfLinenumbers && return Ptr{WORD}(x + 6)
    f === :CheckSum && return Ptr{DWORD}(x + 8)
    f === :Number && return Ptr{SHORT}(x + 12)
    f === :Selection && return Ptr{BYTE}(x + 14)
    f === :bReserved && return Ptr{BYTE}(x + 15)
    f === :HighNumber && return Ptr{SHORT}(x + 16)
    f === :rgbReserved && return Ptr{NTuple{2, BYTE}}(x + 18)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_73, f::Symbol)
    r = Ref{__JL_Ctag_73}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_73}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_73}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_74
    crc::DWORD
    rgbReserved::NTuple{16, BYTE}
end
function Base.getproperty(x::Ptr{__JL_Ctag_74}, f::Symbol)
    f === :crc && return Ptr{DWORD}(x + 0)
    f === :rgbReserved && return Ptr{NTuple{16, BYTE}}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_74, f::Symbol)
    r = Ref{__JL_Ctag_74}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_74}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_74}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct _IMAGE_AUX_SYMBOL_EX
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_AUX_SYMBOL_EX}, f::Symbol)
    f === :Sym && return Ptr{__JL_Ctag_71}(x + 0)
    f === :File && return Ptr{__JL_Ctag_72}(x + 0)
    f === :Section && return Ptr{__JL_Ctag_73}(x + 0)
    f === :TokenDef && return Ptr{IMAGE_AUX_SYMBOL_TOKEN_DEF}(x + 0)
    f === :rgbReserved && return Ptr{NTuple{2, BYTE}}(x + 18)
    f === :CRC && return Ptr{__JL_Ctag_74}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_AUX_SYMBOL_EX, f::Symbol)
    r = Ref{_IMAGE_AUX_SYMBOL_EX}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_AUX_SYMBOL_EX}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_AUX_SYMBOL_EX}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__IMAGE_AUX_SYMBOL_EX = Union{__JL_Ctag_71, __JL_Ctag_72, __JL_Ctag_73, __JL_Ctag_74}

function _IMAGE_AUX_SYMBOL_EX(val::__U__IMAGE_AUX_SYMBOL_EX)
    ref = Ref{_IMAGE_AUX_SYMBOL_EX}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_AUX_SYMBOL_EX}, ref)
    if val isa __JL_Ctag_71
        ptr.Sym = val
    elseif val isa __JL_Ctag_72
        ptr.File = val
    elseif val isa __JL_Ctag_73
        ptr.Section = val
    elseif val isa __JL_Ctag_74
        ptr.CRC = val
    end
    ref[]
end

const IMAGE_AUX_SYMBOL_EX = _IMAGE_AUX_SYMBOL_EX

const PIMAGE_AUX_SYMBOL_EX = Ptr{IMAGE_AUX_SYMBOL_EX}

@cenum IMAGE_AUX_SYMBOL_TYPE::UInt32 begin
    IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1
end

struct _IMAGE_RELOCATION
    data::NTuple{10, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_RELOCATION}, f::Symbol)
    f === :VirtualAddress && return Ptr{DWORD}(x + 0)
    f === :RelocCount && return Ptr{DWORD}(x + 0)
    f === :SymbolTableIndex && return Ptr{DWORD}(x + 4)
    f === :Type && return Ptr{WORD}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_RELOCATION, f::Symbol)
    r = Ref{_IMAGE_RELOCATION}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RELOCATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_RELOCATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_RELOCATION(SymbolTableIndex::DWORD, Type::WORD)
    ref = Ref{_IMAGE_RELOCATION}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RELOCATION}, ref)
    ptr.SymbolTableIndex = SymbolTableIndex
    ptr.Type = Type
    ref[]
end

const IMAGE_RELOCATION = _IMAGE_RELOCATION

const PIMAGE_RELOCATION = Ptr{IMAGE_RELOCATION}

struct __JL_Ctag_48
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_48}, f::Symbol)
    f === :SymbolTableIndex && return Ptr{DWORD}(x + 0)
    f === :VirtualAddress && return Ptr{DWORD}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_48, f::Symbol)
    r = Ref{__JL_Ctag_48}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_48}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_48}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_48 = Union{DWORD, DWORD}

function __JL_Ctag_48(val::__U___JL_Ctag_48)
    ref = Ref{__JL_Ctag_48}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_48}, ref)
    if val isa DWORD
        ptr.SymbolTableIndex = val
    elseif val isa DWORD
        ptr.VirtualAddress = val
    end
    ref[]
end

struct _IMAGE_LINENUMBER
    data::NTuple{6, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_LINENUMBER}, f::Symbol)
    f === :Type && return Ptr{__JL_Ctag_48}(x + 0)
    f === :Linenumber && return Ptr{WORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_LINENUMBER, f::Symbol)
    r = Ref{_IMAGE_LINENUMBER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_LINENUMBER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_LINENUMBER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_LINENUMBER(Type::__JL_Ctag_48, Linenumber::WORD)
    ref = Ref{_IMAGE_LINENUMBER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_LINENUMBER}, ref)
    ptr.Type = Type
    ptr.Linenumber = Linenumber
    ref[]
end

const IMAGE_LINENUMBER = _IMAGE_LINENUMBER

const PIMAGE_LINENUMBER = Ptr{IMAGE_LINENUMBER}

struct _IMAGE_BASE_RELOCATION
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_BASE_RELOCATION}, f::Symbol)
    f === :VirtualAddress && return Ptr{DWORD}(x + 0)
    f === :SizeOfBlock && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_BASE_RELOCATION, f::Symbol)
    r = Ref{_IMAGE_BASE_RELOCATION}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BASE_RELOCATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_BASE_RELOCATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_BASE_RELOCATION(VirtualAddress::DWORD, SizeOfBlock::DWORD)
    ref = Ref{_IMAGE_BASE_RELOCATION}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BASE_RELOCATION}, ref)
    ptr.VirtualAddress = VirtualAddress
    ptr.SizeOfBlock = SizeOfBlock
    ref[]
end

const IMAGE_BASE_RELOCATION = _IMAGE_BASE_RELOCATION

const PIMAGE_BASE_RELOCATION = Ptr{IMAGE_BASE_RELOCATION}

struct _IMAGE_ARCHIVE_MEMBER_HEADER
    data::NTuple{60, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ARCHIVE_MEMBER_HEADER}, f::Symbol)
    f === :Name && return Ptr{NTuple{16, BYTE}}(x + 0)
    f === :Date && return Ptr{NTuple{12, BYTE}}(x + 16)
    f === :UserID && return Ptr{NTuple{6, BYTE}}(x + 28)
    f === :GroupID && return Ptr{NTuple{6, BYTE}}(x + 34)
    f === :Mode && return Ptr{NTuple{8, BYTE}}(x + 40)
    f === :Size && return Ptr{NTuple{10, BYTE}}(x + 48)
    f === :EndHeader && return Ptr{NTuple{2, BYTE}}(x + 58)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ARCHIVE_MEMBER_HEADER, f::Symbol)
    r = Ref{_IMAGE_ARCHIVE_MEMBER_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ARCHIVE_MEMBER_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ARCHIVE_MEMBER_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ARCHIVE_MEMBER_HEADER(Name::NTuple{16, BYTE}, Date::NTuple{12, BYTE}, UserID::NTuple{6, BYTE}, GroupID::NTuple{6, BYTE}, Mode::NTuple{8, BYTE}, Size::NTuple{10, BYTE}, EndHeader::NTuple{2, BYTE})
    ref = Ref{_IMAGE_ARCHIVE_MEMBER_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ARCHIVE_MEMBER_HEADER}, ref)
    ptr.Name = Name
    ptr.Date = Date
    ptr.UserID = UserID
    ptr.GroupID = GroupID
    ptr.Mode = Mode
    ptr.Size = Size
    ptr.EndHeader = EndHeader
    ref[]
end

const IMAGE_ARCHIVE_MEMBER_HEADER = _IMAGE_ARCHIVE_MEMBER_HEADER

const PIMAGE_ARCHIVE_MEMBER_HEADER = Ptr{_IMAGE_ARCHIVE_MEMBER_HEADER}

struct _IMAGE_EXPORT_DIRECTORY
    data::NTuple{40, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_EXPORT_DIRECTORY}, f::Symbol)
    f === :Characteristics && return Ptr{DWORD}(x + 0)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 4)
    f === :MajorVersion && return Ptr{WORD}(x + 8)
    f === :MinorVersion && return Ptr{WORD}(x + 10)
    f === :Name && return Ptr{DWORD}(x + 12)
    f === :Base && return Ptr{DWORD}(x + 16)
    f === :NumberOfFunctions && return Ptr{DWORD}(x + 20)
    f === :NumberOfNames && return Ptr{DWORD}(x + 24)
    f === :AddressOfFunctions && return Ptr{DWORD}(x + 28)
    f === :AddressOfNames && return Ptr{DWORD}(x + 32)
    f === :AddressOfNameOrdinals && return Ptr{DWORD}(x + 36)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_EXPORT_DIRECTORY, f::Symbol)
    r = Ref{_IMAGE_EXPORT_DIRECTORY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_EXPORT_DIRECTORY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_EXPORT_DIRECTORY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_EXPORT_DIRECTORY(Characteristics::DWORD, TimeDateStamp::DWORD, MajorVersion::WORD, MinorVersion::WORD, Name::DWORD, Base::DWORD, NumberOfFunctions::DWORD, NumberOfNames::DWORD, AddressOfFunctions::DWORD, AddressOfNames::DWORD, AddressOfNameOrdinals::DWORD)
    ref = Ref{_IMAGE_EXPORT_DIRECTORY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_EXPORT_DIRECTORY}, ref)
    ptr.Characteristics = Characteristics
    ptr.TimeDateStamp = TimeDateStamp
    ptr.MajorVersion = MajorVersion
    ptr.MinorVersion = MinorVersion
    ptr.Name = Name
    ptr.Base = Base
    ptr.NumberOfFunctions = NumberOfFunctions
    ptr.NumberOfNames = NumberOfNames
    ptr.AddressOfFunctions = AddressOfFunctions
    ptr.AddressOfNames = AddressOfNames
    ptr.AddressOfNameOrdinals = AddressOfNameOrdinals
    ref[]
end

const IMAGE_EXPORT_DIRECTORY = _IMAGE_EXPORT_DIRECTORY

const PIMAGE_EXPORT_DIRECTORY = Ptr{_IMAGE_EXPORT_DIRECTORY}

struct _IMAGE_IMPORT_BY_NAME
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_IMPORT_BY_NAME}, f::Symbol)
    f === :Hint && return Ptr{WORD}(x + 0)
    f === :Name && return Ptr{NTuple{1, CHAR}}(x + 2)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_IMPORT_BY_NAME, f::Symbol)
    r = Ref{_IMAGE_IMPORT_BY_NAME}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_IMPORT_BY_NAME}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_IMPORT_BY_NAME}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_IMPORT_BY_NAME(Hint::WORD, Name::NTuple{1, CHAR})
    ref = Ref{_IMAGE_IMPORT_BY_NAME}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_IMPORT_BY_NAME}, ref)
    ptr.Hint = Hint
    ptr.Name = Name
    ref[]
end

const IMAGE_IMPORT_BY_NAME = _IMAGE_IMPORT_BY_NAME

const PIMAGE_IMPORT_BY_NAME = Ptr{_IMAGE_IMPORT_BY_NAME}

struct __JL_Ctag_85
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_85}, f::Symbol)
    f === :ForwarderString && return Ptr{ULONGLONG}(x + 0)
    f === :Function && return Ptr{ULONGLONG}(x + 0)
    f === :Ordinal && return Ptr{ULONGLONG}(x + 0)
    f === :AddressOfData && return Ptr{ULONGLONG}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_85, f::Symbol)
    r = Ref{__JL_Ctag_85}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_85}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_85}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_85 = Union{ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG}

function __JL_Ctag_85(val::__U___JL_Ctag_85)
    ref = Ref{__JL_Ctag_85}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_85}, ref)
    if val isa ULONGLONG
        ptr.ForwarderString = val
    elseif val isa ULONGLONG
        ptr.Function = val
    elseif val isa ULONGLONG
        ptr.Ordinal = val
    elseif val isa ULONGLONG
        ptr.AddressOfData = val
    end
    ref[]
end

struct _IMAGE_THUNK_DATA64
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_THUNK_DATA64}, f::Symbol)
    f === :u1 && return Ptr{__JL_Ctag_85}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_THUNK_DATA64, f::Symbol)
    r = Ref{_IMAGE_THUNK_DATA64}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_THUNK_DATA64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_THUNK_DATA64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_THUNK_DATA64(u1::__JL_Ctag_85)
    ref = Ref{_IMAGE_THUNK_DATA64}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_THUNK_DATA64}, ref)
    ptr.u1 = u1
    ref[]
end

const IMAGE_THUNK_DATA64 = _IMAGE_THUNK_DATA64

const PIMAGE_THUNK_DATA64 = Ptr{IMAGE_THUNK_DATA64}

struct __JL_Ctag_87
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_87}, f::Symbol)
    f === :ForwarderString && return Ptr{DWORD}(x + 0)
    f === :Function && return Ptr{DWORD}(x + 0)
    f === :Ordinal && return Ptr{DWORD}(x + 0)
    f === :AddressOfData && return Ptr{DWORD}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_87, f::Symbol)
    r = Ref{__JL_Ctag_87}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_87}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_87}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_87 = Union{DWORD, DWORD, DWORD, DWORD}

function __JL_Ctag_87(val::__U___JL_Ctag_87)
    ref = Ref{__JL_Ctag_87}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_87}, ref)
    if val isa DWORD
        ptr.ForwarderString = val
    elseif val isa DWORD
        ptr.Function = val
    elseif val isa DWORD
        ptr.Ordinal = val
    elseif val isa DWORD
        ptr.AddressOfData = val
    end
    ref[]
end

struct _IMAGE_THUNK_DATA32
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_THUNK_DATA32}, f::Symbol)
    f === :u1 && return Ptr{__JL_Ctag_87}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_THUNK_DATA32, f::Symbol)
    r = Ref{_IMAGE_THUNK_DATA32}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_THUNK_DATA32}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_THUNK_DATA32}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_THUNK_DATA32(u1::__JL_Ctag_87)
    ref = Ref{_IMAGE_THUNK_DATA32}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_THUNK_DATA32}, ref)
    ptr.u1 = u1
    ref[]
end

const IMAGE_THUNK_DATA32 = _IMAGE_THUNK_DATA32

const PIMAGE_THUNK_DATA32 = Ptr{IMAGE_THUNK_DATA32}

# typedef VOID ( NTAPI * PIMAGE_TLS_CALLBACK ) ( PVOID DllHandle , DWORD Reason , PVOID Reserved )
const PIMAGE_TLS_CALLBACK = Ptr{Cvoid}

struct _IMAGE_TLS_DIRECTORY64
    data::NTuple{40, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_TLS_DIRECTORY64}, f::Symbol)
    f === :StartAddressOfRawData && return Ptr{ULONGLONG}(x + 0)
    f === :EndAddressOfRawData && return Ptr{ULONGLONG}(x + 8)
    f === :AddressOfIndex && return Ptr{ULONGLONG}(x + 16)
    f === :AddressOfCallBacks && return Ptr{ULONGLONG}(x + 24)
    f === :SizeOfZeroFill && return Ptr{DWORD}(x + 32)
    f === :Characteristics && return Ptr{DWORD}(x + 36)
    f === :Reserved0 && return (Ptr{DWORD}(x + 36), 0, 20)
    f === :Alignment && return (Ptr{DWORD}(x + 36), 20, 4)
    f === :Reserved1 && return (Ptr{DWORD}(x + 36), 24, 8)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_TLS_DIRECTORY64, f::Symbol)
    r = Ref{_IMAGE_TLS_DIRECTORY64}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_TLS_DIRECTORY64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_TLS_DIRECTORY64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_TLS_DIRECTORY64(StartAddressOfRawData::ULONGLONG, EndAddressOfRawData::ULONGLONG, AddressOfIndex::ULONGLONG, AddressOfCallBacks::ULONGLONG, SizeOfZeroFill::DWORD)
    ref = Ref{_IMAGE_TLS_DIRECTORY64}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_TLS_DIRECTORY64}, ref)
    ptr.StartAddressOfRawData = StartAddressOfRawData
    ptr.EndAddressOfRawData = EndAddressOfRawData
    ptr.AddressOfIndex = AddressOfIndex
    ptr.AddressOfCallBacks = AddressOfCallBacks
    ptr.SizeOfZeroFill = SizeOfZeroFill
    ref[]
end

const IMAGE_TLS_DIRECTORY64 = _IMAGE_TLS_DIRECTORY64

const PIMAGE_TLS_DIRECTORY64 = Ptr{IMAGE_TLS_DIRECTORY64}

struct _IMAGE_TLS_DIRECTORY32
    data::NTuple{24, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_TLS_DIRECTORY32}, f::Symbol)
    f === :StartAddressOfRawData && return Ptr{DWORD}(x + 0)
    f === :EndAddressOfRawData && return Ptr{DWORD}(x + 4)
    f === :AddressOfIndex && return Ptr{DWORD}(x + 8)
    f === :AddressOfCallBacks && return Ptr{DWORD}(x + 12)
    f === :SizeOfZeroFill && return Ptr{DWORD}(x + 16)
    f === :Characteristics && return Ptr{DWORD}(x + 20)
    f === :Reserved0 && return (Ptr{DWORD}(x + 20), 0, 20)
    f === :Alignment && return (Ptr{DWORD}(x + 20), 20, 4)
    f === :Reserved1 && return (Ptr{DWORD}(x + 20), 24, 8)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_TLS_DIRECTORY32, f::Symbol)
    r = Ref{_IMAGE_TLS_DIRECTORY32}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_TLS_DIRECTORY32}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_TLS_DIRECTORY32}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_TLS_DIRECTORY32(StartAddressOfRawData::DWORD, EndAddressOfRawData::DWORD, AddressOfIndex::DWORD, AddressOfCallBacks::DWORD, SizeOfZeroFill::DWORD)
    ref = Ref{_IMAGE_TLS_DIRECTORY32}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_TLS_DIRECTORY32}, ref)
    ptr.StartAddressOfRawData = StartAddressOfRawData
    ptr.EndAddressOfRawData = EndAddressOfRawData
    ptr.AddressOfIndex = AddressOfIndex
    ptr.AddressOfCallBacks = AddressOfCallBacks
    ptr.SizeOfZeroFill = SizeOfZeroFill
    ref[]
end

const IMAGE_TLS_DIRECTORY32 = _IMAGE_TLS_DIRECTORY32

const PIMAGE_TLS_DIRECTORY32 = Ptr{IMAGE_TLS_DIRECTORY32}

const IMAGE_THUNK_DATA = IMAGE_THUNK_DATA64

const PIMAGE_THUNK_DATA = PIMAGE_THUNK_DATA64

const IMAGE_TLS_DIRECTORY = IMAGE_TLS_DIRECTORY64

const PIMAGE_TLS_DIRECTORY = PIMAGE_TLS_DIRECTORY64

struct _IMAGE_IMPORT_DESCRIPTOR
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_IMPORT_DESCRIPTOR}, f::Symbol)
    f === :Characteristics && return Ptr{DWORD}(x + 0)
    f === :OriginalFirstThunk && return Ptr{DWORD}(x + 0)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 4)
    f === :ForwarderChain && return Ptr{DWORD}(x + 8)
    f === :Name && return Ptr{DWORD}(x + 12)
    f === :FirstThunk && return Ptr{DWORD}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_IMPORT_DESCRIPTOR, f::Symbol)
    r = Ref{_IMAGE_IMPORT_DESCRIPTOR}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_IMPORT_DESCRIPTOR}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_IMPORT_DESCRIPTOR}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_IMPORT_DESCRIPTOR(TimeDateStamp::DWORD, ForwarderChain::DWORD, Name::DWORD, FirstThunk::DWORD)
    ref = Ref{_IMAGE_IMPORT_DESCRIPTOR}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_IMPORT_DESCRIPTOR}, ref)
    ptr.TimeDateStamp = TimeDateStamp
    ptr.ForwarderChain = ForwarderChain
    ptr.Name = Name
    ptr.FirstThunk = FirstThunk
    ref[]
end

const IMAGE_IMPORT_DESCRIPTOR = _IMAGE_IMPORT_DESCRIPTOR

const PIMAGE_IMPORT_DESCRIPTOR = Ptr{IMAGE_IMPORT_DESCRIPTOR}

struct _IMAGE_BOUND_IMPORT_DESCRIPTOR
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_BOUND_IMPORT_DESCRIPTOR}, f::Symbol)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 0)
    f === :OffsetModuleName && return Ptr{WORD}(x + 4)
    f === :NumberOfModuleForwarderRefs && return Ptr{WORD}(x + 6)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_BOUND_IMPORT_DESCRIPTOR, f::Symbol)
    r = Ref{_IMAGE_BOUND_IMPORT_DESCRIPTOR}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BOUND_IMPORT_DESCRIPTOR}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_BOUND_IMPORT_DESCRIPTOR}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_BOUND_IMPORT_DESCRIPTOR(TimeDateStamp::DWORD, OffsetModuleName::WORD, NumberOfModuleForwarderRefs::WORD)
    ref = Ref{_IMAGE_BOUND_IMPORT_DESCRIPTOR}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BOUND_IMPORT_DESCRIPTOR}, ref)
    ptr.TimeDateStamp = TimeDateStamp
    ptr.OffsetModuleName = OffsetModuleName
    ptr.NumberOfModuleForwarderRefs = NumberOfModuleForwarderRefs
    ref[]
end

const IMAGE_BOUND_IMPORT_DESCRIPTOR = _IMAGE_BOUND_IMPORT_DESCRIPTOR

const PIMAGE_BOUND_IMPORT_DESCRIPTOR = Ptr{_IMAGE_BOUND_IMPORT_DESCRIPTOR}

struct _IMAGE_BOUND_FORWARDER_REF
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_BOUND_FORWARDER_REF}, f::Symbol)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 0)
    f === :OffsetModuleName && return Ptr{WORD}(x + 4)
    f === :Reserved && return Ptr{WORD}(x + 6)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_BOUND_FORWARDER_REF, f::Symbol)
    r = Ref{_IMAGE_BOUND_FORWARDER_REF}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BOUND_FORWARDER_REF}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_BOUND_FORWARDER_REF}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_BOUND_FORWARDER_REF(TimeDateStamp::DWORD, OffsetModuleName::WORD, Reserved::WORD)
    ref = Ref{_IMAGE_BOUND_FORWARDER_REF}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BOUND_FORWARDER_REF}, ref)
    ptr.TimeDateStamp = TimeDateStamp
    ptr.OffsetModuleName = OffsetModuleName
    ptr.Reserved = Reserved
    ref[]
end

const IMAGE_BOUND_FORWARDER_REF = _IMAGE_BOUND_FORWARDER_REF

const PIMAGE_BOUND_FORWARDER_REF = Ptr{_IMAGE_BOUND_FORWARDER_REF}

struct __JL_Ctag_52
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_52}, f::Symbol)
    f === :AllAttributes && return Ptr{DWORD}(x + 0)
    f === :RvaBased && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :ReservedAttributes && return (Ptr{DWORD}(x + 0), 1, 31)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_52, f::Symbol)
    r = Ref{__JL_Ctag_52}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_52}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_52}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_52 = Union{DWORD}

function __JL_Ctag_52(val::__U___JL_Ctag_52)
    ref = Ref{__JL_Ctag_52}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_52}, ref)
    if val isa DWORD
        ptr.AllAttributes = val
    end
    ref[]
end

struct _IMAGE_DELAYLOAD_DESCRIPTOR
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DELAYLOAD_DESCRIPTOR}, f::Symbol)
    f === :Attributes && return Ptr{__JL_Ctag_52}(x + 0)
    f === :DllNameRVA && return Ptr{DWORD}(x + 4)
    f === :ModuleHandleRVA && return Ptr{DWORD}(x + 8)
    f === :ImportAddressTableRVA && return Ptr{DWORD}(x + 12)
    f === :ImportNameTableRVA && return Ptr{DWORD}(x + 16)
    f === :BoundImportAddressTableRVA && return Ptr{DWORD}(x + 20)
    f === :UnloadInformationTableRVA && return Ptr{DWORD}(x + 24)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 28)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DELAYLOAD_DESCRIPTOR, f::Symbol)
    r = Ref{_IMAGE_DELAYLOAD_DESCRIPTOR}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DELAYLOAD_DESCRIPTOR}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DELAYLOAD_DESCRIPTOR}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DELAYLOAD_DESCRIPTOR(Attributes::__JL_Ctag_52, DllNameRVA::DWORD, ModuleHandleRVA::DWORD, ImportAddressTableRVA::DWORD, ImportNameTableRVA::DWORD, BoundImportAddressTableRVA::DWORD, UnloadInformationTableRVA::DWORD, TimeDateStamp::DWORD)
    ref = Ref{_IMAGE_DELAYLOAD_DESCRIPTOR}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DELAYLOAD_DESCRIPTOR}, ref)
    ptr.Attributes = Attributes
    ptr.DllNameRVA = DllNameRVA
    ptr.ModuleHandleRVA = ModuleHandleRVA
    ptr.ImportAddressTableRVA = ImportAddressTableRVA
    ptr.ImportNameTableRVA = ImportNameTableRVA
    ptr.BoundImportAddressTableRVA = BoundImportAddressTableRVA
    ptr.UnloadInformationTableRVA = UnloadInformationTableRVA
    ptr.TimeDateStamp = TimeDateStamp
    ref[]
end

const IMAGE_DELAYLOAD_DESCRIPTOR = _IMAGE_DELAYLOAD_DESCRIPTOR

const PIMAGE_DELAYLOAD_DESCRIPTOR = Ptr{_IMAGE_DELAYLOAD_DESCRIPTOR}

const PCIMAGE_DELAYLOAD_DESCRIPTOR = Ptr{IMAGE_DELAYLOAD_DESCRIPTOR}

struct _IMAGE_RESOURCE_DIRECTORY
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_RESOURCE_DIRECTORY}, f::Symbol)
    f === :Characteristics && return Ptr{DWORD}(x + 0)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 4)
    f === :MajorVersion && return Ptr{WORD}(x + 8)
    f === :MinorVersion && return Ptr{WORD}(x + 10)
    f === :NumberOfNamedEntries && return Ptr{WORD}(x + 12)
    f === :NumberOfIdEntries && return Ptr{WORD}(x + 14)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_RESOURCE_DIRECTORY, f::Symbol)
    r = Ref{_IMAGE_RESOURCE_DIRECTORY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DIRECTORY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_RESOURCE_DIRECTORY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_RESOURCE_DIRECTORY(Characteristics::DWORD, TimeDateStamp::DWORD, MajorVersion::WORD, MinorVersion::WORD, NumberOfNamedEntries::WORD, NumberOfIdEntries::WORD)
    ref = Ref{_IMAGE_RESOURCE_DIRECTORY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DIRECTORY}, ref)
    ptr.Characteristics = Characteristics
    ptr.TimeDateStamp = TimeDateStamp
    ptr.MajorVersion = MajorVersion
    ptr.MinorVersion = MinorVersion
    ptr.NumberOfNamedEntries = NumberOfNamedEntries
    ptr.NumberOfIdEntries = NumberOfIdEntries
    ref[]
end

const IMAGE_RESOURCE_DIRECTORY = _IMAGE_RESOURCE_DIRECTORY

const PIMAGE_RESOURCE_DIRECTORY = Ptr{_IMAGE_RESOURCE_DIRECTORY}

struct _IMAGE_RESOURCE_DIRECTORY_ENTRY
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_RESOURCE_DIRECTORY_ENTRY}, f::Symbol)
    f === :NameOffset && return (Ptr{DWORD}(x + 0), 0, 31)
    f === :NameIsString && return (Ptr{DWORD}(x + 0), 31, 1)
    f === :Name && return Ptr{DWORD}(x + 0)
    f === :Id && return Ptr{WORD}(x + 0)
    f === :OffsetToData && return Ptr{DWORD}(x + 4)
    f === :OffsetToDirectory && return (Ptr{DWORD}(x + 4), 0, 31)
    f === :DataIsDirectory && return (Ptr{DWORD}(x + 4), 31, 1)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_RESOURCE_DIRECTORY_ENTRY, f::Symbol)
    r = Ref{_IMAGE_RESOURCE_DIRECTORY_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DIRECTORY_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_RESOURCE_DIRECTORY_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_RESOURCE_DIRECTORY_ENTRY()
    ref = Ref{_IMAGE_RESOURCE_DIRECTORY_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DIRECTORY_ENTRY}, ref)
    ref[]
end

const IMAGE_RESOURCE_DIRECTORY_ENTRY = _IMAGE_RESOURCE_DIRECTORY_ENTRY

const PIMAGE_RESOURCE_DIRECTORY_ENTRY = Ptr{_IMAGE_RESOURCE_DIRECTORY_ENTRY}

struct _IMAGE_RESOURCE_DIRECTORY_STRING
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_RESOURCE_DIRECTORY_STRING}, f::Symbol)
    f === :Length && return Ptr{WORD}(x + 0)
    f === :NameString && return Ptr{NTuple{1, CHAR}}(x + 2)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_RESOURCE_DIRECTORY_STRING, f::Symbol)
    r = Ref{_IMAGE_RESOURCE_DIRECTORY_STRING}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DIRECTORY_STRING}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_RESOURCE_DIRECTORY_STRING}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_RESOURCE_DIRECTORY_STRING(Length::WORD, NameString::NTuple{1, CHAR})
    ref = Ref{_IMAGE_RESOURCE_DIRECTORY_STRING}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DIRECTORY_STRING}, ref)
    ptr.Length = Length
    ptr.NameString = NameString
    ref[]
end

const IMAGE_RESOURCE_DIRECTORY_STRING = _IMAGE_RESOURCE_DIRECTORY_STRING

const PIMAGE_RESOURCE_DIRECTORY_STRING = Ptr{_IMAGE_RESOURCE_DIRECTORY_STRING}

struct _IMAGE_RESOURCE_DIR_STRING_U
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_RESOURCE_DIR_STRING_U}, f::Symbol)
    f === :Length && return Ptr{WORD}(x + 0)
    f === :NameString && return Ptr{NTuple{1, WCHAR}}(x + 2)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_RESOURCE_DIR_STRING_U, f::Symbol)
    r = Ref{_IMAGE_RESOURCE_DIR_STRING_U}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DIR_STRING_U}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_RESOURCE_DIR_STRING_U}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_RESOURCE_DIR_STRING_U(Length::WORD, NameString::NTuple{1, WCHAR})
    ref = Ref{_IMAGE_RESOURCE_DIR_STRING_U}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DIR_STRING_U}, ref)
    ptr.Length = Length
    ptr.NameString = NameString
    ref[]
end

const IMAGE_RESOURCE_DIR_STRING_U = _IMAGE_RESOURCE_DIR_STRING_U

const PIMAGE_RESOURCE_DIR_STRING_U = Ptr{_IMAGE_RESOURCE_DIR_STRING_U}

struct _IMAGE_RESOURCE_DATA_ENTRY
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_RESOURCE_DATA_ENTRY}, f::Symbol)
    f === :OffsetToData && return Ptr{DWORD}(x + 0)
    f === :Size && return Ptr{DWORD}(x + 4)
    f === :CodePage && return Ptr{DWORD}(x + 8)
    f === :Reserved && return Ptr{DWORD}(x + 12)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_RESOURCE_DATA_ENTRY, f::Symbol)
    r = Ref{_IMAGE_RESOURCE_DATA_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DATA_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_RESOURCE_DATA_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_RESOURCE_DATA_ENTRY(OffsetToData::DWORD, Size::DWORD, CodePage::DWORD, Reserved::DWORD)
    ref = Ref{_IMAGE_RESOURCE_DATA_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RESOURCE_DATA_ENTRY}, ref)
    ptr.OffsetToData = OffsetToData
    ptr.Size = Size
    ptr.CodePage = CodePage
    ptr.Reserved = Reserved
    ref[]
end

const IMAGE_RESOURCE_DATA_ENTRY = _IMAGE_RESOURCE_DATA_ENTRY

const PIMAGE_RESOURCE_DATA_ENTRY = Ptr{_IMAGE_RESOURCE_DATA_ENTRY}

struct _IMAGE_LOAD_CONFIG_CODE_INTEGRITY
    data::NTuple{12, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_LOAD_CONFIG_CODE_INTEGRITY}, f::Symbol)
    f === :Flags && return Ptr{WORD}(x + 0)
    f === :Catalog && return Ptr{WORD}(x + 2)
    f === :CatalogOffset && return Ptr{DWORD}(x + 4)
    f === :Reserved && return Ptr{DWORD}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_LOAD_CONFIG_CODE_INTEGRITY, f::Symbol)
    r = Ref{_IMAGE_LOAD_CONFIG_CODE_INTEGRITY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_LOAD_CONFIG_CODE_INTEGRITY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_LOAD_CONFIG_CODE_INTEGRITY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_LOAD_CONFIG_CODE_INTEGRITY(Flags::WORD, Catalog::WORD, CatalogOffset::DWORD, Reserved::DWORD)
    ref = Ref{_IMAGE_LOAD_CONFIG_CODE_INTEGRITY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_LOAD_CONFIG_CODE_INTEGRITY}, ref)
    ptr.Flags = Flags
    ptr.Catalog = Catalog
    ptr.CatalogOffset = CatalogOffset
    ptr.Reserved = Reserved
    ref[]
end

const IMAGE_LOAD_CONFIG_CODE_INTEGRITY = _IMAGE_LOAD_CONFIG_CODE_INTEGRITY

const PIMAGE_LOAD_CONFIG_CODE_INTEGRITY = Ptr{_IMAGE_LOAD_CONFIG_CODE_INTEGRITY}

struct _IMAGE_DYNAMIC_RELOCATION_TABLE
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DYNAMIC_RELOCATION_TABLE}, f::Symbol)
    f === :Version && return Ptr{DWORD}(x + 0)
    f === :Size && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DYNAMIC_RELOCATION_TABLE, f::Symbol)
    r = Ref{_IMAGE_DYNAMIC_RELOCATION_TABLE}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION_TABLE}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DYNAMIC_RELOCATION_TABLE}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DYNAMIC_RELOCATION_TABLE(Version::DWORD, Size::DWORD)
    ref = Ref{_IMAGE_DYNAMIC_RELOCATION_TABLE}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION_TABLE}, ref)
    ptr.Version = Version
    ptr.Size = Size
    ref[]
end

const IMAGE_DYNAMIC_RELOCATION_TABLE = _IMAGE_DYNAMIC_RELOCATION_TABLE

const PIMAGE_DYNAMIC_RELOCATION_TABLE = Ptr{_IMAGE_DYNAMIC_RELOCATION_TABLE}

struct _IMAGE_DYNAMIC_RELOCATION32
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DYNAMIC_RELOCATION32}, f::Symbol)
    f === :Symbol && return Ptr{DWORD}(x + 0)
    f === :BaseRelocSize && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DYNAMIC_RELOCATION32, f::Symbol)
    r = Ref{_IMAGE_DYNAMIC_RELOCATION32}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION32}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DYNAMIC_RELOCATION32}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DYNAMIC_RELOCATION32(Symbol::DWORD, BaseRelocSize::DWORD)
    ref = Ref{_IMAGE_DYNAMIC_RELOCATION32}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION32}, ref)
    ptr.Symbol = Symbol
    ptr.BaseRelocSize = BaseRelocSize
    ref[]
end

const IMAGE_DYNAMIC_RELOCATION32 = _IMAGE_DYNAMIC_RELOCATION32

const PIMAGE_DYNAMIC_RELOCATION32 = Ptr{_IMAGE_DYNAMIC_RELOCATION32}

struct _IMAGE_DYNAMIC_RELOCATION64
    data::NTuple{12, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DYNAMIC_RELOCATION64}, f::Symbol)
    f === :Symbol && return Ptr{ULONGLONG}(x + 0)
    f === :BaseRelocSize && return Ptr{DWORD}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DYNAMIC_RELOCATION64, f::Symbol)
    r = Ref{_IMAGE_DYNAMIC_RELOCATION64}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DYNAMIC_RELOCATION64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DYNAMIC_RELOCATION64(Symbol::ULONGLONG, BaseRelocSize::DWORD)
    ref = Ref{_IMAGE_DYNAMIC_RELOCATION64}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION64}, ref)
    ptr.Symbol = Symbol
    ptr.BaseRelocSize = BaseRelocSize
    ref[]
end

const IMAGE_DYNAMIC_RELOCATION64 = _IMAGE_DYNAMIC_RELOCATION64

const PIMAGE_DYNAMIC_RELOCATION64 = Ptr{_IMAGE_DYNAMIC_RELOCATION64}

struct _IMAGE_DYNAMIC_RELOCATION32_V2
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DYNAMIC_RELOCATION32_V2}, f::Symbol)
    f === :HeaderSize && return Ptr{DWORD}(x + 0)
    f === :FixupInfoSize && return Ptr{DWORD}(x + 4)
    f === :Symbol && return Ptr{DWORD}(x + 8)
    f === :SymbolGroup && return Ptr{DWORD}(x + 12)
    f === :Flags && return Ptr{DWORD}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DYNAMIC_RELOCATION32_V2, f::Symbol)
    r = Ref{_IMAGE_DYNAMIC_RELOCATION32_V2}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION32_V2}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DYNAMIC_RELOCATION32_V2}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DYNAMIC_RELOCATION32_V2(HeaderSize::DWORD, FixupInfoSize::DWORD, Symbol::DWORD, SymbolGroup::DWORD, Flags::DWORD)
    ref = Ref{_IMAGE_DYNAMIC_RELOCATION32_V2}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION32_V2}, ref)
    ptr.HeaderSize = HeaderSize
    ptr.FixupInfoSize = FixupInfoSize
    ptr.Symbol = Symbol
    ptr.SymbolGroup = SymbolGroup
    ptr.Flags = Flags
    ref[]
end

const IMAGE_DYNAMIC_RELOCATION32_V2 = _IMAGE_DYNAMIC_RELOCATION32_V2

const PIMAGE_DYNAMIC_RELOCATION32_V2 = Ptr{_IMAGE_DYNAMIC_RELOCATION32_V2}

struct _IMAGE_DYNAMIC_RELOCATION64_V2
    data::NTuple{24, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DYNAMIC_RELOCATION64_V2}, f::Symbol)
    f === :HeaderSize && return Ptr{DWORD}(x + 0)
    f === :FixupInfoSize && return Ptr{DWORD}(x + 4)
    f === :Symbol && return Ptr{ULONGLONG}(x + 8)
    f === :SymbolGroup && return Ptr{DWORD}(x + 16)
    f === :Flags && return Ptr{DWORD}(x + 20)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DYNAMIC_RELOCATION64_V2, f::Symbol)
    r = Ref{_IMAGE_DYNAMIC_RELOCATION64_V2}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION64_V2}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DYNAMIC_RELOCATION64_V2}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DYNAMIC_RELOCATION64_V2(HeaderSize::DWORD, FixupInfoSize::DWORD, Symbol::ULONGLONG, SymbolGroup::DWORD, Flags::DWORD)
    ref = Ref{_IMAGE_DYNAMIC_RELOCATION64_V2}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DYNAMIC_RELOCATION64_V2}, ref)
    ptr.HeaderSize = HeaderSize
    ptr.FixupInfoSize = FixupInfoSize
    ptr.Symbol = Symbol
    ptr.SymbolGroup = SymbolGroup
    ptr.Flags = Flags
    ref[]
end

const IMAGE_DYNAMIC_RELOCATION64_V2 = _IMAGE_DYNAMIC_RELOCATION64_V2

const PIMAGE_DYNAMIC_RELOCATION64_V2 = Ptr{_IMAGE_DYNAMIC_RELOCATION64_V2}

const IMAGE_DYNAMIC_RELOCATION = IMAGE_DYNAMIC_RELOCATION64

const PIMAGE_DYNAMIC_RELOCATION = PIMAGE_DYNAMIC_RELOCATION64

const IMAGE_DYNAMIC_RELOCATION_V2 = IMAGE_DYNAMIC_RELOCATION64_V2

const PIMAGE_DYNAMIC_RELOCATION_V2 = PIMAGE_DYNAMIC_RELOCATION64_V2

struct _IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER
    data::NTuple{1, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER}, f::Symbol)
    f === :PrologueByteCount && return Ptr{BYTE}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER, f::Symbol)
    r = Ref{_IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER(PrologueByteCount::BYTE)
    ref = Ref{_IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER}, ref)
    ptr.PrologueByteCount = PrologueByteCount
    ref[]
end

const IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER = _IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER

const PIMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER = Ptr{IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER}

struct _IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER}, f::Symbol)
    f === :EpilogueCount && return Ptr{DWORD}(x + 0)
    f === :EpilogueByteCount && return Ptr{BYTE}(x + 4)
    f === :BranchDescriptorElementSize && return Ptr{BYTE}(x + 5)
    f === :BranchDescriptorCount && return Ptr{WORD}(x + 6)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER, f::Symbol)
    r = Ref{_IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER(EpilogueCount::DWORD, EpilogueByteCount::BYTE, BranchDescriptorElementSize::BYTE, BranchDescriptorCount::WORD)
    ref = Ref{_IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER}, ref)
    ptr.EpilogueCount = EpilogueCount
    ptr.EpilogueByteCount = EpilogueByteCount
    ptr.BranchDescriptorElementSize = BranchDescriptorElementSize
    ptr.BranchDescriptorCount = BranchDescriptorCount
    ref[]
end

const IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER = _IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER

const PIMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER = Ptr{IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER}

struct _IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION}, f::Symbol)
    f === :PageRelativeOffset && return (Ptr{DWORD}(x + 0), 0, 12)
    f === :IndirectCall && return (Ptr{DWORD}(x + 0), 12, 1)
    f === :IATIndex && return (Ptr{DWORD}(x + 0), 13, 19)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION, f::Symbol)
    r = Ref{_IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{_IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function _IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION(PageRelativeOffset::DWORD, IndirectCall::DWORD, IATIndex::DWORD)
    ref = Ref{_IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION}, ref)
    ptr.PageRelativeOffset = PageRelativeOffset
    ptr.IndirectCall = IndirectCall
    ptr.IATIndex = IATIndex
    ref[]
end

const IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION = _IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION

const PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION = Ptr{IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION}

struct _IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION
    data::NTuple{2, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION}, f::Symbol)
    f === :PageRelativeOffset && return (Ptr{WORD}(x + 0), 0, 12)
    f === :IndirectCall && return (Ptr{WORD}(x + 0), 12, 1)
    f === :RexWPrefix && return (Ptr{WORD}(x + 0), 13, 1)
    f === :CfgCheck && return (Ptr{WORD}(x + 0), 14, 1)
    f === :Reserved && return (Ptr{WORD}(x + 0), 15, 1)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION, f::Symbol)
    r = Ref{_IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{_IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function _IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION(PageRelativeOffset::WORD, IndirectCall::WORD, RexWPrefix::WORD, CfgCheck::WORD, Reserved::WORD)
    ref = Ref{_IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION}, ref)
    ptr.PageRelativeOffset = PageRelativeOffset
    ptr.IndirectCall = IndirectCall
    ptr.RexWPrefix = RexWPrefix
    ptr.CfgCheck = CfgCheck
    ptr.Reserved = Reserved
    ref[]
end

const IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION = _IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION

const PIMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION = Ptr{IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION}

struct _IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION
    data::NTuple{2, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION}, f::Symbol)
    f === :PageRelativeOffset && return (Ptr{WORD}(x + 0), 0, 12)
    f === :RegisterNumber && return (Ptr{WORD}(x + 0), 12, 4)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION, f::Symbol)
    r = Ref{_IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{_IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function _IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION(PageRelativeOffset::WORD, RegisterNumber::WORD)
    ref = Ref{_IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION}, ref)
    ptr.PageRelativeOffset = PageRelativeOffset
    ptr.RegisterNumber = RegisterNumber
    ref[]
end

const IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION = _IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION

const PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION = Ptr{IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION}

struct _IMAGE_FUNCTION_OVERRIDE_HEADER
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_FUNCTION_OVERRIDE_HEADER}, f::Symbol)
    f === :FuncOverrideSize && return Ptr{DWORD}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_FUNCTION_OVERRIDE_HEADER, f::Symbol)
    r = Ref{_IMAGE_FUNCTION_OVERRIDE_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FUNCTION_OVERRIDE_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_FUNCTION_OVERRIDE_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_FUNCTION_OVERRIDE_HEADER(FuncOverrideSize::DWORD)
    ref = Ref{_IMAGE_FUNCTION_OVERRIDE_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FUNCTION_OVERRIDE_HEADER}, ref)
    ptr.FuncOverrideSize = FuncOverrideSize
    ref[]
end

const IMAGE_FUNCTION_OVERRIDE_HEADER = _IMAGE_FUNCTION_OVERRIDE_HEADER

const PIMAGE_FUNCTION_OVERRIDE_HEADER = Ptr{IMAGE_FUNCTION_OVERRIDE_HEADER}

struct _IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION}, f::Symbol)
    f === :OriginalRva && return Ptr{DWORD}(x + 0)
    f === :BDDOffset && return Ptr{DWORD}(x + 4)
    f === :RvaSize && return Ptr{DWORD}(x + 8)
    f === :BaseRelocSize && return Ptr{DWORD}(x + 12)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION, f::Symbol)
    r = Ref{_IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION(OriginalRva::DWORD, BDDOffset::DWORD, RvaSize::DWORD, BaseRelocSize::DWORD)
    ref = Ref{_IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION}, ref)
    ptr.OriginalRva = OriginalRva
    ptr.BDDOffset = BDDOffset
    ptr.RvaSize = RvaSize
    ptr.BaseRelocSize = BaseRelocSize
    ref[]
end

const IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION = _IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION

const PIMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION = Ptr{IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION}

struct _IMAGE_BDD_INFO
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_BDD_INFO}, f::Symbol)
    f === :Version && return Ptr{DWORD}(x + 0)
    f === :BDDSize && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_BDD_INFO, f::Symbol)
    r = Ref{_IMAGE_BDD_INFO}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BDD_INFO}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_BDD_INFO}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_BDD_INFO(Version::DWORD, BDDSize::DWORD)
    ref = Ref{_IMAGE_BDD_INFO}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BDD_INFO}, ref)
    ptr.Version = Version
    ptr.BDDSize = BDDSize
    ref[]
end

const IMAGE_BDD_INFO = _IMAGE_BDD_INFO

const PIMAGE_BDD_INFO = Ptr{IMAGE_BDD_INFO}

struct _IMAGE_BDD_DYNAMIC_RELOCATION
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_BDD_DYNAMIC_RELOCATION}, f::Symbol)
    f === :Left && return Ptr{WORD}(x + 0)
    f === :Right && return Ptr{WORD}(x + 2)
    f === :Value && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_BDD_DYNAMIC_RELOCATION, f::Symbol)
    r = Ref{_IMAGE_BDD_DYNAMIC_RELOCATION}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BDD_DYNAMIC_RELOCATION}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_BDD_DYNAMIC_RELOCATION}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_BDD_DYNAMIC_RELOCATION(Left::WORD, Right::WORD, Value::DWORD)
    ref = Ref{_IMAGE_BDD_DYNAMIC_RELOCATION}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_BDD_DYNAMIC_RELOCATION}, ref)
    ptr.Left = Left
    ptr.Right = Right
    ptr.Value = Value
    ref[]
end

const IMAGE_BDD_DYNAMIC_RELOCATION = _IMAGE_BDD_DYNAMIC_RELOCATION

const PIMAGE_BDD_DYNAMIC_RELOCATION = Ptr{IMAGE_BDD_DYNAMIC_RELOCATION}

struct _IMAGE_LOAD_CONFIG_DIRECTORY32
    data::NTuple{192, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY32}, f::Symbol)
    f === :Size && return Ptr{DWORD}(x + 0)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 4)
    f === :MajorVersion && return Ptr{WORD}(x + 8)
    f === :MinorVersion && return Ptr{WORD}(x + 10)
    f === :GlobalFlagsClear && return Ptr{DWORD}(x + 12)
    f === :GlobalFlagsSet && return Ptr{DWORD}(x + 16)
    f === :CriticalSectionDefaultTimeout && return Ptr{DWORD}(x + 20)
    f === :DeCommitFreeBlockThreshold && return Ptr{DWORD}(x + 24)
    f === :DeCommitTotalFreeThreshold && return Ptr{DWORD}(x + 28)
    f === :LockPrefixTable && return Ptr{DWORD}(x + 32)
    f === :MaximumAllocationSize && return Ptr{DWORD}(x + 36)
    f === :VirtualMemoryThreshold && return Ptr{DWORD}(x + 40)
    f === :ProcessHeapFlags && return Ptr{DWORD}(x + 44)
    f === :ProcessAffinityMask && return Ptr{DWORD}(x + 48)
    f === :CSDVersion && return Ptr{WORD}(x + 52)
    f === :DependentLoadFlags && return Ptr{WORD}(x + 54)
    f === :EditList && return Ptr{DWORD}(x + 56)
    f === :SecurityCookie && return Ptr{DWORD}(x + 60)
    f === :SEHandlerTable && return Ptr{DWORD}(x + 64)
    f === :SEHandlerCount && return Ptr{DWORD}(x + 68)
    f === :GuardCFCheckFunctionPointer && return Ptr{DWORD}(x + 72)
    f === :GuardCFDispatchFunctionPointer && return Ptr{DWORD}(x + 76)
    f === :GuardCFFunctionTable && return Ptr{DWORD}(x + 80)
    f === :GuardCFFunctionCount && return Ptr{DWORD}(x + 84)
    f === :GuardFlags && return Ptr{DWORD}(x + 88)
    f === :CodeIntegrity && return Ptr{IMAGE_LOAD_CONFIG_CODE_INTEGRITY}(x + 92)
    f === :GuardAddressTakenIatEntryTable && return Ptr{DWORD}(x + 104)
    f === :GuardAddressTakenIatEntryCount && return Ptr{DWORD}(x + 108)
    f === :GuardLongJumpTargetTable && return Ptr{DWORD}(x + 112)
    f === :GuardLongJumpTargetCount && return Ptr{DWORD}(x + 116)
    f === :DynamicValueRelocTable && return Ptr{DWORD}(x + 120)
    f === :CHPEMetadataPointer && return Ptr{DWORD}(x + 124)
    f === :GuardRFFailureRoutine && return Ptr{DWORD}(x + 128)
    f === :GuardRFFailureRoutineFunctionPointer && return Ptr{DWORD}(x + 132)
    f === :DynamicValueRelocTableOffset && return Ptr{DWORD}(x + 136)
    f === :DynamicValueRelocTableSection && return Ptr{WORD}(x + 140)
    f === :Reserved2 && return Ptr{WORD}(x + 142)
    f === :GuardRFVerifyStackPointerFunctionPointer && return Ptr{DWORD}(x + 144)
    f === :HotPatchTableOffset && return Ptr{DWORD}(x + 148)
    f === :Reserved3 && return Ptr{DWORD}(x + 152)
    f === :EnclaveConfigurationPointer && return Ptr{DWORD}(x + 156)
    f === :VolatileMetadataPointer && return Ptr{DWORD}(x + 160)
    f === :GuardEHContinuationTable && return Ptr{DWORD}(x + 164)
    f === :GuardEHContinuationCount && return Ptr{DWORD}(x + 168)
    f === :GuardXFGCheckFunctionPointer && return Ptr{DWORD}(x + 172)
    f === :GuardXFGDispatchFunctionPointer && return Ptr{DWORD}(x + 176)
    f === :GuardXFGTableDispatchFunctionPointer && return Ptr{DWORD}(x + 180)
    f === :CastGuardOsDeterminedFailureMode && return Ptr{DWORD}(x + 184)
    f === :GuardMemcpyFunctionPointer && return Ptr{DWORD}(x + 188)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_LOAD_CONFIG_DIRECTORY32, f::Symbol)
    r = Ref{_IMAGE_LOAD_CONFIG_DIRECTORY32}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY32}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY32}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_LOAD_CONFIG_DIRECTORY32(Size::DWORD, TimeDateStamp::DWORD, MajorVersion::WORD, MinorVersion::WORD, GlobalFlagsClear::DWORD, GlobalFlagsSet::DWORD, CriticalSectionDefaultTimeout::DWORD, DeCommitFreeBlockThreshold::DWORD, DeCommitTotalFreeThreshold::DWORD, LockPrefixTable::DWORD, MaximumAllocationSize::DWORD, VirtualMemoryThreshold::DWORD, ProcessHeapFlags::DWORD, ProcessAffinityMask::DWORD, CSDVersion::WORD, DependentLoadFlags::WORD, EditList::DWORD, SecurityCookie::DWORD, SEHandlerTable::DWORD, SEHandlerCount::DWORD, GuardCFCheckFunctionPointer::DWORD, GuardCFDispatchFunctionPointer::DWORD, GuardCFFunctionTable::DWORD, GuardCFFunctionCount::DWORD, GuardFlags::DWORD, CodeIntegrity::IMAGE_LOAD_CONFIG_CODE_INTEGRITY, GuardAddressTakenIatEntryTable::DWORD, GuardAddressTakenIatEntryCount::DWORD, GuardLongJumpTargetTable::DWORD, GuardLongJumpTargetCount::DWORD, DynamicValueRelocTable::DWORD, CHPEMetadataPointer::DWORD, GuardRFFailureRoutine::DWORD, GuardRFFailureRoutineFunctionPointer::DWORD, DynamicValueRelocTableOffset::DWORD, DynamicValueRelocTableSection::WORD, Reserved2::WORD, GuardRFVerifyStackPointerFunctionPointer::DWORD, HotPatchTableOffset::DWORD, Reserved3::DWORD, EnclaveConfigurationPointer::DWORD, VolatileMetadataPointer::DWORD, GuardEHContinuationTable::DWORD, GuardEHContinuationCount::DWORD, GuardXFGCheckFunctionPointer::DWORD, GuardXFGDispatchFunctionPointer::DWORD, GuardXFGTableDispatchFunctionPointer::DWORD, CastGuardOsDeterminedFailureMode::DWORD, GuardMemcpyFunctionPointer::DWORD)
    ref = Ref{_IMAGE_LOAD_CONFIG_DIRECTORY32}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY32}, ref)
    ptr.Size = Size
    ptr.TimeDateStamp = TimeDateStamp
    ptr.MajorVersion = MajorVersion
    ptr.MinorVersion = MinorVersion
    ptr.GlobalFlagsClear = GlobalFlagsClear
    ptr.GlobalFlagsSet = GlobalFlagsSet
    ptr.CriticalSectionDefaultTimeout = CriticalSectionDefaultTimeout
    ptr.DeCommitFreeBlockThreshold = DeCommitFreeBlockThreshold
    ptr.DeCommitTotalFreeThreshold = DeCommitTotalFreeThreshold
    ptr.LockPrefixTable = LockPrefixTable
    ptr.MaximumAllocationSize = MaximumAllocationSize
    ptr.VirtualMemoryThreshold = VirtualMemoryThreshold
    ptr.ProcessHeapFlags = ProcessHeapFlags
    ptr.ProcessAffinityMask = ProcessAffinityMask
    ptr.CSDVersion = CSDVersion
    ptr.DependentLoadFlags = DependentLoadFlags
    ptr.EditList = EditList
    ptr.SecurityCookie = SecurityCookie
    ptr.SEHandlerTable = SEHandlerTable
    ptr.SEHandlerCount = SEHandlerCount
    ptr.GuardCFCheckFunctionPointer = GuardCFCheckFunctionPointer
    ptr.GuardCFDispatchFunctionPointer = GuardCFDispatchFunctionPointer
    ptr.GuardCFFunctionTable = GuardCFFunctionTable
    ptr.GuardCFFunctionCount = GuardCFFunctionCount
    ptr.GuardFlags = GuardFlags
    ptr.CodeIntegrity = CodeIntegrity
    ptr.GuardAddressTakenIatEntryTable = GuardAddressTakenIatEntryTable
    ptr.GuardAddressTakenIatEntryCount = GuardAddressTakenIatEntryCount
    ptr.GuardLongJumpTargetTable = GuardLongJumpTargetTable
    ptr.GuardLongJumpTargetCount = GuardLongJumpTargetCount
    ptr.DynamicValueRelocTable = DynamicValueRelocTable
    ptr.CHPEMetadataPointer = CHPEMetadataPointer
    ptr.GuardRFFailureRoutine = GuardRFFailureRoutine
    ptr.GuardRFFailureRoutineFunctionPointer = GuardRFFailureRoutineFunctionPointer
    ptr.DynamicValueRelocTableOffset = DynamicValueRelocTableOffset
    ptr.DynamicValueRelocTableSection = DynamicValueRelocTableSection
    ptr.Reserved2 = Reserved2
    ptr.GuardRFVerifyStackPointerFunctionPointer = GuardRFVerifyStackPointerFunctionPointer
    ptr.HotPatchTableOffset = HotPatchTableOffset
    ptr.Reserved3 = Reserved3
    ptr.EnclaveConfigurationPointer = EnclaveConfigurationPointer
    ptr.VolatileMetadataPointer = VolatileMetadataPointer
    ptr.GuardEHContinuationTable = GuardEHContinuationTable
    ptr.GuardEHContinuationCount = GuardEHContinuationCount
    ptr.GuardXFGCheckFunctionPointer = GuardXFGCheckFunctionPointer
    ptr.GuardXFGDispatchFunctionPointer = GuardXFGDispatchFunctionPointer
    ptr.GuardXFGTableDispatchFunctionPointer = GuardXFGTableDispatchFunctionPointer
    ptr.CastGuardOsDeterminedFailureMode = CastGuardOsDeterminedFailureMode
    ptr.GuardMemcpyFunctionPointer = GuardMemcpyFunctionPointer
    ref[]
end

const IMAGE_LOAD_CONFIG_DIRECTORY32 = _IMAGE_LOAD_CONFIG_DIRECTORY32

const PIMAGE_LOAD_CONFIG_DIRECTORY32 = Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY32}

struct _IMAGE_LOAD_CONFIG_DIRECTORY64
    data::NTuple{320, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY64}, f::Symbol)
    f === :Size && return Ptr{DWORD}(x + 0)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 4)
    f === :MajorVersion && return Ptr{WORD}(x + 8)
    f === :MinorVersion && return Ptr{WORD}(x + 10)
    f === :GlobalFlagsClear && return Ptr{DWORD}(x + 12)
    f === :GlobalFlagsSet && return Ptr{DWORD}(x + 16)
    f === :CriticalSectionDefaultTimeout && return Ptr{DWORD}(x + 20)
    f === :DeCommitFreeBlockThreshold && return Ptr{ULONGLONG}(x + 24)
    f === :DeCommitTotalFreeThreshold && return Ptr{ULONGLONG}(x + 32)
    f === :LockPrefixTable && return Ptr{ULONGLONG}(x + 40)
    f === :MaximumAllocationSize && return Ptr{ULONGLONG}(x + 48)
    f === :VirtualMemoryThreshold && return Ptr{ULONGLONG}(x + 56)
    f === :ProcessAffinityMask && return Ptr{ULONGLONG}(x + 64)
    f === :ProcessHeapFlags && return Ptr{DWORD}(x + 72)
    f === :CSDVersion && return Ptr{WORD}(x + 76)
    f === :DependentLoadFlags && return Ptr{WORD}(x + 78)
    f === :EditList && return Ptr{ULONGLONG}(x + 80)
    f === :SecurityCookie && return Ptr{ULONGLONG}(x + 88)
    f === :SEHandlerTable && return Ptr{ULONGLONG}(x + 96)
    f === :SEHandlerCount && return Ptr{ULONGLONG}(x + 104)
    f === :GuardCFCheckFunctionPointer && return Ptr{ULONGLONG}(x + 112)
    f === :GuardCFDispatchFunctionPointer && return Ptr{ULONGLONG}(x + 120)
    f === :GuardCFFunctionTable && return Ptr{ULONGLONG}(x + 128)
    f === :GuardCFFunctionCount && return Ptr{ULONGLONG}(x + 136)
    f === :GuardFlags && return Ptr{DWORD}(x + 144)
    f === :CodeIntegrity && return Ptr{IMAGE_LOAD_CONFIG_CODE_INTEGRITY}(x + 148)
    f === :GuardAddressTakenIatEntryTable && return Ptr{ULONGLONG}(x + 160)
    f === :GuardAddressTakenIatEntryCount && return Ptr{ULONGLONG}(x + 168)
    f === :GuardLongJumpTargetTable && return Ptr{ULONGLONG}(x + 176)
    f === :GuardLongJumpTargetCount && return Ptr{ULONGLONG}(x + 184)
    f === :DynamicValueRelocTable && return Ptr{ULONGLONG}(x + 192)
    f === :CHPEMetadataPointer && return Ptr{ULONGLONG}(x + 200)
    f === :GuardRFFailureRoutine && return Ptr{ULONGLONG}(x + 208)
    f === :GuardRFFailureRoutineFunctionPointer && return Ptr{ULONGLONG}(x + 216)
    f === :DynamicValueRelocTableOffset && return Ptr{DWORD}(x + 224)
    f === :DynamicValueRelocTableSection && return Ptr{WORD}(x + 228)
    f === :Reserved2 && return Ptr{WORD}(x + 230)
    f === :GuardRFVerifyStackPointerFunctionPointer && return Ptr{ULONGLONG}(x + 232)
    f === :HotPatchTableOffset && return Ptr{DWORD}(x + 240)
    f === :Reserved3 && return Ptr{DWORD}(x + 244)
    f === :EnclaveConfigurationPointer && return Ptr{ULONGLONG}(x + 248)
    f === :VolatileMetadataPointer && return Ptr{ULONGLONG}(x + 256)
    f === :GuardEHContinuationTable && return Ptr{ULONGLONG}(x + 264)
    f === :GuardEHContinuationCount && return Ptr{ULONGLONG}(x + 272)
    f === :GuardXFGCheckFunctionPointer && return Ptr{ULONGLONG}(x + 280)
    f === :GuardXFGDispatchFunctionPointer && return Ptr{ULONGLONG}(x + 288)
    f === :GuardXFGTableDispatchFunctionPointer && return Ptr{ULONGLONG}(x + 296)
    f === :CastGuardOsDeterminedFailureMode && return Ptr{ULONGLONG}(x + 304)
    f === :GuardMemcpyFunctionPointer && return Ptr{ULONGLONG}(x + 312)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_LOAD_CONFIG_DIRECTORY64, f::Symbol)
    r = Ref{_IMAGE_LOAD_CONFIG_DIRECTORY64}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_LOAD_CONFIG_DIRECTORY64(Size::DWORD, TimeDateStamp::DWORD, MajorVersion::WORD, MinorVersion::WORD, GlobalFlagsClear::DWORD, GlobalFlagsSet::DWORD, CriticalSectionDefaultTimeout::DWORD, DeCommitFreeBlockThreshold::ULONGLONG, DeCommitTotalFreeThreshold::ULONGLONG, LockPrefixTable::ULONGLONG, MaximumAllocationSize::ULONGLONG, VirtualMemoryThreshold::ULONGLONG, ProcessAffinityMask::ULONGLONG, ProcessHeapFlags::DWORD, CSDVersion::WORD, DependentLoadFlags::WORD, EditList::ULONGLONG, SecurityCookie::ULONGLONG, SEHandlerTable::ULONGLONG, SEHandlerCount::ULONGLONG, GuardCFCheckFunctionPointer::ULONGLONG, GuardCFDispatchFunctionPointer::ULONGLONG, GuardCFFunctionTable::ULONGLONG, GuardCFFunctionCount::ULONGLONG, GuardFlags::DWORD, CodeIntegrity::IMAGE_LOAD_CONFIG_CODE_INTEGRITY, GuardAddressTakenIatEntryTable::ULONGLONG, GuardAddressTakenIatEntryCount::ULONGLONG, GuardLongJumpTargetTable::ULONGLONG, GuardLongJumpTargetCount::ULONGLONG, DynamicValueRelocTable::ULONGLONG, CHPEMetadataPointer::ULONGLONG, GuardRFFailureRoutine::ULONGLONG, GuardRFFailureRoutineFunctionPointer::ULONGLONG, DynamicValueRelocTableOffset::DWORD, DynamicValueRelocTableSection::WORD, Reserved2::WORD, GuardRFVerifyStackPointerFunctionPointer::ULONGLONG, HotPatchTableOffset::DWORD, Reserved3::DWORD, EnclaveConfigurationPointer::ULONGLONG, VolatileMetadataPointer::ULONGLONG, GuardEHContinuationTable::ULONGLONG, GuardEHContinuationCount::ULONGLONG, GuardXFGCheckFunctionPointer::ULONGLONG, GuardXFGDispatchFunctionPointer::ULONGLONG, GuardXFGTableDispatchFunctionPointer::ULONGLONG, CastGuardOsDeterminedFailureMode::ULONGLONG, GuardMemcpyFunctionPointer::ULONGLONG)
    ref = Ref{_IMAGE_LOAD_CONFIG_DIRECTORY64}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY64}, ref)
    ptr.Size = Size
    ptr.TimeDateStamp = TimeDateStamp
    ptr.MajorVersion = MajorVersion
    ptr.MinorVersion = MinorVersion
    ptr.GlobalFlagsClear = GlobalFlagsClear
    ptr.GlobalFlagsSet = GlobalFlagsSet
    ptr.CriticalSectionDefaultTimeout = CriticalSectionDefaultTimeout
    ptr.DeCommitFreeBlockThreshold = DeCommitFreeBlockThreshold
    ptr.DeCommitTotalFreeThreshold = DeCommitTotalFreeThreshold
    ptr.LockPrefixTable = LockPrefixTable
    ptr.MaximumAllocationSize = MaximumAllocationSize
    ptr.VirtualMemoryThreshold = VirtualMemoryThreshold
    ptr.ProcessAffinityMask = ProcessAffinityMask
    ptr.ProcessHeapFlags = ProcessHeapFlags
    ptr.CSDVersion = CSDVersion
    ptr.DependentLoadFlags = DependentLoadFlags
    ptr.EditList = EditList
    ptr.SecurityCookie = SecurityCookie
    ptr.SEHandlerTable = SEHandlerTable
    ptr.SEHandlerCount = SEHandlerCount
    ptr.GuardCFCheckFunctionPointer = GuardCFCheckFunctionPointer
    ptr.GuardCFDispatchFunctionPointer = GuardCFDispatchFunctionPointer
    ptr.GuardCFFunctionTable = GuardCFFunctionTable
    ptr.GuardCFFunctionCount = GuardCFFunctionCount
    ptr.GuardFlags = GuardFlags
    ptr.CodeIntegrity = CodeIntegrity
    ptr.GuardAddressTakenIatEntryTable = GuardAddressTakenIatEntryTable
    ptr.GuardAddressTakenIatEntryCount = GuardAddressTakenIatEntryCount
    ptr.GuardLongJumpTargetTable = GuardLongJumpTargetTable
    ptr.GuardLongJumpTargetCount = GuardLongJumpTargetCount
    ptr.DynamicValueRelocTable = DynamicValueRelocTable
    ptr.CHPEMetadataPointer = CHPEMetadataPointer
    ptr.GuardRFFailureRoutine = GuardRFFailureRoutine
    ptr.GuardRFFailureRoutineFunctionPointer = GuardRFFailureRoutineFunctionPointer
    ptr.DynamicValueRelocTableOffset = DynamicValueRelocTableOffset
    ptr.DynamicValueRelocTableSection = DynamicValueRelocTableSection
    ptr.Reserved2 = Reserved2
    ptr.GuardRFVerifyStackPointerFunctionPointer = GuardRFVerifyStackPointerFunctionPointer
    ptr.HotPatchTableOffset = HotPatchTableOffset
    ptr.Reserved3 = Reserved3
    ptr.EnclaveConfigurationPointer = EnclaveConfigurationPointer
    ptr.VolatileMetadataPointer = VolatileMetadataPointer
    ptr.GuardEHContinuationTable = GuardEHContinuationTable
    ptr.GuardEHContinuationCount = GuardEHContinuationCount
    ptr.GuardXFGCheckFunctionPointer = GuardXFGCheckFunctionPointer
    ptr.GuardXFGDispatchFunctionPointer = GuardXFGDispatchFunctionPointer
    ptr.GuardXFGTableDispatchFunctionPointer = GuardXFGTableDispatchFunctionPointer
    ptr.CastGuardOsDeterminedFailureMode = CastGuardOsDeterminedFailureMode
    ptr.GuardMemcpyFunctionPointer = GuardMemcpyFunctionPointer
    ref[]
end

const IMAGE_LOAD_CONFIG_DIRECTORY64 = _IMAGE_LOAD_CONFIG_DIRECTORY64

const PIMAGE_LOAD_CONFIG_DIRECTORY64 = Ptr{_IMAGE_LOAD_CONFIG_DIRECTORY64}

const IMAGE_LOAD_CONFIG_DIRECTORY = IMAGE_LOAD_CONFIG_DIRECTORY64

const PIMAGE_LOAD_CONFIG_DIRECTORY = PIMAGE_LOAD_CONFIG_DIRECTORY64

struct _IMAGE_HOT_PATCH_INFO
    data::NTuple{28, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_HOT_PATCH_INFO}, f::Symbol)
    f === :Version && return Ptr{DWORD}(x + 0)
    f === :Size && return Ptr{DWORD}(x + 4)
    f === :SequenceNumber && return Ptr{DWORD}(x + 8)
    f === :BaseImageList && return Ptr{DWORD}(x + 12)
    f === :BaseImageCount && return Ptr{DWORD}(x + 16)
    f === :BufferOffset && return Ptr{DWORD}(x + 20)
    f === :ExtraPatchSize && return Ptr{DWORD}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_HOT_PATCH_INFO, f::Symbol)
    r = Ref{_IMAGE_HOT_PATCH_INFO}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_HOT_PATCH_INFO}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_HOT_PATCH_INFO}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_HOT_PATCH_INFO(Version::DWORD, Size::DWORD, SequenceNumber::DWORD, BaseImageList::DWORD, BaseImageCount::DWORD, BufferOffset::DWORD, ExtraPatchSize::DWORD)
    ref = Ref{_IMAGE_HOT_PATCH_INFO}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_HOT_PATCH_INFO}, ref)
    ptr.Version = Version
    ptr.Size = Size
    ptr.SequenceNumber = SequenceNumber
    ptr.BaseImageList = BaseImageList
    ptr.BaseImageCount = BaseImageCount
    ptr.BufferOffset = BufferOffset
    ptr.ExtraPatchSize = ExtraPatchSize
    ref[]
end

const IMAGE_HOT_PATCH_INFO = _IMAGE_HOT_PATCH_INFO

const PIMAGE_HOT_PATCH_INFO = Ptr{_IMAGE_HOT_PATCH_INFO}

struct _IMAGE_HOT_PATCH_BASE
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_HOT_PATCH_BASE}, f::Symbol)
    f === :SequenceNumber && return Ptr{DWORD}(x + 0)
    f === :Flags && return Ptr{DWORD}(x + 4)
    f === :OriginalTimeDateStamp && return Ptr{DWORD}(x + 8)
    f === :OriginalCheckSum && return Ptr{DWORD}(x + 12)
    f === :CodeIntegrityInfo && return Ptr{DWORD}(x + 16)
    f === :CodeIntegritySize && return Ptr{DWORD}(x + 20)
    f === :PatchTable && return Ptr{DWORD}(x + 24)
    f === :BufferOffset && return Ptr{DWORD}(x + 28)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_HOT_PATCH_BASE, f::Symbol)
    r = Ref{_IMAGE_HOT_PATCH_BASE}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_HOT_PATCH_BASE}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_HOT_PATCH_BASE}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_HOT_PATCH_BASE(SequenceNumber::DWORD, Flags::DWORD, OriginalTimeDateStamp::DWORD, OriginalCheckSum::DWORD, CodeIntegrityInfo::DWORD, CodeIntegritySize::DWORD, PatchTable::DWORD, BufferOffset::DWORD)
    ref = Ref{_IMAGE_HOT_PATCH_BASE}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_HOT_PATCH_BASE}, ref)
    ptr.SequenceNumber = SequenceNumber
    ptr.Flags = Flags
    ptr.OriginalTimeDateStamp = OriginalTimeDateStamp
    ptr.OriginalCheckSum = OriginalCheckSum
    ptr.CodeIntegrityInfo = CodeIntegrityInfo
    ptr.CodeIntegritySize = CodeIntegritySize
    ptr.PatchTable = PatchTable
    ptr.BufferOffset = BufferOffset
    ref[]
end

const IMAGE_HOT_PATCH_BASE = _IMAGE_HOT_PATCH_BASE

const PIMAGE_HOT_PATCH_BASE = Ptr{_IMAGE_HOT_PATCH_BASE}

struct _IMAGE_HOT_PATCH_HASHES
    data::NTuple{52, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_HOT_PATCH_HASHES}, f::Symbol)
    f === :SHA256 && return Ptr{NTuple{32, BYTE}}(x + 0)
    f === :SHA1 && return Ptr{NTuple{20, BYTE}}(x + 32)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_HOT_PATCH_HASHES, f::Symbol)
    r = Ref{_IMAGE_HOT_PATCH_HASHES}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_HOT_PATCH_HASHES}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_HOT_PATCH_HASHES}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_HOT_PATCH_HASHES(SHA256::NTuple{32, BYTE}, SHA1::NTuple{20, BYTE})
    ref = Ref{_IMAGE_HOT_PATCH_HASHES}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_HOT_PATCH_HASHES}, ref)
    ptr.SHA256 = SHA256
    ptr.SHA1 = SHA1
    ref[]
end

const IMAGE_HOT_PATCH_HASHES = _IMAGE_HOT_PATCH_HASHES

const PIMAGE_HOT_PATCH_HASHES = Ptr{_IMAGE_HOT_PATCH_HASHES}

struct _IMAGE_CE_RUNTIME_FUNCTION_ENTRY
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_CE_RUNTIME_FUNCTION_ENTRY}, f::Symbol)
    f === :FuncStart && return Ptr{DWORD}(x + 0)
    f === :PrologLen && return (Ptr{DWORD}(x + 4), 0, 8)
    f === :FuncLen && return (Ptr{DWORD}(x + 4), 8, 22)
    f === :ThirtyTwoBit && return (Ptr{DWORD}(x + 4), 30, 1)
    f === :ExceptionFlag && return (Ptr{DWORD}(x + 4), 31, 1)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_CE_RUNTIME_FUNCTION_ENTRY, f::Symbol)
    r = Ref{_IMAGE_CE_RUNTIME_FUNCTION_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_CE_RUNTIME_FUNCTION_ENTRY}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{_IMAGE_CE_RUNTIME_FUNCTION_ENTRY}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function _IMAGE_CE_RUNTIME_FUNCTION_ENTRY(FuncStart::DWORD, PrologLen::DWORD, FuncLen::DWORD, ThirtyTwoBit::DWORD, ExceptionFlag::DWORD)
    ref = Ref{_IMAGE_CE_RUNTIME_FUNCTION_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_CE_RUNTIME_FUNCTION_ENTRY}, ref)
    ptr.FuncStart = FuncStart
    ptr.PrologLen = PrologLen
    ptr.FuncLen = FuncLen
    ptr.ThirtyTwoBit = ThirtyTwoBit
    ptr.ExceptionFlag = ExceptionFlag
    ref[]
end

const IMAGE_CE_RUNTIME_FUNCTION_ENTRY = _IMAGE_CE_RUNTIME_FUNCTION_ENTRY

const PIMAGE_CE_RUNTIME_FUNCTION_ENTRY = Ptr{_IMAGE_CE_RUNTIME_FUNCTION_ENTRY}

struct _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ARM_RUNTIME_FUNCTION_ENTRY}, f::Symbol)
    f === :BeginAddress && return Ptr{DWORD}(x + 0)
    f === :UnwindData && return Ptr{DWORD}(x + 4)
    f === :Flag && return (Ptr{DWORD}(x + 4), 0, 2)
    f === :FunctionLength && return (Ptr{DWORD}(x + 4), 2, 11)
    f === :Ret && return (Ptr{DWORD}(x + 4), 13, 2)
    f === :H && return (Ptr{DWORD}(x + 4), 15, 1)
    f === :Reg && return (Ptr{DWORD}(x + 4), 16, 3)
    f === :R && return (Ptr{DWORD}(x + 4), 19, 1)
    f === :L && return (Ptr{DWORD}(x + 4), 20, 1)
    f === :C && return (Ptr{DWORD}(x + 4), 21, 1)
    f === :StackAdjust && return (Ptr{DWORD}(x + 4), 22, 10)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ARM_RUNTIME_FUNCTION_ENTRY, f::Symbol)
    r = Ref{_IMAGE_ARM_RUNTIME_FUNCTION_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ARM_RUNTIME_FUNCTION_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ARM_RUNTIME_FUNCTION_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY(BeginAddress::DWORD)
    ref = Ref{_IMAGE_ARM_RUNTIME_FUNCTION_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ARM_RUNTIME_FUNCTION_ENTRY}, ref)
    ptr.BeginAddress = BeginAddress
    ref[]
end

const IMAGE_ARM_RUNTIME_FUNCTION_ENTRY = _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY

const PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY = Ptr{_IMAGE_ARM_RUNTIME_FUNCTION_ENTRY}

@cenum ARM64_FNPDATA_FLAGS::UInt32 begin
    PdataRefToFullXdata = 0
    PdataPackedUnwindFunction = 1
    PdataPackedUnwindFragment = 2
end

@cenum ARM64_FNPDATA_CR::UInt32 begin
    PdataCrUnchained = 0
    PdataCrUnchainedSavedLr = 1
    PdataCrChainedWithPac = 2
    PdataCrChained = 3
end

const IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY = _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY

const PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY = Ptr{_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY}

struct IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA}, f::Symbol)
    f === :HeaderData && return Ptr{DWORD}(x + 0)
    f === :FunctionLength && return (Ptr{DWORD}(x + 0), 0, 18)
    f === :Version && return (Ptr{DWORD}(x + 0), 18, 2)
    f === :ExceptionDataPresent && return (Ptr{DWORD}(x + 0), 20, 1)
    f === :EpilogInHeader && return (Ptr{DWORD}(x + 0), 21, 1)
    f === :EpilogCount && return (Ptr{DWORD}(x + 0), 22, 5)
    f === :CodeWords && return (Ptr{DWORD}(x + 0), 27, 5)
    return getfield(x, f)
end

function Base.getproperty(x::IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA, f::Symbol)
    r = Ref{IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA}(x)
    ptr = Base.unsafe_convert(Ptr{IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA = Union{DWORD}

function IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA(val::__U_IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA)
    ref = Ref{IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA}()
    ptr = Base.unsafe_convert(Ptr{IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA}, ref)
    if val isa DWORD
        ptr.HeaderData = val
    end
    ref[]
end

struct _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY
    data::NTuple{40, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY}, f::Symbol)
    f === :BeginAddress && return Ptr{ULONGLONG}(x + 0)
    f === :EndAddress && return Ptr{ULONGLONG}(x + 8)
    f === :ExceptionHandler && return Ptr{ULONGLONG}(x + 16)
    f === :HandlerData && return Ptr{ULONGLONG}(x + 24)
    f === :PrologEndAddress && return Ptr{ULONGLONG}(x + 32)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY, f::Symbol)
    r = Ref{_IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY(BeginAddress::ULONGLONG, EndAddress::ULONGLONG, ExceptionHandler::ULONGLONG, HandlerData::ULONGLONG, PrologEndAddress::ULONGLONG)
    ref = Ref{_IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY}, ref)
    ptr.BeginAddress = BeginAddress
    ptr.EndAddress = EndAddress
    ptr.ExceptionHandler = ExceptionHandler
    ptr.HandlerData = HandlerData
    ptr.PrologEndAddress = PrologEndAddress
    ref[]
end

const IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY = _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY

const PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY = Ptr{_IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY}

struct _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY}, f::Symbol)
    f === :BeginAddress && return Ptr{DWORD}(x + 0)
    f === :EndAddress && return Ptr{DWORD}(x + 4)
    f === :ExceptionHandler && return Ptr{DWORD}(x + 8)
    f === :HandlerData && return Ptr{DWORD}(x + 12)
    f === :PrologEndAddress && return Ptr{DWORD}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY, f::Symbol)
    r = Ref{_IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY(BeginAddress::DWORD, EndAddress::DWORD, ExceptionHandler::DWORD, HandlerData::DWORD, PrologEndAddress::DWORD)
    ref = Ref{_IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY}, ref)
    ptr.BeginAddress = BeginAddress
    ptr.EndAddress = EndAddress
    ptr.ExceptionHandler = ExceptionHandler
    ptr.HandlerData = HandlerData
    ptr.PrologEndAddress = PrologEndAddress
    ref[]
end

const IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY = _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY

const PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY = Ptr{_IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY}

struct _IMAGE_RUNTIME_FUNCTION_ENTRY
    data::NTuple{12, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_RUNTIME_FUNCTION_ENTRY}, f::Symbol)
    f === :BeginAddress && return Ptr{DWORD}(x + 0)
    f === :EndAddress && return Ptr{DWORD}(x + 4)
    f === :UnwindInfoAddress && return Ptr{DWORD}(x + 8)
    f === :UnwindData && return Ptr{DWORD}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_RUNTIME_FUNCTION_ENTRY, f::Symbol)
    r = Ref{_IMAGE_RUNTIME_FUNCTION_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RUNTIME_FUNCTION_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_RUNTIME_FUNCTION_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_RUNTIME_FUNCTION_ENTRY(BeginAddress::DWORD, EndAddress::DWORD)
    ref = Ref{_IMAGE_RUNTIME_FUNCTION_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_RUNTIME_FUNCTION_ENTRY}, ref)
    ptr.BeginAddress = BeginAddress
    ptr.EndAddress = EndAddress
    ref[]
end

const _PIMAGE_RUNTIME_FUNCTION_ENTRY = Ptr{_IMAGE_RUNTIME_FUNCTION_ENTRY}

const IMAGE_IA64_RUNTIME_FUNCTION_ENTRY = _IMAGE_RUNTIME_FUNCTION_ENTRY

const PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY = _PIMAGE_RUNTIME_FUNCTION_ENTRY

const IMAGE_AMD64_RUNTIME_FUNCTION_ENTRY = _IMAGE_RUNTIME_FUNCTION_ENTRY

const PIMAGE_AMD64_RUNTIME_FUNCTION_ENTRY = _PIMAGE_RUNTIME_FUNCTION_ENTRY

const IMAGE_RUNTIME_FUNCTION_ENTRY = _IMAGE_RUNTIME_FUNCTION_ENTRY

const PIMAGE_RUNTIME_FUNCTION_ENTRY = _PIMAGE_RUNTIME_FUNCTION_ENTRY

struct _IMAGE_ENCLAVE_CONFIG32
    data::NTuple{76, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ENCLAVE_CONFIG32}, f::Symbol)
    f === :Size && return Ptr{DWORD}(x + 0)
    f === :MinimumRequiredConfigSize && return Ptr{DWORD}(x + 4)
    f === :PolicyFlags && return Ptr{DWORD}(x + 8)
    f === :NumberOfImports && return Ptr{DWORD}(x + 12)
    f === :ImportList && return Ptr{DWORD}(x + 16)
    f === :ImportEntrySize && return Ptr{DWORD}(x + 20)
    f === :FamilyID && return Ptr{NTuple{16, BYTE}}(x + 24)
    f === :ImageID && return Ptr{NTuple{16, BYTE}}(x + 40)
    f === :ImageVersion && return Ptr{DWORD}(x + 56)
    f === :SecurityVersion && return Ptr{DWORD}(x + 60)
    f === :EnclaveSize && return Ptr{DWORD}(x + 64)
    f === :NumberOfThreads && return Ptr{DWORD}(x + 68)
    f === :EnclaveFlags && return Ptr{DWORD}(x + 72)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ENCLAVE_CONFIG32, f::Symbol)
    r = Ref{_IMAGE_ENCLAVE_CONFIG32}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ENCLAVE_CONFIG32}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ENCLAVE_CONFIG32}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ENCLAVE_CONFIG32(Size::DWORD, MinimumRequiredConfigSize::DWORD, PolicyFlags::DWORD, NumberOfImports::DWORD, ImportList::DWORD, ImportEntrySize::DWORD, FamilyID::NTuple{16, BYTE}, ImageID::NTuple{16, BYTE}, ImageVersion::DWORD, SecurityVersion::DWORD, EnclaveSize::DWORD, NumberOfThreads::DWORD, EnclaveFlags::DWORD)
    ref = Ref{_IMAGE_ENCLAVE_CONFIG32}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ENCLAVE_CONFIG32}, ref)
    ptr.Size = Size
    ptr.MinimumRequiredConfigSize = MinimumRequiredConfigSize
    ptr.PolicyFlags = PolicyFlags
    ptr.NumberOfImports = NumberOfImports
    ptr.ImportList = ImportList
    ptr.ImportEntrySize = ImportEntrySize
    ptr.FamilyID = FamilyID
    ptr.ImageID = ImageID
    ptr.ImageVersion = ImageVersion
    ptr.SecurityVersion = SecurityVersion
    ptr.EnclaveSize = EnclaveSize
    ptr.NumberOfThreads = NumberOfThreads
    ptr.EnclaveFlags = EnclaveFlags
    ref[]
end

const IMAGE_ENCLAVE_CONFIG32 = _IMAGE_ENCLAVE_CONFIG32

const PIMAGE_ENCLAVE_CONFIG32 = Ptr{_IMAGE_ENCLAVE_CONFIG32}

const PIMAGE_ENCLAVE_CONFIG64 = Ptr{_IMAGE_ENCLAVE_CONFIG64}

const PIMAGE_ENCLAVE_CONFIG = PIMAGE_ENCLAVE_CONFIG64

struct _IMAGE_ENCLAVE_IMPORT
    data::NTuple{80, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_ENCLAVE_IMPORT}, f::Symbol)
    f === :MatchType && return Ptr{DWORD}(x + 0)
    f === :MinimumSecurityVersion && return Ptr{DWORD}(x + 4)
    f === :UniqueOrAuthorID && return Ptr{NTuple{32, BYTE}}(x + 8)
    f === :FamilyID && return Ptr{NTuple{16, BYTE}}(x + 40)
    f === :ImageID && return Ptr{NTuple{16, BYTE}}(x + 56)
    f === :ImportName && return Ptr{DWORD}(x + 72)
    f === :Reserved && return Ptr{DWORD}(x + 76)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_ENCLAVE_IMPORT, f::Symbol)
    r = Ref{_IMAGE_ENCLAVE_IMPORT}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ENCLAVE_IMPORT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_ENCLAVE_IMPORT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_ENCLAVE_IMPORT(MatchType::DWORD, MinimumSecurityVersion::DWORD, UniqueOrAuthorID::NTuple{32, BYTE}, FamilyID::NTuple{16, BYTE}, ImageID::NTuple{16, BYTE}, ImportName::DWORD, Reserved::DWORD)
    ref = Ref{_IMAGE_ENCLAVE_IMPORT}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_ENCLAVE_IMPORT}, ref)
    ptr.MatchType = MatchType
    ptr.MinimumSecurityVersion = MinimumSecurityVersion
    ptr.UniqueOrAuthorID = UniqueOrAuthorID
    ptr.FamilyID = FamilyID
    ptr.ImageID = ImageID
    ptr.ImportName = ImportName
    ptr.Reserved = Reserved
    ref[]
end

const IMAGE_ENCLAVE_IMPORT = _IMAGE_ENCLAVE_IMPORT

const PIMAGE_ENCLAVE_IMPORT = Ptr{_IMAGE_ENCLAVE_IMPORT}

struct _IMAGE_DEBUG_DIRECTORY
    data::NTuple{28, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DEBUG_DIRECTORY}, f::Symbol)
    f === :Characteristics && return Ptr{DWORD}(x + 0)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 4)
    f === :MajorVersion && return Ptr{WORD}(x + 8)
    f === :MinorVersion && return Ptr{WORD}(x + 10)
    f === :Type && return Ptr{DWORD}(x + 12)
    f === :SizeOfData && return Ptr{DWORD}(x + 16)
    f === :AddressOfRawData && return Ptr{DWORD}(x + 20)
    f === :PointerToRawData && return Ptr{DWORD}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DEBUG_DIRECTORY, f::Symbol)
    r = Ref{_IMAGE_DEBUG_DIRECTORY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DEBUG_DIRECTORY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DEBUG_DIRECTORY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DEBUG_DIRECTORY(Characteristics::DWORD, TimeDateStamp::DWORD, MajorVersion::WORD, MinorVersion::WORD, Type::DWORD, SizeOfData::DWORD, AddressOfRawData::DWORD, PointerToRawData::DWORD)
    ref = Ref{_IMAGE_DEBUG_DIRECTORY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DEBUG_DIRECTORY}, ref)
    ptr.Characteristics = Characteristics
    ptr.TimeDateStamp = TimeDateStamp
    ptr.MajorVersion = MajorVersion
    ptr.MinorVersion = MinorVersion
    ptr.Type = Type
    ptr.SizeOfData = SizeOfData
    ptr.AddressOfRawData = AddressOfRawData
    ptr.PointerToRawData = PointerToRawData
    ref[]
end

const IMAGE_DEBUG_DIRECTORY = _IMAGE_DEBUG_DIRECTORY

const PIMAGE_DEBUG_DIRECTORY = Ptr{_IMAGE_DEBUG_DIRECTORY}

struct _IMAGE_COFF_SYMBOLS_HEADER
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_COFF_SYMBOLS_HEADER}, f::Symbol)
    f === :NumberOfSymbols && return Ptr{DWORD}(x + 0)
    f === :LvaToFirstSymbol && return Ptr{DWORD}(x + 4)
    f === :NumberOfLinenumbers && return Ptr{DWORD}(x + 8)
    f === :LvaToFirstLinenumber && return Ptr{DWORD}(x + 12)
    f === :RvaToFirstByteOfCode && return Ptr{DWORD}(x + 16)
    f === :RvaToLastByteOfCode && return Ptr{DWORD}(x + 20)
    f === :RvaToFirstByteOfData && return Ptr{DWORD}(x + 24)
    f === :RvaToLastByteOfData && return Ptr{DWORD}(x + 28)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_COFF_SYMBOLS_HEADER, f::Symbol)
    r = Ref{_IMAGE_COFF_SYMBOLS_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_COFF_SYMBOLS_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_COFF_SYMBOLS_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_COFF_SYMBOLS_HEADER(NumberOfSymbols::DWORD, LvaToFirstSymbol::DWORD, NumberOfLinenumbers::DWORD, LvaToFirstLinenumber::DWORD, RvaToFirstByteOfCode::DWORD, RvaToLastByteOfCode::DWORD, RvaToFirstByteOfData::DWORD, RvaToLastByteOfData::DWORD)
    ref = Ref{_IMAGE_COFF_SYMBOLS_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_COFF_SYMBOLS_HEADER}, ref)
    ptr.NumberOfSymbols = NumberOfSymbols
    ptr.LvaToFirstSymbol = LvaToFirstSymbol
    ptr.NumberOfLinenumbers = NumberOfLinenumbers
    ptr.LvaToFirstLinenumber = LvaToFirstLinenumber
    ptr.RvaToFirstByteOfCode = RvaToFirstByteOfCode
    ptr.RvaToLastByteOfCode = RvaToLastByteOfCode
    ptr.RvaToFirstByteOfData = RvaToFirstByteOfData
    ptr.RvaToLastByteOfData = RvaToLastByteOfData
    ref[]
end

const IMAGE_COFF_SYMBOLS_HEADER = _IMAGE_COFF_SYMBOLS_HEADER

const PIMAGE_COFF_SYMBOLS_HEADER = Ptr{_IMAGE_COFF_SYMBOLS_HEADER}

struct _FPO_DATA
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{_FPO_DATA}, f::Symbol)
    f === :ulOffStart && return Ptr{DWORD}(x + 0)
    f === :cbProcSize && return Ptr{DWORD}(x + 4)
    f === :cdwLocals && return Ptr{DWORD}(x + 8)
    f === :cdwParams && return Ptr{WORD}(x + 12)
    f === :cbProlog && return (Ptr{WORD}(x + 12), 16, 8)
    f === :cbRegs && return (Ptr{WORD}(x + 12), 24, 3)
    f === :fHasSEH && return (Ptr{WORD}(x + 12), 27, 1)
    f === :fUseBP && return (Ptr{WORD}(x + 12), 28, 1)
    f === :reserved && return (Ptr{WORD}(x + 12), 29, 1)
    f === :cbFrame && return (Ptr{WORD}(x + 12), 30, 2)
    return getfield(x, f)
end

function Base.getproperty(x::_FPO_DATA, f::Symbol)
    r = Ref{_FPO_DATA}(x)
    ptr = Base.unsafe_convert(Ptr{_FPO_DATA}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{_FPO_DATA}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function _FPO_DATA(ulOffStart::DWORD, cbProcSize::DWORD, cdwLocals::DWORD, cdwParams::WORD, cbProlog::WORD, cbRegs::WORD, fHasSEH::WORD, fUseBP::WORD, reserved::WORD, cbFrame::WORD)
    ref = Ref{_FPO_DATA}()
    ptr = Base.unsafe_convert(Ptr{_FPO_DATA}, ref)
    ptr.ulOffStart = ulOffStart
    ptr.cbProcSize = cbProcSize
    ptr.cdwLocals = cdwLocals
    ptr.cdwParams = cdwParams
    ptr.cbProlog = cbProlog
    ptr.cbRegs = cbRegs
    ptr.fHasSEH = fHasSEH
    ptr.fUseBP = fUseBP
    ptr.reserved = reserved
    ptr.cbFrame = cbFrame
    ref[]
end

const FPO_DATA = _FPO_DATA

const PFPO_DATA = Ptr{_FPO_DATA}

struct _IMAGE_DEBUG_MISC
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_DEBUG_MISC}, f::Symbol)
    f === :DataType && return Ptr{DWORD}(x + 0)
    f === :Length && return Ptr{DWORD}(x + 4)
    f === :Unicode && return Ptr{BOOLEAN}(x + 8)
    f === :Reserved && return Ptr{NTuple{3, BYTE}}(x + 9)
    f === :Data && return Ptr{NTuple{1, BYTE}}(x + 12)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_DEBUG_MISC, f::Symbol)
    r = Ref{_IMAGE_DEBUG_MISC}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DEBUG_MISC}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_DEBUG_MISC}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_DEBUG_MISC(DataType::DWORD, Length::DWORD, Unicode::BOOLEAN, Reserved::NTuple{3, BYTE}, Data::NTuple{1, BYTE})
    ref = Ref{_IMAGE_DEBUG_MISC}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_DEBUG_MISC}, ref)
    ptr.DataType = DataType
    ptr.Length = Length
    ptr.Unicode = Unicode
    ptr.Reserved = Reserved
    ptr.Data = Data
    ref[]
end

const IMAGE_DEBUG_MISC = _IMAGE_DEBUG_MISC

const PIMAGE_DEBUG_MISC = Ptr{_IMAGE_DEBUG_MISC}

struct _IMAGE_FUNCTION_ENTRY
    data::NTuple{12, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_FUNCTION_ENTRY}, f::Symbol)
    f === :StartingAddress && return Ptr{DWORD}(x + 0)
    f === :EndingAddress && return Ptr{DWORD}(x + 4)
    f === :EndOfPrologue && return Ptr{DWORD}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_FUNCTION_ENTRY, f::Symbol)
    r = Ref{_IMAGE_FUNCTION_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FUNCTION_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_FUNCTION_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_FUNCTION_ENTRY(StartingAddress::DWORD, EndingAddress::DWORD, EndOfPrologue::DWORD)
    ref = Ref{_IMAGE_FUNCTION_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FUNCTION_ENTRY}, ref)
    ptr.StartingAddress = StartingAddress
    ptr.EndingAddress = EndingAddress
    ptr.EndOfPrologue = EndOfPrologue
    ref[]
end

const IMAGE_FUNCTION_ENTRY = _IMAGE_FUNCTION_ENTRY

const PIMAGE_FUNCTION_ENTRY = Ptr{_IMAGE_FUNCTION_ENTRY}

struct _IMAGE_FUNCTION_ENTRY64
    data::NTuple{24, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_FUNCTION_ENTRY64}, f::Symbol)
    f === :StartingAddress && return Ptr{ULONGLONG}(x + 0)
    f === :EndingAddress && return Ptr{ULONGLONG}(x + 8)
    f === :EndOfPrologue && return Ptr{ULONGLONG}(x + 16)
    f === :UnwindInfoAddress && return Ptr{ULONGLONG}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_FUNCTION_ENTRY64, f::Symbol)
    r = Ref{_IMAGE_FUNCTION_ENTRY64}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FUNCTION_ENTRY64}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_FUNCTION_ENTRY64}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_FUNCTION_ENTRY64(StartingAddress::ULONGLONG, EndingAddress::ULONGLONG)
    ref = Ref{_IMAGE_FUNCTION_ENTRY64}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_FUNCTION_ENTRY64}, ref)
    ptr.StartingAddress = StartingAddress
    ptr.EndingAddress = EndingAddress
    ref[]
end

const IMAGE_FUNCTION_ENTRY64 = _IMAGE_FUNCTION_ENTRY64

const PIMAGE_FUNCTION_ENTRY64 = Ptr{_IMAGE_FUNCTION_ENTRY64}

struct _IMAGE_SEPARATE_DEBUG_HEADER
    data::NTuple{48, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_SEPARATE_DEBUG_HEADER}, f::Symbol)
    f === :Signature && return Ptr{WORD}(x + 0)
    f === :Flags && return Ptr{WORD}(x + 2)
    f === :Machine && return Ptr{WORD}(x + 4)
    f === :Characteristics && return Ptr{WORD}(x + 6)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 8)
    f === :CheckSum && return Ptr{DWORD}(x + 12)
    f === :ImageBase && return Ptr{DWORD}(x + 16)
    f === :SizeOfImage && return Ptr{DWORD}(x + 20)
    f === :NumberOfSections && return Ptr{DWORD}(x + 24)
    f === :ExportedNamesSize && return Ptr{DWORD}(x + 28)
    f === :DebugDirectorySize && return Ptr{DWORD}(x + 32)
    f === :SectionAlignment && return Ptr{DWORD}(x + 36)
    f === :Reserved && return Ptr{NTuple{2, DWORD}}(x + 40)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_SEPARATE_DEBUG_HEADER, f::Symbol)
    r = Ref{_IMAGE_SEPARATE_DEBUG_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SEPARATE_DEBUG_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_SEPARATE_DEBUG_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_SEPARATE_DEBUG_HEADER(Signature::WORD, Flags::WORD, Machine::WORD, Characteristics::WORD, TimeDateStamp::DWORD, CheckSum::DWORD, ImageBase::DWORD, SizeOfImage::DWORD, NumberOfSections::DWORD, ExportedNamesSize::DWORD, DebugDirectorySize::DWORD, SectionAlignment::DWORD, Reserved::NTuple{2, DWORD})
    ref = Ref{_IMAGE_SEPARATE_DEBUG_HEADER}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_SEPARATE_DEBUG_HEADER}, ref)
    ptr.Signature = Signature
    ptr.Flags = Flags
    ptr.Machine = Machine
    ptr.Characteristics = Characteristics
    ptr.TimeDateStamp = TimeDateStamp
    ptr.CheckSum = CheckSum
    ptr.ImageBase = ImageBase
    ptr.SizeOfImage = SizeOfImage
    ptr.NumberOfSections = NumberOfSections
    ptr.ExportedNamesSize = ExportedNamesSize
    ptr.DebugDirectorySize = DebugDirectorySize
    ptr.SectionAlignment = SectionAlignment
    ptr.Reserved = Reserved
    ref[]
end

const IMAGE_SEPARATE_DEBUG_HEADER = _IMAGE_SEPARATE_DEBUG_HEADER

const PIMAGE_SEPARATE_DEBUG_HEADER = Ptr{_IMAGE_SEPARATE_DEBUG_HEADER}

struct _NON_PAGED_DEBUG_INFO
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_NON_PAGED_DEBUG_INFO}, f::Symbol)
    f === :Signature && return Ptr{WORD}(x + 0)
    f === :Flags && return Ptr{WORD}(x + 2)
    f === :Size && return Ptr{DWORD}(x + 4)
    f === :Machine && return Ptr{WORD}(x + 8)
    f === :Characteristics && return Ptr{WORD}(x + 10)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 12)
    f === :CheckSum && return Ptr{DWORD}(x + 16)
    f === :SizeOfImage && return Ptr{DWORD}(x + 20)
    f === :ImageBase && return Ptr{ULONGLONG}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_NON_PAGED_DEBUG_INFO, f::Symbol)
    r = Ref{_NON_PAGED_DEBUG_INFO}(x)
    ptr = Base.unsafe_convert(Ptr{_NON_PAGED_DEBUG_INFO}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_NON_PAGED_DEBUG_INFO}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _NON_PAGED_DEBUG_INFO(Signature::WORD, Flags::WORD, Size::DWORD, Machine::WORD, Characteristics::WORD, TimeDateStamp::DWORD, CheckSum::DWORD, SizeOfImage::DWORD, ImageBase::ULONGLONG)
    ref = Ref{_NON_PAGED_DEBUG_INFO}()
    ptr = Base.unsafe_convert(Ptr{_NON_PAGED_DEBUG_INFO}, ref)
    ptr.Signature = Signature
    ptr.Flags = Flags
    ptr.Size = Size
    ptr.Machine = Machine
    ptr.Characteristics = Characteristics
    ptr.TimeDateStamp = TimeDateStamp
    ptr.CheckSum = CheckSum
    ptr.SizeOfImage = SizeOfImage
    ptr.ImageBase = ImageBase
    ref[]
end

const NON_PAGED_DEBUG_INFO = _NON_PAGED_DEBUG_INFO

const PNON_PAGED_DEBUG_INFO = Ptr{_NON_PAGED_DEBUG_INFO}

struct _ImageArchitectureHeader
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_ImageArchitectureHeader}, f::Symbol)
    f === :AmaskValue && return (Ptr{Cuint}(x + 0), 0, 1)
    f === :AmaskShift && return (Ptr{Cuint}(x + 0), 8, 8)
    f === :FirstEntryRVA && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_ImageArchitectureHeader, f::Symbol)
    r = Ref{_ImageArchitectureHeader}(x)
    ptr = Base.unsafe_convert(Ptr{_ImageArchitectureHeader}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{_ImageArchitectureHeader}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function _ImageArchitectureHeader(AmaskValue::Cuint, AmaskShift::Cuint, FirstEntryRVA::DWORD)
    ref = Ref{_ImageArchitectureHeader}()
    ptr = Base.unsafe_convert(Ptr{_ImageArchitectureHeader}, ref)
    ptr.AmaskValue = AmaskValue
    ptr.AmaskShift = AmaskShift
    ptr.FirstEntryRVA = FirstEntryRVA
    ref[]
end

const IMAGE_ARCHITECTURE_HEADER = _ImageArchitectureHeader

const PIMAGE_ARCHITECTURE_HEADER = Ptr{_ImageArchitectureHeader}

struct _ImageArchitectureEntry
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_ImageArchitectureEntry}, f::Symbol)
    f === :FixupInstRVA && return Ptr{DWORD}(x + 0)
    f === :NewInst && return Ptr{DWORD}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::_ImageArchitectureEntry, f::Symbol)
    r = Ref{_ImageArchitectureEntry}(x)
    ptr = Base.unsafe_convert(Ptr{_ImageArchitectureEntry}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_ImageArchitectureEntry}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _ImageArchitectureEntry(FixupInstRVA::DWORD, NewInst::DWORD)
    ref = Ref{_ImageArchitectureEntry}()
    ptr = Base.unsafe_convert(Ptr{_ImageArchitectureEntry}, ref)
    ptr.FixupInstRVA = FixupInstRVA
    ptr.NewInst = NewInst
    ref[]
end

const IMAGE_ARCHITECTURE_ENTRY = _ImageArchitectureEntry

const PIMAGE_ARCHITECTURE_ENTRY = Ptr{_ImageArchitectureEntry}

struct IMPORT_OBJECT_HEADER
    data::NTuple{20, UInt8}
end

function Base.getproperty(x::Ptr{IMPORT_OBJECT_HEADER}, f::Symbol)
    f === :Sig1 && return Ptr{WORD}(x + 0)
    f === :Sig2 && return Ptr{WORD}(x + 2)
    f === :Version && return Ptr{WORD}(x + 4)
    f === :Machine && return Ptr{WORD}(x + 6)
    f === :TimeDateStamp && return Ptr{DWORD}(x + 8)
    f === :SizeOfData && return Ptr{DWORD}(x + 12)
    f === :Ordinal && return Ptr{WORD}(x + 16)
    f === :Hint && return Ptr{WORD}(x + 16)
    f === :Type && return (Ptr{WORD}(x + 16), 16, 2)
    f === :NameType && return (Ptr{WORD}(x + 16), 18, 3)
    f === :Reserved && return (Ptr{WORD}(x + 16), 21, 11)
    return getfield(x, f)
end

function Base.getproperty(x::IMPORT_OBJECT_HEADER, f::Symbol)
    r = Ref{IMPORT_OBJECT_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{IMPORT_OBJECT_HEADER}, r)
    fptr = getproperty(ptr, f)
    begin
        if fptr isa Ptr
            return GC.@preserve(r, unsafe_load(fptr))
        else
            (baseptr, offset, width) = fptr
            ty = eltype(baseptr)
            baseptr32 = convert(Ptr{UInt32}, baseptr)
            u64 = GC.@preserve(r, unsafe_load(baseptr32))
            if offset + width > 32
                u64 |= GC.@preserve(r, unsafe_load(baseptr32 + 4)) << 32
            end
            u64 = u64 >> offset & (1 << width - 1)
            return u64 % ty
        end
    end
end

function Base.setproperty!(x::Ptr{IMPORT_OBJECT_HEADER}, f::Symbol, v)
    fptr = getproperty(x, f)
    if fptr isa Ptr
        unsafe_store!(getproperty(x, f), v)
    else
        (baseptr, offset, width) = fptr
        baseptr32 = convert(Ptr{UInt32}, baseptr)
        u64 = unsafe_load(baseptr32)
        straddle = offset + width > 32
        if straddle
            u64 |= unsafe_load(baseptr32 + 4) << 32
        end
        mask = 1 << width - 1
        u64 &= ~(mask << offset)
        u64 |= (unsigned(v) & mask) << offset
        unsafe_store!(baseptr32, u64 & typemax(UInt32))
        if straddle
            unsafe_store!(baseptr32 + 4, u64 >> 32)
        end
    end
end

function IMPORT_OBJECT_HEADER(Sig1::WORD, Sig2::WORD, Version::WORD, Machine::WORD, TimeDateStamp::DWORD, SizeOfData::DWORD, Type::WORD, NameType::WORD, Reserved::WORD)
    ref = Ref{IMPORT_OBJECT_HEADER}()
    ptr = Base.unsafe_convert(Ptr{IMPORT_OBJECT_HEADER}, ref)
    ptr.Sig1 = Sig1
    ptr.Sig2 = Sig2
    ptr.Version = Version
    ptr.Machine = Machine
    ptr.TimeDateStamp = TimeDateStamp
    ptr.SizeOfData = SizeOfData
    ptr.Type = Type
    ptr.NameType = NameType
    ptr.Reserved = Reserved
    ref[]
end

@cenum IMPORT_OBJECT_TYPE::UInt32 begin
    IMPORT_OBJECT_CODE = 0
    IMPORT_OBJECT_DATA = 1
    IMPORT_OBJECT_CONST = 2
end

@cenum IMPORT_OBJECT_NAME_TYPE::UInt32 begin
    IMPORT_OBJECT_ORDINAL = 0
    IMPORT_OBJECT_NAME = 1
    IMPORT_OBJECT_NAME_NO_PREFIX = 2
    IMPORT_OBJECT_NAME_UNDECORATE = 3
    IMPORT_OBJECT_NAME_EXPORTAS = 4
end

@cenum ReplacesCorHdrNumericDefines::UInt32 begin
    COMIMAGE_FLAGS_ILONLY = 1
    COMIMAGE_FLAGS_32BITREQUIRED = 2
    COMIMAGE_FLAGS_IL_LIBRARY = 4
    COMIMAGE_FLAGS_STRONGNAMESIGNED = 8
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 16
    COMIMAGE_FLAGS_TRACKDEBUGDATA = 65536
    COMIMAGE_FLAGS_32BITPREFERRED = 131072
    COR_VERSION_MAJOR_V2 = 2
    COR_VERSION_MAJOR = 2
    COR_VERSION_MINOR = 5
    COR_DELETED_NAME_LENGTH = 8
    COR_VTABLEGAP_NAME_LENGTH = 8
    NATIVE_TYPE_MAX_CB = 1
    COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE = 255
    IMAGE_COR_MIH_METHODRVA = 1
    IMAGE_COR_MIH_EHRVA = 2
    IMAGE_COR_MIH_BASICBLOCK = 8
    COR_VTABLE_32BIT = 1
    COR_VTABLE_64BIT = 2
    COR_VTABLE_FROM_UNMANAGED = 4
    COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN = 8
    COR_VTABLE_CALL_MOST_DERIVED = 16
    IMAGE_COR_EATJ_THUNK_SIZE = 32
    MAX_CLASS_NAME = 1024
    MAX_PACKAGE_NAME = 1024
end

struct IMAGE_COR20_HEADER
    data::NTuple{72, UInt8}
end

function Base.getproperty(x::Ptr{IMAGE_COR20_HEADER}, f::Symbol)
    f === :cb && return Ptr{DWORD}(x + 0)
    f === :MajorRuntimeVersion && return Ptr{WORD}(x + 4)
    f === :MinorRuntimeVersion && return Ptr{WORD}(x + 6)
    f === :MetaData && return Ptr{IMAGE_DATA_DIRECTORY}(x + 8)
    f === :Flags && return Ptr{DWORD}(x + 16)
    f === :EntryPointToken && return Ptr{DWORD}(x + 20)
    f === :EntryPointRVA && return Ptr{DWORD}(x + 20)
    f === :Resources && return Ptr{IMAGE_DATA_DIRECTORY}(x + 24)
    f === :StrongNameSignature && return Ptr{IMAGE_DATA_DIRECTORY}(x + 32)
    f === :CodeManagerTable && return Ptr{IMAGE_DATA_DIRECTORY}(x + 40)
    f === :VTableFixups && return Ptr{IMAGE_DATA_DIRECTORY}(x + 48)
    f === :ExportAddressTableJumps && return Ptr{IMAGE_DATA_DIRECTORY}(x + 56)
    f === :ManagedNativeHeader && return Ptr{IMAGE_DATA_DIRECTORY}(x + 64)
    return getfield(x, f)
end

function Base.getproperty(x::IMAGE_COR20_HEADER, f::Symbol)
    r = Ref{IMAGE_COR20_HEADER}(x)
    ptr = Base.unsafe_convert(Ptr{IMAGE_COR20_HEADER}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{IMAGE_COR20_HEADER}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function IMAGE_COR20_HEADER(cb::DWORD, MajorRuntimeVersion::WORD, MinorRuntimeVersion::WORD, MetaData::IMAGE_DATA_DIRECTORY, Flags::DWORD, Resources::IMAGE_DATA_DIRECTORY, StrongNameSignature::IMAGE_DATA_DIRECTORY, CodeManagerTable::IMAGE_DATA_DIRECTORY, VTableFixups::IMAGE_DATA_DIRECTORY, ExportAddressTableJumps::IMAGE_DATA_DIRECTORY, ManagedNativeHeader::IMAGE_DATA_DIRECTORY)
    ref = Ref{IMAGE_COR20_HEADER}()
    ptr = Base.unsafe_convert(Ptr{IMAGE_COR20_HEADER}, ref)
    ptr.cb = cb
    ptr.MajorRuntimeVersion = MajorRuntimeVersion
    ptr.MinorRuntimeVersion = MinorRuntimeVersion
    ptr.MetaData = MetaData
    ptr.Flags = Flags
    ptr.Resources = Resources
    ptr.StrongNameSignature = StrongNameSignature
    ptr.CodeManagerTable = CodeManagerTable
    ptr.VTableFixups = VTableFixups
    ptr.ExportAddressTableJumps = ExportAddressTableJumps
    ptr.ManagedNativeHeader = ManagedNativeHeader
    ref[]
end

const PIMAGE_COR20_HEADER = Ptr{IMAGE_COR20_HEADER}

function RtlCaptureStackBackTrace(FramesToSkip, FramesToCapture, BackTrace, BackTraceHash)
    @ccall user32.RtlCaptureStackBackTrace(FramesToSkip::DWORD, FramesToCapture::DWORD, BackTrace::Ptr{PVOID}, BackTraceHash::PDWORD)::WORD
end

function RtlCaptureContext(ContextRecord)
    @ccall user32.RtlCaptureContext(ContextRecord::Cint)::Cvoid
end

function RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue)
    @ccall user32.RtlUnwind(TargetFrame::PVOID, TargetIp::PVOID, ExceptionRecord::PEXCEPTION_RECORD, ReturnValue::PVOID)::Cvoid
end

function RtlRaiseException(ExceptionRecord)
    @ccall user32.RtlRaiseException(ExceptionRecord::PEXCEPTION_RECORD)::Cvoid
end

function RtlPcToFileHeader(PcValue, BaseOfImage)
    @ccall user32.RtlPcToFileHeader(PcValue::PVOID, BaseOfImage::Ptr{PVOID})::PVOID
end

function RtlCompareMemory(Source1, Source2, Length)
    @ccall user32.RtlCompareMemory(Source1::Ptr{Cvoid}, Source2::Ptr{Cvoid}, Length::SIZE_T)::SIZE_T
end

struct _SLIST_ENTRY
    Next::Ptr{_SLIST_ENTRY}
end

const SLIST_ENTRY = _SLIST_ENTRY

const PSLIST_ENTRY = Ptr{_SLIST_ENTRY}

function RtlInitializeSListHead(ListHead)
    @ccall user32.RtlInitializeSListHead(ListHead::Cint)::Cvoid
end

function RtlFirstEntrySList(ListHead)
    @ccall user32.RtlFirstEntrySList(ListHead::Ptr{Cint})::PSLIST_ENTRY
end

function RtlInterlockedPopEntrySList(ListHead)
    @ccall user32.RtlInterlockedPopEntrySList(ListHead::Cint)::PSLIST_ENTRY
end

function RtlInterlockedPushEntrySList(ListHead, ListEntry)
    @ccall user32.RtlInterlockedPushEntrySList(ListHead::Cint, ListEntry::PSLIST_ENTRY)::PSLIST_ENTRY
end

function RtlInterlockedPushListSListEx(ListHead, List, ListEnd, Count)
    @ccall user32.RtlInterlockedPushListSListEx(ListHead::Cint, List::PSLIST_ENTRY, ListEnd::PSLIST_ENTRY, Count::DWORD)::PSLIST_ENTRY
end

function RtlInterlockedFlushSList(ListHead)
    @ccall user32.RtlInterlockedFlushSList(ListHead::Cint)::PSLIST_ENTRY
end

function RtlQueryDepthSList(ListHead)
    @ccall user32.RtlQueryDepthSList(ListHead::Cint)::WORD
end

function RtlGetReturnAddressHijackTarget()
    @ccall user32.RtlGetReturnAddressHijackTarget()::ULONG_PTR
end

struct _RTL_RUN_ONCE
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{_RTL_RUN_ONCE}, f::Symbol)
    f === :Ptr && return Ptr{PVOID}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::_RTL_RUN_ONCE, f::Symbol)
    r = Ref{_RTL_RUN_ONCE}(x)
    ptr = Base.unsafe_convert(Ptr{_RTL_RUN_ONCE}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_RTL_RUN_ONCE}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U__RTL_RUN_ONCE = Union{PVOID}

function _RTL_RUN_ONCE(val::__U__RTL_RUN_ONCE)
    ref = Ref{_RTL_RUN_ONCE}()
    ptr = Base.unsafe_convert(Ptr{_RTL_RUN_ONCE}, ref)
    if val isa PVOID
        ptr.Ptr = val
    end
    ref[]
end

const RTL_RUN_ONCE = _RTL_RUN_ONCE

const PRTL_RUN_ONCE = Ptr{_RTL_RUN_ONCE}

struct _RTL_BARRIER
    Reserved1::DWORD
    Reserved2::DWORD
    Reserved3::NTuple{2, ULONG_PTR}
    Reserved4::DWORD
    Reserved5::DWORD
end

const RTL_BARRIER = _RTL_BARRIER

const PRTL_BARRIER = Ptr{_RTL_BARRIER}

function HEAP_MAKE_TAG_FLAGS(TagBase, Tag)
    @ccall user32.HEAP_MAKE_TAG_FLAGS(TagBase::DWORD, Tag::DWORD)::DWORD
end

function RtlConstantTimeEqualMemory(v1, v2, len)
    @ccall user32.RtlConstantTimeEqualMemory(v1::Ptr{Cvoid}, v2::Ptr{Cvoid}, len::Culong)::Cint
end

function RtlSecureZeroMemory(ptr, cnt)
    @ccall user32.RtlSecureZeroMemory(ptr::PVOID, cnt::SIZE_T)::PVOID
end

struct _MESSAGE_RESOURCE_ENTRY
    Length::WORD
    Flags::WORD
    Text::NTuple{1, BYTE}
end

const MESSAGE_RESOURCE_ENTRY = _MESSAGE_RESOURCE_ENTRY

const PMESSAGE_RESOURCE_ENTRY = Ptr{_MESSAGE_RESOURCE_ENTRY}

struct _MESSAGE_RESOURCE_BLOCK
    LowId::DWORD
    HighId::DWORD
    OffsetToEntries::DWORD
end

const MESSAGE_RESOURCE_BLOCK = _MESSAGE_RESOURCE_BLOCK

const PMESSAGE_RESOURCE_BLOCK = Ptr{_MESSAGE_RESOURCE_BLOCK}

struct _MESSAGE_RESOURCE_DATA
    NumberOfBlocks::DWORD
    Blocks::NTuple{1, MESSAGE_RESOURCE_BLOCK}
end

const MESSAGE_RESOURCE_DATA = _MESSAGE_RESOURCE_DATA

const PMESSAGE_RESOURCE_DATA = Ptr{_MESSAGE_RESOURCE_DATA}

struct _OSVERSIONINFOA
    dwOSVersionInfoSize::DWORD
    dwMajorVersion::DWORD
    dwMinorVersion::DWORD
    dwBuildNumber::DWORD
    dwPlatformId::DWORD
    szCSDVersion::NTuple{128, CHAR}
end

const OSVERSIONINFOA = _OSVERSIONINFOA

const POSVERSIONINFOA = Ptr{_OSVERSIONINFOA}

const LPOSVERSIONINFOA = Ptr{_OSVERSIONINFOA}

struct _OSVERSIONINFOW
    dwOSVersionInfoSize::DWORD
    dwMajorVersion::DWORD
    dwMinorVersion::DWORD
    dwBuildNumber::DWORD
    dwPlatformId::DWORD
    szCSDVersion::NTuple{128, WCHAR}
end

const OSVERSIONINFOW = _OSVERSIONINFOW

const POSVERSIONINFOW = Ptr{_OSVERSIONINFOW}

const LPOSVERSIONINFOW = Ptr{_OSVERSIONINFOW}

const RTL_OSVERSIONINFOW = _OSVERSIONINFOW

const PRTL_OSVERSIONINFOW = Ptr{_OSVERSIONINFOW}

const OSVERSIONINFO = OSVERSIONINFOA

const POSVERSIONINFO = POSVERSIONINFOA

const LPOSVERSIONINFO = LPOSVERSIONINFOA

struct _OSVERSIONINFOEXA
    dwOSVersionInfoSize::DWORD
    dwMajorVersion::DWORD
    dwMinorVersion::DWORD
    dwBuildNumber::DWORD
    dwPlatformId::DWORD
    szCSDVersion::NTuple{128, CHAR}
    wServicePackMajor::WORD
    wServicePackMinor::WORD
    wSuiteMask::WORD
    wProductType::BYTE
    wReserved::BYTE
end

const OSVERSIONINFOEXA = _OSVERSIONINFOEXA

const POSVERSIONINFOEXA = Ptr{_OSVERSIONINFOEXA}

const LPOSVERSIONINFOEXA = Ptr{_OSVERSIONINFOEXA}

struct _OSVERSIONINFOEXW
    dwOSVersionInfoSize::DWORD
    dwMajorVersion::DWORD
    dwMinorVersion::DWORD
    dwBuildNumber::DWORD
    dwPlatformId::DWORD
    szCSDVersion::NTuple{128, WCHAR}
    wServicePackMajor::WORD
    wServicePackMinor::WORD
    wSuiteMask::WORD
    wProductType::BYTE
    wReserved::BYTE
end

const OSVERSIONINFOEXW = _OSVERSIONINFOEXW

const POSVERSIONINFOEXW = Ptr{_OSVERSIONINFOEXW}

const LPOSVERSIONINFOEXW = Ptr{_OSVERSIONINFOEXW}

const RTL_OSVERSIONINFOEXW = _OSVERSIONINFOEXW

const PRTL_OSVERSIONINFOEXW = Ptr{_OSVERSIONINFOEXW}

const OSVERSIONINFOEX = OSVERSIONINFOEXA

const POSVERSIONINFOEX = POSVERSIONINFOEXA

const LPOSVERSIONINFOEX = LPOSVERSIONINFOEXA

@cenum _RTL_UMS_THREAD_INFO_CLASS::UInt32 begin
    UmsThreadInvalidInfoClass = 0
    UmsThreadUserContext = 1
    UmsThreadPriority = 2
    UmsThreadAffinity = 3
    UmsThreadTeb = 4
    UmsThreadIsSuspended = 5
    UmsThreadIsTerminated = 6
    UmsThreadMaxInfoClass = 7
end

const RTL_UMS_THREAD_INFO_CLASS = _RTL_UMS_THREAD_INFO_CLASS

const PRTL_UMS_THREAD_INFO_CLASS = Ptr{_RTL_UMS_THREAD_INFO_CLASS}

@cenum _RTL_UMS_SCHEDULER_REASON::UInt32 begin
    UmsSchedulerStartup = 0
    UmsSchedulerThreadBlocked = 1
    UmsSchedulerThreadYield = 2
end

const RTL_UMS_SCHEDULER_REASON = _RTL_UMS_SCHEDULER_REASON

const PRTL_UMS_SCHEDULER_REASON = Ptr{_RTL_UMS_SCHEDULER_REASON}

# typedef _Function_class_ ( RTL_UMS_SCHEDULER_ENTRY_POINT ) VOID NTAPI RTL_UMS_SCHEDULER_ENTRY_POINT ( _In_ RTL_UMS_SCHEDULER_REASON Reason , _In_ ULONG_PTR ActivationPayload , _In_ PVOID SchedulerParam )
const RTL_UMS_SCHEDULER_ENTRY_POINT = Cvoid

# typedef RTL_UMS_SCHEDULER_ENTRY_POINT * PRTL_UMS_SCHEDULER_ENTRY_POINT
const PRTL_UMS_SCHEDULER_ENTRY_POINT = Ptr{RTL_UMS_SCHEDULER_ENTRY_POINT}

@cenum _IMAGE_POLICY_ENTRY_TYPE::UInt32 begin
    ImagePolicyEntryTypeNone = 0
    ImagePolicyEntryTypeBool = 1
    ImagePolicyEntryTypeInt8 = 2
    ImagePolicyEntryTypeUInt8 = 3
    ImagePolicyEntryTypeInt16 = 4
    ImagePolicyEntryTypeUInt16 = 5
    ImagePolicyEntryTypeInt32 = 6
    ImagePolicyEntryTypeUInt32 = 7
    ImagePolicyEntryTypeInt64 = 8
    ImagePolicyEntryTypeUInt64 = 9
    ImagePolicyEntryTypeAnsiString = 10
    ImagePolicyEntryTypeUnicodeString = 11
    ImagePolicyEntryTypeOverride = 12
    ImagePolicyEntryTypeMaximum = 13
end

const IMAGE_POLICY_ENTRY_TYPE = _IMAGE_POLICY_ENTRY_TYPE

@cenum _IMAGE_POLICY_ID::UInt32 begin
    ImagePolicyIdNone = 0
    ImagePolicyIdEtw = 1
    ImagePolicyIdDebug = 2
    ImagePolicyIdCrashDump = 3
    ImagePolicyIdCrashDumpKey = 4
    ImagePolicyIdCrashDumpKeyGuid = 5
    ImagePolicyIdParentSd = 6
    ImagePolicyIdParentSdRev = 7
    ImagePolicyIdSvn = 8
    ImagePolicyIdDeviceId = 9
    ImagePolicyIdCapability = 10
    ImagePolicyIdScenarioId = 11
    ImagePolicyIdMaximum = 12
end

const IMAGE_POLICY_ID = _IMAGE_POLICY_ID

struct __JL_Ctag_68
    data::NTuple{8, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_68}, f::Symbol)
    f === :None && return Ptr{Ptr{Cvoid}}(x + 0)
    f === :BoolValue && return Ptr{BOOLEAN}(x + 0)
    f === :Int8Value && return Ptr{INT8}(x + 0)
    f === :UInt8Value && return Ptr{UINT8}(x + 0)
    f === :Int16Value && return Ptr{INT16}(x + 0)
    f === :UInt16Value && return Ptr{UINT16}(x + 0)
    f === :Int32Value && return Ptr{INT32}(x + 0)
    f === :UInt32Value && return Ptr{UINT32}(x + 0)
    f === :Int64Value && return Ptr{INT64}(x + 0)
    f === :UInt64Value && return Ptr{UINT64}(x + 0)
    f === :AnsiStringValue && return Ptr{PCSTR}(x + 0)
    f === :UnicodeStringValue && return Ptr{PCWSTR}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_68, f::Symbol)
    r = Ref{__JL_Ctag_68}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_68}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_68}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_68 = Union{Ptr{Cvoid}, BOOLEAN, INT8, UINT8, INT16, UINT16, INT32, UINT32, INT64, UINT64, PCSTR, PCWSTR}

function __JL_Ctag_68(val::__U___JL_Ctag_68)
    ref = Ref{__JL_Ctag_68}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_68}, ref)
    if val isa Ptr{Cvoid}
        ptr.None = val
    elseif val isa BOOLEAN
        ptr.BoolValue = val
    elseif val isa INT8
        ptr.Int8Value = val
    elseif val isa UINT8
        ptr.UInt8Value = val
    elseif val isa INT16
        ptr.Int16Value = val
    elseif val isa UINT16
        ptr.UInt16Value = val
    elseif val isa INT32
        ptr.Int32Value = val
    elseif val isa UINT32
        ptr.UInt32Value = val
    elseif val isa INT64
        ptr.Int64Value = val
    elseif val isa UINT64
        ptr.UInt64Value = val
    elseif val isa PCSTR
        ptr.AnsiStringValue = val
    elseif val isa PCWSTR
        ptr.UnicodeStringValue = val
    end
    ref[]
end

struct _IMAGE_POLICY_ENTRY
    data::NTuple{16, UInt8}
end

function Base.getproperty(x::Ptr{_IMAGE_POLICY_ENTRY}, f::Symbol)
    f === :Type && return Ptr{IMAGE_POLICY_ENTRY_TYPE}(x + 0)
    f === :PolicyId && return Ptr{IMAGE_POLICY_ID}(x + 4)
    f === :u && return Ptr{__JL_Ctag_68}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_IMAGE_POLICY_ENTRY, f::Symbol)
    r = Ref{_IMAGE_POLICY_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_IMAGE_POLICY_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_IMAGE_POLICY_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _IMAGE_POLICY_ENTRY(Type::IMAGE_POLICY_ENTRY_TYPE, PolicyId::IMAGE_POLICY_ID, u::__JL_Ctag_68)
    ref = Ref{_IMAGE_POLICY_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_IMAGE_POLICY_ENTRY}, ref)
    ptr.Type = Type
    ptr.PolicyId = PolicyId
    ptr.u = u
    ref[]
end

const IMAGE_POLICY_ENTRY = _IMAGE_POLICY_ENTRY

const PCIMAGE_POLICY_ENTRY = Ptr{IMAGE_POLICY_ENTRY}

function RtlIsZeroMemory(Buffer, Length)
    @ccall user32.RtlIsZeroMemory(Buffer::PVOID, Length::SIZE_T)::BOOLEAN
end

@cenum _RTL_SYSTEM_GLOBAL_DATA_ID::UInt32 begin
    GlobalDataIdUnknown = 0
    GlobalDataIdRngSeedVersion = 1
    GlobalDataIdInterruptTime = 2
    GlobalDataIdTimeZoneBias = 3
    GlobalDataIdImageNumberLow = 4
    GlobalDataIdImageNumberHigh = 5
    GlobalDataIdTimeZoneId = 6
    GlobalDataIdNtMajorVersion = 7
    GlobalDataIdNtMinorVersion = 8
    GlobalDataIdSystemExpirationDate = 9
    GlobalDataIdKdDebuggerEnabled = 10
    GlobalDataIdCyclesPerYield = 11
    GlobalDataIdSafeBootMode = 12
    GlobalDataIdLastSystemRITEventTickCount = 13
    GlobalDataIdConsoleSharedDataFlags = 14
    GlobalDataIdNtSystemRootDrive = 15
    GlobalDataIdQpcShift = 16
    GlobalDataIdQpcBypassEnabled = 17
    GlobalDataIdQpcData = 18
    GlobalDataIdQpcBias = 19
end

const _RTL_CRITICAL_SECTION = Cvoid

struct _RTL_CRITICAL_SECTION_DEBUG
    Type::WORD
    CreatorBackTraceIndex::WORD
    CriticalSection::Ptr{_RTL_CRITICAL_SECTION}
    ProcessLocksList::LIST_ENTRY
    EntryCount::DWORD
    ContentionCount::DWORD
    Flags::DWORD
    CreatorBackTraceIndexHigh::WORD
    Identifier::WORD
end

function __drv_maxIRQL(APC_LEVEL)
    @ccall user32.__drv_maxIRQL(APC_LEVEL::Cint)::Cint
end

struct _RTL_SRWLOCK
    Ptr::PVOID
end

const RTL_SRWLOCK = _RTL_SRWLOCK

const PRTL_SRWLOCK = Ptr{_RTL_SRWLOCK}

struct _RTL_CONDITION_VARIABLE
    Ptr::PVOID
end

const RTL_CONDITION_VARIABLE = _RTL_CONDITION_VARIABLE

const PRTL_CONDITION_VARIABLE = Ptr{_RTL_CONDITION_VARIABLE}

# typedef VOID ( NTAPI * PAPCFUNC ) ( _In_ ULONG_PTR Parameter )
const PAPCFUNC = Ptr{Cvoid}

# typedef LONG ( NTAPI * PVECTORED_EXCEPTION_HANDLER ) ( struct _EXCEPTION_POINTERS * ExceptionInfo )
const PVECTORED_EXCEPTION_HANDLER = Ptr{Cvoid}

@cenum _HEAP_INFORMATION_CLASS::UInt32 begin
    HeapCompatibilityInformation = 0
    HeapEnableTerminationOnCorruption = 1
    HeapTag = 7
end

const HEAP_INFORMATION_CLASS = _HEAP_INFORMATION_CLASS

# typedef VOID ( NTAPI * WAITORTIMERCALLBACKFUNC ) ( PVOID , BOOLEAN )
const WAITORTIMERCALLBACKFUNC = Ptr{Cvoid}

# typedef VOID ( NTAPI * WORKERCALLBACKFUNC ) ( PVOID )
const WORKERCALLBACKFUNC = Ptr{Cvoid}

# typedef VOID ( NTAPI * APC_CALLBACK_FUNCTION ) ( DWORD , PVOID , PVOID )
const APC_CALLBACK_FUNCTION = Ptr{Cvoid}

const WAITORTIMERCALLBACK = WAITORTIMERCALLBACKFUNC

# typedef VOID ( NTAPI * PFLS_CALLBACK_FUNCTION ) ( _In_ PVOID lpFlsData )
const PFLS_CALLBACK_FUNCTION = Ptr{Cvoid}

# typedef BOOLEAN ( NTAPI * PSECURE_MEMORY_CACHE_CALLBACK ) ( _In_reads_bytes_ ( Range ) PVOID Addr , _In_ SIZE_T Range )
const PSECURE_MEMORY_CACHE_CALLBACK = Ptr{Cvoid}

struct _ACTIVATION_CONTEXT_QUERY_INDEX
    ulAssemblyIndex::DWORD
    ulFileIndexInAssembly::DWORD
end

const ACTIVATION_CONTEXT_QUERY_INDEX = _ACTIVATION_CONTEXT_QUERY_INDEX

const PACTIVATION_CONTEXT_QUERY_INDEX = Ptr{_ACTIVATION_CONTEXT_QUERY_INDEX}

const PCACTIVATION_CONTEXT_QUERY_INDEX = Ptr{_ACTIVATION_CONTEXT_QUERY_INDEX}

struct _ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION
    ulFlags::DWORD
    ulEncodedAssemblyIdentityLength::DWORD
    ulManifestPathType::DWORD
    ulManifestPathLength::DWORD
    liManifestLastWriteTime::LARGE_INTEGER
    ulPolicyPathType::DWORD
    ulPolicyPathLength::DWORD
    liPolicyLastWriteTime::LARGE_INTEGER
    ulMetadataSatelliteRosterIndex::DWORD
    ulManifestVersionMajor::DWORD
    ulManifestVersionMinor::DWORD
    ulPolicyVersionMajor::DWORD
    ulPolicyVersionMinor::DWORD
    ulAssemblyDirectoryNameLength::DWORD
    lpAssemblyEncodedAssemblyIdentity::PCWSTR
    lpAssemblyManifestPath::PCWSTR
    lpAssemblyPolicyPath::PCWSTR
    lpAssemblyDirectoryName::PCWSTR
    ulFileCount::DWORD
end

const ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION = _ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION

const PACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION = Ptr{_ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION}

const PCACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION = Ptr{_ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION}

@cenum ACTCTX_REQUESTED_RUN_LEVEL::UInt32 begin
    ACTCTX_RUN_LEVEL_UNSPECIFIED = 0
    ACTCTX_RUN_LEVEL_AS_INVOKER = 1
    ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE = 2
    ACTCTX_RUN_LEVEL_REQUIRE_ADMIN = 3
    ACTCTX_RUN_LEVEL_NUMBERS = 4
end

struct _ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION
    ulFlags::DWORD
    RunLevel::ACTCTX_REQUESTED_RUN_LEVEL
    UiAccess::DWORD
end

const ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION = _ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION

const PACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION = Ptr{_ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION}

const PCACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION = Ptr{_ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION}

@cenum ACTCTX_COMPATIBILITY_ELEMENT_TYPE::UInt32 begin
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_UNKNOWN = 0
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS = 1
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MITIGATION = 2
    ACTCTX_COMPATIBILITY_ELEMENT_TYPE_MAXVERSIONTESTED = 3
end

struct _COMPATIBILITY_CONTEXT_ELEMENT
    Id::GUID
    Type::ACTCTX_COMPATIBILITY_ELEMENT_TYPE
    MaxVersionTested::ULONGLONG
end

const COMPATIBILITY_CONTEXT_ELEMENT = _COMPATIBILITY_CONTEXT_ELEMENT

const PCOMPATIBILITY_CONTEXT_ELEMENT = Ptr{_COMPATIBILITY_CONTEXT_ELEMENT}

const PCCOMPATIBILITY_CONTEXT_ELEMENT = Ptr{_COMPATIBILITY_CONTEXT_ELEMENT}

struct _SUPPORTED_OS_INFO
    MajorVersion::WORD
    MinorVersion::WORD
end

const SUPPORTED_OS_INFO = _SUPPORTED_OS_INFO

const PSUPPORTED_OS_INFO = Ptr{_SUPPORTED_OS_INFO}

struct _MAXVERSIONTESTED_INFO
    MaxVersionTested::ULONGLONG
end

const MAXVERSIONTESTED_INFO = _MAXVERSIONTESTED_INFO

const PMAXVERSIONTESTED_INFO = Ptr{_MAXVERSIONTESTED_INFO}

struct _ACTIVATION_CONTEXT_DETAILED_INFORMATION
    dwFlags::DWORD
    ulFormatVersion::DWORD
    ulAssemblyCount::DWORD
    ulRootManifestPathType::DWORD
    ulRootManifestPathChars::DWORD
    ulRootConfigurationPathType::DWORD
    ulRootConfigurationPathChars::DWORD
    ulAppDirPathType::DWORD
    ulAppDirPathChars::DWORD
    lpRootManifestPath::PCWSTR
    lpRootConfigurationPath::PCWSTR
    lpAppDirPath::PCWSTR
end

const ACTIVATION_CONTEXT_DETAILED_INFORMATION = _ACTIVATION_CONTEXT_DETAILED_INFORMATION

const PACTIVATION_CONTEXT_DETAILED_INFORMATION = Ptr{_ACTIVATION_CONTEXT_DETAILED_INFORMATION}

const PCACTIVATION_CONTEXT_DETAILED_INFORMATION = Ptr{_ACTIVATION_CONTEXT_DETAILED_INFORMATION}

struct _HARDWARE_COUNTER_DATA
    Type::HARDWARE_COUNTER_TYPE
    Reserved::DWORD
    Value::DWORD64
end

const HARDWARE_COUNTER_DATA = _HARDWARE_COUNTER_DATA

const PHARDWARE_COUNTER_DATA = Ptr{_HARDWARE_COUNTER_DATA}

struct _PERFORMANCE_DATA
    Size::WORD
    Version::BYTE
    HwCountersCount::BYTE
    ContextSwitchCount::DWORD
    WaitReasonBitMap::DWORD64
    CycleTime::DWORD64
    RetryCount::DWORD
    Reserved::DWORD
    HwCounters::NTuple{16, HARDWARE_COUNTER_DATA}
end

const PERFORMANCE_DATA = _PERFORMANCE_DATA

const PPERFORMANCE_DATA = Ptr{_PERFORMANCE_DATA}

struct _EVENTLOGRECORD
    Length::DWORD
    Reserved::DWORD
    RecordNumber::DWORD
    TimeGenerated::DWORD
    TimeWritten::DWORD
    EventID::DWORD
    EventType::WORD
    NumStrings::WORD
    EventCategory::WORD
    ReservedFlags::WORD
    ClosingRecordNumber::DWORD
    StringOffset::DWORD
    UserSidLength::DWORD
    UserSidOffset::DWORD
    DataLength::DWORD
    DataOffset::DWORD
end

const EVENTLOGRECORD = _EVENTLOGRECORD

const PEVENTLOGRECORD = Ptr{_EVENTLOGRECORD}

const _EVENTSFORLOGFILE = Cvoid

const EVENTSFORLOGFILE = _EVENTSFORLOGFILE

const PEVENTSFORLOGFILE = Ptr{_EVENTSFORLOGFILE}

const _PACKEDEVENTINFO = Cvoid

const PACKEDEVENTINFO = _PACKEDEVENTINFO

const PPACKEDEVENTINFO = Ptr{_PACKEDEVENTINFO}

@cenum _CM_SERVICE_NODE_TYPE::UInt32 begin
    DriverType = 1
    FileSystemType = 2
    Win32ServiceOwnProcess = 16
    Win32ServiceShareProcess = 32
    AdapterType = 4
    RecognizerType = 8
end

const SERVICE_NODE_TYPE = _CM_SERVICE_NODE_TYPE

@cenum _CM_SERVICE_LOAD_TYPE::UInt32 begin
    BootLoad = 0
    SystemLoad = 1
    AutoLoad = 2
    DemandLoad = 3
    DisableLoad = 4
end

const SERVICE_LOAD_TYPE = _CM_SERVICE_LOAD_TYPE

@cenum _CM_ERROR_CONTROL_TYPE::UInt32 begin
    IgnoreError = 0
    NormalError = 1
    SevereError = 2
    CriticalError = 3
end

const SERVICE_ERROR_TYPE = _CM_ERROR_CONTROL_TYPE

struct _TAPE_ERASE
    Type::DWORD
    Immediate::BOOLEAN
end

const TAPE_ERASE = _TAPE_ERASE

const PTAPE_ERASE = Ptr{_TAPE_ERASE}

struct _TAPE_PREPARE
    Operation::DWORD
    Immediate::BOOLEAN
end

const TAPE_PREPARE = _TAPE_PREPARE

const PTAPE_PREPARE = Ptr{_TAPE_PREPARE}

struct _TAPE_WRITE_MARKS
    Type::DWORD
    Count::DWORD
    Immediate::BOOLEAN
end

const TAPE_WRITE_MARKS = _TAPE_WRITE_MARKS

const PTAPE_WRITE_MARKS = Ptr{_TAPE_WRITE_MARKS}

struct _TAPE_GET_POSITION
    Type::DWORD
    Partition::DWORD
    Offset::LARGE_INTEGER
end

const TAPE_GET_POSITION = _TAPE_GET_POSITION

const PTAPE_GET_POSITION = Ptr{_TAPE_GET_POSITION}

struct _TAPE_SET_POSITION
    Method::DWORD
    Partition::DWORD
    Offset::LARGE_INTEGER
    Immediate::BOOLEAN
end

const TAPE_SET_POSITION = _TAPE_SET_POSITION

const PTAPE_SET_POSITION = Ptr{_TAPE_SET_POSITION}

struct _TAPE_GET_DRIVE_PARAMETERS
    ECC::BOOLEAN
    Compression::BOOLEAN
    DataPadding::BOOLEAN
    ReportSetmarks::BOOLEAN
    DefaultBlockSize::DWORD
    MaximumBlockSize::DWORD
    MinimumBlockSize::DWORD
    MaximumPartitionCount::DWORD
    FeaturesLow::DWORD
    FeaturesHigh::DWORD
    EOTWarningZoneSize::DWORD
end

const TAPE_GET_DRIVE_PARAMETERS = _TAPE_GET_DRIVE_PARAMETERS

const PTAPE_GET_DRIVE_PARAMETERS = Ptr{_TAPE_GET_DRIVE_PARAMETERS}

struct _TAPE_SET_DRIVE_PARAMETERS
    ECC::BOOLEAN
    Compression::BOOLEAN
    DataPadding::BOOLEAN
    ReportSetmarks::BOOLEAN
    EOTWarningZoneSize::DWORD
end

const TAPE_SET_DRIVE_PARAMETERS = _TAPE_SET_DRIVE_PARAMETERS

const PTAPE_SET_DRIVE_PARAMETERS = Ptr{_TAPE_SET_DRIVE_PARAMETERS}

struct _TAPE_GET_MEDIA_PARAMETERS
    Capacity::LARGE_INTEGER
    Remaining::LARGE_INTEGER
    BlockSize::DWORD
    PartitionCount::DWORD
    WriteProtected::BOOLEAN
end

const TAPE_GET_MEDIA_PARAMETERS = _TAPE_GET_MEDIA_PARAMETERS

const PTAPE_GET_MEDIA_PARAMETERS = Ptr{_TAPE_GET_MEDIA_PARAMETERS}

struct _TAPE_SET_MEDIA_PARAMETERS
    BlockSize::DWORD
end

const TAPE_SET_MEDIA_PARAMETERS = _TAPE_SET_MEDIA_PARAMETERS

const PTAPE_SET_MEDIA_PARAMETERS = Ptr{_TAPE_SET_MEDIA_PARAMETERS}

struct _TAPE_CREATE_PARTITION
    Method::DWORD
    Count::DWORD
    Size::DWORD
end

const TAPE_CREATE_PARTITION = _TAPE_CREATE_PARTITION

const PTAPE_CREATE_PARTITION = Ptr{_TAPE_CREATE_PARTITION}

struct _TAPE_WMI_OPERATIONS
    Method::DWORD
    DataBufferSize::DWORD
    DataBuffer::PVOID
end

const TAPE_WMI_OPERATIONS = _TAPE_WMI_OPERATIONS

const PTAPE_WMI_OPERATIONS = Ptr{_TAPE_WMI_OPERATIONS}

@cenum _TAPE_DRIVE_PROBLEM_TYPE::UInt32 begin
    TapeDriveProblemNone = 0
    TapeDriveReadWriteWarning = 1
    TapeDriveReadWriteError = 2
    TapeDriveReadWarning = 3
    TapeDriveWriteWarning = 4
    TapeDriveReadError = 5
    TapeDriveWriteError = 6
    TapeDriveHardwareError = 7
    TapeDriveUnsupportedMedia = 8
    TapeDriveScsiConnectionError = 9
    TapeDriveTimetoClean = 10
    TapeDriveCleanDriveNow = 11
    TapeDriveMediaLifeExpired = 12
    TapeDriveSnappedTape = 13
end

const TAPE_DRIVE_PROBLEM_TYPE = _TAPE_DRIVE_PROBLEM_TYPE

@cenum _TRANSACTION_OUTCOME::UInt32 begin
    TransactionOutcomeUndetermined = 1
    TransactionOutcomeCommitted = 2
    TransactionOutcomeAborted = 3
end

const TRANSACTION_OUTCOME = _TRANSACTION_OUTCOME

@cenum _TRANSACTION_STATE::UInt32 begin
    TransactionStateNormal = 1
    TransactionStateIndoubt = 2
    TransactionStateCommittedNotify = 3
end

const TRANSACTION_STATE = _TRANSACTION_STATE

struct _TRANSACTION_BASIC_INFORMATION
    TransactionId::GUID
    State::DWORD
    Outcome::DWORD
end

const TRANSACTION_BASIC_INFORMATION = _TRANSACTION_BASIC_INFORMATION

const PTRANSACTION_BASIC_INFORMATION = Ptr{_TRANSACTION_BASIC_INFORMATION}

struct _TRANSACTIONMANAGER_BASIC_INFORMATION
    TmIdentity::GUID
    VirtualClock::LARGE_INTEGER
end

const TRANSACTIONMANAGER_BASIC_INFORMATION = _TRANSACTIONMANAGER_BASIC_INFORMATION

const PTRANSACTIONMANAGER_BASIC_INFORMATION = Ptr{_TRANSACTIONMANAGER_BASIC_INFORMATION}

struct _TRANSACTIONMANAGER_LOG_INFORMATION
    LogIdentity::GUID
end

const TRANSACTIONMANAGER_LOG_INFORMATION = _TRANSACTIONMANAGER_LOG_INFORMATION

const PTRANSACTIONMANAGER_LOG_INFORMATION = Ptr{_TRANSACTIONMANAGER_LOG_INFORMATION}

struct _TRANSACTIONMANAGER_LOGPATH_INFORMATION
    LogPathLength::DWORD
    LogPath::NTuple{1, WCHAR}
end

const TRANSACTIONMANAGER_LOGPATH_INFORMATION = _TRANSACTIONMANAGER_LOGPATH_INFORMATION

const PTRANSACTIONMANAGER_LOGPATH_INFORMATION = Ptr{_TRANSACTIONMANAGER_LOGPATH_INFORMATION}

struct _TRANSACTIONMANAGER_RECOVERY_INFORMATION
    LastRecoveredLsn::ULONGLONG
end

const TRANSACTIONMANAGER_RECOVERY_INFORMATION = _TRANSACTIONMANAGER_RECOVERY_INFORMATION

const PTRANSACTIONMANAGER_RECOVERY_INFORMATION = Ptr{_TRANSACTIONMANAGER_RECOVERY_INFORMATION}

struct _TRANSACTIONMANAGER_OLDEST_INFORMATION
    OldestTransactionGuid::GUID
end

const TRANSACTIONMANAGER_OLDEST_INFORMATION = _TRANSACTIONMANAGER_OLDEST_INFORMATION

const PTRANSACTIONMANAGER_OLDEST_INFORMATION = Ptr{_TRANSACTIONMANAGER_OLDEST_INFORMATION}

struct _TRANSACTION_PROPERTIES_INFORMATION
    IsolationLevel::DWORD
    IsolationFlags::DWORD
    Timeout::LARGE_INTEGER
    Outcome::DWORD
    DescriptionLength::DWORD
    Description::NTuple{1, WCHAR}
end

const TRANSACTION_PROPERTIES_INFORMATION = _TRANSACTION_PROPERTIES_INFORMATION

const PTRANSACTION_PROPERTIES_INFORMATION = Ptr{_TRANSACTION_PROPERTIES_INFORMATION}

struct _TRANSACTION_BIND_INFORMATION
    TmHandle::HANDLE
end

const TRANSACTION_BIND_INFORMATION = _TRANSACTION_BIND_INFORMATION

const PTRANSACTION_BIND_INFORMATION = Ptr{_TRANSACTION_BIND_INFORMATION}

struct _TRANSACTION_ENLISTMENT_PAIR
    EnlistmentId::GUID
    ResourceManagerId::GUID
end

const TRANSACTION_ENLISTMENT_PAIR = _TRANSACTION_ENLISTMENT_PAIR

const PTRANSACTION_ENLISTMENT_PAIR = Ptr{_TRANSACTION_ENLISTMENT_PAIR}

struct _TRANSACTION_ENLISTMENTS_INFORMATION
    NumberOfEnlistments::DWORD
    EnlistmentPair::NTuple{1, TRANSACTION_ENLISTMENT_PAIR}
end

const TRANSACTION_ENLISTMENTS_INFORMATION = _TRANSACTION_ENLISTMENTS_INFORMATION

const PTRANSACTION_ENLISTMENTS_INFORMATION = Ptr{_TRANSACTION_ENLISTMENTS_INFORMATION}

struct _TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION
    SuperiorEnlistmentPair::TRANSACTION_ENLISTMENT_PAIR
end

const TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION = _TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION

const PTRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION = Ptr{_TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION}

struct _RESOURCEMANAGER_BASIC_INFORMATION
    ResourceManagerId::GUID
    DescriptionLength::DWORD
    Description::NTuple{1, WCHAR}
end

const RESOURCEMANAGER_BASIC_INFORMATION = _RESOURCEMANAGER_BASIC_INFORMATION

const PRESOURCEMANAGER_BASIC_INFORMATION = Ptr{_RESOURCEMANAGER_BASIC_INFORMATION}

struct _RESOURCEMANAGER_COMPLETION_INFORMATION
    IoCompletionPortHandle::HANDLE
    CompletionKey::ULONG_PTR
end

const RESOURCEMANAGER_COMPLETION_INFORMATION = _RESOURCEMANAGER_COMPLETION_INFORMATION

const PRESOURCEMANAGER_COMPLETION_INFORMATION = Ptr{_RESOURCEMANAGER_COMPLETION_INFORMATION}

@cenum _TRANSACTION_INFORMATION_CLASS::UInt32 begin
    TransactionBasicInformation = 0
    TransactionPropertiesInformation = 1
    TransactionEnlistmentInformation = 2
    TransactionSuperiorEnlistmentInformation = 3
    TransactionBindInformation = 4
    TransactionDTCPrivateInformation = 5
end

const TRANSACTION_INFORMATION_CLASS = _TRANSACTION_INFORMATION_CLASS

@cenum _TRANSACTIONMANAGER_INFORMATION_CLASS::UInt32 begin
    TransactionManagerBasicInformation = 0
    TransactionManagerLogInformation = 1
    TransactionManagerLogPathInformation = 2
    TransactionManagerRecoveryInformation = 4
    TransactionManagerOnlineProbeInformation = 3
    TransactionManagerOldestTransactionInformation = 5
end

const TRANSACTIONMANAGER_INFORMATION_CLASS = _TRANSACTIONMANAGER_INFORMATION_CLASS

@cenum _RESOURCEMANAGER_INFORMATION_CLASS::UInt32 begin
    ResourceManagerBasicInformation = 0
    ResourceManagerCompletionInformation = 1
end

const RESOURCEMANAGER_INFORMATION_CLASS = _RESOURCEMANAGER_INFORMATION_CLASS

struct _ENLISTMENT_BASIC_INFORMATION
    EnlistmentId::GUID
    TransactionId::GUID
    ResourceManagerId::GUID
end

const ENLISTMENT_BASIC_INFORMATION = _ENLISTMENT_BASIC_INFORMATION

const PENLISTMENT_BASIC_INFORMATION = Ptr{_ENLISTMENT_BASIC_INFORMATION}

struct _ENLISTMENT_CRM_INFORMATION
    CrmTransactionManagerId::GUID
    CrmResourceManagerId::GUID
    CrmEnlistmentId::GUID
end

const ENLISTMENT_CRM_INFORMATION = _ENLISTMENT_CRM_INFORMATION

const PENLISTMENT_CRM_INFORMATION = Ptr{_ENLISTMENT_CRM_INFORMATION}

@cenum _ENLISTMENT_INFORMATION_CLASS::UInt32 begin
    EnlistmentBasicInformation = 0
    EnlistmentRecoveryInformation = 1
    EnlistmentCrmInformation = 2
end

const ENLISTMENT_INFORMATION_CLASS = _ENLISTMENT_INFORMATION_CLASS

struct _TRANSACTION_LIST_ENTRY
    UOW::Cint
end

const TRANSACTION_LIST_ENTRY = _TRANSACTION_LIST_ENTRY

const PTRANSACTION_LIST_ENTRY = Ptr{_TRANSACTION_LIST_ENTRY}

struct _TRANSACTION_LIST_INFORMATION
    NumberOfTransactions::DWORD
    TransactionInformation::NTuple{1, TRANSACTION_LIST_ENTRY}
end

const TRANSACTION_LIST_INFORMATION = _TRANSACTION_LIST_INFORMATION

const PTRANSACTION_LIST_INFORMATION = Ptr{_TRANSACTION_LIST_INFORMATION}

@cenum _KTMOBJECT_TYPE::UInt32 begin
    KTMOBJECT_TRANSACTION = 0
    KTMOBJECT_TRANSACTION_MANAGER = 1
    KTMOBJECT_RESOURCE_MANAGER = 2
    KTMOBJECT_ENLISTMENT = 3
    KTMOBJECT_INVALID = 4
end

const KTMOBJECT_TYPE = _KTMOBJECT_TYPE

const PKTMOBJECT_TYPE = Ptr{_KTMOBJECT_TYPE}

struct _KTMOBJECT_CURSOR
    LastQuery::GUID
    ObjectIdCount::DWORD
    ObjectIds::NTuple{1, GUID}
end

const KTMOBJECT_CURSOR = _KTMOBJECT_CURSOR

const PKTMOBJECT_CURSOR = Ptr{_KTMOBJECT_CURSOR}

const TP_VERSION = DWORD

const PTP_VERSION = Ptr{DWORD}

const _TP_CALLBACK_INSTANCE = Cvoid

const TP_CALLBACK_INSTANCE = _TP_CALLBACK_INSTANCE

const PTP_CALLBACK_INSTANCE = Ptr{_TP_CALLBACK_INSTANCE}

# typedef VOID ( NTAPI * PTP_SIMPLE_CALLBACK ) ( _Inout_ PTP_CALLBACK_INSTANCE Instance , _Inout_opt_ PVOID Context )
const PTP_SIMPLE_CALLBACK = Ptr{Cvoid}

const _TP_POOL = Cvoid

const TP_POOL = _TP_POOL

const PTP_POOL = Ptr{_TP_POOL}

@cenum _TP_CALLBACK_PRIORITY::UInt32 begin
    TP_CALLBACK_PRIORITY_HIGH = 0
    TP_CALLBACK_PRIORITY_NORMAL = 1
    TP_CALLBACK_PRIORITY_LOW = 2
    TP_CALLBACK_PRIORITY_INVALID = 3
    TP_CALLBACK_PRIORITY_COUNT = 3
end

const TP_CALLBACK_PRIORITY = _TP_CALLBACK_PRIORITY

struct _TP_POOL_STACK_INFORMATION
    StackReserve::SIZE_T
    StackCommit::SIZE_T
end

const TP_POOL_STACK_INFORMATION = _TP_POOL_STACK_INFORMATION

const PTP_POOL_STACK_INFORMATION = Ptr{_TP_POOL_STACK_INFORMATION}

const _TP_CLEANUP_GROUP = Cvoid

const TP_CLEANUP_GROUP = _TP_CLEANUP_GROUP

const PTP_CLEANUP_GROUP = Ptr{_TP_CLEANUP_GROUP}

# typedef VOID ( NTAPI * PTP_CLEANUP_GROUP_CANCEL_CALLBACK ) ( _Inout_opt_ PVOID ObjectContext , _Inout_opt_ PVOID CleanupContext )
const PTP_CLEANUP_GROUP_CANCEL_CALLBACK = Ptr{Cvoid}

const _ACTIVATION_CONTEXT = Cvoid

struct __JL_Ctag_90
    LongFunction::DWORD
    Persistent::DWORD
    Private::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_90}, f::Symbol)
    f === :LongFunction && return (Ptr{DWORD}(x + 0), 0, 1)
    f === :Persistent && return (Ptr{DWORD}(x + 0), 1, 1)
    f === :Private && return (Ptr{DWORD}(x + 0), 2, 30)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_90, f::Symbol)
    r = Ref{__JL_Ctag_90}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_90}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_90}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_89
    data::NTuple{4, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_89}, f::Symbol)
    f === :Flags && return Ptr{DWORD}(x + 0)
    f === :s && return Ptr{__JL_Ctag_90}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_89, f::Symbol)
    r = Ref{__JL_Ctag_89}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_89}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_89}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_89 = Union{DWORD, __JL_Ctag_90}

function __JL_Ctag_89(val::__U___JL_Ctag_89)
    ref = Ref{__JL_Ctag_89}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_89}, ref)
    if val isa DWORD
        ptr.Flags = val
    elseif val isa __JL_Ctag_90
        ptr.s = val
    end
    ref[]
end

struct _TP_CALLBACK_ENVIRON_V1
    data::NTuple{64, UInt8}
end

function Base.getproperty(x::Ptr{_TP_CALLBACK_ENVIRON_V1}, f::Symbol)
    f === :Version && return Ptr{TP_VERSION}(x + 0)
    f === :Pool && return Ptr{PTP_POOL}(x + 8)
    f === :CleanupGroup && return Ptr{PTP_CLEANUP_GROUP}(x + 16)
    f === :CleanupGroupCancelCallback && return Ptr{PTP_CLEANUP_GROUP_CANCEL_CALLBACK}(x + 24)
    f === :RaceDll && return Ptr{PVOID}(x + 32)
    f === :ActivationContext && return Ptr{Ptr{_ACTIVATION_CONTEXT}}(x + 40)
    f === :FinalizationCallback && return Ptr{PTP_SIMPLE_CALLBACK}(x + 48)
    f === :u && return Ptr{__JL_Ctag_89}(x + 56)
    return getfield(x, f)
end

function Base.getproperty(x::_TP_CALLBACK_ENVIRON_V1, f::Symbol)
    r = Ref{_TP_CALLBACK_ENVIRON_V1}(x)
    ptr = Base.unsafe_convert(Ptr{_TP_CALLBACK_ENVIRON_V1}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_TP_CALLBACK_ENVIRON_V1}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _TP_CALLBACK_ENVIRON_V1(Version::TP_VERSION, Pool::PTP_POOL, CleanupGroup::PTP_CLEANUP_GROUP, CleanupGroupCancelCallback::PTP_CLEANUP_GROUP_CANCEL_CALLBACK, RaceDll::PVOID, ActivationContext::Ptr{_ACTIVATION_CONTEXT}, FinalizationCallback::PTP_SIMPLE_CALLBACK, u::__JL_Ctag_89)
    ref = Ref{_TP_CALLBACK_ENVIRON_V1}()
    ptr = Base.unsafe_convert(Ptr{_TP_CALLBACK_ENVIRON_V1}, ref)
    ptr.Version = Version
    ptr.Pool = Pool
    ptr.CleanupGroup = CleanupGroup
    ptr.CleanupGroupCancelCallback = CleanupGroupCancelCallback
    ptr.RaceDll = RaceDll
    ptr.ActivationContext = ActivationContext
    ptr.FinalizationCallback = FinalizationCallback
    ptr.u = u
    ref[]
end

const TP_CALLBACK_ENVIRON_V1 = _TP_CALLBACK_ENVIRON_V1

const TP_CALLBACK_ENVIRON = TP_CALLBACK_ENVIRON_V1

const PTP_CALLBACK_ENVIRON = Ptr{TP_CALLBACK_ENVIRON_V1}

function TpInitializeCallbackEnviron(CallbackEnviron)
    @ccall user32.TpInitializeCallbackEnviron(CallbackEnviron::PTP_CALLBACK_ENVIRON)::Cvoid
end

function TpSetCallbackThreadpool(CallbackEnviron, Pool)
    @ccall user32.TpSetCallbackThreadpool(CallbackEnviron::PTP_CALLBACK_ENVIRON, Pool::PTP_POOL)::Cvoid
end

function TpSetCallbackCleanupGroup(CallbackEnviron, CleanupGroup, CleanupGroupCancelCallback)
    @ccall user32.TpSetCallbackCleanupGroup(CallbackEnviron::PTP_CALLBACK_ENVIRON, CleanupGroup::PTP_CLEANUP_GROUP, CleanupGroupCancelCallback::PTP_CLEANUP_GROUP_CANCEL_CALLBACK)::Cvoid
end

function TpSetCallbackActivationContext(CallbackEnviron, ActivationContext)
    @ccall user32.TpSetCallbackActivationContext(CallbackEnviron::PTP_CALLBACK_ENVIRON, ActivationContext::Ptr{_ACTIVATION_CONTEXT})::Cvoid
end

function TpSetCallbackNoActivationContext(CallbackEnviron)
    @ccall user32.TpSetCallbackNoActivationContext(CallbackEnviron::PTP_CALLBACK_ENVIRON)::Cvoid
end

function TpSetCallbackLongFunction(CallbackEnviron)
    @ccall user32.TpSetCallbackLongFunction(CallbackEnviron::PTP_CALLBACK_ENVIRON)::Cvoid
end

function TpSetCallbackRaceWithDll(CallbackEnviron, DllHandle)
    @ccall user32.TpSetCallbackRaceWithDll(CallbackEnviron::PTP_CALLBACK_ENVIRON, DllHandle::PVOID)::Cvoid
end

function TpSetCallbackFinalizationCallback(CallbackEnviron, FinalizationCallback)
    @ccall user32.TpSetCallbackFinalizationCallback(CallbackEnviron::PTP_CALLBACK_ENVIRON, FinalizationCallback::PTP_SIMPLE_CALLBACK)::Cvoid
end

function TpSetCallbackPersistent(CallbackEnviron)
    @ccall user32.TpSetCallbackPersistent(CallbackEnviron::PTP_CALLBACK_ENVIRON)::Cvoid
end

function TpDestroyCallbackEnviron(CallbackEnviron)
    @ccall user32.TpDestroyCallbackEnviron(CallbackEnviron::PTP_CALLBACK_ENVIRON)::Cvoid
end

const _TP_WORK = Cvoid

const TP_WORK = _TP_WORK

const PTP_WORK = Ptr{_TP_WORK}

# typedef VOID ( NTAPI * PTP_WORK_CALLBACK ) ( _Inout_ PTP_CALLBACK_INSTANCE Instance , _Inout_opt_ PVOID Context , _Inout_ PTP_WORK Work )
const PTP_WORK_CALLBACK = Ptr{Cvoid}

const _TP_TIMER = Cvoid

const TP_TIMER = _TP_TIMER

const PTP_TIMER = Ptr{_TP_TIMER}

# typedef VOID ( NTAPI * PTP_TIMER_CALLBACK ) ( _Inout_ PTP_CALLBACK_INSTANCE Instance , _Inout_opt_ PVOID Context , _Inout_ PTP_TIMER Timer )
const PTP_TIMER_CALLBACK = Ptr{Cvoid}

const TP_WAIT_RESULT = DWORD

const _TP_WAIT = Cvoid

const TP_WAIT = _TP_WAIT

const PTP_WAIT = Ptr{_TP_WAIT}

# typedef VOID ( NTAPI * PTP_WAIT_CALLBACK ) ( _Inout_ PTP_CALLBACK_INSTANCE Instance , _Inout_opt_ PVOID Context , _Inout_ PTP_WAIT Wait , _In_ TP_WAIT_RESULT WaitResult )
const PTP_WAIT_CALLBACK = Ptr{Cvoid}

const _TP_IO = Cvoid

const TP_IO = _TP_IO

const PTP_IO = Ptr{_TP_IO}

const _TEB = Cvoid

function NtCurrentTeb()
    @ccall user32.NtCurrentTeb()::Ptr{_TEB}
end

function GetCurrentFiber()
    @ccall user32.GetCurrentFiber()::PVOID
end

function GetFiberData()
    @ccall user32.GetFiberData()::PVOID
end

const SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES

const PSECURITY_ATTRIBUTES = Ptr{_SECURITY_ATTRIBUTES}

struct _OVERLAPPED
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_OVERLAPPED}, f::Symbol)
    f === :Internal && return Ptr{ULONG_PTR}(x + 0)
    f === :InternalHigh && return Ptr{ULONG_PTR}(x + 8)
    f === :Offset && return Ptr{DWORD}(x + 16)
    f === :OffsetHigh && return Ptr{DWORD}(x + 20)
    f === :Pointer && return Ptr{PVOID}(x + 16)
    f === :hEvent && return Ptr{HANDLE}(x + 24)
    return getfield(x, f)
end

function Base.getproperty(x::_OVERLAPPED, f::Symbol)
    r = Ref{_OVERLAPPED}(x)
    ptr = Base.unsafe_convert(Ptr{_OVERLAPPED}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_OVERLAPPED}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _OVERLAPPED(Internal::ULONG_PTR, InternalHigh::ULONG_PTR, hEvent::HANDLE)
    ref = Ref{_OVERLAPPED}()
    ptr = Base.unsafe_convert(Ptr{_OVERLAPPED}, ref)
    ptr.Internal = Internal
    ptr.InternalHigh = InternalHigh
    ptr.hEvent = hEvent
    ref[]
end

const OVERLAPPED = _OVERLAPPED

const LPOVERLAPPED = Ptr{_OVERLAPPED}

struct _OVERLAPPED_ENTRY
    lpCompletionKey::ULONG_PTR
    lpOverlapped::LPOVERLAPPED
    Internal::ULONG_PTR
    dwNumberOfBytesTransferred::DWORD
end

const OVERLAPPED_ENTRY = _OVERLAPPED_ENTRY

const LPOVERLAPPED_ENTRY = Ptr{_OVERLAPPED_ENTRY}

struct _SYSTEMTIME
    wYear::WORD
    wMonth::WORD
    wDayOfWeek::WORD
    wDay::WORD
    wHour::WORD
    wMinute::WORD
    wSecond::WORD
    wMilliseconds::WORD
end

const SYSTEMTIME = _SYSTEMTIME

const PSYSTEMTIME = Ptr{_SYSTEMTIME}

const LPSYSTEMTIME = Ptr{_SYSTEMTIME}

struct _WIN32_FIND_DATAA
    dwFileAttributes::DWORD
    ftCreationTime::FILETIME
    ftLastAccessTime::FILETIME
    ftLastWriteTime::FILETIME
    nFileSizeHigh::DWORD
    nFileSizeLow::DWORD
    dwReserved0::DWORD
    dwReserved1::DWORD
    cFileName::NTuple{260, CHAR}
    cAlternateFileName::NTuple{14, CHAR}
end

const WIN32_FIND_DATAA = _WIN32_FIND_DATAA

const PWIN32_FIND_DATAA = Ptr{_WIN32_FIND_DATAA}

const LPWIN32_FIND_DATAA = Ptr{_WIN32_FIND_DATAA}

struct _WIN32_FIND_DATAW
    dwFileAttributes::DWORD
    ftCreationTime::FILETIME
    ftLastAccessTime::FILETIME
    ftLastWriteTime::FILETIME
    nFileSizeHigh::DWORD
    nFileSizeLow::DWORD
    dwReserved0::DWORD
    dwReserved1::DWORD
    cFileName::NTuple{260, WCHAR}
    cAlternateFileName::NTuple{14, WCHAR}
end

const WIN32_FIND_DATAW = _WIN32_FIND_DATAW

const PWIN32_FIND_DATAW = Ptr{_WIN32_FIND_DATAW}

const LPWIN32_FIND_DATAW = Ptr{_WIN32_FIND_DATAW}

const WIN32_FIND_DATA = WIN32_FIND_DATAA

const PWIN32_FIND_DATA = PWIN32_FIND_DATAA

const LPWIN32_FIND_DATA = LPWIN32_FIND_DATAA

@cenum _FINDEX_INFO_LEVELS::UInt32 begin
    FindExInfoStandard = 0
    FindExInfoBasic = 1
    FindExInfoMaxInfoLevel = 2
end

const FINDEX_INFO_LEVELS = _FINDEX_INFO_LEVELS

@cenum _FINDEX_SEARCH_OPS::UInt32 begin
    FindExSearchNameMatch = 0
    FindExSearchLimitToDirectories = 1
    FindExSearchLimitToDevices = 2
    FindExSearchMaxSearchOp = 3
end

const FINDEX_SEARCH_OPS = _FINDEX_SEARCH_OPS

@cenum _GET_FILEEX_INFO_LEVELS::UInt32 begin
    GetFileExInfoStandard = 0
    GetFileExMaxInfoLevel = 1
end

const GET_FILEEX_INFO_LEVELS = _GET_FILEEX_INFO_LEVELS

const CRITICAL_SECTION = Cint

const PCRITICAL_SECTION = Cint

const LPCRITICAL_SECTION = Cint

const CRITICAL_SECTION_DEBUG = Cint

const PCRITICAL_SECTION_DEBUG = Cint

const LPCRITICAL_SECTION_DEBUG = Cint

# typedef VOID ( WINAPI * LPOVERLAPPED_COMPLETION_ROUTINE ) ( _In_ DWORD dwErrorCode , _In_ DWORD dwNumberOfBytesTransfered , _Inout_ LPOVERLAPPED lpOverlapped )
const LPOVERLAPPED_COMPLETION_ROUTINE = Ptr{Cvoid}

struct _PROCESS_HEAP_ENTRY
    data::NTuple{40, UInt8}
end

function Base.getproperty(x::Ptr{_PROCESS_HEAP_ENTRY}, f::Symbol)
    f === :lpData && return Ptr{PVOID}(x + 0)
    f === :cbData && return Ptr{DWORD}(x + 8)
    f === :cbOverhead && return Ptr{BYTE}(x + 12)
    f === :iRegionIndex && return Ptr{BYTE}(x + 13)
    f === :wFlags && return Ptr{WORD}(x + 14)
    f === :Block && return Ptr{Cvoid}(x + 16)
    f === :Region && return Ptr{Cvoid}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_PROCESS_HEAP_ENTRY, f::Symbol)
    r = Ref{_PROCESS_HEAP_ENTRY}(x)
    ptr = Base.unsafe_convert(Ptr{_PROCESS_HEAP_ENTRY}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_PROCESS_HEAP_ENTRY}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _PROCESS_HEAP_ENTRY(lpData::PVOID, cbData::DWORD, cbOverhead::BYTE, iRegionIndex::BYTE, wFlags::WORD)
    ref = Ref{_PROCESS_HEAP_ENTRY}()
    ptr = Base.unsafe_convert(Ptr{_PROCESS_HEAP_ENTRY}, ref)
    ptr.lpData = lpData
    ptr.cbData = cbData
    ptr.cbOverhead = cbOverhead
    ptr.iRegionIndex = iRegionIndex
    ptr.wFlags = wFlags
    ref[]
end

const PROCESS_HEAP_ENTRY = _PROCESS_HEAP_ENTRY

const LPPROCESS_HEAP_ENTRY = Ptr{_PROCESS_HEAP_ENTRY}

const PPROCESS_HEAP_ENTRY = Ptr{_PROCESS_HEAP_ENTRY}

struct __JL_Ctag_66
    LocalizedReasonModule::HMODULE
    LocalizedReasonId::ULONG
    ReasonStringCount::ULONG
    ReasonStrings::Ptr{LPWSTR}
end
function Base.getproperty(x::Ptr{__JL_Ctag_66}, f::Symbol)
    f === :LocalizedReasonModule && return Ptr{HMODULE}(x + 0)
    f === :LocalizedReasonId && return Ptr{ULONG}(x + 8)
    f === :ReasonStringCount && return Ptr{ULONG}(x + 12)
    f === :ReasonStrings && return Ptr{Ptr{LPWSTR}}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_66, f::Symbol)
    r = Ref{__JL_Ctag_66}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_66}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_66}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


struct __JL_Ctag_65
    data::NTuple{24, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_65}, f::Symbol)
    f === :Detailed && return Ptr{__JL_Ctag_66}(x + 0)
    f === :SimpleReasonString && return Ptr{LPWSTR}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_65, f::Symbol)
    r = Ref{__JL_Ctag_65}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_65}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_65}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_65 = Union{__JL_Ctag_66, LPWSTR}

function __JL_Ctag_65(val::__U___JL_Ctag_65)
    ref = Ref{__JL_Ctag_65}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_65}, ref)
    if val isa __JL_Ctag_66
        ptr.Detailed = val
    elseif val isa LPWSTR
        ptr.SimpleReasonString = val
    end
    ref[]
end

struct _REASON_CONTEXT
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{_REASON_CONTEXT}, f::Symbol)
    f === :Version && return Ptr{ULONG}(x + 0)
    f === :Flags && return Ptr{DWORD}(x + 4)
    f === :Reason && return Ptr{__JL_Ctag_65}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::_REASON_CONTEXT, f::Symbol)
    r = Ref{_REASON_CONTEXT}(x)
    ptr = Base.unsafe_convert(Ptr{_REASON_CONTEXT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_REASON_CONTEXT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _REASON_CONTEXT(Version::ULONG, Flags::DWORD, Reason::__JL_Ctag_65)
    ref = Ref{_REASON_CONTEXT}()
    ptr = Base.unsafe_convert(Ptr{_REASON_CONTEXT}, ref)
    ptr.Version = Version
    ptr.Flags = Flags
    ptr.Reason = Reason
    ref[]
end

const REASON_CONTEXT = _REASON_CONTEXT

const PREASON_CONTEXT = Ptr{_REASON_CONTEXT}

# typedef DWORD ( WINAPI * PTHREAD_START_ROUTINE ) ( LPVOID lpThreadParameter )
const PTHREAD_START_ROUTINE = Ptr{Cvoid}

const LPTHREAD_START_ROUTINE = PTHREAD_START_ROUTINE

# typedef LPVOID ( WINAPI * PENCLAVE_ROUTINE ) ( LPVOID lpThreadParameter )
const PENCLAVE_ROUTINE = Ptr{Cvoid}

const LPENCLAVE_ROUTINE = PENCLAVE_ROUTINE

struct _EXCEPTION_DEBUG_INFO
    ExceptionRecord::EXCEPTION_RECORD
    dwFirstChance::DWORD
end

const EXCEPTION_DEBUG_INFO = _EXCEPTION_DEBUG_INFO

const LPEXCEPTION_DEBUG_INFO = Ptr{_EXCEPTION_DEBUG_INFO}

struct _CREATE_THREAD_DEBUG_INFO
    hThread::HANDLE
    lpThreadLocalBase::LPVOID
    lpStartAddress::LPTHREAD_START_ROUTINE
end

const CREATE_THREAD_DEBUG_INFO = _CREATE_THREAD_DEBUG_INFO

const LPCREATE_THREAD_DEBUG_INFO = Ptr{_CREATE_THREAD_DEBUG_INFO}

struct _CREATE_PROCESS_DEBUG_INFO
    hFile::HANDLE
    hProcess::HANDLE
    hThread::HANDLE
    lpBaseOfImage::LPVOID
    dwDebugInfoFileOffset::DWORD
    nDebugInfoSize::DWORD
    lpThreadLocalBase::LPVOID
    lpStartAddress::LPTHREAD_START_ROUTINE
    lpImageName::LPVOID
    fUnicode::WORD
end

const CREATE_PROCESS_DEBUG_INFO = _CREATE_PROCESS_DEBUG_INFO

const LPCREATE_PROCESS_DEBUG_INFO = Ptr{_CREATE_PROCESS_DEBUG_INFO}

struct _EXIT_THREAD_DEBUG_INFO
    dwExitCode::DWORD
end

const EXIT_THREAD_DEBUG_INFO = _EXIT_THREAD_DEBUG_INFO

const LPEXIT_THREAD_DEBUG_INFO = Ptr{_EXIT_THREAD_DEBUG_INFO}

struct _EXIT_PROCESS_DEBUG_INFO
    dwExitCode::DWORD
end

const EXIT_PROCESS_DEBUG_INFO = _EXIT_PROCESS_DEBUG_INFO

const LPEXIT_PROCESS_DEBUG_INFO = Ptr{_EXIT_PROCESS_DEBUG_INFO}

struct _LOAD_DLL_DEBUG_INFO
    hFile::HANDLE
    lpBaseOfDll::LPVOID
    dwDebugInfoFileOffset::DWORD
    nDebugInfoSize::DWORD
    lpImageName::LPVOID
    fUnicode::WORD
end

const LOAD_DLL_DEBUG_INFO = _LOAD_DLL_DEBUG_INFO

const LPLOAD_DLL_DEBUG_INFO = Ptr{_LOAD_DLL_DEBUG_INFO}

struct _UNLOAD_DLL_DEBUG_INFO
    lpBaseOfDll::LPVOID
end

const UNLOAD_DLL_DEBUG_INFO = _UNLOAD_DLL_DEBUG_INFO

const LPUNLOAD_DLL_DEBUG_INFO = Ptr{_UNLOAD_DLL_DEBUG_INFO}

struct _OUTPUT_DEBUG_STRING_INFO
    lpDebugStringData::LPSTR
    fUnicode::WORD
    nDebugStringLength::WORD
end

const OUTPUT_DEBUG_STRING_INFO = _OUTPUT_DEBUG_STRING_INFO

const LPOUTPUT_DEBUG_STRING_INFO = Ptr{_OUTPUT_DEBUG_STRING_INFO}

struct _RIP_INFO
    dwError::DWORD
    dwType::DWORD
end

const RIP_INFO = _RIP_INFO

const LPRIP_INFO = Ptr{_RIP_INFO}

struct __JL_Ctag_51
    data::NTuple{160, UInt8}
end

function Base.getproperty(x::Ptr{__JL_Ctag_51}, f::Symbol)
    f === :Exception && return Ptr{EXCEPTION_DEBUG_INFO}(x + 0)
    f === :CreateThread && return Ptr{CREATE_THREAD_DEBUG_INFO}(x + 0)
    f === :CreateProcessInfo && return Ptr{CREATE_PROCESS_DEBUG_INFO}(x + 0)
    f === :ExitThread && return Ptr{EXIT_THREAD_DEBUG_INFO}(x + 0)
    f === :ExitProcess && return Ptr{EXIT_PROCESS_DEBUG_INFO}(x + 0)
    f === :LoadDll && return Ptr{LOAD_DLL_DEBUG_INFO}(x + 0)
    f === :UnloadDll && return Ptr{UNLOAD_DLL_DEBUG_INFO}(x + 0)
    f === :DebugString && return Ptr{OUTPUT_DEBUG_STRING_INFO}(x + 0)
    f === :RipInfo && return Ptr{RIP_INFO}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_51, f::Symbol)
    r = Ref{__JL_Ctag_51}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_51}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_51}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

const __U___JL_Ctag_51 = Union{EXCEPTION_DEBUG_INFO, CREATE_THREAD_DEBUG_INFO, CREATE_PROCESS_DEBUG_INFO, EXIT_THREAD_DEBUG_INFO, EXIT_PROCESS_DEBUG_INFO, LOAD_DLL_DEBUG_INFO, UNLOAD_DLL_DEBUG_INFO, OUTPUT_DEBUG_STRING_INFO, RIP_INFO}

function __JL_Ctag_51(val::__U___JL_Ctag_51)
    ref = Ref{__JL_Ctag_51}()
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_51}, ref)
    if val isa EXCEPTION_DEBUG_INFO
        ptr.Exception = val
    elseif val isa CREATE_THREAD_DEBUG_INFO
        ptr.CreateThread = val
    elseif val isa CREATE_PROCESS_DEBUG_INFO
        ptr.CreateProcessInfo = val
    elseif val isa EXIT_THREAD_DEBUG_INFO
        ptr.ExitThread = val
    elseif val isa EXIT_PROCESS_DEBUG_INFO
        ptr.ExitProcess = val
    elseif val isa LOAD_DLL_DEBUG_INFO
        ptr.LoadDll = val
    elseif val isa UNLOAD_DLL_DEBUG_INFO
        ptr.UnloadDll = val
    elseif val isa OUTPUT_DEBUG_STRING_INFO
        ptr.DebugString = val
    elseif val isa RIP_INFO
        ptr.RipInfo = val
    end
    ref[]
end

struct _DEBUG_EVENT
    data::NTuple{176, UInt8}
end

function Base.getproperty(x::Ptr{_DEBUG_EVENT}, f::Symbol)
    f === :dwDebugEventCode && return Ptr{DWORD}(x + 0)
    f === :dwProcessId && return Ptr{DWORD}(x + 4)
    f === :dwThreadId && return Ptr{DWORD}(x + 8)
    f === :u && return Ptr{__JL_Ctag_51}(x + 16)
    return getfield(x, f)
end

function Base.getproperty(x::_DEBUG_EVENT, f::Symbol)
    r = Ref{_DEBUG_EVENT}(x)
    ptr = Base.unsafe_convert(Ptr{_DEBUG_EVENT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{_DEBUG_EVENT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function _DEBUG_EVENT(dwDebugEventCode::DWORD, dwProcessId::DWORD, dwThreadId::DWORD, u::__JL_Ctag_51)
    ref = Ref{_DEBUG_EVENT}()
    ptr = Base.unsafe_convert(Ptr{_DEBUG_EVENT}, ref)
    ptr.dwDebugEventCode = dwDebugEventCode
    ptr.dwProcessId = dwProcessId
    ptr.dwThreadId = dwThreadId
    ptr.u = u
    ref[]
end

const DEBUG_EVENT = _DEBUG_EVENT

const LPDEBUG_EVENT = Ptr{_DEBUG_EVENT}

const LPCONTEXT = Cint

struct tagENUMUILANG
    NumOfEnumUILang::ULONG
    SizeOfEnumUIBuffer::ULONG
    pEnumUIBuffer::Ptr{LANGID}
end

const ENUMUILANG = tagENUMUILANG

const PENUMUILANG = Ptr{tagENUMUILANG}

# typedef BOOL ( CALLBACK * ENUMRESLANGPROCW ) ( _In_opt_ HMODULE hModule , _In_ LPCWSTR lpType , _In_ LPCWSTR lpName , _In_ WORD wLanguage , _In_ LONG_PTR lParam )
const ENUMRESLANGPROCW = Ptr{Cvoid}

# typedef BOOL ( CALLBACK * ENUMRESNAMEPROCW ) ( _In_opt_ HMODULE hModule , _In_ LPCWSTR lpType , _In_ LPWSTR lpName , _In_ LONG_PTR lParam )
const ENUMRESNAMEPROCW = Ptr{Cvoid}

# typedef BOOL ( CALLBACK * ENUMRESTYPEPROCW ) ( _In_opt_ HMODULE hModule , _In_ LPWSTR lpType , _In_ LONG_PTR lParam )
const ENUMRESTYPEPROCW = Ptr{Cvoid}

function DisableThreadLibraryCalls(hLibModule)
    @ccall user32.DisableThreadLibraryCalls(hLibModule::HMODULE)::BOOL
end

function FindResourceExW(hModule, lpType, lpName, wLanguage)
    @ccall user32.FindResourceExW(hModule::HMODULE, lpType::LPCWSTR, lpName::LPCWSTR, wLanguage::WORD)::HRSRC
end

function FreeLibrary(hLibModule)
    @ccall user32.FreeLibrary(hLibModule::HMODULE)::BOOL
end

function FreeLibraryAndExitThread(hLibModule, dwExitCode)
    @ccall user32.FreeLibraryAndExitThread(hLibModule::HMODULE, dwExitCode::DWORD)::Cvoid
end

function FreeResource(hResData)
    @ccall user32.FreeResource(hResData::HGLOBAL)::BOOL
end

function GetModuleFileNameW(hModule, lpFilename, nSize)
    @ccall user32.GetModuleFileNameW(hModule::HMODULE, lpFilename::LPWSTR, nSize::DWORD)::DWORD
end

function GetModuleHandleW(lpModuleName)
    @ccall user32.GetModuleHandleW(lpModuleName::LPCWSTR)::HMODULE
end

# typedef BOOL ( WINAPI * PGET_MODULE_HANDLE_EXW ) ( _In_ DWORD dwFlags , _In_opt_ LPCWSTR lpModuleName , _Outptr_ HMODULE * phModule )
const PGET_MODULE_HANDLE_EXW = Ptr{Cvoid}

function GetModuleHandleExW(dwFlags, lpModuleName, phModule)
    @ccall user32.GetModuleHandleExW(dwFlags::DWORD, lpModuleName::LPCWSTR, phModule::Ptr{HMODULE})::BOOL
end

function GetProcAddress(hModule, lpProcName)
    @ccall user32.GetProcAddress(hModule::HMODULE, lpProcName::LPCSTR)::FARPROC
end

struct _REDIRECTION_FUNCTION_DESCRIPTOR
    DllName::PCSTR
    FunctionName::PCSTR
    RedirectionTarget::PVOID
end

const REDIRECTION_FUNCTION_DESCRIPTOR = _REDIRECTION_FUNCTION_DESCRIPTOR

const PREDIRECTION_FUNCTION_DESCRIPTOR = Ptr{_REDIRECTION_FUNCTION_DESCRIPTOR}

const PCREDIRECTION_FUNCTION_DESCRIPTOR = Ptr{REDIRECTION_FUNCTION_DESCRIPTOR}

struct _REDIRECTION_DESCRIPTOR
    Version::ULONG
    FunctionCount::ULONG
    Redirections::PCREDIRECTION_FUNCTION_DESCRIPTOR
end

const REDIRECTION_DESCRIPTOR = _REDIRECTION_DESCRIPTOR

const PREDIRECTION_DESCRIPTOR = Ptr{_REDIRECTION_DESCRIPTOR}

const PCREDIRECTION_DESCRIPTOR = Ptr{REDIRECTION_DESCRIPTOR}

function LoadLibraryExW(lpLibFileName, hFile, dwFlags)
    @ccall user32.LoadLibraryExW(lpLibFileName::LPCWSTR, hFile::HANDLE, dwFlags::DWORD)::HMODULE
end

function LoadResource(hModule, hResInfo)
    @ccall user32.LoadResource(hModule::HMODULE, hResInfo::HRSRC)::HGLOBAL
end

function LoadStringW(hInstance, uID, lpBuffer, cchBufferMax)
    @ccall user32.LoadStringW(hInstance::HINSTANCE, uID::UINT, lpBuffer::LPWSTR, cchBufferMax::Cint)::Cint
end

function LockResource(hResData)
    @ccall user32.LockResource(hResData::HGLOBAL)::LPVOID
end

function SizeofResource(hModule, hResInfo)
    @ccall user32.SizeofResource(hModule::HMODULE, hResInfo::HRSRC)::DWORD
end

const DLL_DIRECTORY_COOKIE = PVOID

const PDLL_DIRECTORY_COOKIE = Ptr{PVOID}

function AddDllDirectory(NewDirectory)
    @ccall user32.AddDllDirectory(NewDirectory::PCWSTR)::DLL_DIRECTORY_COOKIE
end

function RemoveDllDirectory(Cookie)
    @ccall user32.RemoveDllDirectory(Cookie::DLL_DIRECTORY_COOKIE)::BOOL
end

function SetDefaultDllDirectories(DirectoryFlags)
    @ccall user32.SetDefaultDllDirectories(DirectoryFlags::DWORD)::BOOL
end

function FindResourceW(hModule, lpName, lpType)
    @ccall user32.FindResourceW(hModule::HMODULE, lpName::LPCWSTR, lpType::LPCWSTR)::HRSRC
end

function LoadLibraryW(lpLibFileName)
    @ccall user32.LoadLibraryW(lpLibFileName::LPCWSTR)::HMODULE
end

function EnumResourceNamesW(hModule, lpType, lpEnumFunc, lParam)
    @ccall user32.EnumResourceNamesW(hModule::HMODULE, lpType::LPCWSTR, lpEnumFunc::ENUMRESNAMEPROCW, lParam::LONG_PTR)::BOOL
end

const HDWP = HANDLE

const MENUTEMPLATEW = Cvoid

const MENUTEMPLATE = MENUTEMPLATEA

const LPMENUTEMPLATEA = PVOID

const LPMENUTEMPLATEW = PVOID

const LPMENUTEMPLATE = LPMENUTEMPLATEA

# typedef int ( CALLBACK * EDITWORDBREAKPROCA ) ( LPSTR lpch , int ichCurrent , int cch , int code )
const EDITWORDBREAKPROCA = Ptr{Cvoid}

# typedef int ( CALLBACK * EDITWORDBREAKPROCW ) ( LPWSTR lpch , int ichCurrent , int cch , int code )
const EDITWORDBREAKPROCW = Ptr{Cvoid}

const PROPENUMPROC = PROPENUMPROCA

const PROPENUMPROCEX = PROPENUMPROCEXA

const EDITWORDBREAKPROC = EDITWORDBREAKPROCA

# typedef BOOL ( CALLBACK * NAMEENUMPROCW ) ( LPWSTR , LPARAM )
const NAMEENUMPROCW = Ptr{Cvoid}

const WINSTAENUMPROCW = NAMEENUMPROCW

const DESKTOPENUMPROCW = NAMEENUMPROCW

const WINSTAENUMPROC = WINSTAENUMPROCA

const DESKTOPENUMPROC = DESKTOPENUMPROCA

struct tagCREATESTRUCTA
    lpCreateParams::LPVOID
    hInstance::HINSTANCE
    hMenu::Cint
    hwndParent::Cint
    cy::Cint
    cx::Cint
    y::Cint
    x::Cint
    style::LONG
    lpszName::LPCSTR
    lpszClass::LPCSTR
    dwExStyle::DWORD
end

struct tagCBT_CREATEWNDA
    lpcs::Ptr{tagCREATESTRUCTA}
    hwndInsertAfter::Cint
end

const CBT_CREATEWNDA = tagCBT_CREATEWNDA

const LPCBT_CREATEWNDA = Ptr{tagCBT_CREATEWNDA}

struct tagCREATESTRUCTW
    lpCreateParams::LPVOID
    hInstance::HINSTANCE
    hMenu::Cint
    hwndParent::Cint
    cy::Cint
    cx::Cint
    y::Cint
    x::Cint
    style::LONG
    lpszName::LPCWSTR
    lpszClass::LPCWSTR
    dwExStyle::DWORD
end

struct tagCBT_CREATEWNDW
    lpcs::Ptr{tagCREATESTRUCTW}
    hwndInsertAfter::Cint
end

const CBT_CREATEWNDW = tagCBT_CREATEWNDW

const LPCBT_CREATEWNDW = Ptr{tagCBT_CREATEWNDW}

const CBT_CREATEWND = CBT_CREATEWNDA

const LPCBT_CREATEWND = LPCBT_CREATEWNDA

struct tagCBTACTIVATESTRUCT
    fMouse::BOOL
    hWndActive::Cint
end

const CBTACTIVATESTRUCT = tagCBTACTIVATESTRUCT

const LPCBTACTIVATESTRUCT = Ptr{tagCBTACTIVATESTRUCT}

struct tagWTSSESSION_NOTIFICATION
    cbSize::DWORD
    dwSessionId::DWORD
end

const WTSSESSION_NOTIFICATION = tagWTSSESSION_NOTIFICATION

const PWTSSESSION_NOTIFICATION = Ptr{tagWTSSESSION_NOTIFICATION}

struct __JL_Ctag_38
    hwnd::Cint
    rc::Cint
end
function Base.getproperty(x::Ptr{__JL_Ctag_38}, f::Symbol)
    f === :hwnd && return Ptr{Cint}(x + 0)
    f === :rc && return Ptr{Cint}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_38, f::Symbol)
    r = Ref{__JL_Ctag_38}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_38}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_38}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const SHELLHOOKINFO = __JL_Ctag_38

const LPSHELLHOOKINFO = Ptr{__JL_Ctag_38}

struct tagEVENTMSG
    message::UINT
    paramL::UINT
    paramH::UINT
    time::DWORD
    hwnd::Cint
end

const EVENTMSG = tagEVENTMSG

const PEVENTMSGMSG = Ptr{tagEVENTMSG}

const NPEVENTMSGMSG = Ptr{tagEVENTMSG}

const LPEVENTMSGMSG = Ptr{tagEVENTMSG}

const PEVENTMSG = Ptr{tagEVENTMSG}

const NPEVENTMSG = Ptr{tagEVENTMSG}

const LPEVENTMSG = Ptr{tagEVENTMSG}

struct tagCWPSTRUCT
    lParam::LPARAM
    wParam::WPARAM
    message::UINT
    hwnd::Cint
end

const CWPSTRUCT = tagCWPSTRUCT

const PCWPSTRUCT = Ptr{tagCWPSTRUCT}

const NPCWPSTRUCT = Ptr{tagCWPSTRUCT}

const LPCWPSTRUCT = Ptr{tagCWPSTRUCT}

struct tagCWPRETSTRUCT
    lResult::LRESULT
    lParam::LPARAM
    wParam::WPARAM
    message::UINT
    hwnd::Cint
end

const CWPRETSTRUCT = tagCWPRETSTRUCT

const PCWPRETSTRUCT = Ptr{tagCWPRETSTRUCT}

const NPCWPRETSTRUCT = Ptr{tagCWPRETSTRUCT}

const LPCWPRETSTRUCT = Ptr{tagCWPRETSTRUCT}

struct tagKBDLLHOOKSTRUCT
    vkCode::DWORD
    scanCode::DWORD
    flags::DWORD
    time::DWORD
    dwExtraInfo::ULONG_PTR
end

const KBDLLHOOKSTRUCT = tagKBDLLHOOKSTRUCT

const LPKBDLLHOOKSTRUCT = Ptr{tagKBDLLHOOKSTRUCT}

const PKBDLLHOOKSTRUCT = Ptr{tagKBDLLHOOKSTRUCT}

struct tagMSLLHOOKSTRUCT
    pt::Cint
    mouseData::DWORD
    flags::DWORD
    time::DWORD
    dwExtraInfo::ULONG_PTR
end

const MSLLHOOKSTRUCT = tagMSLLHOOKSTRUCT

const LPMSLLHOOKSTRUCT = Ptr{tagMSLLHOOKSTRUCT}

const PMSLLHOOKSTRUCT = Ptr{tagMSLLHOOKSTRUCT}

struct tagDEBUGHOOKINFO
    idThread::DWORD
    idThreadInstaller::DWORD
    lParam::LPARAM
    wParam::WPARAM
    code::Cint
end

const DEBUGHOOKINFO = tagDEBUGHOOKINFO

const PDEBUGHOOKINFO = Ptr{tagDEBUGHOOKINFO}

const NPDEBUGHOOKINFO = Ptr{tagDEBUGHOOKINFO}

const LPDEBUGHOOKINFO = Ptr{tagDEBUGHOOKINFO}

struct tagMOUSEHOOKSTRUCT
    pt::Cint
    hwnd::Cint
    wHitTestCode::UINT
    dwExtraInfo::ULONG_PTR
end

const MOUSEHOOKSTRUCT = tagMOUSEHOOKSTRUCT

const LPMOUSEHOOKSTRUCT = Ptr{tagMOUSEHOOKSTRUCT}

const PMOUSEHOOKSTRUCT = Ptr{tagMOUSEHOOKSTRUCT}

struct tagMOUSEHOOKSTRUCTEX
    mouseData::DWORD
end

const MOUSEHOOKSTRUCTEX = tagMOUSEHOOKSTRUCTEX

const LPMOUSEHOOKSTRUCTEX = Ptr{tagMOUSEHOOKSTRUCTEX}

const PMOUSEHOOKSTRUCTEX = Ptr{tagMOUSEHOOKSTRUCTEX}

struct tagHARDWAREHOOKSTRUCT
    hwnd::Cint
    message::UINT
    wParam::WPARAM
    lParam::LPARAM
end

const HARDWAREHOOKSTRUCT = tagHARDWAREHOOKSTRUCT

const LPHARDWAREHOOKSTRUCT = Ptr{tagHARDWAREHOOKSTRUCT}

const PHARDWAREHOOKSTRUCT = Ptr{tagHARDWAREHOOKSTRUCT}

function LoadKeyboardLayoutW(pwszKLID, Flags)
    @ccall user32.LoadKeyboardLayoutW(pwszKLID::LPCWSTR, Flags::UINT)::HKL
end

function ActivateKeyboardLayout(hkl, Flags)
    @ccall user32.ActivateKeyboardLayout(hkl::HKL, Flags::UINT)::HKL
end

function ToUnicodeEx(wVirtKey, wScanCode, lpKeyState, pwszBuff, cchBuff, wFlags, dwhkl)
    @ccall user32.ToUnicodeEx(wVirtKey::UINT, wScanCode::UINT, lpKeyState::Ptr{BYTE}, pwszBuff::LPWSTR, cchBuff::Cint, wFlags::UINT, dwhkl::HKL)::Cint
end

function UnloadKeyboardLayout(hkl)
    @ccall user32.UnloadKeyboardLayout(hkl::HKL)::BOOL
end

function GetKeyboardLayoutNameW(pwszKLID)
    @ccall user32.GetKeyboardLayoutNameW(pwszKLID::LPWSTR)::BOOL
end

function GetKeyboardLayoutList(nBuff, lpList)
    @ccall user32.GetKeyboardLayoutList(nBuff::Cint, lpList::Ptr{HKL})::Cint
end

function GetKeyboardLayout(idThread)
    @ccall user32.GetKeyboardLayout(idThread::DWORD)::HKL
end

struct tagMOUSEMOVEPOINT
    x::Cint
    y::Cint
    time::DWORD
    dwExtraInfo::ULONG_PTR
end

const MOUSEMOVEPOINT = tagMOUSEMOVEPOINT

const PMOUSEMOVEPOINT = Ptr{tagMOUSEMOVEPOINT}

const LPMOUSEMOVEPOINT = Ptr{tagMOUSEMOVEPOINT}

function GetMouseMovePointsEx(cbSize, lppt, lpptBuf, nBufPoints, resolution)
    @ccall user32.GetMouseMovePointsEx(cbSize::UINT, lppt::LPMOUSEMOVEPOINT, lpptBuf::LPMOUSEMOVEPOINT, nBufPoints::Cint, resolution::DWORD)::Cint
end

function OpenDesktopW(lpszDesktop, dwFlags, fInherit, dwDesiredAccess)
    @ccall user32.OpenDesktopW(lpszDesktop::LPCWSTR, dwFlags::DWORD, fInherit::BOOL, dwDesiredAccess::ACCESS_MASK)::Cint
end

function OpenInputDesktop(dwFlags, fInherit, dwDesiredAccess)
    @ccall user32.OpenInputDesktop(dwFlags::DWORD, fInherit::BOOL, dwDesiredAccess::ACCESS_MASK)::Cint
end

function EnumDesktopsW(hwinsta, lpEnumFunc, lParam)
    @ccall user32.EnumDesktopsW(hwinsta::HWINSTA, lpEnumFunc::DESKTOPENUMPROCW, lParam::LPARAM)::BOOL
end

function EnumDesktopWindows(hDesktop, lpfn, lParam)
    @ccall user32.EnumDesktopWindows(hDesktop::Cint, lpfn::WNDENUMPROC, lParam::LPARAM)::BOOL
end

function SwitchDesktop(hDesktop)
    @ccall user32.SwitchDesktop(hDesktop::Cint)::BOOL
end

function SetThreadDesktop(hDesktop)
    @ccall user32.SetThreadDesktop(hDesktop::Cint)::BOOL
end

function CloseDesktop(hDesktop)
    @ccall user32.CloseDesktop(hDesktop::Cint)::BOOL
end

function GetThreadDesktop(dwThreadId)
    @ccall user32.GetThreadDesktop(dwThreadId::DWORD)::Cint
end

function CreateWindowStationW(lpwinsta, dwFlags, dwDesiredAccess, lpsa)
    @ccall user32.CreateWindowStationW(lpwinsta::LPCWSTR, dwFlags::DWORD, dwDesiredAccess::ACCESS_MASK, lpsa::LPSECURITY_ATTRIBUTES)::HWINSTA
end

function OpenWindowStationW(lpszWinSta, fInherit, dwDesiredAccess)
    @ccall user32.OpenWindowStationW(lpszWinSta::LPCWSTR, fInherit::BOOL, dwDesiredAccess::ACCESS_MASK)::HWINSTA
end

function EnumWindowStationsW(lpEnumFunc, lParam)
    @ccall user32.EnumWindowStationsW(lpEnumFunc::WINSTAENUMPROCW, lParam::LPARAM)::BOOL
end

function CloseWindowStation(hWinSta)
    @ccall user32.CloseWindowStation(hWinSta::HWINSTA)::BOOL
end

function SetProcessWindowStation(hWinSta)
    @ccall user32.SetProcessWindowStation(hWinSta::HWINSTA)::BOOL
end

function GetProcessWindowStation()
    @ccall user32.GetProcessWindowStation()::HWINSTA
end

function SetUserObjectSecurity(hObj, pSIRequested, pSID)
    @ccall user32.SetUserObjectSecurity(hObj::HANDLE, pSIRequested::PSECURITY_INFORMATION, pSID::PSECURITY_DESCRIPTOR)::BOOL
end

function GetUserObjectSecurity(hObj, pSIRequested, pSID, nLength, lpnLengthNeeded)
    @ccall user32.GetUserObjectSecurity(hObj::HANDLE, pSIRequested::PSECURITY_INFORMATION, pSID::PSECURITY_DESCRIPTOR, nLength::DWORD, lpnLengthNeeded::LPDWORD)::BOOL
end

struct tagUSEROBJECTFLAGS
    fInherit::BOOL
    fReserved::BOOL
    dwFlags::DWORD
end

const USEROBJECTFLAGS = tagUSEROBJECTFLAGS

const PUSEROBJECTFLAGS = Ptr{tagUSEROBJECTFLAGS}

function GetUserObjectInformationW(hObj, nIndex, pvInfo, nLength, lpnLengthNeeded)
    @ccall user32.GetUserObjectInformationW(hObj::HANDLE, nIndex::Cint, pvInfo::PVOID, nLength::DWORD, lpnLengthNeeded::LPDWORD)::BOOL
end

function SetUserObjectInformationW(hObj, nIndex, pvInfo, nLength)
    @ccall user32.SetUserObjectInformationW(hObj::HANDLE, nIndex::Cint, pvInfo::PVOID, nLength::DWORD)::BOOL
end

const PWNDCLASSEXA = Ptr{tagWNDCLASSEXA}

const NPWNDCLASSEXA = Ptr{tagWNDCLASSEXA}

struct tagWNDCLASSEXW
    cbSize::UINT
    style::UINT
    lpfnWndProc::WNDPROC
    cbClsExtra::Cint
    cbWndExtra::Cint
    hInstance::HINSTANCE
    hIcon::Cint
    hCursor::Cint
    hbrBackground::Cint
    lpszMenuName::LPCWSTR
    lpszClassName::LPCWSTR
    hIconSm::Cint
end

const WNDCLASSEXW = tagWNDCLASSEXW

const PWNDCLASSEXW = Ptr{tagWNDCLASSEXW}

const NPWNDCLASSEXW = Ptr{tagWNDCLASSEXW}

const LPWNDCLASSEXW = Ptr{tagWNDCLASSEXW}

const WNDCLASSEX = WNDCLASSEXA

const PWNDCLASSEX = PWNDCLASSEXA

const NPWNDCLASSEX = NPWNDCLASSEXA

const LPWNDCLASSEX = LPWNDCLASSEXA

const PWNDCLASSA = Ptr{tagWNDCLASSA}

const NPWNDCLASSA = Ptr{tagWNDCLASSA}

struct tagWNDCLASSW
    style::UINT
    lpfnWndProc::WNDPROC
    cbClsExtra::Cint
    cbWndExtra::Cint
    hInstance::HINSTANCE
    hIcon::Cint
    hCursor::Cint
    hbrBackground::Cint
    lpszMenuName::LPCWSTR
    lpszClassName::LPCWSTR
end

const WNDCLASSW = tagWNDCLASSW

const PWNDCLASSW = Ptr{tagWNDCLASSW}

const NPWNDCLASSW = Ptr{tagWNDCLASSW}

const LPWNDCLASSW = Ptr{tagWNDCLASSW}

const WNDCLASS = WNDCLASSA

const PWNDCLASS = PWNDCLASSA

const NPWNDCLASS = NPWNDCLASSA

const LPWNDCLASS = LPWNDCLASSA

function IsHungAppWindow(hwnd)
    @ccall user32.IsHungAppWindow(hwnd::Cint)::BOOL
end

const PMSG = Ptr{tagMSG}

const NPMSG = Ptr{tagMSG}

struct tagMINMAXINFO
    ptReserved::Cint
    ptMaxSize::Cint
    ptMaxPosition::Cint
    ptMinTrackSize::Cint
    ptMaxTrackSize::Cint
end

const MINMAXINFO = tagMINMAXINFO

const PMINMAXINFO = Ptr{tagMINMAXINFO}

const LPMINMAXINFO = Ptr{tagMINMAXINFO}

struct tagCOPYDATASTRUCT
    dwData::ULONG_PTR
    cbData::DWORD
    lpData::PVOID
end

const COPYDATASTRUCT = tagCOPYDATASTRUCT

const PCOPYDATASTRUCT = Ptr{tagCOPYDATASTRUCT}

struct tagMDINEXTMENU
    hmenuIn::Cint
    hmenuNext::Cint
    hwndNext::Cint
end

const MDINEXTMENU = tagMDINEXTMENU

const PMDINEXTMENU = Ptr{tagMDINEXTMENU}

const LPMDINEXTMENU = Ptr{tagMDINEXTMENU}

struct __JL_Ctag_39
    PowerSetting::GUID
    DataLength::DWORD
    Data::NTuple{1, UCHAR}
end
function Base.getproperty(x::Ptr{__JL_Ctag_39}, f::Symbol)
    f === :PowerSetting && return Ptr{GUID}(x + 0)
    f === :DataLength && return Ptr{DWORD}(x + 16)
    f === :Data && return Ptr{NTuple{1, UCHAR}}(x + 20)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_39, f::Symbol)
    r = Ref{__JL_Ctag_39}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_39}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_39}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const POWERBROADCAST_SETTING = __JL_Ctag_39

const PPOWERBROADCAST_SETTING = Ptr{__JL_Ctag_39}

function RegisterWindowMessageW(lpString)
    @ccall user32.RegisterWindowMessageW(lpString::LPCWSTR)::UINT
end

struct tagWINDOWPOS
    hwnd::Cint
    hwndInsertAfter::Cint
    x::Cint
    y::Cint
    cx::Cint
    cy::Cint
    flags::UINT
end

const WINDOWPOS = tagWINDOWPOS

const LPWINDOWPOS = Ptr{tagWINDOWPOS}

const PWINDOWPOS = Ptr{tagWINDOWPOS}

struct tagNCCALCSIZE_PARAMS
    rgrc::NTuple{3, Cint}
    lppos::PWINDOWPOS
end

const NCCALCSIZE_PARAMS = tagNCCALCSIZE_PARAMS

const LPNCCALCSIZE_PARAMS = Ptr{tagNCCALCSIZE_PARAMS}

struct tagTRACKMOUSEEVENT
    cbSize::DWORD
    dwFlags::DWORD
    hwndTrack::Cint
    dwHoverTime::DWORD
end

const TRACKMOUSEEVENT = tagTRACKMOUSEEVENT

const LPTRACKMOUSEEVENT = Ptr{tagTRACKMOUSEEVENT}

function TrackMouseEvent(lpEventTrack)
    @ccall user32.TrackMouseEvent(lpEventTrack::LPTRACKMOUSEEVENT)::BOOL
end

function DrawEdge(hdc, qrc, edge, grfFlags)
    @ccall user32.DrawEdge(hdc::Cint, qrc::Cint, edge::UINT, grfFlags::UINT)::BOOL
end

# no prototype is found for this function at winuser.h:3041:1, please use with caution
function DrawFrameControl()
    @ccall user32.DrawFrameControl()::BOOL
end

function DrawCaption(hwnd, hdc, lprect, flags)
    @ccall user32.DrawCaption(hwnd::Cint, hdc::Cint, lprect::Ptr{Cint}, flags::UINT)::BOOL
end

function DrawAnimatedRects(hwnd, idAni, lprcFrom, lprcTo)
    @ccall user32.DrawAnimatedRects(hwnd::Cint, idAni::Cint, lprcFrom::Ptr{Cint}, lprcTo::Ptr{Cint})::BOOL
end

const ACCEL = tagACCEL

struct tagPAINTSTRUCT
    hdc::Cint
    fErase::BOOL
    rcPaint::Cint
    fRestore::BOOL
    fIncUpdate::BOOL
    rgbReserved::NTuple{32, BYTE}
end

const PAINTSTRUCT = tagPAINTSTRUCT

const PPAINTSTRUCT = Ptr{tagPAINTSTRUCT}

const NPPAINTSTRUCT = Ptr{tagPAINTSTRUCT}

const LPPAINTSTRUCT = Ptr{tagPAINTSTRUCT}

const CREATESTRUCTA = tagCREATESTRUCTA

const LPCREATESTRUCTA = Ptr{tagCREATESTRUCTA}

const CREATESTRUCTW = tagCREATESTRUCTW

const LPCREATESTRUCTW = Ptr{tagCREATESTRUCTW}

const CREATESTRUCT = CREATESTRUCTA

const LPCREATESTRUCT = LPCREATESTRUCTA

struct tagWINDOWPLACEMENT
    length::UINT
    flags::UINT
    showCmd::UINT
    ptMinPosition::Cint
    ptMaxPosition::Cint
    rcNormalPosition::Cint
end

const WINDOWPLACEMENT = tagWINDOWPLACEMENT

const PWINDOWPLACEMENT = Ptr{WINDOWPLACEMENT}

const LPWINDOWPLACEMENT = Ptr{WINDOWPLACEMENT}

struct tagNMHDR
    hwndFrom::Cint
    idFrom::UINT_PTR
    code::UINT
end

const NMHDR = tagNMHDR

const LPNMHDR = Ptr{NMHDR}

struct tagSTYLESTRUCT
    styleOld::DWORD
    styleNew::DWORD
end

const STYLESTRUCT = tagSTYLESTRUCT

const LPSTYLESTRUCT = Ptr{tagSTYLESTRUCT}

struct tagMEASUREITEMSTRUCT
    CtlType::UINT
    CtlID::UINT
    itemID::UINT
    itemWidth::UINT
    itemHeight::UINT
    itemData::ULONG_PTR
end

const MEASUREITEMSTRUCT = tagMEASUREITEMSTRUCT

const PMEASUREITEMSTRUCT = Ptr{tagMEASUREITEMSTRUCT}

const LPMEASUREITEMSTRUCT = Ptr{tagMEASUREITEMSTRUCT}

struct tagDRAWITEMSTRUCT
    CtlType::UINT
    CtlID::UINT
    itemID::UINT
    itemAction::UINT
    itemState::UINT
    hwndItem::Cint
    hDC::Cint
    rcItem::Cint
    itemData::ULONG_PTR
end

const DRAWITEMSTRUCT = tagDRAWITEMSTRUCT

const PDRAWITEMSTRUCT = Ptr{tagDRAWITEMSTRUCT}

const LPDRAWITEMSTRUCT = Ptr{tagDRAWITEMSTRUCT}

struct tagDELETEITEMSTRUCT
    CtlType::UINT
    CtlID::UINT
    itemID::UINT
    hwndItem::Cint
    itemData::ULONG_PTR
end

const DELETEITEMSTRUCT = tagDELETEITEMSTRUCT

const PDELETEITEMSTRUCT = Ptr{tagDELETEITEMSTRUCT}

const LPDELETEITEMSTRUCT = Ptr{tagDELETEITEMSTRUCT}

struct tagCOMPAREITEMSTRUCT
    CtlType::UINT
    CtlID::UINT
    hwndItem::Cint
    itemID1::UINT
    itemData1::ULONG_PTR
    itemID2::UINT
    itemData2::ULONG_PTR
    dwLocaleId::DWORD
end

const COMPAREITEMSTRUCT = tagCOMPAREITEMSTRUCT

const PCOMPAREITEMSTRUCT = Ptr{tagCOMPAREITEMSTRUCT}

const LPCOMPAREITEMSTRUCT = Ptr{tagCOMPAREITEMSTRUCT}

function GetMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax)
    @ccall user32.GetMessageW(lpMsg::LPMSG, hWnd::Cint, wMsgFilterMin::UINT, wMsgFilterMax::UINT)::BOOL
end

function TranslateMessage(lpMsg)
    @ccall user32.TranslateMessage(lpMsg::Ptr{MSG})::BOOL
end

function DispatchMessageW(lpMsg)
    @ccall user32.DispatchMessageW(lpMsg::Ptr{MSG})::LRESULT
end

function SetMessageQueue(cMessagesMax)
    @ccall user32.SetMessageQueue(cMessagesMax::Cint)::BOOL
end

function PeekMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg)
    @ccall user32.PeekMessageW(lpMsg::LPMSG, hWnd::Cint, wMsgFilterMin::UINT, wMsgFilterMax::UINT, wRemoveMsg::UINT)::BOOL
end

function RegisterHotKey(hWnd, id, fsModifiers, vk)
    @ccall user32.RegisterHotKey(hWnd::Cint, id::Cint, fsModifiers::UINT, vk::UINT)::BOOL
end

function UnregisterHotKey(hWnd, id)
    @ccall user32.UnregisterHotKey(hWnd::Cint, id::Cint)::BOOL
end

function SwapMouseButton(fSwap)
    @ccall user32.SwapMouseButton(fSwap::BOOL)::BOOL
end

function GetMessagePos()
    @ccall user32.GetMessagePos()::DWORD
end

function GetMessageTime()
    @ccall user32.GetMessageTime()::LONG
end

function GetMessageExtraInfo()
    @ccall user32.GetMessageExtraInfo()::LPARAM
end

function IsWow64Message()
    @ccall user32.IsWow64Message()::BOOL
end

function SetMessageExtraInfo(lParam)
    @ccall user32.SetMessageExtraInfo(lParam::LPARAM)::LPARAM
end

function SendMessageW(hWnd, Msg, _Post_valid_)
    @ccall user32.SendMessageW(hWnd::Cint, Msg::UINT, _Post_valid_::Cint)::LRESULT
end

function SendMessageTimeoutW(hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult)
    @ccall user32.SendMessageTimeoutW(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM, fuFlags::UINT, uTimeout::UINT, lpdwResult::PDWORD_PTR)::LRESULT
end

function SendNotifyMessageW(hWnd, Msg, wParam, lParam)
    @ccall user32.SendNotifyMessageW(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::BOOL
end

function SendMessageCallbackW(hWnd, Msg, wParam, lParam, lpResultCallBack, dwData)
    @ccall user32.SendMessageCallbackW(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM, lpResultCallBack::SENDASYNCPROC, dwData::ULONG_PTR)::BOOL
end

const BSMINFO = __JL_Ctag_40

function BroadcastSystemMessageExW(flags, lpInfo, Msg, wParam, lParam, pbsmInfo)
    @ccall user32.BroadcastSystemMessageExW(flags::DWORD, lpInfo::LPDWORD, Msg::UINT, wParam::WPARAM, lParam::LPARAM, pbsmInfo::PBSMINFO)::Clong
end

function BroadcastSystemMessageW(flags, lpInfo, Msg, wParam, lParam)
    @ccall user32.BroadcastSystemMessageW(flags::DWORD, lpInfo::LPDWORD, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::Clong
end

const PHDEVNOTIFY = Ptr{HDEVNOTIFY}

function RegisterDeviceNotificationW(hRecipient, NotificationFilter, Flags)
    @ccall user32.RegisterDeviceNotificationW(hRecipient::HANDLE, NotificationFilter::LPVOID, Flags::DWORD)::HDEVNOTIFY
end

function UnregisterDeviceNotification(Handle)
    @ccall user32.UnregisterDeviceNotification(Handle::HDEVNOTIFY)::BOOL
end

const HPOWERNOTIFY = PVOID

const PHPOWERNOTIFY = Ptr{HPOWERNOTIFY}

function RegisterPowerSettingNotification(hRecipient, PowerSettingGuid, Flags)
    @ccall user32.RegisterPowerSettingNotification(hRecipient::HANDLE, PowerSettingGuid::LPCGUID, Flags::DWORD)::HPOWERNOTIFY
end

function UnregisterPowerSettingNotification(Handle)
    @ccall user32.UnregisterPowerSettingNotification(Handle::HPOWERNOTIFY)::BOOL
end

function RegisterSuspendResumeNotification(hRecipient, Flags)
    @ccall user32.RegisterSuspendResumeNotification(hRecipient::HANDLE, Flags::DWORD)::HPOWERNOTIFY
end

function UnregisterSuspendResumeNotification(Handle)
    @ccall user32.UnregisterSuspendResumeNotification(Handle::HPOWERNOTIFY)::BOOL
end

function PostMessageW(hWnd, Msg, wParam, lParam)
    @ccall user32.PostMessageW(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::BOOL
end

function AttachThreadInput(idAttach, idAttachTo, fAttach)
    @ccall user32.AttachThreadInput(idAttach::DWORD, idAttachTo::DWORD, fAttach::BOOL)::BOOL
end

function ReplyMessage(lResult)
    @ccall user32.ReplyMessage(lResult::LRESULT)::BOOL
end

function WaitMessage()
    @ccall user32.WaitMessage()::BOOL
end

function WaitForInputIdle(hProcess, dwMilliseconds)
    @ccall user32.WaitForInputIdle(hProcess::HANDLE, dwMilliseconds::DWORD)::DWORD
end

function DefWindowProcW(hWnd, Msg, wParam, lParam)
    @ccall user32.DefWindowProcW(hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function PostQuitMessage(nExitCode)
    @ccall user32.PostQuitMessage(nExitCode::Cint)::Cvoid
end

function CallWindowProcW(lpPrevWndFunc, hWnd, Msg, wParam, lParam)
    @ccall user32.CallWindowProcW(lpPrevWndFunc::WNDPROC, hWnd::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function InSendMessage()
    @ccall user32.InSendMessage()::BOOL
end

function InSendMessageEx(lpReserved)
    @ccall user32.InSendMessageEx(lpReserved::LPVOID)::DWORD
end

function GetDoubleClickTime()
    @ccall user32.GetDoubleClickTime()::UINT
end

function SetDoubleClickTime(arg1)
    @ccall user32.SetDoubleClickTime(arg1::UINT)::BOOL
end

function RegisterClassW(lpWndClass)
    @ccall user32.RegisterClassW(lpWndClass::Ptr{WNDCLASSW})::ATOM
end

function UnregisterClassW(lpClassName, hInstance)
    @ccall user32.UnregisterClassW(lpClassName::LPCWSTR, hInstance::HINSTANCE)::BOOL
end

function GetClassInfoW(hInstance, lpClassName, lpWndClass)
    @ccall user32.GetClassInfoW(hInstance::HINSTANCE, lpClassName::LPCWSTR, lpWndClass::LPWNDCLASSW)::BOOL
end

function RegisterClassExW(arg1)
    @ccall user32.RegisterClassExW(arg1::Ptr{WNDCLASSEXW})::ATOM
end

function GetClassInfoExW(hInstance, lpszClass, lpwcx)
    @ccall user32.GetClassInfoExW(hInstance::HINSTANCE, lpszClass::LPCWSTR, lpwcx::LPWNDCLASSEXW)::BOOL
end

# typedef BOOLEAN ( WINAPI * PREGISTERCLASSNAMEW ) ( LPCWSTR )
const PREGISTERCLASSNAMEW = Ptr{Cvoid}

function IsWindow(hWnd)
    @ccall user32.IsWindow(hWnd::Cint)::BOOL
end

function IsMenu(hMenu)
    @ccall user32.IsMenu(hMenu::Cint)::BOOL
end

function IsChild(hWndParent, hWnd)
    @ccall user32.IsChild(hWndParent::Cint, hWnd::Cint)::BOOL
end

function DestroyWindow(hWnd)
    @ccall user32.DestroyWindow(hWnd::Cint)::BOOL
end

function ShowWindow(hWnd, nCmdShow)
    @ccall user32.ShowWindow(hWnd::Cint, nCmdShow::Cint)::BOOL
end

function AnimateWindow(hWnd, dwTime, dwFlags)
    @ccall user32.AnimateWindow(hWnd::Cint, dwTime::DWORD, dwFlags::DWORD)::BOOL
end

function GetLayeredWindowAttributes(hwnd, pcrKey, pbAlpha, pdwFlags)
    @ccall user32.GetLayeredWindowAttributes(hwnd::Cint, pcrKey::Ptr{Cint}, pbAlpha::Ptr{BYTE}, pdwFlags::Ptr{DWORD})::BOOL
end

function PrintWindow(hwnd, hdcBlt, nFlags)
    @ccall user32.PrintWindow(hwnd::Cint, hdcBlt::Cint, nFlags::UINT)::BOOL
end

function SetLayeredWindowAttributes(hwnd, crKey, bAlpha, dwFlags)
    @ccall user32.SetLayeredWindowAttributes(hwnd::Cint, crKey::Cint, bAlpha::BYTE, dwFlags::DWORD)::BOOL
end

function ShowWindowAsync(hWnd, nCmdShow)
    @ccall user32.ShowWindowAsync(hWnd::Cint, nCmdShow::Cint)::BOOL
end

function FlashWindow(hWnd, bInvert)
    @ccall user32.FlashWindow(hWnd::Cint, bInvert::BOOL)::BOOL
end

struct __JL_Ctag_41
    cbSize::UINT
    hwnd::Cint
    dwFlags::DWORD
    uCount::UINT
    dwTimeout::DWORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_41}, f::Symbol)
    f === :cbSize && return Ptr{UINT}(x + 0)
    f === :hwnd && return Ptr{Cint}(x + 0)
    f === :dwFlags && return Ptr{DWORD}(x + 0)
    f === :uCount && return Ptr{UINT}(x + 0)
    f === :dwTimeout && return Ptr{DWORD}(x + 0)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_41, f::Symbol)
    r = Ref{__JL_Ctag_41}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_41}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_41}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const FLASHWINFO = __JL_Ctag_41

const PFLASHWINFO = Ptr{__JL_Ctag_41}

function FlashWindowEx(pfwi)
    @ccall user32.FlashWindowEx(pfwi::PFLASHWINFO)::BOOL
end

function ShowOwnedPopups(hWnd, fShow)
    @ccall user32.ShowOwnedPopups(hWnd::Cint, fShow::BOOL)::BOOL
end

function OpenIcon(hWnd)
    @ccall user32.OpenIcon(hWnd::Cint)::BOOL
end

function CloseWindow(hWnd)
    @ccall user32.CloseWindow(hWnd::Cint)::BOOL
end

function MoveWindow(hWnd, X, Y, nWidth, nHeight, bRepaint)
    @ccall user32.MoveWindow(hWnd::Cint, X::Cint, Y::Cint, nWidth::Cint, nHeight::Cint, bRepaint::BOOL)::BOOL
end

function SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags)
    @ccall user32.SetWindowPos(hWnd::Cint, hWndInsertAfter::Cint, X::Cint, Y::Cint, cx::Cint, cy::Cint, uFlags::UINT)::BOOL
end

function GetWindowPlacement(hWnd, lpwndpl)
    @ccall user32.GetWindowPlacement(hWnd::Cint, lpwndpl::Ptr{WINDOWPLACEMENT})::BOOL
end

function SetWindowPlacement(hWnd, lpwndpl)
    @ccall user32.SetWindowPlacement(hWnd::Cint, lpwndpl::Ptr{WINDOWPLACEMENT})::BOOL
end

function BeginDeferWindowPos(nNumWindows)
    @ccall user32.BeginDeferWindowPos(nNumWindows::Cint)::HDWP
end

function DeferWindowPos(hWinPosInfo, hWnd, hWndInsertAfter, x, y, cx, cy, uFlags)
    @ccall user32.DeferWindowPos(hWinPosInfo::HDWP, hWnd::Cint, hWndInsertAfter::Cint, x::Cint, y::Cint, cx::Cint, cy::Cint, uFlags::UINT)::HDWP
end

function EndDeferWindowPos(hWinPosInfo)
    @ccall user32.EndDeferWindowPos(hWinPosInfo::HDWP)::BOOL
end

function IsWindowVisible(hWnd)
    @ccall user32.IsWindowVisible(hWnd::Cint)::BOOL
end

function IsIconic(hWnd)
    @ccall user32.IsIconic(hWnd::Cint)::BOOL
end

function AnyPopup()
    @ccall user32.AnyPopup()::BOOL
end

function BringWindowToTop(hWnd)
    @ccall user32.BringWindowToTop(hWnd::Cint)::BOOL
end

function IsZoomed(hWnd)
    @ccall user32.IsZoomed(hWnd::Cint)::BOOL
end

const LPDLGTEMPLATEA = Ptr{DLGTEMPLATE}

const LPDLGTEMPLATEW = Ptr{DLGTEMPLATE}

const LPDLGTEMPLATE = LPDLGTEMPLATEA

const LPCDLGTEMPLATE = LPCDLGTEMPLATEA

struct DLGITEMTEMPLATE
    style::DWORD
    dwExtendedStyle::DWORD
    x::Cshort
    y::Cshort
    cx::Cshort
    cy::Cshort
    id::WORD
end

const PDLGITEMTEMPLATEA = Ptr{DLGITEMTEMPLATE}

const PDLGITEMTEMPLATEW = Ptr{DLGITEMTEMPLATE}

const PDLGITEMTEMPLATE = PDLGITEMTEMPLATEA

const LPDLGITEMTEMPLATEA = Ptr{DLGITEMTEMPLATE}

const LPDLGITEMTEMPLATEW = Ptr{DLGITEMTEMPLATE}

const LPDLGITEMTEMPLATE = LPDLGITEMTEMPLATEA

function EndDialog(hDlg, nResult)
    @ccall user32.EndDialog(hDlg::Cint, nResult::INT_PTR)::BOOL
end

function GetDlgItem(hDlg, nIDDlgItem)
    @ccall user32.GetDlgItem(hDlg::Cint, nIDDlgItem::Cint)::Cint
end

function SetDlgItemInt(hDlg, nIDDlgItem, uValue, bSigned)
    @ccall user32.SetDlgItemInt(hDlg::Cint, nIDDlgItem::Cint, uValue::UINT, bSigned::BOOL)::BOOL
end

function GetDlgItemInt(hDlg, nIDDlgItem, lpTranslated, bSigned)
    @ccall user32.GetDlgItemInt(hDlg::Cint, nIDDlgItem::Cint, lpTranslated::Ptr{BOOL}, bSigned::BOOL)::UINT
end

function SetDlgItemTextW(hDlg, nIDDlgItem, lpString)
    @ccall user32.SetDlgItemTextW(hDlg::Cint, nIDDlgItem::Cint, lpString::LPCWSTR)::BOOL
end

function GetDlgItemTextW(hDlg, nIDDlgItem, lpString, cchMax)
    @ccall user32.GetDlgItemTextW(hDlg::Cint, nIDDlgItem::Cint, lpString::LPWSTR, cchMax::Cint)::UINT
end

function CheckDlgButton(hDlg, nIDButton, uCheck)
    @ccall user32.CheckDlgButton(hDlg::Cint, nIDButton::Cint, uCheck::UINT)::BOOL
end

function CheckRadioButton(hDlg, nIDFirstButton, nIDLastButton, nIDCheckButton)
    @ccall user32.CheckRadioButton(hDlg::Cint, nIDFirstButton::Cint, nIDLastButton::Cint, nIDCheckButton::Cint)::BOOL
end

function IsDlgButtonChecked(hDlg, nIDButton)
    @ccall user32.IsDlgButtonChecked(hDlg::Cint, nIDButton::Cint)::UINT
end

function SendDlgItemMessageW(hDlg, nIDDlgItem, Msg, wParam, lParam)
    @ccall user32.SendDlgItemMessageW(hDlg::Cint, nIDDlgItem::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function GetNextDlgGroupItem(hDlg, hCtl, bPrevious)
    @ccall user32.GetNextDlgGroupItem(hDlg::Cint, hCtl::Cint, bPrevious::BOOL)::Cint
end

function GetNextDlgTabItem(hDlg, hCtl, bPrevious)
    @ccall user32.GetNextDlgTabItem(hDlg::Cint, hCtl::Cint, bPrevious::BOOL)::Cint
end

function GetDlgCtrlID(hWnd)
    @ccall user32.GetDlgCtrlID(hWnd::Cint)::Cint
end

function GetDialogBaseUnits()
    @ccall user32.GetDialogBaseUnits()::Clong
end

function DefDlgProcW(hDlg, Msg, wParam, lParam)
    @ccall user32.DefDlgProcW(hDlg::Cint, Msg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

@cenum DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS::UInt32 begin
    DCDC_DEFAULT = 0
    DCDC_DISABLE_FONT_UPDATE = 1
    DCDC_DISABLE_RELAYOUT = 2
end

function SetDialogControlDpiChangeBehavior(hWnd, mask, values)
    @ccall user32.SetDialogControlDpiChangeBehavior(hWnd::Cint, mask::DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS, values::DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS)::BOOL
end

function GetDialogControlDpiChangeBehavior(hWnd)
    @ccall user32.GetDialogControlDpiChangeBehavior(hWnd::Cint)::DIALOG_CONTROL_DPI_CHANGE_BEHAVIORS
end

@cenum DIALOG_DPI_CHANGE_BEHAVIORS::UInt32 begin
    DDC_DEFAULT = 0
    DDC_DISABLE_ALL = 1
    DDC_DISABLE_RESIZE = 2
    DDC_DISABLE_CONTROL_RELAYOUT = 4
end

function SetDialogDpiChangeBehavior(hDlg, mask, values)
    @ccall user32.SetDialogDpiChangeBehavior(hDlg::Cint, mask::DIALOG_DPI_CHANGE_BEHAVIORS, values::DIALOG_DPI_CHANGE_BEHAVIORS)::BOOL
end

function GetDialogDpiChangeBehavior(hDlg)
    @ccall user32.GetDialogDpiChangeBehavior(hDlg::Cint)::DIALOG_DPI_CHANGE_BEHAVIORS
end

function CallMsgFilterW(lpMsg, nCode)
    @ccall user32.CallMsgFilterW(lpMsg::LPMSG, nCode::Cint)::BOOL
end

function OpenClipboard(hWndNewOwner)
    @ccall user32.OpenClipboard(hWndNewOwner::Cint)::BOOL
end

function CloseClipboard()
    @ccall user32.CloseClipboard()::BOOL
end

function GetClipboardSequenceNumber()
    @ccall user32.GetClipboardSequenceNumber()::DWORD
end

function GetClipboardOwner()
    @ccall user32.GetClipboardOwner()::Cint
end

function SetClipboardViewer(hWndNewViewer)
    @ccall user32.SetClipboardViewer(hWndNewViewer::Cint)::Cint
end

function GetClipboardViewer()
    @ccall user32.GetClipboardViewer()::Cint
end

function ChangeClipboardChain(hWndRemove, hWndNewNext)
    @ccall user32.ChangeClipboardChain(hWndRemove::Cint, hWndNewNext::Cint)::BOOL
end

function SetClipboardData(uFormat, hMem)
    @ccall user32.SetClipboardData(uFormat::UINT, hMem::HANDLE)::HANDLE
end

function GetClipboardData(uFormat)
    @ccall user32.GetClipboardData(uFormat::UINT)::HANDLE
end

struct tagGETCLIPBMETADATA
    Version::UINT
    IsDelayRendered::BOOL
    IsSynthetic::BOOL
end

const GETCLIPBMETADATA = tagGETCLIPBMETADATA

const PGETCLIPBMETADATA = Ptr{tagGETCLIPBMETADATA}

function GetClipboardMetadata(format, metadata)
    @ccall user32.GetClipboardMetadata(format::UINT, metadata::PGETCLIPBMETADATA)::BOOL
end

function RegisterClipboardFormatW(lpszFormat)
    @ccall user32.RegisterClipboardFormatW(lpszFormat::LPCWSTR)::UINT
end

function CountClipboardFormats()
    @ccall user32.CountClipboardFormats()::Cint
end

function EnumClipboardFormats(format)
    @ccall user32.EnumClipboardFormats(format::UINT)::UINT
end

function GetClipboardFormatNameW(format, lpszFormatName, cchMaxCount)
    @ccall user32.GetClipboardFormatNameW(format::UINT, lpszFormatName::LPWSTR, cchMaxCount::Cint)::Cint
end

function EmptyClipboard()
    @ccall user32.EmptyClipboard()::BOOL
end

function IsClipboardFormatAvailable(format)
    @ccall user32.IsClipboardFormatAvailable(format::UINT)::BOOL
end

function GetPriorityClipboardFormat(paFormatPriorityList, cFormats)
    @ccall user32.GetPriorityClipboardFormat(paFormatPriorityList::Ptr{UINT}, cFormats::Cint)::Cint
end

function GetOpenClipboardWindow()
    @ccall user32.GetOpenClipboardWindow()::Cint
end

function CharToOemW(pSrc, pDst)
    @ccall user32.CharToOemW(pSrc::LPCWSTR, pDst::LPSTR)::BOOL
end

# no prototype is found for this function at winuser.h:5595:1, please use with caution
function __drv_preferredFunction()
    @ccall user32.__drv_preferredFunction()::Cint
end

function OemToCharW(pSrc, pDst)
    @ccall user32.OemToCharW(pSrc::LPCSTR, pDst::LPWSTR)::BOOL
end

function CharToOemBuffW(lpszSrc, lpszDst, cchDstLength)
    @ccall user32.CharToOemBuffW(lpszSrc::LPCWSTR, lpszDst::LPSTR, cchDstLength::DWORD)::BOOL
end

function OemToCharBuffW(lpszSrc, lpszDst, cchDstLength)
    @ccall user32.OemToCharBuffW(lpszSrc::LPCSTR, lpszDst::LPWSTR, cchDstLength::DWORD)::BOOL
end

function CharUpperW(lpsz)
    @ccall user32.CharUpperW(lpsz::LPWSTR)::LPWSTR
end

function CharUpperBuffW(lpsz, cchLength)
    @ccall user32.CharUpperBuffW(lpsz::LPWSTR, cchLength::DWORD)::DWORD
end

function CharLowerW(lpsz)
    @ccall user32.CharLowerW(lpsz::LPWSTR)::LPWSTR
end

function CharLowerBuffW(lpsz, cchLength)
    @ccall user32.CharLowerBuffW(lpsz::LPWSTR, cchLength::DWORD)::DWORD
end

function CharNextW(lpsz)
    @ccall user32.CharNextW(lpsz::LPCWSTR)::LPWSTR
end

function CharPrevW(lpszStart, lpszCurrent)
    @ccall user32.CharPrevW(lpszStart::LPCWSTR, lpszCurrent::LPCWSTR)::LPWSTR
end

function CharNextExA(CodePage, lpCurrentChar, dwFlags)
    @ccall user32.CharNextExA(CodePage::WORD, lpCurrentChar::LPCSTR, dwFlags::DWORD)::LPSTR
end

function CharPrevExA(CodePage, lpStart, lpCurrentChar, dwFlags)
    @ccall user32.CharPrevExA(CodePage::WORD, lpStart::LPCSTR, lpCurrentChar::LPCSTR, dwFlags::DWORD)::LPSTR
end

function IsCharAlphaW(ch)
    @ccall user32.IsCharAlphaW(ch::WCHAR)::BOOL
end

function IsCharAlphaNumericW(ch)
    @ccall user32.IsCharAlphaNumericW(ch::WCHAR)::BOOL
end

function IsCharUpperW(ch)
    @ccall user32.IsCharUpperW(ch::WCHAR)::BOOL
end

function IsCharLowerW(ch)
    @ccall user32.IsCharLowerW(ch::WCHAR)::BOOL
end

function SetFocus(hWnd)
    @ccall user32.SetFocus(hWnd::Cint)::Cint
end

function GetActiveWindow()
    @ccall user32.GetActiveWindow()::Cint
end

function GetFocus()
    @ccall user32.GetFocus()::Cint
end

function GetKBCodePage()
    @ccall user32.GetKBCodePage()::UINT
end

function GetKeyState(nVirtKey)
    @ccall user32.GetKeyState(nVirtKey::Cint)::SHORT
end

function GetAsyncKeyState(vKey)
    @ccall user32.GetAsyncKeyState(vKey::Cint)::SHORT
end

function GetKeyboardState(lpKeyState)
    @ccall user32.GetKeyboardState(lpKeyState::PBYTE)::BOOL
end

function SetKeyboardState(lpKeyState)
    @ccall user32.SetKeyboardState(lpKeyState::LPBYTE)::BOOL
end

function GetKeyNameTextW(lParam, lpString, cchSize)
    @ccall user32.GetKeyNameTextW(lParam::LONG, lpString::LPWSTR, cchSize::Cint)::Cint
end

function GetKeyboardType(nTypeFlag)
    @ccall user32.GetKeyboardType(nTypeFlag::Cint)::Cint
end

function ToAscii(uVirtKey, uScanCode, lpKeyState, lpChar, uFlags)
    @ccall user32.ToAscii(uVirtKey::UINT, uScanCode::UINT, lpKeyState::Ptr{BYTE}, lpChar::LPWORD, uFlags::UINT)::Cint
end

function ToAsciiEx(uVirtKey, uScanCode, lpKeyState, lpChar, uFlags, dwhkl)
    @ccall user32.ToAsciiEx(uVirtKey::UINT, uScanCode::UINT, lpKeyState::Ptr{BYTE}, lpChar::LPWORD, uFlags::UINT, dwhkl::HKL)::Cint
end

function ToUnicode(wVirtKey, wScanCode, lpKeyState, pwszBuff, cchBuff, wFlags)
    @ccall user32.ToUnicode(wVirtKey::UINT, wScanCode::UINT, lpKeyState::Ptr{BYTE}, pwszBuff::LPWSTR, cchBuff::Cint, wFlags::UINT)::Cint
end

function OemKeyScan(wOemChar)
    @ccall user32.OemKeyScan(wOemChar::WORD)::DWORD
end

function VkKeyScanW(ch)
    @ccall user32.VkKeyScanW(ch::WCHAR)::SHORT
end

function VkKeyScanExW(ch, dwhkl)
    @ccall user32.VkKeyScanExW(ch::WCHAR, dwhkl::HKL)::SHORT
end

function keybd_event(bVk, bScan, dwFlags, dwExtraInfo)
    @ccall user32.keybd_event(bVk::BYTE, bScan::BYTE, dwFlags::DWORD, dwExtraInfo::ULONG_PTR)::Cvoid
end

function mouse_event(dwFlags, dx, dy, dwData, dwExtraInfo)
    @ccall user32.mouse_event(dwFlags::DWORD, dx::DWORD, dy::DWORD, dwData::DWORD, dwExtraInfo::ULONG_PTR)::Cvoid
end

struct tagMOUSEINPUT
    dx::LONG
    dy::LONG
    mouseData::DWORD
    dwFlags::DWORD
    time::DWORD
    dwExtraInfo::ULONG_PTR
end

const MOUSEINPUT = tagMOUSEINPUT

const PMOUSEINPUT = Ptr{tagMOUSEINPUT}

const LPMOUSEINPUT = Ptr{tagMOUSEINPUT}

struct tagKEYBDINPUT
    wVk::WORD
    wScan::WORD
    dwFlags::DWORD
    time::DWORD
    dwExtraInfo::ULONG_PTR
end

const KEYBDINPUT = tagKEYBDINPUT

const PKEYBDINPUT = Ptr{tagKEYBDINPUT}

const LPKEYBDINPUT = Ptr{tagKEYBDINPUT}

struct tagHARDWAREINPUT
    uMsg::DWORD
    wParamL::WORD
    wParamH::WORD
end

const HARDWAREINPUT = tagHARDWAREINPUT

const PHARDWAREINPUT = Ptr{tagHARDWAREINPUT}

const LPHARDWAREINPUT = Ptr{tagHARDWAREINPUT}

struct tagINPUT
    data::NTuple{40, UInt8}
end

function Base.getproperty(x::Ptr{tagINPUT}, f::Symbol)
    f === :type && return Ptr{DWORD}(x + 0)
    f === :mi && return Ptr{MOUSEINPUT}(x + 8)
    f === :ki && return Ptr{KEYBDINPUT}(x + 8)
    f === :hi && return Ptr{HARDWAREINPUT}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::tagINPUT, f::Symbol)
    r = Ref{tagINPUT}(x)
    ptr = Base.unsafe_convert(Ptr{tagINPUT}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{tagINPUT}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function tagINPUT(type::DWORD)
    ref = Ref{tagINPUT}()
    ptr = Base.unsafe_convert(Ptr{tagINPUT}, ref)
    ptr.type = type
    ref[]
end

const INPUT = tagINPUT

const PINPUT = Ptr{tagINPUT}

const LPINPUT = Ptr{tagINPUT}

function SendInput(cInputs, pInputs, cbSize)
    @ccall user32.SendInput(cInputs::UINT, pInputs::LPINPUT, cbSize::Cint)::UINT
end

struct tagLASTINPUTINFO
    cbSize::UINT
    dwTime::DWORD
end

const LASTINPUTINFO = tagLASTINPUTINFO

const PLASTINPUTINFO = Ptr{tagLASTINPUTINFO}

function GetLastInputInfo(plii)
    @ccall user32.GetLastInputInfo(plii::PLASTINPUTINFO)::BOOL
end

function MapVirtualKeyW(uCode, uMapType)
    @ccall user32.MapVirtualKeyW(uCode::UINT, uMapType::UINT)::UINT
end

function MapVirtualKeyExW(uCode, uMapType, dwhkl)
    @ccall user32.MapVirtualKeyExW(uCode::UINT, uMapType::UINT, dwhkl::HKL)::UINT
end

function GetInputState()
    @ccall user32.GetInputState()::BOOL
end

function GetQueueStatus(flags)
    @ccall user32.GetQueueStatus(flags::UINT)::DWORD
end

function GetCapture()
    @ccall user32.GetCapture()::Cint
end

function SetCapture(hWnd)
    @ccall user32.SetCapture(hWnd::Cint)::Cint
end

function ReleaseCapture()
    @ccall user32.ReleaseCapture()::BOOL
end

function MsgWaitForMultipleObjects(nCount, pHandles, fWaitAll, dwMilliseconds, dwWakeMask)
    @ccall user32.MsgWaitForMultipleObjects(nCount::DWORD, pHandles::Ptr{HANDLE}, fWaitAll::BOOL, dwMilliseconds::DWORD, dwWakeMask::DWORD)::DWORD
end

function MsgWaitForMultipleObjectsEx(nCount, pHandles, dwMilliseconds, dwWakeMask, dwFlags)
    @ccall user32.MsgWaitForMultipleObjectsEx(nCount::DWORD, pHandles::Ptr{HANDLE}, dwMilliseconds::DWORD, dwWakeMask::DWORD, dwFlags::DWORD)::DWORD
end

function SetTimer(hWnd, nIDEvent, uElapse, lpTimerFunc)
    @ccall user32.SetTimer(hWnd::Cint, nIDEvent::UINT_PTR, uElapse::UINT, lpTimerFunc::TIMERPROC)::UINT_PTR
end

function KillTimer(hWnd, uIDEvent)
    @ccall user32.KillTimer(hWnd::Cint, uIDEvent::UINT_PTR)::BOOL
end

function IsWindowUnicode(hWnd)
    @ccall user32.IsWindowUnicode(hWnd::Cint)::BOOL
end

function EnableWindow(hWnd, bEnable)
    @ccall user32.EnableWindow(hWnd::Cint, bEnable::BOOL)::BOOL
end

function IsWindowEnabled(hWnd)
    @ccall user32.IsWindowEnabled(hWnd::Cint)::BOOL
end

function LoadAcceleratorsW(hInstance, lpTableName)
    @ccall user32.LoadAcceleratorsW(hInstance::HINSTANCE, lpTableName::LPCWSTR)::Cint
end

function CreateAcceleratorTableW(paccel, cAccel)
    @ccall user32.CreateAcceleratorTableW(paccel::LPACCEL, cAccel::Cint)::Cint
end

function DestroyAcceleratorTable(hAccel)
    @ccall user32.DestroyAcceleratorTable(hAccel::Cint)::BOOL
end

function CopyAcceleratorTableW(hAccelSrc, lpAccelDst, cAccelEntries)
    @ccall user32.CopyAcceleratorTableW(hAccelSrc::Cint, lpAccelDst::LPACCEL, cAccelEntries::Cint)::Cint
end

function TranslateAcceleratorW(hWnd, hAccTable, lpMsg)
    @ccall user32.TranslateAcceleratorW(hWnd::Cint, hAccTable::Cint, lpMsg::LPMSG)::Cint
end

function GetSystemMetrics(nIndex)
    @ccall user32.GetSystemMetrics(nIndex::Cint)::Cint
end

function LoadMenuW(hInstance, lpMenuName)
    @ccall user32.LoadMenuW(hInstance::HINSTANCE, lpMenuName::LPCWSTR)::Cint
end

function LoadMenuIndirectW(lpMenuTemplate)
    @ccall user32.LoadMenuIndirectW(lpMenuTemplate::Ptr{MENUTEMPLATEW})::Cint
end

function GetMenu(hWnd)
    @ccall user32.GetMenu(hWnd::Cint)::Cint
end

function SetMenu(hWnd, hMenu)
    @ccall user32.SetMenu(hWnd::Cint, hMenu::Cint)::BOOL
end

function ChangeMenuW(hMenu, cmd, lpszNewItem, cmdInsert, flags)
    @ccall user32.ChangeMenuW(hMenu::Cint, cmd::UINT, lpszNewItem::LPCWSTR, cmdInsert::UINT, flags::UINT)::BOOL
end

function HiliteMenuItem(hWnd, hMenu, uIDHiliteItem, uHilite)
    @ccall user32.HiliteMenuItem(hWnd::Cint, hMenu::Cint, uIDHiliteItem::UINT, uHilite::UINT)::BOOL
end

function GetMenuStringW(hMenu, uIDItem, lpString, cchMax, flags)
    @ccall user32.GetMenuStringW(hMenu::Cint, uIDItem::UINT, lpString::LPWSTR, cchMax::Cint, flags::UINT)::Cint
end

function GetMenuState(hMenu, uId, uFlags)
    @ccall user32.GetMenuState(hMenu::Cint, uId::UINT, uFlags::UINT)::UINT
end

function DrawMenuBar(hWnd)
    @ccall user32.DrawMenuBar(hWnd::Cint)::BOOL
end

function GetSystemMenu(hWnd, bRevert)
    @ccall user32.GetSystemMenu(hWnd::Cint, bRevert::BOOL)::Cint
end

function CreateMenu()
    @ccall user32.CreateMenu()::Cint
end

function CreatePopupMenu()
    @ccall user32.CreatePopupMenu()::Cint
end

function DestroyMenu(hMenu)
    @ccall user32.DestroyMenu(hMenu::Cint)::BOOL
end

function CheckMenuItem(hMenu, uIDCheckItem, uCheck)
    @ccall user32.CheckMenuItem(hMenu::Cint, uIDCheckItem::UINT, uCheck::UINT)::DWORD
end

function EnableMenuItem(hMenu, uIDEnableItem, uEnable)
    @ccall user32.EnableMenuItem(hMenu::Cint, uIDEnableItem::UINT, uEnable::UINT)::BOOL
end

function GetSubMenu(hMenu, nPos)
    @ccall user32.GetSubMenu(hMenu::Cint, nPos::Cint)::Cint
end

function GetMenuItemID(hMenu, nPos)
    @ccall user32.GetMenuItemID(hMenu::Cint, nPos::Cint)::UINT
end

function GetMenuItemCount(hMenu)
    @ccall user32.GetMenuItemCount(hMenu::Cint)::Cint
end

function InsertMenuW(hMenu, uPosition, uFlags, uIDNewItem, lpNewItem)
    @ccall user32.InsertMenuW(hMenu::Cint, uPosition::UINT, uFlags::UINT, uIDNewItem::UINT_PTR, lpNewItem::LPCWSTR)::BOOL
end

function AppendMenuW(hMenu, uFlags, uIDNewItem, lpNewItem)
    @ccall user32.AppendMenuW(hMenu::Cint, uFlags::UINT, uIDNewItem::UINT_PTR, lpNewItem::LPCWSTR)::BOOL
end

function ModifyMenuW(hMnu, uPosition, uFlags, uIDNewItem, lpNewItem)
    @ccall user32.ModifyMenuW(hMnu::Cint, uPosition::UINT, uFlags::UINT, uIDNewItem::UINT_PTR, lpNewItem::LPCWSTR)::BOOL
end

function RemoveMenu(hMenu, uPosition, uFlags)
    @ccall user32.RemoveMenu(hMenu::Cint, uPosition::UINT, uFlags::UINT)::BOOL
end

function DeleteMenu(hMenu, uPosition, uFlags)
    @ccall user32.DeleteMenu(hMenu::Cint, uPosition::UINT, uFlags::UINT)::BOOL
end

function SetMenuItemBitmaps(hMenu, uPosition, uFlags, hBitmapUnchecked, hBitmapChecked)
    @ccall user32.SetMenuItemBitmaps(hMenu::Cint, uPosition::UINT, uFlags::UINT, hBitmapUnchecked::Cint, hBitmapChecked::Cint)::BOOL
end

function GetMenuCheckMarkDimensions()
    @ccall user32.GetMenuCheckMarkDimensions()::LONG
end

function TrackPopupMenu(hMenu, uFlags, x, y, nReserved, hWnd, prcRect)
    @ccall user32.TrackPopupMenu(hMenu::Cint, uFlags::UINT, x::Cint, y::Cint, nReserved::Cint, hWnd::Cint, prcRect::Ptr{Cint})::BOOL
end

struct tagTPMPARAMS
    cbSize::UINT
    rcExclude::Cint
end

const TPMPARAMS = tagTPMPARAMS

const LPTPMPARAMS = Ptr{TPMPARAMS}

function TrackPopupMenuEx(hMenu, uFlags, x, y, hwnd, lptpm)
    @ccall user32.TrackPopupMenuEx(hMenu::Cint, uFlags::UINT, x::Cint, y::Cint, hwnd::Cint, lptpm::LPTPMPARAMS)::BOOL
end

struct tagMENUINFO
    cbSize::DWORD
    fMask::DWORD
    dwStyle::DWORD
    cyMax::UINT
    hbrBack::Cint
    dwContextHelpID::DWORD
    dwMenuData::ULONG_PTR
end

const MENUINFO = tagMENUINFO

const LPMENUINFO = Ptr{tagMENUINFO}

const LPCMENUINFO = Ptr{MENUINFO}

# no prototype is found for this function at winuser.h:7780:1, please use with caution
function GetMenuInfo()
    @ccall user32.GetMenuInfo()::BOOL
end

# no prototype is found for this function at winuser.h:7787:1, please use with caution
function SetMenuInfo()
    @ccall user32.SetMenuInfo()::BOOL
end

function EndMenu()
    @ccall user32.EndMenu()::BOOL
end

struct tagMENUGETOBJECTINFO
    dwFlags::DWORD
    uPos::UINT
    hmenu::Cint
    riid::PVOID
    pvObj::PVOID
end

const MENUGETOBJECTINFO = tagMENUGETOBJECTINFO

const PMENUGETOBJECTINFO = Ptr{tagMENUGETOBJECTINFO}

struct tagMENUITEMINFOW
    cbSize::UINT
    fMask::UINT
    fType::UINT
    fState::UINT
    wID::UINT
    hSubMenu::Cint
    hbmpChecked::Cint
    hbmpUnchecked::Cint
    dwItemData::ULONG_PTR
    dwTypeData::LPWSTR
    cch::UINT
    hbmpItem::Cint
end

const MENUITEMINFOW = tagMENUITEMINFOW

const LPMENUITEMINFOW = Ptr{tagMENUITEMINFOW}

const MENUITEMINFO = MENUITEMINFOA

const LPMENUITEMINFO = LPMENUITEMINFOA

const LPCMENUITEMINFOW = Ptr{MENUITEMINFOW}

const LPCMENUITEMINFO = LPCMENUITEMINFOA

function InsertMenuItemW(hmenu, item, fByPosition, lpmi)
    @ccall user32.InsertMenuItemW(hmenu::Cint, item::UINT, fByPosition::BOOL, lpmi::LPCMENUITEMINFOW)::BOOL
end

function GetMenuItemInfoW(hmenu, item, fByPosition, lpmii)
    @ccall user32.GetMenuItemInfoW(hmenu::Cint, item::UINT, fByPosition::BOOL, lpmii::LPMENUITEMINFOW)::BOOL
end

function SetMenuItemInfoW(hmenu, item, fByPositon, lpmii)
    @ccall user32.SetMenuItemInfoW(hmenu::Cint, item::UINT, fByPositon::BOOL, lpmii::LPCMENUITEMINFOW)::BOOL
end

function GetMenuDefaultItem(hMenu, fByPos, gmdiFlags)
    @ccall user32.GetMenuDefaultItem(hMenu::Cint, fByPos::UINT, gmdiFlags::UINT)::UINT
end

function SetMenuDefaultItem(hMenu, uItem, fByPos)
    @ccall user32.SetMenuDefaultItem(hMenu::Cint, uItem::UINT, fByPos::UINT)::BOOL
end

function GetMenuItemRect(hWnd, hMenu, uItem, lprcItem)
    @ccall user32.GetMenuItemRect(hWnd::Cint, hMenu::Cint, uItem::UINT, lprcItem::Cint)::BOOL
end

function MenuItemFromPoint(hWnd, hMenu, ptScreen)
    @ccall user32.MenuItemFromPoint(hWnd::Cint, hMenu::Cint, ptScreen::Cint)::Cint
end

struct tagDROPSTRUCT
    hwndSource::Cint
    hwndSink::Cint
    wFmt::DWORD
    dwData::ULONG_PTR
    ptDrop::Cint
    dwControlData::DWORD
end

const DROPSTRUCT = tagDROPSTRUCT

const PDROPSTRUCT = Ptr{tagDROPSTRUCT}

const LPDROPSTRUCT = Ptr{tagDROPSTRUCT}

function DragObject(hwndParent, hwndFrom, fmt, data, hcur)
    @ccall user32.DragObject(hwndParent::Cint, hwndFrom::Cint, fmt::UINT, data::ULONG_PTR, hcur::Cint)::DWORD
end

function DragDetect(hwnd, pt)
    @ccall user32.DragDetect(hwnd::Cint, pt::Cint)::BOOL
end

function DrawIcon(hDC, X, Y, hIcon)
    @ccall user32.DrawIcon(hDC::Cint, X::Cint, Y::Cint, hIcon::Cint)::BOOL
end

const DRAWTEXTPARAMS = tagDRAWTEXTPARAMS

function DrawTextW(hdc, lpchText, cchText, lprc, format)
    @ccall user32.DrawTextW(hdc::Cint, lpchText::LPCWSTR, cchText::Cint, lprc::Cint, format::UINT)::Cint
end

function DrawTextExW(hdc, lpchText, cchText, lprc, format, lpdtp)
    @ccall user32.DrawTextExW(hdc::Cint, lpchText::LPWSTR, cchText::Cint, lprc::Cint, format::UINT, lpdtp::LPDRAWTEXTPARAMS)::Cint
end

function GrayStringW(hDC, hBrush, lpOutputFunc, lpData, nCount, X, Y, nWidth, nHeight)
    @ccall user32.GrayStringW(hDC::Cint, hBrush::Cint, lpOutputFunc::GRAYSTRINGPROC, lpData::LPARAM, nCount::Cint, X::Cint, Y::Cint, nWidth::Cint, nHeight::Cint)::BOOL
end

function DrawStateW(hdc, hbrFore, qfnCallBack, lData, wData, x, y, cx, cy, uFlags)
    @ccall user32.DrawStateW(hdc::Cint, hbrFore::Cint, qfnCallBack::DRAWSTATEPROC, lData::LPARAM, wData::WPARAM, x::Cint, y::Cint, cx::Cint, cy::Cint, uFlags::UINT)::BOOL
end

function TabbedTextOutW(hdc, x, y, lpString, chCount, nTabPositions, lpnTabStopPositions, nTabOrigin)
    @ccall user32.TabbedTextOutW(hdc::Cint, x::Cint, y::Cint, lpString::LPCWSTR, chCount::Cint, nTabPositions::Cint, lpnTabStopPositions::Ptr{INT}, nTabOrigin::Cint)::LONG
end

function GetTabbedTextExtentW(hdc, lpString, chCount, nTabPositions, lpnTabStopPositions)
    @ccall user32.GetTabbedTextExtentW(hdc::Cint, lpString::LPCWSTR, chCount::Cint, nTabPositions::Cint, lpnTabStopPositions::Ptr{INT})::DWORD
end

function UpdateWindow(hWnd)
    @ccall user32.UpdateWindow(hWnd::Cint)::BOOL
end

function SetActiveWindow(hWnd)
    @ccall user32.SetActiveWindow(hWnd::Cint)::Cint
end

function GetForegroundWindow()
    @ccall user32.GetForegroundWindow()::Cint
end

function PaintDesktop(hdc)
    @ccall user32.PaintDesktop(hdc::Cint)::BOOL
end

function SwitchToThisWindow(hwnd, fUnknown)
    @ccall user32.SwitchToThisWindow(hwnd::Cint, fUnknown::BOOL)::Cvoid
end

function SetForegroundWindow(hWnd)
    @ccall user32.SetForegroundWindow(hWnd::Cint)::BOOL
end

function AllowSetForegroundWindow(dwProcessId)
    @ccall user32.AllowSetForegroundWindow(dwProcessId::DWORD)::BOOL
end

function LockSetForegroundWindow(uLockCode)
    @ccall user32.LockSetForegroundWindow(uLockCode::UINT)::BOOL
end

function WindowFromDC(hDC)
    @ccall user32.WindowFromDC(hDC::Cint)::Cint
end

function GetDC(hWnd)
    @ccall user32.GetDC(hWnd::Cint)::Cint
end

function GetDCEx(hWnd, hrgnClip, flags)
    @ccall user32.GetDCEx(hWnd::Cint, hrgnClip::HRGN, flags::DWORD)::Cint
end

function GetWindowDC(hWnd)
    @ccall user32.GetWindowDC(hWnd::Cint)::Cint
end

function ReleaseDC(hWnd, hDC)
    @ccall user32.ReleaseDC(hWnd::Cint, hDC::Cint)::Cint
end

function BeginPaint(hWnd, lpPaint)
    @ccall user32.BeginPaint(hWnd::Cint, lpPaint::LPPAINTSTRUCT)::Cint
end

function EndPaint(hWnd, lpPaint)
    @ccall user32.EndPaint(hWnd::Cint, lpPaint::Ptr{PAINTSTRUCT})::BOOL
end

function GetUpdateRect(hWnd, lpRect, bErase)
    @ccall user32.GetUpdateRect(hWnd::Cint, lpRect::Cint, bErase::BOOL)::BOOL
end

function GetUpdateRgn(hWnd, hRgn, bErase)
    @ccall user32.GetUpdateRgn(hWnd::Cint, hRgn::HRGN, bErase::BOOL)::Cint
end

function SetWindowRgn(hWnd, hRgn, bRedraw)
    @ccall user32.SetWindowRgn(hWnd::Cint, hRgn::HRGN, bRedraw::BOOL)::Cint
end

function GetWindowRgn(hWnd, hRgn)
    @ccall user32.GetWindowRgn(hWnd::Cint, hRgn::HRGN)::Cint
end

function GetWindowRgnBox(hWnd, lprc)
    @ccall user32.GetWindowRgnBox(hWnd::Cint, lprc::Cint)::Cint
end

function ExcludeUpdateRgn(hDC, hWnd)
    @ccall user32.ExcludeUpdateRgn(hDC::Cint, hWnd::Cint)::Cint
end

function InvalidateRect(hWnd, lpRect, bErase)
    @ccall user32.InvalidateRect(hWnd::Cint, lpRect::Ptr{Cint}, bErase::BOOL)::BOOL
end

function ValidateRect(hWnd, lpRect)
    @ccall user32.ValidateRect(hWnd::Cint, lpRect::Ptr{Cint})::BOOL
end

function InvalidateRgn(hWnd, hRgn, bErase)
    @ccall user32.InvalidateRgn(hWnd::Cint, hRgn::HRGN, bErase::BOOL)::BOOL
end

function ValidateRgn(hWnd, hRgn)
    @ccall user32.ValidateRgn(hWnd::Cint, hRgn::HRGN)::BOOL
end

function RedrawWindow(hWnd, lprcUpdate, hrgnUpdate, flags)
    @ccall user32.RedrawWindow(hWnd::Cint, lprcUpdate::Ptr{Cint}, hrgnUpdate::HRGN, flags::UINT)::BOOL
end

function LockWindowUpdate(hWndLock)
    @ccall user32.LockWindowUpdate(hWndLock::Cint)::BOOL
end

function ScrollWindow(hWnd, XAmount, YAmount, lpRect, lpClipRect)
    @ccall user32.ScrollWindow(hWnd::Cint, XAmount::Cint, YAmount::Cint, lpRect::Ptr{Cint}, lpClipRect::Ptr{Cint})::BOOL
end

function ScrollDC(hDC, dx, dy, lprcScroll, lprcClip, hrgnUpdate, lprcUpdate)
    @ccall user32.ScrollDC(hDC::Cint, dx::Cint, dy::Cint, lprcScroll::Ptr{Cint}, lprcClip::Ptr{Cint}, hrgnUpdate::HRGN, lprcUpdate::Cint)::BOOL
end

function ScrollWindowEx(hWnd, dx, dy, prcScroll, prcClip, hrgnUpdate, prcUpdate, flags)
    @ccall user32.ScrollWindowEx(hWnd::Cint, dx::Cint, dy::Cint, prcScroll::Ptr{Cint}, prcClip::Ptr{Cint}, hrgnUpdate::HRGN, prcUpdate::Cint, flags::UINT)::Cint
end

function SetScrollPos(hWnd, nBar, nPos, bRedraw)
    @ccall user32.SetScrollPos(hWnd::Cint, nBar::Cint, nPos::Cint, bRedraw::BOOL)::Cint
end

function GetScrollPos(hWnd, nBar)
    @ccall user32.GetScrollPos(hWnd::Cint, nBar::Cint)::Cint
end

function SetScrollRange(hWnd, nBar, nMinPos, nMaxPos, bRedraw)
    @ccall user32.SetScrollRange(hWnd::Cint, nBar::Cint, nMinPos::Cint, nMaxPos::Cint, bRedraw::BOOL)::BOOL
end

function GetScrollRange(hWnd, nBar, lpMinPos, lpMaxPos)
    @ccall user32.GetScrollRange(hWnd::Cint, nBar::Cint, lpMinPos::LPINT, lpMaxPos::LPINT)::BOOL
end

function ShowScrollBar(hWnd, wBar, bShow)
    @ccall user32.ShowScrollBar(hWnd::Cint, wBar::Cint, bShow::BOOL)::BOOL
end

function EnableScrollBar(hWnd, wSBflags, wArrows)
    @ccall user32.EnableScrollBar(hWnd::Cint, wSBflags::UINT, wArrows::UINT)::BOOL
end

function SetPropW(hWnd, lpString, hData)
    @ccall user32.SetPropW(hWnd::Cint, lpString::LPCWSTR, hData::HANDLE)::BOOL
end

function GetPropW(hWnd, lpString)
    @ccall user32.GetPropW(hWnd::Cint, lpString::LPCWSTR)::HANDLE
end

function RemovePropW(hWnd, lpString)
    @ccall user32.RemovePropW(hWnd::Cint, lpString::LPCWSTR)::HANDLE
end

function EnumPropsExW(hWnd, lpEnumFunc, lParam)
    @ccall user32.EnumPropsExW(hWnd::Cint, lpEnumFunc::PROPENUMPROCEXW, lParam::LPARAM)::Cint
end

function EnumPropsW(hWnd, lpEnumFunc)
    @ccall user32.EnumPropsW(hWnd::Cint, lpEnumFunc::PROPENUMPROCW)::Cint
end

function SetWindowTextW(hWnd, lpString)
    @ccall user32.SetWindowTextW(hWnd::Cint, lpString::LPCWSTR)::BOOL
end

function GetWindowTextW(hWnd, lpString, nMaxCount)
    @ccall user32.GetWindowTextW(hWnd::Cint, lpString::LPWSTR, nMaxCount::Cint)::Cint
end

function GetWindowTextLengthW(hWnd)
    @ccall user32.GetWindowTextLengthW(hWnd::Cint)::Cint
end

function GetClientRect(hWnd, lpRect)
    @ccall user32.GetClientRect(hWnd::Cint, lpRect::Cint)::BOOL
end

function GetWindowRect(hWnd, lpRect)
    @ccall user32.GetWindowRect(hWnd::Cint, lpRect::Cint)::BOOL
end

function AdjustWindowRect(lpRect, dwStyle, bMenu)
    @ccall user32.AdjustWindowRect(lpRect::Cint, dwStyle::DWORD, bMenu::BOOL)::BOOL
end

function AdjustWindowRectEx(lpRect, dwStyle, bMenu, dwExStyle)
    @ccall user32.AdjustWindowRectEx(lpRect::Cint, dwStyle::DWORD, bMenu::BOOL, dwExStyle::DWORD)::BOOL
end

struct tagHELPINFO
    cbSize::UINT
    iContextType::Cint
    iCtrlId::Cint
    hItemHandle::HANDLE
    dwContextId::DWORD_PTR
    MousePos::Cint
end

const HELPINFO = tagHELPINFO

const LPHELPINFO = Ptr{tagHELPINFO}

# no prototype is found for this function at winuser.h:9067:1, please use with caution
function SetWindowContextHelpId()
    @ccall user32.SetWindowContextHelpId()::BOOL
end

# no prototype is found for this function at winuser.h:9074:1, please use with caution
function GetWindowContextHelpId()
    @ccall user32.GetWindowContextHelpId()::DWORD
end

# no prototype is found for this function at winuser.h:9080:1, please use with caution
function SetMenuContextHelpId()
    @ccall user32.SetMenuContextHelpId()::BOOL
end

# no prototype is found for this function at winuser.h:9087:1, please use with caution
function GetMenuContextHelpId()
    @ccall user32.GetMenuContextHelpId()::DWORD
end

function MessageBoxW(hWnd, lpText, lpCaption, uType)
    @ccall user32.MessageBoxW(hWnd::Cint, lpText::LPCWSTR, lpCaption::LPCWSTR, uType::UINT)::Cint
end

function MessageBoxExW(hWnd, lpText, lpCaption, uType, wLanguageId)
    @ccall user32.MessageBoxExW(hWnd::Cint, lpText::LPCWSTR, lpCaption::LPCWSTR, uType::UINT, wLanguageId::WORD)::Cint
end

const PMSGBOXPARAMSA = Ptr{tagMSGBOXPARAMSA}

const LPMSGBOXPARAMSA = Ptr{tagMSGBOXPARAMSA}

struct tagMSGBOXPARAMSW
    cbSize::UINT
    hwndOwner::Cint
    hInstance::HINSTANCE
    lpszText::LPCWSTR
    lpszCaption::LPCWSTR
    dwStyle::DWORD
    lpszIcon::LPCWSTR
    dwContextHelpId::DWORD_PTR
    lpfnMsgBoxCallback::MSGBOXCALLBACK
    dwLanguageId::DWORD
end

const MSGBOXPARAMSW = tagMSGBOXPARAMSW

const PMSGBOXPARAMSW = Ptr{tagMSGBOXPARAMSW}

const LPMSGBOXPARAMSW = Ptr{tagMSGBOXPARAMSW}

const MSGBOXPARAMS = MSGBOXPARAMSA

const PMSGBOXPARAMS = PMSGBOXPARAMSA

const LPMSGBOXPARAMS = LPMSGBOXPARAMSA

function MessageBoxIndirectW(lpmbp)
    @ccall user32.MessageBoxIndirectW(lpmbp::Ptr{MSGBOXPARAMSW})::Cint
end

function MessageBeep(uType)
    @ccall user32.MessageBeep(uType::UINT)::BOOL
end

function ShowCursor(bShow)
    @ccall user32.ShowCursor(bShow::BOOL)::Cint
end

function SetCursorPos(X, Y)
    @ccall user32.SetCursorPos(X::Cint, Y::Cint)::BOOL
end

function SetCursor(hCursor)
    @ccall user32.SetCursor(hCursor::Cint)::Cint
end

function GetCursorPos(lpPoint)
    @ccall user32.GetCursorPos(lpPoint::Cint)::BOOL
end

function GetClipCursor(lpRect)
    @ccall user32.GetClipCursor(lpRect::Cint)::BOOL
end

function GetCursor()
    @ccall user32.GetCursor()::Cint
end

function CreateCaret(hWnd, hBitmap, nWidth, nHeight)
    @ccall user32.CreateCaret(hWnd::Cint, hBitmap::Cint, nWidth::Cint, nHeight::Cint)::BOOL
end

function GetCaretBlinkTime()
    @ccall user32.GetCaretBlinkTime()::UINT
end

function SetCaretBlinkTime(uMSeconds)
    @ccall user32.SetCaretBlinkTime(uMSeconds::UINT)::BOOL
end

function DestroyCaret()
    @ccall user32.DestroyCaret()::BOOL
end

function HideCaret(hWnd)
    @ccall user32.HideCaret(hWnd::Cint)::BOOL
end

function ShowCaret(hWnd)
    @ccall user32.ShowCaret(hWnd::Cint)::BOOL
end

function SetCaretPos(X, Y)
    @ccall user32.SetCaretPos(X::Cint, Y::Cint)::BOOL
end

function GetCaretPos(lpPoint)
    @ccall user32.GetCaretPos(lpPoint::Cint)::BOOL
end

function ClientToScreen(hWnd, lpPoint)
    @ccall user32.ClientToScreen(hWnd::Cint, lpPoint::Cint)::BOOL
end

function ScreenToClient(hWnd, lpPoint)
    @ccall user32.ScreenToClient(hWnd::Cint, lpPoint::Cint)::BOOL
end

function MapWindowPoints(hWndFrom, hWndTo, lpPoints, cPoints)
    @ccall user32.MapWindowPoints(hWndFrom::Cint, hWndTo::Cint, lpPoints::Cint, cPoints::UINT)::Cint
end

function WindowFromPoint(Point)
    @ccall user32.WindowFromPoint(Point::Cint)::Cint
end

function ChildWindowFromPoint(hWndParent, Point)
    @ccall user32.ChildWindowFromPoint(hWndParent::Cint, Point::Cint)::Cint
end

function ClipCursor(lpRect)
    @ccall user32.ClipCursor(lpRect::Ptr{Cint})::BOOL
end

function ChildWindowFromPointEx(hwnd, pt, flags)
    @ccall user32.ChildWindowFromPointEx(hwnd::Cint, pt::Cint, flags::UINT)::Cint
end

function GetSysColor(nIndex)
    @ccall user32.GetSysColor(nIndex::Cint)::DWORD
end

function GetSysColorBrush(nIndex)
    @ccall user32.GetSysColorBrush(nIndex::Cint)::Cint
end

function SetSysColors(cElements, lpaElements, lpaRgbValues)
    @ccall user32.SetSysColors(cElements::Cint, lpaElements::Ptr{INT}, lpaRgbValues::Ptr{Cint})::BOOL
end

function DrawFocusRect(hDC, lprc)
    @ccall user32.DrawFocusRect(hDC::Cint, lprc::Ptr{Cint})::BOOL
end

function FillRect(hDC, lprc, hbr)
    @ccall user32.FillRect(hDC::Cint, lprc::Ptr{Cint}, hbr::Cint)::Cint
end

function FrameRect(hDC, lprc, hbr)
    @ccall user32.FrameRect(hDC::Cint, lprc::Ptr{Cint}, hbr::Cint)::Cint
end

function InvertRect(hDC, lprc)
    @ccall user32.InvertRect(hDC::Cint, lprc::Ptr{Cint})::BOOL
end

function SetRect(lprc, xLeft, yTop, xRight, yBottom)
    @ccall user32.SetRect(lprc::Cint, xLeft::Cint, yTop::Cint, xRight::Cint, yBottom::Cint)::BOOL
end

function SetRectEmpty(lprc)
    @ccall user32.SetRectEmpty(lprc::Cint)::BOOL
end

function CopyRect(lprcDst, lprcSrc)
    @ccall user32.CopyRect(lprcDst::Cint, lprcSrc::Ptr{Cint})::BOOL
end

function InflateRect(lprc, dx, dy)
    @ccall user32.InflateRect(lprc::Cint, dx::Cint, dy::Cint)::BOOL
end

function IntersectRect(lprcDst, lprcSrc1, lprcSrc2)
    @ccall user32.IntersectRect(lprcDst::Cint, lprcSrc1::Ptr{Cint}, lprcSrc2::Ptr{Cint})::BOOL
end

function UnionRect(lprcDst, lprcSrc1, lprcSrc2)
    @ccall user32.UnionRect(lprcDst::Cint, lprcSrc1::Ptr{Cint}, lprcSrc2::Ptr{Cint})::BOOL
end

function SubtractRect(lprcDst, lprcSrc1, lprcSrc2)
    @ccall user32.SubtractRect(lprcDst::Cint, lprcSrc1::Ptr{Cint}, lprcSrc2::Ptr{Cint})::BOOL
end

function OffsetRect(lprc, dx, dy)
    @ccall user32.OffsetRect(lprc::Cint, dx::Cint, dy::Cint)::BOOL
end

function IsRectEmpty(lprc)
    @ccall user32.IsRectEmpty(lprc::Ptr{Cint})::BOOL
end

function EqualRect(lprc1, lprc2)
    @ccall user32.EqualRect(lprc1::Ptr{Cint}, lprc2::Ptr{Cint})::BOOL
end

function PtInRect(lprc, pt)
    @ccall user32.PtInRect(lprc::Ptr{Cint}, pt::Cint)::BOOL
end

function GetWindowWord(hWnd, nIndex)
    @ccall user32.GetWindowWord(hWnd::Cint, nIndex::Cint)::WORD
end

function SetWindowWord(hWnd, nIndex, wNewWord)
    @ccall user32.SetWindowWord(hWnd::Cint, nIndex::Cint, wNewWord::WORD)::WORD
end

function GetWindowLongW(hWnd, nIndex)
    @ccall user32.GetWindowLongW(hWnd::Cint, nIndex::Cint)::LONG
end

function SetWindowLongW(hWnd, nIndex, dwNewLong)
    @ccall user32.SetWindowLongW(hWnd::Cint, nIndex::Cint, dwNewLong::LONG)::LONG
end

function GetWindowLongPtrW(hWnd, nIndex)
    @ccall user32.GetWindowLongPtrW(hWnd::Cint, nIndex::Cint)::LONG_PTR
end

function SetWindowLongPtrW(hWnd, nIndex, dwNewLong)
    @ccall user32.SetWindowLongPtrW(hWnd::Cint, nIndex::Cint, dwNewLong::LONG_PTR)::LONG_PTR
end

function GetClassWord(hWnd, nIndex)
    @ccall user32.GetClassWord(hWnd::Cint, nIndex::Cint)::WORD
end

function SetClassWord(hWnd, nIndex, wNewWord)
    @ccall user32.SetClassWord(hWnd::Cint, nIndex::Cint, wNewWord::WORD)::WORD
end

function GetClassLongW(hWnd, nIndex)
    @ccall user32.GetClassLongW(hWnd::Cint, nIndex::Cint)::DWORD
end

function SetClassLongW(hWnd, nIndex, dwNewLong)
    @ccall user32.SetClassLongW(hWnd::Cint, nIndex::Cint, dwNewLong::LONG)::DWORD
end

function GetClassLongPtrW(hWnd, nIndex)
    @ccall user32.GetClassLongPtrW(hWnd::Cint, nIndex::Cint)::ULONG_PTR
end

function SetClassLongPtrW(hWnd, nIndex, dwNewLong)
    @ccall user32.SetClassLongPtrW(hWnd::Cint, nIndex::Cint, dwNewLong::LONG_PTR)::ULONG_PTR
end

function GetProcessDefaultLayout(pdwDefaultLayout)
    @ccall user32.GetProcessDefaultLayout(pdwDefaultLayout::Ptr{DWORD})::BOOL
end

function SetProcessDefaultLayout(dwDefaultLayout)
    @ccall user32.SetProcessDefaultLayout(dwDefaultLayout::DWORD)::BOOL
end

function GetDesktopWindow()
    @ccall user32.GetDesktopWindow()::Cint
end

function GetParent(hWnd)
    @ccall user32.GetParent(hWnd::Cint)::Cint
end

function SetParent(hWndChild, hWndNewParent)
    @ccall user32.SetParent(hWndChild::Cint, hWndNewParent::Cint)::Cint
end

function EnumChildWindows(hWndParent, lpEnumFunc, lParam)
    @ccall user32.EnumChildWindows(hWndParent::Cint, lpEnumFunc::WNDENUMPROC, lParam::LPARAM)::BOOL
end

function FindWindowW(lpClassName, lpWindowName)
    @ccall user32.FindWindowW(lpClassName::LPCWSTR, lpWindowName::LPCWSTR)::Cint
end

function FindWindowExW(hWndParent, hWndChildAfter, lpszClass, lpszWindow)
    @ccall user32.FindWindowExW(hWndParent::Cint, hWndChildAfter::Cint, lpszClass::LPCWSTR, lpszWindow::LPCWSTR)::Cint
end

function GetShellWindow()
    @ccall user32.GetShellWindow()::Cint
end

function RegisterShellHookWindow(hwnd)
    @ccall user32.RegisterShellHookWindow(hwnd::Cint)::BOOL
end

function DeregisterShellHookWindow(hwnd)
    @ccall user32.DeregisterShellHookWindow(hwnd::Cint)::BOOL
end

function EnumWindows(lpEnumFunc, lParam)
    @ccall user32.EnumWindows(lpEnumFunc::WNDENUMPROC, lParam::LPARAM)::BOOL
end

function GetClassNameW(hWnd, lpClassName, nMaxCount)
    @ccall user32.GetClassNameW(hWnd::Cint, lpClassName::LPWSTR, nMaxCount::Cint)::Cint
end

function GetTopWindow(hWnd)
    @ccall user32.GetTopWindow(hWnd::Cint)::Cint
end

function IsGUIThread(bConvert)
    @ccall user32.IsGUIThread(bConvert::BOOL)::BOOL
end

function GetLastActivePopup(hWnd)
    @ccall user32.GetLastActivePopup(hWnd::Cint)::Cint
end

function SetWindowsHookW(nFilterType, pfnFilterProc)
    @ccall user32.SetWindowsHookW(nFilterType::Cint, pfnFilterProc::HOOKPROC)::Cint
end

function UnhookWindowsHook(nCode, pfnFilterProc)
    @ccall user32.UnhookWindowsHook(nCode::Cint, pfnFilterProc::HOOKPROC)::BOOL
end

function SetWindowsHookExW(idHook, lpfn, hmod, dwThreadId)
    @ccall user32.SetWindowsHookExW(idHook::Cint, lpfn::HOOKPROC, hmod::HINSTANCE, dwThreadId::DWORD)::Cint
end

function UnhookWindowsHookEx(hhk)
    @ccall user32.UnhookWindowsHookEx(hhk::Cint)::BOOL
end

function CheckMenuRadioItem(hmenu, first, last, check, flags)
    @ccall user32.CheckMenuRadioItem(hmenu::Cint, first::UINT, last::UINT, check::UINT, flags::UINT)::BOOL
end

struct __JL_Ctag_44
    versionNumber::WORD
    offset::WORD
end
function Base.getproperty(x::Ptr{__JL_Ctag_44}, f::Symbol)
    f === :versionNumber && return Ptr{WORD}(x + 0)
    f === :offset && return Ptr{WORD}(x + 2)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_44, f::Symbol)
    r = Ref{__JL_Ctag_44}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_44}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_44}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const MENUITEMTEMPLATEHEADER = __JL_Ctag_44

const PMENUITEMTEMPLATEHEADER = Ptr{__JL_Ctag_44}

struct __JL_Ctag_45
    mtOption::WORD
    mtID::WORD
    mtString::NTuple{1, WCHAR}
end
function Base.getproperty(x::Ptr{__JL_Ctag_45}, f::Symbol)
    f === :mtOption && return Ptr{WORD}(x + 0)
    f === :mtID && return Ptr{WORD}(x + 2)
    f === :mtString && return Ptr{NTuple{1, WCHAR}}(x + 4)
    return getfield(x, f)
end

function Base.getproperty(x::__JL_Ctag_45, f::Symbol)
    r = Ref{__JL_Ctag_45}(x)
    ptr = Base.unsafe_convert(Ptr{__JL_Ctag_45}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{__JL_Ctag_45}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const MENUITEMTEMPLATE = __JL_Ctag_45

const PMENUITEMTEMPLATE = Ptr{__JL_Ctag_45}

function LoadBitmapW(hInstance, lpBitmapName)
    @ccall user32.LoadBitmapW(hInstance::HINSTANCE, lpBitmapName::LPCWSTR)::Cint
end

function LoadCursorW(hInstance, lpCursorName)
    @ccall user32.LoadCursorW(hInstance::HINSTANCE, lpCursorName::LPCWSTR)::Cint
end

function LoadCursorFromFileW(lpFileName)
    @ccall user32.LoadCursorFromFileW(lpFileName::LPCWSTR)::Cint
end

function CreateCursor(hInst, xHotSpot, yHotSpot, nWidth, nHeight, pvANDPlane, pvXORPlane)
    @ccall user32.CreateCursor(hInst::HINSTANCE, xHotSpot::Cint, yHotSpot::Cint, nWidth::Cint, nHeight::Cint, pvANDPlane::Ptr{Cvoid}, pvXORPlane::Ptr{Cvoid})::Cint
end

function DestroyCursor(hCursor)
    @ccall user32.DestroyCursor(hCursor::Cint)::BOOL
end

function SetSystemCursor(hcur, id)
    @ccall user32.SetSystemCursor(hcur::Cint, id::DWORD)::BOOL
end

struct _ICONINFO
    fIcon::BOOL
    xHotspot::DWORD
    yHotspot::DWORD
    hbmMask::Cint
    hbmColor::Cint
end

const ICONINFO = _ICONINFO

const PICONINFO = Ptr{ICONINFO}

function LoadIconW(hInstance, lpIconName)
    @ccall user32.LoadIconW(hInstance::HINSTANCE, lpIconName::LPCWSTR)::Cint
end

function PrivateExtractIconsW(szFileName, nIconIndex, cxIcon, cyIcon, phicon, piconid, nIcons, flags)
    @ccall user32.PrivateExtractIconsW(szFileName::LPCWSTR, nIconIndex::Cint, cxIcon::Cint, cyIcon::Cint, phicon::Ptr{Cint}, piconid::Ptr{UINT}, nIcons::UINT, flags::UINT)::UINT
end

function CreateIcon(hInstance, nWidth, nHeight, cPlanes, cBitsPixel, lpbANDbits, lpbXORbits)
    @ccall user32.CreateIcon(hInstance::HINSTANCE, nWidth::Cint, nHeight::Cint, cPlanes::BYTE, cBitsPixel::BYTE, lpbANDbits::Ptr{BYTE}, lpbXORbits::Ptr{BYTE})::Cint
end

function DestroyIcon(hIcon)
    @ccall user32.DestroyIcon(hIcon::Cint)::BOOL
end

function LookupIconIdFromDirectory(presbits, fIcon)
    @ccall user32.LookupIconIdFromDirectory(presbits::PBYTE, fIcon::BOOL)::Cint
end

function LookupIconIdFromDirectoryEx(presbits, fIcon, cxDesired, cyDesired, Flags)
    @ccall user32.LookupIconIdFromDirectoryEx(presbits::PBYTE, fIcon::BOOL, cxDesired::Cint, cyDesired::Cint, Flags::UINT)::Cint
end

function CreateIconFromResource(presbits, dwResSize, fIcon, dwVer)
    @ccall user32.CreateIconFromResource(presbits::PBYTE, dwResSize::DWORD, fIcon::BOOL, dwVer::DWORD)::Cint
end

function CreateIconFromResourceEx(presbits, dwResSize, fIcon, dwVer, cxDesired, cyDesired, Flags)
    @ccall user32.CreateIconFromResourceEx(presbits::PBYTE, dwResSize::DWORD, fIcon::BOOL, dwVer::DWORD, cxDesired::Cint, cyDesired::Cint, Flags::UINT)::Cint
end

struct tagCURSORSHAPE
    xHotSpot::Cint
    yHotSpot::Cint
    cx::Cint
    cy::Cint
    cbWidth::Cint
    Planes::BYTE
    BitsPixel::BYTE
end

const CURSORSHAPE = tagCURSORSHAPE

const LPCURSORSHAPE = Ptr{tagCURSORSHAPE}

function SetThreadCursorCreationScaling(cursorDpi)
    @ccall user32.SetThreadCursorCreationScaling(cursorDpi::UINT)::UINT
end

function LoadImageW(hInst, name, type, cx, cy, fuLoad)
    @ccall user32.LoadImageW(hInst::HINSTANCE, name::LPCWSTR, type::UINT, cx::Cint, cy::Cint, fuLoad::UINT)::HANDLE
end

function CopyImage(h, type, cx, cy, flags)
    @ccall user32.CopyImage(h::HANDLE, type::UINT, cx::Cint, cy::Cint, flags::UINT)::HANDLE
end

function DrawIconEx(hdc, xLeft, yTop, hIcon, cxWidth, cyWidth, istepIfAniCur, hbrFlickerFreeDraw, diFlags)
    @ccall user32.DrawIconEx(hdc::Cint, xLeft::Cint, yTop::Cint, hIcon::Cint, cxWidth::Cint, cyWidth::Cint, istepIfAniCur::UINT, hbrFlickerFreeDraw::Cint, diFlags::UINT)::BOOL
end

function CreateIconIndirect(piconinfo)
    @ccall user32.CreateIconIndirect(piconinfo::PICONINFO)::Cint
end

function GetIconInfo(hIcon, piconinfo)
    @ccall user32.GetIconInfo(hIcon::Cint, piconinfo::PICONINFO)::BOOL
end

function IsDialogMessageW(hDlg, lpMsg)
    @ccall user32.IsDialogMessageW(hDlg::Cint, lpMsg::LPMSG)::BOOL
end

function MapDialogRect(hDlg, lpRect)
    @ccall user32.MapDialogRect(hDlg::Cint, lpRect::Cint)::BOOL
end

function DlgDirListW(hDlg, lpPathSpec, nIDListBox, nIDStaticPath, uFileType)
    @ccall user32.DlgDirListW(hDlg::Cint, lpPathSpec::LPWSTR, nIDListBox::Cint, nIDStaticPath::Cint, uFileType::UINT)::Cint
end

function DlgDirSelectExW(hwndDlg, lpString, chCount, idListBox)
    @ccall user32.DlgDirSelectExW(hwndDlg::Cint, lpString::LPWSTR, chCount::Cint, idListBox::Cint)::BOOL
end

function DlgDirListComboBoxW(hDlg, lpPathSpec, nIDComboBox, nIDStaticPath, uFiletype)
    @ccall user32.DlgDirListComboBoxW(hDlg::Cint, lpPathSpec::LPWSTR, nIDComboBox::Cint, nIDStaticPath::Cint, uFiletype::UINT)::Cint
end

function DlgDirSelectComboBoxExW(hwndDlg, lpString, cchOut, idComboBox)
    @ccall user32.DlgDirSelectComboBoxExW(hwndDlg::Cint, lpString::LPWSTR, cchOut::Cint, idComboBox::Cint)::BOOL
end

struct tagSCROLLINFO
    cbSize::UINT
    fMask::UINT
    nMin::Cint
    nMax::Cint
    nPage::UINT
    nPos::Cint
    nTrackPos::Cint
end

const SCROLLINFO = tagSCROLLINFO

const LPSCROLLINFO = Ptr{tagSCROLLINFO}

const LPCSCROLLINFO = Ptr{SCROLLINFO}

function SetScrollInfo(hwnd, nBar, lpsi, redraw)
    @ccall user32.SetScrollInfo(hwnd::Cint, nBar::Cint, lpsi::LPCSCROLLINFO, redraw::BOOL)::Cint
end

function GetScrollInfo(hwnd, nBar, lpsi)
    @ccall user32.GetScrollInfo(hwnd::Cint, nBar::Cint, lpsi::LPSCROLLINFO)::BOOL
end

struct tagMDICREATESTRUCTA
    szClass::LPCSTR
    szTitle::LPCSTR
    hOwner::HANDLE
    x::Cint
    y::Cint
    cx::Cint
    cy::Cint
    style::DWORD
    lParam::LPARAM
end

const MDICREATESTRUCTA = tagMDICREATESTRUCTA

const LPMDICREATESTRUCTA = Ptr{tagMDICREATESTRUCTA}

struct tagMDICREATESTRUCTW
    szClass::LPCWSTR
    szTitle::LPCWSTR
    hOwner::HANDLE
    x::Cint
    y::Cint
    cx::Cint
    cy::Cint
    style::DWORD
    lParam::LPARAM
end

const MDICREATESTRUCTW = tagMDICREATESTRUCTW

const LPMDICREATESTRUCTW = Ptr{tagMDICREATESTRUCTW}

const MDICREATESTRUCT = MDICREATESTRUCTA

const LPMDICREATESTRUCT = LPMDICREATESTRUCTA

struct tagCLIENTCREATESTRUCT
    hWindowMenu::HANDLE
    idFirstChild::UINT
end

const CLIENTCREATESTRUCT = tagCLIENTCREATESTRUCT

const LPCLIENTCREATESTRUCT = Ptr{tagCLIENTCREATESTRUCT}

function DefFrameProcW(hWnd, hWndMDIClient, uMsg, wParam, lParam)
    @ccall user32.DefFrameProcW(hWnd::Cint, hWndMDIClient::Cint, uMsg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function DefMDIChildProcW(hWnd, uMsg, wParam, lParam)
    @ccall user32.DefMDIChildProcW(hWnd::Cint, uMsg::UINT, wParam::WPARAM, lParam::LPARAM)::LRESULT
end

function TranslateMDISysAccel(hWndClient, lpMsg)
    @ccall user32.TranslateMDISysAccel(hWndClient::Cint, lpMsg::LPMSG)::BOOL
end

function ArrangeIconicWindows(hWnd)
    @ccall user32.ArrangeIconicWindows(hWnd::Cint)::UINT
end

function CreateMDIWindowW(lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hInstance, lParam)
    @ccall user32.CreateMDIWindowW(lpClassName::LPCWSTR, lpWindowName::LPCWSTR, dwStyle::DWORD, X::Cint, Y::Cint, nWidth::Cint, nHeight::Cint, hWndParent::Cint, hInstance::HINSTANCE, lParam::LPARAM)::Cint
end

function TileWindows(hwndParent, wHow, lpRect, cKids, lpKids)
    @ccall user32.TileWindows(hwndParent::Cint, wHow::UINT, lpRect::Ptr{Cint}, cKids::UINT, lpKids::Ptr{Cint})::WORD
end

function CascadeWindows(hwndParent, wHow, lpRect, cKids, lpKids)
    @ccall user32.CascadeWindows(hwndParent::Cint, wHow::UINT, lpRect::Ptr{Cint}, cKids::UINT, lpKids::Ptr{Cint})::WORD
end

const HELPPOLY = DWORD

struct tagMULTIKEYHELPA
    mkSize::DWORD
    mkKeylist::CHAR
    szKeyphrase::NTuple{1, CHAR}
end

const MULTIKEYHELPA = tagMULTIKEYHELPA

const PMULTIKEYHELPA = Ptr{tagMULTIKEYHELPA}

const LPMULTIKEYHELPA = Ptr{tagMULTIKEYHELPA}

struct tagMULTIKEYHELPW
    mkSize::DWORD
    mkKeylist::WCHAR
    szKeyphrase::NTuple{1, WCHAR}
end

const MULTIKEYHELPW = tagMULTIKEYHELPW

const PMULTIKEYHELPW = Ptr{tagMULTIKEYHELPW}

const LPMULTIKEYHELPW = Ptr{tagMULTIKEYHELPW}

const MULTIKEYHELP = MULTIKEYHELPA

const PMULTIKEYHELP = PMULTIKEYHELPA

const LPMULTIKEYHELP = LPMULTIKEYHELPA

struct tagHELPWININFOA
    wStructSize::Cint
    x::Cint
    y::Cint
    dx::Cint
    dy::Cint
    wMax::Cint
    rgchMember::NTuple{2, CHAR}
end

const HELPWININFOA = tagHELPWININFOA

const PHELPWININFOA = Ptr{tagHELPWININFOA}

const LPHELPWININFOA = Ptr{tagHELPWININFOA}

struct tagHELPWININFOW
    wStructSize::Cint
    x::Cint
    y::Cint
    dx::Cint
    dy::Cint
    wMax::Cint
    rgchMember::NTuple{2, WCHAR}
end

const HELPWININFOW = tagHELPWININFOW

const PHELPWININFOW = Ptr{tagHELPWININFOW}

const LPHELPWININFOW = Ptr{tagHELPWININFOW}

const HELPWININFO = HELPWININFOA

const PHELPWININFO = PHELPWININFOA

const LPHELPWININFO = LPHELPWININFOA

function WinHelpW(hWndMain, lpszHelp, uCommand, dwData)
    @ccall user32.WinHelpW(hWndMain::Cint, lpszHelp::LPCWSTR, uCommand::UINT, dwData::ULONG_PTR)::BOOL
end

function GetGuiResources(hProcess, uiFlags)
    @ccall user32.GetGuiResources(hProcess::HANDLE, uiFlags::DWORD)::DWORD
end

struct tagMINIMIZEDMETRICS
    cbSize::UINT
    iWidth::Cint
    iHorzGap::Cint
    iVertGap::Cint
    iArrange::Cint
end

const MINIMIZEDMETRICS = tagMINIMIZEDMETRICS

const PMINIMIZEDMETRICS = Ptr{tagMINIMIZEDMETRICS}

const LPMINIMIZEDMETRICS = Ptr{tagMINIMIZEDMETRICS}

struct tagANIMATIONINFO
    cbSize::UINT
    iMinAnimate::Cint
end

const ANIMATIONINFO = tagANIMATIONINFO

const LPANIMATIONINFO = Ptr{tagANIMATIONINFO}

struct tagSERIALKEYSA
    cbSize::UINT
    dwFlags::DWORD
    lpszActivePort::LPSTR
    lpszPort::LPSTR
    iBaudRate::UINT
    iPortState::UINT
    iActive::UINT
end

const SERIALKEYSA = tagSERIALKEYSA

const LPSERIALKEYSA = Ptr{tagSERIALKEYSA}

struct tagSERIALKEYSW
    cbSize::UINT
    dwFlags::DWORD
    lpszActivePort::LPWSTR
    lpszPort::LPWSTR
    iBaudRate::UINT
    iPortState::UINT
    iActive::UINT
end

const SERIALKEYSW = tagSERIALKEYSW

const LPSERIALKEYSW = Ptr{tagSERIALKEYSW}

const SERIALKEYS = SERIALKEYSA

const LPSERIALKEYS = LPSERIALKEYSA

struct tagHIGHCONTRASTA
    cbSize::UINT
    dwFlags::DWORD
    lpszDefaultScheme::LPSTR
end

const HIGHCONTRASTA = tagHIGHCONTRASTA

const LPHIGHCONTRASTA = Ptr{tagHIGHCONTRASTA}

struct tagHIGHCONTRASTW
    cbSize::UINT
    dwFlags::DWORD
    lpszDefaultScheme::LPWSTR
end

const HIGHCONTRASTW = tagHIGHCONTRASTW

const LPHIGHCONTRASTW = Ptr{tagHIGHCONTRASTW}

const HIGHCONTRAST = HIGHCONTRASTA

const LPHIGHCONTRAST = LPHIGHCONTRASTA

function SystemParametersInfoW(uiAction, uiParam, _Post_valid_)
    @ccall user32.SystemParametersInfoW(uiAction::UINT, uiParam::UINT, _Post_valid_::Cint)::BOOL
end

struct tagFILTERKEYS
    cbSize::UINT
    dwFlags::DWORD
    iWaitMSec::DWORD
    iDelayMSec::DWORD
    iRepeatMSec::DWORD
    iBounceMSec::DWORD
end

const FILTERKEYS = tagFILTERKEYS

const LPFILTERKEYS = Ptr{tagFILTERKEYS}

struct tagSTICKYKEYS
    cbSize::UINT
    dwFlags::DWORD
end

const STICKYKEYS = tagSTICKYKEYS

const LPSTICKYKEYS = Ptr{tagSTICKYKEYS}

struct tagMOUSEKEYS
    cbSize::UINT
    dwFlags::DWORD
    iMaxSpeed::DWORD
    iTimeToMaxSpeed::DWORD
    iCtrlSpeed::DWORD
    dwReserved1::DWORD
    dwReserved2::DWORD
end

const MOUSEKEYS = tagMOUSEKEYS

const LPMOUSEKEYS = Ptr{tagMOUSEKEYS}

struct tagACCESSTIMEOUT
    cbSize::UINT
    dwFlags::DWORD
    iTimeOutMSec::DWORD
end

const ACCESSTIMEOUT = tagACCESSTIMEOUT

const LPACCESSTIMEOUT = Ptr{tagACCESSTIMEOUT}

struct tagSOUNDSENTRYA
    cbSize::UINT
    dwFlags::DWORD
    iFSTextEffect::DWORD
    iFSTextEffectMSec::DWORD
    iFSTextEffectColorBits::DWORD
    iFSGrafEffect::DWORD
    iFSGrafEffectMSec::DWORD
    iFSGrafEffectColor::DWORD
    iWindowsEffect::DWORD
    iWindowsEffectMSec::DWORD
    lpszWindowsEffectDLL::LPSTR
    iWindowsEffectOrdinal::DWORD
end

const SOUNDSENTRYA = tagSOUNDSENTRYA

const LPSOUNDSENTRYA = Ptr{tagSOUNDSENTRYA}

struct tagSOUNDSENTRYW
    cbSize::UINT
    dwFlags::DWORD
    iFSTextEffect::DWORD
    iFSTextEffectMSec::DWORD
    iFSTextEffectColorBits::DWORD
    iFSGrafEffect::DWORD
    iFSGrafEffectMSec::DWORD
    iFSGrafEffectColor::DWORD
    iWindowsEffect::DWORD
    iWindowsEffectMSec::DWORD
    lpszWindowsEffectDLL::LPWSTR
    iWindowsEffectOrdinal::DWORD
end

const SOUNDSENTRYW = tagSOUNDSENTRYW

const LPSOUNDSENTRYW = Ptr{tagSOUNDSENTRYW}

const SOUNDSENTRY = SOUNDSENTRYA

const LPSOUNDSENTRY = LPSOUNDSENTRYA

struct tagTOGGLEKEYS
    cbSize::UINT
    dwFlags::DWORD
end

const TOGGLEKEYS = tagTOGGLEKEYS

const LPTOGGLEKEYS = Ptr{tagTOGGLEKEYS}

function SetDebugErrorLevel(dwLevel)
    @ccall user32.SetDebugErrorLevel(dwLevel::DWORD)::Cvoid
end

function SetLastErrorEx(dwErrCode, dwType)
    @ccall user32.SetLastErrorEx(dwErrCode::DWORD, dwType::DWORD)::Cvoid
end

function InternalGetWindowText(hWnd, pString, cchMaxCount)
    @ccall user32.InternalGetWindowText(hWnd::Cint, pString::LPWSTR, cchMaxCount::Cint)::Cint
end

function EndTask(hWnd, fShutDown, fForce)
    @ccall user32.EndTask(hWnd::Cint, fShutDown::BOOL, fForce::BOOL)::BOOL
end

function CancelShutdown()
    @ccall user32.CancelShutdown()::BOOL
end

function MonitorFromPoint(pt, dwFlags)
    @ccall user32.MonitorFromPoint(pt::Cint, dwFlags::DWORD)::Cint
end

function MonitorFromRect(lprc, dwFlags)
    @ccall user32.MonitorFromRect(lprc::Cint, dwFlags::DWORD)::Cint
end

function MonitorFromWindow(hwnd, dwFlags)
    @ccall user32.MonitorFromWindow(hwnd::Cint, dwFlags::DWORD)::Cint
end

const MONITORINFO = tagMONITORINFO

struct tagMONITORINFOEXA
    szDevice::NTuple{32, CHAR}
end

const MONITORINFOEXA = tagMONITORINFOEXA

const LPMONITORINFOEXA = Ptr{tagMONITORINFOEXA}

struct tagMONITORINFOEXW
    szDevice::NTuple{32, WCHAR}
end

const MONITORINFOEXW = tagMONITORINFOEXW

const LPMONITORINFOEXW = Ptr{tagMONITORINFOEXW}

const MONITORINFOEX = MONITORINFOEXA

const LPMONITORINFOEX = LPMONITORINFOEXA

function GetMonitorInfoW(hMonitor, lpmi)
    @ccall user32.GetMonitorInfoW(hMonitor::Cint, lpmi::LPMONITORINFO)::BOOL
end

function EnumDisplayMonitors(hdc, lprcClip, lpfnEnum, dwData)
    @ccall user32.EnumDisplayMonitors(hdc::Cint, lprcClip::Cint, lpfnEnum::MONITORENUMPROC, dwData::LPARAM)::BOOL
end

function NotifyWinEvent(event, hwnd, idObject, idChild)
    @ccall user32.NotifyWinEvent(event::DWORD, hwnd::Cint, idObject::LONG, idChild::LONG)::Cvoid
end

# typedef VOID ( CALLBACK * WINEVENTPROC ) ( HWINEVENTHOOK hWinEventHook , DWORD event , HWND hwnd , LONG idObject , LONG idChild , DWORD idEventThread , DWORD dwmsEventTime )
const WINEVENTPROC = Ptr{Cvoid}

function SetWinEventHook(eventMin, eventMax, hmodWinEventProc, pfnWinEventProc, idProcess, idThread, dwFlags)
    @ccall user32.SetWinEventHook(eventMin::DWORD, eventMax::DWORD, hmodWinEventProc::HMODULE, pfnWinEventProc::WINEVENTPROC, idProcess::DWORD, idThread::DWORD, dwFlags::DWORD)::Cint
end

function IsWinEventHookInstalled(event)
    @ccall user32.IsWinEventHookInstalled(event::DWORD)::BOOL
end

function UnhookWinEvent(hWinEventHook)
    @ccall user32.UnhookWinEvent(hWinEventHook::Cint)::BOOL
end

struct tagGUITHREADINFO
    cbSize::DWORD
    flags::DWORD
    hwndActive::Cint
    hwndFocus::Cint
    hwndCapture::Cint
    hwndMenuOwner::Cint
    hwndMoveSize::Cint
    hwndCaret::Cint
    rcCaret::Cint
end

const GUITHREADINFO = tagGUITHREADINFO

const PGUITHREADINFO = Ptr{tagGUITHREADINFO}

const LPGUITHREADINFO = Ptr{tagGUITHREADINFO}

function GetGUIThreadInfo(idThread, pgui)
    @ccall user32.GetGUIThreadInfo(idThread::DWORD, pgui::PGUITHREADINFO)::BOOL
end

function BlockInput(fBlockIt)
    @ccall user32.BlockInput(fBlockIt::BOOL)::BOOL
end

function GetWindowModuleFileNameW(hwnd, pszFileName, cchFileNameMax)
    @ccall user32.GetWindowModuleFileNameW(hwnd::Cint, pszFileName::LPWSTR, cchFileNameMax::UINT)::UINT
end

struct tagCURSORINFO
    cbSize::DWORD
    flags::DWORD
    hCursor::Cint
    ptScreenPos::Cint
end

const CURSORINFO = tagCURSORINFO

const PCURSORINFO = Ptr{tagCURSORINFO}

const LPCURSORINFO = Ptr{tagCURSORINFO}

function GetCursorInfo(pci)
    @ccall user32.GetCursorInfo(pci::PCURSORINFO)::BOOL
end

struct tagWINDOWINFO
    cbSize::DWORD
    rcWindow::Cint
    rcClient::Cint
    dwStyle::DWORD
    dwExStyle::DWORD
    dwWindowStatus::DWORD
    cxWindowBorders::UINT
    cyWindowBorders::UINT
    atomWindowType::ATOM
    wCreatorVersion::WORD
end

const WINDOWINFO = tagWINDOWINFO

const PWINDOWINFO = Ptr{tagWINDOWINFO}

const LPWINDOWINFO = Ptr{tagWINDOWINFO}

function GetWindowInfo(hwnd, pwi)
    @ccall user32.GetWindowInfo(hwnd::Cint, pwi::PWINDOWINFO)::BOOL
end

struct tagTITLEBARINFO
    cbSize::DWORD
    rcTitleBar::Cint
    rgstate::NTuple{6, DWORD}
end

const TITLEBARINFO = tagTITLEBARINFO

const PTITLEBARINFO = Ptr{tagTITLEBARINFO}

const LPTITLEBARINFO = Ptr{tagTITLEBARINFO}

function GetTitleBarInfo(hwnd, pti)
    @ccall user32.GetTitleBarInfo(hwnd::Cint, pti::PTITLEBARINFO)::BOOL
end

struct tagMENUBARINFO
    cbSize::DWORD
    rcBar::Cint
    hMenu::Cint
    hwndMenu::Cint
    fBarFocused::BOOL
    fFocused::BOOL
    fUnused::BOOL
end

const MENUBARINFO = tagMENUBARINFO

const PMENUBARINFO = Ptr{tagMENUBARINFO}

const LPMENUBARINFO = Ptr{tagMENUBARINFO}

function GetMenuBarInfo(hwnd, idObject, idItem, pmbi)
    @ccall user32.GetMenuBarInfo(hwnd::Cint, idObject::LONG, idItem::LONG, pmbi::PMENUBARINFO)::BOOL
end

struct tagSCROLLBARINFO
    cbSize::DWORD
    rcScrollBar::Cint
    dxyLineButton::Cint
    xyThumbTop::Cint
    xyThumbBottom::Cint
    reserved::Cint
    rgstate::NTuple{6, DWORD}
end

const SCROLLBARINFO = tagSCROLLBARINFO

const PSCROLLBARINFO = Ptr{tagSCROLLBARINFO}

const LPSCROLLBARINFO = Ptr{tagSCROLLBARINFO}

function GetScrollBarInfo(hwnd, idObject, psbi)
    @ccall user32.GetScrollBarInfo(hwnd::Cint, idObject::LONG, psbi::PSCROLLBARINFO)::BOOL
end

struct tagCOMBOBOXINFO
    cbSize::DWORD
    rcItem::Cint
    rcButton::Cint
    stateButton::DWORD
    hwndCombo::Cint
    hwndItem::Cint
    hwndList::Cint
end

const COMBOBOXINFO = tagCOMBOBOXINFO

const PCOMBOBOXINFO = Ptr{tagCOMBOBOXINFO}

const LPCOMBOBOXINFO = Ptr{tagCOMBOBOXINFO}

function GetComboBoxInfo(hwndCombo, pcbi)
    @ccall user32.GetComboBoxInfo(hwndCombo::Cint, pcbi::PCOMBOBOXINFO)::BOOL
end

function GetAncestor(hwnd, gaFlags)
    @ccall user32.GetAncestor(hwnd::Cint, gaFlags::UINT)::Cint
end

function RealChildWindowFromPoint(hwndParent, ptParentClientCoords)
    @ccall user32.RealChildWindowFromPoint(hwndParent::Cint, ptParentClientCoords::Cint)::Cint
end

function RealGetWindowClassW(hwnd, ptszClassName, cchClassNameMax)
    @ccall user32.RealGetWindowClassW(hwnd::Cint, ptszClassName::LPWSTR, cchClassNameMax::UINT)::UINT
end

const ALTTABINFO = tagALTTABINFO

const LPALTTABINFO = Ptr{tagALTTABINFO}

function GetAltTabInfoW(hwnd, iItem, pati, pszItemText, cchItemText)
    @ccall user32.GetAltTabInfoW(hwnd::Cint, iItem::Cint, pati::PALTTABINFO, pszItemText::LPWSTR, cchItemText::UINT)::BOOL
end

function GetListBoxInfo(hwnd)
    @ccall user32.GetListBoxInfo(hwnd::Cint)::DWORD
end

function LockWorkStation()
    @ccall user32.LockWorkStation()::BOOL
end

function UserHandleGrantAccess(hUserHandle, hJob, bGrant)
    @ccall user32.UserHandleGrantAccess(hUserHandle::HANDLE, hJob::HANDLE, bGrant::BOOL)::BOOL
end

struct HRAWINPUT__
    unused::Cint
end

const HRAWINPUT = Ptr{HRAWINPUT__}

const PRAWINPUTHEADER = Ptr{tagRAWINPUTHEADER}

const LPRAWINPUTHEADER = Ptr{tagRAWINPUTHEADER}

const PRAWMOUSE = Ptr{tagRAWMOUSE}

const LPRAWMOUSE = Ptr{tagRAWMOUSE}

const PRAWKEYBOARD = Ptr{tagRAWKEYBOARD}

const LPRAWKEYBOARD = Ptr{tagRAWKEYBOARD}

const PRAWHID = Ptr{tagRAWHID}

const LPRAWHID = Ptr{tagRAWHID}

const RAWINPUT = tagRAWINPUT

const LPRAWINPUT = Ptr{tagRAWINPUT}

function GetRawInputData(hRawInput, uiCommand, pData, pcbSize, cbSizeHeader)
    @ccall user32.GetRawInputData(hRawInput::HRAWINPUT, uiCommand::UINT, pData::LPVOID, pcbSize::PUINT, cbSizeHeader::UINT)::UINT
end

struct tagRID_DEVICE_INFO_MOUSE
    dwId::DWORD
    dwNumberOfButtons::DWORD
    dwSampleRate::DWORD
    fHasHorizontalWheel::BOOL
end

const RID_DEVICE_INFO_MOUSE = tagRID_DEVICE_INFO_MOUSE

const PRID_DEVICE_INFO_MOUSE = Ptr{tagRID_DEVICE_INFO_MOUSE}

struct tagRID_DEVICE_INFO_KEYBOARD
    dwType::DWORD
    dwSubType::DWORD
    dwKeyboardMode::DWORD
    dwNumberOfFunctionKeys::DWORD
    dwNumberOfIndicators::DWORD
    dwNumberOfKeysTotal::DWORD
end

const RID_DEVICE_INFO_KEYBOARD = tagRID_DEVICE_INFO_KEYBOARD

const PRID_DEVICE_INFO_KEYBOARD = Ptr{tagRID_DEVICE_INFO_KEYBOARD}

struct tagRID_DEVICE_INFO_HID
    dwVendorId::DWORD
    dwProductId::DWORD
    dwVersionNumber::DWORD
    usUsagePage::USHORT
    usUsage::USHORT
end

const RID_DEVICE_INFO_HID = tagRID_DEVICE_INFO_HID

const PRID_DEVICE_INFO_HID = Ptr{tagRID_DEVICE_INFO_HID}

struct tagRID_DEVICE_INFO
    data::NTuple{32, UInt8}
end

function Base.getproperty(x::Ptr{tagRID_DEVICE_INFO}, f::Symbol)
    f === :cbSize && return Ptr{DWORD}(x + 0)
    f === :dwType && return Ptr{DWORD}(x + 4)
    f === :mouse && return Ptr{RID_DEVICE_INFO_MOUSE}(x + 8)
    f === :keyboard && return Ptr{RID_DEVICE_INFO_KEYBOARD}(x + 8)
    f === :hid && return Ptr{RID_DEVICE_INFO_HID}(x + 8)
    return getfield(x, f)
end

function Base.getproperty(x::tagRID_DEVICE_INFO, f::Symbol)
    r = Ref{tagRID_DEVICE_INFO}(x)
    ptr = Base.unsafe_convert(Ptr{tagRID_DEVICE_INFO}, r)
    fptr = getproperty(ptr, f)
    GC.@preserve r unsafe_load(fptr)
end

function Base.setproperty!(x::Ptr{tagRID_DEVICE_INFO}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end

function tagRID_DEVICE_INFO(cbSize::DWORD, dwType::DWORD)
    ref = Ref{tagRID_DEVICE_INFO}()
    ptr = Base.unsafe_convert(Ptr{tagRID_DEVICE_INFO}, ref)
    ptr.cbSize = cbSize
    ptr.dwType = dwType
    ref[]
end

const RID_DEVICE_INFO = tagRID_DEVICE_INFO

const PRID_DEVICE_INFO = Ptr{tagRID_DEVICE_INFO}

const LPRID_DEVICE_INFO = Ptr{tagRID_DEVICE_INFO}

function GetRawInputDeviceInfoW(hDevice, uiCommand, pData, pcbSize)
    @ccall user32.GetRawInputDeviceInfoW(hDevice::HANDLE, uiCommand::UINT, pData::LPVOID, pcbSize::PUINT)::UINT
end

function GetRawInputBuffer(pData, pcbSize, cbSizeHeader)
    @ccall user32.GetRawInputBuffer(pData::PRAWINPUT, pcbSize::PUINT, cbSizeHeader::UINT)::UINT
end

struct tagRAWINPUTDEVICE
    usUsagePage::USHORT
    usUsage::USHORT
    dwFlags::DWORD
    hwndTarget::Cint
end

const RAWINPUTDEVICE = tagRAWINPUTDEVICE

const PRAWINPUTDEVICE = Ptr{tagRAWINPUTDEVICE}

const LPRAWINPUTDEVICE = Ptr{tagRAWINPUTDEVICE}

const PCRAWINPUTDEVICE = Ptr{RAWINPUTDEVICE}

function RegisterRawInputDevices(pRawInputDevices, uiNumDevices, cbSize)
    @ccall user32.RegisterRawInputDevices(pRawInputDevices::PCRAWINPUTDEVICE, uiNumDevices::UINT, cbSize::UINT)::BOOL
end

function GetRegisteredRawInputDevices(pRawInputDevices, puiNumDevices, cbSize)
    @ccall user32.GetRegisteredRawInputDevices(pRawInputDevices::PRAWINPUTDEVICE, puiNumDevices::PUINT, cbSize::UINT)::UINT
end

struct tagRAWINPUTDEVICELIST
    hDevice::HANDLE
    dwType::DWORD
end

const RAWINPUTDEVICELIST = tagRAWINPUTDEVICELIST

const PRAWINPUTDEVICELIST = Ptr{tagRAWINPUTDEVICELIST}

function GetRawInputDeviceList(pRawInputDeviceList, puiNumDevices, cbSize)
    @ccall user32.GetRawInputDeviceList(pRawInputDeviceList::PRAWINPUTDEVICELIST, puiNumDevices::PUINT, cbSize::UINT)::UINT
end

function DefRawInputProc(paRawInput, nInput, cbSizeHeader)
    @ccall user32.DefRawInputProc(paRawInput::Ptr{PRAWINPUT}, nInput::INT, cbSizeHeader::UINT)::LRESULT
end

function ShutdownBlockReasonCreate(hWnd, pwszReason)
    @ccall user32.ShutdownBlockReasonCreate(hWnd::Cint, pwszReason::LPCWSTR)::BOOL
end

function ShutdownBlockReasonQuery(hWnd, pwszBuff, pcchBuff)
    @ccall user32.ShutdownBlockReasonQuery(hWnd::Cint, pwszBuff::LPWSTR, pcchBuff::Ptr{DWORD})::BOOL
end

function ShutdownBlockReasonDestroy(hWnd)
    @ccall user32.ShutdownBlockReasonDestroy(hWnd::Cint)::BOOL
end

