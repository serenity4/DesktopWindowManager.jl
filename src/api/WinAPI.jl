module WinAPI

__precompile__(false)

const FunctionPtr = Union{Ptr{Cvoid}, Base.CFunction}

using CEnum

# System-dependent definitions.
const BOOL = Cint
# const DWORD = Culong
# const DWORD_PTR = Ptr{DWORD}
# const WINBOOL = BOOL

const GRAYSTRINGPROC = Ptr{Cvoid}
const WNDENUMPROC = Ptr{Cvoid}
const HOOKPROC = Ptr{Cvoid}
const SENDASYNCPROC = Ptr{Cvoid}
const PROPENUMPROCA = Ptr{Cvoid}
const PROPENUMPROCW = Ptr{Cvoid}
const PROPENUMPROCEXA = Ptr{Cvoid}
const PROPENUMPROCEXW = Ptr{Cvoid}
const WNDPROC = Ptr{Cvoid}
const DLGPROC = Ptr{Cvoid}
const EXCEPTION_ROUTINE = Ptr{Cvoid}
const TIMERPROC = Ptr{Cvoid}
const MONITORENUMPROC = Ptr{Cvoid}
const MSGBOXCALLBACK = Ptr{Cvoid}

const CALLBACK = FunctionPtr
MAKEINTRESOURCEA(i) = Ptr{Cuchar}(i)
MAKEINTRESOURCEW(i) = Ptr{Cwchar_t}(i)

# TODO
IO(x, y) = nothing
IOR(x, y, t) = nothing
IOW(x, y, t) = nothing
CTL_CODE(DeviceType, Function, Method, Access) = nothing
OLE_STR(str) = str
MDM_GEN_PROTOCOLINFO(_pid, _pdata) = nothing
MDM_GEN_ANALOG_PROTOCOL_DATA(_rlp) = _rlp
FIELD_OFFSET(type, field) = nothing
UFIELD_OFFSET(type, field) = nothing
RtlEqualMemory(Destination, Source, Length) = nothing # (!memcmp((Destination), (Source), (Length)))
RtlMoveMemory(Destination, Source, Length) = nothing # memmove((Destination), (Source), (Length))
RtlCopyMemory(Destination, Source, Length) = nothing # memcpy((Destination), (Source), (Length))
RtlFillMemory(Destination, Length, Fill) = nothing # memset((Destination), (Fill), (Length))
RtlZeroMemory(Destination, Length) = nothing # memset((Destination), 0, (Length))
ProcThreadAttributeValue(Number, Thread, Input, Additive) = nothing
LongToHandle(h) = HANDLE(UInt(0) + h)
GET_DEVICE_LPARAM(lParam) = nothing
MAKEINTATOM(i) = nothing

TEXT(str) = str
const ui64 = UInt64(1)
const XSTATE_AVX512_ZMM_H = 6
const MINLONG64 = nothing
const UINT_MAX = 0xffffffff
const NULL = C_NULL
const NO_ERROR = Int32(0)
const WINAPI = nothing

user32 = :user32
include("../../gen/library.jl")
include("post.jl")
# include("user32.jl")


end # module
