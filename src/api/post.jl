function EncodePointer(ptr)
  @ccall user32.EncodePointer(ptr::PVOID)::PVOID
end

function DecodePointer(ptr)
  @ccall user32.DecodePointer(ptr::PVOID)::PVOID
end

function EncodeSystemPointer(ptr)
  @ccall user32.EncodeSystemPointer(ptr::PVOID)::PVOID
end

function DecodeSystemPointer(ptr)
  @ccall user32.DecodeSystemPointer(ptr::PVOID)::PVOID
end

function EncodeRemotePointer(ProcessHandle, Ptr, EncodedPtr)
  @ccall user32.EncodeRemotePointer(ProcessHandle::HANDLE, Ptr::PVOID, EncodedPtr::Ptr{PVOID})::HRESULT
end

function DecodeRemotePointer(ProcessHandle, Ptr, DecodedPtr)
  @ccall user32.DecodeRemotePointer(ProcessHandle::HANDLE, Ptr::PVOID, DecodedPtr::Ptr{PVOID})::HRESULT
end


const MEMORY_CURRENT_PARTITION_HANDLE = Ptr{Cvoid}(UInt(0) - 1)
const MEMORY_SYSTEM_PARTITION_HANDLE = Ptr{Cvoid}(UInt(0) - 2)
const MEMORY_EXISTING_VAD_PARTITION_HANDLE = Ptr{Cvoid}(UInt(0) - 3)

const MEM_DEDICATED_ATTRIBUTE_NOT_SPECIFIED = DWORD64(DWORD64(0) - 1)

const MAILSLOT_NO_MESSAGE = DWORD(DWORD(0) - 1)
const MAILSLOT_WAIT_FOREVER = DWORD(DWORD(0) - 1)
const NUMA_NO_PREFERRED_NODE = DWORD(DWORD(0) - 1)
const INVALID_SET_FILE_POINTER = DWORD(DWORD(0) - 1)
const INVALID_FILE_ATTRIBUTES = DWORD(DWORD(0) - 1)
const STD_INPUT_HANDLE = DWORD(DWORD(0) - 10)
const STD_OUTPUT_HANDLE = DWORD(DWORD(0) - 11)
const STD_ERROR_HANDLE = DWORD(DWORD(0) - 12)
const ASFW_ANY = DWORD(DWORD(0) - 1)
const ENUM_CURRENT_SETTINGS = DWORD(DWORD(0) - 1)
const ENUM_REGISTRY_SETTINGS = DWORD(DWORD(0) - 2)
const ATTACH_PARENT_PROCESS = DWORD(DWORD(0) - 1)
const SCARD_AUTOALLOCATE = DWORD(DWORD(0) - 1)
const SCARD_READER_SEL_AUTH_PACKAGE = DWORD(DWORD(0) - 629)
const IGP_GETIMEVERSION = DWORD(DWORD(0) - 4)
const IMAGE_SYM_CLASS_END_OF_FUNCTION = BYTE(BYTE(0) - 1)

const INVALID_HANDLE_VALUE = Ptr{Cvoid}(UInt(0) - 1)

const ERROR_FLT_NO_HANDLER_DEFINED = reinterpret(HRESULT, Culong(0x801f0001))
const ERROR_FLT_CONTEXT_ALREADY_DEFINED = reinterpret(HRESULT, Culong(0x801f0002))
const ERROR_FLT_INVALID_ASYNCHRONOUS_REQUEST = reinterpret(HRESULT, Culong(0x801f0003))
const ERROR_FLT_DISALLOW_FAST_IO = reinterpret(HRESULT, Culong(0x801f0004))
const ERROR_FLT_INVALID_NAME_REQUEST = reinterpret(HRESULT, Culong(0x801f0005))
const ERROR_FLT_NOT_SAFE_TO_POST_OPERATION = reinterpret(HRESULT, Culong(0x801f0006))
const ERROR_FLT_NOT_INITIALIZED = reinterpret(HRESULT, Culong(0x801f0007))
const ERROR_FLT_FILTER_NOT_READY = reinterpret(HRESULT, Culong(0x801f0008))
const ERROR_FLT_POST_OPERATION_CLEANUP = reinterpret(HRESULT, Culong(0x801f0009))
const ERROR_FLT_INTERNAL_ERROR = reinterpret(HRESULT, Culong(0x801f000a))
const ERROR_FLT_DELETING_OBJECT = reinterpret(HRESULT, Culong(0x801f000b))
const ERROR_FLT_MUST_BE_NONPAGED_POOL = reinterpret(HRESULT, Culong(0x801f000c))
const ERROR_FLT_DUPLICATE_ENTRY = reinterpret(HRESULT, Culong(0x801f000d))
const ERROR_FLT_CBDQ_DISABLED = reinterpret(HRESULT, Culong(0x801f000e))
const ERROR_FLT_DO_NOT_ATTACH = reinterpret(HRESULT, Culong(0x801f000f))
const ERROR_FLT_DO_NOT_DETACH = reinterpret(HRESULT, Culong(0x801f0010))
const ERROR_FLT_INSTANCE_ALTITUDE_COLLISION = reinterpret(HRESULT, Culong(0x801f0011))
const ERROR_FLT_INSTANCE_NAME_COLLISION = reinterpret(HRESULT, Culong(0x801f0012))
const ERROR_FLT_FILTER_NOT_FOUND = reinterpret(HRESULT, Culong(0x801f0013))
const ERROR_FLT_VOLUME_NOT_FOUND = reinterpret(HRESULT, Culong(0x801f0014))
const ERROR_FLT_INSTANCE_NOT_FOUND = reinterpret(HRESULT, Culong(0x801f0015))
const ERROR_FLT_CONTEXT_ALLOCATION_NOT_FOUND = reinterpret(HRESULT, Culong(0x801f0016))
const ERROR_FLT_INVALID_CONTEXT_REGISTRATION = reinterpret(HRESULT, Culong(0x801f0017))
const ERROR_FLT_NAME_CACHE_MISS = reinterpret(HRESULT, Culong(0x801f0018))
const ERROR_FLT_NO_DEVICE_OBJECT = reinterpret(HRESULT, Culong(0x801f0019))
const ERROR_FLT_VOLUME_ALREADY_MOUNTED = reinterpret(HRESULT, Culong(0x801f001a))
const ERROR_FLT_NO_WAITER_FOR_REPLY = reinterpret(HRESULT, Culong(0x801f0020))

const HWND_BROADCAST = HWND(UInt(0) + 0xffff)
const HWND_MESSAGE = HWND(UInt(0) + -3)
const HWND_DESKTOP = HWND(UInt(0) + 0)
const HWND_TOP = HWND(UInt(0) + 0)
const HWND_BOTTOM = HWND(UInt(0) + 1)
const HWND_TOPMOST = HWND(UInt(0) + -1)
const HWND_NOTOPMOST = HWND(UInt(0) + -2)

const CW_USEDEFAULT = reinterpret(Cint, 0x80000000)

const OBJID_WINDOW = reinterpret(LONG, 0x00000000)
const OBJID_SYSMENU = reinterpret(LONG, 0xffffffff)
const OBJID_TITLEBAR = reinterpret(LONG, 0xfffffffe)
const OBJID_MENU = reinterpret(LONG, 0xfffffffd)
const OBJID_CLIENT = reinterpret(LONG, 0xfffffffc)
const OBJID_VSCROLL = reinterpret(LONG, 0xfffffffb)
const OBJID_HSCROLL = reinterpret(LONG, 0xfffffffa)
const OBJID_SIZEGRIP = reinterpret(LONG, 0xfffffff9)
const OBJID_CARET = reinterpret(LONG, 0xfffffff8)
const OBJID_CURSOR = reinterpret(LONG, 0xfffffff7)
const OBJID_ALERT = reinterpret(LONG, 0xfffffff6)
const OBJID_SOUND = reinterpret(LONG, 0xfffffff5)
const OBJID_QUERYCLASSNAMEIDX = reinterpret(LONG, 0xfffffff4)
const OBJID_NATIVEOM = reinterpret(LONG, 0xfffffff0)

const HKEY_CLASSES_ROOT = HKEY(UInt(0x80000000))
const HKEY_CURRENT_USER = HKEY(UInt(0x80000001))
const HKEY_LOCAL_MACHINE = HKEY(UInt(0x80000002))
const HKEY_USERS = HKEY(UInt(0x80000003))
const HKEY_PERFORMANCE_DATA = HKEY(UInt(0x80000004))
const HKEY_PERFORMANCE_TEXT = HKEY(UInt(0x80000050))
const HKEY_PERFORMANCE_NLSTEXT = HKEY(UInt(0x80000060))
const HKEY_CURRENT_CONFIG = HKEY(UInt(0x80000005))
const HKEY_DYN_DATA = HKEY(UInt(0x80000006))
const HKEY_CURRENT_USER_LOCAL_SETTINGS = HKEY(UInt(0x80000007))
