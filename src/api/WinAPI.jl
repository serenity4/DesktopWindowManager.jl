module WinAPI

using CEnum

# System-dependent definitions.
const BOOL = Cint
const DWORD = Culong
const DWORD_PTR = Ptr{DWORD}
const WINBOOL = BOOL

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

user32 = :user32

include("user32.jl")

end # module
