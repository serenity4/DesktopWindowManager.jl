module DesktopWindowManager

using Base: RefValue, CFunction
import Base: convert, unsafe_convert
using CEnum: @cenum
using BitMasks
using Reexport

using WindowAbstractions

const kernel32 = :kernel32
const user32 = :user32

const WORD = UInt16
const DWORD = UInt64

const FunctionPtr = Union{Ptr{Cvoid}, CFunction}
const Optional{T} = Union{T, Nothing}

# We always use the short versions of Windows structs/functions.
include("winapi/enums.jl")
include("winapi/constants.jl")
include("winapi/pointers.jl")
include("winapi/errors.jl")
include("winapi/types.jl")
include("winapi/functions.jl")

include("window.jl")
include("window_manager.jl")
include("events.jl")

const hInstance = Ref(C_NULL)

is_supported() = hInstance[] ≠ C_NULL

function __init__()
  if Sys.iswindows()
    hInstance[] = get_module_handle()
  end
end

export WindowManager, Window
@reexport using WindowAbstractions

export
      @check,
      WindowMessage,
      Window,
      WindowManager

end
