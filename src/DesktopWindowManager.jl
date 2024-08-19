module DesktopWindowManager

using Base: cconvert, unsafe_convert
using CEnum: @cenum
using BitMasks

const kernel32 = :kernel32
const user32 = :user32

const WORD = UInt16
const DWORD = UInt64

# We always use the short versions of windows structs/functions.
include("winapi/errors.jl")
include("winapi/types.jl")
include("winapi/functions.jl")

const FunctionPtr = Union{Ptr{Cvoid}, Base.CFunction}

const instance = Ref(C_NULL)

function __init__()
  if Sys.iswindows()
    instance[] = get_module_handle()
  end
end

is_an_error(ret) = iszero(ret)
is_an_error(ret::Ptr) = ret == typeof(ret)(0)

macro check(ex)
  quote
    ret = $(esc(ex))
    if is_an_error(ret)
      err = ErrorCode(get_last_error())
      error("$(bitmask_name(err)): failed to execute ", $(string(ex)))
    end
    ret
  end
end

function create_window_class(window_callback::FunctionPtr, class_name)
  class_name = cconvert(Ptr{Cchar}, class_name)
  window_class = WindowClass(WNDCLASS(sizeof(WNDCLASS), 0, window_callback, 0, 0, instance[], C_NULL, C_NULL, C_NULL, C_NULL, unsafe_convert(Ptr{Cchar}, class_name), C_NULL), [class_name])
  @check register_class(window_class)
  window_class
end

create_window(class::WindowClass, name, style::WindowStyle) = create_window(class.api.lpszClassName, name, style)
function create_window(class_name, name, style::WindowStyle)
  @check create_window(0, class_name, name, style, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 720, C_NULL, C_NULL, C_NULL)
end

map_window(window) = show_window(window, SW_SHOW)
unmap_window(window) = show_window(window, SW_HIDE)

export get_module_handle, @check, WindowMessage

end
