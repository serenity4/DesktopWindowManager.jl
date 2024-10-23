function create_window_class(window_callback::FunctionPtr, class_name)
  class_name = cconvert(Ptr{Cchar}, class_name)
  window_class = WindowClass(WNDCLASS(sizeof(WNDCLASS), 0, unsafe_convert(Ptr{Cvoid}, window_callback), 0, 0, hInstance[], C_NULL, C_NULL, C_NULL, C_NULL, unsafe_convert(Ptr{Cchar}, class_name), C_NULL), [class_name])
  @check register_class(window_class)
  window_class
end

function create_window(class_name::Ptr{Cchar}, name, style::WindowStyle, data_ptr)
  create_window(0, class_name, name, style, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 720, C_NULL, C_NULL, data_ptr)
end

mutable struct Window <: AbstractWindow
  handle::Ptr{Cvoid}
  callback::CFunction
  user_data_ref#::RefValue(CallbackData)
  Window() = new()
end

Base.unsafe_convert(::Type{Ptr{Cvoid}}, window::Window) = window.handle

destroy_window(window::Window) = @ccall user32.DestroyWindow(window::Ptr{Cvoid})::Bool

revised_window_callback(callback) = (hwnd, msg, wparam, lparam) -> @invokelatest window_callback_internal(hwnd::Ptr{Cvoid}, msg::WindowMessage, wparam::Ptr{UInt32}, lparam::Ptr{Cvoid})

# https://learn.microsoft.com/en-us/windows/win32/winmsg/about-messages-and-message-queues#system-defined-messages
function window_callback_internal(hwnd::Ptr{Cvoid}, msg::WindowMessage, wparam::Ptr{UInt32}, lparam::Ptr{Cvoid})::Ptr{Cvoid}
  (; wm, window) = retrieve_callback_data(hwnd)
  @show msg
  @show UInt32(msg)
  if msg == WM_CREATE
    ptr = unsafe_load(Ptr{Ptr{Cvoid}}(lparam))
    set_window_user_data(hwnd, ptr)
  elseif msg == WM_DESTROY
    @ccall user32.SetWindowLongPtrA(hwnd::Ptr{Cvoid}, GWLP_USERDATA::Cint, C_NULL::Ptr{Cvoid})::Ptr{Cvoid}
    @ccall user32.PostQuitMessage(0::Cint)::Cvoid
    return 0
  elseif msg == WM_CLOSE
    finalize(window)
  end
  @ccall user32.DefWindowProcA(hwnd::Ptr{Cvoid}, msg::UInt32, wparam::Ptr{UInt32}, lparam::Ptr{Cvoid})::Ptr{Cvoid}
end

function retrieve_callback_data(hwnd::Ptr{Cvoid})
  data_ptr = @ccall user32.GetWindowLongPtrA(hwnd::Ptr{Cvoid}, GWLP_USERDATA::Cint)::Ptr{Cvoid}
  data_ptr == C_NULL && return (; wm = nothing, window = nothing)
  unsafe_load(Ptr{CallbackData}(data_ptr))
end

function set_window_user_data(hwnd, data_ptr)
  @ccall kernel32.SetLastError(0::Cint)::Cvoid
  @check @ccall user32.SetWindowLongPtrA(hwnd::Ptr{Cvoid}, GWLP_USERDATA::Cint, data_ptr::Ptr{Cvoid})::Ptr{Cvoid}
end

function WindowAbstractions.map_window(window::Window)
  ret = show_window(window, SW_SHOW)
  @check @ccall user32.UpdateWindow(window::Ptr{Cvoid})::Bool
  ret
end

WindowAbstractions.unmap_window(window::Window) = show_window(window, SW_HIDE)
