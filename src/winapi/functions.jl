function get_module_handle()
  @ccall kernel32.GetModuleHandleA(C_NULL::Ptr{Cchar})::Ptr{Cvoid}
end

function get_last_error()
  @ccall kernel32.GetLastError()::DWORD
end

function register_class(window_class)
  @ccall user32.RegisterClassExA(window_class::Ptr{WNDCLASS})::UInt16
end

function create_window(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, lpParam)
  @ccall user32.CreateWindowExA(dwExStyle::DWORD, lpClassName::Ptr{Cchar}, lpWindowName::Ptr{Cchar}, dwStyle::DWORD, X::Cint, Y::Cint, nWidth::Cint, nHeight::Cint, hWndParent::Ptr{Cvoid}, hMenu::Ptr{Cvoid}, hInstance[]::Ptr{Cvoid}, lpParam::Ptr{Cvoid})::Ptr{Cvoid}
end

function show_window(window, mode)
  ret = @ccall user32.ShowWindow(window::Ptr{Cvoid}, mode::Cint)::Cint
  !iszero(ret)
end
