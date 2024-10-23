struct WNDCLASS
  cbSize::Cuint
  style::Cuint
  lpfnWndProc::Ptr{Cvoid}
  cbClsExtra::Cint
  cbWndExtra::Cint
  hInstance::Ptr{Cvoid}
  hIcon::Ptr{Cvoid}
  hCursor::Ptr{Cvoid}
  hbrBackground::Ptr{Cvoid}
  lpszMenuName::Ptr{Cchar}
  lpszClassName::Ptr{Cchar}
  hIconSm::Ptr{Cvoid}
end

struct WindowClass <: WinAPIStruct{true}
  win::WNDCLASS
  deps::Vector{Any}
end

struct WinAPIMessage
  hwnd::Ptr{Cvoid}
  message::Cuint
  wparam::Ptr{UInt32}
  lparam::Ptr{Cvoid}
  time::DWORD
  pt::NTuple{2, Cint}
  lPrivate::DWORD
end

struct Message <: WinAPIStruct{true}
  win::WinAPIMessage
  deps::Vector{Any}
end
