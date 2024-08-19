# Fixes about the dependency graph being broken,
# where certain expressions use symbols before the definitions of these symbols.
# Similar fixes are in WinAPI.jl for system-dependent symbols.

struct _LUID
  LowPart::DWORD
  HighPart::LONG
end

const LUID = _LUID

const DWORD_PTR = Ptr{DWORD}

struct tagRAWMOUSE
  data::NTuple{24, UInt8}
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

const PRAWKEYBOARD = Ptr{tagRAWKEYBOARD}

const LPRAWKEYBOARD = Ptr{tagRAWKEYBOARD}
