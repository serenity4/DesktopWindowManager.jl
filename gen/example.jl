using Clang
using Clang.Generators

WIN_INCLUDE = "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um"
WIN_HEADERS = [joinpath(WIN_INCLUDE, "winuser.h")]

target = "x86_64-w64-mingw32"
args = get_default_args(target)
push!(args, "-I$WIN_INCLUDE")
tu = Clang.parse_headers(Index(), WIN_HEADERS, args)[1]
root_cursor = Clang.getTranslationUnitCursor(tu)
s1 = only(search(root_cursor, "tagCBT_CREATEWNDA"))
fields(Clang.getCursorType(s1))
children(s1)
