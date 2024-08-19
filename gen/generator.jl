using Clang.Generators
using Clang.Generators.JLLEnvs

cd(@__DIR__)

WIN_INCLUDES = [
    "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um",
    # "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/shared",
    # "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/winrt",
    # "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/cppwinrt",
    # "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/ucrt",
    # "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.39.33519/include",
]
WIN_HEADERS = [joinpath(WIN_INCLUDES[1], "windows.h")]
# WIN_HEADERS = [joinpath(WIN_INCLUDES[1], "winuser.h")]

# include is C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um

target = "x86_64-w64-mingw32"

# function main()
for target in ["x86_64-w64-mingw32"]
# for target in JLLEnvs.JLL_ENV_TRIPLES
    @info "processing $target"
    options = load_options(joinpath(@__DIR__, "generator.toml"))

    # add compiler flags
    args = get_default_args(target)
    append!(args, "-I" .* WIN_INCLUDES)
    push!(args, "-D_X86_")
    push!(args, "-Wno-nonportable-include-path", "-Wno-pragma-pack", "-ferror-limit=100")
    # push!(args, "-D_WIN64")

    global ctx = create_context(WIN_HEADERS, args, options)

    build!(ctx)
end
# end

open("log.txt", "w+") do io
    redirect_stderr(io) do
        main()
    end
end
