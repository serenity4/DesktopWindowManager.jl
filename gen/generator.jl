using .Meta: isexpr
using Clang.Generators
using Clang.Generators.JLLEnvs

cd(@__DIR__)

WIN_INCLUDE = "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0"

WIN_INCLUDES = [
    "$WIN_INCLUDE/um",
    "$WIN_INCLUDE/shared",
    # "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/winrt",
    # "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/cppwinrt",
    # "C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/ucrt",
    # "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.39.33519/include",
]
WIN_HEADERS = ["$WIN_INCLUDE/shared/winerror.h", "$WIN_INCLUDE/um/Windows.h"]
WIN_HEADERS = ["$WIN_INCLUDE/um/Windows.h"]
# WIN_HEADERS = [joinpath(WIN_INCLUDE, "winuser.h")]

# include is C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um

target = "x86_64-w64-mingw32"

function main()
    @info "processing $target"
    options = load_options(joinpath(@__DIR__, "generator.toml"))

    # add compiler flags
    args = get_default_args(target)
    append!(args, "-I" .* WIN_INCLUDES)
    # push!(args, "-DNOGDICAPMASKS")
    # push!(args, "-DNOVIRTUALKEYCODES")
    # push!(args, "-DNOWINMESSAGES")
    # push!(args, "-DNOWINSTYLES")
    # push!(args, "-DNOSYSMETRICS")
    # push!(args, "-DNOMENUS")
    # push!(args, "-DNOICONS")
    # push!(args, "-DNOKEYSTATES")
    # push!(args, "-DNOSYSCOMMANDS")
    # push!(args, "-DNORASTEROPS")
    # push!(args, "-DNOSHOWWINDOW")
    # push!(args, "-DOEMRESOURCE")
    # push!(args, "-DNOATOM")
    # push!(args, "-DNOCLIPBOARD")
    # push!(args, "-DNOCOLOR")
    # push!(args, "-DNOCTLMGR")
    # push!(args, "-DNODRAWTEXT")
    # push!(args, "-DNOGDI")
    # push!(args, "-DNOKERNEL")
    # push!(args, "-DNOUSER")
    # push!(args, "-DNONLS")
    # push!(args, "-DNOMB")
    # push!(args, "-DNOMEMMGR")
    # push!(args, "-DNOMETAFILE")
    # push!(args, "-DNOMINMAX")
    # push!(args, "-DNOMSG")
    # push!(args, "-DNOOPENFILE")
    # push!(args, "-DNOSCROLL")
    # push!(args, "-DNOSERVICE")
    # push!(args, "-DNOSOUND")
    # push!(args, "-DNOTEXTMETRIC")
    # push!(args, "-DNOWH")
    # push!(args, "-DNOWINOFFSETS")
    # push!(args, "-DNOCOMM")
    # push!(args, "-DNOKANJI")
    # push!(args, "-DNOHELP")
    # push!(args, "-DNOPROFILER")
    # push!(args, "-DNODEFERWINDOWPOS")
    # push!(args, "-DNOMCX")
    push!(args, "-D__oaidl_h__")
    # push!(args, "-DSPECSTRINGS_H")
    # push!(args, "-D_X86_")
    push!(args, "-Wno-nonportable-include-path", "-Wno-pragma-pack", "-ferror-limit=10")
    # push!(args, "-D_WIN64")

    ctx = create_context(WIN_HEADERS, args, options)

    return build!(ctx)

    build!(ctx, BUILDSTAGE_NO_PRINTING)
    rewrite!(ctx.dag)
    # return
    build!(ctx, BUILDSTAGE_PRINTING_ONLY)
end

function rewrite!(dag::ExprDAG)
    for node in get_nodes(dag)
        isa(node, ExprNode{<:AbstractUnionNodeType}) || continue
        length(node.exprs) > 1 || continue
        s, f = node.exprs[1], node.exprs[end]
        isexpr(s, :struct) || continue
        isexpr(f, :function) || continue
        name = s.args[2]
        # name == Symbol("struct (unnamed at C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um\\winnt.h:18965:5)") || continue
        isa(name, Symbol) || continue
        call = f.args[1]
        isexpr(call, :call) || continue
        fname, arg = call.args
        fname === name || continue
        isexpr(arg, :(::)) || continue
        argname, argtype = arg.args
        @show node
        @show f node.cursor argtype
        isexpr(argtype, :curly) || continue
        base, parameters = argtype.args
        base === :NTuple || continue
        length(parameters) == 2 || continue
        parameters[2] == :BYTE && @show node.cursor
    end
end

@time main();

# rewrite!(ctx.dag)

# open("log.txt", "w+") do io
#     redirect_stderr(io) do
#         main()
#     end
# end

#var"struct (unnamed at C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um\\winnt.h:18965:5)"
