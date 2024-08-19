using DesktopWindowManager
const DWM = DesktopWindowManager
using Test

function window_callback(window, msg, wparam, lparam)::Ptr{Cvoid}
    @show msg
    if msg == DWM.WM_DESTROY
        @ccall (DWM.user32).PostQuitMessage(0::Cint)::Cvoid
        return 0
    end
    @ccall (DWM.user32).DefWindowProcA(window::Ptr{Cvoid}, msg::UInt32, wparam::Ptr{UInt32}, lparam::Ptr{Cvoid})::Ptr{Cvoid}
end
window_callback_cfunction = @cfunction(window_callback, Ptr{Cvoid}, (Ptr{Cvoid}, WindowMessage, Ptr{UInt32}, Ptr{Cvoid}))

@testset "DesktopWindowManager.jl" begin
    # Don't run tests on unsupported configurations.
    DWM.instance[] == C_NULL && exit(0)

    class = DWM.create_window_class(window_callback_cfunction, string(gensym("Class")))
    # FIXME: Window decorations are missing (minimize/maximize/close buttons).
    window = DWM.create_window(class, "Test Window", DWM.WS_OVERLAPPEDWINDOW)
    was_visible = DWM.map_window(window)
    @test !was_visible
    was_visible = DWM.unmap_window(window)
    @test was_visible
end;
