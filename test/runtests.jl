using DesktopWindowManager
const DWM = DesktopWindowManager
using Test

# https://learn.microsoft.com/en-us/windows/win32/learnwin32/your-first-windows-program
@testset "DesktopWindowManager.jl" begin
    DWM.is_supported() || return

    wm = WindowManager()
    window = Window(wm; window_title = "Test Window")
    was_visible = map_window(window)
    @test !was_visible
    was_visible = unmap_window(window)
    @test was_visible
    map_window(window)
    queue = EventQueue(wm)
    collect_events!(queue)
end;
