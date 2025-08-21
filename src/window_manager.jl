mutable struct WindowManager <: AbstractWindowManager
  # Events are to be stored here before being processed as part of an EventQueue.
  events::Vector{Event{Window}}
  windows::Vector{Window}
  function WindowManager()
    wm = new()
    wm.events = Event{Window}[]
    wm.windows = Window[]
    wm
  end
end

WindowAbstractions.window_type(::WindowManager) = Window

mutable struct CallbackData
  wm::WindowManager
  window::Window
end

function Window(wm::WindowManager; window_title = "", class_name = String(gensym(:Window)), style::WindowStyle = WS_OVERLAPPEDWINDOW, window_callback = revised_window_callback(window_callback_internal))
  callback = @cfunction($window_callback, Ptr{Cvoid}, (Ptr{Cvoid}, WindowMessage, Ptr{UInt32}, Ptr{Cvoid}))
  class = create_window_class(callback, class_name)
  window = Window()
  user_data = CallbackData(wm, window)
  handle = @check create_window(class.win.lpszClassName, window_title, style, pointer_from_objref(user_data))
  window.handle = handle
  window.callback = callback
  window.user_data = user_data
  finalizer(destroy_window, window)
  push!(wm.windows, window)
  window
end
