function WindowAbstractions.EventQueue(wm::WindowManager; sleep::Bool = true, record_history::Bool = false)
  EventQueue{WindowManager, Window}(wm, wm.events, Event{Window}[], sleep, record_history)
end

function WindowAbstractions.poll_for_events!(queue::EventQueue{WindowManager, Window})
  msg = peek_message()
  isnothing(msg) && return false
  translate_message(msg)
  dispatch_message(msg)
  true
end

function peek_message(; window = C_NULL, range = WM_NULL:WM_HOTKEY, remove_msg = true)
  msg = Ref{WinAPIMessage}()
  ret = @ccall user32.PeekMessageA(msg::Ptr{WinAPIMessage}, window::Ptr{Cvoid}, range.start::Cuint, range.stop::Cuint, remove_msg::Cuint)::Bool
  !ret && return nothing
  Message(msg[], [])
end

"Produce character messages from virtual key messages, posting them in the message queue for later retrieval."
function translate_message(message::Message)
  @ccall user32.TranslateMessage(message::Ptr{WinAPIMessage})::Bool
end

"Call the registered window procedure on the provided message."
function dispatch_message(message::Message)
  @ccall user32.DispatchMessageA(message::Ptr{WinAPIMessage})::Cvoid
end
