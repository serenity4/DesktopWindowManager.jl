abstract type WinAPIStruct{HasDeps} end
abstract type Handle <: WinAPIStruct{false} end

Base.:(==)(x::H, y::H) where {H<:Handle} = x.win == y.win
Base.hash(handle::Handle, h::UInt) = hash(handle.win, h)

Base.show(io::IO, h::Handle) = print(io, typeof(h), '(', h.win, ')')

abstract type HighLevelStruct end

# Make sure our dispatches for vectors are hit before any other method.
# Unfortunately, we'll still need to add dispatches from `Base.cconvert` to this `cconvert`
# because `Base.cconvert` is what will be called during `ccall`s, not this function.
cconvert(T, x) = Base.cconvert(T, x)

Base.cconvert(T::Type{Ptr{Cvoid}}, x::Handle) = x
Base.cconvert(T::Type{<:Ptr}, x::WinAPIStruct{false}) = Ref(x.win)
Base.cconvert(T::Type{<:Ptr}, x::WinAPIStruct{true}) = (x, Ref(x.win))
Base.cconvert(T::Type{<:Ptr}, x::HighLevelStruct) = Base.cconvert(T, convert(getproperty(@__MODULE__, Symbol(:_, nameof(typeof(x)))), x))

cconvert(T::Type{<:Ptr}, x::AbstractVector{<:WinAPIStruct{false}}) = Base.cconvert(T, getproperty.(x, :win))
cconvert(T::Type{<:Ptr}, x::AbstractVector{<:WinAPIStruct{true}}) = (x, Base.cconvert(T, getproperty.(x, :win)))
cconvert(T::Type{<:Ptr}, x::AbstractVector{<:HighLevelStruct}) = Base.cconvert(T, convert.(getproperty(@__MODULE__, Symbol(:_, nameof(eltype(x)))), x))

Base.cconvert(T::Type{<:Ptr}, x::AbstractVector{<:WinAPIStruct{false}}) = cconvert(T, x)
Base.cconvert(T::Type{<:Ptr}, x::AbstractVector{<:WinAPIStruct{true}}) = cconvert(T, x)
Base.cconvert(T::Type{<:Ptr}, x::AbstractVector{<:HighLevelStruct}) = cconvert(T, x)

# Shadow the otherwise more specific Base method
# `cconvert(::Type{<:Ptr}, ::Array)`.
Base.cconvert(T::Type{<:Ptr}, x::Vector{<:WinAPIStruct{false}}) = cconvert(T, x)
Base.cconvert(T::Type{<:Ptr}, x::Vector{<:WinAPIStruct{true}}) = cconvert(T, x)
Base.cconvert(T::Type{<:Ptr}, x::Vector{<:HighLevelStruct}) = cconvert(T, x)

# Shadow the otherwise more specific Base method
# `cconvert(::Type{Ptr{P<:Union{Cstring,Cwstring,Ptr}}}, ::Array)`.
Base.cconvert(T::Type{Ptr{P}}, x::Vector{<:WinAPIStruct{false}}) where {P<:Ptr} = cconvert(T, x)
Base.cconvert(T::Type{Ptr{P}}, x::Vector{<:WinAPIStruct{true}}) where {P<:Ptr} = cconvert(T, x)
Base.cconvert(T::Type{Ptr{P}}, x::Vector{<:HighLevelStruct}) where {P<:Ptr} = cconvert(T, x)

convert(T::Type{Ptr{Cvoid}}, x::Handle) = x.win

unsafe_convert(T::Type, x::WinAPIStruct) = x.win
unsafe_convert(T::Type, x::Tuple{<:WinAPIStruct{true}, <:Ref}) = unsafe_convert(T, last(x))
unsafe_convert(T::Type, x::Tuple{<:AbstractVector{<:WinAPIStruct{true}}, <:Any}) = unsafe_convert(T, last(x))
