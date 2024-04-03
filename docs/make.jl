using Documenter, DesktopWindowManager

makedocs(;
    modules=[DesktopWindowManager],
    format=Documenter.HTML(prettyurls = true),
    pages=[
        "Home" => "index.md",
        "API" => "api.md",
    ],
    repo="https://github.com/serenity4/DesktopWindowManager.jl/blob/{commit}{path}#L{line}",
    sitename="DesktopWindowManager.jl",
    authors="serenity4 <cedric.bel@hotmail.fr>",
    warnonly=false,
    doctest=false,
    checkdocs=:exports,
    linkcheck=:true,
)

deploydocs(repo = "github.com/serenity4/DesktopWindowManager.jl.git")
