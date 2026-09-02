<#
    App\Entry.ps1 -- chunk P5-C1, part C: the single entry point.

    THIS FILE IS A LAUNCHER, NOT A SOURCE FILE. It is the thing a shortcut, a
    packaged launcher or an elevated relaunch invokes:

        pwsh.exe -NoProfile -File <module root>\App\Entry.ps1

    It is therefore the ONE .ps1 under src\Win11Optimizer.Engine that the
    module's folder loader deliberately does not dot-source -- see the App\ line
    in Win11Optimizer.Engine.psm1. Dot-sourcing it during import would re-enter
    Import-Module and then start the menu, from inside the import of the module
    the menu lives in. It is excluded by name, and a test asserts the exclusion
    list is exactly this file.

    IT HAS TWO STATEMENTS AND THAT IS THE POINT. Everything a launcher could get
    wrong -- what the menu offers, when to elevate, what to do with a
    cancellation -- lives in App\Menu.ps1, where it is reachable by the test
    suite. A launcher with logic in it is a launcher nothing can test.

    -Choice and -Argument are how an elevated relaunch says where to start; see
    Support\Elevation.ps1. Run without them, it is just the menu.
#>
[CmdletBinding()]
param(
    # The menu choice to start on, by name. Supplied by an elevated relaunch.
    # A session started this way does not itself relaunch -- Invoke-OptimizerMenu
    # explains why -- which is what bounds the chain at one level deep.
    [Parameter()]
    [AllowNull()]
    [AllowEmptyString()]
    [string] $Choice,

    # What that choice needs: the action id, for Undo.
    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [AllowEmptyString()]
    [string[]] $Argument = @()
)

Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Win11Optimizer.Engine.psd1') -Force -ErrorAction Stop

$null = Invoke-OptimizerMenu -InitialChoice $Choice -InitialArgument $Argument
