<#
    Builds the GUI shell. Chunk P6-C2.

    THE SAME SHAPE AS Build-Msi.ps1, on purpose: find the tool or throw with the
    line that installs it, and never guess. It is also the one place that knows
    how to find dotnet, so tests\GuiShell.Tests.ps1 asks this file rather than
    keeping a second copy of the search.

    WHY dotnet AND NOT THE IN-BOX csc.exe. This machine has no .NET SDK, no
    MSBuild that can target 4.8 and no 4.8 targeting pack -- only the C# 5
    compiler that ships with the framework itself. The SDK was chosen over that
    for the test story: xunit and a runner that reports counts are worth more
    than avoiding a build-time dependency. NOTHING THE SDK PROVIDES IS SHIPPED.
    The output is a .NET Framework 4.8 executable and three WebView2 files, and
    it runs on a machine that has never seen the SDK.

    ASCII only.
#>
[CmdletBinding()]
param(
    # Debug or Release.
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    # Report what would be used and stop, without building.
    [Parameter()]
    [switch] $VerifyOnly,

    # Build the tests as well and run them.
    [Parameter()]
    [switch] $Test
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DotnetMissingMessage = @'
The .NET SDK was not found, so the GUI cannot be built.

Install it for this user only, with no administrator rights:

    Invoke-WebRequest https://dot.net/v1/dotnet-install.ps1 -OutFile $env:TEMP\dotnet-install.ps1
    & $env:TEMP\dotnet-install.ps1 -Channel LTS -InstallDir $env:LOCALAPPDATA\Microsoft\dotnet

Nothing it installs is shipped: the build output is a .NET Framework 4.8
executable, and .NET Framework 4.8 is already on every Windows 11 machine.
'@

function Get-OptimizerDotnetPath {
    <#
    .SYNOPSIS
        The dotnet executable, or $null. Searches; changes nothing.

    .DESCRIPTION
        The per-user install location first, because dotnet-install.ps1 does not
        put itself on PATH and that is the install this project documents. Then
        the machine-wide location, then PATH.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidates = @(
        (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\dotnet\dotnet.exe')
        (Join-Path -Path $env:ProgramFiles -ChildPath 'dotnet\dotnet.exe')
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and [System.IO.File]::Exists($candidate)) { return $candidate }
    }

    $onPath = Get-Command -Name 'dotnet' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($onPath) { return $onPath.Source }

    $null
}

function Get-OptimizerGuiRoot {
    # The solution folder. Resolved from this file, not from the current
    # directory, which is not ours to depend on.
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'src\Win11Optimizer.Gui'
}

function Invoke-OptimizerGuiBuild {
    [CmdletBinding()]
    param(
        [Parameter()] [ValidateSet('Debug', 'Release')] [string] $Configuration = 'Release',
        [Parameter()] [switch] $IncludeTests
    )

    $dotnet = Get-OptimizerDotnetPath
    if (-not $dotnet) { throw $script:DotnetMissingMessage }

    $root = Get-OptimizerGuiRoot
    $projects = @(Join-Path -Path $root -ChildPath 'Win11Optimizer.Gui\Win11Optimizer.Gui.csproj')
    if ($IncludeTests) {
        $projects += (Join-Path -Path $root -ChildPath 'Win11Optimizer.Gui.Core.Tests\Win11Optimizer.Gui.Core.Tests.csproj')
    }

    foreach ($project in $projects) {
        & $dotnet build $project -c $Configuration --nologo
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet build failed for '$project' with exit code $LASTEXITCODE."
        }
    }

    Join-Path -Path $root -ChildPath "Win11Optimizer.Gui\bin\$Configuration\net48\Win11Optimizer.Gui.exe"
}

# Dot-sourced by the test suite, which wants the functions and not a build.
if ($MyInvocation.InvocationName -eq '.') { return }

$dotnet = Get-OptimizerDotnetPath
if (-not $dotnet) { throw $script:DotnetMissingMessage }

Write-Host "dotnet:        $dotnet"
Write-Host "sdk:           $(& $dotnet --version)"
Write-Host "solution:      $(Get-OptimizerGuiRoot)"
Write-Host "configuration: $Configuration"

if ($VerifyOnly) { return }

$exe = Invoke-OptimizerGuiBuild -Configuration $Configuration -IncludeTests:$Test
Write-Host ''
Write-Host "built: $exe"

if ($Test) {
    $project = Join-Path -Path (Get-OptimizerGuiRoot) -ChildPath 'Win11Optimizer.Gui.Core.Tests\Win11Optimizer.Gui.Core.Tests.csproj'
    & $dotnet test $project -c $Configuration --nologo --no-build
    if ($LASTEXITCODE -ne 0) { throw "dotnet test failed with exit code $LASTEXITCODE." }
}
