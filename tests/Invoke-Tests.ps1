<#
.SYNOPSIS
    Runs the win11-optimizer test suite.

.DESCRIPTION
    Wraps Pester 5 so the suite runs the same way everywhere. Because the engine
    targets Windows PowerShell 5.1 as its floor, -On51 re-runs the whole suite
    under Windows PowerShell to catch anything that only works on PowerShell 7.

.PARAMETER On51
    Re-launch under Windows PowerShell 5.1 instead of the current shell.

.PARAMETER Detailed
    Show per-test output rather than the summary.

.EXAMPLE
    .\tests\Invoke-Tests.ps1

.EXAMPLE
    .\tests\Invoke-Tests.ps1 -On51 -Detailed
#>
[CmdletBinding()]
param(
    [switch] $On51,
    [switch] $Detailed
)

$ErrorActionPreference = 'Stop'

if ($On51) {
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell)) {
        throw "Windows PowerShell 5.1 not found at $windowsPowerShell."
    }
    $arguments = @('-NoProfile', '-File', $PSCommandPath)
    if ($Detailed) { $arguments += '-Detailed' }

    $previousModulePath = $env:PSModulePath
    try {
        # Windows PowerShell computes its own default when this is absent. Inheriting
        # PowerShell 7's copy puts 7's Modules folder ahead of 5.1's own, and 5.1 then
        # loads 7's Microsoft.PowerShell.Utility -- which has no Import-PowerShellDataFile.
        Remove-Item Env:\PSModulePath -ErrorAction SilentlyContinue
        & $windowsPowerShell @arguments
    }
    finally { $env:PSModulePath = $previousModulePath }

    exit $LASTEXITCODE
}

$pester = Get-Module -ListAvailable Pester |
    Where-Object { $_.Version -ge [version]'5.0.0' } |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $pester) {
    throw @'
Pester 5 or newer is required (Windows ships an inbox Pester 3.4.0 that cannot run this suite).
Install it with:

    Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
'@
}

Import-Module $pester.Path -Force

$configuration = New-PesterConfiguration
$configuration.Run.Path = $PSScriptRoot
$configuration.Run.Exit = $true
$configuration.Output.Verbosity = if ($Detailed) { 'Detailed' } else { 'Normal' }

Write-Host "Pester $($pester.Version) on PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
Invoke-Pester -Configuration $configuration
