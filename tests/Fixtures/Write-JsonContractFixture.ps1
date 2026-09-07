<#
.SYNOPSIS
    Serializes the JSON contract's fixture and writes the bytes to a file.

.DESCRIPTION
    Chunk P6-C1. THIS IS WHAT THE OTHER SHELL RUNS. The suite spawns it under
    Windows PowerShell 5.1 and compares the bytes it produces with the bytes the
    shell running the suite produced from the same fixture -- which is the
    direct evidence for the acceptance criterion that both shells produce
    byte-identical output for the same scan input.

    It takes no shortcuts on the way out. The text is converted to bytes with
    ASCII explicitly and written with WriteAllBytes, so nothing between here and
    the file can add a BOM, translate a line ending or re-encode anything. The
    contract's writer escapes every character above 0x7E, so ASCII is exact
    rather than lossy -- and if that ever stopped being true, this is where it
    would show up as a mangled byte rather than as a silently different
    encoding.

    It changes nothing. The engine is imported, a fabricated scan is serialized,
    and one file is written to a path the caller chose.

    ASCII only.

.PARAMETER Path
    Where to write the bytes.

.EXAMPLE
    powershell.exe -NoProfile -File .\tests\Fixtures\Write-JsonContractFixture.ps1 -Path C:\Temp\on51.jsonl
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Path
)

$ErrorActionPreference = 'Stop'

# A log root of its own. Importing the engine can open a run log, and nothing
# here may go near the repository's own.
$env:WIN11OPTIMIZER_LOGROOT = Join-Path ([System.IO.Path]::GetTempPath()) ('win11opt-fixture-' + [guid]::NewGuid().ToString('N'))

$testsRoot = Split-Path -Path $PSScriptRoot -Parent
$repoRoot  = Split-Path -Path $testsRoot -Parent

Import-Module -Name (Join-Path $repoRoot 'src\Win11Optimizer.Engine\Win11Optimizer.Engine.psd1') -Force -ErrorAction Stop
. (Join-Path $PSScriptRoot 'JsonContract.Fixture.ps1')

$bytes = [System.Text.Encoding]::ASCII.GetBytes((Get-JsonContractFixtureText))
[System.IO.File]::WriteAllBytes($Path, $bytes)
