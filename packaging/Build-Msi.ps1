<#
.SYNOPSIS
    Builds win11-optimizer.msi from packaging\win11-optimizer.wxs with WiX v3.

.DESCRIPTION
    Chunk P5-C2, part B. Two commands, in order: candle compiles the .wxs to a
    .wixobj, light links the .wixobj to a .msi. Both come from the WiX Toolset
    v3, and this script's first job is to find them.

    IF WiX IS NOT INSTALLED THIS SCRIPT STOPS. It does not fall back to a .zip,
    a self-extracting .exe, an "installer" that is really a PowerShell script,
    or a hand-assembled .msi. Two of those cannot set the ACL that Q21 exists
    for, and the third is not a .msi no matter what it is named. The message
    says what to install and where to get it, and that is the whole of the
    error path.

    WHAT IT DOES NOT DO: sign anything. Code signing is P5-C3 and is deferred
    until there is a build worth signing (docs\CHECKLIST.md). An unsigned .msi
    shows an unknown-publisher prompt on the UAC dialog; that is expected, and
    pretending otherwise by suppressing the prompt would be worse.

.PARAMETER Version
    Three-part product version. Defaults to the engine module's ModuleVersion,
    so the .msi and the module can never claim different versions.

.PARAMETER OutputPath
    Where to put the .msi. Defaults to packaging\dist.

.PARAMETER VerifyOnly
    Find the toolset, report what was found, and build nothing. This is the
    quickest way to answer "can this machine build the installer at all?".

.EXAMPLE
    .\packaging\Build-Msi.ps1

.EXAMPLE
    .\packaging\Build-Msi.ps1 -Version 0.2.0 -OutputPath C:\drop

.EXAMPLE
    .\packaging\Build-Msi.ps1 -VerifyOnly
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^\d+\.\d+(\.\d+)?$')]
    [string] $Version,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath,

    [switch] $VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PackagingRoot = $PSScriptRoot
$script:RepositoryRoot = Split-Path -Path $PSScriptRoot -Parent
$script:WxsPath = Join-Path -Path $script:PackagingRoot -ChildPath 'win11-optimizer.wxs'
$script:ManifestPath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src\Win11Optimizer.Engine\Win11Optimizer.Engine.psd1'

$script:WixMissingMessage = @'
The WiX Toolset v3 is not installed on this machine, so the .msi cannot be built.

    Looked for candle.exe and light.exe in, in order:
      1. %WIX%\bin                       (set by the WiX v3 installer)
      2. anywhere on PATH
      3. %ProgramFiles(x86)%\WiX Toolset v3.*\bin

    Install WiX v3.11 or newer. Two ways, and the second needs no rights at all:

      * winget install --id WiXToolset.WiXToolset
        (v3.14.1. Needs administrator AND the .NET Framework 3.5 Windows
        feature, which its bundle installs as a prerequisite.)

      * Download wix314-binaries.zip from
        https://github.com/wixtoolset/wix3/releases, unpack it anywhere, and
        point WIX at that folder:  $env:WIX = '<the folder>'
        The tools themselves need nothing installed. This is how the .msi that
        shipped with this chunk was built.

WiX v4 and v5 replace candle and light with a single wix.exe and a different
schema; this project targets v3 and its .wxs will not compile under either.

This script deliberately has no fallback. A .zip, a self-extracting .exe or a
PowerShell "installer" cannot set the ACL on %ProgramData%\win11-optimizer that
the action ledger depends on, and a file assembled by hand is not a .msi.
'@

function Get-WixToolPath {
    <#
    .SYNOPSIS
        Returns the folder holding candle.exe and light.exe, or an empty string.

    .DESCRIPTION
        %WIX% first, because that is what the v3 installer sets and what a build
        agent is most likely to have. PATH second. The default install location
        third, newest version first -- so a machine with both v3.11 and v3.14
        builds with v3.14.

        A folder is only accepted if BOTH tools are in it. Half a toolset fails
        later, in the middle of a build, with a worse message.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidate = New-Object System.Collections.Generic.List[string]

    $fromEnvironment = [Environment]::GetEnvironmentVariable('WIX')
    if (-not [string]::IsNullOrWhiteSpace($fromEnvironment)) {
        $null = $candidate.Add((Join-Path -Path $fromEnvironment -ChildPath 'bin'))
        $null = $candidate.Add($fromEnvironment)
    }

    $onPath = Get-Command -Name 'candle.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($onPath) {
        $null = $candidate.Add((Split-Path -Path $onPath.Source -Parent))
    }

    $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ([string]::IsNullOrWhiteSpace($programFiles)) {
        $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles')
    }
    if (-not [string]::IsNullOrWhiteSpace($programFiles) -and (Test-Path -LiteralPath $programFiles)) {
        $installed = @(Get-ChildItem -LiteralPath $programFiles -Directory -Filter 'WiX Toolset v3.*' -ErrorAction SilentlyContinue |
            Sort-Object -Property Name -Descending)
        foreach ($folder in $installed) {
            $null = $candidate.Add((Join-Path -Path $folder.FullName -ChildPath 'bin'))
        }
    }

    foreach ($folder in $candidate) {
        if ([string]::IsNullOrWhiteSpace($folder)) { continue }
        $candle = Join-Path -Path $folder -ChildPath 'candle.exe'
        $light  = Join-Path -Path $folder -ChildPath 'light.exe'
        if ((Test-Path -LiteralPath $candle -PathType Leaf) -and (Test-Path -LiteralPath $light -PathType Leaf)) {
            return $folder
        }
    }

    ''
}

function Get-ModuleVersion {
    <#
    .SYNOPSIS
        Returns the engine module's ModuleVersion.

    .DESCRIPTION
        Read from the manifest rather than written down here, so that a build
        can never label itself a version the module does not claim to be.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
    [string] $manifest.ModuleVersion
}

# ---- find the toolset ------------------------------------------------------

$wixBin = Get-WixToolPath
if ([string]::IsNullOrWhiteSpace($wixBin)) {
    throw $script:WixMissingMessage
}

$candleExe = Join-Path -Path $wixBin -ChildPath 'candle.exe'
$lightExe  = Join-Path -Path $wixBin -ChildPath 'light.exe'

Write-Host "WiX toolset : $wixBin"

if (-not (Test-Path -LiteralPath $script:WxsPath -PathType Leaf)) {
    throw "The installer source is missing: '$($script:WxsPath)'."
}

if (-not $Version) { $Version = Get-ModuleVersion }
if (-not $OutputPath) { $OutputPath = Join-Path -Path $script:PackagingRoot -ChildPath 'dist' }

$objPath = Join-Path -Path $script:PackagingRoot -ChildPath 'obj'
$msiPath = Join-Path -Path $OutputPath -ChildPath ("win11-optimizer-$Version-x64.msi")

Write-Host "Source root : $($script:RepositoryRoot)"
Write-Host "Version     : $Version"
Write-Host "Output      : $msiPath"

if ($VerifyOnly) {
    Write-Host 'VerifyOnly: the toolset is present and nothing was built.'
    return
}

foreach ($folder in @($objPath, $OutputPath)) {
    if (-not (Test-Path -LiteralPath $folder)) {
        $null = New-Item -Path $folder -ItemType Directory -Force
    }
}

# ---- candle: .wxs to .wixobj ----------------------------------------------
#
# -arch x64 is what makes ProgramFiles64Folder and System64Folder resolve to the
# 64-bit locations. A 32-bit package would put the tool in Program Files (x86)
# and point the shortcut at SysWOW64's powershell.exe, which is a different
# shell than the one this project's suite runs against.

$wixobj = Join-Path -Path $objPath -ChildPath 'win11-optimizer.wixobj'

$candleArgument = @(
    '-nologo'
    '-arch', 'x64'
    "-dSourceRoot=$($script:RepositoryRoot)"
    "-dProductVersion=$Version"
    '-out', $wixobj
    $script:WxsPath
)

Write-Host ''
Write-Host "candle $($candleArgument -join ' ')"
& $candleExe @candleArgument
if ($LASTEXITCODE -ne 0) {
    throw "candle.exe failed with exit code $LASTEXITCODE. Nothing was linked."
}

# ---- light: .wixobj to .msi -----------------------------------------------

$lightArgument = @(
    '-nologo'
    '-out', $msiPath
    $wixobj
)

Write-Host ''
Write-Host "light $($lightArgument -join ' ')"
& $lightExe @lightArgument
if ($LASTEXITCODE -ne 0) {
    throw "light.exe failed with exit code $LASTEXITCODE. No .msi was produced."
}

Write-Host ''
Write-Host "Built: $msiPath"
Get-Item -LiteralPath $msiPath | Select-Object -Property Name, Length, LastWriteTime
