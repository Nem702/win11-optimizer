<#
    Shared inventory and scan-result plumbing -- promoted out of
    Detectors\OemBloatware.ps1 during chunk P2-C3, on the second detector that
    needed it rather than the fourth.

    Everything here is detector-agnostic:
      * strict-mode-safe property reads          (Get-OptimizerProperty)
      * the tiny match-pattern dialect           (Assert-/Test-OptimizerPattern*)
      * the normalised installed-app record      (New-InstalledApp)
      * the registry uninstall walk, all 3 views (Get-RegistryInstalledApp)
      * the per-source status record             (New-ScanSource)
      * the scan-result wrapper                  (New-ScanResult)

    READ-ONLY. Nothing in this file writes, uninstalls or deletes anything.
    Win32_Product / WMI is deliberately never used: it triggers an MSI
    reconfiguration pass across every other installed MSI application.

    ASCII only -- Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, and a
    UTF-8 em dash then decodes to a byte 5.1 accepts as a string delimiter.
#>

# Captured at dot-source time: $PSScriptRoot is this file's folder while the .psm1
# dot-sources it, but resolves to the module folder once the functions are called.
$script:OptimizerDataRoot = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Data'

# Inventory source names. Shared so detectors and the scan-result source list
# cannot drift apart on spelling.
$script:SourceAppx        = 'AppxPackage'
$script:SourceProvisioned = 'AppxProvisionedPackage'
$script:SourceRegistry    = 'RegistryUninstall'

# Minimum literal prefix in front of a trailing '*'. See Data\README.md.
$script:MinimumPatternPrefix = 6

$script:InstalledAppTypeName = 'Win11Optimizer.InstalledApp'
$script:ScanResultTypeName   = 'Win11Optimizer.ScanResult'
$script:ScanSourceTypeName   = 'Win11Optimizer.ScanSource'

# The three uninstall views. Leaving out WOW6432Node hides most 32-bit software,
# which on a real machine is most of the OEM-installed software.
$script:RegistryUninstallPath = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

#region Strict-mode-safe reads

function Get-OptimizerProperty {
    # Strict-mode-safe property read. The module runs under Set-StrictMode -Version
    # Latest, where touching a property that does not exist on a PSCustomObject
    # throws -- and inventory objects legitimately arrive with fields missing.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] $Default = $null
    )

    if ($null -eq $InputObject) { return $Default }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    if ($null -eq $property.Value) { return $Default }

    $property.Value
}

#endregion

#region The match-pattern dialect

function Assert-OptimizerPattern {
    # Enforces the deliberately tiny pattern syntax documented in Data\README.md:
    # an exact string, or a prefix of at least $MinimumPatternPrefix characters
    # followed by exactly one trailing '*'. Nothing else is a wildcard.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string] $Pattern,
        [Parameter(Mandatory)] [string] $Context
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) {
        throw "$Context : pattern is empty."
    }

    $starCount = @($Pattern.ToCharArray() | Where-Object { $_ -eq '*' }).Count
    if ($starCount -eq 0) { return }

    if ($starCount -gt 1) {
        throw "$Context : pattern '$Pattern' contains more than one '*'. Only a single trailing '*' is allowed."
    }

    if ($Pattern[$Pattern.Length - 1] -ne '*') {
        throw "$Context : pattern '$Pattern' uses '*' somewhere other than the last character. Only a single trailing '*' is allowed."
    }

    $prefix = $Pattern.Substring(0, $Pattern.Length - 1)
    if ($prefix.Length -lt $script:MinimumPatternPrefix) {
        throw "$Context : pattern '$Pattern' has a literal prefix shorter than $($script:MinimumPatternPrefix) characters. A curated list entry is a claim about real software; broad prefixes are not allowed."
    }
}

function Test-OptimizerPatternMatch {
    # The matching primitive. Case-insensitive ordinal; exact unless the pattern
    # ends in '*', in which case it is a prefix test. Deliberately not -like, so
    # '?', '[' and ']' stay literal.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Pattern,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    if ($Pattern.EndsWith('*')) {
        $prefix = $Pattern.Substring(0, $Pattern.Length - 1)
        return $Value.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
    }

    [string]::Equals($Pattern, $Value, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-OptimizerAnyPatternMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [string[]] $Pattern,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Value
    )

    if ($null -eq $Pattern -or $Pattern.Count -eq 0) { return $false }
    foreach ($candidate in $Pattern) {
        if (Test-OptimizerPatternMatch -Pattern $candidate -Value $Value) { return $true }
    }
    $false
}

function ConvertTo-OptimizerPackageFamilyName {
    # Derives Name_PublisherId from a full package name
    # (Name_Version_Architecture_ResourceId_PublisherId). Provisioned packages only
    # expose the full name, so this is how the two Appx sources become comparable.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $PackageFullName
    )

    if ([string]::IsNullOrWhiteSpace($PackageFullName)) { return $null }
    $parts = $PackageFullName.Split('_')
    if ($parts.Count -lt 2) { return $null }
    '{0}_{1}' -f $parts[0], $parts[$parts.Count - 1]
}

#endregion

#region The normalised installed-app record

function New-InstalledApp {
    # Normalized inventory record shared by every detector that needs to know what
    # is installed. Every property is always present (even when null) so downstream
    # code and the test suite can rely on the shape.
    #
    # InstallDate / EstimatedSizeKb / InstallLocation were added by chunk P2-C3 and
    # are ignored by P2-C1. All three are routinely missing or malformed in real
    # uninstall keys, so they are always fed through the defensive converters below
    # and come out null rather than wrong when the source value makes no sense.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Id,
        [Parameter()] [AllowNull()] [string] $Name,
        [Parameter()] [AllowNull()] [string] $DisplayName,
        [Parameter()] [AllowNull()] [string] $PackageFamilyName,
        [Parameter()] [AllowNull()] [string] $Publisher,
        [Parameter()] [AllowNull()] [string] $Version,
        [Parameter()] [AllowNull()] [string] $UninstallString,
        [Parameter()] [AllowNull()] [string] $Detail,
        [Parameter()] [AllowNull()] [Nullable[datetime]] $InstallDate,
        [Parameter()] [AllowNull()] [Nullable[long]] $EstimatedSizeKb,
        [Parameter()] [AllowNull()] [string] $InstallLocation
    )

    [pscustomobject]@{
        PSTypeName        = $script:InstalledAppTypeName
        Source            = $Source
        Id                = $Id
        Name              = $Name
        DisplayName       = $DisplayName
        PackageFamilyName = $PackageFamilyName
        Publisher         = $Publisher
        Version           = $Version
        UninstallString   = $UninstallString
        Detail            = $Detail
        InstallDate       = $InstallDate
        EstimatedSizeKb   = $EstimatedSizeKb
        InstallLocation   = $InstallLocation
    }
}

function ConvertTo-OptimizerInstallDate {
    # Uninstall keys write InstallDate as 'yyyyMMdd'. Real machines also carry
    # garbage there -- this one has a Unix epoch second count ('1750011767') in a
    # Riot Vanguard key. Anything that is not a parseable yyyyMMdd is treated as
    # ABSENT, never as a guess: the install date feeds the minimum-age rule, and an
    # app wrongly aged past the minimum becomes eligible to be flagged.
    [CmdletBinding()]
    [OutputType([Nullable[datetime]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] $Value
    )

    $text = [string] $Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text = $text.Trim()
    if ($text.Length -ne 8) { return $null }

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::None
    if (-not [datetime]::TryParseExact($text, 'yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref] $parsed)) {
        return $null
    }
    if ($parsed.Year -lt 1990 -or $parsed -gt [datetime]::Now.AddDays(1)) { return $null }

    [Nullable[datetime]] $parsed
}

function ConvertTo-OptimizerEstimatedSize {
    # EstimatedSize is a REG_DWORD in KB. It is frequently absent, and occasionally
    # a string or a negative number. Anything that will not convert to a
    # non-negative long is absent.
    [CmdletBinding()]
    [OutputType([Nullable[long]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Value
    )

    if ($null -eq $Value) { return $null }

    $parsed = [long] 0
    if (-not [long]::TryParse([string] $Value, [ref] $parsed)) { return $null }
    if ($parsed -lt 0) { return $null }

    [Nullable[long]] $parsed
}

function ConvertTo-OptimizerInstallLocation {
    # InstallLocation arrives quoted, trailing-slashed, with environment variables
    # in it, or pointing at a folder that no longer exists. Normalise what can be
    # normalised and return null for anything that does not resolve to a real
    # directory -- a path that is not there is not evidence about anything.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] $Value,
        [Parameter()] [switch] $SkipExistenceCheck
    )

    $text = [string] $Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $text = $text.Trim().Trim('"').Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    try { $text = [System.Environment]::ExpandEnvironmentVariables($text) } catch { return $null }

    $text = $text.TrimEnd([char] 92).TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    # A bare drive root ('C:') is never a meaningful install location, and probing
    # under it would sweep the whole volume.
    if ($text.Length -le 2) { return $null }

    if ($SkipExistenceCheck) { return $text }

    try {
        if (-not [System.IO.Directory]::Exists($text)) { return $null }
    }
    catch { return $null }

    $text
}

#endregion

#region The registry uninstall walk

function Get-RegistryInstalledApp {
    <#
    .SYNOPSIS
        Enumerates traditional Win32 applications from the registry uninstall views.

    .DESCRIPTION
        The shared installed-software inventory. Reads ALL THREE uninstall views --
        HKLM, HKLM\WOW6432Node and HKCU -- and returns one normalised
        Win11Optimizer.InstalledApp record per entry that has a DisplayName.
        Omitting WOW6432Node hides most 32-bit software, which on a real machine is
        most of the OEM-installed software, so the default covers all three and a
        caller has to opt out deliberately.

        Read-only, and works without elevation.

        Promoted here from Detectors\OemBloatware.ps1 by chunk P2-C3 so the OEM
        detector and the unused-app detector share one walk and one record shape
        rather than growing two that drift apart.

        InstallDate, EstimatedSizeKb and InstallLocation are read defensively: each
        is absent on a large fraction of real keys and malformed on a few, and a
        malformed value is reported as absent rather than as a guess.

    .PARAMETER Path
        Uninstall views to read. Defaults to all three.

    .EXAMPLE
        Get-RegistryInstalledApp | Where-Object InstallLocation | Select-Object DisplayName, InstallDate
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]] $Path = $script:RegistryUninstallPath
    )

    foreach ($root in $Path) {
        if (-not (Test-Path -LiteralPath $root)) {
            Write-Verbose "Uninstall view not present, skipping: $root"
            continue
        }

        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            $values = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $values) { continue }

            $displayName = [string](Get-OptimizerProperty -InputObject $values -Name 'DisplayName')
            if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

            $uninstall = [string](Get-OptimizerProperty -InputObject $values -Name 'QuietUninstallString')
            if ([string]::IsNullOrWhiteSpace($uninstall)) {
                $uninstall = [string](Get-OptimizerProperty -InputObject $values -Name 'UninstallString')
            }

            New-InstalledApp -Source $script:SourceRegistry `
                -Id $key.Name `
                -Name $displayName `
                -DisplayName $displayName `
                -Publisher ([string](Get-OptimizerProperty -InputObject $values -Name 'Publisher')) `
                -Version ([string](Get-OptimizerProperty -InputObject $values -Name 'DisplayVersion')) `
                -UninstallString $uninstall `
                -Detail $root `
                -InstallDate (ConvertTo-OptimizerInstallDate -Value (Get-OptimizerProperty -InputObject $values -Name 'InstallDate')) `
                -EstimatedSizeKb (ConvertTo-OptimizerEstimatedSize -Value (Get-OptimizerProperty -InputObject $values -Name 'EstimatedSize')) `
                -InstallLocation (ConvertTo-OptimizerInstallLocation -Value (Get-OptimizerProperty -InputObject $values -Name 'InstallLocation'))
        }
    }
}

#endregion

#region The scan-result wrapper

function New-ScanSource {
    # One record per inventory or signal source: did it run, and if not, why not.
    # 'Skipped' means the source was deliberately not read (not elevated, disabled
    # on this machine); 'Failed' means it was tried and errored. Both carry a Reason
    # a human can act on -- a source being unavailable is never silence.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('Succeeded', 'Skipped', 'Failed')] [string] $Status,
        [Parameter()] [AllowNull()] [string] $Reason,
        [Parameter()] [int] $ItemCount = 0,
        [Parameter()] [double] $DurationSeconds = 0,
        [Parameter()] [AllowNull()] [string[]] $AdditionalTypeName
    )

    $source = [pscustomobject]@{
        PSTypeName      = $script:ScanSourceTypeName
        Name            = $Name
        Status          = $Status
        Reason          = $Reason
        ItemCount       = $ItemCount
        DurationSeconds = $DurationSeconds
    }

    if ($AdditionalTypeName) {
        foreach ($typeName in $AdditionalTypeName) {
            if ([string]::IsNullOrWhiteSpace($typeName)) { continue }
            $source.PSObject.TypeNames.Insert(0, $typeName)
        }
    }

    $source
}

function New-ScanResult {
    <#
        The shape that makes a partial scan impossible to mistake for a complete
        one, shared by every detector rather than re-derived per detector.

        IsComplete / IncompleteReason / SummaryText are derived ScriptProperties:
        they cannot be set by a caller and cannot drift from what the sources
        reported. An incomplete scan also writes to the warning stream from here,
        so no detector can forget to.

        Findings are reachable only through the result object, so a caller cannot
        receive a partial list and mistake it for a complete one.

        Kept internal to the module: it is plumbing every detector uses, not part
        of the public surface. Detector-specific fields go in -AdditionalProperty.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Detector,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [datetime] $StartedUtc,
        [Parameter(Mandatory)] [double] $DurationSeconds,
        [Parameter(Mandatory)] [bool] $IsElevated,
        [Parameter(Mandatory)] [int] $InventoryCount,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [psobject[]] $Source,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Finding,

        # SummaryText reads: "Complete scan of {N} {ItemNoun}: {M} {FindingNoun}."
        [Parameter()] [string] $ItemNoun = 'installed items',
        [Parameter()] [string] $FindingNoun = 'findings',

        # Names the scan in the warning written when it is incomplete.
        [Parameter(Mandatory)] [string] $ScanLabel,

        [Parameter()] [AllowNull()] [string] $TypeName,
        [Parameter()] [AllowNull()] $AdditionalProperty
    )

    $result = [pscustomobject]@{
        PSTypeName      = $script:ScanResultTypeName
        Detector        = $Detector
        Category        = $Category
        StartedUtc      = $StartedUtc
        DurationSeconds = $DurationSeconds
        IsElevated      = $IsElevated
        InventoryCount  = $InventoryCount
        Sources         = [psobject[]] @($Source)
        Findings        = [psobject[]] @($Finding)
    }

    # The detector-specific tag goes in front of the shared one, so a caller can
    # gate on either. P2-C1's callers gate on 'Win11Optimizer.OemScanResult'.
    if (-not [string]::IsNullOrWhiteSpace($TypeName)) {
        $result.PSObject.TypeNames.Insert(0, $TypeName)
    }

    if ($null -ne $AdditionalProperty) {
        foreach ($key in @($AdditionalProperty.Keys)) {
            $result | Add-Member -MemberType NoteProperty -Name ([string] $key) -Value $AdditionalProperty[$key]
        }
    }

    $result | Add-Member -MemberType NoteProperty -Name 'ItemNoun' -Value $ItemNoun
    $result | Add-Member -MemberType NoteProperty -Name 'FindingNoun' -Value $FindingNoun

    # Derived and read-only, the same pattern as Finding.SafetyLabel: completeness
    # cannot be set by a caller and cannot drift from what the sources reported.
    $result | Add-Member -MemberType ScriptProperty -Name 'IsComplete' -Value {
        @($this.Sources | Where-Object { $_.Status -ne 'Succeeded' }).Count -eq 0
    }

    $result | Add-Member -MemberType ScriptProperty -Name 'IncompleteReason' -Value {
        $unfinished = @($this.Sources | Where-Object { $_.Status -ne 'Succeeded' })
        if ($unfinished.Count -eq 0) { return $null }
        ($unfinished | ForEach-Object { "$($_.Name) [$($_.Status)]: $($_.Reason)" }) -join ' '
    }

    $result | Add-Member -MemberType ScriptProperty -Name 'SummaryText' -Value {
        if ($this.IsComplete) {
            "Complete scan of $($this.InventoryCount) $($this.ItemNoun): $(@($this.Findings).Count) $($this.FindingNoun)."
        }
        else {
            "PARTIAL scan of $($this.InventoryCount) $($this.ItemNoun): $(@($this.Findings).Count) $($this.FindingNoun) so far. $($this.IncompleteReason)"
        }
    }

    if (-not $result.IsComplete) {
        Write-Warning "$ScanLabel is INCOMPLETE -- this list is partial. $($result.IncompleteReason)"
    }

    $result
}

#endregion
