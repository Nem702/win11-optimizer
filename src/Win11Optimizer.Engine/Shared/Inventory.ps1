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
      * the tri-state path existence probe       (Test-OptimizerPathPresent)
      * the in-use file probe                    (Test-OptimizerFileInUse)
      * path comparison and containment          (ConvertTo-OptimizerComparablePath,
                                                  Test-OptimizerPathWithin)
      * the protected-path list and its check    (Get-OptimizerProtectedPath,
                                                  Get-OptimizerProtectedPathConflict)

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

# The four scan-source statuses, defined once so New-ScanSource's ValidateSet and
# the completeness derivation below cannot drift apart.
#
# The distinction that matters, and the reason 'Refused' exists at all (added by
# chunk P2-C2, decided in docs\STATE.md 2026-08-25):
#
#   Succeeded  read, got data.
#   Skipped    not read THIS TIME, for a reason that could have gone the other way
#              on another machine, at another privilege level, or on another run --
#              not elevated, feature turned off here, path absent.
#   Failed     tried and errored.
#   Refused    this project has decided never to use this signal, on ANY machine,
#              at ANY privilege level. It is a design decision, not a condition of
#              this run.
#
# Only Skipped and Failed mean "this scan saw less than the truth", so only those
# two make a scan incomplete. Refused stays fully visible in Sources with its
# reason -- the measurement behind the decision is not deleted, it just stops
# being called an incompleteness.
#
# THE SAFETY PROPERTY: 'Refused' must never become a way to hide an environmental
# failure. If the answer could be different somewhere else, the status is
# 'Skipped' or 'Failed'. A source that is Refused on one machine is Refused on all
# of them.
$script:ScanSourceStatuses = @('Succeeded', 'Skipped', 'Failed', 'Refused')

# The statuses that count as incompleteness. Everything else in the set above is
# either a success or a permanent, deliberate omission.
$script:ScanSourceIncompleteStatuses = @('Skipped', 'Failed')

# The three in-use verdicts returned by Test-OptimizerFileInUse. 'Undetermined'
# exists because a probe that cannot answer must not be read as "free": it is
# counted separately and every caller treats it as in use.
$script:OptimizerInUseFree         = 'Free'
$script:OptimizerInUseHeld         = 'InUse'
$script:OptimizerInUseUndetermined = 'Undetermined'

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

function Get-OptimizerExclusionMatch {
    # Returns the first curated exclusion entry an inventory record matches, or
    # $null. Promoted here from Detectors\UnusedApps.ps1 by chunk P2-C2 on its
    # second use -- P2-C2 matches SERVICES against the same P2-C3 exclusion list,
    # so that the driver / security / firmware-update vendor classes are stated
    # once in one file rather than twice in two.
    #
    # The record only has to expose the four properties below; anything missing
    # reads as absent. P2-C2 builds one from a service registry key (DisplayName
    # from the service, Publisher from the target binary's version info) precisely
    # so this one matcher can serve both detectors.
    #
    # Unlike the OEM whitelist, RegistryPublisher stands alone here: on an
    # exclusion list a vendor-wide rule only ever means "never flag this", so
    # over-matching costs a missed finding rather than a broken machine. See
    # Data\README.md.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $InstalledApp,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ExclusionEntry
    )

    if ($null -eq $InstalledApp -or $null -eq $ExclusionEntry) { return $null }

    $name        = [string](Get-OptimizerProperty -InputObject $InstalledApp -Name 'Name')
    $displayName = [string](Get-OptimizerProperty -InputObject $InstalledApp -Name 'DisplayName')
    $familyName  = [string](Get-OptimizerProperty -InputObject $InstalledApp -Name 'PackageFamilyName')
    $publisher   = [string](Get-OptimizerProperty -InputObject $InstalledApp -Name 'Publisher')
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $name }

    foreach ($entry in $ExclusionEntry) {
        if ($null -eq $entry) { continue }

        if (Test-OptimizerAnyPatternMatch -Pattern ([string[]](Get-OptimizerProperty -InputObject $entry -Name 'AppxPackageName' -Default @())) -Value $name) { return $entry }
        if (Test-OptimizerAnyPatternMatch -Pattern ([string[]](Get-OptimizerProperty -InputObject $entry -Name 'AppxPackageFamilyName' -Default @())) -Value $familyName) { return $entry }
        if (Test-OptimizerAnyPatternMatch -Pattern ([string[]](Get-OptimizerProperty -InputObject $entry -Name 'RegistryDisplayName' -Default @())) -Value $displayName) { return $entry }
        if (Test-OptimizerAnyPatternMatch -Pattern ([string[]](Get-OptimizerProperty -InputObject $entry -Name 'RegistryPublisher' -Default @())) -Value $publisher) { return $entry }
    }

    $null
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
    # See $script:ScanSourceStatuses above for what the four statuses mean and
    # which two make a scan incomplete.
    #
    # Reason is MANDATORY for every status except 'Succeeded'. A source that is not
    # Succeeded and carries no reason is exactly the silent under-report this
    # project exists to prevent: it would reach the user as an unexplained gap, or
    # -- worse, for 'Refused' -- as a permanent omission nobody can audit. A
    # Succeeded source is forced back to a null Reason rather than an empty string,
    # because callers and tests distinguish the two.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('Succeeded', 'Skipped', 'Failed', 'Refused')] [string] $Status,
        [Parameter()] [AllowNull()] [string] $Reason,
        [Parameter()] [int] $ItemCount = 0,
        [Parameter()] [double] $DurationSeconds = 0,
        [Parameter()] [AllowNull()] [string[]] $AdditionalTypeName
    )

    # Held in its own untyped variable: assigning $null back to $Reason would be
    # re-coerced by the [string] parameter type into an empty string, and callers
    # and tests distinguish a null Reason from an empty one.
    $statedReason = $null
    if ($Status -eq 'Succeeded') {
        $statedReason = $null
    }
    elseif ([string]::IsNullOrWhiteSpace($Reason)) {
        throw "Scan source '$Name' is '$Status' with no Reason. Every source that did not simply succeed has to say why in words a human can act on -- an unexplained gap is the silent under-report this project exists to prevent."
    }
    else {
        $statedReason = $Reason
    }

    $source = [pscustomobject]@{
        PSTypeName      = $script:ScanSourceTypeName
        Name            = $Name
        Status          = $Status
        Reason          = $statedReason
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
    #
    # Both of these key on $script:ScanSourceIncompleteStatuses rather than on
    # "anything that is not Succeeded". A 'Refused' source is a decision this
    # project made on purpose, on every machine, forever -- counting it as an
    # incompleteness would make IsComplete false on every run of the shipped app
    # and spend the PARTIAL warning on a condition that can never clear.
    $result | Add-Member -MemberType ScriptProperty -Name 'IsComplete' -Value {
        @($this.Sources | Where-Object { $script:ScanSourceIncompleteStatuses -contains $_.Status }).Count -eq 0
    }

    $result | Add-Member -MemberType ScriptProperty -Name 'IncompleteReason' -Value {
        $unfinished = @($this.Sources | Where-Object { $script:ScanSourceIncompleteStatuses -contains $_.Status })
        if ($unfinished.Count -eq 0) { return $null }
        ($unfinished | ForEach-Object { "$($_.Name) [$($_.Status)]: $($_.Reason)" }) -join ' '
    }

    # The refused sources, by name. Structured access so a caller -- notably the
    # P4-C1 GUI -- can name the signals this project does not use without parsing
    # SummaryText or re-deriving the status rule.
    $result | Add-Member -MemberType ScriptProperty -Name 'RefusedSourceName' -Value {
        [string[]] @($this.Sources | Where-Object { $_.Status -eq 'Refused' } | ForEach-Object { $_.Name })
    }

    $result | Add-Member -MemberType ScriptProperty -Name 'SummaryText' -Value {
        # Refused sources are acknowledged in one short clause: named, pointed at
        # Sources, and never quoted at paragraph length -- the reason itself can
        # run to several sentences and belongs on the source record, not in a
        # one-line summary. The word PARTIAL is deliberately absent from it.
        $refused = @($this.RefusedSourceName)
        $refusedClause = ''
        if ($refused.Count -gt 0) {
            $noun = if ($refused.Count -eq 1) { 'signal' } else { 'signals' }
            $refusedClause = " $($refused.Count) $noun not used by design ($($refused -join ', ')) -- see Sources."
        }

        if ($this.IsComplete) {
            "Complete scan of $($this.InventoryCount) $($this.ItemNoun): $(@($this.Findings).Count) $($this.FindingNoun).$refusedClause"
        }
        else {
            "PARTIAL scan of $($this.InventoryCount) $($this.ItemNoun): $(@($this.Findings).Count) $($this.FindingNoun) so far. $($this.IncompleteReason)$refusedClause"
        }
    }

    if (-not $result.IsComplete) {
        Write-Warning "$ScanLabel is INCOMPLETE -- this list is partial. $($result.IncompleteReason)"
    }

    $result
}

#endregion

#region Filesystem probes

# How far up the tree Test-OptimizerPathPresent will walk looking for a directory
# it can actually list. Bounded so a pathological path cannot spin. Promoted here
# from Detectors\StartupItems.ps1 with the probe below.
$script:OptimizerPathProbeDepth = 8

function Test-OptimizerPathPresent {
    <#
        Tri-state existence probe: $true present, $false PROVED absent, $null
        undeterminable.

        Promoted out of Detectors\StartupItems.ps1 by chunk P2-C4 on its second
        consumer, the way Get-OptimizerExclusionMatch was promoted by P2-C2:
        moved here, with a one-line delegation left behind so the existing call
        sites and their tests are untouched. The junk detector needs the same
        answer about DIRECTORIES, hence -PathType.

        Everything that acts on "it is not there" rests on this returning $false
        only when the thing is genuinely gone. [System.IO.File]::Exists and
        [System.IO.Directory]::Exists both return $false for a path the current
        user is not allowed to look at, exactly as REVIEW.md records
        Get-ChildItem doing on Prefetch -- so a bare Exists() check reports every
        entry under a locked-down folder as absent. For the startup detector that
        meant offering to delete working software; for the junk detector it would
        mean reporting a location as "not on this machine" when it is merely
        unreadable at this privilege level.

        So an absent path is only believed once the containing directory has been
        successfully LISTED. Listing throws UnauthorizedAccessException where a
        bare Exists() would have quietly said "not there". If no ancestor can be
        listed, the answer is $null.

        The walk returns $false as soon as a parent is listable, without looking
        at what the listing contained: by that point Exists() has already said no
        for the requested PathType, so an entry of the OTHER type with the same
        name (a directory where a file was asked for) still means the requested
        thing is absent.
    #>
    [CmdletBinding()]
    [OutputType([Nullable[bool]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path,
        [Parameter()] [ValidateSet('File', 'Directory', 'Any')] [string] $PathType = 'File'
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    try {
        if (-not [System.IO.Path]::IsPathRooted($Path)) { return $null }

        $found = $false
        if ($PathType -ne 'Directory') { $found = [System.IO.File]::Exists($Path) }
        if (-not $found -and $PathType -ne 'File') { $found = [System.IO.Directory]::Exists($Path) }
        if ($found) { return [Nullable[bool]] $true }
    }
    catch {
        Write-Verbose "Could not probe path '$Path': $($_.Exception.Message)"
        return $null
    }

    # Not found. Prove we can actually see the folder it should be in, walking up
    # until something is listable.
    $current = $Path
    for ($depth = 0; $depth -lt $script:OptimizerPathProbeDepth; $depth++) {
        $parent = $null
        try { $parent = [System.IO.Path]::GetDirectoryName($current) } catch { return $null }
        if ([string]::IsNullOrWhiteSpace($parent)) { return $null }

        $leaf = $null
        try { $leaf = [System.IO.Path]::GetFileName($current) } catch { return $null }
        if ([string]::IsNullOrWhiteSpace($leaf)) { return $null }

        try {
            # A search pattern rather than a full listing: same permission
            # semantics, without enumerating a directory that might hold 100k
            # files. Throws DirectoryNotFoundException when $parent is absent and
            # UnauthorizedAccessException when it is merely unreadable, and those
            # two mean opposite things here.
            $null = [System.IO.Directory]::GetFileSystemEntries($parent, $leaf)
            return [Nullable[bool]] $false
        }
        catch [System.IO.DirectoryNotFoundException] {
            $current = $parent
            continue
        }
        catch {
            Write-Verbose "Could not list '$parent' while probing '$Path': $($_.Exception.Message)"
            return $null
        }
    }

    $null
}

function Get-OptimizerInnerException {
    # PowerShell wraps an exception thrown by a .NET METHOD in a
    # MethodInvocationException, so $_.Exception.GetType().Name reads
    # 'MethodInvocationException' for every [System.IO.Directory]:: failure and
    # the reason a source reports says nothing about what actually went wrong.
    # Returns the innermost real exception.
    [CmdletBinding()]
    [OutputType([System.Exception])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Exception
    )

    $current = $Exception
    while ($null -ne $current -and $current -is [System.Management.Automation.MethodInvocationException] -and $null -ne $current.InnerException) {
        $current = $current.InnerException
    }
    $current
}

#endregion

#region The in-use probe

function Test-OptimizerFileInUse {
    <#
        Is another process holding this file open? Returns one of Free / InUse /
        Undetermined, and every caller treats the last two identically.

        Promoted out of Detectors\JunkFiles.ps1 by chunk P3-C1 on its second
        consumer -- the removal dispatcher re-checks the gate at plan time,
        because the scan's answer has a shelf life of minutes -- the same way
        Test-OptimizerPathPresent was promoted here by P2-C4. The old name stays
        in JunkFiles.ps1 as a delegation, so P2-C4's call sites and tests are
        untouched.

        Probed by opening the file for READ with FileShare None: if anyone else
        has it open at all, the open fails with a sharing violation. Nothing is
        written and the handle is closed immediately.

        "Cannot tell" is never "free". A denied open, or a path too long for the
        API, means the answer is unknown, and an unknown file stays out of the
        deletable set.

        NOTE ON A VANISHED FILE. FileNotFoundException derives from IOException,
        so a file that disappeared between enumeration and probe answers 'InUse'
        here. That is the right default for a detector, and it is the WRONG answer
        for the dispatcher, which has to tell "gone" (a success) from "held" (a
        refusal). The dispatcher therefore proves presence with
        Test-OptimizerPathPresent FIRST and only asks this question about a file
        it has just proved is there. Do not "fix" that by widening this function:
        an Exists() check inside it would answer $false for a path the caller may
        not look at, which is the trap REVIEW.md records twice.

        Cost, measured on the development machine during P2-C4: 0.034 ms per file
        (1,964 files in %TEMP% in 0.067 s), so the gate runs over every candidate
        rather than a sample.

        -Access is a parameter rather than a constant so the guarantee this probe
        makes -- it never asks for more than read -- is stated at the call site as
        well as in the implementation, and is enforced here. It also keeps P2-C4's
        source-scanning assertion about JunkFiles.ps1 true after the promotion;
        see the report for chunk P3-C1.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path,
        [Parameter()] [System.IO.FileAccess] $Access = ([System.IO.FileAccess]::Read)
    )

    if ($Access -ne [System.IO.FileAccess]::Read) {
        throw "Test-OptimizerFileInUse is a read-only probe; -Access '$Access' would open the file for writing."
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $script:OptimizerInUseUndetermined }

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, $Access, [System.IO.FileShare]::None)
        return $script:OptimizerInUseFree
    }
    catch [System.IO.IOException] {
        # A sharing violation is the answer this gate exists for: somebody else
        # has it open. See the note above about FileNotFoundException.
        return $script:OptimizerInUseHeld
    }
    catch {
        Write-Verbose "Could not determine whether '$Path' is in use: $($_.Exception.Message)"
        return $script:OptimizerInUseUndetermined
    }
    finally {
        if ($null -ne $stream) {
            try { $stream.Dispose() } catch { }
        }
    }
}

#endregion

#region Path comparison and the protected-path gate

function ConvertTo-OptimizerComparablePath {
    # Normalised form for path comparison: full path, no trailing separator
    # (except on a drive root, where the separator is part of the path), used as
    # the dedupe key and by the containment test. Returns $null for anything that
    # will not normalise, and a caller must treat that as "do not touch this".
    #
    # Promoted out of Detectors\JunkFiles.ps1 by chunk P3-C1 with the rest of the
    # protected-path cluster.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $full = $null
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return $null }
    if ([string]::IsNullOrWhiteSpace($full)) { return $null }

    $separator = [System.IO.Path]::DirectorySeparatorChar
    if ($full.Length -gt 3) { $full = $full.TrimEnd($separator) }
    $full
}

function Test-OptimizerPathWithin {
    <#
        Is $Path the same as, or underneath, $Container? Ordinal case-insensitive
        on normalised paths, with an explicit separator boundary so 'C:\Temp2' is
        not treated as being inside 'C:\Temp'.

        Deliberately a string comparison and not a resolution: it runs BEFORE
        anything is enumerated or acted on, on paths that may not exist, and it is
        the gate that keeps this project out of the user's own folders.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Container
    )

    $left  = ConvertTo-OptimizerComparablePath -Path $Path
    $right = ConvertTo-OptimizerComparablePath -Path $Container
    if ([string]::IsNullOrWhiteSpace($left) -or [string]::IsNullOrWhiteSpace($right)) { return $false }

    if ([string]::Equals($left, $right, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }

    $separator = [string][System.IO.Path]::DirectorySeparatorChar
    $prefix = $right
    if (-not $prefix.EndsWith($separator)) { $prefix += $separator }

    $left.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-OptimizerFixedDriveRoot {
    # Fixed-drive roots, for the "a whole drive is never a target" rule and for
    # the junk detector's Recycle Bin resolver. Removable and network drives are
    # out: this tool does not clean a USB stick it happens to find.
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $roots = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
            try {
                if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) { continue }
                if (-not $drive.IsReady) { continue }
                $roots.Add($drive.RootDirectory.FullName)
            }
            catch { continue }
        }
    }
    catch {
        Write-Verbose "Could not enumerate drives: $($_.Exception.Message)"
    }

    [string[]] $roots.ToArray()
}

function Get-OptimizerKnownUserFolderPath {
    <#
        The folders a person saves things into, resolved from the shell rather
        than spelled out. Anything that enumerates or acts on one of these is
        something that deletes somebody's tax return, so they are rejected in
        code, where no list edit and no Finding from an unreviewed source can
        reach.

        Downloads has no Environment.SpecialFolder member under .NET Framework
        4.x, so it comes from the User Shell Folders registry value that Explorer
        itself reads (which also picks up a redirected Downloads folder), with the
        profile-relative default as a fallback.

        -ProfileRoot is that fallback's base. It is a parameter so a test can
        point the resolver at a fabricated profile without touching the real one,
        and so a caller can state which profile root it is asking about.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ProfileRoot = ([Environment]::GetFolderPath('UserProfile'))
    )

    $paths = New-Object System.Collections.Generic.List[string]

    foreach ($folder in 'Desktop', 'DesktopDirectory', 'MyDocuments', 'MyPictures', 'MyVideos', 'MyMusic', 'Personal', 'CommonDocuments', 'CommonPictures', 'CommonVideos', 'CommonMusic') {
        $resolved = $null
        try { $resolved = [Environment]::GetFolderPath($folder) } catch { $resolved = $null }
        if (-not [string]::IsNullOrWhiteSpace($resolved)) { $paths.Add($resolved) }
    }

    $downloads = $null
    try {
        $downloads = [string](Get-ItemPropertyValue -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\User Shell Folders' -Name '{374DE290-123F-4565-9164-39C4925E467B}' -ErrorAction Stop)
        if (-not [string]::IsNullOrWhiteSpace($downloads)) {
            $downloads = [System.Environment]::ExpandEnvironmentVariables($downloads)
        }
    }
    catch { $downloads = $null }

    if ([string]::IsNullOrWhiteSpace($downloads) -and -not [string]::IsNullOrWhiteSpace($ProfileRoot)) {
        $downloads = Join-Path -Path $ProfileRoot -ChildPath 'Downloads'
    }
    if (-not [string]::IsNullOrWhiteSpace($downloads)) { $paths.Add($downloads) }

    [string[]] @($paths.ToArray() | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Get-OptimizerProtectedPath {
    <#
        Every filesystem path this project may not act on, with the reason and
        with HOW the check applies. Two kinds, and conflating them is what makes a
        naive version of this reject %TEMP% for being inside the user's profile:

          Subtree  the known user folders. A candidate may neither sit INSIDE one
                   nor CONTAIN one. Both directions, because a path containing
                   Documents reaches it just as surely as a path inside it.

          Root     the profile root, the Windows folder and the fixed drive roots.
                   A candidate may not BE one or CONTAIN one, but living inside
                   one is the normal case -- %TEMP% is inside the profile,
                   %SystemRoot%\Logs\CBS is inside Windows, and both are
                   legitimate targets.

        Promoted out of Detectors\JunkFiles.ps1 by chunk P3-C1, on its second
        consumer: the removal dispatcher is the LAST gate before anything is
        acted on and, unlike a detector, it takes Findings from a run log or a
        GUI rather than only from code it can see. The junk detector's own
        Get-JunkProtectedPath now returns this list plus the one entry that
        belongs to it alone (the WinSxS component store), so the universal rules
        are stated once.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    foreach ($path in @(Get-OptimizerKnownUserFolderPath)) {
        [pscustomobject]@{
            Path   = $path
            Match  = 'Subtree'
            Reason = 'it is a folder the user saves things into, and this tool never acts on one'
        }
    }

    $windowsRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
    if (-not [string]::IsNullOrWhiteSpace($windowsRoot)) {
        [pscustomobject]@{
            Path   = $windowsRoot
            Match  = 'Root'
            Reason = 'the Windows folder as a whole is never a target; name the specific thing inside it'
        }
    }

    $profileRoot = [Environment]::GetFolderPath('UserProfile')
    if (-not [string]::IsNullOrWhiteSpace($profileRoot)) {
        [pscustomobject]@{
            Path   = $profileRoot
            Match  = 'Root'
            Reason = 'the user profile root contains the folders the user saves things into'
        }
    }

    foreach ($drive in @(Get-OptimizerFixedDriveRoot)) {
        [pscustomobject]@{
            Path   = $drive
            Match  = 'Root'
            Reason = 'a whole drive is never a target'
        }
    }
}

function Get-OptimizerProtectedPathConflict {
    # Returns the first protected path a candidate collides with, or $null.
    # 'Subtree' entries collide in either direction -- a candidate inside
    # Documents is obviously wrong, and so is one that CONTAINS Documents.
    # 'Root' entries collide only when the candidate is, or contains, the root:
    # everything a person owns lives inside the profile, so "inside" cannot be
    # the test there.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ProtectedPath
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or $null -eq $ProtectedPath) { return $null }

    foreach ($protected in $ProtectedPath) {
        if ($null -eq $protected) { continue }

        # NOT named $protectedPath: PowerShell variable names are case-INSENSITIVE,
        # so that would be the $ProtectedPath parameter, whose [psobject[]] type
        # constraint is re-applied on assignment -- the array would silently become
        # a one-element array holding this string, and the next call would fail on
        # a type conversion nowhere near the real mistake.
        $protectedRoot = [string](Get-OptimizerProperty -InputObject $protected -Name 'Path')
        if ([string]::IsNullOrWhiteSpace($protectedRoot)) { continue }

        $mode = [string](Get-OptimizerProperty -InputObject $protected -Name 'Match' -Default 'Subtree')

        # Contains-or-equals: Test-OptimizerPathWithin is true when the two paths
        # are the same, so this covers "the candidate IS the protected root" too.
        if (Test-OptimizerPathWithin -Path $protectedRoot -Container $Path) { return $protected }

        if ($mode -ne 'Root' -and (Test-OptimizerPathWithin -Path $Path -Container $protectedRoot)) {
            return $protected
        }
    }

    $null
}

#endregion
