<#
    OemBloatware detector -- chunk P2-C1.

    Finds OEM/preinstalled bloatware by matching what is installed on the machine
    against the curated whitelist in Data\known-bloatware.json, and returns the
    matches as Findings with Confidence = Known.

    This file DETECTS ONLY. It never uninstalls, deletes, disables or writes
    anything; every registry and package call in it is a read. The dispatcher
    (chunk P3-C1) owns all removal behaviour, including how RemovalMethod is acted
    on. Win32_Product / WMI is deliberately not used anywhere: it triggers an MSI
    reconfiguration pass across every other installed MSI application.

    Public surface (registered in the .psm1 export list and the .psd1 manifest):
      Get-KnownBloatwareList   load + validate the curated whitelist
      Find-KnownBloatware      pure matcher: installed apps + whitelist -> Findings
      Invoke-OemBloatwareScan  scan this machine -> OemScanResult (Findings + completeness)
#>

# Captured at dot-source time: $PSScriptRoot is this file's folder while the .psm1
# dot-sources it, but resolves to the module folder once the functions are called.
$script:OemBloatwareDataRoot = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Data'

# The three inventory sources, in the order they are reported.
$script:OemSourceAppx        = 'AppxPackage'
$script:OemSourceProvisioned = 'AppxProvisionedPackage'
$script:OemSourceRegistry    = 'RegistryUninstall'

# Whitelist match fields, and which installed-app property each is compared against.
# Anything outside this set is rejected at load time so a typo cannot silently
# disable a whitelist entry.
$script:OemMatchFields = @('appxPackageName', 'appxPackageFamilyName', 'registryDisplayName', 'registryPublisher')

# Minimum literal prefix in front of a trailing '*'. See Data\README.md.
$script:OemMinimumPatternPrefix = 6

# The only accepted values of an entry's optional 'sensitiveClass'. This is a
# closed set on purpose: a typo must fail the load rather than quietly downgrade
# an entry to an ordinary one and lose the extra rules that go with the class.
$script:OemSensitiveClasses = @('security-trial')

# The narrow carve-out to the "never whitelist security software" rule
# (docs/STATE.md, 2026-08-25): OEM trial/nagware editions of security suites may
# be listed, and the loader -- not convention -- enforces what that costs. A
# 'security-trial' entry must require consent, must be wildcard-free in EVERY
# match field, and must say in its reason that it is the trial edition. The point
# is that it cannot be possible to add a wildcarded security entry and still have
# the list load: a broad pattern here would match the security product the user
# chose and paid for, which is the one outcome this project must never produce.
# The reason check is a keyword test because that is the only structural handle on
# prose; see Data\README.md.
# Findings from an entry whose identifier has never been seen on real hardware say
# so in plain words. Silence means the opposite: the identifier was measured. The
# GUI gets the same fact structurally via WhitelistEntryId -> EvidenceSource; this
# line is for the human reading the evidence, who should not have to know the
# whitelist schema to learn that a row is unverified.
$script:OemPublicListEvidenceSource = 'public-list'
$script:OemPublicListEvidenceText   = 'Provenance: this whitelist entry comes from a published bloatware list. Its identifier has never been observed on real hardware by this project, so the match is only as good as that list.'

$script:OemSecurityTrialClass       = 'security-trial'
$script:OemSecurityTrialReasonWords = @('trial', 'nagware')

$script:OemScanResultTypeName   = 'Win11Optimizer.OemScanResult'
$script:OemScanSourceTypeName   = 'Win11Optimizer.OemScanSource'
$script:OemInstalledAppTypeName = 'Win11Optimizer.InstalledApp'

#region Internal helpers

function Get-OemPropertyValue {
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

function Assert-OemPattern {
    # Enforces the deliberately tiny pattern syntax documented in Data\README.md:
    # an exact string, or a prefix of at least $OemMinimumPatternPrefix characters
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
    if ($prefix.Length -lt $script:OemMinimumPatternPrefix) {
        throw "$Context : pattern '$Pattern' has a literal prefix shorter than $($script:OemMinimumPatternPrefix) characters. A whitelist entry is a safety claim; broad prefixes are not allowed."
    }
}

function Test-OemPatternMatch {
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

function Test-OemAnyPatternMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [string[]] $Pattern,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Value
    )

    if ($null -eq $Pattern -or $Pattern.Count -eq 0) { return $false }
    foreach ($candidate in $Pattern) {
        if (Test-OemPatternMatch -Pattern $candidate -Value $Value) { return $true }
    }
    $false
}

function New-OemInstalledApp {
    # Normalized inventory record. Every property is always present (even when
    # null) so downstream code and the test suite can rely on the shape.
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
        [Parameter()] [AllowNull()] [string] $Detail
    )

    [pscustomobject]@{
        PSTypeName        = $script:OemInstalledAppTypeName
        Source            = $Source
        Id                = $Id
        Name              = $Name
        DisplayName       = $DisplayName
        PackageFamilyName = $PackageFamilyName
        Publisher         = $Publisher
        Version           = $Version
        UninstallString   = $UninstallString
        Detail            = $Detail
    }
}

function ConvertTo-OemPackageFamilyName {
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

function New-OemScanSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('Succeeded', 'Skipped', 'Failed')] [string] $Status,
        [Parameter()] [AllowNull()] [string] $Reason,
        [Parameter()] [int] $ItemCount = 0,
        [Parameter()] [double] $DurationSeconds = 0
    )

    [pscustomobject]@{
        PSTypeName      = $script:OemScanSourceTypeName
        Name            = $Name
        Status          = $Status
        Reason          = $Reason
        ItemCount       = $ItemCount
        DurationSeconds = $DurationSeconds
    }
}

#endregion

#region Inventory sources (all read-only)

function Get-OemAppxPackageItem {
    # Source 1: per-user UWP/Store packages. Works without elevation.
    [CmdletBinding()]
    param()

    foreach ($package in @(Get-AppxPackage -ErrorAction Stop)) {
        $name = [string](Get-OemPropertyValue -InputObject $package -Name 'Name')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $familyName = [string](Get-OemPropertyValue -InputObject $package -Name 'PackageFamilyName')
        $fullName   = [string](Get-OemPropertyValue -InputObject $package -Name 'PackageFullName')
        $version    = [string](Get-OemPropertyValue -InputObject $package -Name 'Version')
        $publisher  = [string](Get-OemPropertyValue -InputObject $package -Name 'Publisher')

        $identifier = $familyName
        if ([string]::IsNullOrWhiteSpace($identifier)) { $identifier = $name }

        New-OemInstalledApp -Source $script:OemSourceAppx `
            -Id $identifier `
            -Name $name `
            -DisplayName $name `
            -PackageFamilyName $familyName `
            -Publisher $publisher `
            -Version $version `
            -Detail $fullName
    }
}

function Get-OemProvisionedAppxItem {
    # Source 2: all-users/provisioned packages. Requires elevation just to READ --
    # Get-AppxProvisionedPackage -Online opens a DISM servicing session, which also
    # means it can legitimately fail while Windows Update is mid-install. Callers
    # treat a throw here as "this source did not run", never as a fatal error.
    [CmdletBinding()]
    param()

    foreach ($package in @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)) {
        $fullName = [string](Get-OemPropertyValue -InputObject $package -Name 'PackageName')
        $name     = [string](Get-OemPropertyValue -InputObject $package -Name 'DisplayName')

        if ([string]::IsNullOrWhiteSpace($name) -and -not [string]::IsNullOrWhiteSpace($fullName)) {
            $name = $fullName.Split('_')[0]
        }
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $familyName = ConvertTo-OemPackageFamilyName -PackageFullName $fullName
        $identifier = $familyName
        if ([string]::IsNullOrWhiteSpace($identifier)) { $identifier = $name }

        New-OemInstalledApp -Source $script:OemSourceProvisioned `
            -Id $identifier `
            -Name $name `
            -DisplayName $name `
            -PackageFamilyName $familyName `
            -Publisher ([string](Get-OemPropertyValue -InputObject $package -Name 'PublisherId')) `
            -Version ([string](Get-OemPropertyValue -InputObject $package -Name 'Version')) `
            -Detail $fullName
    }
}

function Get-OemRegistryUninstallItem {
    # Source 3: traditional Win32 apps. All three uninstall views are read -- leaving
    # out WOW6432Node hides most 32-bit software, which on a real machine is most of
    # the OEM-installed software.
    [CmdletBinding()]
    param(
        [Parameter()] [string[]] $Path = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        )
    )

    foreach ($root in $Path) {
        if (-not (Test-Path -LiteralPath $root)) {
            Write-Verbose "Uninstall view not present, skipping: $root"
            continue
        }

        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            $values = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $values) { continue }

            $displayName = [string](Get-OemPropertyValue -InputObject $values -Name 'DisplayName')
            if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

            $uninstall = [string](Get-OemPropertyValue -InputObject $values -Name 'QuietUninstallString')
            if ([string]::IsNullOrWhiteSpace($uninstall)) {
                $uninstall = [string](Get-OemPropertyValue -InputObject $values -Name 'UninstallString')
            }

            New-OemInstalledApp -Source $script:OemSourceRegistry `
                -Id $key.Name `
                -Name $displayName `
                -DisplayName $displayName `
                -Publisher ([string](Get-OemPropertyValue -InputObject $values -Name 'Publisher')) `
                -Version ([string](Get-OemPropertyValue -InputObject $values -Name 'DisplayVersion')) `
                -UninstallString $uninstall `
                -Detail $root
        }
    }
}

#endregion

#region Public: whitelist

function Get-KnownBloatwareList {
    <#
    .SYNOPSIS
        Loads and validates the curated known-bloatware whitelist.

    .DESCRIPTION
        Reads Data\known-bloatware.json and returns one normalized entry object per
        whitelist entry, with every field guaranteed present.

        Every rule in Data\README.md is enforced here and violations throw. That is
        deliberate: on this project a scan that quietly finds nothing is worse than a
        scan that fails, so a missing or malformed whitelist must be impossible to
        mistake for a clean machine.

    .PARAMETER Path
        Whitelist file to load. Defaults to Data\known-bloatware.json next to the
        module.

    .EXAMPLE
        Get-KnownBloatwareList | Select-Object Id, DisplayName, Reason
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if (-not $Path) {
        $Path = Join-Path -Path $script:OemBloatwareDataRoot -ChildPath 'known-bloatware.json'
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Known-bloatware whitelist not found at '$Path'. The OemBloatware detector cannot run without it -- an empty result here would be indistinguishable from a clean machine."
    }

    $raw = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Known-bloatware whitelist '$Path' is empty."
    }

    try {
        $document = ConvertFrom-Json -InputObject $raw
    }
    catch {
        throw "Known-bloatware whitelist '$Path' is not valid JSON: $($_.Exception.Message)"
    }

    # Read the property directly rather than through Get-OemPropertyValue: an empty
    # JSON array would unroll to nothing on the way out of a function and be
    # indistinguishable from a missing 'entries' key.
    $entriesProperty = $document.PSObject.Properties['entries']
    if ($null -eq $entriesProperty -or $null -eq $entriesProperty.Value) {
        throw "Known-bloatware whitelist '$Path' has no 'entries' array."
    }

    $entries = @($entriesProperty.Value)
    if ($entries.Count -lt 1) {
        throw "Known-bloatware whitelist '$Path' contains no entries."
    }

    $seenIds = @{}
    $index = -1

    foreach ($entry in $entries) {
        $index++
        $id = [string](Get-OemPropertyValue -InputObject $entry -Name 'id')
        $where = if ([string]::IsNullOrWhiteSpace($id)) { "entry #$index" } else { "entry '$id'" }

        foreach ($required in 'id', 'displayName', 'vendor', 'reason') {
            $value = [string](Get-OemPropertyValue -InputObject $entry -Name $required)
            if ([string]::IsNullOrWhiteSpace($value)) {
                throw "Known-bloatware whitelist '$Path': $where is missing a non-empty '$required'. Every entry is a safety claim and must say who it comes from and why it is bloat."
            }
        }

        if ($seenIds.ContainsKey($id.ToLowerInvariant())) {
            throw "Known-bloatware whitelist '$Path': duplicate entry id '$id'."
        }
        $seenIds[$id.ToLowerInvariant()] = $true

        # requiresConsent must be a real JSON boolean. The string "true" is the
        # failure this rejects: it is truthy in PowerShell, so accepting it would
        # let a mistyped entry look enforced while the Finding contract -- which
        # fails closed on a non-boolean -- and the carve-out check below disagreed
        # about what it meant. One shape, checked at the door.
        $requiresConsent = $false
        $consentProperty = $entry.PSObject.Properties['requiresConsent']
        if ($null -ne $consentProperty -and $null -ne $consentProperty.Value) {
            if ($consentProperty.Value -isnot [bool]) {
                throw "Known-bloatware whitelist '$Path': $where declares 'requiresConsent' as [$($consentProperty.Value.GetType().Name)] '$($consentProperty.Value)'. It must be a JSON boolean (true / false), not a string."
            }
            $requiresConsent = [bool] $consentProperty.Value
        }

        $sensitiveClass = $null
        $classProperty = $entry.PSObject.Properties['sensitiveClass']
        if ($null -ne $classProperty -and $null -ne $classProperty.Value) {
            $declaredClass = [string] $classProperty.Value
            if ($script:OemSensitiveClasses -notcontains $declaredClass) {
                throw "Known-bloatware whitelist '$Path': $where declares unknown 'sensitiveClass' '$declaredClass'. Allowed: $($script:OemSensitiveClasses -join ', ')."
            }
            $sensitiveClass = @($script:OemSensitiveClasses | Where-Object { $_ -eq $declaredClass })[0]
        }

        $match = Get-OemPropertyValue -InputObject $entry -Name 'match'
        if ($null -eq $match) {
            throw "Known-bloatware whitelist '$Path': $where has no 'match' block."
        }

        $rules = @{}
        foreach ($field in $script:OemMatchFields) { $rules[$field] = @() }

        foreach ($field in @($match.PSObject.Properties.Name)) {
            if ($script:OemMatchFields -notcontains $field) {
                throw "Known-bloatware whitelist '$Path': $where declares unknown match field '$field'. Allowed: $($script:OemMatchFields -join ', ')."
            }

            $patterns = @(@(Get-OemPropertyValue -InputObject $match -Name $field -Default @()) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ })

            if ($patterns.Count -lt 1) {
                throw "Known-bloatware whitelist '$Path': $where declares match field '$field' with no patterns."
            }

            foreach ($pattern in $patterns) {
                Assert-OemPattern -Pattern $pattern -Context "Known-bloatware whitelist '$Path', $where, field '$field'"
            }

            $rules[$field] = $patterns
        }

        $ruleCount = 0
        foreach ($field in $script:OemMatchFields) { $ruleCount += $rules[$field].Count }
        if ($ruleCount -lt 1) {
            throw "Known-bloatware whitelist '$Path': $where has an empty 'match' block."
        }

        if ($rules['registryPublisher'].Count -gt 0 -and $rules['registryDisplayName'].Count -lt 1) {
            throw "Known-bloatware whitelist '$Path': $where uses 'registryPublisher' without 'registryDisplayName'. Publisher alone is a guard, never a match -- matching every product from a vendor is too broad to be a safety claim."
        }

        if ($sensitiveClass -eq $script:OemSecurityTrialClass) {
            if (-not $requiresConsent) {
                throw "Known-bloatware whitelist '$Path': $where is sensitiveClass '$($script:OemSecurityTrialClass)' but does not set 'requiresConsent': true. A security-trial entry surfaces at 'Review needed' and never as safe to remove; it must say so structurally."
            }

            foreach ($field in $script:OemMatchFields) {
                foreach ($pattern in $rules[$field]) {
                    if ($pattern.Contains('*')) {
                        throw "Known-bloatware whitelist '$Path': $where is sensitiveClass '$($script:OemSecurityTrialClass)' and field '$field' contains the wildcard pattern '$pattern'. Security-trial entries are exact display names only, in every field, with no exceptions -- a prefix match here would eventually match the security product the user chose and paid for."
                    }
                }
            }

            $reason = [string](Get-OemPropertyValue -InputObject $entry -Name 'reason')
            $saysTrial = $false
            foreach ($word in $script:OemSecurityTrialReasonWords) {
                if ($reason.IndexOf($word, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $saysTrial = $true }
            }
            if (-not $saysTrial) {
                throw "Known-bloatware whitelist '$Path': $where is sensitiveClass '$($script:OemSecurityTrialClass)' but its 'reason' never says this is the trial or nagware edition. The reason is what the user reads before approving a removal, and for a security product it has to state which edition is being flagged. Mention '$($script:OemSecurityTrialReasonWords -join "' or '")'."
            }
        }

        [pscustomobject]@{
            PSTypeName            = 'Win11Optimizer.KnownBloatwareEntry'
            Id                    = $id
            DisplayName           = [string](Get-OemPropertyValue -InputObject $entry -Name 'displayName')
            Vendor                = [string](Get-OemPropertyValue -InputObject $entry -Name 'vendor')
            Reason                = [string](Get-OemPropertyValue -InputObject $entry -Name 'reason')
            EvidenceSource        = [string](Get-OemPropertyValue -InputObject $entry -Name 'evidenceSource' -Default 'unspecified')
            RequiresConsent       = [bool] $requiresConsent
            SensitiveClass        = $sensitiveClass
            Note                  = [string](Get-OemPropertyValue -InputObject $entry -Name 'note')
            AppxPackageName       = [string[]] $rules['appxPackageName']
            AppxPackageFamilyName = [string[]] $rules['appxPackageFamilyName']
            RegistryDisplayName   = [string[]] $rules['registryDisplayName']
            RegistryPublisher     = [string[]] $rules['registryPublisher']
        }
    }
}

#endregion

#region Public: matcher

function Find-KnownBloatware {
    <#
    .SYNOPSIS
        Matches a supplied installed-app inventory against whitelist entries and
        returns the matches as Findings.

    .DESCRIPTION
        The pure half of the detector: no machine access, no elevation, no I/O. It
        exists separately from Invoke-OemBloatwareScan so the matching and
        deduplication rules can be tested against fabricated input rather than
        against whatever happens to be installed on the test machine.

        Every returned object comes from New-Finding with Category 'OemBloatware'
        and Confidence 'Known'. This detector emits no heuristic findings: a
        whitelist match, or nothing. Surfacing unrecognized-but-unused software is
        chunk P2-C3's job. An entry marked 'requiresConsent' produces a Finding
        that is still Confidence 'Known' but carries RequiresConsent, so its
        SafetyLabel reads 'Review needed' -- certainty and consent are separate
        questions and the contract keeps them separate.

        Each Finding also carries WhitelistEntryId: the id of the entry it matched.
        That is the join key back into Get-KnownBloatwareList, where a caller can
        read the entry's evidenceSource, sensitiveClass and requiresConsent
        structurally instead of string-matching the Evidence prose. It lives on the
        OemBloatware Findings rather than on the Finding contract because
        provenance is a whitelist concept; the other detectors have no whitelist.

        Deduplication: one Finding per (whitelist entry, RemovalMethod). An app found
        as both a per-user Appx package and a provisioned package collapses into a
        single Appx Finding whose Evidence names both sources, because clearing it
        fully needs both calls and the dispatcher has to know that. An app that is
        genuinely installed twice by two different mechanisms -- an Appx package plus
        a separate Win32 install of the same product -- stays two Findings, because
        those are two installs needing two different removal calls and RemovalMethod
        holds only one value.

    .PARAMETER InstalledApp
        Inventory records to match. Each is expected to carry: Source
        ('AppxPackage', 'AppxProvisionedPackage' or 'RegistryUninstall'), Id, Name,
        DisplayName, and -- where applicable -- PackageFamilyName, Publisher, Version,
        UninstallString. Missing properties are tolerated.

    .PARAMETER KnownBloatwareEntry
        Whitelist entries as returned by Get-KnownBloatwareList.

    .EXAMPLE
        Find-KnownBloatware -InstalledApp $inventory -KnownBloatwareEntry (Get-KnownBloatwareList)
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [psobject[]] $InstalledApp,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject[]] $KnownBloatwareEntry
    )

    $matched = [ordered]@{}

    foreach ($app in @($InstalledApp)) {
        if ($null -eq $app) { continue }

        $source     = [string](Get-OemPropertyValue -InputObject $app -Name 'Source')
        $isAppx     = ($source -eq $script:OemSourceAppx -or $source -eq $script:OemSourceProvisioned)
        $isRegistry = ($source -eq $script:OemSourceRegistry)

        if (-not $isAppx -and -not $isRegistry) {
            Write-Verbose "Ignoring inventory record with unrecognized Source '$source'."
            continue
        }

        $name        = [string](Get-OemPropertyValue -InputObject $app -Name 'Name')
        $displayName = [string](Get-OemPropertyValue -InputObject $app -Name 'DisplayName')
        $familyName  = [string](Get-OemPropertyValue -InputObject $app -Name 'PackageFamilyName')
        $publisher   = [string](Get-OemPropertyValue -InputObject $app -Name 'Publisher')
        $version     = [string](Get-OemPropertyValue -InputObject $app -Name 'Version')
        $identifier  = [string](Get-OemPropertyValue -InputObject $app -Name 'Id')
        $uninstall   = [string](Get-OemPropertyValue -InputObject $app -Name 'UninstallString')

        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $name }
        if ([string]::IsNullOrWhiteSpace($identifier)) { $identifier = $displayName }

        foreach ($entry in $KnownBloatwareEntry) {
            if ($null -eq $entry) { continue }

            $hit = $false
            $removalMethod = $null

            if ($isAppx) {
                $appxPatterns   = [string[]](Get-OemPropertyValue -InputObject $entry -Name 'AppxPackageName' -Default @())
                $familyPatterns = [string[]](Get-OemPropertyValue -InputObject $entry -Name 'AppxPackageFamilyName' -Default @())

                if ((Test-OemAnyPatternMatch -Pattern $appxPatterns -Value $name) -or
                    (Test-OemAnyPatternMatch -Pattern $familyPatterns -Value $familyName)) {
                    $hit = $true
                    $removalMethod = 'Appx'
                }
            }
            else {
                $namePatterns = [string[]](Get-OemPropertyValue -InputObject $entry -Name 'RegistryDisplayName' -Default @())
                if (Test-OemAnyPatternMatch -Pattern $namePatterns -Value $displayName) {
                    # registryPublisher is an AND-guard, never a match of its own.
                    $publisherPatterns = [string[]](Get-OemPropertyValue -InputObject $entry -Name 'RegistryPublisher' -Default @())
                    if ($null -eq $publisherPatterns -or $publisherPatterns.Count -lt 1) {
                        $hit = $true
                    }
                    elseif (Test-OemAnyPatternMatch -Pattern $publisherPatterns -Value $publisher) {
                        $hit = $true
                    }
                    if ($hit) { $removalMethod = 'RegistryUninstallString' }
                }
            }

            if (-not $hit) { continue }

            $entryId      = [string](Get-OemPropertyValue -InputObject $entry -Name 'Id')
            $entryName    = [string](Get-OemPropertyValue -InputObject $entry -Name 'DisplayName')
            $entryVendor  = [string](Get-OemPropertyValue -InputObject $entry -Name 'Vendor')
            $entryReason  = [string](Get-OemPropertyValue -InputObject $entry -Name 'Reason')
            $entrySource  = [string](Get-OemPropertyValue -InputObject $entry -Name 'EvidenceSource')
            $entryConsent = [bool](Get-OemPropertyValue -InputObject $entry -Name 'RequiresConsent' -Default $false)

            $key = '{0}|{1}' -f $entryId.ToLowerInvariant(), $removalMethod

            if (-not $matched.Contains($key)) {
                $shownName = $entryName
                if ([string]::IsNullOrWhiteSpace($shownName)) { $shownName = $displayName }

                $record = [pscustomobject]@{
                    EntryId         = $entryId
                    DisplayName     = $shownName
                    RemovalMethod   = $removalMethod
                    Id              = $identifier
                    RequiresConsent = $entryConsent
                    Sources         = (New-Object System.Collections.Generic.List[string])
                    Evidence        = (New-Object System.Collections.Generic.List[string])
                }
                $record.Evidence.Add("Matches curated known-bloatware entry '$entryId' ($shownName, $entryVendor).")
                $record.Evidence.Add($entryReason)
                if ($entrySource -eq $script:OemPublicListEvidenceSource) {
                    $record.Evidence.Add($script:OemPublicListEvidenceText)
                }
                if ($entryConsent) {
                    $record.Evidence.Add('This entry requires an explicit human OK before anything is removed, however certain the match is.')
                }
                $matched[$key] = $record
            }

            $record = $matched[$key]
            if (-not $record.Sources.Contains($source)) { $record.Sources.Add($source) }

            if ($source -eq $script:OemSourceAppx) {
                $shown = $familyName
                if ([string]::IsNullOrWhiteSpace($shown)) { $shown = $name }
                $line = "Installed as a per-user Appx package: $shown"
                if (-not [string]::IsNullOrWhiteSpace($version)) { $line += " (version $version)" }
                $record.Evidence.Add("$line.")
                # Prefer the per-user family name as the Finding Id: it is the stable
                # identifier the Appx path takes.
                if (-not [string]::IsNullOrWhiteSpace($familyName)) { $record.Id = $familyName }
            }
            elseif ($source -eq $script:OemSourceProvisioned) {
                $shown = [string](Get-OemPropertyValue -InputObject $app -Name 'Detail')
                if ([string]::IsNullOrWhiteSpace($shown)) { $shown = $name }
                $record.Evidence.Add("Provisioned for all users in the Windows image: $shown.")
            }
            else {
                $line = "Registered as an installed Win32 application: $displayName"
                if (-not [string]::IsNullOrWhiteSpace($publisher)) { $line += " by $publisher" }
                if (-not [string]::IsNullOrWhiteSpace($version)) { $line += ", version $version" }
                $record.Evidence.Add("$line (uninstall key $identifier).")
                if ([string]::IsNullOrWhiteSpace($uninstall)) {
                    $record.Evidence.Add('The uninstall key records no uninstall command; the dispatcher will need another path for this one.')
                }
            }
        }
    }

    foreach ($record in $matched.Values) {
        if ($record.Sources.Contains($script:OemSourceAppx) -and $record.Sources.Contains($script:OemSourceProvisioned)) {
            $record.Evidence.Add('Present both per-user and provisioned: clearing it fully needs both the per-user and the provisioned call.')
        }

        $finding = New-Finding -Category 'OemBloatware' `
            -Id $record.Id `
            -DisplayName $record.DisplayName `
            -Evidence ([string[]] $record.Evidence.ToArray()) `
            -Confidence 'Known' `
            -RequiresConsent:$record.RequiresConsent `
            -RemovalMethod $record.RemovalMethod

        # Added here, not in New-Finding: the join key back to the whitelist is an
        # OemBloatware concept, and the generic contract has no whitelist to join to.
        $finding | Add-Member -MemberType NoteProperty -Name 'WhitelistEntryId' -Value $record.EntryId

        $finding
    }
}

#endregion

#region Public: scan

function Invoke-OemBloatwareScan {
    <#
    .SYNOPSIS
        Scans this machine for known OEM/preinstalled bloatware.

    .DESCRIPTION
        Enumerates the three inventory sources (per-user Appx packages, provisioned
        all-users Appx packages, and the three registry uninstall views), matches
        them against the curated whitelist, and returns a single OemScanResult object
        carrying both the Findings and which sources actually ran.

        Read-only. Nothing is uninstalled, disabled or written; -WhatIf and -Confirm
        are deliberately not implemented because there is no state change for them to
        guard.

        ELEVATION. Reading provisioned (all-users) Appx packages requires
        administrator rights, so a non-elevated scan sees strictly less than the
        truth. Rather than throwing or quietly reporting less, the scan runs every
        source it can, marks itself incomplete, and says which source was skipped and
        why. Findings are reachable only through the result object's Findings
        property, so a caller cannot receive a partial list and mistake it for a
        complete one. A warning is also written to the warning stream when the scan is
        incomplete, for the benefit of interactive callers.

        This chunk does not self-elevate; relaunching the process under UAC belongs to
        the application entry point.

    .PARAMETER WhitelistPath
        Whitelist file to match against. Defaults to Data\known-bloatware.json.

    .PARAMETER RegistryPath
        Uninstall views to read. Defaults to the HKLM, HKLM\WOW6432Node and HKCU
        views -- all three, because omitting WOW6432Node hides most 32-bit software.

    .EXAMPLE
        $scan = Invoke-OemBloatwareScan
        if (-not $scan.IsComplete) { "Partial scan: $($scan.IncompleteReason)" }
        $scan.Findings | Format-Table DisplayName, RemovalMethod, SafetyLabel

    .OUTPUTS
        Win11Optimizer.OemScanResult
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $WhitelistPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]] $RegistryPath
    )

    $startedUtc = [datetime]::UtcNow
    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

    Write-OptimizerLog -EventName 'OemScanStarted' -Message 'OEM bloatware scan started.'

    # Load the whitelist first and let a failure propagate: a scan with no usable
    # whitelist must not return an empty, apparently-clean result.
    try {
        $whitelistArguments = @{}
        if ($WhitelistPath) { $whitelistArguments['Path'] = $WhitelistPath }
        $whitelist = @(Get-KnownBloatwareList @whitelistArguments)
    }
    catch {
        Write-OptimizerLog -EventName 'OemScanFailed' -Level 'Error' `
            -Message "Known-bloatware whitelist could not be loaded: $($_.Exception.Message)"
        throw
    }

    Write-OptimizerLog -EventName 'OemWhitelistLoaded' -Message "Loaded $($whitelist.Count) known-bloatware whitelist entries."

    $isElevated = Test-IsElevated
    $inventory = New-Object System.Collections.Generic.List[psobject]
    $sources = New-Object System.Collections.Generic.List[psobject]

    # --- Source 1: per-user Appx packages -------------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $items = @(Get-OemAppxPackageItem)
        $timer.Stop()
        foreach ($item in $items) { $inventory.Add($item) }
        $sources.Add((New-OemScanSource -Name $script:OemSourceAppx -Status 'Succeeded' `
            -ItemCount $items.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    catch {
        $timer.Stop()
        $sources.Add((New-OemScanSource -Name $script:OemSourceAppx -Status 'Failed' `
            -Reason "Enumerating per-user Appx packages failed: $($_.Exception.Message)" `
            -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }

    # --- Source 2: provisioned Appx packages (elevated only) -------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $isElevated) {
        $timer.Stop()
        $sources.Add((New-OemScanSource -Name $script:OemSourceProvisioned -Status 'Skipped' `
            -Reason 'Not elevated. Reading provisioned (all-users) Appx packages requires administrator rights; re-run this scan as administrator to see them.' `
            -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    else {
        try {
            $items = @(Get-OemProvisionedAppxItem)
            $timer.Stop()
            foreach ($item in $items) { $inventory.Add($item) }
            $sources.Add((New-OemScanSource -Name $script:OemSourceProvisioned -Status 'Succeeded' `
                -ItemCount $items.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
        }
        catch {
            # A DISM servicing session can be busy for legitimate reasons -- another
            # servicing operation, or Windows Update mid-install. That is "this
            # source did not run", not a fatal scan error.
            $timer.Stop()
            $sources.Add((New-OemScanSource -Name $script:OemSourceProvisioned -Status 'Failed' `
                -Reason "Reading provisioned Appx packages failed: $($_.Exception.Message) A servicing session may be in progress (for example a Windows Update install); try again later." `
                -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
        }
    }

    # --- Source 3: registry uninstall views ------------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $registryArguments = @{}
        if ($RegistryPath) { $registryArguments['Path'] = $RegistryPath }
        $items = @(Get-OemRegistryUninstallItem @registryArguments)
        $timer.Stop()
        foreach ($item in $items) { $inventory.Add($item) }
        $sources.Add((New-OemScanSource -Name $script:OemSourceRegistry -Status 'Succeeded' `
            -ItemCount $items.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    catch {
        $timer.Stop()
        $sources.Add((New-OemScanSource -Name $script:OemSourceRegistry -Status 'Failed' `
            -Reason "Reading the registry uninstall views failed: $($_.Exception.Message)" `
            -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }

    foreach ($source in $sources) {
        $level = if ($source.Status -eq 'Succeeded') { 'Info' } else { 'Warning' }
        Write-OptimizerLog -EventName 'OemScanSource' -Level $level `
            -Message "Source $($source.Name): $($source.Status)." `
            -Data ([ordered]@{
                Source          = $source.Name
                Status          = $source.Status
                ItemCount       = $source.ItemCount
                DurationSeconds = $source.DurationSeconds
                Reason          = $source.Reason
            })
    }

    $findings = @(Find-KnownBloatware -InstalledApp $inventory.ToArray() -KnownBloatwareEntry $whitelist |
        Sort-Object DisplayName, RemovalMethod)

    $totalTimer.Stop()

    $defaultWhitelistPath = Join-Path -Path $script:OemBloatwareDataRoot -ChildPath 'known-bloatware.json'

    $result = [pscustomobject]@{
        PSTypeName      = $script:OemScanResultTypeName
        Detector        = 'OemBloatware'
        Category        = 'OemBloatware'
        StartedUtc      = $startedUtc
        DurationSeconds = [math]::Round($totalTimer.Elapsed.TotalSeconds, 3)
        IsElevated      = $isElevated
        WhitelistPath   = $(if ($WhitelistPath) { $WhitelistPath } else { $defaultWhitelistPath })
        WhitelistCount  = $whitelist.Count
        InventoryCount  = $inventory.Count
        Sources         = [psobject[]] $sources.ToArray()
        Findings        = [psobject[]] $findings
    }

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
            "Complete scan of $($this.InventoryCount) installed items: $(@($this.Findings).Count) known-bloatware findings."
        }
        else {
            "PARTIAL scan of $($this.InventoryCount) installed items: $(@($this.Findings).Count) known-bloatware findings so far. $($this.IncompleteReason)"
        }
    }

    Write-OptimizerLog -EventName 'OemScanCompleted' `
        -Level $(if ($result.IsComplete) { 'Info' } else { 'Warning' }) `
        -Message $result.SummaryText `
        -Data ([ordered]@{
            IsComplete      = $result.IsComplete
            IsElevated      = $isElevated
            FindingCount    = @($result.Findings).Count
            InventoryCount  = $result.InventoryCount
            DurationSeconds = $result.DurationSeconds
        })

    if (-not $result.IsComplete) {
        Write-Warning "OEM bloatware scan is INCOMPLETE -- this list is partial. $($result.IncompleteReason)"
    }

    $result
}

#endregion
