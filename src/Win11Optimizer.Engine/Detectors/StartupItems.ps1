<#
    StartupItems detector -- chunk P2-C2.

    Enumerates everything on this machine that runs automatically at logon or boot,
    and returns Findings for the small, defensible subset that is actually junk.

    THE RULE THIS FILE EXISTS TO OBEY
    ---------------------------------
    "Autostarting is not evidence of being unwanted."

    Almost everything a person deliberately installs adds a startup entry. On the
    development machine Discord, Steam, Overwolf, Epic, EA, Riot, Spotify, OneDrive,
    Google Drive, NZXT CAM and Docker Desktop all autostart, and every one of them
    is there because the user put it there. A detector that flags what autostarts
    produces a long, confident, wrong list. So there are exactly TWO ways an entry
    becomes a Finding:

      1. it matches the shipped, reviewed curated list (Data\known-startup-items.json), or
      2. it is an ORPHAN -- its target executable or script is not on disk.

    Everything else is INVENTORIED and returned in the scan result, and never
    flagged. The inventory is what P4-C1 shows the user beside the Findings; it is
    this category's equivalent of P2-C3's Classifications.

    There is deliberately NO publisher heuristic. Flagging what is not
    Microsoft-published would produce 22 Findings on this machine, every one of them
    software the user chose. It was considered and rejected.

    THE SECOND, QUIETER FAILURE MODE
    --------------------------------
    "A startup source you did not read is not an empty startup source."

    There are four independent mechanisms and they do not overlap. Each is its own
    scan source with its own status, item count and reason, so reading three of
    them and reporting a complete scan is impossible:

      RunKeys         Run and RunOnce under HKLM, HKLM\WOW6432Node and HKCU
                      (and HKCU\WOW6432Node where it exists). Omitting
                      WOW6432Node hid 38% of Win32 software in P2-C3.
      StartupFolders  the per-user and all-users Startup folders, resolved from
                      the shell known folders rather than hard-coded paths.
      ScheduledTasks  tasks with a logon or boot trigger. Tasks under
                      \Microsoft\Windows\ are OS components: inventoried, never
                      flagged, enforced in code rather than by list entry.
      Services        services with an automatic start mode. Review-only, always:
                      every Service Finding sets RequiresConsent, so it can only
                      ever surface as "Review needed".

    This file DETECTS ONLY. It never removes, disables, deletes or writes anything;
    every registry, filesystem, Task Scheduler and service call in it is a read.
    Win32_Product / WMI is deliberately not used anywhere. Win32_StartupCommand is
    not used either, and the measurement behind that is in
    docs\handoff\05-startup-items.report.md.

    Public surface (registered in the .psm1 export list and the .psd1 manifest):
      Get-KnownStartupItemList  load + validate the curated list
      Get-StartupItemInventory  read this machine -> items + per-source status
      Find-UnwantedStartupItem  pure: inventory + lists -> Findings
      Invoke-StartupItemScan    scan this machine -> scan result

    ASCII only -- see Detectors\README.md for what a UTF-8 em dash does to 5.1.
#>

#region Constants

# The four mechanisms. Named once so the inventory records, the source list and
# the matcher cannot drift apart on spelling.
$script:StartupMechanismRunKey  = 'RunKey'
$script:StartupMechanismFolder  = 'StartupFolder'
$script:StartupMechanismTask    = 'ScheduledTask'
$script:StartupMechanismService = 'Service'

# Scan-source names, as they appear in the scan result's Sources list.
$script:StartupSourceRunKeys  = 'RunKeys'
$script:StartupSourceFolders  = 'StartupFolders'
$script:StartupSourceTasks    = 'ScheduledTasks'
$script:StartupSourceServices = 'Services'

# The enabled/disabled tri-state. 'Unknown' is a first-class outcome, not a
# default that quietly becomes 'Enabled': an entry whose state cannot be decoded
# is inventory, never a Finding. Guessing "enabled" would let this detector flag
# something the user already turned off, which is exactly the padding that makes a
# tool in this category look like it is inventing work.
$script:StartupStateEnabled  = 'Enabled'
$script:StartupStateDisabled = 'Disabled'
$script:StartupStateUnknown  = 'Unknown'

# Which RemovalMethod (Finding contract, P1-C1) each mechanism needs. Recorded
# only; nothing here acts on it. The dispatcher (P3-C1) owns removal.
$script:StartupRemovalMethod = @{
    $script:StartupMechanismRunKey  = 'RegistryRunKey'
    $script:StartupMechanismFolder  = 'FileDelete'
    $script:StartupMechanismTask    = 'TaskScheduler'
    $script:StartupMechanismService = 'ServiceDisable'
}

# Which Finding Category each mechanism reports under. Services are their own
# category because docs\STATE.md gives them their own treatment.
$script:StartupFindingCategory = @{
    $script:StartupMechanismRunKey  = 'StartupItem'
    $script:StartupMechanismFolder  = 'StartupItem'
    $script:StartupMechanismTask    = 'StartupItem'
    $script:StartupMechanismService = 'Service'
}

# Every Run/RunOnce view, with the StartupApproved store Task Manager records its
# enabled/disabled state in. HKLM\WOW6432Node is here because leaving it out is
# this project's oldest recurring bug: on the development machine the ONLY
# machine-scope 32-bit Run entry (Discord) lives there and appears nowhere else.
$script:StartupRunKeyView = @(
    [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                 Scope = 'Machine'; View = 'Native';      IsRunOnce = $false; ApprovalPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';             Scope = 'Machine'; View = 'Native';      IsRunOnce = $true;  ApprovalPath = $null }
    [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';     Scope = 'Machine'; View = 'WOW6432Node'; IsRunOnce = $false; ApprovalPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' }
    [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'Machine'; View = 'WOW6432Node'; IsRunOnce = $true;  ApprovalPath = $null }
    [pscustomobject]@{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                 Scope = 'User';    View = 'Native';      IsRunOnce = $false; ApprovalPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    [pscustomobject]@{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';             Scope = 'User';    View = 'Native';      IsRunOnce = $true;  ApprovalPath = $null }
    [pscustomobject]@{ Path = 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';     Scope = 'User';    View = 'WOW6432Node'; IsRunOnce = $false; ApprovalPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' }
    [pscustomobject]@{ Path = 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'User';    View = 'WOW6432Node'; IsRunOnce = $true;  ApprovalPath = $null }
)

# The StartupApproved stores for the two Startup folders.
$script:StartupFolderApprovalPath = @{
    'User'    = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    'Machine' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
}

# StartupApproved value decoding, MEASURED on the development machine 2026-08-25
# and confirmed against Task Manager's own display -- see the report.
#
# The value is a 12-byte REG_BINARY. Byte 0 carries the state; bytes 4-11 are a
# FILETIME recording WHEN the entry was turned off.
#
# The trap, and the reason this is a table rather than a rule about the timestamp:
# a DISABLED entry can carry an all-zero FILETIME. 'Docker Desktop' on this
# machine reads 01 00 00 00 00 00 00 00 00 00 00 00 and Task Manager shows it as
# off. Reading "zero timestamp means enabled" would have got that one backwards.
#
# Observed here: 0x01 disabled (10 entries), 0x04 enabled (1 entry). 0x02/0x06
# enabled and 0x03/0x07 disabled are the values documented elsewhere and follow
# the same parity, so they are in the table too. ANY OTHER BYTE IS 'Unknown' --
# a closed table rather than a parity rule, because parity would resolve an
# unrecognised value to 'Enabled', and 'Enabled' is the answer that lets an entry
# become a Finding.
$script:StartupApprovedState = @{
    1 = $script:StartupStateDisabled
    2 = $script:StartupStateEnabled
    3 = $script:StartupStateDisabled
    4 = $script:StartupStateEnabled
    6 = $script:StartupStateEnabled
    7 = $script:StartupStateDisabled
}

# The task namespace that is off limits, always. Enforced in code (see
# Find-UnwantedStartupItem), not as a list entry, so no curated entry and no
# future edit can reach into it.
$script:StartupProtectedTaskNamespace = '\Microsoft\Windows\'

# Service scoping. 2 is SERVICE_AUTO_START; a manual-start service is not a
# startup item. 0x10 | 0x20 are SERVICE_WIN32_OWN_PROCESS / _SHARE_PROCESS: a
# service key without one of those bits is a driver, and drivers are out of scope
# structurally rather than by list entry.
$script:StartupServiceAutomaticStart = 2
$script:StartupServiceWin32TypeMask  = 0x30
$script:StartupServiceRoot           = 'HKLM:\SYSTEM\CurrentControlSet\Services'

# The exclusion-list classes a service must never be flagged from, per the
# handoff prompt and docs\STATE.md: driver, security and firmware-update software
# have a blast radius this tool does not take on. Reused from P2-C3's list rather
# than restated as a second vendor list.
$script:StartupProtectedServiceClass = @('driver', 'driver-utility', 'security')

# The exclusion classes that survive a PROVED ORPHAN (chunk P2-C2a, docs\STATE.md
# 2026-08-26). The class exclusion above is right for a service that is running
# software; it is wrong for a service whose ImagePath binary is proved absent,
# because Windows has been failing to start it at every boot and it is protecting
# nothing. So for 'driver' and 'driver-utility' a proved orphan beats the
# exclusion.
#
# 'security' is the exception and stays on this list unconditionally: endpoint-
# protection anti-tamper minifilters HIDE their binaries from enumeration, so a
# directory that lists successfully without showing the file is exactly what
# tamper protection produces -- the one case where Test-StartupTargetPresent can
# return a confident $false that is a lie. The downside of getting that wrong is
# offering to disable live antivirus.
$script:StartupOrphanProofServiceClass = @('security')

# Curated-list match fields, and the closed set of provenance values. Same
# dialect and same primitives as the other two lists (Shared\Inventory.ps1).
$script:StartupMatchFields = @(
    'runValueName'
    'startupFolderFileName'
    'scheduledTaskName'
    'serviceName'
    'serviceDisplayName'
    'targetFileName'
)

$script:StartupProvenanceValues     = @('measured', 'published')
$script:StartupPublishedProvenance  = 'published'
$script:StartupPublishedEvidence    = 'Provenance: this list entry comes from a published source. The identifier has never been observed on real hardware by this project, so the match is only as good as that source.'

# Why a Finding exists. Carried on the Finding so the GUI does not have to parse
# prose to tell a curated match from an orphan.
$script:StartupReasonCurated = 'CuratedList'
$script:StartupReasonOrphan  = 'Orphan'

$script:StartupScanResultTypeName = 'Win11Optimizer.StartupScanResult'
$script:StartupScanSourceTypeName = 'Win11Optimizer.StartupScanSource'
$script:StartupInventoryTypeName  = 'Win11Optimizer.StartupInventory'
$script:StartupItemTypeName       = 'Win11Optimizer.StartupItem'
$script:StartupEntryTypeName      = 'Win11Optimizer.KnownStartupItemEntry'

# The probe depth that used to live here moved into Shared, next to
# Test-OptimizerPathPresent ($script:OptimizerPathProbeDepth), chunk P2-C4.

#endregion

#region Internal: records

function New-StartupScanSource {
    # Thin wrapper over the shared New-ScanSource so every source this detector
    # reports carries the detector's own type tag as well as the shared one.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('Succeeded', 'Skipped', 'Failed', 'Refused')] [string] $Status,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Reason,
        [Parameter()] [int] $ItemCount = 0,
        [Parameter()] [double] $DurationSeconds = 0
    )

    $arguments = @{
        AdditionalTypeName = $script:StartupScanSourceTypeName
        Name               = $Name
        Status             = $Status
        ItemCount          = $ItemCount
        DurationSeconds    = $DurationSeconds
    }
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $arguments['Reason'] = $Reason }

    New-ScanSource @arguments
}

function New-StartupItem {
    # One normalised record per autostart entry, whatever mechanism it came from.
    # Every property is always present (even when null) so the matcher, the tests
    # and P4-C1 can rely on the shape.
    #
    # TargetExists is a TRI-STATE and the distinction is load-bearing:
    #   $true   the target is on disk
    #   $false  the target is genuinely absent -- proved, not assumed
    #   $null   could not be determined (no target to resolve, a path we are not
    #           allowed to look at, a non-file action)
    # Only $false is an orphan. See Test-StartupTargetPresent for why $null is not
    # collapsed into $false.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Mechanism,
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [AllowNull()] [string] $DisplayName,
        [Parameter()] [AllowNull()] [string] $Command,
        [Parameter()] [AllowNull()] [string] $TargetPath,
        [Parameter()] [AllowNull()] [Nullable[bool]] $TargetExists,
        [Parameter()] [AllowNull()] [string] $Publisher,
        [Parameter(Mandatory)] [string] $Scope,
        [Parameter()] [AllowNull()] [string] $View,
        [Parameter()] [AllowNull()] [string] $Location,
        [Parameter()] [string] $EnabledState = $script:StartupStateUnknown,
        [Parameter()] [AllowNull()] [string] $EnabledStateDetail,
        [Parameter()] [AllowNull()] [string] $Trigger,
        [Parameter()] [bool] $IsProtectedNamespace = $false,
        [Parameter()] [AllowNull()] [string] $Detail
    )

    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $Name }

    [pscustomobject]@{
        PSTypeName           = $script:StartupItemTypeName
        Mechanism            = $Mechanism
        Id                   = $Id
        Name                 = $Name
        DisplayName          = $DisplayName
        Command              = $Command
        TargetPath           = $TargetPath
        TargetExists         = $TargetExists
        Publisher            = $Publisher
        Scope                = $Scope
        View                 = $View
        Location             = $Location
        EnabledState         = $EnabledState
        EnabledStateDetail   = $EnabledStateDetail
        Trigger              = $Trigger
        IsProtectedNamespace = $IsProtectedNamespace
        RemovalMethod        = $script:StartupRemovalMethod[$Mechanism]
        Category             = $script:StartupFindingCategory[$Mechanism]
        Detail               = $Detail
    }
}

#endregion

#region Internal: target resolution

function Get-StartupTargetPath {
    <#
        Pulls the executable/script path out of a command line.

        Handles the four shapes that actually turn up in Run values, shortcut
        targets and service ImagePath values:
          "C:\Path With Spaces\app.exe" --flag      quoted
          C:\Path\app.exe --flag                    unquoted, no spaces in path
          \??\C:\Path\driver.sys                    NT object-manager prefix
          %windir%\system32\thing.exe               environment variables

        Returns $null rather than a guess when the string cannot be resolved to a
        rooted path. A guessed path would be probed for existence and could
        manufacture an orphan Finding out of a parsing failure, which is the one
        way this detector could invent work for the user.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Command
    )

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }

    $text = $Command.Trim()
    try { $text = [System.Environment]::ExpandEnvironmentVariables($text) } catch { return $null }
    $text = $text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    # NT object-manager prefix, used by service ImagePath values.
    if ($text.StartsWith('\??\')) { $text = $text.Substring(4) }

    $candidate = $null

    if ($text.StartsWith('"')) {
        $closing = $text.IndexOf('"', 1)
        if ($closing -lt 1) { return $null }
        $candidate = $text.Substring(1, $closing - 1)
    }
    else {
        # Longest leading run that ends in a known executable extension wins. This
        # is what gets 'C:\Program Files\NZXT CAM\NZXT CAM.exe --startup' right
        # without a quote to lean on.
        $match = [regex]::Match($text, '^(?<path>.+?\.(exe|com|cmd|bat|scr|vbs|js|ps1|sys|dll))(\s|$)', 'IgnoreCase')
        if ($match.Success) {
            $candidate = $match.Groups['path'].Value
        }
        else {
            $space = $text.IndexOf(' ')
            $candidate = if ($space -gt 0) { $text.Substring(0, $space) } else { $text }
        }
    }

    if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }
    $candidate = $candidate.Trim().Trim('"').Trim()
    if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }

    # A bare relative name (a service whose ImagePath is just 'svchost.exe') is
    # resolved against System32, which is where the service control manager looks.
    try {
        if (-not [System.IO.Path]::IsPathRooted($candidate)) {
            $candidate = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath $candidate
        }
    }
    catch { return $null }

    try { $null = [System.IO.Path]::GetFullPath($candidate) } catch { return $null }

    $candidate
}

function Test-StartupTargetPresent {
    <#
        Tri-state existence probe: $true present, $false PROVED absent, $null
        undeterminable. The whole orphan rule rests on this returning $false only
        when the file is genuinely gone.

        The implementation lives in Shared\Inventory.ps1 as
        Test-OptimizerPathPresent, promoted there by chunk P2-C4 on its second
        consumer -- the junk detector needs the same answer about directories.
        This name stays as a one-line delegation so the call sites in this file
        and their tests are untouched, exactly as Get-OptimizerExclusionMatch was
        promoted in P2-C2.
    #>
    [CmdletBinding()]
    [OutputType([Nullable[bool]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    Test-OptimizerPathPresent -Path $Path -PathType File
}

function Get-StartupTargetCompany {
    # CompanyName off the target binary's version resource, used only to give the
    # shared exclusion matcher a Publisher to work with for services. Frequently
    # absent -- 3 of the 20 non-OS automatic services on the development machine
    # carry no CompanyName at all -- so callers must treat $null as "no publisher",
    # never as "not that vendor".
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    try {
        if (-not [System.IO.File]::Exists($Path)) { return $null }
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $company = [string] $info.CompanyName
        if ([string]::IsNullOrWhiteSpace($company)) { return $null }
        return $company.Trim()
    }
    catch {
        Write-Verbose "Could not read version info from '$Path': $($_.Exception.Message)"
        return $null
    }
}

function Get-StartupTargetSigner {
    # The Authenticode signer's common name, or $null. Nothing else.
    #
    # CompanyName (above) is OPTIONAL version-resource metadata and is blank for 4
    # of the 90 automatic services on the development machine, NvContainerLocalSystem
    # among them -- while the exclusion list's strongest service rules are
    # registryPublisher rules. A signature subject is not optional for anything
    # NVIDIA, Razer or MSI ship, so it is the better answer where it exists.
    #
    # Unsigned, missing, untrusted and unparseable all return $null. A failed
    # signature check means "no publisher", exactly as a blank CompanyName does; it
    # must NEVER be read as "not that vendor", and a partial or guessed vendor
    # string is worse than nothing on a list whose polarity is "never flag this".
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    try {
        if (-not [System.IO.Path]::IsPathRooted($Path)) { return $null }
        if (-not [System.IO.File]::Exists($Path)) { return $null }

        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($null -eq $signature) { return $null }

        # Only 'Valid' counts. NotSigned, HashMismatch, UnknownError and a chain
        # that does not build all mean the same thing here: no publisher.
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            Write-Verbose "Signature on '$Path' is $($signature.Status); treating it as no publisher."
            return $null
        }

        $certificate = $signature.SignerCertificate
        if ($null -eq $certificate) { return $null }

        # GetNameInfo rather than a regex over Subject: the subject is an X.500
        # name whose CN can be quoted and can contain escaped commas, and a regex
        # that got that wrong would produce exactly the partial vendor string this
        # function must never return.
        $name = [string] $certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if ([string]::IsNullOrWhiteSpace($name)) { return $null }

        return $name.Trim()
    }
    catch {
        Write-Verbose "Could not read a signature from '$Path': $($_.Exception.Message)"
        return $null
    }
}

function Get-StartupTargetPublisher {
    # The publisher used for the SERVICE EXCLUSION GATE: signer first, version
    # resource second, $null if neither answers.
    #
    # Called lazily -- see Find-UnwantedStartupItem's ServicePublisherResolver.
    # One signature check on this machine instead of ~90, against a 2.50 s budget.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    $signer = Get-StartupTargetSigner -Path $Path
    if (-not [string]::IsNullOrWhiteSpace($signer)) { return $signer }

    Get-StartupTargetCompany -Path $Path
}

#endregion

#region Internal: StartupApproved

function ConvertFrom-StartupApprovedValue {
    # Decodes one StartupApproved REG_BINARY into Enabled / Disabled / Unknown.
    # See $script:StartupApprovedState for the measurement and for why an
    # unrecognised byte resolves to Unknown rather than to Enabled.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Value
    )

    if ($null -eq $Value) { return $script:StartupStateUnknown }
    $bytes = $Value -as [byte[]]
    if ($null -eq $bytes -or $bytes.Length -lt 1) { return $script:StartupStateUnknown }

    $flag = [int] $bytes[0]
    if (-not $script:StartupApprovedState.ContainsKey($flag)) { return $script:StartupStateUnknown }

    $script:StartupApprovedState[$flag]
}

function Get-StartupApprovalTable {
    # Reads one StartupApproved subkey into a name -> state lookup.
    #
    # The distinction between "the store has no record for this entry" and "the
    # store could not be read" matters, so the returned object says which: a
    # missing key is normal (Windows creates it on first use) and means every
    # entry under it is enabled, while an unreadable key means no entry under it
    # has a knowable state.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    $table = @{}

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Readable = $false; Present = $false; State = $table; Reason = 'No StartupApproved store applies to this location.' }
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Readable = $true; Present = $false; State = $table; Reason = $null }
    }

    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($name in @($key.GetValueNames())) {
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $table[$name.ToLowerInvariant()] = ConvertFrom-StartupApprovedValue -Value $key.GetValue($name)
        }
    }
    catch {
        return [pscustomobject]@{ Readable = $false; Present = $true; State = @{}; Reason = "StartupApproved store '$Path' could not be read: $($_.Exception.Message)" }
    }

    [pscustomobject]@{ Readable = $true; Present = $true; State = $table; Reason = $null }
}

function Resolve-StartupApprovalState {
    # Looks one entry up in an approval table built by Get-StartupApprovalTable and
    # returns the state plus a plain-words account of how it was decided. The
    # account reaches the inventory record, so a human can tell "Windows says this
    # is on" from "there is no record, which means on".
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Table,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Name
    )

    if ($null -eq $Table) {
        return [pscustomobject]@{ State = $script:StartupStateUnknown; Detail = 'No StartupApproved store was read for this location.' }
    }

    if (-not $Table.Readable) {
        return [pscustomobject]@{ State = $script:StartupStateUnknown; Detail = $Table.Reason }
    }

    if (-not [string]::IsNullOrWhiteSpace($Name)) {
        $key = $Name.ToLowerInvariant()
        if ($Table.State.ContainsKey($key)) {
            $state = $Table.State[$key]
            $detail = if ($state -eq $script:StartupStateUnknown) {
                'Windows records a startup-approval value for this entry that this version cannot decode, so its enabled state is unknown and it is inventory only.'
            }
            else {
                "Windows records this entry as $($state.ToLowerInvariant()) in the StartupApproved store."
            }
            return [pscustomobject]@{ State = $state; Detail = $detail }
        }
    }

    [pscustomobject]@{
        State  = $script:StartupStateEnabled
        Detail = 'No StartupApproved record exists for this entry, which is how Windows represents an entry that has never been turned off.'
    }
}

#endregion

#region Internal: the four mechanism readers (all read-only)

function Get-StartupRunKeyItem {
    <#
        Mechanism 1: Run and RunOnce, every hive and every registry view.

        A view that is not present on this machine is not an error -- HKCU has no
        WOW6432Node on most installs. A view that is present and cannot be READ is
        an error, and is reported through the thrown exception rather than by
        returning fewer items.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [ValidateNotNullOrEmpty()] [psobject[]] $View = $script:StartupRunKeyView
    )

    $approvals = @{}

    foreach ($entry in $View) {
        $path = [string](Get-OptimizerProperty -InputObject $entry -Name 'Path')
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Verbose "Run key view not present, skipping: $path"
            continue
        }

        $approvalPath = [string](Get-OptimizerProperty -InputObject $entry -Name 'ApprovalPath')
        if (-not $approvals.ContainsKey([string] $approvalPath)) {
            $approvals[[string] $approvalPath] = Get-StartupApprovalTable -Path $approvalPath
        }
        $approvalTable = $approvals[[string] $approvalPath]

        $isRunOnce = [bool](Get-OptimizerProperty -InputObject $entry -Name 'IsRunOnce' -Default $false)
        # Deliberately not named $scope / $view: PowerShell variable names are
        # case-insensitive, so $view would rebind the [psobject[]] $View parameter
        # this loop is iterating.
        $scopeName = [string](Get-OptimizerProperty -InputObject $entry -Name 'Scope')
        $viewName  = [string](Get-OptimizerProperty -InputObject $entry -Name 'View')

        $key = Get-Item -LiteralPath $path -ErrorAction Stop

        foreach ($name in @($key.GetValueNames())) {
            if ([string]::IsNullOrWhiteSpace($name)) { continue }

            $command = [string] $key.GetValue($name)
            $target  = Get-StartupTargetPath -Command $command

            if ($isRunOnce) {
                # RunOnce is not represented in the StartupApproved store at all --
                # Task Manager does not list it, because it deletes itself after it
                # runs. Saying so beats leaving the state blank.
                $state  = $script:StartupStateEnabled
                $detail = 'RunOnce entries are not managed by the StartupApproved store: Windows deletes the value once it has run, so there is nothing for the user to have turned off.'
            }
            else {
                $resolved = Resolve-StartupApprovalState -Table $approvalTable -Name $name
                $state    = $resolved.State
                $detail   = $resolved.Detail
            }

            New-StartupItem -Mechanism $script:StartupMechanismRunKey `
                -Id "$path::$name" `
                -Name $name `
                -DisplayName $name `
                -Command $command `
                -TargetPath $target `
                -TargetExists (Test-StartupTargetPresent -Path $target) `
                -Publisher (Get-StartupTargetCompany -Path $target) `
                -Scope $scopeName `
                -View $viewName `
                -Location $path `
                -EnabledState $state `
                -EnabledStateDetail $detail `
                -Trigger $(if ($isRunOnce) { 'Next logon, once' } else { 'Every logon' }) `
                -Detail $(if ($isRunOnce) { 'RunOnce' } else { 'Run' })
        }
    }
}

function Get-StartupFolderItem {
    <#
        Mechanism 2: the per-user and all-users Startup folders.

        Enumerated with [System.IO.Directory]::GetFiles, never Get-ChildItem:
        REVIEW.md records Get-ChildItem returning zero items and raising no error
        on a folder the user cannot list, even with -ErrorAction Stop, and a
        silently empty Startup folder is indistinguishable from a clean one.

        A .lnk is resolved through the shell so the orphan rule can see the real
        target. A .url has no file target and is recorded with TargetExists $null;
        anything else in the folder is its own target and, having just been listed,
        is present by construction.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path,
        [Parameter(Mandatory)] [ValidateSet('User', 'Machine')] [string] $Scope
    )

    if (-not [System.IO.Directory]::Exists($Path)) {
        Write-Verbose "Startup folder not present, skipping: $Path"
        return
    }

    $approvalTable = Get-StartupApprovalTable -Path $script:StartupFolderApprovalPath[$Scope]

    $shell = $null
    $files = @([System.IO.Directory]::GetFiles($Path))

    try {
        foreach ($file in $files) {
            $fileName = [System.IO.Path]::GetFileName($file)

            # Windows drops a desktop.ini into both Startup folders to localise the
            # folder name. It is not a startup entry.
            if ([string]::Equals($fileName, 'desktop.ini', [System.StringComparison]::OrdinalIgnoreCase)) { continue }

            $extension = [System.IO.Path]::GetExtension($fileName)
            $target    = $null
            $command   = $file
            $exists    = [Nullable[bool]] $true
            $detail    = $null

            if ([string]::Equals($extension, '.lnk', [System.StringComparison]::OrdinalIgnoreCase)) {
                if ($null -eq $shell) { $shell = New-Object -ComObject WScript.Shell }
                try {
                    $shortcut = $shell.CreateShortcut($file)
                    $target   = [string] $shortcut.TargetPath
                    $arguments = [string] $shortcut.Arguments
                    $command  = if ([string]::IsNullOrWhiteSpace($arguments)) { $target } else { "$target $arguments" }
                    $exists   = Test-StartupTargetPresent -Path $target
                }
                catch {
                    # A shortcut that will not resolve is not evidence that its
                    # target is missing -- it is evidence we do not know.
                    $detail = "The shortcut could not be resolved: $($_.Exception.Message)"
                    $target = $null
                    $exists = $null
                }
            }
            elseif ([string]::Equals($extension, '.url', [System.StringComparison]::OrdinalIgnoreCase)) {
                $detail = 'Internet shortcut: it opens a URL rather than a file, so there is no target on disk to check.'
                $exists = $null
            }
            else {
                $target = $file
            }

            $resolved = Resolve-StartupApprovalState -Table $approvalTable -Name $fileName

            New-StartupItem -Mechanism $script:StartupMechanismFolder `
                -Id $file `
                -Name $fileName `
                -DisplayName ([System.IO.Path]::GetFileNameWithoutExtension($fileName)) `
                -Command $command `
                -TargetPath $target `
                -TargetExists $exists `
                -Publisher (Get-StartupTargetCompany -Path $target) `
                -Scope $Scope `
                -Location $Path `
                -EnabledState $resolved.State `
                -EnabledStateDetail $resolved.Detail `
                -Trigger 'Every logon' `
                -Detail $detail
        }
    }
    finally {
        if ($null -ne $shell) {
            try { $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) } catch { }
        }
    }
}

function Get-StartupScheduledTaskItem {
    <#
        Mechanism 3: scheduled tasks with a logon or boot trigger.

        Read through the Schedule.Service COM API rather than Get-ScheduledTask.
        Measured on the development machine: 0.27s against 1.90s, and -- the
        reason that actually matters -- the CIM route hands back 101 of this
        machine's triggers as the base MSFT_TaskTrigger class, from which the
        trigger TYPE cannot be read. The task XML says <LogonTrigger> or
        <BootTrigger> unambiguously.

        Scope: a daily or event-driven maintenance task is not a startup item, so
        only logon and boot triggers count. Tasks under \Microsoft\Windows\ ARE
        inventoried -- they are most of the list and P4-C1 should be able to show
        them -- but they are marked IsProtectedNamespace and the matcher refuses to
        flag them regardless of what any list says.

        Counts what it could not read, in $Statistic, rather than returning less
        and saying nothing.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [hashtable] $Statistic
    )

    if ($null -ne $Statistic) {
        foreach ($counter in 'TaskTotal', 'TaskUnreadable', 'TaskFolderUnreadable', 'TaskLogonOrBoot', 'TaskProtected') {
            if (-not $Statistic.ContainsKey($counter)) { $Statistic[$counter] = 0 }
        }
    }

    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()

    try {
        $pending = New-Object System.Collections.Stack
        $pending.Push($service.GetFolder('\'))

        while ($pending.Count -gt 0) {
            $folder = $pending.Pop()

            try {
                foreach ($child in $folder.GetFolders(0)) { $pending.Push($child) }
            }
            catch {
                if ($null -ne $Statistic) { $Statistic['TaskFolderUnreadable']++ }
                Write-Verbose "Task folder listing failed: $($_.Exception.Message)"
            }

            $tasks = $null
            try {
                # 1 = TASK_ENUM_HIDDEN. Hidden tasks are still startup items.
                $tasks = $folder.GetTasks(1)
            }
            catch {
                if ($null -ne $Statistic) { $Statistic['TaskFolderUnreadable']++ }
                Write-Verbose "Task listing failed: $($_.Exception.Message)"
                continue
            }

            foreach ($task in $tasks) {
                if ($null -ne $Statistic) { $Statistic['TaskTotal']++ }

                $taskPath = $null
                $taskName = $null
                $enabled  = $null
                $document = $null

                try {
                    $taskPath = [string] $task.Path
                    $taskName = [string] $task.Name
                    $enabled  = [bool] $task.Enabled
                    $document = [xml] $task.Xml
                }
                catch {
                    if ($null -ne $Statistic) { $Statistic['TaskUnreadable']++ }
                    Write-Verbose "Task could not be read: $($_.Exception.Message)"
                    continue
                }

                $triggers = @(Get-StartupTaskTrigger -Document $document)
                $startupTriggers = @($triggers | Where-Object { $_.Name -eq 'LogonTrigger' -or $_.Name -eq 'BootTrigger' })
                if ($startupTriggers.Count -lt 1) { continue }
                if ($null -ne $Statistic) { $Statistic['TaskLogonOrBoot']++ }

                # A task with only switched-off startup triggers does not run at
                # startup, whatever the task's own Enabled flag says.
                $hasEnabledStartupTrigger = @($startupTriggers | Where-Object { $_.Enabled }).Count -gt 0

                $isProtected = $taskPath.StartsWith($script:StartupProtectedTaskNamespace, [System.StringComparison]::OrdinalIgnoreCase)
                if ($isProtected -and $null -ne $Statistic) { $Statistic['TaskProtected']++ }

                $action  = Get-StartupTaskExecAction -Document $document
                $command = $null
                $target  = $null
                $detail  = $null

                if ($null -eq $action) {
                    $detail = 'The task runs a non-executable action (a COM handler, a message or an e-mail), so there is no target on disk to check.'
                }
                else {
                    $command = $action.Command
                    if (-not [string]::IsNullOrWhiteSpace($action.Arguments)) { $command = "$($action.Command) $($action.Arguments)" }
                    $target = Get-StartupTargetPath -Command $action.Command
                }

                $state = if ($enabled -and $hasEnabledStartupTrigger) { $script:StartupStateEnabled } else { $script:StartupStateDisabled }
                $stateDetail = if (-not $enabled) {
                    'The task is disabled in Task Scheduler, so it does not run at logon or boot.'
                }
                elseif (-not $hasEnabledStartupTrigger) {
                    'The task is enabled, but every one of its logon/boot triggers is switched off, so it does not start with Windows.'
                }
                else {
                    'The task is enabled in Task Scheduler and its logon/boot trigger is active.'
                }

                New-StartupItem -Mechanism $script:StartupMechanismTask `
                    -Id $taskPath `
                    -Name $taskName `
                    -DisplayName $taskName `
                    -Command $command `
                    -TargetPath $target `
                    -TargetExists (Test-StartupTargetPresent -Path $target) `
                    -Publisher (Get-StartupTargetCompany -Path $target) `
                    -Scope 'Machine' `
                    -Location $taskPath `
                    -EnabledState $state `
                    -EnabledStateDetail $stateDetail `
                    -Trigger ((@($startupTriggers | ForEach-Object { $_.Name }) | Select-Object -Unique) -join ', ') `
                    -IsProtectedNamespace $isProtected `
                    -Detail $detail
            }
        }
    }
    finally {
        try { $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($service) } catch { }
    }
}

function Get-StartupTaskTrigger {
    # A task's triggers, as {Name, Enabled} records. Walked through the DOM rather
    # than read as properties or matched with a regex: the task XML carries a
    # default namespace, and PowerShell's XML adapter throws under Set-StrictMode
    # -Version Latest for a <Triggers> element that is simply not there -- which is
    # the normal shape of an on-demand task, of which this machine has 53.
    #
    # A DISABLED trigger is returned, not dropped. A task with a switched-off logon
    # trigger is still a startup entry the user has already dealt with, and it
    # belongs in the inventory saying so -- dropping it would make the inventory
    # disagree with what the user sees in Task Scheduler. Six tasks on this machine
    # are in exactly that state.
    [CmdletBinding()]
    [OutputType([psobject[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Document
    )

    $triggers = New-Object System.Collections.Generic.List[psobject]
    if ($null -eq $Document -or $null -eq $Document.DocumentElement) { return }

    foreach ($node in $Document.DocumentElement.ChildNodes) {
        if ($node.LocalName -ne 'Triggers') { continue }
        foreach ($trigger in $node.ChildNodes) {
            # A trigger can be individually disabled inside an enabled task.
            $enabled = $true
            foreach ($field in $trigger.ChildNodes) {
                if ($field.LocalName -eq 'Enabled' -and $field.InnerText -eq 'false') { $enabled = $false }
            }
            $triggers.Add([pscustomobject]@{ Name = [string] $trigger.LocalName; Enabled = $enabled })
        }
    }

    # NOT ", $triggers.ToArray()": the comma operator preserves the array as ONE
    # output item, so an empty result would reach the caller's @(...) as an array
    # containing an empty array, and $_.Name on that throws under strict mode.
    # Emitting the elements lets the caller's @(...) normalise both cases.
    $triggers.ToArray()
}

function Get-StartupTaskExecAction {
    # The first <Exec> action's command and arguments, or $null when the task's
    # actions are all non-executable. Same DOM walk, same reasons.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Document
    )

    if ($null -eq $Document -or $null -eq $Document.DocumentElement) { return $null }

    foreach ($node in $Document.DocumentElement.ChildNodes) {
        if ($node.LocalName -ne 'Actions') { continue }
        foreach ($action in $node.ChildNodes) {
            if ($action.LocalName -ne 'Exec') { continue }
            $command   = $null
            $arguments = $null
            foreach ($field in $action.ChildNodes) {
                if ($field.LocalName -eq 'Command')   { $command   = [string] $field.InnerText }
                if ($field.LocalName -eq 'Arguments') { $arguments = [string] $field.InnerText }
            }
            if ([string]::IsNullOrWhiteSpace($command)) { continue }
            return [pscustomobject]@{ Command = $command; Arguments = $arguments }
        }
    }

    $null
}

function Get-StartupServiceItem {
    <#
        Mechanism 4: services with an automatic start mode.

        Read from HKLM\SYSTEM\CurrentControlSet\Services rather than through
        Get-Service, for three reasons measured on the development machine:
          * it exposes Type, so DRIVERS can be excluded structurally -- 24 of the
            114 automatic-start keys here are kernel or filesystem drivers, and
            Get-Service does not show them at all;
          * it exposes ImagePath, which is what the orphan rule needs;
          * Get-Service's StartType does not report AutomaticDelayedStart the same
            way under Windows PowerShell 5.1 and PowerShell 7, and this project
            ships on 5.1.

        Scope: Start = 2 (SERVICE_AUTO_START) only. A manual-start service is not a
        startup item. Delayed autostart is still Start = 2 and is recorded, not
        excluded -- it still runs on its own at every boot.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [ValidateNotNullOrEmpty()] [string] $Path = $script:StartupServiceRoot,
        [Parameter()] [AllowNull()] [hashtable] $Statistic
    )

    if ($null -ne $Statistic) {
        foreach ($counter in 'ServiceKeyTotal', 'ServiceKeyUnreadable', 'ServiceDriverExcluded') {
            if (-not $Statistic.ContainsKey($counter)) { $Statistic[$counter] = 0 }
        }
    }

    foreach ($key in @(Get-ChildItem -LiteralPath $Path -ErrorAction Stop)) {
        if ($null -ne $Statistic) { $Statistic['ServiceKeyTotal']++ }

        # Get-ItemProperty returns $null for TWO different situations, and treating
        # them as one is how this detector nearly shipped reporting itself PARTIAL
        # on every machine forever: a key that could not be read, and a key that
        # simply holds no values. 49 of the 880 keys here are the second kind --
        # '.NET CLR Data' and friends, which exist only to carry Linkage and
        # Performance subkeys and are not service definitions at all. Only a real
        # exception counts as unreadable.
        $values = $null
        try {
            $values = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
        }
        catch {
            if ($null -ne $Statistic) { $Statistic['ServiceKeyUnreadable']++ }
            Write-Verbose "Service key '$($key.PSChildName)' could not be read: $($_.Exception.Message)"
            continue
        }
        if ($null -eq $values) { continue }

        $start = Get-OptimizerProperty -InputObject $values -Name 'Start'
        if ($null -eq $start) { continue }
        if (([int] $start) -ne $script:StartupServiceAutomaticStart) { continue }

        # Drivers are out of scope structurally, not by list entry: a service key
        # without SERVICE_WIN32_OWN_PROCESS or SERVICE_WIN32_SHARE_PROCESS is a
        # kernel or filesystem driver, and nothing in this project offers to touch
        # one.
        $type = Get-OptimizerProperty -InputObject $values -Name 'Type'
        if ($null -eq $type -or ((([int] $type) -band $script:StartupServiceWin32TypeMask) -eq 0)) {
            if ($null -ne $Statistic) { $Statistic['ServiceDriverExcluded']++ }
            continue
        }

        $imagePath = [string](Get-OptimizerProperty -InputObject $values -Name 'ImagePath')
        $target    = Get-StartupTargetPath -Command $imagePath

        # A DisplayName beginning with '@' is an indirect MUI string
        # (@%SystemRoot%\system32\thing.dll,-258). Resolving it needs
        # SHLoadIndirectString; showing it raw would be worse than showing the
        # service key name, which is at least a real identifier.
        $displayName = [string](Get-OptimizerProperty -InputObject $values -Name 'DisplayName')
        $rawDisplayName = $displayName
        if ([string]::IsNullOrWhiteSpace($displayName) -or $displayName.StartsWith('@')) {
            $displayName = $key.PSChildName
        }

        $delayed = Get-OptimizerProperty -InputObject $values -Name 'DelayedAutostart'
        $isDelayed = ($null -ne $delayed -and ([int] $delayed) -ne 0)

        $detail = "Service type 0x$(([int] $type).ToString('X'))."
        if ($rawDisplayName -ne $displayName -and -not [string]::IsNullOrWhiteSpace($rawDisplayName)) {
            $detail += " DisplayName is an indirect resource string ('$rawDisplayName'); the service key name is shown instead."
        }

        New-StartupItem -Mechanism $script:StartupMechanismService `
            -Id $key.PSChildName `
            -Name $key.PSChildName `
            -DisplayName $displayName `
            -Command $imagePath `
            -TargetPath $target `
            -TargetExists (Test-StartupTargetPresent -Path $target) `
            -Publisher (Get-StartupTargetCompany -Path $target) `
            -Scope 'Machine' `
            -Location "$Path\$($key.PSChildName)" `
            -EnabledState $script:StartupStateEnabled `
            -EnabledStateDetail 'The service start mode is Automatic, so the service control manager starts it at boot.' `
            -Trigger $(if ($isDelayed) { 'Boot (delayed autostart)' } else { 'Boot' }) `
            -Detail $detail
    }
}

#endregion

#region Public: the curated list

function Get-KnownStartupItemList {
    <#
    .SYNOPSIS
        Loads and validates the curated known-unnecessary startup-item list.

    .DESCRIPTION
        Reads Data\known-startup-items.json and returns one normalized entry per
        list entry, with every field guaranteed present.

        Every rule is enforced here and violations throw, the same treatment
        Get-KnownBloatwareList and Get-UnusedAppExclusionList get, and for the same
        reason: a list that silently fails to load yields zero matches, which looks
        exactly like a machine with nothing to flag.

        An entry on this list is a claim about a specific autostart ENTRY, not
        about the application it belongs to. See Data\README.md for what may and
        may not go on it -- in particular, updaters do not go on it.

    .PARAMETER Path
        List file to load. Defaults to Data\known-startup-items.json next to the
        module.

    .EXAMPLE
        Get-KnownStartupItemList | Select-Object Id, DisplayName, Provenance, Reason
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if (-not $Path) {
        $Path = Join-Path -Path $script:OptimizerDataRoot -ChildPath 'known-startup-items.json'
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Known-startup-item list not found at '$Path'. The StartupItems detector will not run without it -- with no list, a scan that flagged only orphans would be indistinguishable from a scan whose list failed to load."
    }

    $raw = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Known-startup-item list '$Path' is empty."
    }

    try {
        $document = ConvertFrom-Json -InputObject $raw
    }
    catch {
        throw "Known-startup-item list '$Path' is not valid JSON: $($_.Exception.Message)"
    }

    # Read the property directly rather than through Get-OptimizerProperty: an empty
    # JSON array would unroll to nothing on the way out of a function and be
    # indistinguishable from a missing 'entries' key.
    $entriesProperty = $document.PSObject.Properties['entries']
    if ($null -eq $entriesProperty -or $null -eq $entriesProperty.Value) {
        throw "Known-startup-item list '$Path' has no 'entries' array."
    }

    $entries = @($entriesProperty.Value)
    if ($entries.Count -lt 1) {
        throw "Known-startup-item list '$Path' contains no entries."
    }

    $seenIds = @{}
    $index = -1

    foreach ($entry in $entries) {
        $index++
        $id = [string](Get-OptimizerProperty -InputObject $entry -Name 'id')
        $where = if ([string]::IsNullOrWhiteSpace($id)) { "entry #$index" } else { "entry '$id'" }

        foreach ($required in 'id', 'displayName', 'vendor', 'reason', 'provenance') {
            $value = [string](Get-OptimizerProperty -InputObject $entry -Name $required)
            if ([string]::IsNullOrWhiteSpace($value)) {
                throw "Known-startup-item list '$Path': $where is missing a non-empty '$required'. Every entry is a claim that something on a user's machine is not worth running; it has to say who it comes from, why, and whether the identifier was ever observed on real hardware."
            }
        }

        if ($seenIds.ContainsKey($id.ToLowerInvariant())) {
            throw "Known-startup-item list '$Path': duplicate entry id '$id'."
        }
        $seenIds[$id.ToLowerInvariant()] = $true

        $provenance = [string](Get-OptimizerProperty -InputObject $entry -Name 'provenance')
        if ($script:StartupProvenanceValues -notcontains $provenance) {
            throw "Known-startup-item list '$Path': $where declares unknown 'provenance' '$provenance'. Allowed: $($script:StartupProvenanceValues -join ', ')."
        }

        # Same rule and same reasoning as the OEM whitelist: the string "true" is
        # truthy in PowerShell and would leave an entry looking enforced while the
        # Finding contract, which fails closed on a non-boolean, disagreed.
        $requiresConsent = $false
        $consentProperty = $entry.PSObject.Properties['requiresConsent']
        if ($null -ne $consentProperty -and $null -ne $consentProperty.Value) {
            if ($consentProperty.Value -isnot [bool]) {
                throw "Known-startup-item list '$Path': $where declares 'requiresConsent' as [$($consentProperty.Value.GetType().Name)] '$($consentProperty.Value)'. It must be a JSON boolean (true / false), not a string."
            }
            $requiresConsent = [bool] $consentProperty.Value
        }

        $match = Get-OptimizerProperty -InputObject $entry -Name 'match'
        if ($null -eq $match) {
            throw "Known-startup-item list '$Path': $where has no 'match' block."
        }

        $rules = @{}
        foreach ($field in $script:StartupMatchFields) { $rules[$field] = @() }

        # Enumerated one property at a time rather than as $match.PSObject.Properties.Name:
        # under Set-StrictMode -Version Latest, member enumeration of .Name over an
        # EMPTY property collection throws "the property 'Name' cannot be found",
        # so an entry declaring "match": {} would fail with a parser-level message
        # instead of the one that says what is actually wrong.
        $declaredFields = @($match.PSObject.Properties | ForEach-Object { $_.Name })

        foreach ($field in $declaredFields) {
            if ($script:StartupMatchFields -notcontains $field) {
                throw "Known-startup-item list '$Path': $where declares unknown match field '$field'. Allowed: $($script:StartupMatchFields -join ', ')."
            }

            $patterns = @(@(Get-OptimizerProperty -InputObject $match -Name $field -Default @()) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ })

            if ($patterns.Count -lt 1) {
                throw "Known-startup-item list '$Path': $where declares match field '$field' with no patterns."
            }

            foreach ($pattern in $patterns) {
                Assert-OptimizerPattern -Pattern $pattern -Context "Known-startup-item list '$Path', $where, field '$field'"

                # An entry may not reach for a task PATH. The \Microsoft\Windows\
                # namespace is barred in code and this keeps a list entry from
                # trying to address a task by path at all.
                if ($field -eq 'scheduledTaskName' -and $pattern.Contains([string][char]92)) {
                    throw "Known-startup-item list '$Path': $where matches scheduled tasks by name, and '$pattern' contains a path separator. Entries name a task, never a path -- which task namespaces are off limits is decided in code, not on this list."
                }

                # No wildcards on executable names. 'Update*' would match the
                # updater of every product on the machine; on this machine alone
                # Update.exe, setup.exe and crashpad_handler.exe each appear in
                # several install folders.
                if ($field -eq 'targetFileName' -and $pattern.Contains('*')) {
                    throw "Known-startup-item list '$Path': $where matches on the target file name with the wildcard pattern '$pattern'. Executable names are exact strings only -- a prefix match on a file name catches every vendor that happens to ship one."
                }
            }

            $rules[$field] = $patterns
        }

        $ruleCount = 0
        foreach ($field in $script:StartupMatchFields) { $ruleCount += $rules[$field].Count }
        if ($ruleCount -lt 1) {
            throw "Known-startup-item list '$Path': $where has an empty 'match' block."
        }

        [pscustomobject]@{
            PSTypeName            = $script:StartupEntryTypeName
            Id                    = $id
            DisplayName           = [string](Get-OptimizerProperty -InputObject $entry -Name 'displayName')
            Vendor                = [string](Get-OptimizerProperty -InputObject $entry -Name 'vendor')
            Reason                = [string](Get-OptimizerProperty -InputObject $entry -Name 'reason')
            Provenance            = $provenance
            RequiresConsent       = [bool] $requiresConsent
            Note                  = [string](Get-OptimizerProperty -InputObject $entry -Name 'note')
            RunValueName          = [string[]] $rules['runValueName']
            StartupFolderFileName = [string[]] $rules['startupFolderFileName']
            ScheduledTaskName     = [string[]] $rules['scheduledTaskName']
            ServiceName           = [string[]] $rules['serviceName']
            ServiceDisplayName    = [string[]] $rules['serviceDisplayName']
            TargetFileName        = [string[]] $rules['targetFileName']
        }
    }
}

#endregion

#region Public: inventory

function Get-StartupItemInventory {
    <#
    .SYNOPSIS
        Enumerates everything on this machine that runs automatically at logon or
        boot, across all four mechanisms.

    .DESCRIPTION
        Returns one object carrying Items (the normalised startup records) and
        Sources (one status record per mechanism). Read-only.

        The two halves are returned together on purpose. There are four
        independent mechanisms and they do not overlap, so a caller that received
        a bare list of items could not tell "the Startup folder is empty" from
        "the Startup folder was never read". Every mechanism reports its own
        status, item count and reason.

        Nothing here needs elevation. Measured on the development machine
        un-elevated: all four mechanisms read completely.

    .PARAMETER RunKeyView
        Run/RunOnce views to read. Defaults to all eight -- both hives, both
        registry views, Run and RunOnce. A view that does not exist on this
        machine is skipped silently; a view that exists and cannot be read makes
        the source Failed.

    .PARAMETER StartupFolderPath
        Startup folders to read, as objects with Path and Scope. Defaults to the
        per-user and all-users Startup folders resolved from the shell known
        folders, never from hard-coded AppData / ProgramData paths.

    .PARAMETER SkipScheduledTask
        Do not read scheduled tasks. The source is reported Skipped with a reason,
        never omitted.

    .PARAMETER SkipService
        Do not read services. The source is reported Skipped with a reason.

    .EXAMPLE
        $inventory = Get-StartupItemInventory
        $inventory.Items | Group-Object Mechanism | Select-Object Name, Count
        $inventory.Sources | Format-Table Name, Status, ItemCount

    .OUTPUTS
        Win11Optimizer.StartupInventory
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [psobject[]] $RunKeyView = $script:StartupRunKeyView,

        [Parameter()]
        [ValidateNotNull()]
        [psobject[]] $StartupFolderPath,

        [Parameter()]
        [switch] $SkipScheduledTask,

        [Parameter()]
        [switch] $SkipService
    )

    if (-not $PSBoundParameters.ContainsKey('StartupFolderPath')) {
        $StartupFolderPath = @(
            [pscustomobject]@{ Path = [Environment]::GetFolderPath('Startup');       Scope = 'User' }
            [pscustomobject]@{ Path = [Environment]::GetFolderPath('CommonStartup'); Scope = 'Machine' }
        )
    }

    $items     = New-Object System.Collections.Generic.List[psobject]
    $sources   = New-Object System.Collections.Generic.List[psobject]
    $statistic = @{}

    # --- Mechanism 1: Run and RunOnce keys ------------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $read = @(Get-StartupRunKeyItem -View $RunKeyView)
        $timer.Stop()
        foreach ($item in $read) { $items.Add($item) }
        $sources.Add((New-StartupScanSource -Name $script:StartupSourceRunKeys -Status 'Succeeded' `
            -ItemCount $read.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    catch {
        $timer.Stop()
        $sources.Add((New-StartupScanSource -Name $script:StartupSourceRunKeys -Status 'Failed' `
            -Reason "Reading the Run and RunOnce registry keys failed: $($_.Exception.Message) Startup entries registered there are not in this list." `
            -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }

    # --- Mechanism 2: Startup folders ------------------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $folderCount = 0
    $folderProblem = New-Object System.Collections.Generic.List[string]
    foreach ($folder in @($StartupFolderPath)) {
        $path  = [string](Get-OptimizerProperty -InputObject $folder -Name 'Path')
        $scope = [string](Get-OptimizerProperty -InputObject $folder -Name 'Scope' -Default 'User')
        if ([string]::IsNullOrWhiteSpace($path)) {
            $folderProblem.Add('A Startup known folder did not resolve to a path on this machine.')
            continue
        }
        try {
            $read = @(Get-StartupFolderItem -Path $path -Scope $scope)
            foreach ($item in $read) { $items.Add($item) }
            $folderCount += $read.Count
        }
        catch {
            $folderProblem.Add("'$path' could not be listed: $($_.Exception.Message)")
        }
    }
    $timer.Stop()
    if ($folderProblem.Count -gt 0) {
        $sources.Add((New-StartupScanSource -Name $script:StartupSourceFolders -Status 'Failed' `
            -Reason "One or more Startup folders could not be read, so anything in them is missing from this list: $($folderProblem -join ' ')" `
            -ItemCount $folderCount -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    else {
        $sources.Add((New-StartupScanSource -Name $script:StartupSourceFolders -Status 'Succeeded' `
            -ItemCount $folderCount -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }

    # --- Mechanism 3: scheduled tasks -------------------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    if ($SkipScheduledTask) {
        $timer.Stop()
        $sources.Add((New-StartupScanSource -Name $script:StartupSourceTasks -Status 'Skipped' `
            -Reason 'Scheduled tasks were not read because the caller asked for them to be skipped. Tasks with a logon or boot trigger are startup items and are missing from this list.' `
            -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    else {
        try {
            $read = @(Get-StartupScheduledTaskItem -Statistic $statistic)
            $timer.Stop()
            foreach ($item in $read) { $items.Add($item) }

            # Some tasks can be invisible or unreadable at this privilege level. A
            # source that read most of the truth is not a source that read all of
            # it, so it is reported Skipped with the count rather than Succeeded
            # with a footnote -- which is what makes the scan report itself
            # incomplete.
            $unreadable = [int] $statistic['TaskUnreadable'] + [int] $statistic['TaskFolderUnreadable']
            if ($unreadable -gt 0) {
                $sources.Add((New-StartupScanSource -Name $script:StartupSourceTasks -Status 'Skipped' `
                    -Reason "$unreadable of $($statistic['TaskTotal']) scheduled tasks could not be read at this privilege level, so any startup task among them is missing from this list. Re-run this scan as administrator to see them." `
                    -ItemCount $read.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
            }
            else {
                $sources.Add((New-StartupScanSource -Name $script:StartupSourceTasks -Status 'Succeeded' `
                    -ItemCount $read.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
            }
        }
        catch {
            $timer.Stop()
            $sources.Add((New-StartupScanSource -Name $script:StartupSourceTasks -Status 'Failed' `
                -Reason "Reading the Task Scheduler failed: $($_.Exception.Message) Tasks with a logon or boot trigger are startup items and are missing from this list." `
                -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
        }
    }

    # --- Mechanism 4: services ---------------------------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    if ($SkipService) {
        $timer.Stop()
        $sources.Add((New-StartupScanSource -Name $script:StartupSourceServices -Status 'Skipped' `
            -Reason 'Services were not read because the caller asked for them to be skipped. Services with an automatic start mode run at every boot and are missing from this list.' `
            -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    else {
        try {
            $read = @(Get-StartupServiceItem -Statistic $statistic)
            $timer.Stop()
            foreach ($item in $read) { $items.Add($item) }

            $unreadable = [int] $statistic['ServiceKeyUnreadable']
            if ($unreadable -gt 0) {
                $sources.Add((New-StartupScanSource -Name $script:StartupSourceServices -Status 'Skipped' `
                    -Reason "$unreadable of $($statistic['ServiceKeyTotal']) service registry keys could not be read at this privilege level, so any automatic-start service among them is missing from this list. Re-run this scan as administrator to see them." `
                    -ItemCount $read.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
            }
            else {
                $sources.Add((New-StartupScanSource -Name $script:StartupSourceServices -Status 'Succeeded' `
                    -ItemCount $read.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
            }
        }
        catch {
            $timer.Stop()
            $sources.Add((New-StartupScanSource -Name $script:StartupSourceServices -Status 'Failed' `
                -Reason "Reading the service registry keys failed: $($_.Exception.Message) Services with an automatic start mode run at every boot and are missing from this list." `
                -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
        }
    }

    [pscustomobject]@{
        PSTypeName = $script:StartupInventoryTypeName
        Items      = [psobject[]] $items.ToArray()
        Sources    = [psobject[]] $sources.ToArray()
        Statistic  = $statistic
    }
}

#endregion

#region Public: the matcher

function Find-UnwantedStartupItem {
    <#
    .SYNOPSIS
        Turns a startup inventory into Findings, using the curated list and the
        orphan rule and nothing else.

    .DESCRIPTION
        The pure half of the detector: no machine access, no elevation, no I/O. It
        is separate from Invoke-StartupItemScan so the flag/do-not-flag rules can
        be tested against fabricated input rather than against whatever this
        machine happens to autostart.

        Every returned object comes from New-Finding. There are exactly two ways
        an entry becomes a Finding:

          CuratedList  it matched an entry on the shipped, reviewed list.
          Orphan       its target executable or script is PROVED absent from disk.
                       Not "could not be found" -- see Test-StartupTargetPresent,
                       which returns $null rather than $false whenever absence
                       cannot be distinguished from a permission problem.

        Both are Confidence 'Known': the first is a curated claim, the second is a
        filesystem fact. There is no heuristic tier, and no publisher tier.

        Four things are never flagged, whatever any list says:

          1. Anything the user has already turned off (EnabledState 'Disabled').
             It is already handled, and flagging it is the padding that makes a
             tool in this category look like it is inventing work.
          2. Anything whose enabled state could not be decoded ('Unknown'). An
             entry that might already be disabled is inventory.
          3. Any scheduled task under \Microsoft\Windows\. Those are OS
             components. Enforced here, in code.
          4. Any service matching a driver, security or firmware-update entry on
             P2-C3's exclusion list. One vendor list, not two.

             With ONE exception, added by P2-C2a: a PROVED ORPHAN beats 'driver'
             and 'driver-utility' exclusion, because a device utility whose binary
             is absent is managing no hardware. It never beats a class on
             OrphanProofServiceClass ('security'), where the orphan proof itself is
             the unreliable part -- anti-tamper minifilters hide binaries from
             enumeration, and the cost of getting it wrong is offering to disable
             live antivirus.

        Every Service Finding sets RequiresConsent, without exception, so its
        SafetyLabel comes out "Review needed" even at Confidence 'Known'. That is
        the v1 decision in docs\STATE.md: services are flag-for-review only,
        because the blast radius is higher than a Run key. The label is derived by
        the contract; nothing here re-derives it.

    .PARAMETER StartupItem
        Inventory records, as returned by Get-StartupItemInventory.

    .PARAMETER KnownStartupItemEntry
        Curated entries, as returned by Get-KnownStartupItemList.

    .PARAMETER ExclusionEntry
        P2-C3's curated exclusion entries, as returned by
        Get-UnusedAppExclusionList. Used for services only.

    .PARAMETER ProtectedServiceClass
        Exclusion-list classes that make a service unflaggable. Defaults to
        driver, driver-utility and security.

    .PARAMETER OrphanProofServiceClass
        The subset of ProtectedServiceClass whose protection survives a proved
        orphan. Defaults to 'security', and see $script:StartupOrphanProofServiceClass
        for why that one is different from the other two.

    .PARAMETER ProtectedTaskNamespace
        Task path prefix that is never flagged. Defaults to '\Microsoft\Windows\'.

    .PARAMETER ServicePublisherResolver
        Optional scriptblock taking a target path and returning a publisher string
        or $null, used only as a SECOND attempt at the service exclusion gate --
        never as a replacement for the Publisher already on the record. Defaults to
        $null, meaning the record's own Publisher stands alone and this function
        performs no I/O whatsoever. Invoke-StartupItemScan supplies
        Get-StartupTargetPublisher; the tests supply a fake and assert how often it
        is called.

    .EXAMPLE
        Find-UnwantedStartupItem -StartupItem $inventory.Items `
            -KnownStartupItemEntry (Get-KnownStartupItemList) `
            -ExclusionEntry (Get-UnusedAppExclusionList)
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [psobject[]] $StartupItem,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [psobject[]] $KnownStartupItemEntry,

        [Parameter()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [psobject[]] $ExclusionEntry = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $ProtectedServiceClass = $script:StartupProtectedServiceClass,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $OrphanProofServiceClass = $script:StartupOrphanProofServiceClass,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ProtectedTaskNamespace = $script:StartupProtectedTaskNamespace,

        [Parameter()]
        [AllowNull()]
        [scriptblock] $ServicePublisherResolver = $null
    )

    foreach ($item in @($StartupItem)) {
        if ($null -eq $item) { continue }

        $mechanism = [string](Get-OptimizerProperty -InputObject $item -Name 'Mechanism')
        if (-not $script:StartupFindingCategory.ContainsKey($mechanism)) {
            Write-Verbose "Ignoring startup record with unrecognized Mechanism '$mechanism'."
            continue
        }

        # Rule 1/2: only an entry Windows says is ON can be a Finding.
        $state = [string](Get-OptimizerProperty -InputObject $item -Name 'EnabledState')
        if ($state -ne $script:StartupStateEnabled) { continue }

        $isService = ($mechanism -eq $script:StartupMechanismService)

        # Rule 3: the OS task namespace, in code.
        if ($mechanism -eq $script:StartupMechanismTask) {
            $taskPath = [string](Get-OptimizerProperty -InputObject $item -Name 'Id')
            if (-not [string]::IsNullOrWhiteSpace($taskPath) -and
                $taskPath.StartsWith($ProtectedTaskNamespace, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
        }

        $displayName = [string](Get-OptimizerProperty -InputObject $item -Name 'DisplayName')
        $name        = [string](Get-OptimizerProperty -InputObject $item -Name 'Name')
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $name }

        $identifier = [string](Get-OptimizerProperty -InputObject $item -Name 'Id')
        if ([string]::IsNullOrWhiteSpace($identifier)) { $identifier = $displayName }

        # TargetExists is read ONCE, here, and the same value drives both rule 4's
        # orphan exemption and the orphan Finding below. Re-reading it in two
        # places is how the two would eventually disagree.
        $targetExists = Get-OptimizerProperty -InputObject $item -Name 'TargetExists'
        $isOrphan     = ($targetExists -is [bool] -and -not $targetExists)

        $entry = Get-StartupCuratedMatch -StartupItem $item -KnownStartupItemEntry $KnownStartupItemEntry

        # Nothing below this line can produce a Finding, so everything below is
        # only reached for a curated match or a proved orphan. That is what makes
        # the publisher resolution in rule 4 lazy.
        if ($null -eq $entry -and -not $isOrphan) { continue }

        # Rule 4: driver / security / firmware-update services, from P2-C3's list.
        #
        # A PROVED ORPHAN beats 'driver' and 'driver-utility' exclusion -- a device
        # utility whose binary is gone is managing no hardware -- but never beats
        # a class on $OrphanProofServiceClass. See that list for why 'security' is
        # on it. Both halves were argued; neither is a simplification of the other.
        $exemptedClass   = $null
        $exemptedEntryId = $null
        if ($isService) {
            $exclusion = Get-OptimizerExclusionMatch -InstalledApp (ConvertTo-StartupExclusionCandidate -StartupItem $item) -ExclusionEntry $ExclusionEntry

            # SECOND CHANCE, not a replacement. The resolved signer is only ever
            # tried where the record's own publisher (and its display name) already
            # failed to exclude the service, so resolution can only ever ADD an
            # exclusion, never take one away.
            #
            # That direction matters more than it looks. Measured on the
            # development machine, the signer and the version resource routinely
            # disagree about the same vendor -- 'Razer USA Ltd.' vs 'Razer Inc.',
            # 'MICRO-STAR INTERNATIONAL CO., LTD.' vs "Micro-Star Int'l Co., Ltd."
            # -- and NvContainerLocalSystem is signed by 'Microsoft Windows
            # Hardware Compatibility Publisher', the WHQL attestation signer,
            # rather than by NVIDIA at all. A resolver that overwrote the
            # publisher would silently break a registryPublisher rule written
            # from a CompanyName, and a lost exclusion is a SPURIOUS FINDING --
            # the one direction this list is not allowed to fail in.
            #
            # The resolver is INJECTED so this function keeps its no-I/O contract;
            # with none supplied the record's own Publisher stands alone, which is
            # what every fabricated-input test relies on.
            if ($null -eq $exclusion -and $null -ne $ServicePublisherResolver) {
                $targetPath = [string](Get-OptimizerProperty -InputObject $item -Name 'TargetPath')
                $resolved   = [string](& $ServicePublisherResolver $targetPath)
                # $null from the resolver means "no publisher", exactly as a blank
                # CompanyName does. It never means "not that vendor".
                if (-not [string]::IsNullOrWhiteSpace($resolved)) {
                    $exclusion = Get-OptimizerExclusionMatch -InstalledApp (ConvertTo-StartupExclusionCandidate -StartupItem $item -Publisher $resolved) -ExclusionEntry $ExclusionEntry
                }
            }

            if ($null -ne $exclusion) {
                $class = [string](Get-OptimizerProperty -InputObject $exclusion -Name 'Class')
                if ($ProtectedServiceClass -contains $class) {
                    if (-not $isOrphan -or $OrphanProofServiceClass -contains $class) { continue }
                    $exemptedClass   = $class
                    $exemptedEntryId = [string](Get-OptimizerProperty -InputObject $exclusion -Name 'Id')
                }
            }
        }

        $evidence = New-Object System.Collections.Generic.List[string]
        $evidence.Add((Get-StartupItemEvidenceLine -StartupItem $item))

        $command = [string](Get-OptimizerProperty -InputObject $item -Name 'Command')
        if (-not [string]::IsNullOrWhiteSpace($command)) {
            $evidence.Add("Command: $command")
        }

        $findingReason   = $script:StartupReasonOrphan
        $entryId         = $null
        $requiresConsent = $isService

        if ($null -ne $entry) {
            $findingReason = $script:StartupReasonCurated
            $entryId       = [string](Get-OptimizerProperty -InputObject $entry -Name 'Id')
            $entryName     = [string](Get-OptimizerProperty -InputObject $entry -Name 'DisplayName')
            $entryVendor   = [string](Get-OptimizerProperty -InputObject $entry -Name 'Vendor')

            $evidence.Add("Matches curated known-startup-item entry '$entryId' ($entryName, $entryVendor).")
            $evidence.Add([string](Get-OptimizerProperty -InputObject $entry -Name 'Reason'))

            if ([string](Get-OptimizerProperty -InputObject $entry -Name 'Provenance') -eq $script:StartupPublishedProvenance) {
                $evidence.Add($script:StartupPublishedEvidence)
            }

            if ([bool](Get-OptimizerProperty -InputObject $entry -Name 'RequiresConsent' -Default $false)) {
                $requiresConsent = $true
            }

            if (-not [string]::IsNullOrWhiteSpace($entryName)) { $displayName = $entryName }
        }

        if ($isOrphan) {
            $target = [string](Get-OptimizerProperty -InputObject $item -Name 'TargetPath')
            $evidence.Add("The file this entry points at is not on disk: '$target'. The folder that should contain it was listed successfully, so the file is genuinely absent rather than hidden by a permission this scan does not have. Windows tries to start it every time and fails.")
            if ($null -ne $entry) {
                $evidence.Add('This entry is both a curated-list match and a broken pointer.')
            }
        }

        if ($null -ne $exemptedClass) {
            # A user looking at a flagged driver service deserves to be told that
            # the usual protection existed and why it was set aside.
            $evidence.Add("This service matches the '$exemptedClass' protection class on the shared exclusion list (entry '$exemptedEntryId'), which normally keeps a service off this list entirely. That protection was set aside here because the file it points at is proved absent: a driver or device utility whose binary is gone is not managing any hardware. Security software is never treated this way, whatever its target looks like.")
        }

        if ($isService) {
            $evidence.Add('Services are flag-for-review only in this version: this is surfaced for a human to decide on, never as safe to act on unattended.')
        }

        $finding = New-Finding -Category $script:StartupFindingCategory[$mechanism] `
            -Id $identifier `
            -DisplayName $displayName `
            -Evidence ([string[]] $evidence.ToArray()) `
            -Confidence 'Known' `
            -RequiresConsent:$requiresConsent `
            -RemovalMethod $script:StartupRemovalMethod[$mechanism]

        # Detector-specific fields, attached after New-Finding the way
        # OemBloatware.ps1 attaches WhitelistEntryId: which mechanism this came
        # from, why it was flagged, and the join key back into the curated list.
        # The generic contract has no use for any of the three.
        $finding | Add-Member -MemberType NoteProperty -Name 'Mechanism' -Value $mechanism
        $finding | Add-Member -MemberType NoteProperty -Name 'FindingReason' -Value $findingReason
        $finding | Add-Member -MemberType NoteProperty -Name 'StartupEntryId' -Value $entryId

        $finding
    }
}

function Get-StartupCuratedMatch {
    # First curated entry a startup record matches, or $null. Which match fields
    # apply depends on the mechanism, so a serviceName rule can never be tested
    # against a Run value name.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $StartupItem,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $KnownStartupItemEntry
    )

    if ($null -eq $StartupItem -or $null -eq $KnownStartupItemEntry) { return $null }

    $mechanism   = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'Mechanism')
    $name        = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'Name')
    $displayName = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'DisplayName')
    $target      = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'TargetPath')

    $targetFileName = $null
    if (-not [string]::IsNullOrWhiteSpace($target)) {
        try { $targetFileName = [System.IO.Path]::GetFileName($target) } catch { $targetFileName = $null }
    }

    # Which of the curated entry's fields this mechanism answers to.
    $applicable = switch ($mechanism) {
        $script:StartupMechanismRunKey  { @{ 'RunValueName' = $name } }
        $script:StartupMechanismFolder  { @{ 'StartupFolderFileName' = $name } }
        $script:StartupMechanismTask    { @{ 'ScheduledTaskName' = $name } }
        $script:StartupMechanismService { @{ 'ServiceName' = $name; 'ServiceDisplayName' = $displayName } }
        default { @{} }
    }

    foreach ($entry in $KnownStartupItemEntry) {
        if ($null -eq $entry) { continue }

        foreach ($field in @($applicable.Keys)) {
            $patterns = [string[]](Get-OptimizerProperty -InputObject $entry -Name $field -Default @())
            if (Test-OptimizerAnyPatternMatch -Pattern $patterns -Value $applicable[$field]) { return $entry }
        }

        # targetFileName applies to every mechanism: it is how the same product is
        # caught whether the vendor registered it as a Run value or a task.
        $targetPatterns = [string[]](Get-OptimizerProperty -InputObject $entry -Name 'TargetFileName' -Default @())
        if (Test-OptimizerAnyPatternMatch -Pattern $targetPatterns -Value $targetFileName) { return $entry }
    }

    $null
}

function ConvertTo-StartupExclusionCandidate {
    # Presents a startup record in the shape Get-OptimizerExclusionMatch reads, so
    # services can be tested against P2-C3's curated exclusion list rather than
    # against a second vendor list written here.
    #
    # Publisher comes from the target binary's version resource and is frequently
    # absent -- on the development machine NvContainerLocalSystem, CAMService and
    # the Claude service all carry no CompanyName. An absent publisher means the
    # publisher rules simply do not match; it never means "not that vendor".
    #
    # -Publisher overrides that inventory-time value, and is how the lazily
    # resolved Authenticode signer reaches the gate for the handful of services
    # that get that far. An ORPHAN can never benefit from it: the binary that
    # would carry the signature is gone, by definition, so only display-name rules
    # can reach one.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $StartupItem,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Publisher
    )

    if ($null -eq $StartupItem) { return $null }

    if (-not $PSBoundParameters.ContainsKey('Publisher')) {
        $Publisher = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'Publisher')
    }

    [pscustomobject]@{
        Name              = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'Name')
        DisplayName       = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'DisplayName')
        PackageFamilyName = $null
        Publisher         = [string] $Publisher
    }
}

function Get-StartupItemEvidenceLine {
    # The one-line "what this is and where it lives" that opens every Finding's
    # Evidence, phrased per mechanism.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $StartupItem
    )

    $mechanism = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'Mechanism')
    $name      = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'Name')
    $location  = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'Location')
    $scope     = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'Scope')
    $view      = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'View')
    $trigger   = [string](Get-OptimizerProperty -InputObject $StartupItem -Name 'Trigger')

    $who = if ($scope -eq 'Machine') { 'for every user on this machine' } else { 'for this user' }

    switch ($mechanism) {
        $script:StartupMechanismRunKey {
            $viewText = if ($view -eq 'WOW6432Node') { ' (32-bit registry view)' } else { '' }
            return "Runs automatically $who from the registry startup key '$location'$viewText, as value '$name'. Trigger: $trigger."
        }
        $script:StartupMechanismFolder {
            return "Runs automatically $who from the Startup folder '$location', as '$name'. Trigger: $trigger."
        }
        $script:StartupMechanismTask {
            return "Runs automatically as the scheduled task '$location'. Trigger: $trigger."
        }
        $script:StartupMechanismService {
            return "Runs automatically as the Windows service '$name', whose start mode is Automatic. Trigger: $trigger."
        }
    }

    "Runs automatically at startup: $name."
}

#endregion

#region Public: scan

function Invoke-StartupItemScan {
    <#
    .SYNOPSIS
        Scans this machine for startup items and background services worth
        flagging.

    .DESCRIPTION
        Enumerates all four autostart mechanisms, returns Findings only for
        curated-list matches and orphans, and hands back the FULL inventory
        alongside them.

        Read-only. Nothing is removed, disabled or written; -WhatIf and -Confirm
        are deliberately not implemented because there is no state change for them
        to guard. Disabling belongs to the dispatcher (chunk P3-C1).

        WHAT THE COUNTS MEAN. FindingCount is expected to be small or zero on a
        machine whose owner installed their own software, and that is the correct
        answer, not a broken scan -- the inventory counts are how the two are told
        apart. StartupItems carries every entry found, so P4-C1 can show the user
        what autostarts on their machine without any of it being presented as
        something to remove. DisabledCount and UnknownStateCount say how many
        entries were held back because the user had already turned them off or
        because their state could not be decoded.

        ELEVATION. Nothing here requires it: measured un-elevated on the
        development machine, all four mechanisms read completely. Where a
        privilege level does hide something -- an unreadable task or service key --
        the count reaches the source's reason and the scan reports itself
        incomplete rather than returning less in silence.

    .PARAMETER CuratedListPath
        Curated list to match against. Defaults to Data\known-startup-items.json.

    .PARAMETER ExclusionPath
        P2-C3's exclusion list, used to keep driver, security and firmware-update
        services from ever being flagged. Defaults to
        Data\unused-app-exclusions.json.

    .PARAMETER StartupFolderPath
        Startup folders to read, as objects with Path and Scope. Defaults to the
        per-user and all-users Startup known folders.

    .PARAMETER ProtectedServiceClass
        Exclusion-list classes that make a service unflaggable. Defaults to
        driver, driver-utility, security.

    .PARAMETER OrphanProofServiceClass
        The subset of those classes whose protection survives a proved orphan.
        Defaults to 'security'.

    .PARAMETER ProtectedTaskNamespace
        Task path prefix that is never flagged. Defaults to '\Microsoft\Windows\'.

    .PARAMETER SkipScheduledTask
        Do not read scheduled tasks; the source reports itself Skipped and the
        scan reports itself incomplete.

    .PARAMETER SkipService
        Do not read services; the source reports itself Skipped and the scan
        reports itself incomplete.

    .EXAMPLE
        $scan = Invoke-StartupItemScan
        $scan.SummaryText
        $scan.StartupItems | Group-Object Mechanism | Select-Object Name, Count
        $scan.Findings | Format-Table DisplayName, Mechanism, FindingReason, SafetyLabel

    .OUTPUTS
        Win11Optimizer.StartupScanResult
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $CuratedListPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ExclusionPath,

        [Parameter()]
        [ValidateNotNull()]
        [psobject[]] $StartupFolderPath,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $ProtectedServiceClass = $script:StartupProtectedServiceClass,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $OrphanProofServiceClass = $script:StartupOrphanProofServiceClass,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ProtectedTaskNamespace = $script:StartupProtectedTaskNamespace,

        [Parameter()]
        [switch] $SkipScheduledTask,

        [Parameter()]
        [switch] $SkipService
    )

    $startedUtc = [datetime]::UtcNow
    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

    Write-OptimizerLog -EventName 'StartupScanStarted' -Message 'Startup-items scan started.'

    # Both lists load first and a failure propagates. A curated list that silently
    # yielded nothing would leave only the orphan rule running, and a scan with
    # one working rule out of two is indistinguishable from a clean machine.
    try {
        $curatedArguments = @{}
        if ($CuratedListPath) { $curatedArguments['Path'] = $CuratedListPath }
        $curated = @(Get-KnownStartupItemList @curatedArguments)
    }
    catch {
        Write-OptimizerLog -EventName 'StartupScanFailed' -Level 'Error' `
            -Message "Known-startup-item list could not be loaded: $($_.Exception.Message)"
        throw
    }

    try {
        $exclusionArguments = @{}
        if ($ExclusionPath) { $exclusionArguments['Path'] = $ExclusionPath }
        $exclusions = @(Get-UnusedAppExclusionList @exclusionArguments)
    }
    catch {
        Write-OptimizerLog -EventName 'StartupScanFailed' -Level 'Error' `
            -Message "Service exclusion list could not be loaded: $($_.Exception.Message)"
        throw
    }

    Write-OptimizerLog -EventName 'StartupListsLoaded' `
        -Message "Loaded $($curated.Count) known-startup-item entries and $($exclusions.Count) service exclusion entries."

    $isElevated = Test-IsElevated

    $inventoryArguments = @{}
    if ($PSBoundParameters.ContainsKey('StartupFolderPath')) { $inventoryArguments['StartupFolderPath'] = $StartupFolderPath }
    if ($SkipScheduledTask) { $inventoryArguments['SkipScheduledTask'] = $true }
    if ($SkipService) { $inventoryArguments['SkipService'] = $true }

    $inventory = Get-StartupItemInventory @inventoryArguments
    $items     = @($inventory.Items)
    $sources   = @($inventory.Sources)

    foreach ($source in $sources) {
        $level = if ($script:ScanSourceIncompleteStatuses -contains $source.Status) { 'Warning' } else { 'Info' }
        Write-OptimizerLog -EventName 'StartupScanSource' -Level $level `
            -Message "Source $($source.Name): $($source.Status)." `
            -Data ([ordered]@{
                Source          = $source.Name
                Status          = $source.Status
                ItemCount       = $source.ItemCount
                DurationSeconds = $source.DurationSeconds
                Reason          = $source.Reason
            })
    }

    # The machine half of the publisher question lives here, not in the pure
    # matcher: one Authenticode read per service that has ALREADY earned a
    # Finding, rather than ~90 across the inventory.
    $publisherResolver = { param($TargetPath) Get-StartupTargetPublisher -Path $TargetPath }

    $findings = @(Find-UnwantedStartupItem -StartupItem $items `
        -KnownStartupItemEntry $curated `
        -ExclusionEntry $exclusions `
        -ProtectedServiceClass $ProtectedServiceClass `
        -OrphanProofServiceClass $OrphanProofServiceClass `
        -ProtectedTaskNamespace $ProtectedTaskNamespace `
        -ServicePublisherResolver $publisherResolver |
        Sort-Object Category, DisplayName)

    $enabledCount      = @($items | Where-Object { $_.EnabledState -eq $script:StartupStateEnabled }).Count
    $disabledCount     = @($items | Where-Object { $_.EnabledState -eq $script:StartupStateDisabled }).Count
    $unknownStateCount = @($items | Where-Object { $_.EnabledState -eq $script:StartupStateUnknown }).Count
    $protectedTaskCount = @($items | Where-Object { $_.IsProtectedNamespace }).Count

    $orphanCount  = @($findings | Where-Object { $_.FindingReason -eq $script:StartupReasonOrphan }).Count
    $curatedCount = @($findings | Where-Object { $_.FindingReason -eq $script:StartupReasonCurated }).Count

    # How many enabled services the exclusion list held back, so a zero-Finding
    # scan can be told apart from an exclusion list that swallowed the lot. It
    # applies the same orphan exemption the matcher does -- a service that matched
    # a class but was flagged anyway was not held back by anything, and counting it
    # here would make the number disagree with the Findings beside it.
    #
    # Deliberately no publisher resolution in this loop: it runs across the whole
    # inventory, and the point of resolving lazily is that this is exactly where a
    # signature check per service would be paid for.
    $protectedServiceCount = 0
    foreach ($item in $items) {
        if ($item.Mechanism -ne $script:StartupMechanismService) { continue }
        if ($item.EnabledState -ne $script:StartupStateEnabled) { continue }
        $match = Get-OptimizerExclusionMatch -InstalledApp (ConvertTo-StartupExclusionCandidate -StartupItem $item) -ExclusionEntry $exclusions
        if ($null -eq $match) { continue }

        $matchedClass = [string](Get-OptimizerProperty -InputObject $match -Name 'Class')
        if ($ProtectedServiceClass -notcontains $matchedClass) { continue }

        $itemIsOrphan = ($item.TargetExists -is [bool] -and -not $item.TargetExists)
        if ($itemIsOrphan -and $OrphanProofServiceClass -notcontains $matchedClass) { continue }

        $protectedServiceCount++
    }

    $mechanismCount = [ordered]@{}
    foreach ($mechanism in $script:StartupMechanismRunKey, $script:StartupMechanismFolder, $script:StartupMechanismTask, $script:StartupMechanismService) {
        $mechanismCount[$mechanism] = @($items | Where-Object { $_.Mechanism -eq $mechanism }).Count
    }

    $totalTimer.Stop()

    $defaultCuratedPath   = Join-Path -Path $script:OptimizerDataRoot -ChildPath 'known-startup-items.json'
    $defaultExclusionPath = Join-Path -Path $script:OptimizerDataRoot -ChildPath 'unused-app-exclusions.json'

    $result = New-ScanResult -Detector 'StartupItems' -Category 'StartupItem' `
        -StartedUtc $startedUtc `
        -DurationSeconds ([math]::Round($totalTimer.Elapsed.TotalSeconds, 3)) `
        -IsElevated $isElevated `
        -InventoryCount $items.Count `
        -Source $sources `
        -Finding $findings `
        -ItemNoun 'startup entries' `
        -FindingNoun 'startup findings' `
        -ScanLabel 'Startup-items scan' `
        -TypeName $script:StartupScanResultTypeName `
        -AdditionalProperty ([ordered]@{
            CuratedListPath       = $(if ($CuratedListPath) { $CuratedListPath } else { $defaultCuratedPath })
            CuratedListCount      = $curated.Count
            ExclusionPath         = $(if ($ExclusionPath) { $ExclusionPath } else { $defaultExclusionPath })
            ExclusionCount        = $exclusions.Count
            MechanismCount        = $mechanismCount
            EnabledCount          = $enabledCount
            DisabledCount         = $disabledCount
            UnknownStateCount     = $unknownStateCount
            ProtectedTaskCount    = $protectedTaskCount
            ProtectedServiceCount = $protectedServiceCount
            OrphanCount           = $orphanCount
            CuratedMatchCount     = $curatedCount
            ReadStatistic         = $inventory.Statistic
            StartupItems          = [psobject[]] $items
        })

    Write-OptimizerLog -EventName 'StartupScanCompleted' `
        -Level $(if ($result.IsComplete) { 'Info' } else { 'Warning' }) `
        -Message $result.SummaryText `
        -Data ([ordered]@{
            IsComplete            = $result.IsComplete
            IsElevated            = $isElevated
            InventoryCount        = $items.Count
            FindingCount          = @($result.Findings).Count
            OrphanCount           = $orphanCount
            CuratedMatchCount     = $curatedCount
            DisabledCount         = $disabledCount
            UnknownStateCount     = $unknownStateCount
            ProtectedTaskCount    = $protectedTaskCount
            ProtectedServiceCount = $protectedServiceCount
            DurationSeconds       = $result.DurationSeconds
        })

    $result
}

#endregion
