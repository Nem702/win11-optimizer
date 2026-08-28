<#
    Win11Optimizer.Engine -- core engine module.

    Scope of this file (chunk P1-C1): the shared contract + plumbing that every
    later detector and the removal dispatcher build on:
      * the Finding object contract      (New-Finding / Test-Finding)
      * the elevation check              (Test-IsElevated)
      * the JSON-lines run log scaffold  (Start-/Write-/Stop-OptimizerLog)

    No detection, no removal, no registry/Appx queries live here -- see docs/PLAN.md
    for which chunk owns what.
#>

Set-StrictMode -Version Latest

#region Contract constants

# The allowed values for the Finding contract. Kept as module-scope arrays so the
# ValidateSet attributes below and Test-Finding can never drift apart.
$script:FindingCategories = @(
    'OemBloatware'
    'StartupItem'
    'Service'
    'UnusedApp'
    'JunkFile'
)

$script:FindingConfidences = @(
    'Known'      # matched the curated known-bloatware whitelist
    'Heuristic'  # surfaced by a usage heuristic -- never presentable as "safe"
)

$script:FindingRemovalMethods = @(
    'Appx'
    'RegistryUninstallString'
    'PackageManagement'
    'TaskScheduler'
    'RegistryRunKey'
    'ServiceDisable'
    'FileDelete'
)

# The two safety labels. Defined once here so nothing else spells them out.
$script:FindingSafetyLabelSafe   = 'Safe to remove'
$script:FindingSafetyLabelReview = 'Review needed'

# The safety model from docs/PLAN.md and the 2026-08-25 decision in docs/STATE.md,
# expressed exactly once. It reads TWO axes, which answer different questions:
#
#   Confidence       how sure are we this is the thing we think it is?
#   RequiresConsent  regardless of that, must a human explicitly approve this one?
#
# Only a curated-whitelist (Known) match that needs no explicit consent is ever
# shown to the user as safe. Everything else is "review needed". Findings carry
# this as a derived property so no UI or report can quietly re-label an item, and
# Get-FindingContract hands the rule itself out so no consumer restates it.
#
# It FAILS CLOSED. Anything other than a real [bool] $false for RequiresConsent --
# absent, $null, or the string 'true' off a sloppy round-trip -- is read as
# "consent required". A Finding serialized before RequiresConsent existed therefore
# degrades to "review needed"; a round-trip through JSON can never silently upgrade
# a sensitive item to "safe".
$script:FindingSafetyLabelRule = {
    param($Confidence, $RequiresConsent)

    if ($Confidence -ne 'Known')        { return $script:FindingSafetyLabelReview }
    if ($RequiresConsent -isnot [bool]) { return $script:FindingSafetyLabelReview }
    if ($RequiresConsent)               { return $script:FindingSafetyLabelReview }

    $script:FindingSafetyLabelSafe
}

$script:FindingTypeName = 'Win11Optimizer.Finding'

#endregion

#region Finding contract

function New-Finding {
    <#
    .SYNOPSIS
        Creates a Finding -- the single object shape every detector returns.

    .DESCRIPTION
        Returns a PSCustomObject tagged with the PSTypeName 'Win11Optimizer.Finding'.
        All field validation happens here at construction time, so a Finding that
        exists is by definition a valid one.

        The SafetyLabel property is derived from BOTH Confidence and
        RequiresConsent, and is not settable: per the safety model in
        docs/PLAN.md, only a Confidence 'Known' (curated whitelist match) that
        does not require consent is ever labelled "Safe to remove". Everything
        else -- a 'Heuristic' finding, or a certain match that a human must still
        approve -- is "Review needed". The derivation fails closed, so a Finding
        whose RequiresConsent is missing or not a boolean is "Review needed" too.

    .PARAMETER Category
        Which sweep category surfaced this item.

    .PARAMETER Id
        Stable identifier for the item. What this holds depends on Category:
        package family name (Appx), uninstall registry key path (Win32 app),
        service name, scheduled task path, or absolute file path.

    .PARAMETER DisplayName
        Human-readable name, as shown in the review UI.

    .PARAMETER Evidence
        One or more strings explaining why this item was flagged. At least one is
        required -- nothing is ever surfaced to the user without a stated reason.

    .PARAMETER Confidence
        'Known' for a curated-whitelist match, 'Heuristic' for anything surfaced
        by a usage heuristic.

    .PARAMETER RequiresConsent
        The second safety axis, orthogonal to Confidence: set it when this item
        must not be acted on without an explicit human OK, however certain the
        match is. A curated whitelist entry for an OEM security-suite trial is
        the motivating case -- the match is certain, and it still needs a human.
        Absent means $false; the resulting Finding always carries a real [bool].

    .PARAMETER RemovalMethod
        Which mechanism the removal dispatcher (chunk P3-C1) will need for this
        item. Recorded here only; nothing in this chunk acts on it.

    .EXAMPLE
        New-Finding -Category OemBloatware -Id 'Acme.Widget_8wekyb3d8bbwe' -DisplayName 'Acme Widget' -Evidence 'Matches curated OEM list entry Acme.Widget' -Confidence Known -RemovalMethod Appx
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('OemBloatware', 'StartupItem', 'Service', 'UnusedApp', 'JunkFile')]
        [string] $Category,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Id,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DisplayName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (@($_ | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -lt 1) {
                throw 'Evidence must contain at least one non-empty string.'
            }
            $true
        })]
        [string[]] $Evidence,

        [Parameter(Mandatory)]
        [ValidateSet('Known', 'Heuristic')]
        [string] $Confidence,

        [Parameter()]
        [switch] $RequiresConsent,

        [Parameter(Mandatory)]
        [ValidateSet('Appx', 'RegistryUninstallString', 'PackageManagement', 'TaskScheduler', 'RegistryRunKey', 'ServiceDisable', 'FileDelete')]
        [string] $RemovalMethod
    )

    $finding = [pscustomobject]@{
        PSTypeName      = $script:FindingTypeName
        Category        = $Category
        Id              = $Id
        DisplayName     = $DisplayName
        Evidence        = [string[]] $Evidence
        Confidence      = $Confidence
        # Always a real [bool], never absent and never $null -- the safety rule
        # treats anything else as "consent required", and that must be a genuine
        # signal about the item rather than an artefact of a missing field.
        RequiresConsent = [bool] $RequiresConsent
        RemovalMethod   = $RemovalMethod
    }

    # Derived, read-only: cannot be set by a caller and cannot drift from the two
    # axes it reads. Both are read through PSObject.Properties rather than direct
    # property access, because Set-StrictMode -Version Latest is on and this
    # property must still answer -- with "Review needed" -- for a tampered or
    # pre-RequiresConsent object that is missing one of them.
    $finding | Add-Member -MemberType ScriptProperty -Name 'SafetyLabel' -Value {
        $confidenceProperty = $this.PSObject.Properties['Confidence']
        $consentProperty    = $this.PSObject.Properties['RequiresConsent']

        $confidence = if ($null -eq $confidenceProperty) { $null } else { $confidenceProperty.Value }
        $consent    = if ($null -eq $consentProperty)    { $null } else { $consentProperty.Value }

        & $script:FindingSafetyLabelRule $confidence $consent
    }

    $finding
}

function Test-Finding {
    <#
    .SYNOPSIS
        Validates that an object satisfies the Finding contract.

    .DESCRIPTION
        New-Finding validates at construction, but Findings also cross boundaries
        where the type tag alone is not a guarantee -- deserialized from a run log,
        handed in by the GUI, or produced by a future detector. Anything that
        consumes Findings (notably the removal dispatcher, chunk P3-C1) should
        gate on this rather than trusting the shape.

        Returns $true/$false. Use -Detailed to get the reasons instead.

    .PARAMETER InputObject
        The object to validate.

    .PARAMETER Detailed
        Return the list of validation failures (empty when valid) instead of a boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool], [string[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $InputObject,

        [switch] $Detailed
    )

    process {
        $problems = New-Object System.Collections.Generic.List[string]

        if ($null -eq $InputObject) {
            $problems.Add('Finding is null.')
        }
        else {
            $properties = @($InputObject.PSObject.Properties.Name)

            foreach ($required in 'Category', 'Id', 'DisplayName', 'Evidence', 'Confidence', 'RequiresConsent', 'RemovalMethod') {
                if ($properties -notcontains $required) {
                    $problems.Add("Missing required field '$required'.")
                }
            }

            if ($properties -contains 'Category' -and $script:FindingCategories -notcontains $InputObject.Category) {
                $problems.Add("Category '$($InputObject.Category)' is not one of: $($script:FindingCategories -join ', ').")
            }

            if ($properties -contains 'Confidence' -and $script:FindingConfidences -notcontains $InputObject.Confidence) {
                $problems.Add("Confidence '$($InputObject.Confidence)' is not one of: $($script:FindingConfidences -join ', ').")
            }

            # A real boolean, not a truthy string. SafetyLabel fails closed on a
            # non-boolean, so an item whose consent flag arrived as the string
            # "true" would still be labelled "Review needed" -- but it would be
            # labelled that for the wrong reason, and the next field to arrive
            # mistyped might not fail as harmlessly. Reject it here instead.
            if ($properties -contains 'RequiresConsent' -and $InputObject.RequiresConsent -isnot [bool]) {
                $problems.Add("Field 'RequiresConsent' must be a boolean, not [$(if ($null -eq $InputObject.RequiresConsent) { 'null' } else { $InputObject.RequiresConsent.GetType().Name })].")
            }

            if ($properties -contains 'RemovalMethod' -and $script:FindingRemovalMethods -notcontains $InputObject.RemovalMethod) {
                $problems.Add("RemovalMethod '$($InputObject.RemovalMethod)' is not one of: $($script:FindingRemovalMethods -join ', ').")
            }

            foreach ($required in 'Id', 'DisplayName') {
                if ($properties -contains $required -and [string]::IsNullOrWhiteSpace($InputObject.$required)) {
                    $problems.Add("Field '$required' must not be empty.")
                }
            }

            if ($properties -contains 'Evidence') {
                $evidence = @($InputObject.Evidence | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                if ($evidence.Count -lt 1) {
                    $problems.Add('Evidence must contain at least one non-empty string.')
                }
            }
        }

        if ($Detailed) { , $problems.ToArray() } else { $problems.Count -eq 0 }
    }
}

function Get-FindingContract {
    <#
    .SYNOPSIS
        Returns the allowed values of the Finding contract.

    .DESCRIPTION
        Lets detectors, the GUI and the test suite read the permitted Category /
        Confidence / RemovalMethod values from one place instead of restating them.

        SafetyLabelRule is the safety rule itself, as a scriptblock taking
        ($Confidence, $RequiresConsent) and returning the label. It is the same
        scriptblock a Finding's SafetyLabel property runs, so a consumer that has
        only the two field values -- a row deserialized from a run log, say -- can
        derive the label without restating the two-axis rule or the fail-closed
        behaviour. SafetyLabels lists the only two strings it can return.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    [pscustomobject]@{
        TypeName        = $script:FindingTypeName
        Categories      = [string[]] $script:FindingCategories
        Confidences     = [string[]] $script:FindingConfidences
        RemovalMethods  = [string[]] $script:FindingRemovalMethods
        SafetyLabels    = [string[]] @($script:FindingSafetyLabelSafe, $script:FindingSafetyLabelReview)
        SafetyLabelRule = $script:FindingSafetyLabelRule
    }
}

#endregion

#region Elevation

function Test-IsElevated {
    <#
    .SYNOPSIS
        Returns $true when the current process is running elevated (as Administrator).

    .DESCRIPTION
        Later detectors and the removal dispatcher call this to decide whether a
        given path is available, or whether the user needs to be asked to relaunch.

        Fails closed: if the check itself cannot be performed the function reports
        "not elevated" rather than throwing, so a caller can never be tricked into
        attempting a privileged operation because the probe errored.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        [bool] $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Verbose "Elevation check failed, reporting not-elevated: $($_.Exception.Message)"
        $false
    }
}

#endregion

#region Run log (JSON lines)

# Seed of the rollback/action log described in docs/RESEARCH.md. This chunk
# provides the transport only: one JSON object per line, appended to a per-run
# file. Removal-specific records (registry exports, package IDs) are chunk P3-C2.

$script:LogState = $null

function Get-OptimizerLogRoot {
    <#
    .SYNOPSIS
        Returns the folder run logs are written to.

    .DESCRIPTION
        Defaults to the 'logs' folder at the repo root (two levels above this
        module). Override with the WIN11OPTIMIZER_LOGROOT environment variable --
        a packaged install will not sit in a repo working tree.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $override = [Environment]::GetEnvironmentVariable('WIN11OPTIMIZER_LOGROOT')
    if (-not [string]::IsNullOrWhiteSpace($override)) {
        return $override
    }

    Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'logs'
}

function Start-OptimizerLog {
    <#
    .SYNOPSIS
        Opens a new per-run JSON-lines log file and writes the run header record.

    .DESCRIPTION
        Creates <log root>\run-<UTC timestamp>-<short run id>.jsonl and records a
        'RunStart' entry describing the environment the run happened in (OS build,
        PowerShell version, user, elevation). Subsequent Write-OptimizerLog calls
        append to this file until Stop-OptimizerLog is called.

        Calling this while a run log is already open closes the previous one first.

    .PARAMETER Path
        Write to this exact file instead of a generated one under the log root.

    .PARAMETER PassThru
        Return the run state (RunId, Path, StartedUtc) instead of nothing.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([psobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [switch] $PassThru
    )

    if ($null -ne $script:LogState) {
        Stop-OptimizerLog
    }

    $startedUtc = [datetime]::UtcNow
    $runId = [guid]::NewGuid().ToString()

    if (-not $Path) {
        $logRoot = Get-OptimizerLogRoot
        $fileName = 'run-{0}-{1}.jsonl' -f $startedUtc.ToString('yyyyMMdd-HHmmss'), $runId.Substring(0, 8)
        $Path = Join-Path -Path $logRoot -ChildPath $fileName
    }

    if (-not $PSCmdlet.ShouldProcess($Path, 'Start run log')) {
        return
    }

    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -Path $directory -ItemType Directory -Force
    }

    $script:LogState = [pscustomobject]@{
        RunId      = $runId
        Path       = $Path
        StartedUtc = $startedUtc
    }

    Write-OptimizerLog -EventName 'RunStart' -Message 'Run log opened.' -Data ([ordered]@{
        LogPath           = $Path
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition = $PSVersionTable.PSEdition
        OSVersion         = [Environment]::OSVersion.VersionString
        MachineName       = [Environment]::MachineName
        UserName          = [Environment]::UserName
        IsElevated        = (Test-IsElevated)
        ProcessId         = $PID
    })

    if ($PassThru) { $script:LogState }
}

function Write-OptimizerLog {
    <#
    .SYNOPSIS
        Appends one structured JSON-lines record to the current run log.

    .DESCRIPTION
        Each call writes exactly one line: a compact JSON object carrying the UTC
        timestamp, run id, level, event name, message and an optional Data payload.
        One object per line keeps the log appendable, tail-readable and parseable
        without loading the whole file.

        If no run log is open, one is started automatically.

    .PARAMETER Message
        Human-readable description of what happened.

    .PARAMETER EventName
        Short machine-readable event name, e.g. 'RunStart', 'DetectorCompleted'.

    .PARAMETER Level
        Severity: Debug, Info, Warning or Error. Defaults to Info.

    .PARAMETER Data
        Optional structured payload -- a hashtable or any object that survives
        ConvertTo-Json. A Finding can be passed here directly.

    .PARAMETER PassThru
        Return the record that was written.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $EventName = 'Message',

        [Parameter()]
        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string] $Level = 'Info',

        [Parameter()]
        [AllowNull()]
        $Data,

        [switch] $PassThru
    )

    if ($null -eq $script:LogState) {
        Start-OptimizerLog
    }

    $record = [ordered]@{
        Timestamp = [datetime]::UtcNow.ToString('o')
        RunId     = $script:LogState.RunId
        Level     = $Level
        Event     = $EventName
        Message   = $Message
    }

    if ($PSBoundParameters.ContainsKey('Data') -and $null -ne $Data) {
        $record['Data'] = $Data
    }

    $line = ConvertTo-Json -InputObject $record -Depth 6 -Compress

    if ($PSCmdlet.ShouldProcess($script:LogState.Path, 'Append log record')) {
        # AppendAllText with an explicit BOM-less UTF-8 encoder: Out-File -Append
        # under Windows PowerShell 5.1 would stamp a BOM into the middle of the
        # file and break line-by-line JSON parsing.
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::AppendAllText($script:LogState.Path, $line + [Environment]::NewLine, $encoding)
    }

    if ($PassThru) { [pscustomobject] $record }
}

function Stop-OptimizerLog {
    <#
    .SYNOPSIS
        Writes the run footer record and closes the current run log.

    .PARAMETER PassThru
        Return the state of the run log that was closed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([psobject])]
    param(
        [switch] $PassThru
    )

    if ($null -eq $script:LogState) {
        Write-Verbose 'No run log is open.'
        return
    }

    $closing = $script:LogState

    if ($PSCmdlet.ShouldProcess($closing.Path, 'Stop run log')) {
        Write-OptimizerLog -EventName 'RunEnd' -Message 'Run log closed.' -Data @{
            DurationSeconds = [math]::Round(([datetime]::UtcNow - $closing.StartedUtc).TotalSeconds, 3)
        }
        $script:LogState = $null
    }

    if ($PassThru) { $closing }
}

function Get-OptimizerLog {
    <#
    .SYNOPSIS
        Reads a JSON-lines run log back into objects.

    .DESCRIPTION
        Convenience for inspecting a run afterwards (and for the test suite).
        Blank lines are skipped; a malformed line is reported as a warning rather
        than aborting the read, so one bad record cannot hide the rest of the run.

    .PARAMETER Path
        The log file to read. Defaults to the currently open run log.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Position = 0)]
        [string] $Path
    )

    if (-not $Path) {
        if ($null -eq $script:LogState) {
            throw 'No run log is open; specify -Path.'
        }
        $Path = $script:LogState.Path
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Run log not found: $Path"
    }

    $lineNumber = 0
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            ConvertFrom-Json -InputObject $line
        }
        catch {
            Write-Warning "Skipping unparseable line $lineNumber in ${Path}: $($_.Exception.Message)"
        }
    }
}

function Get-OptimizerLogPath {
    <#
    .SYNOPSIS
        Returns the path of the currently open run log, or $null if none is open.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($null -eq $script:LogState) { return $null }
    $script:LogState.Path
}

#endregion

#region The source-folder loader

# The module's source is split across three folders, dot-sourced in this order:
#
#   Shared\     plumbing more than one consumer needs -- the registry uninstall
#               walk, the installed-app record, the match-pattern dialect, the
#               scan-result wrapper, the path probes and the protected-path gate.
#               FIRST, because detector and removal files reference its
#               module-scope constants at dot-source time.
#   Detectors\  one file per sweep category (chunks P2-C1..C4).
#   Removal\    the removal dispatcher (chunk P3-C1). AFTER Detectors\, because
#               it reads their module-scope constants -- the Run-key view table
#               and the StartupApproved store paths -- rather than restating them.
#
# Every one of them is REQUIRED. This used to be
#
#     Get-ChildItem -Path ... -Filter '*.ps1' -File -ErrorAction SilentlyContinue
#
# which is this project's signature failure mode sitting in the loader itself: an
# absent or unreadable folder produced zero files, no error, and a module that
# imported "successfully" with every name still in FunctionsToExport and none of
# them defined. Shared\ became load-bearing in P2-C3, so the failure would be a
# module that exports 24 functions and defines 10.
#
# Get-ChildItem cannot be used to detect it either. docs\REVIEW.md records the
# measurement: on a folder the current user cannot list it returns zero items and
# raises no error EVEN WITH -ErrorAction Stop. Only the .NET call distinguishes
# "empty" from "not allowed to look", by throwing.
#
# The three folders are dot-sourced by three explicit statements rather than by a
# loop over a list. The ORDER is the load-bearing thing here, and three lines say
# it where a loop would hide it behind a variable.

function Get-OptimizerSourceFile {
    <#
    .SYNOPSIS
        Returns the .ps1 files in one required module source folder, or throws.

    .DESCRIPTION
        Fails loud. A folder that is missing, or present and unreadable, throws
        with a message naming the folder -- never an empty list, which is how a
        half-loaded module gets imported and only fails later at the first call
        to a function that was exported but never defined.

        Enumerated with [System.IO.Directory]::GetFiles rather than
        Get-ChildItem: see the block comment above.

        Sorted ordinally so the dot-source order is the same on every machine.
        A folder that exists, is readable and is genuinely empty returns an empty
        array without error -- that is a real answer, not a gap.

    .PARAMETER Path
        The folder to read.

    .PARAMETER Name
        The folder's short name, for the error message.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Name
    )

    $files = $null
    try {
        $files = [System.IO.Directory]::GetFiles($Path, '*.ps1')
    }
    catch {
        # PowerShell wraps an exception thrown by a .NET METHOD in a
        # MethodInvocationException, so the useful type and message are one level
        # down. Get-OptimizerInnerException in Shared\ does this properly, and is
        # not available yet -- this runs before Shared\ is dot-sourced.
        $inner = $_.Exception.GetBaseException()
        throw "Win11Optimizer.Engine cannot be imported: the required '$Name' source folder at '$Path' could not be read. $($inner.GetType().Name): $($inner.Message)"
    }

    [string[]] @(@($files) | Sort-Object -CaseSensitive)
}

foreach ($optimizerSourceFile in (Get-OptimizerSourceFile -Path (Join-Path $PSScriptRoot 'Shared') -Name 'Shared')) {
    . $optimizerSourceFile
}

foreach ($optimizerSourceFile in (Get-OptimizerSourceFile -Path (Join-Path $PSScriptRoot 'Detectors') -Name 'Detectors')) {
    . $optimizerSourceFile
}

foreach ($optimizerSourceFile in (Get-OptimizerSourceFile -Path (Join-Path $PSScriptRoot 'Removal') -Name 'Removal')) {
    . $optimizerSourceFile
}

#endregion

Export-ModuleMember -Function @(
    'New-Finding'
    'Test-Finding'
    'Get-FindingContract'
    'Test-IsElevated'
    'Start-OptimizerLog'
    'Write-OptimizerLog'
    'Stop-OptimizerLog'
    'Get-OptimizerLog'
    'Get-OptimizerLogPath'
    'Get-OptimizerLogRoot'

    # P2-C1 -- OemBloatware detector (Detectors/OemBloatware.ps1)
    'Get-KnownBloatwareList'
    'Find-KnownBloatware'
    'Invoke-OemBloatwareScan'

    # P2-C3 -- shared inventory (Shared/Inventory.ps1)
    'Get-RegistryInstalledApp'

    # P2-C3 -- UnusedApp detector (Detectors/UnusedApps.ps1)
    'Get-UnusedAppExclusionList'
    'Get-AppUsageClassification'
    'Find-UnusedApp'
    'Invoke-UnusedAppScan'

    # P2-C2 -- StartupItem / Service detector (Detectors/StartupItems.ps1)
    'Get-KnownStartupItemList'
    'Get-StartupItemInventory'
    'Find-UnwantedStartupItem'
    'Invoke-StartupItemScan'

    # P2-C4 - JunkFile detector (Detectors/JunkFiles.ps1)
    'Get-JunkLocationList'
    'Get-JunkLocationInventory'
    'Find-JunkFileLocation'
    'Invoke-JunkFileScan'

    # P3-C1 - removal dispatcher (Removal/Dispatcher.ps1). Plans only:
    # nothing in this chunk removes, disables or writes anything.
    'Get-RemovalContract'
    'Get-RemovalPlan'
    'Get-RemovalPreview'

    # P3-C2 - the append-only action ledger (Removal/ActionLog.ps1). Appends to
    # its own log files and changes nothing about the machine.
    'Get-OptimizerActionLogPath'
    'Write-OptimizerAction'
    'Get-OptimizerActionLog'
    'Get-OptimizerRunReceipt'

    # P3-C2 - the best-effort System Restore checkpoint (Removal/RestorePoint.ps1).
    # The ONE call in this project that changes the state of the machine, kept in
    # a file of its own so that fact can be audited in one place.
    'New-OptimizerRestorePoint'
)
