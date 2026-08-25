<#
    Win11Optimizer.Engine — core engine module.

    Scope of this file (chunk P1-C1): the shared contract + plumbing that every
    later detector and the removal dispatcher build on:
      * the Finding object contract      (New-Finding / Test-Finding)
      * the elevation check              (Test-IsElevated)
      * the JSON-lines run log scaffold  (Start-/Write-/Stop-OptimizerLog)

    No detection, no removal, no registry/Appx queries live here — see docs/PLAN.md
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
    'Heuristic'  # surfaced by a usage heuristic — never presentable as "safe"
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

# The safety model from docs/PLAN.md, expressed once: only a curated-whitelist
# (Known) match may ever be shown to the user as safe. Everything else is
# "review needed". Findings carry this as a derived property so no UI or report
# can quietly re-label a Heuristic item.
$script:FindingSafetyLabels = @{
    Known     = 'Safe to remove'
    Heuristic = 'Review needed'
}

$script:FindingTypeName = 'Win11Optimizer.Finding'

#endregion

#region Finding contract

function New-Finding {
    <#
    .SYNOPSIS
        Creates a Finding — the single object shape every detector returns.

    .DESCRIPTION
        Returns a PSCustomObject tagged with the PSTypeName 'Win11Optimizer.Finding'.
        All field validation happens here at construction time, so a Finding that
        exists is by definition a valid one.

        The SafetyLabel property is derived from Confidence and is not settable:
        per the safety model in docs/PLAN.md, only Confidence 'Known' (curated
        whitelist match) is ever labelled "Safe to remove"; 'Heuristic' findings
        are always "Review needed".

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
        required — nothing is ever surfaced to the user without a stated reason.

    .PARAMETER Confidence
        'Known' for a curated-whitelist match, 'Heuristic' for anything surfaced
        by a usage heuristic.

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

        [Parameter(Mandatory)]
        [ValidateSet('Appx', 'RegistryUninstallString', 'PackageManagement', 'TaskScheduler', 'RegistryRunKey', 'ServiceDisable', 'FileDelete')]
        [string] $RemovalMethod
    )

    $finding = [pscustomobject]@{
        PSTypeName    = $script:FindingTypeName
        Category      = $Category
        Id            = $Id
        DisplayName   = $DisplayName
        Evidence      = [string[]] $Evidence
        Confidence    = $Confidence
        RemovalMethod = $RemovalMethod
    }

    # Derived, read-only: cannot be set by a caller and cannot drift from Confidence.
    $finding | Add-Member -MemberType ScriptProperty -Name 'SafetyLabel' -Value {
        if ($this.Confidence -eq 'Known') { 'Safe to remove' } else { 'Review needed' }
    }

    $finding
}

function Test-Finding {
    <#
    .SYNOPSIS
        Validates that an object satisfies the Finding contract.

    .DESCRIPTION
        New-Finding validates at construction, but Findings also cross boundaries
        where the type tag alone is not a guarantee — deserialized from a run log,
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

            foreach ($required in 'Category', 'Id', 'DisplayName', 'Evidence', 'Confidence', 'RemovalMethod') {
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
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    [pscustomobject]@{
        TypeName       = $script:FindingTypeName
        Categories     = [string[]] $script:FindingCategories
        Confidences    = [string[]] $script:FindingConfidences
        RemovalMethods = [string[]] $script:FindingRemovalMethods
        SafetyLabels   = $script:FindingSafetyLabels.Clone()
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
        module). Override with the WIN11OPTIMIZER_LOGROOT environment variable —
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
        Optional structured payload — a hashtable or any object that survives
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

# Detector chunks (P2-C1..C4) drop one file per sweep category in Detectors\ and
# add their public function names to the export list below and to
# FunctionsToExport in Win11Optimizer.Engine.psd1.
$detectorFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Detectors') -Filter '*.ps1' -File -ErrorAction SilentlyContinue)
foreach ($detectorFile in $detectorFiles) {
    . $detectorFile.FullName
}

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
)
