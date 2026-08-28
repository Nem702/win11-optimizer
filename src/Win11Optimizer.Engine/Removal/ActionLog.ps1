<#
    The action ledger -- chunk P3-C2, first half.

    ONE append-only JSONL ledger for the machine, at <log root>\actions.jsonl.
    Not one file per run: rollback answers "what has this tool ever done to this
    PC, and can it be undone?", which a user asks weeks later without knowing
    which run did it. A per-run file cannot answer that without an index, and an
    index is a second thing to keep true.

    THIS FILE CHANGES NOTHING ABOUT THE MACHINE. It appends to its own ledger and
    to the per-action manifest sidecars beside it, and that is the entire set of
    writes it performs. It removes nothing, disables nothing, deletes nothing and
    touches no registry value. tests\ActionLog.Tests.ps1 re-applies P3-C1's three
    no-removal enforcement lists to this source, unchanged, and adds a positive
    allowlist naming the only two paths it may ever write to.

    The one call in this project that changes the state of the machine lives in
    Removal\RestorePoint.ps1, on its own, so that this claim about this file can
    be made without an exception attached to it.

    Why the ledger ships before the executor (docs\STATE.md 2026-08-25): the
    locked decision is "nothing is removed before an action log exists". If the
    executor and the ledger shipped together that decision would be satisfied by
    construction and would never have been a gate. The obvious risk of this order
    is a schema designed with no writer to prove it, and the answer is the machine
    survey: this machine produces 13 real plans across 7 routes, and every one of
    them is written to a ledger and read back before this chunk claims to work.

    THE FAILURE MODE THIS FILE EXISTS TO PREVENT is an action that happened and
    was not recorded. So:

      * the Intent record is written AND FLUSHED TO DISK before the caller gets
        control back, never batched and never queued;
      * an Intent with no Outcome is a first-class readable state --
        'OutcomeUnknown', "attempted, outcome unknown" -- and is never collapsed
        into "did not happen". It is the tri-state rule applied to history;
      * a line that will not parse is surfaced as a parse error and counted,
        never skipped;
      * a write that cannot be completed THROWS. A caller that cannot record what
        it is about to do must not do it.

    ASCII only -- Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, and one
    non-ASCII character in a comment walks the test suite's comment-blanking
    offsets off the end of the file (docs\REVIEW.md, after P3-C1a).
#>

#region Constants

$script:ActionLogFileName        = 'actions.jsonl'
$script:ActionManifestFolderName = 'action-manifests'
$script:ActionManifestSuffix     = '.files.jsonl'

# The ledger IS versioned, and unlike the data files' schemaVersion the reader
# actually reads it. See the report: a curated list is loaded by the same build
# that ships it, so a version it ignores costs nothing; a ledger is read back by
# a FUTURE version of this tool, months later, which is the exact case a version
# field exists for. An unknown version is surfaced on the entry and warned about,
# never silently reinterpreted.
$script:ActionLogSchemaVersion = 1

$script:ActionRecordTypeName  = 'Win11Optimizer.ActionRecord'
$script:ActionEntryTypeName   = 'Win11Optimizer.ActionLogEntry'
$script:ActionReceiptTypeName = 'Win11Optimizer.RunReceipt'

# What a line is.
#
#   Intent   written BEFORE anything is attempted. Carries the plan header, the
#            rollback data, the size before, the elevation state and the run id.
#   Outcome  written after the attempt returns. Carries the result, the duration
#            and the per-step results.
#   Note     anything else worth recording: a checkpoint result, a refusal, a
#            supersede.
#
# There is no fourth kind and no line is ever rewritten. A status change is a NEW
# record superseding an earlier one by ActionId.
$script:ActionRecordKindIntent  = 'Intent'
$script:ActionRecordKindOutcome = 'Outcome'
$script:ActionRecordKindNote    = 'Note'

$script:ActionRecordKinds = @(
    $script:ActionRecordKindIntent
    $script:ActionRecordKindOutcome
    $script:ActionRecordKindNote
)

# What an Outcome may say. A closed set, because the receipt counts on it.
$script:ActionResultSucceeded = 'Succeeded'
$script:ActionResultFailed    = 'Failed'
$script:ActionResultSkipped   = 'Skipped'
$script:ActionResultPartial   = 'Partial'

$script:ActionOutcomeResults = @(
    $script:ActionResultSucceeded
    $script:ActionResultFailed
    $script:ActionResultSkipped
    $script:ActionResultPartial
)

# Derived by the READER, never written on a line.
#
#   OutcomeUnknown  an Intent with no Outcome. The process died, or the outcome
#                   was never recorded. NOT "did not happen".
#   Refused         the ledger declined to record an intent because the plan
#                   said it was not supported. "We declined to act" is history.
#   ParseError      the line could not be read at all.
$script:ActionResultUnknown    = 'OutcomeUnknown'
$script:ActionResultRefused    = 'Refused'
$script:ActionResultParseError = 'ParseError'

# ConvertTo-Json truncates BELOW the depth it is given and does not error: the
# over-deep branch becomes the string 'System.Object[]'. This project's signature
# failure mode, in a serializer. Generous on purpose, and pinned by a round-trip
# test over a real plan from every route.
$script:ActionLogJsonDepth = 24

# Concurrency. The ledger is opened for append with FileShare.Read, so a second
# writer cannot open it at all rather than interleaving with the first; it waits
# and retries. See Add-OptimizerActionLine.
$script:ActionLogAppendAttemptLimit  = 200
$script:ActionLogAppendDelayFloorMs  = 2
$script:ActionLogAppendDelayJitterMs = 8

# How much of an unreadable line is quoted back. Enough to recognise it, not so
# much that a very long line of nonsense lands in a console.
$script:ActionLogRawLineLimit = 512

#endregion

#region Internal: the append primitive

function Add-OptimizerActionLine {
    <#
        Appends whole lines to a UTF-8 file and FLUSHES THEM TO DISK before
        returning. The only write path in this file.

        Opened with FileMode.Append + FileShare.Read: exclusive to writers,
        readable throughout. Two processes therefore cannot interleave a partial
        line -- the second one cannot open the file at all while the first holds
        it, and retries. That is a mutual-exclusion claim, not a claim that the
        operating system merges concurrent appends; the report says which of the
        two was actually measured.

        Flush($true) is the flushToDisk overload. Without it the line sits in the
        operating system's write cache, and a machine that loses power between the
        Intent and the attempt has a ledger that says nothing was starting --
        which is precisely the state this whole file exists to make impossible.

        THROWS if it cannot write. A caller that cannot record what it is about to
        do must not do it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string[]] $Line
    )

    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -Path $directory -ItemType Directory -Force
    }

    # One string, one Write call. Building the payload up front keeps the time the
    # file is held to the shortest it can be, and keeps a single line's write
    # indivisible from this process's point of view.
    $payload  = ($Line -join [Environment]::NewLine) + [Environment]::NewLine
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $bytes    = $encoding.GetBytes($payload)

    $lastError = $null
    for ($attempt = 1; $attempt -le $script:ActionLogAppendAttemptLimit; $attempt++) {
        $stream = $null
        try {
            $stream = New-Object System.IO.FileStream(
                $Path,
                [System.IO.FileMode]::Append,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::Read)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
            return
        }
        catch [System.IO.IOException] {
            # A sharing violation from another writer. Everything else -- a bad
            # path, a denied ACL, a full disk -- is not retried, because retrying
            # it only delays the throw.
            $lastError = $_
        }
        finally {
            if ($null -ne $stream) { $stream.Dispose() }
        }

        Start-Sleep -Milliseconds ($script:ActionLogAppendDelayFloorMs + (Get-Random -Minimum 0 -Maximum $script:ActionLogAppendDelayJitterMs))
    }

    $inner = Get-OptimizerInnerException -Exception $lastError.Exception
    throw "The action ledger at '$Path' could not be written after $($script:ActionLogAppendAttemptLimit) attempts, so nothing about this action has been recorded and it must not be attempted: $($inner.GetType().Name): $($inner.Message)"
}

#endregion

#region Internal: shapes

function Get-OptimizerActionHostContext {
    # Who and what wrote the line. Denormalised onto every record on purpose: a
    # ledger is read back by a future version on a machine that may have been
    # rebuilt, and "which account did this" is not derivable from anything else in
    # the file.
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    [pscustomobject][ordered]@{
        MachineName       = [Environment]::MachineName
        UserName          = [Environment]::UserName
        IsElevated        = [bool](Test-IsElevated)
        ProcessId         = $PID
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

function Copy-OptimizerObjectExcept {
    <#
        A [pscustomobject] copy of an object with some property names left out.

        A [pscustomobject], never [ordered]@{} and never a [hashtable]: a
        dictionary serialises to JSON correctly, so a round-trip test passes,
        while PSObject.Properties on it exposes Count/Keys/Values and not the
        entries -- so every Get-OptimizerProperty consumer reads nothing and no
        error is raised anywhere. docs\REVIEW.md, after P3-C1.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $ExcludeName
    )

    if ($null -eq $InputObject) { return $null }

    $copy = [ordered]@{}
    foreach ($property in @($InputObject.PSObject.Properties)) {
        if ($ExcludeName -contains $property.Name) { continue }
        $copy[$property.Name] = $property.Value
    }
    [pscustomobject] $copy
}

function Test-OptimizerActionPlan {
    <#
        The plan equivalent of Test-Finding: a plan arrives here deserialized from
        a ledger or handed in by a GUI, and the type tag alone is not a guarantee.

        Returns the problems as [string[]] -- empty when the plan is valid.

        It does NOT end in `, $array`, deliberately, because Test-Finding does and
        that shape cost P3-C1 a bug: @(Test-Finding ... -Detailed).Count is 1 for
        a perfectly valid Finding. Here @(Test-OptimizerActionPlan ...).Count is 0
        for a valid plan, which is what a reader expects it to be.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Plan
    )

    $problems = New-Object System.Collections.Generic.List[string]

    if ($null -eq $Plan) {
        $problems.Add('Plan is null.')
        return [string[]] $problems.ToArray()
    }

    $names = @($Plan.PSObject.Properties.Name)

    foreach ($required in 'FindingId', 'Category', 'RemovalMethod', 'DisplayName', 'Route', 'Supported', 'CurrentState', 'VerifiedUtc') {
        if ($names -notcontains $required) { $problems.Add("Missing required field '$required'.") }
    }

    $findingContract = Get-FindingContract
    $removalContract = Get-RemovalContract

    if ($names -contains 'Category' -and $findingContract.Categories -notcontains $Plan.Category) {
        $problems.Add("Category '$($Plan.Category)' is not one of: $($findingContract.Categories -join ', ').")
    }

    $knownRoute = [string[]] @(@($removalContract.RouteIds) + $removalContract.UnsupportedRoute)
    if ($names -contains 'Route' -and $knownRoute -notcontains $Plan.Route) {
        $problems.Add("Route '$($Plan.Route)' is not one of: $($knownRoute -join ', ').")
    }

    if ($names -contains 'CurrentState' -and $removalContract.CurrentStates -notcontains $Plan.CurrentState) {
        $problems.Add("CurrentState '$($Plan.CurrentState)' is not one of: $($removalContract.CurrentStates -join ', ').")
    }

    # A real boolean, not a truthy string, for the same reason Test-Finding
    # insists on one for RequiresConsent: this field decides whether an action is
    # attempted at all, and the string 'false' is $true to PowerShell.
    if ($names -contains 'Supported' -and $Plan.Supported -isnot [bool]) {
        $problems.Add("Field 'Supported' must be a boolean, not [$(if ($null -eq $Plan.Supported) { 'null' } else { $Plan.Supported.GetType().Name })].")
    }

    foreach ($required in 'FindingId', 'DisplayName') {
        if ($names -contains $required -and [string]::IsNullOrWhiteSpace([string] $Plan.$required)) {
            $problems.Add("Field '$required' must not be empty.")
        }
    }

    [string[]] $problems.ToArray()
}

function Get-OptimizerActionSizeBefore {
    # The disk-size-before capture the receipt is built from, taken from the plan
    # where the plan knows it. Only the junk route measures bytes today; every
    # other route reports $null rather than 0, because 0 is a measurement and
    # $null is "not measured", and a receipt must not add the two together.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Plan
    )

    $rollback = Get-OptimizerProperty -InputObject $Plan -Name 'RollbackData'
    $total    = Get-OptimizerProperty -InputObject $rollback -Name 'TotalBytes'
    if ($null -eq $total) { return $null }

    try { return [long] $total } catch { return $null }
}

#endregion

#region Internal: the manifest sidecar

function Get-OptimizerActionManifestFolder {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $LedgerPath
    )

    Join-Path -Path (Split-Path -Path $LedgerPath -Parent) -ChildPath $script:ActionManifestFolderName
}

function Write-OptimizerActionManifest {
    <#
        Writes one action's per-file manifest to a sidecar and returns the
        reference that goes on the ledger line.

        THE MANIFEST DOES NOT GO ON THE LINE. docs\STATE.md 2026-08-27: a plan is
        not a log line. Carrying the manifest inline made one Chrome plan 14 MB of
        JSON, and the ledger is the one file this project must never be tempted to
        rotate. So the line carries the counts, the byte total and a reference,
        and Get-OptimizerActionLog does not read the sidecar unless asked.

        JSONL, one file record per line, for the same reason the ledger is: a
        14,440-line manifest that is half-written is still readable up to the
        point it stops.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $LedgerPath,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $ActionId,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [psobject[]] $File
    )

    $folder   = Get-OptimizerActionManifestFolder -LedgerPath $LedgerPath
    $fileName = $ActionId + $script:ActionManifestSuffix
    $path     = Join-Path -Path $folder -ChildPath $fileName

    $lines      = New-Object System.Collections.Generic.List[string]
    $totalBytes = [long] 0
    foreach ($record in @($File)) {
        $size = Get-OptimizerProperty -InputObject $record -Name 'SizeBytes' -Default 0
        try { $totalBytes += [long] $size } catch { }
        $null = $lines.Add((ConvertTo-Json -InputObject ([pscustomobject][ordered]@{
            Path         = [string](Get-OptimizerProperty -InputObject $record -Name 'Path')
            SizeBytes    = [long] $size
            LastWriteUtc = (ConvertTo-RemovalUtcText -Value (Get-OptimizerProperty -InputObject $record -Name 'LastWriteUtc'))
            LocationId   = [string](Get-OptimizerProperty -InputObject $record -Name 'LocationId')
        }) -Depth 4 -Compress))
    }

    if ($lines.Count -gt 0) {
        Add-OptimizerActionLine -Path $path -Line ([string[]] $lines.ToArray())
    }

    [pscustomobject][ordered]@{
        SchemaVersion = $script:ActionLogSchemaVersion
        FileName      = $fileName
        RelativePath  = (Join-Path -Path $script:ActionManifestFolderName -ChildPath $fileName)
        RecordCount   = $lines.Count
        TotalBytes    = $totalBytes
        # Resolved against the LEDGER'S OWN FOLDER when it is read back, not
        # stored absolute: a log root that gets moved wholesale -- which is
        # exactly what the P5-C1 packaging question in the report is about --
        # keeps working, and an absolute path baked in at write time would not.
        Note          = 'Resolved against the folder the ledger itself is in. One JSON object per line: Path, SizeBytes, LastWriteUtc, LocationId.'
    }
}

#endregion

#region Internal: the plan header

function ConvertTo-OptimizerActionPlanHeader {
    <#
        The plan, minus the one thing that must not be on a log line: the junk
        route's per-file manifest.

        Everything else is carried as-is -- including RollbackData, which is the
        material a rollback is built from and is never summarised, never truncated
        and never reshaped by this file. P3-C1's locked decision says the
        dispatcher owns those shapes; this chunk persists them and proves the
        round trip.

        PreviewText is kept deliberately. It is derivable from the plan, so it
        looks redundant -- but it is the text a human actually read before
        approving, and a future version whose renderer has been reworded would
        derive different text for the same plan. What the user was told is
        history; what this build would say today is not.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Plan,
        [Parameter()] [AllowNull()] $ManifestRef
    )

    if ($null -eq $Plan) { return $null }

    $steps = New-Object System.Collections.Generic.List[psobject]
    foreach ($step in @(Get-OptimizerProperty -InputObject $Plan -Name 'Step' -Default @())) {
        if ($null -eq $step) { continue }

        $detail   = Get-OptimizerProperty -InputObject $step -Name 'Detail'
        $fileList = Get-OptimizerProperty -InputObject $detail -Name 'File'

        if ($null -eq $fileList) {
            $null = $steps.Add($step)
            continue
        }

        $trimmed = Copy-OptimizerObjectExcept -InputObject $detail -ExcludeName @('File')
        $trimmed | Add-Member -MemberType NoteProperty -Name 'FileManifestRef' -Value $ManifestRef
        $trimmed | Add-Member -MemberType NoteProperty -Name 'FileOnLine' -Value $false

        $trimmedStep = Copy-OptimizerObjectExcept -InputObject $step -ExcludeName @('Detail')
        $trimmedStep | Add-Member -MemberType NoteProperty -Name 'Detail' -Value $trimmed
        $null = $steps.Add($trimmedStep)
    }

    $header = Copy-OptimizerObjectExcept -InputObject $Plan -ExcludeName @('Step')
    $header | Add-Member -MemberType NoteProperty -Name 'Step' -Value ([psobject[]] $steps.ToArray())
    $header
}

#endregion

#region Public: the ledger

function Get-OptimizerActionLogPath {
    <#
    .SYNOPSIS
        Returns the path of the append-only action ledger.

    .DESCRIPTION
        <log root>\actions.jsonl, where the log root is exactly the one
        Get-OptimizerLogRoot returns -- same WIN11OPTIMIZER_LOGROOT override, no
        second location mechanism.

        DOES NOT CREATE THE FILE, and does not create the folder. Asking where the
        ledger is must never be the thing that brings one into existence.

        The ledger is DISTINCT from the per-run log Start-OptimizerLog writes and
        is not a replacement for it: a run log records a scan session and is
        disposable, the ledger records changes to the machine and is not. A run
        log entry may reference a ledger record id; never the reverse.

    .EXAMPLE
        Get-OptimizerActionLogPath
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Join-Path -Path (Get-OptimizerLogRoot) -ChildPath $script:ActionLogFileName
}

function Write-OptimizerAction {
    <#
    .SYNOPSIS
        Appends exactly one record to the append-only action ledger.

    .DESCRIPTION
        One line, flushed to disk, then it returns. No batching, no in-memory
        queue a crash can lose. Returns the ActionId.

        NOTHING IS EVER REWRITTEN. A status change is a NEW record superseding an
        earlier one by ActionId -- an Outcome after an Intent, a Note after
        either. There is no code path in this file that truncates, trims, rotates
        or edits a line, and none that deletes the ledger.

        The Intent record is what makes a removal safe to attempt, so it is
        written BEFORE the attempt and never after. An Intent with no Outcome is a
        readable state, not a gap: Get-OptimizerActionLog reports it as
        'OutcomeUnknown'.

        A plan that does not satisfy the plan contract THROWS, naming the
        problems. Nothing was attempted yet, so refusing loudly is the safe
        direction, and a caller handing this function an object that is not a plan
        has a bug that must not be written into permanent history.

        A plan whose Supported is $false is NOT silently skipped: it is recorded
        as a Note carrying the refusal reason, because "we declined to act" is
        history too. The ActionId is still returned and the entry reads back with
        Result 'Refused'.

    .PARAMETER Plan
        A Win11Optimizer.RemovalPlan, or one deserialized from JSON. A plan is
        data and must survive a round trip; this function accepts either.

    .PARAMETER RecordKind
        Intent, Outcome or Note. Defaults to Intent.

    .PARAMETER ActionId
        The action this record belongs to. Generated for an Intent when omitted.
        REQUIRED for an Outcome or a Note: a record that cannot be joined to its
        intent is lost history, so it fails loudly rather than orphaning itself.

    .PARAMETER Result
        Outcome only, and mandatory there: Succeeded, Failed, Skipped or Partial.

    .PARAMETER DurationSeconds
        Outcome only. How long the attempt took.

    .PARAMETER StepResult
        Outcome only. One object per plan step, in plan order.

    .PARAMETER ErrorText
        Any error text worth keeping, on an Outcome or a Note.

    .PARAMETER SizeBeforeBytes
        The disk size captured before the action. Derived from the plan's
        RollbackData when the route measures one; pass it explicitly to override.

    .PARAMETER Data
        Free-form payload. This is what a Note carries -- a restore-point result,
        a supersede, a checkpoint.

    .PARAMETER RunId
        The run this action belongs to. Defaults to the currently open run log's
        run id, or $null when no run log is open.

    .PARAMETER Path
        Write to this ledger instead of the default one.

    .PARAMETER PassThru
        Return the record that was written instead of the ActionId.

    .EXAMPLE
        $actionId = Get-RemovalPlan -Finding $finding | Write-OptimizerAction

    .EXAMPLE
        Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $actionId -Result Succeeded -DurationSeconds 12.4
    #>
    [CmdletBinding()]
    [OutputType([string], [psobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [AllowNull()]
        $Plan,

        [Parameter()]
        [ValidateSet('Intent', 'Outcome', 'Note')]
        [string] $RecordKind = 'Intent',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ActionId,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Result,

        [Parameter()]
        [AllowNull()]
        $DurationSeconds,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        $StepResult,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ErrorText,

        [Parameter()]
        [AllowNull()]
        $SizeBeforeBytes,

        [Parameter()]
        [AllowNull()]
        $Data,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $RunId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [switch] $PassThru
    )

    process {
        # Assign first, wrap second -- the P3-C1 lesson, applied to this file's own
        # validator even though this one does not carry the comma.
        $problemList = Test-OptimizerActionPlan -Plan $Plan
        $problems = [string[]] @($problemList)
        if ($problems.Count -gt 0) {
            throw "Write-OptimizerAction was handed something that is not a removal plan, so nothing has been recorded and nothing must be attempted: $($problems -join ' ')"
        }

        $ledgerPath = $(if ($PSBoundParameters.ContainsKey('Path')) { $Path } else { Get-OptimizerActionLogPath })

        # $Reason = $null on a [string] parameter becomes '' -- PowerShell
        # re-applies the type constraint on assignment -- so anything that has to
        # be able to be genuinely absent is held in an UNTYPED local and only ever
        # assigned a string. docs\REVIEW.md; it bites the tri-state reason strings
        # in RestorePoint.ps1 too.
        $runIdValue = $null
        if ($PSBoundParameters.ContainsKey('RunId')) {
            if (-not [string]::IsNullOrWhiteSpace($RunId)) { $runIdValue = $RunId }
        }
        elseif ($null -ne $script:LogState) {
            $runIdValue = $script:LogState.RunId
        }

        $errorValue = $null
        if ($PSBoundParameters.ContainsKey('ErrorText') -and -not [string]::IsNullOrWhiteSpace($ErrorText)) {
            $errorValue = $ErrorText
        }

        $kind = $RecordKind
        $refusalReason = $null

        if ($kind -eq $script:ActionRecordKindIntent -and -not $Plan.Supported) {
            # Not a silent skip and not a throw. The plan says no, with a reason a
            # user could read, and that decision belongs in the history exactly as
            # much as an action does.
            $kind = $script:ActionRecordKindNote
            $unsupported = [string](Get-OptimizerProperty -InputObject $Plan -Name 'UnsupportedReason')
            $refusalReason = $(if ([string]::IsNullOrWhiteSpace($unsupported)) {
                    'The plan was not supported and carried no reason.'
                } else { $unsupported })
            Write-Verbose "Recording a refusal rather than an intent for '$($Plan.FindingId)': $refusalReason"
        }

        if ($kind -eq $script:ActionRecordKindOutcome) {
            if ($script:ActionOutcomeResults -notcontains $Result) {
                throw "Write-OptimizerAction: an Outcome record needs a Result from: $($script:ActionOutcomeResults -join ', '). Got '$Result'."
            }
        }
        elseif ($PSBoundParameters.ContainsKey('Result') -and -not [string]::IsNullOrWhiteSpace($Result)) {
            throw "Write-OptimizerAction: Result belongs on an Outcome record, not on a $kind record."
        }

        $id = $null
        if ($PSBoundParameters.ContainsKey('ActionId')) {
            $id = $ActionId
        }
        elseif ($RecordKind -eq $script:ActionRecordKindIntent) {
            $id = [guid]::NewGuid().ToString()
        }
        else {
            throw "Write-OptimizerAction: a $RecordKind record needs -ActionId. A record that cannot be joined to the intent it belongs to is lost history, so it is refused rather than orphaned."
        }

        $manifestRef = $null
        if ($kind -eq $script:ActionRecordKindIntent) {
            foreach ($step in @(Get-OptimizerProperty -InputObject $Plan -Name 'Step' -Default @())) {
                $detail   = Get-OptimizerProperty -InputObject $step -Name 'Detail'
                $fileList = Get-OptimizerProperty -InputObject $detail -Name 'File'
                if ($null -eq $fileList) { continue }
                $manifestRef = Write-OptimizerActionManifest -LedgerPath $ledgerPath -ActionId $id -File ([psobject[]] @($fileList))
                break
            }
        }

        $sizeBefore = $null
        if ($PSBoundParameters.ContainsKey('SizeBeforeBytes')) {
            if ($null -ne $SizeBeforeBytes) { $sizeBefore = [long] $SizeBeforeBytes }
        }
        elseif ($kind -eq $script:ActionRecordKindIntent) {
            $sizeBefore = Get-OptimizerActionSizeBefore -Plan $Plan
        }

        $durationValue = $null
        if ($PSBoundParameters.ContainsKey('DurationSeconds') -and $null -ne $DurationSeconds) {
            $durationValue = [double] $DurationSeconds
        }

        $stepResultValue = $null
        if ($PSBoundParameters.ContainsKey('StepResult') -and $null -ne $StepResult) {
            $stepResultValue = [psobject[]] @($StepResult)
        }

        $dataValue = $null
        if ($PSBoundParameters.ContainsKey('Data') -and $null -ne $Data) { $dataValue = $Data }

        if ($null -ne $refusalReason) {
            $dataValue = [pscustomobject][ordered]@{
                IsRefusal         = $true
                UnsupportedReason = $refusalReason
                RequestedKind     = $script:ActionRecordKindIntent
                Note              = 'This tool declined to act on this plan. Nothing was attempted.'
                Payload           = $dataValue
            }
        }

        # Only an Intent (or the refusal that stands in for one) carries the plan
        # and the rollback material. An Outcome and a Note carry the identity
        # fields and their own payload: the plan is already on the line that
        # precedes them, and repeating it would make the ledger grow with every
        # status change on the same action.
        $carriesPlan = ($kind -eq $script:ActionRecordKindIntent) -or ($null -ne $refusalReason)

        $record = [pscustomobject][ordered]@{
            SchemaVersion     = $script:ActionLogSchemaVersion
            RecordId          = [guid]::NewGuid().ToString()
            ActionId          = $id
            RecordKind        = $kind
            TimestampUtc      = [datetime]::UtcNow.ToString('o')
            RunId             = $runIdValue
            Host              = (Get-OptimizerActionHostContext)
            FindingId         = [string] $Plan.FindingId
            Category          = [string] $Plan.Category
            RemovalMethod     = [string] $Plan.RemovalMethod
            DisplayName       = [string] $Plan.DisplayName
            Route             = [string] $Plan.Route
            IsReversible      = [bool](Get-OptimizerProperty -InputObject $Plan -Name 'IsReversible' -Default $false)
            RequiresElevation = [bool](Get-OptimizerProperty -InputObject $Plan -Name 'RequiresElevation' -Default $false)
            SizeBeforeBytes   = $sizeBefore
            Plan              = $(if ($carriesPlan) { ConvertTo-OptimizerActionPlanHeader -Plan $Plan -ManifestRef $manifestRef } else { $null })
            RollbackData      = $(if ($carriesPlan) { Get-OptimizerProperty -InputObject $Plan -Name 'RollbackData' } else { $null })
            ManifestRef       = $manifestRef
            Result            = $(if ($kind -eq $script:ActionRecordKindOutcome) { $Result } else { $null })
            DurationSeconds   = $durationValue
            StepResult        = $stepResultValue
            ErrorText         = $errorValue
            Data              = $dataValue
        }

        $line = ConvertTo-Json -InputObject $record -Depth $script:ActionLogJsonDepth -Compress
        Add-OptimizerActionLine -Path $ledgerPath -Line ([string[]] @($line))

        if ($PassThru) { $record } else { $id }
    }
}

function Get-OptimizerActionLog {
    <#
    .SYNOPSIS
        Reads the action ledger back, one object per ACTION rather than per record.

    .DESCRIPTION
        The Intent and any later Outcome or Note records for the same ActionId are
        collapsed into a current view, newest first. Result is the outcome, or
        'OutcomeUnknown' when there is no Outcome record -- which means
        "attempted, outcome unknown" and is never collapsed into "did not happen".
        It is the tri-state rule applied to history.

        A MALFORMED LINE DOES NOT KILL THE READ. It comes back as an entry of its
        own carrying IsParseError, the line number and the parse error; it is
        counted and warned about. A ledger that quietly drops the one line you
        needed is the same failure this project has hit six other ways.

        Parse errors are emitted FIRST and are NOT filtered out by -ActionId,
        -Category or the date range: a line that will not parse cannot be matched
        against a filter, and the line you filtered for is exactly the one it
        might be.

        An empty or absent ledger produces nothing, so @(...).Count is 0. It is
        not `return , $array`, which would give the caller an array containing an
        empty array and a Count of 1.

    .PARAMETER Path
        The ledger to read. Defaults to Get-OptimizerActionLogPath.

    .PARAMETER ActionId
        Return only these actions.

    .PARAMETER Category
        Return only actions in these Finding categories.

    .PARAMETER FromUtc
        Return only actions whose last record is at or after this UTC time.

    .PARAMETER ToUtc
        Return only actions whose first record is at or before this UTC time.

    .PARAMETER IncludeManifest
        Read the per-file manifest sidecar as well. OFF by default, so listing
        history never loads 14,440 paths.

    .EXAMPLE
        Get-OptimizerActionLog | Where-Object Result -eq 'OutcomeUnknown'

    .EXAMPLE
        Get-OptimizerActionLog -Category JunkFile -IncludeManifest
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $ActionId,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Category,

        [Parameter()]
        [AllowNull()]
        [datetime] $FromUtc,

        [Parameter()]
        [AllowNull()]
        [datetime] $ToUtc,

        [switch] $IncludeManifest
    )

    $ledgerPath = $(if ($PSBoundParameters.ContainsKey('Path')) { $Path } else { Get-OptimizerActionLogPath })

    if (-not (Test-Path -LiteralPath $ledgerPath)) {
        Write-Verbose "No action ledger at '$ledgerPath'. Nothing has been recorded on this machine by this tool."
        return
    }

    $lines = @()
    try { $lines = @([System.IO.File]::ReadAllLines($ledgerPath)) }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        throw "The action ledger at '$ledgerPath' could not be read: $($inner.GetType().Name): $($inner.Message)"
    }

    $parseFailure = New-Object System.Collections.Generic.List[psobject]
    $records      = New-Object System.Collections.Generic.List[psobject]

    $lineNumber = 0
    foreach ($line in $lines) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $parsed = $null
        try { $parsed = ConvertFrom-Json -InputObject $line -ErrorAction Stop }
        catch {
            $null = $parseFailure.Add((New-OptimizerActionLogEntry -IsParseError $true -Path $ledgerPath `
                -LineNumber $lineNumber -ParseError ([string] $_.Exception.Message) `
                -RawLine (ConvertTo-OptimizerActionRawLine -Line $line)))
            continue
        }

        $id = [string](Get-OptimizerProperty -InputObject $parsed -Name 'ActionId')
        if ([string]::IsNullOrWhiteSpace($id)) {
            $null = $parseFailure.Add((New-OptimizerActionLogEntry -IsParseError $true -Path $ledgerPath `
                -LineNumber $lineNumber -ParseError 'The line parsed as JSON but carries no ActionId, so it cannot be joined to an action.' `
                -RawLine (ConvertTo-OptimizerActionRawLine -Line $line)))
            continue
        }

        $parsed | Add-Member -MemberType NoteProperty -Name 'LineNumber' -Value $lineNumber -Force
        $null = $records.Add($parsed)
    }

    if ($parseFailure.Count -gt 0) {
        Write-Warning "$($parseFailure.Count) line(s) in '$ledgerPath' could not be read and are reported as parse errors, not dropped."
    }

    # Group by action, then collapse. Ordered by the timestamp ON the record, not
    # by line order: two processes appending concurrently can interleave lines
    # without interleaving bytes, so line order is not record order.
    $byAction = @{}
    foreach ($record in $records) {
        $id = [string] $record.ActionId
        if (-not $byAction.ContainsKey($id)) { $byAction[$id] = New-Object System.Collections.Generic.List[psobject] }
        $null = $byAction[$id].Add($record)
    }

    $entries = New-Object System.Collections.Generic.List[psobject]
    foreach ($id in @($byAction.Keys)) {
        $null = $entries.Add((ConvertTo-OptimizerActionLogEntry -ActionId $id -Record ([psobject[]] @($byAction[$id])) -Path $ledgerPath))
    }

    $selected = @($entries.ToArray())

    if ($PSBoundParameters.ContainsKey('ActionId') -and @($ActionId).Count -gt 0) {
        $wantedId = [string[]] @($ActionId)
        $selected = @($selected | Where-Object { $wantedId -contains $_.ActionId })
    }
    if ($PSBoundParameters.ContainsKey('Category') -and @($Category).Count -gt 0) {
        $wantedCategory = [string[]] @($Category)
        $selected = @($selected | Where-Object { $wantedCategory -contains $_.Category })
    }
    if ($PSBoundParameters.ContainsKey('FromUtc')) {
        $from = $FromUtc.ToUniversalTime()
        $selected = @($selected | Where-Object { $null -ne $_.LastRecordUtc -and $_.LastRecordUtc -ge $from })
    }
    if ($PSBoundParameters.ContainsKey('ToUtc')) {
        $to = $ToUtc.ToUniversalTime()
        $selected = @($selected | Where-Object { $null -ne $_.FirstRecordUtc -and $_.FirstRecordUtc -le $to })
    }

    $selected = @($selected | Sort-Object -Property LastRecordUtc -Descending)

    if ($IncludeManifest) {
        foreach ($entry in $selected) { Add-OptimizerActionManifestToEntry -Entry $entry -LedgerPath $ledgerPath }
    }

    # Parse errors first: they are the reason not to trust what follows, and a
    # caller that pipes into Select-Object -First would otherwise never see them.
    foreach ($entry in @($parseFailure.ToArray())) { $entry }
    foreach ($entry in $selected) { $entry }
}

function ConvertTo-OptimizerActionRawLine {
    # As much of an unreadable line as is worth quoting back.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Line
    )

    if ($null -eq $Line) { return '' }
    if ($Line.Length -le $script:ActionLogRawLineLimit) { return $Line }
    $Line.Substring(0, $script:ActionLogRawLineLimit) + '...'
}

function New-OptimizerActionLogEntry {
    <#
        The one shape Get-OptimizerActionLog ever emits. EVERY field exists on
        every entry, including the parse-error ones, because the module runs under
        Set-StrictMode -Version Latest and so does everything that consumes it: an
        entry that omits a field turns a consumer's branch into a throw instead of
        a $null.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ActionId,
        [Parameter()] [bool] $IsParseError = $false,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Path,
        [Parameter()] [AllowNull()] $LineNumber,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ParseError,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $RawLine
    )

    $idValue = $null
    if (-not [string]::IsNullOrWhiteSpace($ActionId)) { $idValue = $ActionId }

    [pscustomobject][ordered]@{
        PSTypeName           = $script:ActionEntryTypeName
        ActionId             = $idValue
        IsParseError         = $IsParseError
        Result               = $(if ($IsParseError) { $script:ActionResultParseError } else { $script:ActionResultUnknown })
        LedgerPath           = $Path
        LineNumber           = $LineNumber
        ParseError           = $ParseError
        RawLine              = $RawLine
        SchemaVersion        = $null
        IsSchemaVersionKnown = $true
        FirstRecordUtc       = $null
        LastRecordUtc        = $null
        IntentUtc            = $null
        OutcomeUtc           = $null
        RunId                = $null
        Category             = $null
        RemovalMethod        = $null
        Route                = $null
        FindingId            = $null
        DisplayName          = $null
        HasIntent            = $false
        HasOutcome           = $false
        IsRefused            = $false
        RecordCount          = 0
        RecordKind           = [string[]] @()
        SizeBeforeBytes      = $null
        RequiresElevation    = $null
        IsReversible         = $null
        DurationSeconds      = $null
        ErrorText            = $null
        Plan                 = $null
        RollbackData         = $null
        ManifestRef          = $null
        Manifest             = $null
        ManifestError        = $null
        StepResult           = $null
        Note                 = [psobject[]] @()
        Record               = [psobject[]] @()
    }
}

function ConvertTo-OptimizerActionLogEntry {
    # Collapses every record for one ActionId into the current view of it.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $ActionId,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [psobject[]] $Record,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path
    )

    # Timestamps come off JSON as [datetime] under both shells -- ConvertFrom-Json
    # recognises an ISO-8601 string and converts it -- so they are sorted as dates
    # through the same normaliser the dispatcher uses for VerifiedUtc. Anything
    # unparseable sorts to the front rather than vanishing.
    $ordered = @($Record | Sort-Object -Property @{ Expression = { ConvertTo-RemovalUtcText -Value (Get-OptimizerProperty -InputObject $_ -Name 'TimestampUtc') } })

    $entry = New-OptimizerActionLogEntry -ActionId $ActionId -Path $Path
    $entry.RecordCount = $ordered.Count
    $entry.Record      = [psobject[]] $ordered

    $kinds = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[psobject]

    $intent  = $null
    $outcome = $null

    # The loop variable is NOT $record. A local whose name differs from a
    # parameter only by case IS that parameter -- PowerShell has no shadowing --
    # and the parameter's type constraint is re-applied on assignment. Under a
    # [psobject[]] $Record parameter, `foreach ($record in $ordered)` therefore
    # hands each iteration a ONE-ELEMENT ARRAY wrapping the record, every
    # Get-OptimizerProperty against it reads $null, an Intent stops being
    # recognised as an Intent, and every action reads back as OutcomeUnknown with
    # no plan and no rollback data -- silently, with no error anywhere.
    # docs\REVIEW.md records the shape (added after P2-C4); this is it landing on
    # the one function in the project whose whole job is not to lose history.
    foreach ($current in $ordered) {
        $kind = [string](Get-OptimizerProperty -InputObject $current -Name 'RecordKind')
        $null = $kinds.Add($kind)

        $version = Get-OptimizerProperty -InputObject $current -Name 'SchemaVersion'
        if ($null -ne $version) {
            $entry.SchemaVersion = $version
            if ([int] $version -ne $script:ActionLogSchemaVersion) { $entry.IsSchemaVersionKnown = $false }
        }
        else { $entry.IsSchemaVersionKnown = $false }

        if ($kind -eq $script:ActionRecordKindIntent) {
            if ($null -eq $intent) { $intent = $current }
        }
        elseif ($kind -eq $script:ActionRecordKindOutcome) {
            # The LAST Outcome wins. A second Outcome for the same action is a
            # supersede, which is how an append-only ledger records a correction.
            $outcome = $current
        }
        elseif ($kind -eq $script:ActionRecordKindNote) {
            $null = $notes.Add($current)
        }
    }

    $entry.RecordKind = [string[]] @($kinds.ToArray() | Sort-Object -Unique)
    $entry.Note       = [psobject[]] @($notes.ToArray())

    $first = @($ordered | Select-Object -First 1)[0]
    $last  = @($ordered | Select-Object -Last 1)[0]
    $entry.FirstRecordUtc = ConvertTo-OptimizerActionDate -Value (Get-OptimizerProperty -InputObject $first -Name 'TimestampUtc')
    $entry.LastRecordUtc  = ConvertTo-OptimizerActionDate -Value (Get-OptimizerProperty -InputObject $last -Name 'TimestampUtc')

    # The identity fields are denormalised onto every record, so they can be read
    # from whichever record exists -- an Outcome that arrived without its Intent is
    # still identifiable.
    $identitySource = $(if ($null -ne $intent) { $intent } else { $last })
    $entry.RunId         = Get-OptimizerProperty -InputObject $identitySource -Name 'RunId'
    $entry.Category      = Get-OptimizerProperty -InputObject $identitySource -Name 'Category'
    $entry.RemovalMethod = Get-OptimizerProperty -InputObject $identitySource -Name 'RemovalMethod'
    $entry.Route         = Get-OptimizerProperty -InputObject $identitySource -Name 'Route'
    $entry.FindingId     = Get-OptimizerProperty -InputObject $identitySource -Name 'FindingId'
    $entry.DisplayName   = Get-OptimizerProperty -InputObject $identitySource -Name 'DisplayName'

    if ($null -ne $intent) {
        $entry.HasIntent         = $true
        $entry.IntentUtc         = ConvertTo-OptimizerActionDate -Value (Get-OptimizerProperty -InputObject $intent -Name 'TimestampUtc')
        $entry.Plan              = Get-OptimizerProperty -InputObject $intent -Name 'Plan'
        $entry.RollbackData      = Get-OptimizerProperty -InputObject $intent -Name 'RollbackData'
        $entry.ManifestRef       = Get-OptimizerProperty -InputObject $intent -Name 'ManifestRef'
        $entry.SizeBeforeBytes   = Get-OptimizerProperty -InputObject $intent -Name 'SizeBeforeBytes'
        $entry.RequiresElevation = Get-OptimizerProperty -InputObject $intent -Name 'RequiresElevation'
        $entry.IsReversible      = Get-OptimizerProperty -InputObject $intent -Name 'IsReversible'
    }

    foreach ($note in @($notes.ToArray())) {
        $data = Get-OptimizerProperty -InputObject $note -Name 'Data'
        if ([bool](Get-OptimizerProperty -InputObject $data -Name 'IsRefusal' -Default $false)) {
            $entry.IsRefused = $true
            if ($null -eq $entry.Plan)         { $entry.Plan         = Get-OptimizerProperty -InputObject $note -Name 'Plan' }
            if ($null -eq $entry.RollbackData) { $entry.RollbackData = Get-OptimizerProperty -InputObject $note -Name 'RollbackData' }
            if ($null -eq $entry.ManifestRef)  { $entry.ManifestRef  = Get-OptimizerProperty -InputObject $note -Name 'ManifestRef' }
        }
    }

    if ($null -ne $outcome) {
        $entry.HasOutcome      = $true
        $entry.OutcomeUtc      = ConvertTo-OptimizerActionDate -Value (Get-OptimizerProperty -InputObject $outcome -Name 'TimestampUtc')
        $entry.Result          = [string](Get-OptimizerProperty -InputObject $outcome -Name 'Result')
        $entry.DurationSeconds = Get-OptimizerProperty -InputObject $outcome -Name 'DurationSeconds'
        $entry.StepResult      = Get-OptimizerProperty -InputObject $outcome -Name 'StepResult'
        $entry.ErrorText       = Get-OptimizerProperty -InputObject $outcome -Name 'ErrorText'
    }
    elseif ($entry.IsRefused) {
        $entry.Result = $script:ActionResultRefused
    }
    else {
        # THE POINT OF THE WHOLE FILE. An intent with no outcome is not absent and
        # is not a failure. It is "we started, and we do not know how it ended",
        # and anyone reading history has to be told that in those terms.
        $entry.Result = $script:ActionResultUnknown
    }

    if (-not $entry.IsSchemaVersionKnown) {
        Write-Warning "Action '$ActionId' carries schema version '$($entry.SchemaVersion)'; this build reads version $($script:ActionLogSchemaVersion). It is reported as-is rather than reinterpreted."
    }

    $entry
}

function ConvertTo-OptimizerActionDate {
    # A [datetime] in UTC, or $null. ConvertFrom-Json hands back a [datetime]
    # already; a hand-edited ledger might not.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return ([datetime] $Value).ToUniversalTime() }

    $text = [string] $Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse($text, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $parsed)) {
        return $parsed.ToUniversalTime()
    }
    $null
}

function Add-OptimizerActionManifestToEntry {
    # Reads one entry's sidecar, resolved against the folder the ledger is in.
    # Only ever called for -IncludeManifest.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Entry,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $LedgerPath
    )

    if ($null -eq $Entry.ManifestRef) { return }

    $fileName = [string](Get-OptimizerProperty -InputObject $Entry.ManifestRef -Name 'FileName')
    if ([string]::IsNullOrWhiteSpace($fileName)) {
        $Entry.ManifestError = 'The manifest reference on this action carries no file name.'
        return
    }

    $path = Join-Path -Path (Get-OptimizerActionManifestFolder -LedgerPath $LedgerPath) -ChildPath $fileName
    if (-not (Test-Path -LiteralPath $path)) {
        $Entry.ManifestError = "The manifest sidecar '$path' is not there. The ledger line still records how many files there were and how big they were."
        return
    }

    $records = New-Object System.Collections.Generic.List[psobject]
    $bad = 0
    $number = 0
    foreach ($line in @([System.IO.File]::ReadAllLines($path))) {
        $number++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $null = $records.Add((ConvertFrom-Json -InputObject $line -ErrorAction Stop)) }
        catch { $bad++ }
    }

    $Entry.Manifest = [psobject[]] @($records.ToArray())
    if ($bad -gt 0) {
        $Entry.ManifestError = "$bad of $number line(s) in '$path' could not be read."
    }
}

#endregion

#region Public: the receipt

function Get-OptimizerRunReceipt {
    <#
    .SYNOPSIS
        Derives the post-run receipt from the action ledger.

    .DESCRIPTION
        IT IS A RECEIPT, NOT A BENCHMARK (docs\PLAN.md, docs\STATE.md 2026-08-25).
        Items acted on, per-category counts, and disk sizes captured before each
        action. No boot-time claim, no memory claim, no "faster", and nothing
        implying any of these numbers is reproducible from one run to the next.

        Derived from the ledger alone, per the locked decision -- there is no
        second parallel record for it to disagree with.

        Actions whose outcome was never recorded are counted and SHOWN. A receipt
        that quietly omitted them would be claiming a clean run it cannot prove.

        Bytes are summed only over actions that completed AND carried a
        SizeBeforeBytes. An action with no size measurement is counted separately
        rather than as zero: zero is a measurement, absent is not, and adding the
        two together is how a receipt starts lying.

    .PARAMETER Path
        The ledger to read. Defaults to Get-OptimizerActionLogPath.

    .PARAMETER RunId
        Only actions recorded under this run id.

    .PARAMETER FromUtc
        Only actions at or after this UTC time.

    .PARAMETER ToUtc
        Only actions at or before this UTC time.

    .EXAMPLE
        (Get-OptimizerRunReceipt -RunId $runId).ReceiptText
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $RunId,

        [Parameter()]
        [AllowNull()]
        [datetime] $FromUtc,

        [Parameter()]
        [AllowNull()]
        [datetime] $ToUtc
    )

    $ledgerPath = $(if ($PSBoundParameters.ContainsKey('Path')) { $Path } else { Get-OptimizerActionLogPath })

    $readArgs = @{ Path = $ledgerPath }
    if ($PSBoundParameters.ContainsKey('FromUtc')) { $readArgs['FromUtc'] = $FromUtc }
    if ($PSBoundParameters.ContainsKey('ToUtc'))   { $readArgs['ToUtc']   = $ToUtc }

    $all = @(Get-OptimizerActionLog @readArgs)

    $parseErrorCount = @($all | Where-Object { $_.IsParseError }).Count
    $actions = @($all | Where-Object { -not $_.IsParseError })

    if ($PSBoundParameters.ContainsKey('RunId')) {
        $actions = @($actions | Where-Object { [string] $_.RunId -eq $RunId })
    }

    $succeeded = @($actions | Where-Object { $_.Result -eq $script:ActionResultSucceeded })
    $partial   = @($actions | Where-Object { $_.Result -eq $script:ActionResultPartial })
    $failed    = @($actions | Where-Object { $_.Result -eq $script:ActionResultFailed })
    $skipped   = @($actions | Where-Object { $_.Result -eq $script:ActionResultSkipped })
    $refused   = @($actions | Where-Object { $_.Result -eq $script:ActionResultRefused })
    $unknown   = @($actions | Where-Object { $_.Result -eq $script:ActionResultUnknown })

    $counted = @(@($succeeded) + @($partial))

    $bytes = [long] 0
    $unmeasured = 0
    $measured = 0
    foreach ($action in $counted) {
        if ($null -eq $action.SizeBeforeBytes) { $unmeasured++; continue }
        try { $bytes += [long] $action.SizeBeforeBytes; $measured++ } catch { $unmeasured++ }
    }

    $categories = New-Object System.Collections.Generic.List[psobject]
    foreach ($name in @($actions | ForEach-Object { [string] $_.Category } | Sort-Object -Unique)) {
        # $_ inside a Where-Object nested in a loop is the PIPELINE element, not
        # the loop variable, and both readings type-check -- docs\REVIEW.md, after
        # P3-C1a. Captured here so the filter cannot be filtering on itself.
        $categoryName = $name
        $inCategory = @($actions | Where-Object { [string] $_.Category -eq $categoryName })
        $categoryBytes = [long] 0
        $categoryMeasured = 0
        foreach ($action in @($inCategory | Where-Object { $_.Result -eq $script:ActionResultSucceeded -or $_.Result -eq $script:ActionResultPartial })) {
            if ($null -eq $action.SizeBeforeBytes) { continue }
            try { $categoryBytes += [long] $action.SizeBeforeBytes; $categoryMeasured++ } catch { }
        }
        $null = $categories.Add([pscustomobject][ordered]@{
            Category            = $categoryName
            ActionCount         = $inCategory.Count
            SucceededCount      = @($inCategory | Where-Object { $_.Result -eq $script:ActionResultSucceeded }).Count
            PartialCount        = @($inCategory | Where-Object { $_.Result -eq $script:ActionResultPartial }).Count
            FailedCount         = @($inCategory | Where-Object { $_.Result -eq $script:ActionResultFailed }).Count
            SkippedCount        = @($inCategory | Where-Object { $_.Result -eq $script:ActionResultSkipped }).Count
            RefusedCount        = @($inCategory | Where-Object { $_.Result -eq $script:ActionResultRefused }).Count
            OutcomeUnknownCount = @($inCategory | Where-Object { $_.Result -eq $script:ActionResultUnknown }).Count
            SizeBeforeBytes     = $categoryBytes
            MeasuredCount       = $categoryMeasured
            # 'not measured' is NOT '0 bytes'. Zero is a measurement; absent is
            # not, and a category where nothing completed with a size recorded
            # must not render a figure that looks like one. See the same rule on
            # the receipt total below.
            SizeBeforeText      = $(if ($categoryMeasured -lt 1) { 'no size measured' } else { Format-JunkSize -Bytes $categoryBytes })
        })
    }

    $items = New-Object System.Collections.Generic.List[psobject]
    foreach ($action in $actions) {
        $null = $items.Add([pscustomobject][ordered]@{
            ActionId        = $action.ActionId
            Category        = $action.Category
            DisplayName     = $action.DisplayName
            Route           = $action.Route
            Result          = $action.Result
            IsReversible    = $action.IsReversible
            SizeBeforeBytes = $action.SizeBeforeBytes
            IntentUtc       = $action.IntentUtc
            OutcomeUtc      = $action.OutcomeUtc
        })
    }

    $receipt = [pscustomobject][ordered]@{
        PSTypeName          = $script:ActionReceiptTypeName
        GeneratedUtc        = [datetime]::UtcNow.ToString('o')
        LedgerPath          = $ledgerPath
        RunId               = $(if ($PSBoundParameters.ContainsKey('RunId')) { $RunId } else { $null })
        FromUtc             = $(if ($PSBoundParameters.ContainsKey('FromUtc')) { $FromUtc.ToUniversalTime().ToString('o') } else { $null })
        ToUtc               = $(if ($PSBoundParameters.ContainsKey('ToUtc')) { $ToUtc.ToUniversalTime().ToString('o') } else { $null })
        ActionCount         = $actions.Count
        SucceededCount      = $succeeded.Count
        PartialCount        = $partial.Count
        FailedCount         = $failed.Count
        SkippedCount        = $skipped.Count
        RefusedCount        = $refused.Count
        OutcomeUnknownCount = $unknown.Count
        ParseErrorCount     = $parseErrorCount
        SizeBeforeBytes     = $bytes
        SizeBeforeText      = (Format-JunkSize -Bytes $bytes)
        MeasuredCount       = $measured
        UnmeasuredCount     = $unmeasured
        Category            = [psobject[]] @($categories.ToArray())
        Item                = [psobject[]] @($items.ToArray())
        ReceiptText         = [string[]] @()
    }

    $receipt.ReceiptText = [string[]] @(Format-OptimizerRunReceiptText -Receipt $receipt)
    $receipt
}

function Format-OptimizerRunReceiptText {
    <#
        The receipt as lines.

        Every number here is a count of records or a sum of sizes measured before
        an action. NOTHING in this renderer may say what the user GETS from any of
        it -- no space freed, no time saved, no performance claim -- and a test
        asserts that against the same forbidden-phrase list the junk detector's
        evidence is already held to.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [psobject] $Receipt
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $null = $lines.Add('What this tool has done')
    $null = $lines.Add('=======================')
    $null = $lines.Add('')

    if ($Receipt.ActionCount -lt 1) {
        $null = $lines.Add('Nothing has been recorded for this selection. No action was taken.')
        $null = $lines.Add('')
        $null = $lines.Add("Read from: $($Receipt.LedgerPath)")
        return [string[]] $lines.ToArray()
    }

    $null = $lines.Add("Actions recorded: $(Format-JunkCount -Count $Receipt.ActionCount)")
    $null = $lines.Add("  Completed:                  $(Format-JunkCount -Count $Receipt.SucceededCount)")
    if ($Receipt.PartialCount -gt 0) { $null = $lines.Add("  Partly completed:           $(Format-JunkCount -Count $Receipt.PartialCount)") }
    if ($Receipt.FailedCount -gt 0)  { $null = $lines.Add("  Failed:                     $(Format-JunkCount -Count $Receipt.FailedCount)") }
    if ($Receipt.SkippedCount -gt 0) { $null = $lines.Add("  Skipped:                    $(Format-JunkCount -Count $Receipt.SkippedCount)") }
    if ($Receipt.RefusedCount -gt 0) { $null = $lines.Add("  Declined by this tool:      $(Format-JunkCount -Count $Receipt.RefusedCount)") }
    if ($Receipt.OutcomeUnknownCount -gt 0) {
        $null = $lines.Add("  Attempted, outcome unknown: $(Format-JunkCount -Count $Receipt.OutcomeUnknownCount)")
    }

    $null = $lines.Add('')
    $null = $lines.Add('By category')
    foreach ($category in @($Receipt.Category)) {
        $size = $(if ($category.MeasuredCount -lt 1) { 'no size measured' } else { "$($category.SizeBeforeText) measured before" })
        $null = $lines.Add("  $($category.Category): $(Format-JunkCount -Count $category.ActionCount) recorded, $(Format-JunkCount -Count $category.SucceededCount) completed, $size")
    }

    $null = $lines.Add('')
    if ($Receipt.MeasuredCount -lt 1) {
        # NOT '0 bytes'. Zero is a measurement and absent is not, and printing a
        # figure here when nothing was measured is the same failure this whole
        # project is built against, wearing a receipt. Measured 2026-08-27 in the
        # P3-C2 survey, where every completed action happened to be one of the
        # routes that records no size.
        $null = $lines.Add('Disk space occupied by what was acted on: not measured')
        if ($Receipt.UnmeasuredCount -gt 0) {
            $null = $lines.Add("  None of the $(Format-JunkCount -Count $Receipt.UnmeasuredCount) completed item(s) carried a size measurement, so there is no total to give.")
        }
        else {
            $null = $lines.Add('  Nothing completed, so there is nothing to measure.')
        }
    }
    else {
        $null = $lines.Add("Disk space occupied by what was acted on: $($Receipt.SizeBeforeText)")
        $null = $lines.Add('  Measured before each action, from the sizes recorded when the scan ran.')
        if ($Receipt.UnmeasuredCount -gt 0) {
            $null = $lines.Add("  $(Format-JunkCount -Count $Receipt.UnmeasuredCount) of the completed items had no size measurement and are not in that total.")
        }
    }

    if ($Receipt.OutcomeUnknownCount -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add("$(Format-JunkCount -Count $Receipt.OutcomeUnknownCount) action(s) were recorded as starting and never recorded as finishing.")
        $null = $lines.Add('  The ledger cannot say whether they happened. They are listed here rather than')
        $null = $lines.Add('  left out, because leaving them out would present this as a clean run.')
    }

    if ($Receipt.ParseErrorCount -gt 0) {
        $null = $lines.Add('')
        $null = $lines.Add("$(Format-JunkCount -Count $Receipt.ParseErrorCount) line(s) in the ledger could not be read, so this receipt may be incomplete.")
    }

    $null = $lines.Add('')
    $null = $lines.Add('This is a record of what was changed and how much disk space those items took.')
    $null = $lines.Add('It is not a benchmark and makes no claim about how this PC performs.')
    $null = $lines.Add('')
    $null = $lines.Add("Read from: $($Receipt.LedgerPath)")

    [string[]] $lines.ToArray()
}

#endregion
