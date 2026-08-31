<#
    Wiring a confirmed selection to the executor -- chunk P4-C2.

    THIS IS THE FIRST PLACE IN THE PROJECT WHERE A PERSON'S CHOICE REACHES
    SOMETHING THAT CHANGES THE MACHINE. Everything either side of it already
    existed: the review screen collects picks by Finding id (P4-C1), the
    dispatcher turns a Finding into a plan (P3-C1), the ledger records what is
    about to happen before it happens (P3-C2) and the executor performs one route
    and refuses the rest (P3-C3). This file is the two joins between them, and it
    adds no mechanism of its own.

    ITS ENTIRE WRITE SURFACE IS TWO CALLS: Invoke-RemovalPlan and
    Undo-RemovalAction. There is no registry access here, no filesystem write, no
    process started and no ledger call: the executor writes the ledger, because
    the ordering that makes an action safe -- Intent flushed to disk before the
    first write -- is a property of the function that does the writing and must
    not be reimplemented one layer up.

    ALL OF THEM OR NONE OF THEM, and the honest version of that sentence is worth
    writing out because the obvious one is not achievable:

      * BEFORE anything is attempted, every plan is offered to the executor with
        -WhatIf. That runs all five of its gates -- route, supported,
        Unverifiable, re-verification against the machine as it is now, elevation
        -- and writes nothing whatever: no ledger record, no restore point, no
        registry value. If ANY plan comes back refused, the whole run is refused
        and the ledger is untouched. On this machine that is the common case, not
        the exception: six of the seven routes are refused by this build, so a
        selection that mixes an app with a service stops here having done
        nothing, and says which picks stopped it.

      * If a plan still fails after that -- the machine moved, a write was
        denied -- the run STOPS at that plan and puts back what it had already
        done, newest first, through Undo-RemovalAction. The machine ends where it
        started.

      * THE LEDGER DOES NOT END WHERE IT STARTED, and it must not. An undo is a
        new action carrying UndoOfActionId, never an edit (P3-C3's locked
        decision), and nothing in this project ever rewrites a ledger line. So a
        rolled-back run reads as: this happened, and then it was put back. Both
        are true and the record says both. "No partial ledgers" is achievable
        only up to the first write, and the pre-flight above is where it is
        achieved.

    IT ASKS ONCE, FOR THE RUN. ConfirmImpact is High and ShouldProcess is called
    once, on the set, rather than once per plan: a person who has already read a
    preview and typed 'yes' at the review screen must not then be asked seven
    more times. The per-plan calls are made with -Confirm:$false for that reason
    and no other.

    ASCII only -- Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, and one
    non-ASCII character in a comment walks the test suite's comment-blanking
    offsets off the end of the file (docs\REVIEW.md, after P3-C1a).
#>

#region Constants

$script:ExecutionRunTypeName = 'Win11Optimizer.ExecutionRun'

# What a run may say. The ledger's own outcome vocabulary plus 'Refused', reused
# rather than restated -- the same five strings the executor answers with.
#
#   Succeeded  every plan was performed.
#   Refused    nothing was attempted. The ledger is untouched.
#   Skipped    there was nothing to do, or it was a dry run.
#   Failed     one plan failed and everything already done was put back.
#   Partial    one plan failed and putting it back did not fully work. The one
#              state that is neither before nor after, and the reason this value
#              exists here at all.
$script:ExecutionRunRefused = 'Refused'

#endregion

#region Internal

function Get-OptimizerExecutionRunId {
    <#
        The run these actions belong to.

        Mirrors Write-OptimizerAction's own default -- the open run log's id, or
        a fresh one when no run log is open -- and is then passed EXPLICITLY to
        every executor call, so the id on the ledger lines and the id the receipt
        is filtered by cannot come from two different places and disagree.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($null -ne $script:LogState) {
        $id = [string](Get-OptimizerProperty -InputObject $script:LogState -Name 'RunId' -Default '')
        if (-not [string]::IsNullOrWhiteSpace($id)) { return $id }
    }

    [guid]::NewGuid().ToString()
}

function New-OptimizerExecutionResult {
    # What Invoke-OptimizerExecutionPlan hands back. Every field on every one of
    # them, whatever happened: the module runs under Set-StrictMode -Version
    # Latest and a result that omits a field turns a consumer's branch into a
    # throw instead of a $null.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Result,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $RunId,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $LedgerPath,
        [Parameter(Mandatory)] [datetime] $StartedUtc,
        [Parameter()] [int] $PlanCount = 0,
        [Parameter()] [bool] $Performed = $false,
        [Parameter()] [bool] $IsWhatIf = $false,
        [Parameter()] [bool] $RolledBack = $false,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Reason,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ActionResult = @(),
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $UndoResult = @(),
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $Refusal = @(),
        [Parameter()] [AllowNull()] $Receipt = $null,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [string[]] $ReceiptText = @(),
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [string[]] $Note = @()
    )

    # Held untyped and only ever assigned a string: $x = $null on a
    # [string]-constrained variable becomes '', and '' reads as "there was a
    # reason and it was blank" rather than as "there was none". docs\REVIEW.md.
    $reasonValue = $null
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $reasonValue = $Reason }

    $actions = [psobject[]] @($ActionResult)
    $undone  = [psobject[]] @($UndoResult)

    [pscustomobject][ordered]@{
        PSTypeName      = $script:ExecutionRunTypeName
        Result          = $Result
        RunId           = $RunId
        LedgerPath      = $LedgerPath
        StartedUtc      = $StartedUtc.ToUniversalTime().ToString('o')
        CompletedUtc    = [datetime]::UtcNow.ToString('o')
        DurationSeconds = [math]::Round(([datetime]::UtcNow - $StartedUtc).TotalSeconds, 3)
        PlanCount       = $PlanCount
        AttemptedCount  = $actions.Count
        SucceededCount  = @($actions | Where-Object { [string](Get-OptimizerProperty -InputObject $_ -Name 'Result') -eq $script:ActionResultSucceeded }).Count
        Performed       = $Performed
        IsWhatIf        = $IsWhatIf
        RolledBack      = $RolledBack
        Reason          = $reasonValue
        ActionResult    = $actions
        UndoResult      = $undone
        # One entry per plan that stopped the run, in the order they were given:
        # the row, the route it was planned as, and the executor's own reason for
        # turning it down, unaltered. Reason above is the count; this is the list.
        Refusal         = [psobject[]] @($Refusal)
        Receipt         = $Receipt
        ReceiptText     = [string[]] @($ReceiptText)
        Note            = [string[]] @($Note)
    }
}

function Get-OptimizerExecutionReceipt {
    <#
        The receipt for THIS run, derived from the ledger and nothing else.

        Filtered by run id rather than by time: P4-C1's report noted that the
        receipt on the review screen is the whole ledger, which is right for a
        screen that opens with "what this tool has ever done" and wrong for the
        run that just happened.

        A ledger that is not there is the ordinary case for a run that was
        refused before it wrote anything, and Get-OptimizerRunReceipt answers it
        with "Nothing has been recorded for this selection" rather than an error.
        A ledger that cannot be READ is different, and is reported rather than
        swallowed: it means the run happened and this tool cannot show what it
        did.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $LedgerPath,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $RunId
    )

    try {
        return (Get-OptimizerRunReceipt -Path $LedgerPath -RunId $RunId)
    }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        Write-Warning "The run receipt could not be built from '$LedgerPath': $($inner.Message)"
        return $null
    }
}

#endregion

#region Public: picks to plans

function New-OptimizerExecutionPlan {
    <#
    .SYNOPSIS
        Turns the review screen's picks into removal plans -- one output per
        pick, in the order they were picked. Plans only; nothing is performed.

    .DESCRIPTION
        The review screen records what a person chose as Finding ids (P4-C1), and
        the executor takes plans. This is the join, and it is deliberately the
        only place that knows how to make one from the other.

        ONE OUTPUT PER PICK, IN PICK ORDER. A pick that matches no Finding
        produces $null IN ITS PLACE rather than a shorter list: the caller's Nth
        output is the Nth pick, and a run built from a list that quietly lost an
        entry would be a run acting on something nobody chose. Invoke-
        OptimizerExecutionPlan refuses a $null for exactly that reason.

        A pick that matches MORE THAN ONE Finding produces a plan for each. Ids
        are unique within a category by construction, so this is a guard rather
        than an expected shape -- but dropping the second silently is the failure
        this project exists to prevent, and the count coming back larger than the
        pick list is a signal a caller can see.

        Matching is case-insensitive, because a Finding id can be a registry key
        path, and a path that differs only in case is the same key.

        NOTHING HERE CHANGES THE MACHINE. Get-RemovalPlan reads; it removes,
        disables and writes nothing, and this function adds nothing to it. The
        plans are built in ONE pipeline call so the dispatcher's per-pipeline
        setup -- the protected-path walk over the shell's known folders and the
        drive table -- is paid once for the run rather than once per pick.

    .PARAMETER Finding
        The Findings the picks refer to. Show-ReviewScreen hands these back on
        its selection object.

    .PARAMETER Pick
        The Finding ids to act on, in the order they should be acted on.

    .EXAMPLE
        $selection = Show-ReviewScreen
        $plans = New-OptimizerExecutionPlan -Finding $selection.Finding -Pick ($selection.Finding | ForEach-Object { $_.Id })

    .EXAMPLE
        New-OptimizerExecutionPlan -Finding $scan.Findings -Pick @('Microsoft.Copilot_8wekyb3d8bbwe')
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory, Position = 0)] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Finding,
        # AllowEmptyString as well as AllowEmptyCollection: a mandatory [string[]]
        # otherwise rejects an array with a blank element outright, and a blank
        # pick is a thing a caller can hand us -- it resolves to no plan, which
        # is an answer this function has, rather than a binding error it does not.
        [Parameter(Mandatory, Position = 1)] [AllowEmptyCollection()] [AllowEmptyString()] [AllowNull()] [string[]] $Pick
    )

    $findings = @(@($Finding) | Where-Object { $null -ne $_ })

    # Resolve every pick first, then plan once. $matched holds the Findings in
    # pick order and $perPick how many of them each pick claimed, which is what
    # lets the plans be handed back against the picks they came from.
    $matched = New-Object System.Collections.Generic.List[psobject]
    $perPick = New-Object System.Collections.Generic.List[int]

    foreach ($id in @($Pick)) {
        if ([string]::IsNullOrWhiteSpace($id)) {
            Write-Verbose 'A pick was blank, which resolves to no Finding and therefore to no plan.'
            $null = $perPick.Add(0)
            continue
        }

        # $id is captured into a local first: $_ inside a Where-Object is the
        # pipeline element, and a filter reading the enclosing loop variable by
        # the same name would be filtering on itself. docs\REVIEW.md, after
        # P3-C1a.
        $wanted = $id
        $hits = @($findings | Where-Object { [string](Get-OptimizerProperty -InputObject $_ -Name 'Id') -eq $wanted })
        foreach ($hit in $hits) { $null = $matched.Add($hit) }
        $null = $perPick.Add($hits.Count)

        if ($hits.Count -lt 1) {
            Write-Verbose "No Finding carries the id '$id', so that pick resolves to no plan."
        }
    }

    $plans = @()
    if ($matched.Count -gt 0) {
        $plans = @(@($matched.ToArray()) | Get-RemovalPlan)
    }

    # Get-RemovalPlan's contract is one input, one plan, always -- so the plans
    # come back in the order the Findings went in and can be handed straight back
    # against the picks. If that ever stopped being true this loop would run off
    # the end, so it is checked rather than assumed.
    if ($plans.Count -ne $matched.Count) {
        throw "New-OptimizerExecutionPlan: the dispatcher returned $($plans.Count) plan(s) for $($matched.Count) finding(s). Its contract is one plan per finding, always, so nothing is guessed at and nothing is returned."
    }

    $position = 0
    foreach ($count in $perPick) {
        if ($count -lt 1) {
            # A $null IN ITS PLACE. See the description: the Nth output is the
            # Nth pick, and this is what says "that one resolved to nothing".
            Write-Output -InputObject $null
            continue
        }
        for ($offset = 0; $offset -lt $count; $offset++) {
            $plans[$position + $offset]
        }
        $position += $count
    }
}

#endregion

#region Public: perform a confirmed selection

function Invoke-OptimizerExecutionPlan {
    <#
    .SYNOPSIS
        Performs a confirmed set of removal plans as one run: all of them, or
        none of them. Prints the receipt and hands back what happened.

    .DESCRIPTION
        The set is taken as an array and NOT one plan at a time from the
        pipeline, on purpose: all-or-nothing is a property of the whole set, and
        a process block that sees one plan at a time cannot refuse a run because
        of the plan after it.

        THE SEQUENCE:

          1. Every input is checked for being a plan at all. A $null -- a pick
             that resolved to nothing -- stops the run here, named by its
             position, with nothing attempted.

          2. THE PRE-FLIGHT. Every plan is offered to Invoke-RemovalPlan with
             -WhatIf, which runs its five gates and writes nothing at all. One
             refusal refuses the whole run, quoting the executor's own reason for
             each plan it turned down. This is the step that makes "none of them"
             mean the ledger was never touched, and on this machine it is the
             usual outcome: this build performs one route of seven.

          3. One ShouldProcess, for the run. ConfirmImpact is High, so an
             interactive caller is asked once; pass -Confirm:$false to run
             unattended. The per-plan calls that follow are made with
             -Confirm:$false so nobody is asked twice for the same decision.

          4. The plans are performed in the order they were given. The FIRST one
             that does not come back Succeeded stops the run: the rest are not
             attempted.

          5. If anything was performed before that failure, it is put back --
             newest first, through Undo-RemovalAction, which refuses to overwrite
             a value something else has changed since. The machine ends where it
             started. Where an undo is itself refused, the run reports Partial:
             the one state that is neither before nor after, and it is said
             plainly rather than rounded to Failed.

          6. The receipt for THIS run is derived from the ledger by run id and
             printed through -Writer.

        THE RECEIPT IS PRINTED ONLY WHERE SOMETHING REACHED THE LEDGER. A run
        refused at step 1 or step 2 wrote nothing, and its run id is new, so a
        receipt for it can only ever say "Actions recorded: 0" -- a derivation
        that cannot come out any other way is not evidence of anything. Those
        runs get the plain sentence instead, and ReceiptText comes back empty so
        a caller can tell the two cases apart.

        WHAT IT DOES NOT DO. It does not build plans (that is
        New-OptimizerExecutionPlan), it does not decide anything (that is
        Show-ReviewScreen), it does not write to the ledger (the executor does,
        before it writes anything else), and it does not prompt for elevation --
        a plan that needs administrator rights in a process that has none is
        refused by the executor at the pre-flight, with its reason, and the UAC
        shim is P5-C1.

    .PARAMETER Plan
        The plans to perform, in order. A $null in the array is a pick that
        resolved to no plan and refuses the run.

    .PARAMETER LedgerPath
        Write to this action ledger instead of the default one.

    .PARAMETER RunId
        The run these actions belong to. Defaults to the open run log's run id,
        or a fresh one. The receipt is filtered by it.

    .PARAMETER Writer
        Scriptblock taking one line to display. Defaults to Write-Host; a test
        passes a collector and asserts on the exact transcript.

    .PARAMETER SkipRestorePoint
        Do not ask Windows for a System Restore checkpoint. The ledger, not the
        checkpoint, is what makes a change recoverable.

    .EXAMPLE
        $selection = Show-ReviewScreen
        if ($selection.Confirmed) {
            New-OptimizerExecutionPlan -Finding $selection.Finding -Pick @($selection.Finding | ForEach-Object { $_.Id }) |
                ForEach-Object { $_ } | Invoke-OptimizerExecutionPlan
        }

    .EXAMPLE
        $run = Invoke-OptimizerExecutionPlan -Plan $plans -Confirm:$false
        $run.Result
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [psobject[]] $Plan,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $LedgerPath,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $RunId,

        [Parameter()]
        [ValidateNotNull()]
        [scriptblock] $Writer = { param($Line) Write-Host $Line },

        [switch] $SkipRestorePoint
    )

    $started = [datetime]::UtcNow

    $runIdValue = $(if ($PSBoundParameters.ContainsKey('RunId') -and -not [string]::IsNullOrWhiteSpace($RunId)) {
            $RunId
        } else {
            Get-OptimizerExecutionRunId
        })
    $resolvedLedger = $(if ($PSBoundParameters.ContainsKey('LedgerPath')) { $LedgerPath } else { Get-OptimizerActionLogPath })

    # Every executor call in this function is made with these. -Confirm:$false is
    # here because the run has already been confirmed once, at step 3, and asking
    # again per plan would train a person to answer without reading.
    $executorArgument = @{ RunId = $runIdValue; Confirm = $false }
    if ($PSBoundParameters.ContainsKey('LedgerPath')) { $executorArgument['LedgerPath'] = $LedgerPath }
    if ($SkipRestorePoint) { $executorArgument['SkipRestorePoint'] = $true }

    $plans = @($Plan)
    $note  = New-Object System.Collections.Generic.List[string]

    function New-RunRefusal {
        param(
            [Parameter(Mandatory)] [string] $Because,
            [Parameter()] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Detail = @()
        )
        New-OptimizerExecutionResult -Result $script:ExecutionRunRefused -RunId $runIdValue `
            -LedgerPath $resolvedLedger -StartedUtc $started -PlanCount $plans.Count -Reason $Because `
            -Refusal ([psobject[]] @($Detail)) -Note ([string[]] @($note.ToArray()))
    }

    function New-RunRefusalDetail {
        param(
            [Parameter(Mandatory)] [AllowEmptyString()] [string] $DisplayName,
            [Parameter(Mandatory)] [AllowEmptyString()] [string] $Route,
            [Parameter(Mandatory)] [AllowEmptyString()] [string] $Reason
        )
        [pscustomobject][ordered]@{ DisplayName = $DisplayName; Route = $Route; Reason = $Reason }
    }

    # ---- 1. is every one of them a plan at all -------------------------------
    $problem = New-Object System.Collections.Generic.List[psobject]
    for ($index = 0; $index -lt $plans.Count; $index++) {
        $position = "Pick $($index + 1) of $($plans.Count)"

        if ($null -eq $plans[$index]) {
            $null = $problem.Add((New-RunRefusalDetail -DisplayName $position -Route '(no plan)' `
                -Reason "$position resolved to no plan at all, so this tool does not know what it would be acting on. Nothing was attempted."))
            continue
        }
        # Assigned first and wrapped second -- P3-C1's lesson, applied even
        # though Test-OptimizerActionPlan deliberately does not carry the comma.
        $detailList = Test-OptimizerActionPlan -Plan $plans[$index]
        $detail = [string[]] @($detailList)
        if ($detail.Count -gt 0) {
            $null = $problem.Add((New-RunRefusalDetail -DisplayName $position -Route '(not a plan)' `
                -Reason "$position is not a removal plan: $($detail -join ' ')"))
        }
    }

    if ($problem.Count -gt 0) {
        $refusal = New-RunRefusal -Detail ([psobject[]] @($problem.ToArray())) `
            -Because ("{0} of the {1} given are not something this tool can act on, so nothing was attempted and nothing was written." -f $problem.Count, $plans.Count)
        Write-OptimizerExecutionReport -Run $refusal -Writer $Writer
        return $refusal
    }

    if ($plans.Count -lt 1) {
        $result = New-OptimizerExecutionResult -Result $script:ActionResultSkipped -RunId $runIdValue `
            -LedgerPath $resolvedLedger -StartedUtc $started -PlanCount 0 `
            -Reason 'Nothing was selected, so there was nothing to do and nothing was written.'
        Write-OptimizerExecutionReport -Run $result -Writer $Writer
        return $result
    }

    # ---- 2. THE PRE-FLIGHT ---------------------------------------------------
    #
    # -WhatIf runs the executor's five gates and writes nothing whatever. A
    # refusal here costs a read; a refusal after the first plan has been
    # performed costs an undo, and the ledger then carries both.
    $refused = New-Object System.Collections.Generic.List[psobject]
    foreach ($candidate in $plans) {
        $check = Invoke-RemovalPlan -Plan $candidate -WhatIf @executorArgument
        if ([string](Get-OptimizerProperty -InputObject $check -Name 'Result') -eq $script:ExecutionRunRefused) {
            $null = $refused.Add((New-RunRefusalDetail `
                -DisplayName ([string](Get-OptimizerProperty -InputObject $candidate -Name 'DisplayName')) `
                -Route ([string](Get-OptimizerProperty -InputObject $candidate -Name 'Route')) `
                -Reason ([string](Get-OptimizerProperty -InputObject $check -Name 'Reason'))))
        }
    }

    if ($refused.Count -gt 0) {
        $refusal = New-RunRefusal -Detail ([psobject[]] @($refused.ToArray())) `
            -Because ("{0} of the {1} selected cannot be carried out, so none of them was attempted and nothing was written." -f $refused.Count, $plans.Count)
        Write-OptimizerExecutionReport -Run $refusal -Writer $Writer
        return $refusal
    }

    # ---- 3. one question, for the run ---------------------------------------
    $target = ("{0} change(s) to this PC" -f $plans.Count)
    $action = 'Carry out the selected changes'
    if (-not $PSCmdlet.ShouldProcess($target, $action)) {
        $result = New-OptimizerExecutionResult -Result $script:ActionResultSkipped -RunId $runIdValue `
            -LedgerPath $resolvedLedger -StartedUtc $started -PlanCount $plans.Count -IsWhatIf $true `
            -Reason 'Nothing was written: no ledger record, no restore point and no registry value. This was a dry run.'
        Write-OptimizerExecutionReport -Run $result -Writer $Writer
        return $result
    }

    # ---- 4. perform them, in order, stopping at the first that does not ------
    $actionResult = New-Object System.Collections.Generic.List[psobject]
    $failure = $null

    foreach ($candidate in $plans) {
        $outcome = Invoke-RemovalPlan -Plan $candidate @executorArgument
        $null = $actionResult.Add($outcome)

        if ([string](Get-OptimizerProperty -InputObject $outcome -Name 'Result') -ne $script:ActionResultSucceeded) {
            $failure = $outcome
            break
        }
    }

    $performed = @($actionResult | Where-Object { [bool](Get-OptimizerProperty -InputObject $_ -Name 'Performed' -Default $false) }).Count -gt 0

    # ---- 5. put back what was already done ----------------------------------
    $undoResult = New-Object System.Collections.Generic.List[psobject]
    $rolledBack = $false
    $undoRefused = 0

    if ($null -ne $failure) {
        $null = $note.Add(("'{0}' did not go through, so the run stopped there and the {1} plan(s) after it were not attempted." -f `
            [string](Get-OptimizerProperty -InputObject $failure -Name 'DisplayName'),
            ($plans.Count - $actionResult.Count)))

        # Newest first, and every action this run recorded -- including the one
        # that failed. An action that failed changed nothing, so its undo finds
        # the value already where the record says it was and writes nothing; an
        # action that partly succeeded is exactly the one that has to be put
        # back. Undo-RemovalAction decides which of those it is, from the ledger.
        $recorded = @($actionResult | Where-Object { -not [string]::IsNullOrWhiteSpace([string](Get-OptimizerProperty -InputObject $_ -Name 'ActionId')) })
        for ($index = $recorded.Count - 1; $index -ge 0; $index--) {
            $undo = Undo-RemovalAction -ActionId ([string] $recorded[$index].ActionId) @executorArgument
            $null = $undoResult.Add($undo)
            if ([string](Get-OptimizerProperty -InputObject $undo -Name 'Result') -eq $script:ExecutionRunRefused) { $undoRefused++ }
        }

        $rolledBack = ($undoResult.Count -gt 0 -and $undoRefused -eq 0)

        if ($undoRefused -gt 0) {
            $null = $note.Add(("{0} of the {1} attempted undo(s) were refused, so this PC is not back where it started. The action log has every record of what was done and what was put back." -f `
                $undoRefused, $undoResult.Count))
        }
        elseif ($undoResult.Count -gt 0) {
            $null = $note.Add(("Everything this run had already done was put back: {0} undo action(s), each one recorded in the action log as a new action rather than as an edit to the old one." -f $undoResult.Count))
        }
    }

    # ---- 6. the receipt for this run ----------------------------------------
    $receipt = Get-OptimizerExecutionReceipt -LedgerPath $resolvedLedger -RunId $runIdValue
    $receiptText = [string[]] @()
    if ($null -ne $receipt) { $receiptText = [string[]] @(Get-OptimizerProperty -InputObject $receipt -Name 'ReceiptText' -Default @()) }

    $overall = $script:ActionResultSucceeded
    $reason  = $null
    if ($null -ne $failure) {
        $overall = $(if ($undoRefused -gt 0) { $script:ActionResultPartial } else { $script:ActionResultFailed })
        $reason  = ("The run stopped at '{0}': {1}" -f `
            [string](Get-OptimizerProperty -InputObject $failure -Name 'DisplayName'),
            [string](Get-OptimizerProperty -InputObject $failure -Name 'Reason'))
    }

    $result = New-OptimizerExecutionResult -Result $overall -RunId $runIdValue -LedgerPath $resolvedLedger `
        -StartedUtc $started -PlanCount $plans.Count -Performed $performed -RolledBack $rolledBack `
        -Reason $reason -ActionResult ([psobject[]] @($actionResult.ToArray())) `
        -UndoResult ([psobject[]] @($undoResult.ToArray())) -Receipt $receipt -ReceiptText $receiptText `
        -Note ([string[]] @($note.ToArray()))

    Write-OptimizerExecutionReport -Run $result -Writer $Writer
    $result
}

#endregion

#region Internal: what it prints

function Write-OptimizerExecutionReport {
    <#
        The run, as lines, through the caller's writer.

        IT PRINTS THE RECEIPT AND DOES NOT RE-RENDER IT.
        Get-OptimizerRunReceipt's ReceiptText is already worded, is already held
        to this project's no-benefit-claim rule, and is what the ledger will
        still say tomorrow. A second renderer here would eventually disagree with
        the record -- the same rule Show-ReviewScreen follows for a plan's
        PreviewText.

        The few lines this function does own say what happened to the RUN, which
        the receipt cannot: a run refused before anything was attempted writes no
        ledger records at all, so its receipt correctly reads "nothing has been
        recorded" and the reason it was refused has to come from here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Run,
        [Parameter(Mandatory)] [ValidateNotNull()] [scriptblock] $Writer
    )

    # Created and invoked in this one scope. A scriptblock is not a closure
    # unless it is made one, so a wrapper built in the calling function and
    # invoked here would resolve $Writer against whatever scope chain it happened
    # to be invoked from -- which works today and is a trap tomorrow.
    $emit = { param($Line) $null = & $Writer ([string] $Line) }

    & $emit ''
    & $emit 'What was done'
    & $emit '============='
    & $emit ''

    $result = [string](Get-OptimizerProperty -InputObject $Run -Name 'Result')
    $reason = [string](Get-OptimizerProperty -InputObject $Run -Name 'Reason' -Default '')

    if ($result -eq $script:ExecutionRunRefused) {
        & $emit 'Nothing on this PC was changed and nothing was written to the action log.'
    }
    elseif ($result -eq $script:ActionResultSucceeded) {
        & $emit ("All {0} of the selected change(s) were carried out." -f (Get-OptimizerProperty -InputObject $Run -Name 'PlanCount' -Default 0))
    }
    elseif ($result -eq $script:ActionResultFailed) {
        & $emit 'The run stopped at a change that did not go through, and everything it had already done was put back. This PC is where it started.'
    }
    elseif ($result -eq $script:ActionResultPartial) {
        & $emit 'The run stopped at a change that did not go through, and putting back what it had already done did not fully work. This PC is NOT where it started -- read the action log below.'
    }
    else {
        & $emit 'Nothing was carried out.'
    }

    if (-not [string]::IsNullOrWhiteSpace($reason)) {
        foreach ($line in @(Split-ReviewText -Text $reason -Width 96 -Indent '  ')) { & $emit $line }
    }

    # ONE BLOCK PER REFUSED ROW, not one paragraph for all of them. Measured on
    # this machine: a twelve-row selection produces twelve refusals whose reasons
    # differ only in the row's name, and joining them into one wrapped paragraph
    # made a thirty-line block in which no individual row could be found. Each
    # reason is the EXECUTOR'S OWN TEXT, unaltered and not deduplicated: they
    # are near-identical because the answer really is the same for each row, and
    # summarising that away would be this file re-wording a refusal it did not
    # write.
    $refusal = @(Get-OptimizerProperty -InputObject $Run -Name 'Refusal' -Default @())
    foreach ($entry in $refusal) {
        & $emit ''
        & $emit ("  {0} ({1})" -f `
            [string](Get-OptimizerProperty -InputObject $entry -Name 'DisplayName'),
            [string](Get-OptimizerProperty -InputObject $entry -Name 'Route'))
        foreach ($line in @(Split-ReviewText -Text (Get-OptimizerProperty -InputObject $entry -Name 'Reason') -Width 96 -Indent '      ')) {
            & $emit $line
        }
    }

    foreach ($entry in @(Get-OptimizerProperty -InputObject $Run -Name 'Note' -Default @())) {
        foreach ($line in @(Split-ReviewText -Text $entry -Width 96 -Indent '  ')) { & $emit $line }
    }

    & $emit ''

    # VERBATIM, indented to sit under the heading. Written by
    # Get-OptimizerRunReceipt and already worded; this file does not touch them.
    foreach ($line in @(Get-OptimizerProperty -InputObject $Run -Name 'ReceiptText' -Default @())) {
        & $emit ('  ' + $line)
    }
}

#endregion
