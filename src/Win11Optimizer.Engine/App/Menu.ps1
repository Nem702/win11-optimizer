<#
    App\Menu.ps1 -- chunk P5-C1, part A: the entry point's menu.

    THE WHOLE FILE IS A SWITCHBOARD. Every choice on it is a call to something
    that already exists and was already tested in the chunk that shipped it: the
    review screen, the ledger's receipt, the executor's undo, the restore point.
    Nothing here scans, plans, removes, writes a ledger line or decides what is
    safe. If a behaviour on this menu looks wrong, the fix is almost never in
    this file.

    WHAT IT DOES OWN, and there are only three things:

      1. THE LIST OF CHOICES, once, as a table -- including which of them need
         administrator rights. Part B (Support\Elevation.ps1) deliberately does
         not know this list, so that "which choices need admin" has exactly one
         home and a new choice cannot be added in one place and forgotten in the
         other.

      2. THE ORDER OF OPERATIONS AROUND ELEVATION. Anything the choice needs from
         the person is collected FIRST, on the window they are looking at, and
         only then is the relaunch offered -- so an action id typed into the old
         window survives into the new one instead of being asked for twice.

      3. NOT CRASHING. A cancelled operation and a failed one both print a line
         and return to the menu. See Invoke-OptimizerMenu's notes on what
         "cancelled" can and cannot catch.

    TALKING TO A PERSON IS A PARAMETER, not a dependency -- the same -Reader /
    -Writer pair Show-ReviewScreen uses, for the same reason: the whole menu can
    then be driven by a test that asserts on the exact transcript.
#>

#region Constants

$script:MenuSessionTypeName   = 'Win11Optimizer.MenuSession'
$script:MenuIterationTypeName = 'Win11Optimizer.MenuIteration'

$script:MenuChoiceScan         = 'Scan and review'
$script:MenuChoiceReceipt      = 'Receipt'
$script:MenuChoiceUndo         = 'Undo'
$script:MenuChoiceRestorePoint = 'Restore point'
$script:MenuChoiceQuit         = 'Quit'

# THE TABLE. Key, name, whether it needs administrator rights, and -- for the
# ones that do -- the words that finish the sentence "This tool requires
# administrator rights to ...". The sentence is assembled from this column rather
# than written out per branch, so a choice cannot end up claiming to need admin
# in its message and not in its gate.
$script:MenuChoice = @(
    [pscustomobject][ordered]@{
        Key = '1'; Name = $script:MenuChoiceScan; RequiresElevation = $true
        ElevationVerb = 'scan this PC and carry out what you confirm'
        Summary = 'look at what is on this PC and choose what to change'
    }
    [pscustomobject][ordered]@{
        Key = '2'; Name = $script:MenuChoiceReceipt; RequiresElevation = $false
        ElevationVerb = $null
        Summary = 'what this tool has already done, from the action ledger'
    }
    [pscustomobject][ordered]@{
        Key = '3'; Name = $script:MenuChoiceUndo; RequiresElevation = $true
        ElevationVerb = 'undo a recorded change'
        Summary = 'put back one change, by action id'
    }
    [pscustomobject][ordered]@{
        Key = '4'; Name = $script:MenuChoiceRestorePoint; RequiresElevation = $true
        ElevationVerb = 'take a restore point'
        Summary = 'ask Windows for a System Restore checkpoint'
    }
    [pscustomobject][ordered]@{
        Key = '5'; Name = $script:MenuChoiceQuit; RequiresElevation = $false
        ElevationVerb = $null
        Summary = 'leave'
    }
)

# What one pass round the loop is recorded as. Named constants rather than bare
# strings so the session object and the tests cannot drift.
$script:MenuOutcomePerformed            = 'Performed'
$script:MenuOutcomeRelaunched           = 'Relaunched'
$script:MenuOutcomeElevationDeclined    = 'ElevationDeclined'
$script:MenuOutcomeElevationUnavailable = 'ElevationUnavailable'
$script:MenuOutcomeCancelled            = 'Cancelled'
$script:MenuOutcomeFailed               = 'Failed'
$script:MenuOutcomeNotUnderstood        = 'NotUnderstood'
$script:MenuOutcomeNothingToDo          = 'NothingToDo'
$script:MenuOutcomeQuit                 = 'Quit'

$script:MenuEndReasonQuit       = 'Quit'
$script:MenuEndReasonEndOfInput = 'EndOfInput'

# How many recorded actions the Undo prompt lists. Enough to cover a session's
# worth of changes without turning the prompt into a report.
$script:MenuUndoListCount = 10

#endregion

#region Internal: reading a choice

function Get-OptimizerMenuChoice {
    <#
        Returns the choice table, or the one entry matching what was typed.

        The input language is the smallest one that works: the key ('3'), or the
        name ('Undo'), case-insensitively, with surrounding space ignored. No
        abbreviations and no prefix matching -- 'R' would be ambiguous between
        Receipt and Restore point, and a menu that guesses which of those a
        person meant is a menu that eventually takes a restore point when they
        wanted to read one.

        $null when nothing matches. The caller says so and asks again.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Position = 0)] [AllowNull()] [AllowEmptyString()] [string] $InputText
    )

    if (-not $PSBoundParameters.ContainsKey('InputText')) {
        return [psobject[]] @($script:MenuChoice)
    }

    $text = ([string] $InputText).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    foreach ($choice in $script:MenuChoice) {
        if ($text -eq $choice.Key) { return $choice }
        if ($text -eq $choice.Name) { return $choice }
    }

    $null
}

function Get-OptimizerMenuText {
    <#
        The menu itself, as lines. Decides nothing and prints nothing -- the
        caller writes them -- so what the menu says can be asserted on directly.

        It states the elevation position up front. A person who is about to be
        sent through a UAC prompt by choice 1 should be able to see that before
        they pick it, not after.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [bool] $IsElevated
    )

    $line = New-Object System.Collections.Generic.List[string]

    $null = $line.Add('')
    $null = $line.Add('win11-optimizer')
    $null = $line.Add('===============')
    $null = $line.Add('')
    $null = $line.Add($(if ($IsElevated) {
        'Running as administrator. Every choice below can be carried out in this window.'
    } else {
        'Running as a standard user. The starred choices will ask to relaunch as administrator, which opens a new window.'
    }))
    $null = $line.Add('')

    foreach ($choice in $script:MenuChoice) {
        $star = $(if ($choice.RequiresElevation -and -not $IsElevated) { '*' } else { ' ' })
        $null = $line.Add(('  {0}{1}  {2,-16}  {3}' -f $star, $choice.Key, $choice.Name, $choice.Summary))
    }

    $null = $line.Add('')

    [string[]] @($line.ToArray())
}

#endregion

#region Internal: the session record

function New-OptimizerMenuIteration {
    # One pass round the loop. Every field on every one of them, whatever
    # happened: the module runs under Set-StrictMode -Version Latest and a record
    # that omits a field turns a consumer's branch into a throw.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [int] $Number,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Answer,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ChoiceName,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Outcome,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [string[]] $Argument = @(),
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Detail,
        [Parameter()] [AllowNull()] $Result = $null
    )

    # Held untyped and only ever assigned a string: $x = $null on a
    # [string]-constrained variable becomes '', and '' reads as "there was a
    # detail and it was blank" rather than as "there was none". docs\REVIEW.md.
    $choiceValue = $null
    if (-not [string]::IsNullOrWhiteSpace($ChoiceName)) { $choiceValue = $ChoiceName }
    $detailValue = $null
    if (-not [string]::IsNullOrWhiteSpace($Detail)) { $detailValue = $Detail }

    [pscustomobject][ordered]@{
        PSTypeName = $script:MenuIterationTypeName
        Number     = $Number
        Answer     = $Answer
        ChoiceName = $choiceValue
        Argument   = [string[]] @($Argument)
        Outcome    = $Outcome
        Detail     = $detailValue
        Result     = $Result
    }
}

function New-OptimizerMenuSession {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [datetime] $StartedUtc,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $EndReason,
        [Parameter(Mandatory)] [bool] $IsElevated,
        [Parameter(Mandatory)] [bool] $CanRelaunch,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $Iteration = @()
    )

    $iterations = [psobject[]] @($Iteration)

    [pscustomobject][ordered]@{
        PSTypeName      = $script:MenuSessionTypeName
        StartedUtc      = $StartedUtc.ToUniversalTime().ToString('o')
        CompletedUtc    = [datetime]::UtcNow.ToString('o')
        DurationSeconds = [math]::Round(([datetime]::UtcNow - $StartedUtc).TotalSeconds, 3)
        IsElevated      = $IsElevated
        CanRelaunch     = $CanRelaunch
        EndReason       = $EndReason
        IterationCount  = $iterations.Count
        Iteration       = $iterations
    }
}

#endregion

#region Internal: what each choice does

function Invoke-OptimizerMenuScan {
    <#
        Choice 1, end to end: the review screen collects a decision, and if the
        answer was yes the picks are turned into plans and performed.

        -Confirm:$false ON THE EXECUTION, and this is the one place in the
        project that passes it for a real run. Invoke-OptimizerExecutionPlan is
        ConfirmImpact High, so without it PowerShell raises its own confirmation
        prompt -- a SECOND yes/no, asked through the host rather than through
        -Reader, immediately after the screen asked the same question with the
        plan text still on screen. The screen's question is the confirmation;
        re-asking it in a worse place is how people learn to answer without
        reading.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [scriptblock] $Reader,
        [Parameter(Mandatory)] [scriptblock] $Writer
    )

    $selection = Show-ReviewScreen -Reader $Reader -Writer $Writer

    if (-not [bool](Get-OptimizerProperty -InputObject $selection -Name 'Confirmed' -Default $false)) {
        return [pscustomobject][ordered]@{
            Outcome   = $script:MenuOutcomeNothingToDo
            Detail    = 'Nothing was confirmed, so nothing was carried out.'
            Selection = $selection
            Run       = $null
        }
    }

    $findings = [psobject[]] @(Get-OptimizerProperty -InputObject $selection -Name 'Finding' -Default @())
    $picks = [string[]] @($findings | ForEach-Object { [string](Get-OptimizerProperty -InputObject $_ -Name 'Id') })

    # Planned again here rather than reusing the screen's plans. Get-RemovalPlan
    # re-probes, so this is the state of the machine at the moment of execution
    # rather than at the moment of rendering, and the executor's own gates get a
    # plan that has not been sitting in a variable while somebody read it.
    $plans = [psobject[]] @(New-OptimizerExecutionPlan -Finding $findings -Pick $picks)

    $run = Invoke-OptimizerExecutionPlan -Plan $plans -Writer $Writer -Confirm:$false

    [pscustomobject][ordered]@{
        Outcome   = $script:MenuOutcomePerformed
        Detail    = [string](Get-OptimizerProperty -InputObject $run -Name 'Result')
        Selection = $selection
        Run       = $run
    }
}

function Invoke-OptimizerMenuReceipt {
    <#
        Choice 2: the whole ledger, in the words the ledger already gives it.

        PRINTED, NOT RE-RENDERED -- the same rule the review screen follows for
        plan previews. A second renderer here would eventually disagree with the
        record.

        Unfiltered, on purpose: P4-C2's receipt is filtered to one run because
        that is what a run has just finished doing, and this one answers a
        different question -- what has this tool EVER done to this PC.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [scriptblock] $Writer,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $LedgerPath
    )

    $argument = @{}
    if (-not [string]::IsNullOrWhiteSpace($LedgerPath)) { $argument['Path'] = $LedgerPath }

    $receipt = Get-OptimizerRunReceipt @argument

    foreach ($line in @(Get-OptimizerProperty -InputObject $receipt -Name 'ReceiptText' -Default @())) {
        $null = & $Writer ([string] $line)
    }

    [pscustomobject][ordered]@{
        Outcome = $script:MenuOutcomePerformed
        Detail  = 'The action ledger was read.'
        Receipt = $receipt
    }
}

function Get-OptimizerMenuUndoTarget {
    <#
        Asks which recorded action to undo, and answers with an action id or
        $null. READS ONLY -- it lists the ledger and takes an answer; undoing is
        the executor's job and happens after this returns.

        This runs BEFORE the elevation gate, and that ordering is the point: the
        id is collected on the window the person is looking at, so a relaunch can
        carry it into the new one rather than asking for it again there.

        The listing is the nice-to-have from the prompt. What it does NOT claim
        is which actions have already been undone: an undo is recorded as a new
        action carrying UndoOfActionId, and Get-OptimizerActionLog's aggregate
        view does not surface that field, so this list would have to re-derive it
        from raw records to say so. It does not, and it does not need to --
        Undo-RemovalAction refuses to overwrite a value something else has
        already changed, which is the check that actually matters.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [scriptblock] $Reader,
        [Parameter(Mandatory)] [scriptblock] $Writer,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $LedgerPath
    )

    $write = { param($Line) $null = & $Writer ([string] $Line) }

    $argument = @{}
    if (-not [string]::IsNullOrWhiteSpace($LedgerPath)) { $argument['Path'] = $LedgerPath }

    $recorded = @()
    try {
        $recorded = @(@(Get-OptimizerActionLog @argument) | Where-Object {
            -not [bool](Get-OptimizerProperty -InputObject $_ -Name 'IsParseError' -Default $false)
        })
    }
    catch [System.OperationCanceledException] {
        # RETHROWN, not folded into the message below. A cancellation is the
        # person saying stop, and turning it into "the ledger could not be read,
        # you can still type an id" would answer a question they did not ask and
        # leave them at a prompt they wanted out of. The menu's own handler says
        # "cancelled" and comes back.
        throw
    }
    catch {
        # A ledger that cannot be READ is different from one that is not there,
        # and is said rather than swallowed: it means this tool may have changed
        # things it can no longer show you.
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        & $write "  The action ledger could not be read: $($inner.Message)"
        & $write '  You can still undo by typing an action id.'
    }

    # Newest last, which is the order the ledger is written in and the order a
    # person reads a list of things that happened.
    $recent = @($recorded | Select-Object -Last $script:MenuUndoListCount)

    if ($recent.Count -lt 1) {
        & $write ''
        & $write '  Nothing is recorded in the action ledger yet, so there is nothing to undo.'
        return $null
    }

    & $write ''
    & $write "  The $(if ($recent.Count -eq 1) { 'one recorded action' } else { "$($recent.Count) most recent recorded actions" }):"
    & $write ''

    for ($index = 0; $index -lt $recent.Count; $index++) {
        $action = $recent[$index]
        & $write ('    {0,2}  {1}  {2}' -f ($index + 1),
            [string](Get-OptimizerProperty -InputObject $action -Name 'ActionId' -Default '(no id)'),
            [string](Get-OptimizerProperty -InputObject $action -Name 'DisplayName' -Default '(unnamed)'))
        & $write ('        {0} / {1} / {2}' -f
            [string](Get-OptimizerProperty -InputObject $action -Name 'Route' -Default '(no route)'),
            [string](Get-OptimizerProperty -InputObject $action -Name 'Result' -Default 'OutcomeUnknown'),
            $(if ([bool](Get-OptimizerProperty -InputObject $action -Name 'IsReversible' -Default $false)) { 'reversible' } else { 'NOT recorded as reversible' }))
    }

    & $write ''

    $typed = ([string](& $Reader "Which one? Type a number from the list or a full action id, or press Enter to go back")).Trim()

    if ([string]::IsNullOrWhiteSpace($typed)) {
        & $write '  Nothing chosen.'
        return $null
    }

    # A bare number is an index into the list that was just printed. Anything
    # else is taken as an action id verbatim -- ids are GUIDs, so the two cannot
    # be confused for one another.
    if ($typed -match '^\d+$') {
        $number = [int] $typed
        if ($number -lt 1 -or $number -gt $recent.Count) {
            & $write "  '$typed' is not a row on that list. There $(if ($recent.Count -eq 1) { 'is 1 row' } else { "are $($recent.Count) rows" })."
            return $null
        }
        return [string](Get-OptimizerProperty -InputObject $recent[$number - 1] -Name 'ActionId')
    }

    $typed
}

function Invoke-OptimizerMenuUndo {
    <#
        Choice 3: hand one action id to the executor's undo and print what came
        back. The refusing is all done in Undo-RemovalAction, which is where it
        belongs -- this prints the answer.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [scriptblock] $Writer,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $ActionId,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $LedgerPath
    )

    $write = { param($Line) $null = & $Writer ([string] $Line) }

    $argument = @{ ActionId = $ActionId; Confirm = $false }
    if (-not [string]::IsNullOrWhiteSpace($LedgerPath)) { $argument['LedgerPath'] = $LedgerPath }

    $result = Undo-RemovalAction @argument

    $outcome = [string](Get-OptimizerProperty -InputObject $result -Name 'Result' -Default 'OutcomeUnknown')
    $reason  = [string](Get-OptimizerProperty -InputObject $result -Name 'ErrorText' -Default '')

    & $write ''
    & $write "  Undo of $ActionId : $outcome"
    if (-not [string]::IsNullOrWhiteSpace($reason)) { & $write "  $reason" }
    & $write ''

    [pscustomobject][ordered]@{
        Outcome = $script:MenuOutcomePerformed
        Detail  = $outcome
        Undo    = $result
    }
}

function Invoke-OptimizerMenuRestorePoint {
    <#
        Choice 4: ask Windows for a checkpoint and say what Windows said.

        Tri-state on purpose, and the wording keeps it that way. Throttled is not
        a failure -- Windows declining because one already exists inside the
        frequency window means there IS a recent restore point, which is the
        thing the person wanted.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [scriptblock] $Writer
    )

    $write = { param($Line) $null = & $Writer ([string] $Line) }

    & $write ''
    & $write '  Asking Windows for a System Restore checkpoint...'

    $checkpoint = New-OptimizerRestorePoint

    $state  = [string](Get-OptimizerProperty -InputObject $checkpoint -Name 'State' -Default 'Failed')
    $reason = [string](Get-OptimizerProperty -InputObject $checkpoint -Name 'Reason' -Default '')

    & $write "  $state"
    if (-not [string]::IsNullOrWhiteSpace($reason)) { & $write "  $reason" }
    & $write ''

    [pscustomobject][ordered]@{
        Outcome    = $script:MenuOutcomePerformed
        Detail     = $state
        Checkpoint = $checkpoint
    }
}

#endregion

#region Public

function Invoke-OptimizerMenu {
    <#
    .SYNOPSIS
        The tool's menu. Loops until Quit, dispatching each choice to the export
        that already does it, and hands back a record of the session.

    .DESCRIPTION
        Five choices -- Scan and review, Receipt, Undo, Restore point, Quit --
        and nothing else. Every one of them is a call to an existing export; this
        function adds the loop, the elevation gate and the not-crashing.

        THE ORDER OF OPERATIONS, per pass:

          1. Print the menu and read a choice. An answer that matches nothing is
             said so and asked again; it does not end the session.
          2. Collect whatever that choice needs from the person -- for Undo, the
             action id, which means listing the ledger. This happens BEFORE the
             elevation gate so the answer survives a relaunch.
          3. If the choice needs administrator rights and this process has none,
             print why, relaunch elevated, and come back to the menu whatever
             happened. The relaunched process runs its own session in its own
             window; this one does not wait on its outcome beyond "did it exit
             cleanly".
          4. Otherwise, do it.

        WHAT "CANCELLED" CATCHES, AND WHAT IT CANNOT. This is worth stating
        exactly, because the obvious reading of "trap Ctrl+C" is not achievable
        and a comment claiming it would be a promise this code cannot keep.

        CAUGHT: an OperationCanceledException raised by anything a choice calls.
        It is printed as one line and the menu comes back. Tested.

        NOT CAUGHT, AND NOT CATCHABLE:

          * PipelineStoppedException. MEASURED on 5.1 and 7.6.5, both the same,
            and the detail is worth having exactly right:

                catch      does NOT run -- neither a typed one nor a bare one
                finally    DOES run
                after it   does NOT run; execution stops at the try statement

            The engine reads it as its own stop signal. So a catch clause for it
            here would be dead code that reads as a guarantee, and there is not
            one; a finally would genuinely run, and nothing in this file needs
            one.

            AND THE EXIT CODE IS NOT A SIGNAL EITHER: measured at 1 when the host
            was started with -Command and 0 when it was started with -File. So an
            elevated relaunch stopped this way exits 0, and
            Invoke-OptimizerElevated reports it as a clean exit. That is a real
            limit of this design and is written down rather than papered over --
            the ledger below is what actually answers "what happened".
          * A console Ctrl+C at a Read-Host prompt. That is handled by the HOST,
            before this process's exception machinery sees anything. NOT measured
            here -- unlike the line above, this one is the well-known behaviour
            rather than something taken on this machine, and it is written as the
            weaker claim on purpose.

        SO WHAT ACTUALLY MAKES A HARD STOP SAFE is not a trap in this file: it is
        the ledger. The executor flushes its Intent record before it attempts
        anything and throws if that write fails, so a process killed mid-change
        reads back afterwards as OutcomeUnknown rather than as nothing having
        happened -- and choice 2 is how a person sees that. That is P3-C2's
        design, and it is the reason this menu does not need to survive Ctrl+C in
        order for Ctrl+C to be survivable.

        A CHOICE THAT THROWS DOES NOT END THE SESSION EITHER. It is printed --
        loudly, with the exception type -- recorded on the session object as
        Failed, and the menu comes back. A menu that dies on the first error
        leaves a person with no way to reach the receipt that would tell them
        what state their machine is in.

        RELAUNCHING IS BOUNDED AT ONE LEVEL DEEP. A session started at a named
        choice (-InitialChoice) never relaunches, for the whole session. That is
        precisely the shape of a session that IS the child of a relaunch, so the
        chain can never be longer than parent-and-child however Test-IsElevated
        answers. The cost is that a scripted run started at a choice will report
        that it needs administrator rights instead of asking for them; the thing
        it buys is that no bug in the elevation check can turn into an unbounded
        cascade of UAC prompts.

    .PARAMETER Reader
        Scriptblock taking one prompt string and returning what was typed.

        Returning $null ends the session with EndReason 'EndOfInput', which is a
        different ending from Quit and is recorded as itself. Two things produce
        it, and both want the same handling:

          * a test's reader running out of queued answers, so driving the loop
            needs no sentinel choice to escape it;
          * MEASURED, on 5.1 and 7.6.5 alike: Read-Host returns $null -- not the
            empty string -- when standard input is at end of file. So a launcher
            started with redirected or closed input exits after one menu instead
            of spinning forever on an answer it cannot understand.

        An empty string is different, and is Enter: not one of the choices, said
        so, asked again.

    .PARAMETER Writer
        Scriptblock taking one line to display.

    .PARAMETER InitialChoice
        Start on this choice instead of prompting for the first one. This is what
        an elevated relaunch is handed. Also disables relaunching -- see above.

    .PARAMETER InitialArgument
        What the initial choice needs: the action id, for Undo.

    .PARAMETER LedgerPath
        Read the receipt and the undo list from this action ledger, and undo
        against it, instead of the default one.

    .EXAMPLE
        Invoke-OptimizerMenu

    .EXAMPLE
        (Invoke-OptimizerMenu -InitialChoice 'Receipt').EndReason
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()] [ValidateNotNull()] [scriptblock] $Reader = { param($Prompt) Read-Host -Prompt $Prompt },
        [Parameter()] [ValidateNotNull()] [scriptblock] $Writer = { param($Line) Write-Host $Line },
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $InitialChoice,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $InitialArgument = @(),
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $LedgerPath
    )

    $started = [datetime]::UtcNow
    $write = { param($Line) $null = & $Writer ([string] $Line) }

    $startedAtChoice = -not [string]::IsNullOrWhiteSpace($InitialChoice)
    $canRelaunch = -not $startedAtChoice

    $iteration = New-Object System.Collections.Generic.List[psobject]
    $number = 0
    $pending = $(if ($startedAtChoice) { [string] $InitialChoice } else { $null })
    # Blanks dropped on the way in. A relaunch never sends one -- the command-line
    # builder drops them too -- but -InitialArgument is a public parameter, and an
    # array holding one empty string would otherwise count as "the argument was
    # supplied" and reach a choice as an empty action id.
    $pendingArgument = [string[]] @(@($InitialArgument) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $endReason = $script:MenuEndReasonQuit

    while ($true) {
        $number++
        $isElevated = Test-IsElevated

        # ---- 1. what did they pick ------------------------------------------
        $answer = $null
        if ($null -ne $pending) {
            $answer = $pending
            $pending = $null
        }
        else {
            foreach ($line in (Get-OptimizerMenuText -IsElevated $isElevated)) { & $write $line }
            $answer = & $Reader 'Choose'
            if ($null -eq $answer) {
                # The reader has nothing left. Not an error and not a Quit: a
                # different way for the session to be over, said as itself.
                $endReason = $script:MenuEndReasonEndOfInput
                break
            }
            $answer = [string] $answer
        }

        $choice = Get-OptimizerMenuChoice -InputText $answer

        if ($null -eq $choice) {
            & $write ''
            & $write "  '$(([string] $answer).Trim())' is not one of the choices. Type a number from 1 to $($script:MenuChoice.Count), or the name next to it."
            $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                -Outcome $script:MenuOutcomeNotUnderstood -Detail 'Not one of the choices.'))
            continue
        }

        if ($choice.Name -eq $script:MenuChoiceQuit) {
            & $write ''
            & $write 'Goodbye.'
            $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                -ChoiceName $choice.Name -Outcome $script:MenuOutcomeQuit))
            $endReason = $script:MenuEndReasonQuit
            break
        }

        # ---- 2. anything the choice needs from the person --------------------
        #
        # Collected here, before the elevation gate, so a relaunch carries it.
        $choiceArgument = [string[]] @()
        $abandoned = $false

        try {
            if ($choice.Name -eq $script:MenuChoiceUndo) {
                if ($pendingArgument.Count -gt 0) {
                    # Handed in by the relaunch. Not asked for a second time.
                    $choiceArgument = [string[]] @($pendingArgument)
                }
                else {
                    $actionId = Get-OptimizerMenuUndoTarget -Reader $Reader -Writer $Writer -LedgerPath $LedgerPath
                    if ([string]::IsNullOrWhiteSpace($actionId)) { $abandoned = $true }
                    else { $choiceArgument = [string[]] @($actionId) }
                }
            }
        }
        catch [System.OperationCanceledException] {
            & $write ''
            & $write "  Cancelled. '$($choice.Name)' was not started, and nothing on this PC has been changed."
            $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                -ChoiceName $choice.Name -Outcome $script:MenuOutcomeCancelled -Detail 'Cancelled while collecting what the choice needs.'))
            $pendingArgument = [string[]] @()
            continue
        }

        # Consumed. A relaunch-supplied argument belongs to the choice it arrived
        # with, and must not leak into the next pass round the loop.
        $pendingArgument = [string[]] @()

        if ($abandoned) {
            $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                -ChoiceName $choice.Name -Outcome $script:MenuOutcomeNothingToDo -Detail 'Nothing was chosen.'))
            continue
        }

        # ---- 3. the elevation gate -------------------------------------------
        #
        # INFERRED FROM THE CHOICE, not discovered by trying. Attempting the work
        # to find out whether it needs admin means half-doing it first, and the
        # half that already ran is the half nobody planned for.
        if ($choice.RequiresElevation -and -not $isElevated) {
            if (-not $canRelaunch) {
                & $write ''
                & $write "  This tool requires administrator rights to $($choice.ElevationVerb), and this window does not have them."
                & $write '  This session was started at a named choice, so it will not open another window. Start the tool again as administrator.'
                $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                    -ChoiceName $choice.Name -Argument $choiceArgument -Outcome $script:MenuOutcomeElevationUnavailable `
                    -Detail 'Relaunching is disabled for a session that was started at a choice.'))
                continue
            }

            # ON THE OLD WINDOW, BEFORE THE NEW ONE EXISTS. This is the only
            # explanation a person gets for why the thing they were reading is
            # about to be replaced by a UAC prompt and a fresh console.
            & $write ''
            & $write "  This tool requires administrator rights to $($choice.ElevationVerb)."
            & $write '  Relaunching elevated...'
            & $write '  A new window will open. This one stays as it is -- Windows cannot raise the rights of a window that is already open.'

            $relaunched = Invoke-OptimizerElevated -Choice $choice.Name -Argument $choiceArgument

            if ($relaunched) {
                & $write ''
                & $write '  The elevated window has finished.'
                $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                    -ChoiceName $choice.Name -Argument $choiceArgument -Outcome $script:MenuOutcomeRelaunched `
                    -Detail 'The elevated process ran and exited cleanly.'))
            }
            else {
                & $write ''
                & $write '  Elevation was denied or the process crashed.'
                $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                    -ChoiceName $choice.Name -Argument $choiceArgument -Outcome $script:MenuOutcomeElevationDeclined `
                    -Detail 'The elevated process did not run to a clean exit.'))
            }
            continue
        }

        # ---- 4. do it ---------------------------------------------------------
        try {
            $performed = $null
            switch ($choice.Name) {
                $script:MenuChoiceScan {
                    $performed = Invoke-OptimizerMenuScan -Reader $Reader -Writer $Writer
                }
                $script:MenuChoiceReceipt {
                    $performed = Invoke-OptimizerMenuReceipt -Writer $Writer -LedgerPath $LedgerPath
                }
                $script:MenuChoiceUndo {
                    $performed = Invoke-OptimizerMenuUndo -Writer $Writer -ActionId $choiceArgument[0] -LedgerPath $LedgerPath
                }
                $script:MenuChoiceRestorePoint {
                    $performed = Invoke-OptimizerMenuRestorePoint -Writer $Writer
                }
                default {
                    throw "Invoke-OptimizerMenu: '$($choice.Name)' is on the choice table and has no branch here. That is a bug in this file, not in anything it calls."
                }
            }

            $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                -ChoiceName $choice.Name -Argument $choiceArgument `
                -Outcome ([string](Get-OptimizerProperty -InputObject $performed -Name 'Outcome' -Default $script:MenuOutcomePerformed)) `
                -Detail ([string](Get-OptimizerProperty -InputObject $performed -Name 'Detail')) `
                -Result $performed))
        }
        catch [System.OperationCanceledException] {
            & $write ''
            & $write "  Cancelled. '$($choice.Name)' did not finish."
            $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                -ChoiceName $choice.Name -Argument $choiceArgument -Outcome $script:MenuOutcomeCancelled `
                -Detail 'Cancelled while the choice was running.'))
        }
        catch {
            # LOUD, and then back to the menu. The exception type is named
            # because "something went wrong" is not a bug report, and the receipt
            # on choice 2 is how a person finds out what state they are in --
            # which they cannot reach if this function exits here.
            $inner = Get-OptimizerInnerException -Exception $_.Exception
            & $write ''
            & $write "  '$($choice.Name)' stopped with an error and the menu is still here."
            & $write "  $($inner.GetType().Name): $($inner.Message)"
            & $write '  Choose Receipt to see what, if anything, was recorded.'
            $null = $iteration.Add((New-OptimizerMenuIteration -Number $number -Answer $answer `
                -ChoiceName $choice.Name -Argument $choiceArgument -Outcome $script:MenuOutcomeFailed `
                -Detail "$($inner.GetType().Name): $($inner.Message)"))
        }
    }

    New-OptimizerMenuSession -StartedUtc $started -EndReason $endReason `
        -IsElevated (Test-IsElevated) -CanRelaunch $canRelaunch `
        -Iteration ([psobject[]] @($iteration.ToArray()))
}

#endregion
