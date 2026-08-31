<#
    The executor -- chunk P3-C3.

    THE FIRST CODE IN THIS PROJECT THAT CHANGES THE MACHINE ON PURPOSE, and it
    changes exactly one kind of thing: the Start value (and, on the way back, the
    DelayedAutostart value) of one Windows service key under
    HKLM\SYSTEM\CurrentControlSet\Services.

    Scope, and the argument for it (docs\handoff\11-executor.md): 12 of the 13
    real findings on the development machine are on routes with NO UNDO. The one
    route the dispatcher marks IsReversible is ServiceStartupType, it is the only
    one whose RollbackData is provably sufficient to reverse the action, and it
    is the only one where a mistake costs one service's startup type rather than
    a package that cannot be reinstalled or 27 GiB of deleted files. So this
    build performs that route and REFUSES every other one -- not behind a switch,
    not behind a flag, not in a helper nothing calls.

    Everything else still plans exactly as it does today. Get-RemovalPlan is
    unchanged; this file is a consumer of it.

    WHAT THIS FILE MAY WRITE, and the whole list:

      * the value 'Start' under HKLM:\SYSTEM\CurrentControlSet\Services\<name>
      * the value 'DelayedAutostart' under the same key, on the undo path only
        and only where the ledger's record says it was switched on

    Both go through ONE function, Write-ExecutorServiceRegistryValue, whose -Name
    parameter carries a ValidateSet of exactly those two strings, and whose key
    path is checked against a pattern that admits nothing but a single service
    key. It writes through Microsoft.Win32.Registry. Not Set-Service, which does
    not report AutomaticDelayedStart the same way under Windows PowerShell 5.1
    and PowerShell 7 and which reaches the SCM rather than the value the rollback
    record restores; and never the service control program, which this project
    does not run for any purpose. It never stops a service, never starts one,
    never deletes one and never creates one.

    THE ORDER IS THE SAFETY PROPERTY. The Intent record is written to the ledger
    and flushed to disk BEFORE the first registry write, and a ledger that will
    not accept the Intent stops the action -- Write-OptimizerAction throws when it
    cannot record, and a caller that cannot record what it is about to do must not
    do it. tests\Executor.Tests.ps1 asserts that ordering out of the AST as well
    as by observing it.

    ASCII only -- Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, and one
    non-ASCII character in a comment walks the test suite's comment-blanking
    offsets off the end of the file (docs\REVIEW.md, after P3-C1a).
#>

#region Constants

$script:ExecutorResultTypeName     = 'Win11Optimizer.RemovalResult'
$script:ExecutorStepResultTypeName = 'Win11Optimizer.RemovalStepResult'

# The ONLY two registry value names this file may ever write. Stated here, and
# enforced by a ValidateSet on the one function that writes -- so the claim is
# checked by PowerShell on every call and not only by a test reading the source.
$script:ExecutorServiceStartValueName   = 'Start'
$script:ExecutorServiceDelayedValueName = 'DelayedAutostart'

# The ONLY shape of registry key this file may ever open for writing: one service
# key, directly under the services root, with nothing after it. A ledger is data
# and can be hand-edited or arrive from another machine, so the key path a
# rollback record carries is checked against this rather than trusted.
$script:ExecutorServiceKeyPattern = '^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+$'

# The restore point is taken ONCE and reused for the rest of the session. Windows
# throttles restore points to one per 24 hours anyway, and creating one measured
# 11.959 s on this hardware (docs\STATE.md Q23) -- paying that per plan in a batch
# of twenty would be twenty times a stall for one checkpoint.
$script:ExecutorRestorePoint = $null

# What an executor result may say. The ledger's own outcome vocabulary, reused
# rather than restated, plus 'Refused' -- which the ledger derives for an action
# it declined to record and which this file uses for a plan it declined to act
# on. There is no sixth value.
$script:ExecutorRefusedResult = 'Refused'

#endregion

#region Internal: the service key

function Get-ExecutorServiceKeyPart {
    <#
        Splits a service key path into the .NET hive and sub-key the writer needs,
        or returns $null for anything that is not a single service key under
        HKLM\SYSTEM\CurrentControlSet\Services.

        $null is a REFUSAL, not an error state: every caller turns it into a
        readable reason naming the path it was given. Nothing here falls back to
        a nearest-match or strips a suffix to make a bad path fit.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $KeyPath
    )

    if ([string]::IsNullOrWhiteSpace($KeyPath)) { return $null }
    if ($KeyPath -notmatch $script:ExecutorServiceKeyPattern) { return $null }

    $subKey = $KeyPath.Substring('HKLM:\'.Length)
    $name   = $KeyPath.Substring($KeyPath.LastIndexOf('\') + 1)
    if ([string]::IsNullOrWhiteSpace($subKey) -or [string]::IsNullOrWhiteSpace($name)) { return $null }

    [pscustomobject][ordered]@{
        Hive        = [Microsoft.Win32.Registry]::LocalMachine
        SubKey      = $subKey
        ServiceName = $name
        KeyPath     = $KeyPath
    }
}

function Get-ExecutorServiceRegistryState {
    <#
        Reads the two values this file cares about, through the same .NET API it
        writes them with, so the read and the write cannot disagree about which
        view of the registry they are looking at.

        Tri-state, like every other probe in this project: Exists is $true /
        $false / $null, and $null is "could not be read" and is never collapsed
        into "not there".

        StartPresent and DelayedPresent are separate from the values themselves
        because a REG_DWORD that is absent and a REG_DWORD that is 0 are different
        facts, and the second half of this file exists because the dispatcher's
        rollback record cannot tell them apart (see Undo-RemovalAction).
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $KeyPath
    )

    $absent = [pscustomobject][ordered]@{
        Exists         = $null
        Start          = $null
        StartPresent   = $false
        Delayed        = $null
        DelayedPresent = $false
        Reason         = "'$KeyPath' is not a service key this tool will read."
    }

    $part = Get-ExecutorServiceKeyPart -KeyPath $KeyPath
    if ($null -eq $part) { return $absent }

    $key = $null
    try {
        $key = $part.Hive.OpenSubKey($part.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::QueryValues)
        if ($null -eq $key) {
            return [pscustomobject][ordered]@{
                Exists = $false; Start = $null; StartPresent = $false
                Delayed = $null; DelayedPresent = $false; Reason = $null
            }
        }

        $names = [string[]] @($key.GetValueNames())
        $startPresent   = $names -contains $script:ExecutorServiceStartValueName
        $delayedPresent = $names -contains $script:ExecutorServiceDelayedValueName

        $start = $null
        if ($startPresent) { try { $start = [int] $key.GetValue($script:ExecutorServiceStartValueName) } catch { $start = $null } }
        $delayed = $null
        if ($delayedPresent) { try { $delayed = [int] $key.GetValue($script:ExecutorServiceDelayedValueName) } catch { $delayed = $null } }

        [pscustomobject][ordered]@{
            Exists         = $true
            Start          = $start
            StartPresent   = $startPresent
            Delayed        = $delayed
            DelayedPresent = $delayedPresent
            Reason         = $null
        }
    }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        [pscustomobject][ordered]@{
            Exists = $null; Start = $null; StartPresent = $false
            Delayed = $null; DelayedPresent = $false
            Reason = "$($inner.GetType().Name): $($inner.Message)"
        }
    }
    finally {
        if ($null -ne $key) { try { $key.Close() } catch { } }
    }
}

function Get-ExecutorServiceRunState {
    <#
        Is the service running right now? 'Running' / 'Stopped' / 'Unknown'.

        Recorded, never acted on. This build does not stop a running service and
        does not start a stopped one -- a startup-type change takes effect at the
        next boot, which is the least disruptive thing that achieves the user's
        goal. Knowing which it was is what makes "we did not stop it" a fact on
        the ledger rather than a claim in a comment.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $ServiceName
    )

    if ([string]::IsNullOrWhiteSpace($ServiceName)) { return 'Unknown' }

    $service = $null
    try { $service = @(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) }
    catch { return 'Unknown' }

    if (@($service).Count -lt 1) { return 'Unknown' }
    $status = [string](Get-OptimizerProperty -InputObject $service[0] -Name 'Status')
    if ([string]::IsNullOrWhiteSpace($status)) { return 'Unknown' }
    if ($status -eq 'Running') { return 'Running' }
    if ($status -eq 'Stopped') { return 'Stopped' }
    'Unknown'
}

#endregion

#region Internal: THE ONE WRITE

function Write-ExecutorServiceRegistryValue {
    <#
        THE ONLY FUNCTION IN THIS PROJECT THAT CHANGES A REGISTRY VALUE.

        One value, on one service key, as a REG_DWORD. The -Name parameter's
        ValidateSet is the enforcement of the two-value claim made at the top of
        this file: it is checked by PowerShell on every call, so a future edit
        that tried to write a third value name would fail at run time and not
        merely fail a source scan.

        The key path is checked against the single-service-key pattern before
        anything is opened, so a rollback record that arrived from a hand-edited
        ledger cannot aim this at an arbitrary part of the registry.

        CONFIRMED BY LOOKING, not by the call returning. The value is read back
        through a fresh handle after the write and the result carries what was
        actually found; a write that returned cleanly and produced a different
        value is IsVerified = $false, which the caller reports as a failed step.
        Same rule as the restore point, which reports Throttled rather than
        Created when Windows accepts a checkpoint request and makes nothing.

        Returns the record that goes on the ledger's StepResult. Throws only if
        the key cannot be opened for writing or the write itself errors -- both of
        which the caller catches and turns into a failed step with the reason.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $KeyPath,

        # The two-value claim, enforced by the shell rather than by a comment.
        [Parameter(Mandatory)]
        [ValidateSet('Start', 'DelayedAutostart')]
        [string] $Name,

        [Parameter(Mandatory)] [int] $Value
    )

    $part = Get-ExecutorServiceKeyPart -KeyPath $KeyPath
    if ($null -eq $part) {
        throw "Refusing to write to '$KeyPath': this tool only ever writes to a single service key directly under HKLM:\SYSTEM\CurrentControlSet\Services, and that path is not one."
    }

    $previous        = $null
    $previousPresent = $false

    $key = $null
    try {
        $key = $part.Hive.OpenSubKey(
            $part.SubKey,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]([int][System.Security.AccessControl.RegistryRights]::SetValue -bor [int][System.Security.AccessControl.RegistryRights]::QueryValues))

        if ($null -eq $key) {
            throw "The service key '$KeyPath' is not there, so there is nothing to write to."
        }

        if ([string[]] @($key.GetValueNames()) -contains $Name) {
            $previousPresent = $true
            try { $previous = [int] $key.GetValue($Name) } catch { $previous = $null }
        }

        $key.SetValue($Name, [int] $Value, [Microsoft.Win32.RegistryValueKind]::DWord)
    }
    finally {
        if ($null -ne $key) { try { $key.Close() } catch { } }
    }

    # A fresh handle, deliberately: reading back through the handle that wrote is
    # a weaker check than reading the key again from the top.
    $after    = Get-ExecutorServiceRegistryState -KeyPath $KeyPath
    $verified = $null
    if ($Name -eq $script:ExecutorServiceStartValueName)   { $verified = $after.Start }
    if ($Name -eq $script:ExecutorServiceDelayedValueName) { $verified = $after.Delayed }

    [pscustomobject][ordered]@{
        KeyPath              = $KeyPath
        ValueName            = $Name
        PreviousValue        = $previous
        PreviousValuePresent = $previousPresent
        WrittenValue         = [int] $Value
        VerifiedValue        = $verified
        IsVerified           = ($null -ne $verified -and [int] $verified -eq [int] $Value)
        WrittenUtc           = [datetime]::UtcNow.ToString('o')
    }
}

#endregion

#region Internal: shapes

function New-ExecutorStepResult {
    # One per plan step, in plan order. EVERY field on every one of them: the
    # module runs under Set-StrictMode -Version Latest and so does everything that
    # reads a ledger back, and a step result that omits a field turns a consumer's
    # branch into a throw instead of a $null.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [int] $StepIndex,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Kind,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Target,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Result,
        [Parameter()] [AllowNull()] $Write = $null,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ErrorText,
        [Parameter()] [AllowNull()] $DurationSeconds = $null
    )

    $errorValue = $null
    if (-not [string]::IsNullOrWhiteSpace($ErrorText)) { $errorValue = $ErrorText }

    [pscustomobject][ordered]@{
        PSTypeName      = $script:ExecutorStepResultTypeName
        StepIndex       = $StepIndex
        Kind            = $Kind
        Target          = $Target
        Result          = $Result
        DurationSeconds = $DurationSeconds
        ErrorText       = $errorValue
        # A [pscustomobject], never a hashtable: PSObject.Properties on a
        # dictionary exposes Count/Keys/Values and not the entries, so every
        # Get-OptimizerProperty consumer would read nothing and nothing would be
        # raised anywhere. docs\REVIEW.md, after P3-C1.
        Detail          = [pscustomobject][ordered]@{
            Write = [psobject[]] @($Write | Where-Object { $null -ne $_ })
        }
    }
}

function New-ExecutorResult {
    # What Invoke-RemovalPlan and Undo-RemovalAction hand back. ONE INPUT, ONE
    # RESULT, ALWAYS -- the mirror of Get-RemovalPlan's contract, so a batch of
    # twenty plans never loses nineteen because the first one was refused.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Result,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ActionId,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $UndoOfActionId,
        [Parameter()] [AllowNull()] $Plan = $null,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $FindingId,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $DisplayName,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Category,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Route,
        [Parameter()] [bool] $Performed = $false,
        [Parameter()] [bool] $IsWhatIf = $false,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Reason,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $StepResult = @(),
        [Parameter()] [AllowNull()] $RestorePoint = $null,
        [Parameter()] [AllowNull()] $DurationSeconds = $null,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $LedgerPath,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [string[]] $Note = @()
    )

    # Held untyped and only ever assigned a string: $x = $null on a
    # [string]-constrained variable becomes '', and '' reads as "there was a
    # reason and it was blank" rather than as "there was none". docs\REVIEW.md.
    $reasonValue = $null
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $reasonValue = $Reason }
    $actionIdValue = $null
    if (-not [string]::IsNullOrWhiteSpace($ActionId)) { $actionIdValue = $ActionId }
    $undoOfValue = $null
    if (-not [string]::IsNullOrWhiteSpace($UndoOfActionId)) { $undoOfValue = $UndoOfActionId }

    [pscustomobject][ordered]@{
        PSTypeName      = $script:ExecutorResultTypeName
        Result          = $Result
        Performed       = $Performed
        IsWhatIf        = $IsWhatIf
        ActionId        = $actionIdValue
        UndoOfActionId  = $undoOfValue
        FindingId       = $FindingId
        DisplayName     = $DisplayName
        Category        = $Category
        Route           = $Route
        Reason          = $reasonValue
        StepResult      = [psobject[]] @($StepResult)
        RestorePoint    = $RestorePoint
        DurationSeconds = $DurationSeconds
        LedgerPath      = $LedgerPath
        Note            = [string[]] @($Note)
        Plan            = $Plan
        CompletedUtc    = [datetime]::UtcNow.ToString('o')
    }
}

function Get-ExecutorPlanIdentity {
    # The identity fields off a plan, defensively -- a refusal has to be able to
    # name the row it refused even when the object it was handed is barely a plan.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Plan
    )

    [pscustomobject]@{
        FindingId   = [string](Get-OptimizerProperty -InputObject $Plan -Name 'FindingId' -Default '')
        DisplayName = [string](Get-OptimizerProperty -InputObject $Plan -Name 'DisplayName' -Default '(unnamed)')
        Category    = [string](Get-OptimizerProperty -InputObject $Plan -Name 'Category' -Default '')
        Route       = [string](Get-OptimizerProperty -InputObject $Plan -Name 'Route' -Default '')
    }
}

#endregion

#region Internal: re-verification

function Get-ExecutorPlanDisagreement {
    <#
        RE-VERIFY, DON'T TRUST THE PLAN.

        A plan is data. It may have been built minutes ago, in another process,
        at another elevation level, and the machine may have moved since. So the
        plan is rebuilt HERE, in the process that is about to do the work, by
        running the dispatcher again on a Finding reconstructed from the plan's
        own identity fields -- and the two are compared.

        Rebuilding rather than re-probing by hand is the point: it re-runs the
        whole route, including the security-exclusion gate that refuses to touch
        antivirus, the key-permission probe, and the Start value read. Restating
        any of those here would be a second copy that could drift from the one
        the user was shown a preview of.

        The measured reason this is not optional (docs\STATE.md Q24): a plan built
        un-elevated UNDER-REPORTS RequiresElevation, because the flag is derived
        from what could be read. That is this project's signature failure shape
        sitting in a field the executor branches on.

        Returns the disagreements as [string[]] -- empty when the fresh plan
        agrees with the one it was handed. It does NOT end in `, $array`: the
        caller expects @(...).Count to be 0 for agreement, and Test-Finding's
        comma is the shape that cost P3-C1 a bug.

        Anything that goes wrong while rebuilding is itself a disagreement. A
        re-verification that cannot be performed is never read as "it agreed".
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Plan
    )

    $problems = New-Object System.Collections.Generic.List[string]

    $finding = $null
    try {
        $finding = New-Finding `
            -Category ([string](Get-OptimizerProperty -InputObject $Plan -Name 'Category')) `
            -Id ([string](Get-OptimizerProperty -InputObject $Plan -Name 'FindingId')) `
            -DisplayName ([string](Get-OptimizerProperty -InputObject $Plan -Name 'DisplayName')) `
            -Evidence 'Rebuilt at execute time so the plan can be checked against the machine as it is now.' `
            -Confidence ([string](Get-OptimizerProperty -InputObject $Plan -Name 'Confidence' -Default 'Heuristic')) `
            -RequiresConsent:([bool](Get-OptimizerProperty -InputObject $Plan -Name 'RequiresConsent' -Default $true)) `
            -RemovalMethod ([string](Get-OptimizerProperty -InputObject $Plan -Name 'RemovalMethod'))
    }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        $null = $problems.Add("The plan could not be checked against the machine because its own identity fields do not make a valid finding: $($inner.Message)")
        return [string[]] $problems.ToArray()
    }

    $fresh = $null
    try { $fresh = Get-RemovalPlan -Finding $finding }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        $null = $problems.Add("The plan could not be re-checked against the machine: $($inner.GetType().Name): $($inner.Message)")
        return [string[]] $problems.ToArray()
    }

    if ($null -eq $fresh) {
        $null = $problems.Add('Re-checking the plan against the machine produced no plan at all, so there is nothing to compare it with.')
        return [string[]] $problems.ToArray()
    }

    # The load-bearing fields only. VerifiedUtc and PreviewText differ by
    # construction on every rebuild and say nothing about the machine.
    foreach ($field in 'Route', 'Supported', 'CurrentState', 'RequiresElevation', 'IsReversible') {
        $was = Get-OptimizerProperty -InputObject $Plan  -Name $field
        $now = Get-OptimizerProperty -InputObject $fresh -Name $field
        if ([string] $was -ne [string] $now) {
            $null = $problems.Add("The plan says $field is '$was'; checking again now says '$now'.")
        }
    }

    if (-not [bool](Get-OptimizerProperty -InputObject $fresh -Name 'Supported' -Default $false)) {
        $reason = [string](Get-OptimizerProperty -InputObject $fresh -Name 'UnsupportedReason')
        if (-not [string]::IsNullOrWhiteSpace($reason)) {
            $null = $problems.Add("Checking again now, this tool will not act on it: $reason")
        }
    }

    $wasStep = @(Get-OptimizerProperty -InputObject $Plan  -Name 'Step' -Default @())
    $nowStep = @(Get-OptimizerProperty -InputObject $fresh -Name 'Step' -Default @())
    if ($wasStep.Count -ne $nowStep.Count) {
        $null = $problems.Add("The plan has $($wasStep.Count) step(s); checking again now produces $($nowStep.Count).")
    }

    # The rollback material is what makes this route reversible, so a difference
    # in it is a difference in whether the action can be undone at all.
    $wasBack = Get-OptimizerProperty -InputObject $Plan  -Name 'RollbackData'
    $nowBack = Get-OptimizerProperty -InputObject $fresh -Name 'RollbackData'
    foreach ($field in 'ServiceName', 'KeyPath', 'PreviousStartValue', 'PreviousDelayedAutostart') {
        $was = Get-OptimizerProperty -InputObject $wasBack -Name $field
        $now = Get-OptimizerProperty -InputObject $nowBack -Name $field
        if ([string] $was -ne [string] $now) {
            $null = $problems.Add("The plan recorded $field as '$was'; on this machine now it is '$now'.")
        }
    }

    # And what the step would actually write.
    for ($index = 0; $index -lt [math]::Min($wasStep.Count, $nowStep.Count); $index++) {
        $wasDetail = Get-OptimizerProperty -InputObject $wasStep[$index] -Name 'Detail'
        $nowDetail = Get-OptimizerProperty -InputObject $nowStep[$index] -Name 'Detail'
        foreach ($field in 'KeyPath', 'PreviousStartValue', 'PlannedStartValue') {
            $was = Get-OptimizerProperty -InputObject $wasDetail -Name $field
            $now = Get-OptimizerProperty -InputObject $nowDetail -Name $field
            if ([string] $was -ne [string] $now) {
                $null = $problems.Add("Step $($index + 1) of the plan says $field is '$was'; checking again now says '$now'.")
            }
        }
    }

    [string[]] $problems.ToArray()
}

#endregion

#region Internal: the checkpoint, once

function Get-ExecutorRestorePoint {
    <#
        The best-effort System Restore checkpoint, taken ONCE and reused.

        It NEVER fails an action. New-OptimizerRestorePoint documents that it does
        not throw, and this wraps it anyway: the one thing that must not happen is
        an action refused because a checkpoint nobody depends on went wrong. The
        ledger is the primary net; the checkpoint is worth taking when it is free.

        Cached at module scope rather than per pipeline, because a GUI that calls
        Invoke-RemovalPlan once per approved row would otherwise ask Windows for a
        checkpoint per row -- twenty stalls for one checkpoint, since Windows
        throttles to one per 24 hours and declines the rest reporting success.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    if ($null -ne $script:ExecutorRestorePoint) { return $script:ExecutorRestorePoint }

    $result = $null
    try {
        $result = New-OptimizerRestorePoint -Description 'win11-optimizer' -RestorePointType 'MODIFY_SETTINGS'
    }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        $result = [pscustomobject][ordered]@{
            State  = 'Failed'
            Reason = "Asking Windows for a restore point threw, which it is documented not to do: $($inner.GetType().Name): $($inner.Message). The action was not affected -- the action log is what makes a change recoverable."
        }
    }

    $script:ExecutorRestorePoint = $result
    $result
}

#endregion

#region Public: perform a plan

function Invoke-RemovalPlan {
    <#
    .SYNOPSIS
        Performs a removal plan. ServiceStartupType only; every other route is
        refused, with a reason.

    .DESCRIPTION
        ONE PLAN IN, ONE RESULT OUT, ALWAYS -- the mirror of Get-RemovalPlan's
        contract. A refusal is a result carrying Result 'Refused' and a reason a
        user could read, never a throw and never a silent skip, so a batch of
        twenty plans cannot lose nineteen because the first one was refused.

        THE REFUSALS, in this order, each with its own reason:

          1. the plan's route is not ServiceStartupType. This build performs one
             route -- the only one the dispatcher marks reversible and the only
             one whose rollback record can provably put the machine back.
          2. Supported is $false. The plan itself says no.
          3. CurrentState is Unverifiable. The gate lives HERE rather than in a
             caller because it belongs where the damage happens: P3-C1 locked that
             Unverifiable is never collapsed into AlreadyGone, and this is the
             other half of that -- it is not collapsed into Present either.
          4. re-verification disagrees with the plan. The plan is rebuilt in this
             process, against this machine, now; any difference in a load-bearing
             field is recorded and the action refused rather than proceeding on
             the better data. A plan built un-elevated under-reports
             RequiresElevation (docs\STATE.md Q24), which is exactly the shape
             this catches.
          5. the plan requires elevation and this process is not elevated.

        AlreadyGone is a SUCCESS with an empty step list, not a refusal, and so is
        Changed: the plan is supported, there is nothing to do, and the user's
        goal is already met. P3-C1 locked that shape.

        THE ORDER IS THE SAFETY PROPERTY. The Intent record is written to the
        ledger and flushed to disk before the first registry write. If the ledger
        will not accept it, Write-OptimizerAction throws and NOTHING IS
        ATTEMPTED -- that throw is the gate, and this function reports Failed with
        the ledger's own message rather than doing the work anyway.

        A refusal writes NOTHING to the ledger. An executor refusal changed
        nothing, and an Intent with no Outcome reads back as 'OutcomeUnknown' --
        "attempted, outcome unknown" -- which would be a lie about the one state
        this project is most careful with.

        -WhatIf writes nothing at all: no ledger record, no restore point, no
        registry value. ConfirmImpact is High, so an interactive caller is asked;
        pass -Confirm:$false to run unattended.

    .PARAMETER Plan
        A Win11Optimizer.RemovalPlan, or one deserialized from JSON. Accepts
        pipeline input.

    .PARAMETER LedgerPath
        Write to this action ledger instead of the default one.

    .PARAMETER RunId
        The run these actions belong to. Defaults to the open run log's run id.

    .PARAMETER SkipRestorePoint
        Do not ask Windows for a System Restore checkpoint. The ledger, not the
        checkpoint, is what makes a change recoverable.

    .EXAMPLE
        Get-RemovalPlan -Finding $serviceFinding | Invoke-RemovalPlan -WhatIf

    .EXAMPLE
        $result = Invoke-RemovalPlan -Plan $plan -Confirm:$false
        Undo-RemovalAction -ActionId $result.ActionId -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [AllowNull()]
        $Plan,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $LedgerPath,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $RunId,

        [switch] $SkipRestorePoint
    )

    process {
        $started  = [datetime]::UtcNow
        $identity = Get-ExecutorPlanIdentity -Plan $Plan

        $ledgerArgument = @{}
        if ($PSBoundParameters.ContainsKey('LedgerPath')) { $ledgerArgument['Path'] = $LedgerPath }
        if ($PSBoundParameters.ContainsKey('RunId'))      { $ledgerArgument['RunId'] = $RunId }
        $resolvedLedger = $(if ($PSBoundParameters.ContainsKey('LedgerPath')) { $LedgerPath } else { Get-OptimizerActionLogPath })

        function New-Refusal {
            param([Parameter(Mandatory)] [string] $Because)
            New-ExecutorResult -Result $script:ExecutorRefusedResult -Reason $Because -Plan $Plan `
                -FindingId $identity.FindingId -DisplayName $identity.DisplayName `
                -Category $identity.Category -Route $identity.Route -LedgerPath $resolvedLedger `
                -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3))
        }

        # ---- 0. is it a plan at all --------------------------------------
        # Not one of the five, and it precedes them: Write-OptimizerAction throws
        # for anything that is not a plan, and a caller that handed us a
        # half-deserialized object deserves the reason rather than a stack trace.
        # Assigned first and wrapped second -- P3-C1's lesson, applied even though
        # Test-OptimizerActionPlan deliberately does not carry the comma.
        $problemList = Test-OptimizerActionPlan -Plan $Plan
        $problems = [string[]] @($problemList)
        if ($problems.Count -gt 0) {
            return (New-Refusal -Because "This is not a removal plan, so nothing was attempted: $($problems -join ' ')")
        }

        # ---- 1. the route ------------------------------------------------
        if ([string] $Plan.Route -ne $script:RemovalRouteServiceStartup) {
            return (New-Refusal -Because "This build performs one kind of change only: a service's startup type ($($script:RemovalRouteServiceStartup)). '$($Plan.DisplayName)' is planned as '$($Plan.Route)', which this tool can describe in full and will not carry out. It is the only route whose record can provably put this PC back the way it was, and the others are not offered behind a switch.")
        }

        # ---- 2. the plan itself says no ----------------------------------
        if (-not [bool] $Plan.Supported) {
            $unsupported = [string](Get-OptimizerProperty -InputObject $Plan -Name 'UnsupportedReason')
            if ([string]::IsNullOrWhiteSpace($unsupported)) { $unsupported = 'The plan carried no reason.' }
            return (New-Refusal -Because "The plan for '$($Plan.DisplayName)' says nothing can be done for it, so nothing was attempted: $unsupported")
        }

        # ---- 3. Unverifiable is a block, and the gate lives here ----------
        if ([string] $Plan.CurrentState -eq $script:RemovalStateUnverifiable) {
            return (New-Refusal -Because "The state of '$($Plan.DisplayName)' could not be read when this plan was made, so this tool does not know what it would be changing. Nothing is assumed either way and nothing was attempted. Re-run the scan as administrator and try again.")
        }

        # ---- 4. re-verify against the machine as it is now ----------------
        $disagreementList = Get-ExecutorPlanDisagreement -Plan $Plan
        $disagreement = [string[]] @($disagreementList)
        if ($disagreement.Count -gt 0) {
            return (New-Refusal -Because "This PC is not in the state the plan was made against, so nothing was attempted. What changed: $($disagreement -join ' ')")
        }

        # ---- 5. elevation -------------------------------------------------
        if ([bool] $Plan.RequiresElevation -and -not (Test-IsElevated)) {
            return (New-Refusal -Because "Changing the startup type of '$($Plan.DisplayName)' needs administrator rights and this program is not running as administrator. Nothing was attempted. Restart it as administrator and try again.")
        }

        $steps = [psobject[]] @(Get-OptimizerProperty -InputObject $Plan -Name 'Step' -Default @())
        $rollback = Get-OptimizerProperty -InputObject $Plan -Name 'RollbackData'
        $serviceName = [string](Get-OptimizerProperty -InputObject $rollback -Name 'ServiceName' -Default $Plan.FindingId)

        $shouldTarget = $(if ([string]::IsNullOrWhiteSpace($serviceName)) { [string] $Plan.DisplayName } else { $serviceName })
        $shouldAction = $(if ($steps.Count -lt 1) {
                "Record that there is nothing to change ($($Plan.CurrentState))"
            } else {
                "Set the service's startup type to Disabled"
            })

        if (-not $PSCmdlet.ShouldProcess($shouldTarget, $shouldAction)) {
            return (New-ExecutorResult -Result $script:ActionResultSkipped -IsWhatIf $true -Plan $Plan `
                -FindingId $identity.FindingId -DisplayName $identity.DisplayName `
                -Category $identity.Category -Route $identity.Route -LedgerPath $resolvedLedger `
                -Reason 'Nothing was written: no ledger record, no restore point and no registry value. This was a dry run.' `
                -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)))
        }

        # ---- the checkpoint, before the first action ----------------------
        # Only where there is actually an action. A plan with no steps changes
        # nothing, and a twelve-second checkpoint for a no-op is a cost with no
        # matching risk.
        $checkpoint = $null
        if ($steps.Count -gt 0 -and -not $SkipRestorePoint) {
            $checkpoint = Get-ExecutorRestorePoint
        }

        # ---- the Intent. THIS IS THE GATE. -------------------------------
        $actionId = $null
        try {
            $actionId = Write-OptimizerAction -Plan $Plan @ledgerArgument
        }
        catch {
            $inner = Get-OptimizerInnerException -Exception $_.Exception
            Write-Warning "Nothing was changed: the action could not be recorded first. $($inner.Message)"
            return (New-ExecutorResult -Result $script:ActionResultFailed -Plan $Plan `
                -FindingId $identity.FindingId -DisplayName $identity.DisplayName `
                -Category $identity.Category -Route $identity.Route -LedgerPath $resolvedLedger `
                -RestorePoint $checkpoint `
                -Reason "Nothing on this PC was changed. What this tool was about to do could not be written to the action log first, and an action that cannot be recorded must not be attempted: $($inner.Message)" `
                -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)))
        }

        $note = New-Object System.Collections.Generic.List[string]

        # The checkpoint result goes on a Note against this action. Best-effort in
        # both directions: a Note that will not write must not fail the action
        # whose Intent is already safely on disk.
        if ($null -ne $checkpoint) {
            try {
                $null = Write-OptimizerAction -Plan $Plan -RecordKind Note -ActionId $actionId -Data $checkpoint @ledgerArgument
            }
            catch {
                $inner = Get-OptimizerInnerException -Exception $_.Exception
                $null = $note.Add("The restore point result could not be recorded on the ledger: $($inner.Message)")
            }
        }

        # ---- the work ----------------------------------------------------
        $runState = Get-ExecutorServiceRunState -ServiceName $serviceName
        if ($runState -eq 'Running') {
            $null = $note.Add("'$serviceName' is running right now. It was NOT stopped: the startup type takes effect at the next restart, and stopping a service somebody is using is a bigger change than the one that was approved.")
        }

        $stepResult = New-Object System.Collections.Generic.List[psobject]
        $index = 0
        foreach ($step in $steps) {
            $stepStarted = [datetime]::UtcNow
            $kind   = [string](Get-OptimizerProperty -InputObject $step -Name 'Kind')
            $target = [string](Get-OptimizerProperty -InputObject $step -Name 'Target' -Default $serviceName)
            $detail = Get-OptimizerProperty -InputObject $step -Name 'Detail'

            if ($kind -ne $script:RemovalStepServiceStartupType) {
                # Fails closed. The route gate above should make this unreachable;
                # it is here because "unreachable" is a claim about today's code.
                $null = $stepResult.Add((New-ExecutorStepResult -StepIndex $index -Kind $kind -Target $target `
                    -Result $script:ActionResultSkipped `
                    -ErrorText "This build performs no step of kind '$kind'. Nothing was done for it." `
                    -DurationSeconds ([math]::Round(([datetime]::UtcNow - $stepStarted).TotalSeconds, 3))))
                $index++
                continue
            }

            $keyPath = [string](Get-OptimizerProperty -InputObject $detail -Name 'KeyPath')
            $planned = Get-OptimizerProperty -InputObject $detail -Name 'PlannedStartValue'

            try {
                if ([string]::IsNullOrWhiteSpace($keyPath) -or $null -eq $planned) {
                    throw "The step does not say which key to write or what to write to it, so nothing was done for it."
                }
                $write = Write-ExecutorServiceRegistryValue -KeyPath $keyPath -Name $script:ExecutorServiceStartValueName -Value ([int] $planned)
                $null = $stepResult.Add((New-ExecutorStepResult -StepIndex $index -Kind $kind -Target $target `
                    -Result $(if ($write.IsVerified) { $script:ActionResultSucceeded } else { $script:ActionResultFailed }) `
                    -Write ([psobject[]] @($write)) `
                    -ErrorText $(if ($write.IsVerified) { $null } else { "The value was written and read back as '$($write.VerifiedValue)' rather than '$($write.WrittenValue)'." }) `
                    -DurationSeconds ([math]::Round(([datetime]::UtcNow - $stepStarted).TotalSeconds, 3))))
            }
            catch {
                $inner = Get-OptimizerInnerException -Exception $_.Exception
                $null = $stepResult.Add((New-ExecutorStepResult -StepIndex $index -Kind $kind -Target $target `
                    -Result $script:ActionResultFailed `
                    -ErrorText "$($inner.GetType().Name): $($inner.Message)" `
                    -DurationSeconds ([math]::Round(([datetime]::UtcNow - $stepStarted).TotalSeconds, 3))))
            }
            $index++
        }

        # ---- the Outcome --------------------------------------------------
        $results   = [string[]] @($stepResult | ForEach-Object { $_.Result })
        $succeeded = @($results | Where-Object { $_ -eq $script:ActionResultSucceeded }).Count
        $overall = $script:ActionResultSucceeded
        if ($results.Count -gt 0) {
            if ($succeeded -eq 0) { $overall = $script:ActionResultFailed }
            elseif ($succeeded -lt $results.Count) { $overall = $script:ActionResultPartial }
        }
        elseif ([string] $Plan.CurrentState -eq $script:RemovalStateAlreadyGone) {
            $null = $note.Add('There was nothing to change: this service is no longer registered on this PC.')
        }
        else {
            $null = $note.Add("There was nothing to change: this service is no longer in the state it was found in ($($Plan.CurrentState)).")
        }

        $duration = [math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)
        $errorText = [string[]] @($stepResult | Where-Object { $null -ne $_.ErrorText } | ForEach-Object { $_.ErrorText })

        try {
            $null = Write-OptimizerAction -Plan $Plan -RecordKind Outcome -ActionId $actionId -Result $overall `
                -DurationSeconds $duration -StepResult ([psobject[]] @($stepResult.ToArray())) `
                -ErrorText $(if ($errorText.Count -gt 0) { $errorText -join ' ' } else { $null }) @ledgerArgument
        }
        catch {
            # The Intent is on disk and the work has happened. An Outcome that
            # cannot be written leaves the action reading 'OutcomeUnknown', which
            # is the honest state and exactly what that value is for -- so this is
            # surfaced loudly and not swallowed.
            $inner = Get-OptimizerInnerException -Exception $_.Exception
            Write-Warning "The action was performed but its outcome could not be recorded, so the ledger will report it as OutcomeUnknown: $($inner.Message)"
            $null = $note.Add("The outcome could not be written to the action log: $($inner.Message). The ledger will report this action as 'attempted, outcome unknown'.")
        }

        New-ExecutorResult -Result $overall -ActionId $actionId -Plan $Plan `
            -FindingId $identity.FindingId -DisplayName $identity.DisplayName `
            -Category $identity.Category -Route $identity.Route `
            -Performed ($succeeded -gt 0) -StepResult ([psobject[]] @($stepResult.ToArray())) `
            -RestorePoint $checkpoint -DurationSeconds $duration -LedgerPath $resolvedLedger `
            -Note ([string[]] @($note.ToArray()))
    }
}

#endregion

#region Public: put it back

function Undo-RemovalAction {
    <#
    .SYNOPSIS
        Puts back a service startup type this tool changed, from the record it
        wrote at the time.

    .DESCRIPTION
        Takes an ActionId, reads the append-only ledger, and restores the startup
        type the rollback record captured before the change. It writes its own
        Intent/Outcome pair, carrying the original ActionId, so the undo is a new
        action in history and not an edit to the old one -- nothing in this
        project ever rewrites a ledger line.

        THE REFUSALS:

          * the ledger has no such action, or more than one.
          * the action's Result is 'OutcomeUnknown'. An Intent with no Outcome
            means "attempted, outcome unknown" and is never collapsed into "did
            not happen"; this tool will not guess which it was, so it refuses and
            says so. That is the whole reason the value exists.
          * the action was Refused or Skipped: nothing was changed, so there is
            nothing to put back.
          * the route is not ServiceStartupType. This build undoes what it can
            perform, and nothing else.
          * the rollback record does not carry the previous startup type.
          * the startup type on this PC now is NEITHER what this tool set it to
            NOR what it was before. Something else has changed it since, and
            overwriting somebody else's decision is not an undo.
          * it needs administrator rights and this process does not have them.

        Where the startup type is ALREADY what the record says it was, the undo
        writes nothing and reports Skipped. Doing less is the point.

        DelayedAutostart is restored ONLY where the record says it was switched
        ON. The dispatcher's PreviousDelayedAutostart is a derived boolean, so
        $false cannot distinguish "the value was 0" from "the key had no such
        value" -- and creating a value the service never had would be a change
        beyond the undo. See the report; this is a gap in the rollback record's
        shape, not in this function.

        -WhatIf writes nothing at all.

    .PARAMETER ActionId
        The action to undo, as returned by Invoke-RemovalPlan.

    .PARAMETER LedgerPath
        Read from, and write to, this ledger instead of the default one.

    .PARAMETER RunId
        The run this undo belongs to. Defaults to the open run log's run id.

    .PARAMETER SkipRestorePoint
        Do not ask Windows for a System Restore checkpoint.

    .EXAMPLE
        Undo-RemovalAction -ActionId $result.ActionId -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string] $ActionId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $LedgerPath,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $RunId,

        [switch] $SkipRestorePoint
    )

    process {
        $started = [datetime]::UtcNow

        $ledgerArgument = @{}
        if ($PSBoundParameters.ContainsKey('LedgerPath')) { $ledgerArgument['Path'] = $LedgerPath }
        $outcomeArgument = @{}
        foreach ($key in $ledgerArgument.Keys) { $outcomeArgument[$key] = $ledgerArgument[$key] }
        if ($PSBoundParameters.ContainsKey('RunId')) { $outcomeArgument['RunId'] = $RunId }
        $resolvedLedger = $(if ($PSBoundParameters.ContainsKey('LedgerPath')) { $LedgerPath } else { Get-OptimizerActionLogPath })

        function New-UndoRefusal {
            param([Parameter(Mandatory)] [string] $Because)
            New-ExecutorResult -Result $script:ExecutorRefusedResult -Reason $Because `
                -UndoOfActionId $ActionId -LedgerPath $resolvedLedger `
                -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3))
        }

        # ---- read the history ---------------------------------------------
        $read = @()
        try { $read = @(Get-OptimizerActionLog -ActionId $ActionId @ledgerArgument) }
        catch {
            $inner = Get-OptimizerInnerException -Exception $_.Exception
            return (New-UndoRefusal -Because "The action log could not be read, so there is no record to put anything back from: $($inner.Message)")
        }

        # Parse errors come back FIRST and are not filtered by -ActionId, because
        # a line that will not parse cannot be matched against a filter -- and the
        # line you filtered for is exactly the one it might be.
        $parseError = @($read | Where-Object { $_.IsParseError })
        $entries    = @($read | Where-Object { -not $_.IsParseError })

        if ($entries.Count -lt 1) {
            return (New-UndoRefusal -Because "There is no action '$ActionId' in the action log at '$resolvedLedger', so there is nothing recorded to put back.$(if ($parseError.Count -gt 0) { " $($parseError.Count) line(s) in that log could not be read at all, and one of them may be the one you are looking for." } else { '' })")
        }
        if ($entries.Count -gt 1) {
            return (New-UndoRefusal -Because "The action log holds $($entries.Count) different actions under the id '$ActionId'. That should be impossible, so nothing is assumed and nothing was attempted.")
        }

        $entry  = $entries[0]
        $result = [string](Get-OptimizerProperty -InputObject $entry -Name 'Result')

        # ---- the OutcomeUnknown gate ---------------------------------------
        if ($result -eq $script:ActionResultUnknown) {
            return (New-UndoRefusal -Because "The action log cannot say whether action '$ActionId' happened: it recorded what this tool was about to do and never recorded how it ended. That is 'attempted, outcome unknown', which is not the same as 'it did not happen', and this tool will not guess which it was. Nothing was attempted.$(if ($parseError.Count -gt 0) { " $($parseError.Count) line(s) in that log could not be read at all, which may be why." } else { '' })")
        }
        if ($result -eq $script:ActionResultRefused -or $result -eq $script:ActionResultSkipped) {
            return (New-UndoRefusal -Because "Action '$ActionId' is recorded as '$result': nothing on this PC was changed by it, so there is nothing to put back.")
        }

        $route = [string](Get-OptimizerProperty -InputObject $entry -Name 'Route')
        if ($route -ne $script:RemovalRouteServiceStartup) {
            return (New-UndoRefusal -Because "Action '$ActionId' is on the '$route' route. This build can only put back a service's startup type ($($script:RemovalRouteServiceStartup)), which is the one route whose record is enough to reverse it.")
        }

        # ---- the rollback material -----------------------------------------
        $rollback = Get-OptimizerProperty -InputObject $entry -Name 'RollbackData'
        $serviceName = [string](Get-OptimizerProperty -InputObject $rollback -Name 'ServiceName')
        $keyPath     = [string](Get-OptimizerProperty -InputObject $rollback -Name 'KeyPath')
        $previous    = Get-OptimizerProperty -InputObject $rollback -Name 'PreviousStartValue'
        $wasDelayed  = [bool](Get-OptimizerProperty -InputObject $rollback -Name 'PreviousDelayedAutostart' -Default $false)
        $displayName = [string](Get-OptimizerProperty -InputObject $rollback -Name 'DisplayName' -Default (Get-OptimizerProperty -InputObject $entry -Name 'DisplayName' -Default $serviceName))

        if ([string]::IsNullOrWhiteSpace($keyPath) -or $null -eq $previous) {
            return (New-UndoRefusal -Because "The record for action '$ActionId' does not carry the startup type this service had before the change, so there is nothing to put it back to. Nothing was attempted.")
        }
        if ($null -eq (Get-ExecutorServiceKeyPart -KeyPath $keyPath)) {
            return (New-UndoRefusal -Because "The record for action '$ActionId' names '$keyPath', which is not a single service key under HKLM:\SYSTEM\CurrentControlSet\Services. This tool writes nowhere else, so nothing was attempted.")
        }

        # ---- what is there now ----------------------------------------------
        $live = Get-ExecutorServiceRegistryState -KeyPath $keyPath
        if ($null -eq $live.Exists) {
            return (New-UndoRefusal -Because "The service key '$keyPath' could not be read, so this tool does not know what it would be changing. Nothing was attempted$(if ($live.Reason) { " ($($live.Reason))" } else { '' }).")
        }
        if ($live.Exists -eq $false) {
            return (New-UndoRefusal -Because "The service '$serviceName' is no longer registered on this PC, so its startup type cannot be put back. Nothing was attempted.")
        }
        if (-not $live.StartPresent) {
            return (New-UndoRefusal -Because "The key for '$serviceName' has no Start value at all, which is not a state this tool produced. Nothing was assumed and nothing was attempted.")
        }

        # What this tool actually wrote, from the outcome it recorded, falling
        # back to what the plan said it would write. Needed because putting back a
        # value somebody ELSE changed since is not an undo.
        $written = $null
        foreach ($step in @(Get-OptimizerProperty -InputObject $entry -Name 'StepResult' -Default @())) {
            foreach ($record in @(Get-OptimizerProperty -InputObject (Get-OptimizerProperty -InputObject $step -Name 'Detail') -Name 'Write' -Default @())) {
                if ([string](Get-OptimizerProperty -InputObject $record -Name 'ValueName') -eq $script:ExecutorServiceStartValueName) {
                    $written = Get-OptimizerProperty -InputObject $record -Name 'WrittenValue'
                }
            }
        }
        if ($null -eq $written) {
            foreach ($step in @(Get-OptimizerProperty -InputObject (Get-OptimizerProperty -InputObject $entry -Name 'Plan') -Name 'Step' -Default @())) {
                $planned = Get-OptimizerProperty -InputObject (Get-OptimizerProperty -InputObject $step -Name 'Detail') -Name 'PlannedStartValue'
                if ($null -ne $planned) { $written = $planned }
            }
        }

        $liveStart = [int] $live.Start
        $alreadyBack = ($liveStart -eq [int] $previous)
        $liveDelayedOn = ($live.DelayedPresent -and $null -ne $live.Delayed -and [int] $live.Delayed -ne 0)

        if (-not $alreadyBack) {
            if ($null -eq $written) {
                return (New-UndoRefusal -Because "The record for action '$ActionId' does not say what startup type this tool set '$displayName' to, and it is not the one it had before, so this tool cannot tell whether the current setting is its own doing. Nothing was attempted.")
            }
            if ($liveStart -ne [int] $written) {
                return (New-UndoRefusal -Because "The startup type of '$displayName' on this PC is now '$liveStart', which is neither what this tool set it to ('$([int] $written)') nor what it was before ('$([int] $previous)'). Something else has changed it since, and overwriting that is not an undo. Nothing was attempted.")
            }
        }

        # ---- elevation, and only where something would actually be written ---
        # Do less: an action whose recorded state is already the state on this PC
        # writes nothing, so it does not need rights it will not use.
        $needsWrite = (-not $alreadyBack) -or ($wasDelayed -and -not $liveDelayedOn)
        if ($needsWrite -and -not (Test-IsElevated)) {
            return (New-UndoRefusal -Because "Putting back the startup type of '$displayName' needs administrator rights and this program is not running as administrator. Nothing was attempted.")
        }

        # ---- the undo plan ---------------------------------------------------
        # Built through the dispatcher's own factories, so the record this undo
        # writes is the same shape as every other plan on the ledger and its
        # preview comes from the one renderer. RollbackData holds the state as it
        # is RIGHT NOW, so the undo is itself undoable.
        $undoPlan = New-ExecutorUndoPlan -Entry $entry -ServiceName $serviceName -DisplayName $displayName `
            -KeyPath $keyPath -RestoreStartValue ([int] $previous) -RestoreDelayed $wasDelayed -Live $live

        $shouldAction = $(if ($alreadyBack) {
                "Record that the startup type is already back to '$([int] $previous)'"
            } else {
                "Put the service's startup type back to '$([int] $previous)'"
            })
        if (-not $PSCmdlet.ShouldProcess($serviceName, $shouldAction)) {
            return (New-ExecutorResult -Result $script:ActionResultSkipped -IsWhatIf $true -Plan $undoPlan `
                -UndoOfActionId $ActionId -FindingId $serviceName -DisplayName $displayName `
                -Category 'Service' -Route $script:RemovalRouteServiceStartup -LedgerPath $resolvedLedger `
                -Reason 'Nothing was written: no ledger record, no restore point and no registry value. This was a dry run.' `
                -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)))
        }

        $checkpoint = $null
        if ($needsWrite -and -not $SkipRestorePoint) { $checkpoint = Get-ExecutorRestorePoint }

        # ---- the Intent. SAME GATE. -----------------------------------------
        $undoData = [pscustomobject][ordered]@{
            IsUndo               = $true
            UndoOfActionId       = $ActionId
            UndoOfResult         = $result
            RestoreStartValue    = [int] $previous
            RestoreDelayed       = $wasDelayed
            StartValueBeforeUndo = $liveStart
            WasAlreadyRestored   = $alreadyBack
            Note                 = "Puts back what action $ActionId changed. The original action's records are untouched; this is a new action in history."
        }

        $undoActionId = $null
        try {
            $undoActionId = Write-OptimizerAction -Plan $undoPlan -Data $undoData @outcomeArgument
        }
        catch {
            $inner = Get-OptimizerInnerException -Exception $_.Exception
            Write-Warning "Nothing was changed: the undo could not be recorded first. $($inner.Message)"
            return (New-ExecutorResult -Result $script:ActionResultFailed -Plan $undoPlan `
                -UndoOfActionId $ActionId -FindingId $serviceName -DisplayName $displayName `
                -Category 'Service' -Route $script:RemovalRouteServiceStartup -LedgerPath $resolvedLedger `
                -RestorePoint $checkpoint `
                -Reason "Nothing on this PC was changed. What this tool was about to put back could not be written to the action log first, and an action that cannot be recorded must not be attempted: $($inner.Message)" `
                -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)))
        }

        $note = New-Object System.Collections.Generic.List[string]
        if ($null -ne $checkpoint) {
            try { $null = Write-OptimizerAction -Plan $undoPlan -RecordKind Note -ActionId $undoActionId -Data $checkpoint @outcomeArgument }
            catch { $null = $note.Add("The restore point result could not be recorded on the ledger: $($_.Exception.Message)") }
        }

        # ---- the work --------------------------------------------------------
        $stepResult = New-Object System.Collections.Generic.List[psobject]
        $writes = New-Object System.Collections.Generic.List[psobject]
        $stepStarted = [datetime]::UtcNow
        $stepError = $null

        try {
            if ($alreadyBack) {
                $null = $note.Add("The startup type of '$displayName' was already '$([int] $previous)'. Nothing was written.")
            }
            else {
                $null = $writes.Add((Write-ExecutorServiceRegistryValue -KeyPath $keyPath -Name $script:ExecutorServiceStartValueName -Value ([int] $previous)))
            }

            # DelayedAutostart, and only where the record says it was ON. Where it
            # says $false, nothing is written: the record cannot tell "the value
            # was 0" from "there was no such value", and creating one the service
            # never had would be a change beyond the undo.
            if ($wasDelayed -and -not $liveDelayedOn) {
                $null = $writes.Add((Write-ExecutorServiceRegistryValue -KeyPath $keyPath -Name $script:ExecutorServiceDelayedValueName -Value 1))
            }
        }
        catch {
            $inner = Get-OptimizerInnerException -Exception $_.Exception
            $stepError = "$($inner.GetType().Name): $($inner.Message)"
        }

        $unverified = @($writes | Where-Object { -not $_.IsVerified })
        if ($unverified.Count -gt 0 -and $null -eq $stepError) {
            $stepError = "$($unverified.Count) value(s) were written and did not read back as written."
        }

        $stepOutcome = $script:ActionResultSucceeded
        if ($null -ne $stepError) { $stepOutcome = $script:ActionResultFailed }
        elseif ($alreadyBack -and $writes.Count -lt 1) { $stepOutcome = $script:ActionResultSkipped }

        $null = $stepResult.Add((New-ExecutorStepResult -StepIndex 0 -Kind $script:RemovalStepServiceStartupType `
            -Target $serviceName -Result $stepOutcome -Write ([psobject[]] @($writes.ToArray())) `
            -ErrorText $stepError -DurationSeconds ([math]::Round(([datetime]::UtcNow - $stepStarted).TotalSeconds, 3))))

        $duration = [math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)

        try {
            $null = Write-OptimizerAction -Plan $undoPlan -RecordKind Outcome -ActionId $undoActionId -Result $stepOutcome `
                -DurationSeconds $duration -StepResult ([psobject[]] @($stepResult.ToArray())) -ErrorText $stepError @outcomeArgument
        }
        catch {
            $inner = Get-OptimizerInnerException -Exception $_.Exception
            Write-Warning "The undo was performed but its outcome could not be recorded, so the ledger will report it as OutcomeUnknown: $($inner.Message)"
            $null = $note.Add("The outcome could not be written to the action log: $($inner.Message).")
        }

        New-ExecutorResult -Result $stepOutcome -ActionId $undoActionId -UndoOfActionId $ActionId -Plan $undoPlan `
            -FindingId $serviceName -DisplayName $displayName -Category 'Service' `
            -Route $script:RemovalRouteServiceStartup -Performed ($writes.Count -gt 0 -and $null -eq $stepError) `
            -StepResult ([psobject[]] @($stepResult.ToArray())) -RestorePoint $checkpoint `
            -DurationSeconds $duration -LedgerPath $resolvedLedger -Note ([string[]] @($note.ToArray()))
    }
}

function New-ExecutorUndoPlan {
    <#
        The plan an undo writes its Intent from, built with the dispatcher's own
        builder, step factory and renderer rather than assembled by hand -- so it
        is the same shape as every other plan on the ledger, and so the preview
        the ledger keeps comes from the one renderer that produced every other.

        Its RollbackData describes the state RIGHT NOW, before the undo runs, in
        the same field names the dispatcher uses. That makes the undo itself
        undoable by the same code path, which is the property that distinguishes
        a reversible action from a one-way one.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Entry,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $ServiceName,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $DisplayName,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $KeyPath,
        [Parameter(Mandatory)] [int] $RestoreStartValue,
        [Parameter(Mandatory)] [bool] $RestoreDelayed,
        [Parameter(Mandatory)] [psobject] $Live
    )

    $plan = Get-OptimizerProperty -InputObject $Entry -Name 'Plan'

    $seed = [pscustomobject]@{
        Id              = $ServiceName
        Category        = 'Service'
        RemovalMethod   = 'ServiceDisable'
        DisplayName     = $DisplayName
        Confidence      = [string](Get-OptimizerProperty -InputObject $plan -Name 'Confidence' -Default 'Known')
        RequiresConsent = [bool](Get-OptimizerProperty -InputObject $plan -Name 'RequiresConsent' -Default $true)
    }

    $builder = New-RemovalPlanBuilder -Finding $seed -Route $script:RemovalRouteServiceStartup
    Approve-RemovalPlan -Builder $builder -CurrentState $script:RemovalStatePresent -IsReversible $true
    $builder.RequiresElevation = $true

    $liveStart = $(if ($Live.StartPresent -and $null -ne $Live.Start) { [int] $Live.Start } else { $null })
    $liveDelayed = ($Live.DelayedPresent -and $null -ne $Live.Delayed -and [int] $Live.Delayed -ne 0)

    # The name table is the dispatcher's, read rather than restated. Indexed only
    # with a value we have: a $null key is guarded, because "we could not read the
    # startup type" must not render as the startup type named by entry $null.
    $restoreName = [string] $script:RemovalServiceStartName[$RestoreStartValue]
    if ([string]::IsNullOrWhiteSpace($restoreName)) { $restoreName = "Unknown (Start = $RestoreStartValue)" }
    if ($RestoreStartValue -eq $script:RemovalServiceStartAutomatic -and $RestoreDelayed) { $restoreName = 'Automatic (Delayed Start)' }

    $currentName = '(could not be read)'
    if ($null -ne $liveStart) {
        $currentName = [string] $script:RemovalServiceStartName[$liveStart]
        if ([string]::IsNullOrWhiteSpace($currentName)) { $currentName = "Unknown (Start = $liveStart)" }
        if ($liveStart -eq $script:RemovalServiceStartAutomatic -and $liveDelayed) { $currentName = 'Automatic (Delayed Start)' }
    }

    $builder.RollbackData = [pscustomobject][ordered]@{
        ServiceName              = $ServiceName
        DisplayName              = $DisplayName
        KeyPath                  = $KeyPath
        PreviousStartValue       = $liveStart
        PreviousStartupType      = $currentName
        PreviousDelayedAutostart = $liveDelayed
        Note                     = "The state of this service immediately before the undo ran. To undo the undo: set Start back to $liveStart."
    }

    $null = $builder.Note.Add("This is an undo of action $([string](Get-OptimizerProperty -InputObject $Entry -Name 'ActionId')). The records of that action are untouched; nothing in this log is ever rewritten.")

    $null = $builder.Step.Add((New-RemovalStep `
        -Kind $script:RemovalStepServiceStartupType `
        -Description "Put the service's startup type back to $restoreName, the setting it had before this tool changed it. The service is not deleted, not started and not stopped." `
        -Target $ServiceName `
        -RequiresElevation $true `
        -ReverseHint "Set the startup type back to $currentName." `
        -Detail ([pscustomobject][ordered]@{
            KeyPath             = $KeyPath
            PreviousStartValue  = $liveStart
            PreviousStartupType = $currentName
            PlannedStartValue   = $RestoreStartValue
            PlannedStartupType  = $restoreName
            RestoreDelayed      = $RestoreDelayed
        })))

    ConvertTo-RemovalPlan -Builder $builder -VerifiedUtc ([datetime]::UtcNow.ToString('o'))
}

#endregion
