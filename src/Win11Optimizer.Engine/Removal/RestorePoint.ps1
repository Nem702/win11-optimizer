<#
    The System Restore checkpoint -- chunk P3-C2.

    THIS IS THE ONLY FILE IN THIS PROJECT THAT CHANGES THE STATE OF THE MACHINE,
    and it is on its own for exactly that reason. Everything else in Removal\
    reads, plans or appends to this tool's own log files; this one asks Windows to
    create a restore point. Keeping it in its own file means the claim made at the
    top of ActionLog.ps1 -- "this file changes nothing about the machine" -- needs
    no exception attached to it, and means the one call that does can be named,
    pinned by a test, and read in ninety seconds by anyone auditing this project.

    It is NOT the primary net. The append-only ledger is. A restore point is
    best-effort, is off on a great many machines, is silently throttled to one per
    24 hours, and does not restore user files at all. It is worth taking when it
    is free and it must never be allowed to fail an action.

    So the contract is: TRI-STATE PLUS A REASON, and never a bare bool.

        Created      Windows made a new restore point, and it was confirmed to
                     exist afterwards rather than believed on a return value.
        Throttled    Windows declined because one already exists inside its own
                     frequency window. It reports SUCCESS when it does this,
                     which is why this function checks instead of believing it.
        Unavailable  the machine cannot do this right now: System Protection is
                     switched off, or the shell has no Checkpoint-Computer, or we
                     are not elevated. NORMAL STATES, not broken ones.
        Failed       it was attempted and it errored.

    System Protection being off is Unavailable, never Failed. It is the default
    on a large share of Windows 11 installations, and a tool that reports its own
    normal environment as a failure teaches people to ignore its errors.

    ASCII only -- see docs\REVIEW.md, after P3-C1a.
#>

#region Constants

$script:RestorePointTypeName = 'Win11Optimizer.RestorePointResult'

$script:RestorePointStateCreated     = 'Created'
$script:RestorePointStateThrottled   = 'Throttled'
$script:RestorePointStateUnavailable = 'Unavailable'
$script:RestorePointStateFailed      = 'Failed'

$script:RestorePointStates = @(
    $script:RestorePointStateCreated
    $script:RestorePointStateThrottled
    $script:RestorePointStateUnavailable
    $script:RestorePointStateFailed
)

# Where Windows keeps the two things this function has to know before it calls
# anything: whether System Protection is on at all, and how often it will accept
# a new checkpoint. Read from the registry rather than through WMI because these
# are two value reads and WMI is a whole subsystem.
$script:RestorePointPolicyKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
$script:RestorePointControlKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SystemRestore'

# Windows' own default when SystemRestorePointCreationFrequency is absent: one
# restore point per 24 hours. Documented, and the reason a second Checkpoint-
# Computer call in the same day returns success and does nothing.
$script:RestorePointDefaultFrequencyMinutes = 1440

#endregion

#region Internal

function New-OptimizerRestorePointResult {
    # Every field on every result, whatever the state -- Set-StrictMode -Version
    # Latest is on for everything that will read this.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $State,
        [Parameter()] [AllowNull()] $Reason,
        [Parameter()] [AllowNull()] $SequenceNumber,
        [Parameter()] [AllowNull()] $CreatedUtc,
        [Parameter()] [AllowNull()] $PreviousRestorePointUtc,
        [Parameter()] [AllowNull()] $ThrottleMinutes,
        [Parameter()] [AllowNull()] $MinutesSinceLast,
        [Parameter()] [bool] $IsElevated = $false,
        [Parameter()] [AllowNull()] $DurationSeconds,
        [Parameter()] [AllowNull()] $RestorePointCountBefore,
        [Parameter()] [AllowNull()] $RestorePointCountAfter
    )

    if ($script:RestorePointStates -notcontains $State) {
        throw "New-OptimizerRestorePointResult: '$State' is not one of: $($script:RestorePointStates -join ', ')."
    }

    [pscustomobject][ordered]@{
        PSTypeName              = $script:RestorePointTypeName
        State                   = $State
        Reason                  = $Reason
        SequenceNumber          = $SequenceNumber
        CreatedUtc              = $CreatedUtc
        PreviousRestorePointUtc = $PreviousRestorePointUtc
        ThrottleMinutes         = $ThrottleMinutes
        MinutesSinceLast        = $MinutesSinceLast
        IsElevated              = $IsElevated
        DurationSeconds         = $DurationSeconds
        RestorePointCountBefore = $RestorePointCountBefore
        RestorePointCountAfter  = $RestorePointCountAfter
        CheckedUtc              = [datetime]::UtcNow.ToString('o')
    }
}

function Get-OptimizerSystemRestoreValue {
    # One registry value, or $null. Never throws: every caller here treats "could
    # not read it" as a reason to be careful, not as an answer.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Name
    )

    try { return Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop }
    catch {
        Write-Verbose "Could not read '$Name' from '$Path': $($_.Exception.Message)"
        return $null
    }
}

function Get-OptimizerRestorePointInventory {
    <#
        The restore points currently on this machine, newest first, or $null when
        they could not be enumerated at all.

        $null is NEVER "there are none". An empty list means the machine really
        has no restore points; $null means we could not look, and the two lead to
        different answers -- the first lets a checkpoint be attempted, the second
        makes the throttle undetectable.

        Get-ComputerRestorePoint exists only on Windows PowerShell. Under
        PowerShell 7 it is absent, which is a real and honest Unavailable rather
        than something to work around.
    #>
    [CmdletBinding()]
    param()

    $command = Get-Command -Name 'Get-ComputerRestorePoint' -ErrorAction SilentlyContinue
    if ($null -eq $command) { return $null }

    try {
        $points = @(Get-ComputerRestorePoint -ErrorAction Stop)
    }
    catch {
        Write-Verbose "Could not enumerate restore points: $($_.Exception.Message)"
        return $null
    }

    $records = New-Object System.Collections.Generic.List[psobject]
    foreach ($point in $points) {
        $created = $null
        try {
            # CreationTime is a WMI datetime string ('20260827062928.000000-000'),
            # in LOCAL time. Converted through the object's own ConvertToDateTime
            # so the offset is applied by the thing that knows it, then taken to
            # UTC here, because everything else in this project is UTC.
            $created = ([datetime] $point.ConvertToDateTime($point.CreationTime)).ToUniversalTime()
        }
        catch { $created = $null }

        $null = $records.Add([pscustomobject]@{
            SequenceNumber = [int](Get-OptimizerProperty -InputObject $point -Name 'SequenceNumber' -Default 0)
            Description    = [string](Get-OptimizerProperty -InputObject $point -Name 'Description')
            CreatedUtc     = $created
        })
    }

    , [psobject[]] @($records.ToArray())
}

function Test-OptimizerSystemProtectionEnabled {
    <#
        Is System Protection on? Returns $true / $false / $null, and $null means
        "could not tell" rather than "off" -- the tri-state rule again.

        Two independent switches, either of which turns it off:
          DisableSR         under Control\SystemRestore, 1 = off
          RPSessionInterval under CurrentVersion\SystemRestore, 0 = off
    #>
    [CmdletBinding()]
    param()

    $disabled = Get-OptimizerSystemRestoreValue -Path $script:RestorePointControlKey -Name 'DisableSR'
    if ($null -ne $disabled -and [int] $disabled -ne 0) { return $false }

    $interval = Get-OptimizerSystemRestoreValue -Path $script:RestorePointPolicyKey -Name 'RPSessionInterval'
    if ($null -ne $interval) { return ([int] $interval -ne 0) }

    if ($null -ne $disabled) { return $true }
    $null
}

#endregion

#region Public

function New-OptimizerRestorePoint {
    <#
    .SYNOPSIS
        Best-effort System Restore checkpoint. Tri-state plus a reason, never a
        bare boolean, and it never fails an action.

    .DESCRIPTION
        EXPLICITLY NOT THE PRIMARY NET. The append-only action ledger is. This is
        worth taking when it is free; whatever it returns, the ledger is still
        what makes a removal recoverable, and a caller must carry on regardless.

        Returns State = Created / Throttled / Unavailable / Failed, with a Reason
        string on the last three.

          * Not elevated -> Unavailable with a reason. Never a throw.
          * No Checkpoint-Computer in this shell (PowerShell 7 has none)
            -> Unavailable with a reason.
          * System Protection switched off -> Unavailable, NOT Failed. It is the
            normal state on a great many machines and must not read as a broken
            tool.
          * Inside Windows' own frequency window -> Throttled, detected by
            reading the existing restore points rather than by believing the
            return value. Checkpoint-Computer reports SUCCESS when it silently
            declines, so its return value cannot be used to answer this.
          * Otherwise the checkpoint is attempted, and then CONFIRMED by looking
            for a new restore point. A call that returned cleanly and produced
            nothing is reported as Throttled, not Created.

        THE ONE CALL IN THIS PROJECT THAT CHANGES THE MACHINE is the
        Checkpoint-Computer below. It is additive: it creates a restore point and
        removes, disables and modifies nothing.

    .PARAMETER Description
        The label the restore point carries in the Windows UI.

    .PARAMETER RestorePointType
        Windows' own restore point type. MODIFY_SETTINGS is the honest one for
        what this tool does; APPLICATION_UNINSTALL is available for the executor.

    .PARAMETER Force
        Attempt the checkpoint even when the frequency window says Windows will
        decline it. The result is still confirmed afterwards, so a declined call
        still reports Throttled rather than Created.

    .EXAMPLE
        $checkpoint = New-OptimizerRestorePoint
        Write-OptimizerAction -Plan $plan -RecordKind Note -ActionId $id -Data $checkpoint
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Description = 'win11-optimizer',

        [Parameter()]
        [ValidateSet('APPLICATION_INSTALL', 'APPLICATION_UNINSTALL', 'DEVICE_DRIVER_INSTALL', 'MODIFY_SETTINGS', 'CANCELLED_OPERATION')]
        [string] $RestorePointType = 'MODIFY_SETTINGS',

        [switch] $Force
    )

    $started = [datetime]::UtcNow
    $isElevated = [bool](Test-IsElevated)

    # Held untyped on purpose. $reason = $null on a [string]-constrained variable
    # becomes '' because PowerShell re-applies the constraint on assignment, and
    # an empty string reads as "there was a reason and it was blank" rather than
    # as "there was none". docs\REVIEW.md.
    $reason = $null

    if (-not $isElevated) {
        $reason = 'This process is not running as administrator, and creating a restore point needs it. Nothing was attempted.'
        return (New-OptimizerRestorePointResult -State $script:RestorePointStateUnavailable -Reason $reason -IsElevated $false `
            -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)))
    }

    $checkpointCommand = Get-Command -Name 'Checkpoint-Computer' -ErrorAction SilentlyContinue
    if ($null -eq $checkpointCommand) {
        $reason = "This shell has no Checkpoint-Computer command (PowerShell $($PSVersionTable.PSVersion), $($PSVersionTable.PSEdition)). It exists on Windows PowerShell 5.1, which is this project's target runtime."
        return (New-OptimizerRestorePointResult -State $script:RestorePointStateUnavailable -Reason $reason -IsElevated $true `
            -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)))
    }

    $protectionEnabled = Test-OptimizerSystemProtectionEnabled
    if ($protectionEnabled -eq $false) {
        $reason = 'System Protection is switched off for this PC, so Windows cannot create a restore point. That is a normal Windows setting, not a fault, and it does not stop anything else this tool does: the action log is what makes a change recoverable.'
        return (New-OptimizerRestorePointResult -State $script:RestorePointStateUnavailable -Reason $reason -IsElevated $true `
            -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)))
    }

    $throttleMinutes = $script:RestorePointDefaultFrequencyMinutes
    $configured = Get-OptimizerSystemRestoreValue -Path $script:RestorePointPolicyKey -Name 'SystemRestorePointCreationFrequency'
    if ($null -ne $configured) {
        try { $throttleMinutes = [int] $configured } catch { $throttleMinutes = $script:RestorePointDefaultFrequencyMinutes }
    }

    $before = Get-OptimizerRestorePointInventory
    $countBefore = $null
    $previousUtc = $null
    $minutesSince = $null

    if ($null -ne $before) {
        $countBefore = @($before).Count
        $newest = @(@($before) | Where-Object { $null -ne $_.CreatedUtc } | Sort-Object -Property CreatedUtc -Descending | Select-Object -First 1)
        if ($newest.Count -gt 0) {
            $previousUtc = $newest[0].CreatedUtc
            $minutesSince = [math]::Round(([datetime]::UtcNow - $previousUtc).TotalMinutes, 1)
        }
    }

    # Detect the throttle rather than believing the return value. Windows accepts
    # the call and reports success when it declines inside its own window, so a
    # tool that trusted the exit status would report a checkpoint that does not
    # exist -- which is exactly the class of failure this project is built
    # against, in the one place it would be most expensive.
    if (-not $Force -and $throttleMinutes -gt 0 -and $null -ne $minutesSince -and $minutesSince -lt $throttleMinutes) {
        $reason = "Windows creates at most one restore point every $throttleMinutes minutes and the last one is $minutesSince minutes old, so it would decline this one and report success. Nothing was attempted."
        return (New-OptimizerRestorePointResult -State $script:RestorePointStateThrottled -Reason $reason -IsElevated $true `
            -PreviousRestorePointUtc $previousUtc -ThrottleMinutes $throttleMinutes -MinutesSinceLast $minutesSince `
            -RestorePointCountBefore $countBefore -RestorePointCountAfter $countBefore `
            -DurationSeconds ([math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)))
    }

    $failure = $null
    try {
        Checkpoint-Computer -Description $Description -RestorePointType $RestorePointType -ErrorAction Stop
    }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        $failure = "$($inner.GetType().Name): $($inner.Message)"
    }

    $after = Get-OptimizerRestorePointInventory
    $countAfter = $null
    $createdUtc = $null
    $sequence = $null

    if ($null -ne $after) {
        $countAfter = @($after).Count
        $newest = @(@($after) | Where-Object { $null -ne $_.CreatedUtc } | Sort-Object -Property CreatedUtc -Descending | Select-Object -First 1)
        if ($newest.Count -gt 0 -and ($null -eq $previousUtc -or $newest[0].CreatedUtc -gt $previousUtc)) {
            $createdUtc = $newest[0].CreatedUtc
            $sequence   = $newest[0].SequenceNumber
        }
    }

    $duration = [math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 3)

    if ($null -ne $createdUtc) {
        # Confirmed by looking, not by the call returning.
        return (New-OptimizerRestorePointResult -State $script:RestorePointStateCreated -Reason $null -IsElevated $true `
            -SequenceNumber $sequence -CreatedUtc ($createdUtc.ToString('o')) `
            -PreviousRestorePointUtc $previousUtc -ThrottleMinutes $throttleMinutes -MinutesSinceLast $minutesSince `
            -RestorePointCountBefore $countBefore -RestorePointCountAfter $countAfter -DurationSeconds $duration)
    }

    if ($null -ne $failure) {
        $reason = "Windows was asked for a restore point and refused: $failure"
        return (New-OptimizerRestorePointResult -State $script:RestorePointStateFailed -Reason $reason -IsElevated $true `
            -PreviousRestorePointUtc $previousUtc -ThrottleMinutes $throttleMinutes -MinutesSinceLast $minutesSince `
            -RestorePointCountBefore $countBefore -RestorePointCountAfter $countAfter -DurationSeconds $duration)
    }

    if ($null -eq $after) {
        $reason = 'Windows accepted the request and the restore points on this PC could not be listed afterwards, so whether one was created is unknown. It is reported as unavailable rather than as created, because a checkpoint this tool cannot see is not one it may rely on.'
        return (New-OptimizerRestorePointResult -State $script:RestorePointStateUnavailable -Reason $reason -IsElevated $true `
            -PreviousRestorePointUtc $previousUtc -ThrottleMinutes $throttleMinutes -MinutesSinceLast $minutesSince `
            -RestorePointCountBefore $countBefore -RestorePointCountAfter $countAfter -DurationSeconds $duration)
    }

    $reason = "Windows accepted the request, reported no error and created no restore point. That is how it declines inside its own frequency window of $throttleMinutes minutes."
    New-OptimizerRestorePointResult -State $script:RestorePointStateThrottled -Reason $reason -IsElevated $true `
        -PreviousRestorePointUtc $previousUtc -ThrottleMinutes $throttleMinutes -MinutesSinceLast $minutesSince `
        -RestorePointCountBefore $countBefore -RestorePointCountAfter $countAfter -DurationSeconds $duration
}

#endregion
