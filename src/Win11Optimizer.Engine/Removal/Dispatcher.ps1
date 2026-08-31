<#
    The removal dispatcher -- chunk P3-C1.

    Takes a Finding, works out which mechanism WOULD remove or disable it,
    verifies the item is still there, and returns a PLAN describing exactly what
    would happen. As data.

    THIS FILE REMOVES NOTHING, DISABLES NOTHING AND WRITES NOTHING. Not behind a
    flag, not commented out, not in a helper nothing calls. Naming a command in a
    plan step's data is the deliverable; calling one is the thing that must not
    happen, and tests\RemovalDispatcher.Tests.ps1 scans this source to enforce it.

    docs\STATE.md (2026-08-25) locks the reason: P3-C2 depends on P3-C1, so the
    first removal code would otherwise run on a daily-driver machine with nothing
    recording what it did. The execute path arrives in P3-C2, which owns the
    append-only action log that makes it safe, and it will take a plan object as
    its input.

    Deliberate deviation from docs\STATE.md, argued in the P3-C1 report: there is
    no Invoke-* function and no SupportsShouldProcess anywhere here.
    ShouldProcess on a function whose action branch cannot exist yet is theatre,
    and it leaves an `if ($PSCmdlet.ShouldProcess(...)) { }` hole shaped exactly
    like the removal call somebody adds in a hurry later.

    Public surface:
      Get-RemovalContract  the route table and the vocabulary, stated once
      Get-RemovalPlan      routing + verification + the step list
      Get-RemovalPreview   the human-readable dry run, derived from a plan

    ASCII only -- Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, and a
    UTF-8 em dash then decodes to a byte 5.1 accepts as a string delimiter.
#>

#region Constants: the vocabulary

$script:RemovalPlanTypeName = 'Win11Optimizer.RemovalPlan'
$script:RemovalStepTypeName = 'Win11Optimizer.RemovalStep'

# The seven routes. A route is a MECHANISM, not a RemovalMethod: two different
# (Category, RemovalMethod) pairs can share one, and -- the reason the table is
# keyed on the pair at all -- one RemovalMethod can mean two unrelated things.
#
# 'FileDelete' is that case. StartupItem + FileDelete is ONE SHORTCUT FILE in a
# Startup folder, and the least destructive action that achieves the user's goal
# is to switch it off in the StartupApproved store, not to delete it. JunkFile +
# FileDelete is A SET OF UP TO 13,375 FILES that really are deleted. Same method
# string, nothing in common. Routing on the pair costs one hashtable key.
$script:RemovalRouteAppx              = 'AppxPackage'
$script:RemovalRouteUninstallString   = 'RegistryUninstallString'
$script:RemovalRoutePackageManagement = 'PackageManagement'
$script:RemovalRouteStartupApproved   = 'StartupApproved'
$script:RemovalRouteScheduledTask     = 'ScheduledTask'
$script:RemovalRouteServiceStartup    = 'ServiceStartupType'
$script:RemovalRouteJunkFileSet       = 'JunkFileSet'

# Fails closed. An unrecognised pair is this, never a guess at the nearest route.
$script:RemovalRouteUnsupported = 'Unsupported'

$script:RemovalRouteIds = @(
    $script:RemovalRouteAppx
    $script:RemovalRouteUninstallString
    $script:RemovalRoutePackageManagement
    $script:RemovalRouteStartupApproved
    $script:RemovalRouteScheduledTask
    $script:RemovalRouteServiceStartup
    $script:RemovalRouteJunkFileSet
)

# (Category, RemovalMethod) -> route. Every pair a detector can actually produce
# is here, plus the two PackageManagement pairs, which nothing produces and which
# still need defined behaviour because the GUI can hand us a Finding from an old
# run log.
$script:RemovalRouteTable = [ordered]@{
    'OemBloatware|Appx'                    = $script:RemovalRouteAppx
    'UnusedApp|Appx'                       = $script:RemovalRouteAppx
    'OemBloatware|RegistryUninstallString' = $script:RemovalRouteUninstallString
    'UnusedApp|RegistryUninstallString'    = $script:RemovalRouteUninstallString
    'OemBloatware|PackageManagement'       = $script:RemovalRoutePackageManagement
    'UnusedApp|PackageManagement'          = $script:RemovalRoutePackageManagement
    'StartupItem|RegistryRunKey'           = $script:RemovalRouteStartupApproved
    'StartupItem|FileDelete'               = $script:RemovalRouteStartupApproved
    'StartupItem|TaskScheduler'            = $script:RemovalRouteScheduledTask
    'Service|ServiceDisable'               = $script:RemovalRouteServiceStartup
    'JunkFile|FileDelete'                  = $script:RemovalRouteJunkFileSet
}

# What a step is. P3-C2 switches on this; P4-C1 renders it.
$script:RemovalStepAppxRemove            = 'AppxRemovePackage'
$script:RemovalStepAppxRemoveProvisioned = 'AppxRemoveProvisionedPackage'
$script:RemovalStepProcessCommand        = 'ProcessCommand'
$script:RemovalStepRegistryValueWrite    = 'RegistryValueWrite'
$script:RemovalStepScheduledTaskDisable  = 'ScheduledTaskDisable'
$script:RemovalStepServiceStartupType    = 'ServiceStartupTypeChange'
$script:RemovalStepFileDeleteSet         = 'FileDeleteSet'

$script:RemovalStepKinds = @(
    $script:RemovalStepAppxRemove
    $script:RemovalStepAppxRemoveProvisioned
    $script:RemovalStepProcessCommand
    $script:RemovalStepRegistryValueWrite
    $script:RemovalStepScheduledTaskDisable
    $script:RemovalStepServiceStartupType
    $script:RemovalStepFileDeleteSet
)

# What the plan-time verification found.
#
#   Present       the item the Finding describes is still there, as described.
#   AlreadyGone   it is PROVED gone. A success shape, not an error: the user's
#                 goal is already met and the step list is empty.
#   Changed       it is still there but no longer in the state that made it a
#                 Finding -- a service whose start type is no longer Automatic,
#                 say. Never acted on blind; the plan says so and does less.
#   Unverifiable  could not be read. NEVER collapsed into AlreadyGone: every
#                 probe in this project is tri-state for exactly this reason, and
#                 "$false for a path you may not look at" is the trap REVIEW.md
#                 records three times.
$script:RemovalStatePresent      = 'Present'
$script:RemovalStateAlreadyGone  = 'AlreadyGone'
$script:RemovalStateChanged      = 'Changed'
$script:RemovalStateUnverifiable = 'Unverifiable'

$script:RemovalCurrentStates = @(
    $script:RemovalStatePresent
    $script:RemovalStateAlreadyGone
    $script:RemovalStateChanged
    $script:RemovalStateUnverifiable
)

# StartupApproved: the byte that means "the user turned this off".
#
# Byte 0 carries the state, on its own; bytes 4-11 are a FILETIME recording WHEN.
# The decoding is a CLOSED table, measured in P2-C2 and confirmed against Task
# Manager (docs\STATE.md 2026-08-26): 0x01/0x03/0x07 disabled, 0x02/0x04/0x06
# enabled, anything else Unknown. 0x01 is what this machine's disabled entries
# actually carry, so 0x01 is what the plan writes.
#
# Only byte 0 changes. Where a record already exists the plan preserves the
# other eleven bytes rather than inventing a timestamp; where none exists it
# plans twelve bytes with the rest zero, which is exactly the shape Docker
# Desktop's disabled record has on this machine.
$script:RemovalStartupApprovedDisabledByte = 0x01
$script:RemovalStartupApprovedValueLength  = 12

# Service start values, HKLM\SYSTEM\CurrentControlSet\Services\<name>\Start. Read
# from the registry rather than from a cmdlet: Get-Service's StartType does not
# report AutomaticDelayedStart the same way under 5.1 and 7, and the previous
# state is the thing a rollback restores.
$script:RemovalServiceStartName = @{
    0 = 'Boot'
    1 = 'System'
    2 = 'Automatic'
    3 = 'Manual'
    4 = 'Disabled'
}
$script:RemovalServiceStartAutomatic = 2
$script:RemovalServiceStartDisabled  = 4

# What an executable looks like, for the unquoted-path-with-spaces case in
# section 2.2. Five extensions, because a real uninstall string on this machine
# reaches RunDll32.EXE and unins000.exe alike.
$script:RemovalExecutableExtension = @('.exe', '.com', '.bat', '.cmd', '.msi')

# The one uninstall string this project rewrites. MsiExec's uninstall form is
# documented and mechanical; every other installer's string is used as written.
$script:RemovalMsiExecName = 'msiexec'
$script:RemovalGuidPattern = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'

# The one uninstall string this project refuses outright (docs\STATE.md Q17).
#
# Five NVIDIA keys on the development machine are of the form
#
#     "...\RunDll32.EXE" "...\NVI2.DLL",UninstallPackage Display.Driver
#
# and the parser produces a correct argv for it. rundll32 is the one program that
# does not read argv: it parses GetCommandLine() itself and splits the module from
# the entry point on the comma, so an argument array re-quoted by whoever launches
# the process may not reproduce the string it was built from. The plan would
# therefore LOOK right and probably not be, which is the worst state for a plan to
# be in, so the shape is unsupported rather than guessed at.
$script:RemovalRunDll32Name = 'rundll32'
$script:RemovalEntryPointExtension = @('.dll', '.cpl', '.ocx')

# How many file paths the preview quotes for a FileDeleteSet step. The set can be
# five figures; the preview shows counts, the location and a sample, never the
# list.
$script:RemovalPreviewSampleCount = 3

#endregion

#region The contract

function Get-RemovalContract {
    <#
    .SYNOPSIS
        Returns the removal dispatcher's route table and vocabulary.

    .DESCRIPTION
        The mirror of Get-FindingContract: everything a consumer would otherwise
        restate, expressed once. The test suite reads Routes rather than listing
        the pairs again, and P4-C1 reads StepKinds and CurrentStates rather than
        hard-coding the strings it switches on.

        Routes is the (Category, RemovalMethod) -> route id table, keyed
        'Category|RemovalMethod'. RouteIds is the seven mechanisms; anything not
        in Routes plans as UnsupportedRoute, which is a route with defined
        behaviour and not an error.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    # A copy, not the module's own table: a consumer that edits what it is handed
    # must not be able to re-route this dispatcher.
    $routes = [ordered]@{}
    foreach ($key in $script:RemovalRouteTable.Keys) { $routes[$key] = $script:RemovalRouteTable[$key] }

    [pscustomobject]@{
        TypeName         = $script:RemovalPlanTypeName
        StepTypeName     = $script:RemovalStepTypeName
        Routes           = $routes
        RouteIds         = [string[]] $script:RemovalRouteIds
        UnsupportedRoute = $script:RemovalRouteUnsupported
        StepKinds        = [string[]] $script:RemovalStepKinds
        CurrentStates    = [string[]] $script:RemovalCurrentStates
    }
}

function Get-RemovalRouteKey {
    # The route table's key for one Finding. Kept in a function so the string
    # format is written once.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Category,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $RemovalMethod
    )

    '{0}|{1}' -f $Category, $RemovalMethod
}

#endregion

#region Internal: the plan and step factories

function New-RemovalStep {
    <#
        One step. A plan may have more than one -- the Appx case forces it, since
        a per-user registration and a provisioned registration are two different
        calls with two different identifiers and removing one does not touch the
        other.

        Executable + Argument are for ProcessCommand steps and nothing else, and
        Argument is an ARRAY. Never a single command line, never a string handed
        to a shell: a command line is a thing that gets re-parsed by whoever
        receives it, and the re-parse is where an argument with a space in it
        becomes two arguments pointing somewhere nobody intended.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Kind,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Description,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Target,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Executable,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [string[]] $Argument,
        [Parameter()] [bool] $RequiresElevation = $false,
        [Parameter()] [bool] $RequiresInteraction = $false,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $ReverseHint,
        [Parameter()] [AllowNull()] $Detail
    )

    if ($script:RemovalStepKinds -notcontains $Kind) {
        throw "New-RemovalStep: '$Kind' is not one of the step kinds in Get-RemovalContract().StepKinds."
    }

    # An executable with no argument array is a real shape (Steam's
    # uninstall.exe takes none). An argument array with no executable is not.
    if ([string]::IsNullOrWhiteSpace($Executable) -and $null -ne $Argument -and $Argument.Count -gt 0) {
        throw "New-RemovalStep: step '$Kind' has arguments but no executable."
    }

    [pscustomobject]@{
        PSTypeName          = $script:RemovalStepTypeName
        Kind                = $Kind
        Description         = $Description
        Target              = $Target
        Executable          = $(if ([string]::IsNullOrWhiteSpace($Executable)) { $null } else { $Executable })
        # @($null) is an array of ONE element, so the empty case is built
        # explicitly rather than by wrapping a possibly-null value.
        Argument            = $(if ($null -eq $Argument) { $null } else { [string[]] @($Argument) })
        RequiresElevation   = [bool] $RequiresElevation
        RequiresInteraction = [bool] $RequiresInteraction
        ReverseHint         = $ReverseHint
        Detail              = $Detail
    }
}

function New-RemovalPlanBuilder {
    # The mutable half of a plan, filled in by whichever route runs. Kept separate
    # from the finished object so a route cannot forget to set a field: every
    # property exists from the start, with the fail-safe value.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Finding,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Route
    )

    [pscustomobject]@{
        FindingId         = [string](Get-OptimizerProperty -InputObject $Finding -Name 'Id')
        Category          = [string](Get-OptimizerProperty -InputObject $Finding -Name 'Category')
        RemovalMethod     = [string](Get-OptimizerProperty -InputObject $Finding -Name 'RemovalMethod')
        DisplayName       = [string](Get-OptimizerProperty -InputObject $Finding -Name 'DisplayName')
        Confidence        = [string](Get-OptimizerProperty -InputObject $Finding -Name 'Confidence')
        RequiresConsent   = Get-OptimizerProperty -InputObject $Finding -Name 'RequiresConsent'
        Route             = $Route
        Supported         = $false
        UnsupportedReason = $null
        CurrentState      = $script:RemovalStateUnverifiable
        RequiresElevation = $false
        IsReversible      = $false
        Step              = (New-Object System.Collections.Generic.List[psobject])
        RollbackData      = $null
        Note              = (New-Object System.Collections.Generic.List[string])
    }
}

function Deny-RemovalPlan {
    # A refusal. Not an error: it is a plan that says no, with a reason a user
    # could read. Deliberately clears the step list -- a refused plan that still
    # carries steps is one careless caller away from being executed.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Reason
    )

    $Builder.Supported         = $false
    $Builder.UnsupportedReason = $Reason
    $Builder.IsReversible      = $false
    $Builder.Step.Clear()
}

function Approve-RemovalPlan {
    # Marks the plan supported. Separate from Deny-RemovalPlan so that "supported"
    # is always something a route said on purpose; the builder starts at $false.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $CurrentState,
        [Parameter()] [bool] $IsReversible = $false
    )

    if ($script:RemovalCurrentStates -notcontains $CurrentState) {
        throw "Approve-RemovalPlan: '$CurrentState' is not one of Get-RemovalContract().CurrentStates."
    }

    $Builder.Supported         = $true
    $Builder.UnsupportedReason = $null
    $Builder.CurrentState      = $CurrentState
    $Builder.IsReversible      = $IsReversible
}

function ConvertTo-RemovalPlan {
    <#
        Freezes a builder into the plan object.

        It must survive ConvertTo-Json / ConvertFrom-Json intact, because P3-C2
        logs it and P4-C1 renders it, so: no scriptblocks, no ScriptProperty, no
        [datetime] (which round-trips to a string under PowerShell 7 and back to a
        [datetime] under 5.1 -- VerifiedUtc is therefore an ISO-8601 UTC string,
        the same shape the run log writes).

        SafetyLabel is a plain string obtained by RUNNING the Finding contract's
        own rule. Nothing here restates the two-axis AND, and nothing re-derives
        the label from Confidence alone. Confidence and RequiresConsent are both
        carried so a deserialized plan can re-run the rule and get the same
        answer -- including the fail-closed answer, if RequiresConsent arrived as
        something other than a real boolean.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [psobject] $Builder,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $VerifiedUtc
    )

    $contract = Get-FindingContract

    $steps = [psobject[]] @($Builder.Step.ToArray())

    $plan = [pscustomobject]@{
        PSTypeName        = $script:RemovalPlanTypeName
        FindingId         = $Builder.FindingId
        Category          = $Builder.Category
        RemovalMethod     = $Builder.RemovalMethod
        DisplayName       = $Builder.DisplayName
        Confidence        = $Builder.Confidence
        Route             = $Builder.Route
        Supported         = [bool] $Builder.Supported
        UnsupportedReason = $Builder.UnsupportedReason
        CurrentState      = $Builder.CurrentState
        VerifiedUtc       = $VerifiedUtc
        RequiresElevation = [bool] $Builder.RequiresElevation
        RequiresConsent   = $Builder.RequiresConsent
        SafetyLabel       = [string](& $contract.SafetyLabelRule $Builder.Confidence $Builder.RequiresConsent)
        IsReversible      = [bool] $Builder.IsReversible
        Step              = $steps
        RollbackData      = $Builder.RollbackData
        Note              = [string[]] @($Builder.Note.ToArray())
        PreviewText       = [string[]] @()
    }

    # One renderer, filled in here so a plan carries its own preview and
    # Get-RemovalPreview can also re-render a plan read back out of a run log.
    $plan.PreviewText = [string[]] @(Format-RemovalPlanText -Plan $plan)
    $plan
}

#endregion

#region Internal: shared verification helpers

function ConvertTo-RemovalRegistryProviderPath {
    # 'HKEY_LOCAL_MACHINE\SOFTWARE\...' is what a Finding's Id carries (it comes
    # from a registry key's .Name). The provider needs 'HKLM:\SOFTWARE\...'.
    # Returns $null for anything that is not a hive this project reads, which the
    # caller must treat as unsupported rather than as absent.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $map = [ordered]@{
        'HKEY_LOCAL_MACHINE\' = 'HKLM:\'
        'HKEY_CURRENT_USER\'  = 'HKCU:\'
        'HKLM:\'              = 'HKLM:\'
        'HKCU:\'              = 'HKCU:\'
    }

    foreach ($prefix in $map.Keys) {
        if ($Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $map[$prefix] + $Path.Substring($prefix.Length)
        }
    }

    $null
}

function Get-RemovalRegistryKeyState {
    <#
        Tri-state read of one registry key: does it exist, and what value names
        does it have?

        Returns { Exists = $true/$false/$null; ValueName = [string[]]; Reason }.
        $null is "could not be read", and it is never collapsed into $false.

        Value NAMES come from (Get-Item $key).Property, not from
        Get-ItemProperty: REVIEW.md records that Get-ItemProperty prints nothing
        at all, with no error, for a key that has no values, which is
        indistinguishable from a key that does not exist.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Exists = $null; ValueName = [string[]] @(); Reason = 'no registry path was given' }
    }

    $item = $null
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return [pscustomobject]@{ Exists = $false; ValueName = [string[]] @(); Reason = $null }
    }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        return [pscustomobject]@{ Exists = $null; ValueName = [string[]] @(); Reason = "$($inner.GetType().Name): $($inner.Message)" }
    }

    $names = @()
    try { $names = @($item.Property) } catch { $names = @() }

    [pscustomobject]@{
        Exists    = $true
        ValueName = [string[]] @($names | Where-Object { $null -ne $_ })
        Reason    = $null
    }
}

function Get-RemovalRegistryValue {
    # One value, or $null. Enumerate names first (see above); this only reads a
    # name the caller has already seen.
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

function Test-RemovalHiveIsMachine {
    # Does this registry path live in a machine-wide hive? Decides elevation.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    $Path.StartsWith('HKLM:', [System.StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith('HKEY_LOCAL_MACHINE', [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-RemovalHexString {
    # A REG_BINARY value as '01-00-00-...' so RollbackData survives JSON as
    # something a human can read in a log. The byte array is carried alongside it
    # as int[], which is what P3-C2 would write back.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] $Byte
    )

    if ($null -eq $Byte) { return $null }
    $values = @($Byte)
    if ($values.Count -lt 1) { return '' }
    ($values | ForEach-Object { '{0:X2}' -f [int] $_ }) -join '-'
}

function ConvertTo-RemovalUtcText {
    <#
        One UTC timestamp as one string, whatever shape it arrives in.

        A plan CANNOT carry a timestamp that survives ConvertTo-Json /
        ConvertFrom-Json as the same type, and this cost a test before it was
        understood. JSON has no date type; ConvertFrom-Json recognises an
        ISO-8601 string and hands back a [datetime]. So VerifiedUtc is stored as
        an ISO-8601 string (the shape the run log already writes) and comes back
        as a [datetime] on the far side, and a renderer that printed it directly
        would produce '2026-08-27T02:03:29.7515504Z' from a fresh plan and
        '08/27/2026 02:03:29' -- in the reader's locale -- from the same plan read
        back out of a log.

        The fix belongs in the renderer, not in the storage: the storage cannot
        win, and a preview that changes wording depending on where the plan came
        from is a preview nobody can diff.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Value
    )

    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return ([datetime] $Value).ToUniversalTime().ToString('o') }

    $text = [string] $Value
    if ([string]::IsNullOrWhiteSpace($text)) { return '' }

    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse($text, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $parsed)) {
        return $parsed.ToUniversalTime().ToString('o')
    }
    $text
}

function Get-RemovalProtectedPathRefusal {
    <#
        THE LAST GATE. The detectors already refuse to flag protected things; this
        runs again, at plan time, because the dispatcher takes ARBITRARY Findings
        -- from a run log, from a GUI, from a future detector nobody has reviewed
        yet -- and a Finding is just data.

        Returns the refusal sentence, or $null. The list and the directional check
        are the shared ones promoted out of the junk detector, not a second copy:
        Subtree entries (the user's own folders) collide in both directions, Root
        entries (the profile root, the Windows folder, drive roots) only when the
        candidate IS or CONTAINS them -- %TEMP% lives inside the profile and
        %SystemRoot%\Logs\CBS inside Windows, and both are legitimate.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ProtectedPath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $conflict = Get-OptimizerProtectedPathConflict -Path $Path -ProtectedPath $ProtectedPath
    if ($null -eq $conflict) { return $null }

    "'$Path' was refused: it collides with '$($conflict.Path)' -- $($conflict.Reason)."
}

#endregion

#region Internal: the uninstall-string parser

function Split-RemovalArgumentString {
    <#
        Splits the argument half of a command line into an ARGUMENT ARRAY,
        respecting double quotes. Never returns a command line.

        Quote handling is the simple toggle: a '"' starts or ends a quoted run and
        is not itself part of the argument, and whitespace outside a quoted run
        ends the token. That is enough for every uninstall string on the
        development machine, including the ones that embed a quoted value inside a
        token ( --displayname="Battle.net" comes out as one argument,
        --displayname=Battle.net, which is what the receiving process's argv would
        have held anyway).

        What it deliberately does NOT implement is the backslash-escaping half of
        the Windows command-line rules. No uninstall string in the 140-entry
        survey uses it, and guessing wrong there would change an argument rather
        than fail visibly.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return [string[]] @() }

    $arguments = New-Object System.Collections.Generic.List[string]
    $current   = New-Object System.Text.StringBuilder
    $inQuotes  = $false
    $started   = $false

    foreach ($character in $Text.ToCharArray()) {
        if ($character -eq '"') {
            $inQuotes = -not $inQuotes
            $started  = $true
            continue
        }
        if (-not $inQuotes -and [char]::IsWhiteSpace($character)) {
            if ($started) {
                $arguments.Add($current.ToString())
                $null = $current.Clear()
                $started = $false
            }
            continue
        }
        $null = $current.Append($character)
        $started = $true
    }

    if ($started) { $arguments.Add($current.ToString()) }

    [string[]] @($arguments.ToArray())
}

function Split-RemovalCommandString {
    <#
        Turns an uninstall string into an executable path plus an argument array.

        NEVER hands the string to a shell. No Invoke-Expression, no cmd /c. The
        whole point of this function is that the string is parsed here, once,
        into two typed fields, instead of being passed along as a command line for
        something else to re-parse later.

        Three shapes, all measured on the development machine's 140 uninstall
        entries:

          "C:\Program Files\App\unins000.exe" /SILENT     quoted -- easy
          C:\Program Files\AMD\...\Setup.exe /U {GUID}    UNQUOTED, WITH SPACES
          C:\Program Files (x86)\Steam\uninstall.exe      unquoted, no arguments

        The second is the ugly one and there are five of them here. A naive
        split-on-first-space gives 'C:\Program' -- a path that does not exist,
        pointing at a drive root. So the unquoted case walks the space positions
        from the LONGEST prefix down and takes the first one that both ends in an
        executable extension and is a file we can prove is there; failing that,
        the longest prefix that merely ends in an executable extension (the binary
        may legitimately be gone, and that is the caller's AlreadyGone case, not a
        parse failure). Only if neither finds anything does it fall back to the
        first token, and it says so in Note.

        Returns { Executable; Argument; Note } or $null when there is nothing to
        parse.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $CommandString
    )

    if ([string]::IsNullOrWhiteSpace($CommandString)) { return $null }

    $text = $CommandString.Trim()
    $note = $null

    if ($text.StartsWith('"')) {
        $closing = $text.IndexOf('"', 1)
        if ($closing -lt 0) {
            return [pscustomobject]@{
                Executable = $null
                Argument   = [string[]] @()
                Note       = 'the uninstall string opens with a quote that is never closed, so the executable path cannot be read out of it'
            }
        }
        $executable = $text.Substring(1, $closing - 1)
        $remainder  = $text.Substring($closing + 1)
        return [pscustomobject]@{
            Executable = $executable
            Argument   = [string[]] @(Split-RemovalArgumentString -Text $remainder)
            Note       = $null
        }
    }

    # Unquoted. Candidate split points are every space, longest prefix first.
    $candidates = New-Object System.Collections.Generic.List[string]
    $null = $candidates.Add($text)
    for ($index = $text.Length - 1; $index -ge 0; $index--) {
        if ($text[$index] -eq ' ') { $null = $candidates.Add($text.Substring(0, $index)) }
    }

    $extensionMatch = $null
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $extension = $null
        try { $extension = [System.IO.Path]::GetExtension($candidate) } catch { $extension = $null }
        if ([string]::IsNullOrWhiteSpace($extension)) { continue }
        if ($script:RemovalExecutableExtension -notcontains $extension.ToLowerInvariant()) { continue }

        if ($null -eq $extensionMatch) { $extensionMatch = $candidate }

        # Tri-state, never [System.IO.File]::Exists: that answers $false for a
        # path the current user may not look at, and this decision would then
        # silently pick a shorter, wrong prefix.
        if ((Test-OptimizerPathPresent -Path $candidate -PathType File) -eq $true) {
            $remainder = $text.Substring($candidate.Length)
            return [pscustomobject]@{
                Executable = $candidate
                Argument   = [string[]] @(Split-RemovalArgumentString -Text $remainder)
                Note       = $null
            }
        }
    }

    if ($null -ne $extensionMatch) {
        $remainder = $text.Substring($extensionMatch.Length)
        return [pscustomobject]@{
            Executable = $extensionMatch
            Argument   = [string[]] @(Split-RemovalArgumentString -Text $remainder)
            Note       = "the executable named by the uninstall string could not be found on disk, so the path was read from the string alone ('$extensionMatch')"
        }
    }

    $firstSpace = $text.IndexOf(' ')
    if ($firstSpace -lt 0) {
        return [pscustomobject]@{
            Executable = $text
            Argument   = [string[]] @()
            Note       = 'the uninstall string names no recognised executable extension; it was read as a bare path'
        }
    }

    [pscustomobject]@{
        Executable = $text.Substring(0, $firstSpace)
        Argument   = [string[]] @(Split-RemovalArgumentString -Text $text.Substring($firstSpace))
        Note       = 'the uninstall string names no recognised executable extension; everything before the first space was read as the path, which may be wrong for a path containing spaces'
    }
}

function Test-RemovalIsMsiExec {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Executable
    )

    if ([string]::IsNullOrWhiteSpace($Executable)) { return $false }
    $leaf = $null
    try { $leaf = [System.IO.Path]::GetFileNameWithoutExtension($Executable) } catch { return $false }
    [string]::Equals($leaf, $script:RemovalMsiExecName, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-RemovalIsRunDll32 {
    # Is this executable Windows' rundll32 launcher? Matched on the file name with
    # the extension dropped rather than on 'rundll32.exe' literally, so a string
    # that names it without one -- or as RunDll32.COM -- is caught too. Same shape
    # as Test-RemovalIsMsiExec, and case-insensitive for the same reason: the real
    # keys on this machine write 'RunDll32.EXE'.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Executable
    )

    if ([string]::IsNullOrWhiteSpace($Executable)) { return $false }
    $leaf = $null
    try { $leaf = [System.IO.Path]::GetFileNameWithoutExtension($Executable) } catch { return $false }
    [string]::Equals($leaf, $script:RemovalRunDll32Name, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-RemovalHasEntryPointArgument {
    <#
        Does this argument array carry a '<module path>,<entry point>' token?

        The SECOND of the two signals the rundll32 refusal needs. Either alone can
        be dodged -- a string could name rundll32 and pass an ordinary switch, or
        name something else entirely and still use a comma -- so the refusal wants
        both, and this half is what says the comma is load-bearing rather than
        incidental.

        Shape: a comma at least one character in, something after it, and a module
        extension on the left of it. Nothing here parses the entry point; it only
        has to be non-empty, because what makes the string unusable is the comma
        being significant to the receiving program and to nothing else.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [string[]] $Argument
    )

    if ($null -eq $Argument) { return $false }

    foreach ($token in @($Argument)) {
        if ([string]::IsNullOrWhiteSpace($token)) { continue }

        $comma = $token.IndexOf(',')
        if ($comma -lt 1) { continue }
        if ($comma -ge ($token.Length - 1)) { continue }

        $module = $token.Substring(0, $comma)
        $extension = $null
        try { $extension = [System.IO.Path]::GetExtension($module) } catch { $extension = $null }
        if ([string]::IsNullOrWhiteSpace($extension)) { continue }

        if ($script:RemovalEntryPointExtension -contains $extension.ToLowerInvariant()) { return $true }
    }

    $false
}

function ConvertTo-RemovalMsiExecCommand {
    <#
        The ONE rewrite this project does, because MsiExec's uninstall form is
        documented and mechanical rather than guessed:

            MsiExec.exe /I{GUID}   ->   msiexec.exe /X{GUID} /qn /norestart

        Measured across this machine's 140 uninstall entries: 28 keys write /X,
        27 write /I and one writes '/i {GUID} AI_UNINSTALLER_CTP=1'. /I means
        "install or repair" and is what a lot of installers leave in the key; run
        as written it would REPAIR the product rather than remove it, which is
        the reason the rewrite exists at all.

        Any trailing NAME=VALUE public properties are preserved -- that last entry
        is an Advanced Installer package whose property tells its custom action
        which mode to run in, and dropping it would change what the uninstall
        does.

        Returns $null when the string carries no product GUID; the caller then
        refuses the plan rather than inventing one.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $CommandString,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [string[]] $Argument
    )

    $match = [regex]::Match([string] $CommandString, $script:RemovalGuidPattern)
    if (-not $match.Success) { return $null }

    $guid = $match.Value

    $rewritten = New-Object System.Collections.Generic.List[string]
    $rewritten.Add("/X$guid")
    $rewritten.Add('/qn')
    $rewritten.Add('/norestart')

    $preserved = New-Object System.Collections.Generic.List[string]
    foreach ($token in @($Argument)) {
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        if ($token -match '^[A-Za-z_][A-Za-z0-9_.]*=') {
            $rewritten.Add($token)
            $preserved.Add($token)
        }
    }

    # System32\msiexec.exe is correct for a 32-bit product too: msiexec is the
    # Windows Installer client and there is only one of it.
    $executable = Join-Path -Path ([Environment]::GetEnvironmentVariable('SystemRoot')) -ChildPath 'System32\msiexec.exe'

    [pscustomobject]@{
        Executable    = $executable
        Argument      = [string[]] @($rewritten.ToArray())
        ProductCode   = $guid
        PreservedName = [string[]] @($preserved.ToArray())
    }
}

#endregion

#region Route: Appx

function Read-RemovalAppxInventory {
    <#
        Fills the per-pipeline Appx cache, once, on first use. Each of the three
        reads records its own failure separately, because they fail for different
        reasons and mean different things:

          User        Get-AppxPackage. Works un-elevated. A failure here means the
                      package list could not be read at all, and NOTHING can be
                      concluded about whether the app is still installed.
          Provisioned Get-AppxProvisionedPackage -Online. Needs elevation just to
                      READ (docs\STATE.md Q3) and opens a DISM servicing session,
                      so it can also fail legitimately while Windows Update is
                      mid-install. Its failure is the normal un-elevated case.
          AllUsers    Get-AppxPackage -AllUsers. Needs elevation. Recorded only.

        A failure is stored as a message, never as an empty list: an empty list
        would read as "not installed", which is this project's signature bug.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Cache
    )

    if ($Cache.ContainsKey('Loaded')) { return }
    $Cache['Loaded'] = $true

    $Cache['User'] = @()
    $Cache['UserFailure'] = $null
    try { $Cache['User'] = @(Get-OemAppxPackageItem) }
    catch { $Cache['UserFailure'] = (Get-OptimizerInnerException -Exception $_.Exception).Message.Trim() }

    $Cache['Provisioned'] = @()
    $Cache['ProvisionedFailure'] = $null
    try { $Cache['Provisioned'] = @(Get-OemProvisionedAppxItem) }
    catch { $Cache['ProvisionedFailure'] = (Get-OptimizerInnerException -Exception $_.Exception).Message.Trim() }

    $Cache['AllUsers'] = @()
    $Cache['AllUsersFailure'] = $null
    try { $Cache['AllUsers'] = @(Get-AppxPackage -AllUsers -ErrorAction Stop) }
    catch { $Cache['AllUsersFailure'] = (Get-OptimizerInnerException -Exception $_.Exception).Message.Trim() }
}

function Add-RemovalAppxRoute {
    <#
        The Finding's Id is the package FAMILY name. That is not what removal
        takes, and the two Appx registrations are two different things:

          per-user      needs the package FULL name, and clears it for the person
                        running the tool only.
          provisioned   is a different call with a different identifier, and
                        removing it does not touch any existing user's copy --
                        it stops the package being installed into NEW accounts.

        So an item registered both ways is ONE Finding with TWO steps, which is
        the case docs\handoff\02-oem-detector.report.md describes. Copilot on this
        machine goes further: three registrations, of which the third (a Win32
        uninstall key) is a separate Finding on a separate route. They are not
        merged; see the report.

        Scope reaches the preview in words, because "removes it for you" and
        "stops it appearing for new user accounts" are different promises and a
        user is entitled to both, or neither, knowingly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder,
        [Parameter(Mandatory)] [hashtable] $Cache
    )

    $familyName = $Builder.FindingId
    if ([string]::IsNullOrWhiteSpace($familyName)) {
        Deny-RemovalPlan -Builder $Builder -Reason 'The Finding carries no identifier, so the package to act on cannot be named.'
        return
    }

    # The three registration reads are cached FOR ONE PIPELINE, not across calls:
    # a batch of five Appx findings would otherwise open five DISM servicing
    # sessions for the provisioned list, at 0.18 s each when it works. A cache
    # that outlived the call would be a stale verification, which is the one thing
    # a plan-time check must not be.
    Read-RemovalAppxInventory -Cache $Cache

    $userPackage  = $null
    $userReadable = ($null -eq $Cache['UserFailure'])
    $userFailure  = $Cache['UserFailure']
    if ($userReadable) {
        $userPackage = @(@($Cache['User']) | Where-Object {
            [string]::Equals([string](Get-OptimizerProperty -InputObject $_ -Name 'PackageFamilyName'), $familyName, [System.StringComparison]::OrdinalIgnoreCase)
        })
    }

    # Provisioned. Reading it needs elevation (docs\STATE.md Q3), so "not
    # readable" is the normal un-elevated case and must never read as "absent".
    $provisioned      = $null
    $provisionedState = 'Unverifiable'
    $provisionedNote  = $Cache['ProvisionedFailure']
    if ($null -eq $provisionedNote) {
        $provisionedMatch = @(@($Cache['Provisioned']) | Where-Object {
            [string]::Equals([string](Get-OptimizerProperty -InputObject $_ -Name 'PackageFamilyName'), $familyName, [System.StringComparison]::OrdinalIgnoreCase)
        })
        $provisioned      = $(if ($provisionedMatch.Count -gt 0) { $provisionedMatch[0] } else { $null })
        $provisionedState = $(if ($provisionedMatch.Count -gt 0) { 'Present' } else { 'Absent' })
    }

    # Other users' registrations. -AllUsers needs elevation too. This is recorded,
    # never acted on: nothing in v1 removes a package out of somebody else's
    # account.
    $otherUserState = 'Unverifiable'
    if ($null -eq $Cache['AllUsersFailure']) {
        $otherUserMatch = @(@($Cache['AllUsers']) | Where-Object {
            [string]::Equals([string](Get-OptimizerProperty -InputObject $_ -Name 'PackageFamilyName'), $familyName, [System.StringComparison]::OrdinalIgnoreCase)
        })
        $otherUserState = $(if ($otherUserMatch.Count -gt 0) { 'Present' } else { 'Absent' })
    }

    if (-not $userReadable) {
        $Builder.CurrentState = $script:RemovalStateUnverifiable
        Deny-RemovalPlan -Builder $Builder -Reason "The list of installed packages could not be read, so it is not known whether '$familyName' is still installed. $userFailure"
        return
    }

    $userCount = @($userPackage).Count
    $fullName  = $null
    if ($userCount -gt 0) {
        $fullName = [string](Get-OptimizerProperty -InputObject $userPackage[0] -Name 'Detail')
    }

    $Builder.RollbackData = [pscustomobject][ordered]@{
        PackageFamilyName        = $familyName
        PackageFullName          = $fullName
        Version                  = $(if ($userCount -gt 0) { [string](Get-OptimizerProperty -InputObject $userPackage[0] -Name 'Version') } else { $null })
        ProvisionedPackageName   = $(if ($null -ne $provisioned) { [string](Get-OptimizerProperty -InputObject $provisioned -Name 'Detail') } else { $null })
        ProvisionedState         = $provisionedState
        OtherUserRegistration    = $otherUserState
        Note                     = 'Removing an Appx package cannot be undone from anything recorded here. Reinstalling it means fetching it again from the Store or the Windows image.'
    }

    if ($userCount -lt 1 -and $provisionedState -ne 'Present') {
        # Nothing to do. If the provisioned side could not be read, say so rather
        # than claiming the package is gone everywhere.
        if ($provisionedState -eq 'Unverifiable') {
            Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateUnverifiable
            $Builder.Note.Add("This package is not registered for you. Whether it is still provisioned for new user accounts could not be checked without administrator rights$(if ($provisionedNote) { " ($provisionedNote)" } else { '' }).")
            return
        }
        Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateAlreadyGone
        $Builder.Note.Add('This package is no longer registered for you and is not provisioned for new user accounts. There is nothing to remove.')
        return
    }

    Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStatePresent

    if ($userCount -gt 0) {
        if ([string]::IsNullOrWhiteSpace($fullName)) {
            Deny-RemovalPlan -Builder $Builder -Reason "The package '$familyName' is registered for you, but its full package name could not be read, and per-user removal takes the full name rather than the family name."
            return
        }

        $null = $Builder.Step.Add((New-RemovalStep `
            -Kind $script:RemovalStepAppxRemove `
            -Description "Remove the app for your account only. Other user accounts on this PC keep their own copy." `
            -Target $fullName `
            -RequiresElevation $false `
            -ReverseHint 'Not reversible from anything recorded in this plan: the app would have to be installed again from the Store or the Windows image.'))
    }

    if ($provisionedState -eq 'Present') {
        $provisionedName = [string](Get-OptimizerProperty -InputObject $provisioned -Name 'Detail')
        if ([string]::IsNullOrWhiteSpace($provisionedName)) {
            $Builder.Note.Add('This app is also provisioned for new user accounts, but the provisioned package name could not be read, so that half cannot be planned.')
        }
        else {
            $Builder.RequiresElevation = $true
            $null = $Builder.Step.Add((New-RemovalStep `
                -Kind $script:RemovalStepAppxRemoveProvisioned `
                -Description "Remove the app from the Windows image, so it stops appearing for new user accounts. This does not touch any existing account's copy." `
                -Target $provisionedName `
                -RequiresElevation $true `
                -ReverseHint 'Not reversible from anything recorded in this plan: re-provisioning needs the original package.'))
        }
    }
    elseif ($provisionedState -eq 'Unverifiable') {
        $Builder.Note.Add("Whether this app is also provisioned for new user accounts could not be checked without administrator rights, so this plan covers your account only$(if ($provisionedNote) { " ($provisionedNote)" } else { '' }).")
    }

    if ($otherUserState -eq 'Present' -and $userCount -gt 0) {
        $Builder.Note.Add('This app is registered for more than one user account on this PC. Nothing here removes it from anybody else, by design.')
    }
    elseif ($otherUserState -eq 'Unverifiable') {
        $Builder.Note.Add('Whether other user accounts on this PC also have this app could not be checked without administrator rights.')
    }
}

#endregion

#region Route: RegistryUninstallString

function Add-RemovalUninstallStringRoute {
    <#
        The Finding's Id is the uninstall KEY PATH. The uninstall string is not on
        the Finding, and that is correct -- a scan result can be minutes or days
        old, so QuietUninstallString and then UninstallString are re-read from the
        key here, at plan time.

        Rules, and they are not negotiable:

          * the string is never handed to a shell; it is parsed into an
            executable plus an argument array (Split-RemovalCommandString);
          * MsiExec is the one string that is rewritten, because its uninstall
            form is documented;
          * every other installer's string is used UNMODIFIED. If
            QuietUninstallString exists the plan is silent; if only
            UninstallString exists it is used as written and the step is marked
            RequiresInteraction. No invented /S: a guessed silent switch that a
            given installer reads as something else is a removal nobody can
            predict;
          * a rundll32 string with a comma-joined entry point is REFUSED. It is
            the one shape this parser gets right as argv and still cannot deliver,
            because rundll32 re-reads the command line for itself. See
            Test-RemovalIsRunDll32.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder
    )

    $keyPath = $Builder.FindingId
    $provider = ConvertTo-RemovalRegistryProviderPath -Path $keyPath
    if ([string]::IsNullOrWhiteSpace($provider)) {
        Deny-RemovalPlan -Builder $Builder -Reason "The Finding's identifier '$keyPath' does not name a registry key in a hive this tool reads (HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER)."
        return
    }

    $Builder.RequiresElevation = (Test-RemovalHiveIsMachine -Path $provider)

    $state = Get-RemovalRegistryKeyState -Path $provider

    if ($state.Exists -eq $false) {
        # A success shape, not an error: the application has been uninstalled
        # since the scan.
        Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateAlreadyGone
        $Builder.RequiresElevation = $false
        $Builder.RollbackData = [pscustomobject][ordered]@{ KeyPath = $keyPath; Note = 'The uninstall key was already gone at plan time; nothing was captured.' }
        $Builder.Note.Add('This application is no longer registered on this PC. There is nothing to remove.')
        return
    }

    if ($null -eq $state.Exists) {
        $Builder.CurrentState = $script:RemovalStateUnverifiable
        Deny-RemovalPlan -Builder $Builder -Reason "The uninstall key '$keyPath' could not be read, so it is not known whether this application is still installed$(if ($state.Reason) { " ($($state.Reason))" } else { '' })."
        return
    }

    $names = @($state.ValueName)
    $usedName = $null
    $commandString = $null
    foreach ($candidate in 'QuietUninstallString', 'UninstallString') {
        if ($names -notcontains $candidate) { continue }
        $value = [string](Get-RemovalRegistryValue -Path $provider -Name $candidate)
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        $usedName = $candidate
        $commandString = $value
        break
    }

    $Builder.RollbackData = [pscustomobject][ordered]@{
        KeyPath         = $keyPath
        DisplayName     = [string](Get-RemovalRegistryValue -Path $provider -Name 'DisplayName')
        DisplayVersion  = $(if ($names -contains 'DisplayVersion') { [string](Get-RemovalRegistryValue -Path $provider -Name 'DisplayVersion') } else { $null })
        Publisher       = $(if ($names -contains 'Publisher') { [string](Get-RemovalRegistryValue -Path $provider -Name 'Publisher') } else { $null })
        InstallLocation = $(if ($names -contains 'InstallLocation') { [string](Get-RemovalRegistryValue -Path $provider -Name 'InstallLocation') } else { $null })
        UninstallValueName = $usedName
        UninstallString    = $commandString
        Note = 'Not reversible from anything recorded here. An uninstall is undone by installing the application again.'
    }

    if ($null -eq $usedName) {
        $Builder.CurrentState = $script:RemovalStatePresent
        Deny-RemovalPlan -Builder $Builder -Reason "The uninstall key '$keyPath' is present but carries no QuietUninstallString and no UninstallString, so there is no command to run. This tool does not invent one."
        return
    }

    $parsed = Split-RemovalCommandString -CommandString $commandString
    if ($null -eq $parsed -or [string]::IsNullOrWhiteSpace($parsed.Executable)) {
        $Builder.CurrentState = $script:RemovalStatePresent
        $why = $(if ($null -ne $parsed -and $parsed.Note) { " $($parsed.Note)" } else { '' })
        Deny-RemovalPlan -Builder $Builder -Reason "The uninstall command recorded for '$keyPath' could not be read as a program plus arguments, and this tool never hands an uninstall string to a shell.$why"
        return
    }

    # FAILS CLOSED ON rundll32 (docs\STATE.md Q17). Both signals, because either
    # alone can be dodged: the program is rundll32, AND an argument joins a module
    # to an entry point with a comma. rundll32 reads its own command line instead
    # of the argument array every other program here receives, so this is the one
    # shape whose plan would look correct and probably not be -- and a plan nobody
    # can predict from is worse than no plan at all.
    if ((Test-RemovalIsRunDll32 -Executable $parsed.Executable) -and
        (Test-RemovalHasEntryPointArgument -Argument $parsed.Argument)) {
        $Builder.CurrentState = $script:RemovalStatePresent
        Deny-RemovalPlan -Builder $Builder -Reason "The uninstaller registered for '$keyPath' runs Windows' rundll32 helper with a library and an entry point joined by a comma ('$commandString'), and rundll32 reads the original command line for itself rather than the separate arguments this tool would hand it -- so this tool cannot rebuild that command safely and will not try. Uninstall this one from Windows' own list instead: Settings, Apps, Installed apps."
        return
    }

    Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStatePresent

    $isMsi = Test-RemovalIsMsiExec -Executable $parsed.Executable
    $requiresInteraction = $false
    $executable = $parsed.Executable
    $argument   = [string[]] @($parsed.Argument)
    $description = $null

    if ($isMsi) {
        $rewritten = ConvertTo-RemovalMsiExecCommand -CommandString $commandString -Argument $argument
        if ($null -eq $rewritten) {
            $Builder.CurrentState = $script:RemovalStatePresent
            Deny-RemovalPlan -Builder $Builder -Reason "The uninstall key '$keyPath' names MsiExec but records no product code, so the documented /X rewrite cannot be applied and the string is not usable as written."
            return
        }
        $executable = $rewritten.Executable
        $argument   = $rewritten.Argument
        $description = "Uninstall through Windows Installer. The key records '$commandString'; that is rewritten to the documented uninstall form '/X$($rewritten.ProductCode) /qn /norestart' so it removes the product silently instead of repairing it."
        if (@($rewritten.PreservedName).Count -gt 0) {
            $description += " The installer property $($rewritten.PreservedName -join ', ') from the original string is kept."
        }
    }
    else {
        if ($usedName -eq 'QuietUninstallString') {
            $description = "Run the application's own uninstaller, using the silent command the application itself registered ($usedName). Nothing about the command is changed."
        }
        else {
            $requiresInteraction = $true
            $description = "Run the application's own uninstaller, exactly as the key records it ($usedName). This application registers no silent uninstall command, and this tool does not invent one, so its uninstaller will appear on screen and may ask questions."
        }
    }

    # The parser's note is only meaningful for a string used AS WRITTEN. The
    # MsiExec rewrite replaces the executable with Windows Installer's own path,
    # so "the executable named by the string could not be found on disk" -- which
    # is what the parser says for the bare 'MsiExec.exe' every one of these keys
    # records -- would be true and misleading in the same breath.
    if ($parsed.Note -and -not $isMsi) {
        $description += " Note: $($parsed.Note)."
        $Builder.Note.Add("The uninstall string for this application is an awkward shape: $($parsed.Note).")
    }

    $null = $Builder.Step.Add((New-RemovalStep `
        -Kind $script:RemovalStepProcessCommand `
        -Description $description `
        -Target $keyPath `
        -Executable $executable `
        -Argument $argument `
        -RequiresElevation $Builder.RequiresElevation `
        -RequiresInteraction $requiresInteraction `
        -ReverseHint 'Not reversible from anything recorded in this plan: undoing an uninstall means installing the application again.'))
}

#endregion

#region Route: PackageManagement

function Add-RemovalPackageManagementRoute {
    <#
        Nothing produces this. It is in the Finding contract's allowed
        RemovalMethod set and no detector ever assigns it (docs\STATE.md, Q1/Q2),
        so it is implemented as an EXPLICITLY unsupported route rather than
        deleted from the contract or quietly pretended to work.

        A route nothing produces still needs defined behaviour, because the GUI
        can hand this dispatcher a Finding deserialized from an old run log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder
    )

    $Builder.CurrentState = $script:RemovalStateUnverifiable
    Deny-RemovalPlan -Builder $Builder -Reason 'No detector in this project assigns the PackageManagement removal method, and the winget / PackageManagement removal path is unresolved research question Q2 in docs\STATE.md. This tool will not guess at it.'
}

#endregion

#region Route: StartupApproved

function Get-RemovalStartupApprovedPlanData {
    <#
        Resolves one StartupItem Finding to the StartupApproved record that Task
        Manager writes: which store, which value name, and what is in it now.

        Returns { StorePath; ValueName; Scope; ItemPath; ItemState; Refusal }.
        Refusal is a sentence when this entry has no approval-store
        representation, and a fabricated store entry is never invented in its
        place.

        The Run-key view table and the two Startup-folder store paths are read
        from Detectors\StartupItems.ps1's module-scope constants rather than
        restated. They are the measured mapping -- including the Run32 stores that
        WOW6432Node entries use -- and a second copy here is a second thing to get
        wrong.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder
    )

    $identifier = $Builder.FindingId
    $method     = $Builder.RemovalMethod

    if ($method -eq 'RegistryRunKey') {
        $separator = $identifier.IndexOf('::')
        if ($separator -lt 1) {
            return [pscustomobject]@{ Refusal = "The Finding's identifier '$identifier' is not in the '<run key path>::<value name>' form this tool records for a Run entry." }
        }

        $runKeyPath = $identifier.Substring(0, $separator)
        $valueName  = $identifier.Substring($separator + 2)

        $view = @($script:StartupRunKeyView | Where-Object {
            [string]::Equals([string](Get-OptimizerProperty -InputObject $_ -Name 'Path'), $runKeyPath, [System.StringComparison]::OrdinalIgnoreCase)
        })
        if ($view.Count -lt 1) {
            return [pscustomobject]@{ Refusal = "'$runKeyPath' is not one of the Run or RunOnce keys this tool reads, so there is no approval store for it." }
        }

        if ([bool](Get-OptimizerProperty -InputObject $view[0] -Name 'IsRunOnce' -Default $false)) {
            return [pscustomobject]@{ Refusal = "This is a RunOnce entry. RunOnce has no representation in the StartupApproved store at all -- Windows deletes the value once it has run, so there is nothing for Task Manager to switch off. Disabling it would mean deleting the registry value, and this version never deletes a Run value." }
        }

        $storePath = [string](Get-OptimizerProperty -InputObject $view[0] -Name 'ApprovalPath')
        if ([string]::IsNullOrWhiteSpace($storePath)) {
            return [pscustomobject]@{ Refusal = "'$runKeyPath' has no StartupApproved store, so this entry cannot be switched off the way Task Manager does. This tool does not fabricate a store entry." }
        }

        # Is the Run value still there?
        $runState  = Get-RemovalRegistryKeyState -Path $runKeyPath
        $itemState = $script:RemovalStateUnverifiable
        if ($runState.Exists -eq $true) {
            $itemState = $(if (@($runState.ValueName) -contains $valueName) { $script:RemovalStatePresent } else { $script:RemovalStateAlreadyGone })
        }
        elseif ($runState.Exists -eq $false) {
            $itemState = $script:RemovalStateAlreadyGone
        }

        return [pscustomobject]@{
            StorePath = $storePath
            ValueName = $valueName
            Scope     = [string](Get-OptimizerProperty -InputObject $view[0] -Name 'Scope')
            ItemPath  = $runKeyPath
            ItemState = $itemState
            Refusal   = $null
        }
    }

    # StartupItem + FileDelete: one shortcut file in a Startup folder. The store
    # is keyed on the BARE FILE NAME, extension included, with no path -- measured
    # 2026-08-26, docs\STATE.md Q9.
    $fileName = $null
    $parent   = $null
    try {
        $fileName = [System.IO.Path]::GetFileName($identifier)
        $parent   = [System.IO.Path]::GetDirectoryName($identifier)
    }
    catch {
        return [pscustomobject]@{ Refusal = "The Finding's identifier '$identifier' is not a usable file path." }
    }

    if ([string]::IsNullOrWhiteSpace($fileName) -or [string]::IsNullOrWhiteSpace($parent)) {
        return [pscustomobject]@{ Refusal = "The Finding's identifier '$identifier' is not a usable file path." }
    }

    $scope = $null
    foreach ($candidate in @(
        [pscustomobject]@{ Scope = 'User';    Path = [Environment]::GetFolderPath('Startup') }
        [pscustomobject]@{ Scope = 'Machine'; Path = [Environment]::GetFolderPath('CommonStartup') }
    )) {
        if ([string]::IsNullOrWhiteSpace($candidate.Path)) { continue }
        if (Test-OptimizerPathWithin -Path $identifier -Container $candidate.Path) { $scope = $candidate.Scope; break }
    }

    if ($null -eq $scope) {
        return [pscustomobject]@{ Refusal = "'$identifier' is not in either of this PC's Startup folders, so it has no StartupApproved record and cannot be switched off the way Task Manager does." }
    }

    $storePath = $script:StartupFolderApprovalPath[$scope]
    if ([string]::IsNullOrWhiteSpace($storePath)) {
        return [pscustomobject]@{ Refusal = "No StartupApproved store is known for the $scope Startup folder." }
    }

    $present = Test-OptimizerPathPresent -Path $identifier -PathType File
    $itemState = $script:RemovalStateUnverifiable
    if ($present -eq $true)  { $itemState = $script:RemovalStatePresent }
    if ($present -eq $false) { $itemState = $script:RemovalStateAlreadyGone }

    [pscustomobject]@{
        StorePath = $storePath
        ValueName = $fileName
        Scope     = $scope
        ItemPath  = $identifier
        ItemState = $itemState
        Refusal   = $null
    }
}

function ConvertTo-RemovalStartupExclusionCandidate {
    <#
        Presents a StartupItem Finding in the shape Get-OptimizerExclusionMatch
        reads, so the startup route can be gated against the same curated
        exclusion list the service route uses rather than against a second vendor
        list written here.

        The record is built through Detectors\StartupItems.ps1's own
        ConvertTo-StartupExclusionCandidate, not beside it: the field mapping that
        decides which curated rules can reach a startup entry is P2-C2a's, stated
        once.

        NAME is the startup entry's own name -- the Run VALUE name, or the leaf
        file name of a Startup-folder shortcut -- because that is what the startup
        detector puts there. DISPLAYNAME is the Finding's, which is what a curated
        registryDisplayName rule matches.

        PUBLISHER IS DELIBERATELY EMPTY, and the gate is weaker for it in a way
        worth stating rather than hiding. The service route resolves a publisher
        from the service key's own ImagePath, additively; there is no equivalent
        here that is cheap and certain, and P2-C2a's rule is that for an entry
        whose binary may be gone only registryDisplayName rules can ever match
        anyway -- the binary carrying the publisher is gone by definition. So this
        gate is a display-name gate, on purpose. An absent publisher means the
        publisher rules do not match; it never means "not that vendor".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder
    )

    $identifier = [string] $Builder.FindingId
    $name = $identifier

    if ($Builder.RemovalMethod -eq 'RegistryRunKey') {
        # '<run key path>::<value name>'. A malformed identifier keeps the whole
        # string as the name, which matches nothing -- and is refused a few lines
        # later for being malformed anyway.
        $separator = $identifier.IndexOf('::')
        if ($separator -ge 0) { $name = $identifier.Substring($separator + 2) }
    }
    else {
        $leaf = $null
        try { $leaf = [System.IO.Path]::GetFileName($identifier) } catch { $leaf = $null }
        if (-not [string]::IsNullOrWhiteSpace($leaf)) { $name = $leaf }
    }

    $displayName = [string] $Builder.DisplayName
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $name }

    ConvertTo-StartupExclusionCandidate -Publisher '' -StartupItem ([pscustomobject]@{
        Name        = $name
        DisplayName = $displayName
    })
}

function Add-RemovalStartupApprovedRoute {
    <#
        Both StartupItem routes -- a Run value and a Startup-folder shortcut --
        DISABLE rather than delete. The StartupApproved store is what Task Manager
        writes; it is reversible from twelve bytes, and the least destructive
        action that achieves the user's goal is the one to plan. Nothing here
        deletes a Run value or a .lnk.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ProtectedPath,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ExclusionEntry
    )

    # THE LAST GATE for startup entries: the 'security' exclusion class, whatever
    # the Finding says (docs\STATE.md Q15). The service route has had this since
    # P3-C1; this route did not, so handed a StartupItem finding naming an
    # antivirus product it would have planned a disable. No detector produces one
    # -- and this gate exists precisely so that nothing has to rely on that.
    #
    # FIRST, before the store is even resolved. A finding for security software
    # must be refused FOR BEING SECURITY SOFTWARE: refusing it three checks later
    # for a malformed run key would be the same outcome reached by luck, and the
    # sentence the user reads would say the wrong thing.
    #
    # 'security' ONLY, from the same $script:StartupOrphanProofServiceClass P2-C2a
    # pinned. Not 'driver' and not 'driver-utility': those are the detector's
    # business, and it has a measured orphan exemption for them that took a whole
    # chunk to get right. A gate here that refused every protected class would
    # silently undo it.
    #
    # And no orphan exemption, ever. 'security' beats a proved orphan
    # unconditionally, because the orphan proof is the unreliable part --
    # anti-tamper minifilters hide binaries from enumeration -- and the cost of
    # getting it wrong is offering to switch off live antivirus.
    $exclusion = Get-OptimizerExclusionMatch -ExclusionEntry $ExclusionEntry `
        -InstalledApp (ConvertTo-RemovalStartupExclusionCandidate -Builder $Builder)

    if ($null -ne $exclusion) {
        $class = [string](Get-OptimizerProperty -InputObject $exclusion -Name 'Class')
        if ($script:StartupOrphanProofServiceClass -contains $class) {
            Deny-RemovalPlan -Builder $Builder -Reason "'$($Builder.DisplayName)' matches the '$class' class on the shared exclusion list (entry '$([string](Get-OptimizerProperty -InputObject $exclusion -Name 'Id'))'). This tool never switches off a startup entry belonging to security software, whatever produced the finding: the evidence that would say it is safe to touch is the same evidence tamper protection is designed to hide."
            return
        }
    }

    $data = Get-RemovalStartupApprovedPlanData -Builder $Builder
    if ($data.Refusal) {
        Deny-RemovalPlan -Builder $Builder -Reason $data.Refusal
        return
    }

    # The last gate. A Startup-folder Finding names a file, and a Finding is just
    # data -- it can arrive from a run log or a GUI naming anything at all.
    if ($Builder.RemovalMethod -eq 'FileDelete') {
        $refusal = Get-RemovalProtectedPathRefusal -Path $data.ItemPath -ProtectedPath $ProtectedPath
        if ($refusal) {
            Deny-RemovalPlan -Builder $Builder -Reason $refusal
            return
        }
    }

    $Builder.RequiresElevation = (Test-RemovalHiveIsMachine -Path $data.StorePath)

    if ($data.ItemState -eq $script:RemovalStateAlreadyGone) {
        Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateAlreadyGone
        $Builder.RequiresElevation = $false
        $Builder.RollbackData = [pscustomobject][ordered]@{ ApprovalKeyPath = $data.StorePath; ValueName = $data.ValueName; Note = 'The startup entry was already gone at plan time; nothing was captured.' }
        $Builder.Note.Add('This startup entry is no longer on the PC. There is nothing to switch off.')
        return
    }

    if ($data.ItemState -eq $script:RemovalStateUnverifiable) {
        $Builder.CurrentState = $script:RemovalStateUnverifiable
        Deny-RemovalPlan -Builder $Builder -Reason "Whether '$($data.ItemPath)' is still on this PC could not be determined, so nothing is planned for it. Not being able to see something is never treated as it being gone."
        return
    }

    # The current bytes, read now. This is what a rollback writes back, and it is
    # read at plan time rather than at removal time because P3-C2's action log
    # must be able to restore a state that was actually observed.
    $storeState = Get-RemovalRegistryKeyState -Path $data.StorePath
    $existingBytes = $null
    $valueExisted  = $false

    if ($storeState.Exists -eq $true -and @($storeState.ValueName) -contains $data.ValueName) {
        $valueExisted  = $true
        $existingBytes = Get-RemovalRegistryValue -Path $data.StorePath -Name $data.ValueName
    }
    elseif ($null -eq $storeState.Exists) {
        $Builder.CurrentState = $script:RemovalStateUnverifiable
        Deny-RemovalPlan -Builder $Builder -Reason "The StartupApproved store '$($data.StorePath)' could not be read$(if ($storeState.Reason) { " ($($storeState.Reason))" } else { '' }), so the current state cannot be captured and nothing is planned."
        return
    }

    # Only byte 0 changes. Where a record exists the rest is preserved rather than
    # a timestamp being invented; where none exists, twelve bytes with the rest
    # zero -- the shape a disabled record has on this machine.
    $planned = New-Object 'System.Collections.Generic.List[int]'
    if ($valueExisted -and $null -ne $existingBytes -and @($existingBytes).Count -ge 1) {
        foreach ($byte in @($existingBytes)) { $null = $planned.Add([int] $byte) }
    }
    else {
        for ($index = 0; $index -lt $script:RemovalStartupApprovedValueLength; $index++) { $null = $planned.Add(0) }
    }
    $planned[0] = $script:RemovalStartupApprovedDisabledByte

    $previousBytes = $(if ($valueExisted) { [int[]] @(@($existingBytes) | ForEach-Object { [int] $_ }) } else { $null })

    $Builder.RollbackData = [pscustomobject][ordered]@{
        ApprovalKeyPath  = $data.StorePath
        ValueName        = $data.ValueName
        ValueKind        = 'Binary'
        ValueExisted     = $valueExisted
        PreviousByte     = $previousBytes
        PreviousHex      = ConvertTo-RemovalHexString -Byte $previousBytes
        StartupItemPath  = $data.ItemPath
        Scope            = $data.Scope
        Note             = $(if ($valueExisted) {
                                'To undo: write these exact bytes back to this value.'
                            } else {
                                'To undo: delete this value. It did not exist before, and Windows treats a missing StartupApproved record as enabled.'
                            })
    }

    Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStatePresent -IsReversible $true

    $what = $(if ($Builder.RemovalMethod -eq 'RegistryRunKey') { 'registry startup entry' } else { 'Startup folder shortcut' })

    $null = $Builder.Step.Add((New-RemovalStep `
        -Kind $script:RemovalStepRegistryValueWrite `
        -Description "Switch this $what off the way Task Manager's Startup tab does, by writing 0x$('{0:X2}' -f $script:RemovalStartupApprovedDisabledByte) into the first byte of its StartupApproved record. Nothing is deleted: the $what itself stays exactly where it is, and Windows simply stops running it at logon." `
        -Target "$($data.StorePath)::$($data.ValueName)" `
        -RequiresElevation $Builder.RequiresElevation `
        -ReverseHint $(if ($valueExisted) { "Write the previous bytes ($(ConvertTo-RemovalHexString -Byte $previousBytes)) back to this value." } else { 'Delete this value; it did not exist before.' }) `
        -Detail ([pscustomobject][ordered]@{
            ValueKind    = 'Binary'
            PlannedByte  = [int[]] @($planned.ToArray())
            PlannedHex   = ConvertTo-RemovalHexString -Byte @($planned.ToArray())
            PreviousByte = $previousBytes
            ValueExisted = $valueExisted
        })))
}

#endregion

#region Route: ScheduledTask

function Add-RemovalScheduledTaskRoute {
    <#
        DISABLE, never unregister. Disabling is reversible from one boolean;
        unregistering is only reversible from the task's XML.

        The XML and the prior enabled state are captured anyway, because it is
        cheap, because the detector already reads task XML through the
        Schedule.Service COM API, and because it is the datum P3-C2 would need if
        unregistering ever became a route.

        The prior state has to be able to express a task that is ENABLED with
        every trigger individually switched off: P2-C2 measured 6 of this
        machine's 19 apparently-disabled tasks in exactly that shape, and a
        rollback that restored only the task-level boolean would silently
        re-enable them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder
    )

    $taskPath = $Builder.FindingId
    if ([string]::IsNullOrWhiteSpace($taskPath)) {
        Deny-RemovalPlan -Builder $Builder -Reason 'The Finding carries no task path, so the scheduled task to act on cannot be named.'
        return
    }

    # The last gate, in code. Tasks under \Microsoft\Windows\ are OS components,
    # whatever a Finding says.
    if ($taskPath.StartsWith($script:StartupProtectedTaskNamespace, [System.StringComparison]::OrdinalIgnoreCase)) {
        Deny-RemovalPlan -Builder $Builder -Reason "'$taskPath' is in the \Microsoft\Windows\ task namespace, which holds Windows' own scheduled tasks. This tool never disables one, whatever produced the finding."
        return
    }

    # The task's own folder and leaf, so GetTask is asked an unambiguous question.
    # Both are needed anyway for the "gone or merely out of reach" distinction
    # below.
    $folderPath = $null
    $taskName   = $null
    try {
        $folderPath = [System.IO.Path]::GetDirectoryName($taskPath)
        $taskName   = [System.IO.Path]::GetFileName($taskPath)
    }
    catch { $folderPath = $null; $taskName = $null }
    if ([string]::IsNullOrWhiteSpace($folderPath)) { $folderPath = '\' }
    if ([string]::IsNullOrWhiteSpace($taskName)) {
        Deny-RemovalPlan -Builder $Builder -Reason "The Finding's identifier '$taskPath' does not name a scheduled task."
        return
    }

    $service = $null
    $task    = $null
    $missing = $false
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        try {
            $task = $service.GetFolder($folderPath).GetTask($taskName)
        }
        catch {
            # GetTask throws for a task that is not there and for one that cannot
            # be read; only the first is AlreadyGone, so the two are told apart by
            # asking the folder to list itself.
            $missing = $true
        }
    }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        $Builder.CurrentState = $script:RemovalStateUnverifiable
        Deny-RemovalPlan -Builder $Builder -Reason "The Task Scheduler service could not be reached, so it is not known whether '$taskPath' still exists ($($inner.Message))."
        return
    }

    try {
        if ($missing) {
            $listed = $false
            try {
                # 1 = TASK_ENUM_HIDDEN, the same flag the detector uses.
                $null = $service.GetFolder($folderPath).GetTasks(1)
                $listed = $true
            }
            catch { $listed = $false }

            if ($listed) {
                Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateAlreadyGone
                $Builder.RollbackData = [pscustomobject][ordered]@{ TaskPath = $taskPath; Note = 'The task was already gone at plan time; nothing was captured.' }
                $Builder.Note.Add('This scheduled task no longer exists on this PC. There is nothing to disable.')
            }
            else {
                $Builder.CurrentState = $script:RemovalStateUnverifiable
                Deny-RemovalPlan -Builder $Builder -Reason "'$taskPath' could not be read and the folder that should contain it could not be listed either, so it is not known whether the task is gone or merely out of reach at this privilege level."
            }
            return
        }

        $enabled  = $null
        $xml      = $null
        try {
            $enabled = [bool] $task.Enabled
            $xml     = [string] $task.Xml
        }
        catch {
            $inner = Get-OptimizerInnerException -Exception $_.Exception
            $Builder.CurrentState = $script:RemovalStateUnverifiable
            Deny-RemovalPlan -Builder $Builder -Reason "'$taskPath' exists but its definition could not be read, so its current state cannot be captured and nothing is planned ($($inner.Message))."
            return
        }

        # Per-trigger state, through the DOM by LocalName -- the task XML carries a
        # default namespace, and property access throws under strict mode for a
        # task with no <Triggers> element at all.
        $triggers = New-Object System.Collections.Generic.List[psobject]
        $document = $null
        try { $document = [xml] $xml } catch { $document = $null }
        if ($null -ne $document) {
            foreach ($trigger in @(Get-StartupTaskTrigger -Document $document)) {
                $null = $triggers.Add([pscustomobject]@{ Type = $trigger.Name; Enabled = [bool] $trigger.Enabled })
            }
        }

        $anyTriggerEnabled = @($triggers | Where-Object { $_.Enabled }).Count -gt 0

        $Builder.RollbackData = [pscustomobject][ordered]@{
            TaskPath    = $taskPath
            WasEnabled  = $enabled
            Trigger     = [psobject[]] @($triggers.ToArray())
            TaskXml     = $xml
            Note        = 'To undo: set the task Enabled again AND restore each trigger''s own Enabled flag. A task can be enabled with every trigger switched off, and restoring only the task-level flag would re-enable it.'
        }

        $Builder.RequiresElevation = $true

        if (-not $enabled) {
            Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateChanged
            $Builder.RequiresElevation = $false
            $Builder.Note.Add('This scheduled task is already disabled. There is nothing to do.')
            return
        }

        if (-not $anyTriggerEnabled -and $triggers.Count -gt 0) {
            Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateChanged -IsReversible $true
            $Builder.Note.Add('This task is still enabled, but every one of its triggers has since been switched off individually, so it no longer starts with Windows. Disabling the task itself would still be a change, and the previous state recorded here can put it back exactly as it is now.')
        }
        else {
            Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStatePresent -IsReversible $true
        }

        $null = $Builder.Step.Add((New-RemovalStep `
            -Kind $script:RemovalStepScheduledTaskDisable `
            -Description 'Disable the scheduled task. The task, its schedule and everything it would have run stay exactly as they are; Task Scheduler simply stops starting it. It is not unregistered, because unregistering can only be undone from the task definition, and disabling can be undone from a single switch.' `
            -Target $taskPath `
            -RequiresElevation $true `
            -ReverseHint 'Enable the task again, then restore each trigger''s own Enabled flag from the trigger list recorded in this plan.' `
            -Detail ([pscustomobject][ordered]@{
                WasEnabled = $enabled
                Trigger    = [psobject[]] @($triggers.ToArray())
            })))
    }
    finally {
        if ($null -ne $service) {
            try { $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($service) } catch { }
        }
    }
}

#endregion

#region Route: ServiceStartupType

function Test-RemovalServiceKeyWritable {
    <#
        Can this service key be reconfigured, read-only?

        Some services cannot be changed even elevated -- TrustedInstaller-owned
        and protected ones. The honest read-only proxy is the service key's own
        ACL: if Administrators hold no write access to the key, an elevated
        Set-Service would not get one either.

        Tri-state, and it means what it says: $true the key's ACL grants
        Administrators write access, $false it does not, $null the ACL itself
        could not be read. $null is Unverifiable, never a guess at Present.

        This is a PROXY and the report says so. The authoritative answer is the
        service's SCM security descriptor, and reading that means sc.exe, which
        this chunk does not call.

        Read through Microsoft.Win32.Registry rather than Get-Acl. Not style:
        Get-Acl lives in Microsoft.PowerShell.Security, and that module fails to
        load outright when a Windows PowerShell 5.1 process inherits PowerShell
        7's PSModulePath -- which is exactly what happens when the engine is
        driven from a PS7 host, as this project's own test runner does. The
        failure is a CommandNotFoundException, which this function would dutifully
        report as "cannot tell" for every service on every machine. The .NET call
        has no module to fail to load.

        Rules are asked for as SecurityIdentifier, so no name translation is
        needed -- Translate() reaches out to a domain controller on a joined
        machine and can hang.
    #>
    [CmdletBinding()]
    [OutputType([Nullable[bool]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $hive   = $null
    $subKey = $null
    foreach ($prefix in @(
        [pscustomobject]@{ Text = 'HKLM:\'; Hive = [Microsoft.Win32.Registry]::LocalMachine }
        [pscustomobject]@{ Text = 'HKCU:\'; Hive = [Microsoft.Win32.Registry]::CurrentUser }
    )) {
        if ($Path.StartsWith($prefix.Text, [System.StringComparison]::OrdinalIgnoreCase)) {
            $hive   = $prefix.Hive
            $subKey = $Path.Substring($prefix.Text.Length)
            break
        }
    }
    if ($null -eq $hive -or [string]::IsNullOrWhiteSpace($subKey)) { return $null }

    $administrators = $null
    try {
        $administrators = (New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)).Value
    }
    catch { return $null }

    $writeRights = [int][System.Security.AccessControl.RegistryRights]::SetValue
    $key = $null

    try {
        $key = $hive.OpenSubKey($subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        if ($null -eq $key) { return $null }

        $security = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        foreach ($rule in $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if ([string] $rule.IdentityReference.Value -ne $administrators) { continue }
            if ((([int] $rule.RegistryRights) -band $writeRights) -ne 0) { return [Nullable[bool]] $true }
        }
    }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        Write-Verbose "Could not read the permissions of '$Path': $($inner.Message)"
        return $null
    }
    finally {
        if ($null -ne $key) { try { $key.Close() } catch { } }
    }

    [Nullable[bool]] $false
}

function Add-RemovalServiceRoute {
    <#
        Startup type only. NEVER delete a service, NEVER stop a running one in
        v1 -- docs\STATE.md: services are flag-for-review only, because the blast
        radius is higher than a Run key.

        The previous startup type comes from the registry Start value rather than
        from a cmdlet: Get-Service's StartType does not report delayed-auto the
        same way under Windows PowerShell 5.1 and PowerShell 7, and the previous
        state is precisely what a rollback restores.

        Every Service Finding is RequiresConsent, unconditionally. The plan COPIES
        that from the Finding rather than deciding it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ExclusionEntry
    )

    $serviceName = $Builder.FindingId
    if ([string]::IsNullOrWhiteSpace($serviceName)) {
        Deny-RemovalPlan -Builder $Builder -Reason 'The Finding carries no service name, so the service to act on cannot be named.'
        return
    }

    $keyPath = "$($script:StartupServiceRoot)\$serviceName"
    $Builder.RequiresElevation = $true

    $state = Get-RemovalRegistryKeyState -Path $keyPath

    if ($state.Exists -eq $false) {
        Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateAlreadyGone
        $Builder.RequiresElevation = $false
        $Builder.RollbackData = [pscustomobject][ordered]@{ ServiceName = $serviceName; KeyPath = $keyPath; Note = 'The service was already gone at plan time; nothing was captured.' }
        $Builder.Note.Add('This service is no longer registered on this PC. There is nothing to change.')
        return
    }

    if ($null -eq $state.Exists) {
        $Builder.CurrentState = $script:RemovalStateUnverifiable
        Deny-RemovalPlan -Builder $Builder -Reason "The service key '$keyPath' could not be read, so the service's current startup type is unknown and nothing is planned$(if ($state.Reason) { " ($($state.Reason))" } else { '' })."
        return
    }

    $displayName = [string](Get-RemovalRegistryValue -Path $keyPath -Name 'DisplayName')
    if ([string]::IsNullOrWhiteSpace($displayName) -or $displayName.StartsWith('@')) { $displayName = $serviceName }

    # THE LAST GATE for services: the 'security' exclusion class, whatever the
    # Finding says. The same set P2-C2a pinned as the one a proved orphan never
    # beats, and for the same reason -- anti-tamper minifilters hide binaries from
    # enumeration, so the orphan proof is exactly what is unreliable here, and the
    # cost of being wrong is offering to disable live antivirus.
    #
    # The publisher is resolved ADDITIVELY, exactly as P2-C2a locked it
    # (docs\STATE.md 2026-08-26, "a resolved identity may only ever ADD an
    # exclusion, never remove one"): the match runs first with the version
    # resource's CompanyName, and the Authenticode signer is consulted only where
    # that found nothing. Preferring the signer would be wrong in a measured way
    # -- NvContainerLocalSystem is signed by the WHQL attestation publisher rather
    # than by NVIDIA -- and here a LOST exclusion means offering to disable
    # security software.
    $imagePath  = [string](Get-RemovalRegistryValue -Path $keyPath -Name 'ImagePath')
    $targetPath = Get-StartupTargetPath -Command $imagePath

    $exclusion = Get-OptimizerExclusionMatch -ExclusionEntry $ExclusionEntry -InstalledApp (
        New-InstalledApp -Source 'Service' -Id $serviceName -Name $serviceName -DisplayName $displayName `
            -Publisher ([string](Get-StartupTargetCompany -Path $targetPath)))

    if ($null -eq $exclusion) {
        $resolvedPublisher = [string](Get-StartupTargetPublisher -Path $targetPath)
        if (-not [string]::IsNullOrWhiteSpace($resolvedPublisher)) {
            $exclusion = Get-OptimizerExclusionMatch -ExclusionEntry $ExclusionEntry -InstalledApp (
                New-InstalledApp -Source 'Service' -Id $serviceName -Name $serviceName -DisplayName $displayName `
                    -Publisher $resolvedPublisher)
        }
    }

    if ($null -ne $exclusion) {
        $class = [string](Get-OptimizerProperty -InputObject $exclusion -Name 'Class')
        if ($script:StartupOrphanProofServiceClass -contains $class) {
            Deny-RemovalPlan -Builder $Builder -Reason "'$displayName' matches the '$class' class on the shared exclusion list (entry '$([string](Get-OptimizerProperty -InputObject $exclusion -Name 'Id'))'). This tool never changes the startup type of security software, whatever produced the finding: the evidence that would say it is safe to touch is the same evidence tamper protection is designed to hide."
            return
        }
    }

    $startValue = Get-RemovalRegistryValue -Path $keyPath -Name 'Start'
    if ($null -eq $startValue) {
        $Builder.CurrentState = $script:RemovalStateUnverifiable
        Deny-RemovalPlan -Builder $Builder -Reason "The service key '$keyPath' is present but its Start value could not be read, so the current startup type is unknown and nothing is planned."
        return
    }

    $start = [int] $startValue
    $delayed = Get-RemovalRegistryValue -Path $keyPath -Name 'DelayedAutostart'
    $isDelayed = ($null -ne $delayed -and ([int] $delayed) -ne 0)

    # WHETHER THE VALUE WAS THERE AT ALL, separately from what it said. This is
    # the same distinction StartupApproved's ValueExisted already draws, and it is
    # needed for the same reason: PreviousDelayedAutostart is a DERIVED boolean,
    # so its $false means either "the value was present and 0" or "the key had no
    # such value", and those two need different undos -- write 0 back, or write
    # nothing and leave the key as Windows had it.
    #
    # Captured now rather than with the executor chunk that will use it because
    # THE LEDGER IS PERMANENT. A service action recorded today without this flag
    # can never gain it: the record is written once, appended to a file that is
    # never rewritten, and a later build reading it back has no way to recover
    # what the key looked like at the moment of the change.
    $delayedExisted = ($null -ne $delayed)

    $previousName = $script:RemovalServiceStartName[$start]
    if ([string]::IsNullOrWhiteSpace($previousName)) { $previousName = "Unknown (Start = $start)" }
    if ($start -eq $script:RemovalServiceStartAutomatic -and $isDelayed) { $previousName = 'Automatic (Delayed Start)' }

    $Builder.RollbackData = [pscustomobject][ordered]@{
        ServiceName              = $serviceName
        DisplayName              = $displayName
        KeyPath                  = $keyPath
        PreviousStartValue       = $start
        PreviousStartupType      = $previousName
        # ADDITIVE. PreviousDelayedAutostart keeps its exact current meaning and
        # its exact current value, because Executor.ps1 reads it and this chunk
        # does not touch the executor: its rule -- restore the value only where
        # the record says it was switched ON -- stays as it is. The new field
        # sits beside it so a later chunk can tell the two $false cases apart
        # without the ledger having to be re-read against a machine that has
        # since changed.
        PreviousDelayedAutostart = $isDelayed
        DelayedAutostartExisted  = $delayedExisted
        Note                     = "To undo: set Start back to $start$(if ($isDelayed) { ' and DelayedAutostart back to 1' } else { '' }). Nothing else about the service is changed by this plan."
    }

    # The startup type the Finding described comes first: a service that no longer
    # starts automatically is not the startup item that was flagged, and nothing
    # is planned for it whatever its permissions look like.
    if ($start -eq $script:RemovalServiceStartDisabled) {
        Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateChanged
        $Builder.RequiresElevation = $false
        $Builder.Note.Add('This service is already set to Disabled. There is nothing to change.')
        return
    }

    if ($start -ne $script:RemovalServiceStartAutomatic) {
        # Do LESS, not more: this plan does not disable a manual-start service
        # that nobody reviewed in that state.
        Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateChanged
        $Builder.RequiresElevation = $false
        $Builder.Note.Add("This service no longer starts automatically -- its startup type is now $previousName -- so it is not the startup item that was flagged. Nothing is planned for it; if you still want it disabled, that is a fresh decision to make about a different thing.")
        return
    }

    # Some services cannot be reconfigured even elevated. Probed read-only, and
    # tri-state: $null is 'Unverifiable', never a guess at 'Present'.
    $writable = Test-RemovalServiceKeyWritable -Path $keyPath

    if ($writable -eq $false) {
        $Builder.CurrentState = $script:RemovalStateUnverifiable
        Deny-RemovalPlan -Builder $Builder -Reason "The registry key for '$displayName' does not grant administrators permission to change it, so its startup type cannot be changed even with administrator rights. Services owned by the system (TrustedInstaller) are in this state by design."
        return
    }

    if ($null -eq $writable) {
        Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateUnverifiable -IsReversible $true
        $Builder.Note.Add('Whether this service can be reconfigured at all could not be checked: its key permissions could not be read. Some services are owned by the system and refuse a startup-type change even for an administrator, so this step may simply fail.')
    }
    else {
        Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStatePresent -IsReversible $true
    }

    $null = $Builder.Step.Add((New-RemovalStep `
        -Kind $script:RemovalStepServiceStartupType `
        -Description "Set the service's startup type to Disabled, so Windows stops starting it at boot. The service is not deleted and, if it happens to be running now, it is not stopped -- it simply does not come back after a restart." `
        -Target $serviceName `
        -RequiresElevation $true `
        -ReverseHint "Set the startup type back to $previousName." `
        -Detail ([pscustomobject][ordered]@{
            KeyPath             = $keyPath
            PreviousStartValue  = $start
            PreviousStartupType = $previousName
            PlannedStartValue   = $script:RemovalServiceStartDisabled
            PlannedStartupType  = $script:RemovalServiceStartName[$script:RemovalServiceStartDisabled]
        })))
}

#endregion

#region Route: JunkFileSet

function Add-RemovalJunkFileSetRoute {
    <#
        docs\handoff\07-junk-files.report.md section 7 is the contract, and four
        of its requirements belong to the plan:

          1. RE-CHECK THE IN-USE GATE PER FILE, at plan time. The scan's answer
             has a shelf life of minutes -- %TEMP% gained 16 files during one
             session's four scans.
          2. A VANISHED FILE IS SUCCESS, not failure. These are temp files; some
             of this set will be gone by the time anyone clicks anything.
          3. SizeBytes comes FROM THE FINDING, per file, as captured at scan time.
             It is the disk-size-before that docs\PLAN.md requires for the
             receipt, and by removal time a re-read may fail.
          4. NEVER A DIRECTORY. Only the paths in EligibleFile.

        One step, not 13,375: Kind FileDeleteSet, carrying the list plus the
        counts and the bytes. The preview shows counts, the location and a small
        sample, never the whole list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Builder,
        [Parameter(Mandatory)] [AllowNull()] $Finding,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ProtectedPath
    )

    $eligibleProperty = $Finding.PSObject.Properties['EligibleFile']
    if ($null -eq $eligibleProperty) {
        Deny-RemovalPlan -Builder $Builder -Reason "This finding does not carry the file list that 'FileDelete' on a JunkFile finding refers to. The identifier '$($Builder.FindingId)' is a curated location id, not a path, and this tool never deletes a location -- so without the list there is nothing it can act on. Re-run the scan."
        return
    }

    $locationPath = [string[]] @(@(Get-OptimizerProperty -InputObject $Finding -Name 'LocationPath' -Default @()) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $isSizeFloor  = [bool](Get-OptimizerProperty -InputObject $Finding -Name 'IsSizeFloor' -Default $false)

    # THE LAST GATE, and it has to reach every file: the detector gated the
    # LOCATION, and a Finding can arrive from a run log or a GUI naming anything
    # at all.
    #
    # Running the full directional check per file is correct and unaffordable --
    # measured at ~40 s for this machine's 20,000 eligible files, because each
    # call is ~28 nested PowerShell function invocations. So it is done in two
    # passes, which is equivalent and about fifty times cheaper:
    #
    #   1. Check each declared LOCATION with the full check. Cleared locations
    #      are normalised once into prefixes.
    #   2. Per file, if the file sits under a cleared location it is clear too,
    #      because containment is transitive: a path under a folder that neither
    #      is, contains, nor sits inside a protected path cannot do any of those
    #      three itself. Only a file that is NOT under a cleared location -- which
    #      is what a hand-built or tampered Finding produces -- pays for the full
    #      check.
    $separator = [string][System.IO.Path]::DirectorySeparatorChar
    $clearedPrefix = New-Object System.Collections.Generic.List[string]
    $refused = New-Object System.Collections.Generic.List[string]

    foreach ($location in $locationPath) {
        $refusal = Get-RemovalProtectedPathRefusal -Path $location -ProtectedPath $ProtectedPath
        if ($null -ne $refusal) {
            $null = $refused.Add($refusal)
            continue
        }
        $normalised = ConvertTo-OptimizerComparablePath -Path $location
        if ([string]::IsNullOrWhiteSpace($normalised)) { continue }
        if (-not $normalised.EndsWith($separator)) { $normalised += $separator }
        $null = $clearedPrefix.Add($normalised)
    }

    if ($refused.Count -gt 0) {
        Deny-RemovalPlan -Builder $Builder -Reason "$($refused[0]) A finding in this category must never name a location this tool is not allowed to touch, so none of its files are planned."
        return
    }

    $keep         = New-Object System.Collections.Generic.List[psobject]
    $keepBytes    = [long] 0
    $vanished     = 0
    $held         = 0
    $undetermined = 0

    foreach ($file in @($eligibleProperty.Value)) {
        if ($null -eq $file) { continue }
        $path = [string](Get-OptimizerProperty -InputObject $file -Name 'Path')
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        $normalisedFile = ConvertTo-OptimizerComparablePath -Path $path
        if ([string]::IsNullOrWhiteSpace($normalisedFile)) {
            # A path that will not normalise is one nothing may act on.
            $undetermined++
            continue
        }

        $cleared = $false
        foreach ($prefix in $clearedPrefix) {
            if ($normalisedFile.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { $cleared = $true; break }
        }

        if (-not $cleared) {
            $refusal = Get-RemovalProtectedPathRefusal -Path $path -ProtectedPath $ProtectedPath
            if ($null -ne $refusal) {
                if ($refused.Count -lt 5) { $null = $refused.Add($refusal) }
                continue
            }
        }

        # Presence FIRST, tri-state. Test-OptimizerFileInUse answers 'InUse' for a
        # file that is not there (FileNotFoundException derives from IOException),
        # and here the difference between "gone" and "held" decides whether this
        # is a success or a refusal.
        $present = Test-OptimizerPathPresent -Path $path -PathType File
        if ($present -eq $false) { $vanished++; continue }
        if ($null -eq $present)  { $undetermined++; continue }

        $verdict = Test-OptimizerFileInUse -Path $path
        if ($verdict -eq $script:OptimizerInUseHeld)         { $held++; continue }
        if ($verdict -ne $script:OptimizerInUseFree)          { $undetermined++; continue }

        # SizeBytes from the Finding, per file, as captured at scan time.
        $size = Get-OptimizerProperty -InputObject $file -Name 'SizeBytes' -Default 0
        $null = $keep.Add([pscustomobject]@{
            Path         = $path
            SizeBytes    = [long] $size
            LastWriteUtc = [string](Get-OptimizerProperty -InputObject $file -Name 'LastWriteUtc')
            LocationId   = [string](Get-OptimizerProperty -InputObject $file -Name 'LocationId')
        })
        $keepBytes += [long] $size
    }

    if ($refused.Count -gt 0) {
        Deny-RemovalPlan -Builder $Builder -Reason "$($refused[0]) A finding in this category must never name a file in one of your own folders, so none of its files are planned."
        return
    }

    # The per-file manifest lives on the STEP, not here as well. It is up to five
    # figures long, and carrying it twice doubled a single plan's JSON to 14 MB
    # when P3-C2 has to write that into a one-line log record. What a rollback
    # record needs from this route is the counts and the location: a deleted file
    # is not restorable from anything either copy could hold.
    $Builder.RollbackData = [pscustomobject][ordered]@{
        LocationId   = [string](Get-OptimizerProperty -InputObject $Finding -Name 'LocationId' -Default $Builder.FindingId)
        LocationPath = $locationPath
        FileCount    = $keep.Count
        TotalBytes   = $keepBytes
        IsSizeFloor  = $isSizeFloor
        FileManifest = "on the FileDeleteSet step, as Detail.File -- one record per file with the path, the size captured at scan time and the last-write time"
        Note         = 'Deleting a file cannot be undone from anything recorded here. The per-file sizes on the step are the disk-size-before capture the run receipt is built from, measured when the scan ran rather than re-read now, because by removal time a re-read may fail.'
    }

    # Elevation heuristic: anything outside the current user's profile needs it.
    # A guess, honestly labelled -- P3-C2 finds out for certain by trying.
    $profileRoot = [Environment]::GetFolderPath('UserProfile')
    $outsideProfile = 0
    foreach ($file in @($keep.ToArray())) {
        if (-not (Test-OptimizerPathWithin -Path $file.Path -Container $profileRoot)) { $outsideProfile++ }
    }
    $Builder.RequiresElevation = ($outsideProfile -gt 0)

    if ($keep.Count -lt 1) {
        Approve-RemovalPlan -Builder $Builder -CurrentState $script:RemovalStateAlreadyGone
        $Builder.RequiresElevation = $false
        $Builder.Note.Add("None of the files this finding listed can be removed now: $vanished are already gone, $held are open in another program and $undetermined could not be checked. That is the expected shape for temporary files.")
        return
    }

    $state = $(if ($vanished -gt 0 -or $held -gt 0 -or $undetermined -gt 0) { $script:RemovalStateChanged } else { $script:RemovalStatePresent })
    Approve-RemovalPlan -Builder $Builder -CurrentState $state

    if ($vanished -gt 0) {
        $Builder.Note.Add("$(Format-JunkCount -Count $vanished) of the files this finding listed have already gone since the scan. That is normal for temporary files and is not a problem.")
    }
    if ($held -gt 0 -or $undetermined -gt 0) {
        $Builder.Note.Add("$(Format-JunkCount -Count ($held + $undetermined)) are open in another program, or could not be checked, and are left alone. A file this tool cannot prove is free is never deleted.")
    }
    if ($isSizeFloor) {
        $Builder.Note.Add('The size in this plan is a floor, not a total: part of this location could not be read when the scan ran, so whatever is in it was neither counted nor listed.')
    }

    $sample = [string[]] @(@($keep.ToArray() | Select-Object -First $script:RemovalPreviewSampleCount) | ForEach-Object { $_.Path })

    # Chrome resolves to eleven folders on this machine, so the description names
    # how many rather than reciting them; the list itself is on Detail, and the
    # preview shows the first few. Target stays the precise thing -- the folders
    # the set was taken from -- because it is data, not prose.
    $where = $(if ($locationPath.Count -eq 1) { $locationPath[0] } else { "$($locationPath.Count) folders (listed in this plan)" })

    $null = $Builder.Step.Add((New-RemovalStep `
        -Kind $script:RemovalStepFileDeleteSet `
        -Description "Delete $(Format-JunkCount -Count $keep.Count) file$(if ($keep.Count -eq 1) { '' } else { 's' }), $(Format-JunkSize -Bytes $keepBytes) on disk now, from $where. Only these files: the folders themselves stay, and nothing is deleted that could not just now be proved present and not open in another program." `
        -Target ($locationPath -join '; ') `
        -RequiresElevation $Builder.RequiresElevation `
        -ReverseHint 'Not reversible. Deleted files are not sent to the Recycle Bin by this plan and are not recoverable from anything recorded in it.' `
        -Detail ([pscustomobject][ordered]@{
            LocationId        = [string](Get-OptimizerProperty -InputObject $Finding -Name 'LocationId' -Default $Builder.FindingId)
            LocationPath      = $locationPath
            File              = [psobject[]] @($keep.ToArray())
            FileCount         = $keep.Count
            TotalBytes        = $keepBytes
            VanishedCount     = $vanished
            InUseCount        = $held
            UndeterminedCount = $undetermined
            IsSizeFloor       = $isSizeFloor
            SamplePath        = $sample
        })))
}

#endregion

#region The preview renderer

function Format-RemovalPlanText {
    <#
        The dry run, in words. ONE renderer: Get-RemovalPlan calls this to fill in
        a plan's PreviewText, and Get-RemovalPreview calls it again so a plan read
        back out of a run log renders identically without the caller having to
        trust a stored string.

        House rules this text obeys, all of them locked elsewhere:
          * a JunkFile line says what is ON DISK NOW, never what will be freed.
            Nothing in this project says "free up", "reclaim" or "will save" --
            the receipt is derived from P3-C2's action log, not from a promise.
          * scope is stated in words, not implied.
          * SafetyLabel is printed, never re-derived.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [psobject] $Plan
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $displayName = [string](Get-OptimizerProperty -InputObject $Plan -Name 'DisplayName' -Default '(unnamed)')
    $label       = [string](Get-OptimizerProperty -InputObject $Plan -Name 'SafetyLabel' -Default '')
    $null = $lines.Add("$displayName -- $label")

    $null = $lines.Add("  Found by: $([string](Get-OptimizerProperty -InputObject $Plan -Name 'Category')) / $([string](Get-OptimizerProperty -InputObject $Plan -Name 'RemovalMethod')); planned as: $([string](Get-OptimizerProperty -InputObject $Plan -Name 'Route'))")

    $state = [string](Get-OptimizerProperty -InputObject $Plan -Name 'CurrentState')
    $stateText = switch ($state) {
        'Present'      { 'it is still on this PC, as described.' }
        'AlreadyGone'  { 'it is already gone. Nothing to do.' }
        'Changed'      { 'it is still on this PC but not in the state it was found in. See below.' }
        'Unverifiable' { 'its current state could not be read. Nothing is assumed either way.' }
        default        { "current state: $state." }
    }
    $null = $lines.Add("  Checked $(ConvertTo-RemovalUtcText -Value (Get-OptimizerProperty -InputObject $Plan -Name 'VerifiedUtc')): $stateText")

    if (-not [bool](Get-OptimizerProperty -InputObject $Plan -Name 'Supported' -Default $false)) {
        $null = $lines.Add("  NOTHING IS PLANNED FOR THIS ONE.")
        $null = $lines.Add("  Why: $([string](Get-OptimizerProperty -InputObject $Plan -Name 'UnsupportedReason'))")
    }
    else {
        $steps = @(Get-OptimizerProperty -InputObject $Plan -Name 'Step' -Default @())
        if ($steps.Count -lt 1) {
            $null = $lines.Add('  Nothing would be done.')
        }
        else {
            $number = 0
            foreach ($step in $steps) {
                $number++
                $null = $lines.Add("  Step ${number} of $($steps.Count) -- $([string](Get-OptimizerProperty -InputObject $step -Name 'Kind'))")
                $null = $lines.Add("    $([string](Get-OptimizerProperty -InputObject $step -Name 'Description'))")

                # A step whose Detail names its folders renders them one per line
                # instead of repeating a semicolon-joined Target that can be
                # eleven paths long. Target is still the precise field; this is
                # the readable rendering of it.
                $stepDetail   = Get-OptimizerProperty -InputObject $step -Name 'Detail'
                $locationPath = [string[]] @(Get-OptimizerProperty -InputObject $stepDetail -Name 'LocationPath' -Default @())
                if ($locationPath.Count -gt 0) {
                    foreach ($location in @($locationPath | Select-Object -First $script:RemovalPreviewSampleCount)) {
                        $null = $lines.Add("    In: $location")
                    }
                    if ($locationPath.Count -gt $script:RemovalPreviewSampleCount) {
                        $null = $lines.Add("    In: ... and $($locationPath.Count - $script:RemovalPreviewSampleCount) more folder(s); the full list is in the plan.")
                    }
                }
                else {
                    $null = $lines.Add("    On: $([string](Get-OptimizerProperty -InputObject $step -Name 'Target'))")
                }

                $executable = [string](Get-OptimizerProperty -InputObject $step -Name 'Executable')
                if (-not [string]::IsNullOrWhiteSpace($executable)) {
                    $arguments = @(Get-OptimizerProperty -InputObject $step -Name 'Argument' -Default @())
                    $null = $lines.Add("    Program: $executable")
                    if ($arguments.Count -gt 0) {
                        $number2 = 0
                        foreach ($argument in $arguments) {
                            $number2++
                            $null = $lines.Add("    Argument ${number2}: $argument")
                        }
                    }
                    else {
                        $null = $lines.Add('    Arguments: none')
                    }
                }

                $detail = $stepDetail
                if ($null -ne $detail) {
                    $sample = @(Get-OptimizerProperty -InputObject $detail -Name 'SamplePath' -Default @())
                    if ($sample.Count -gt 0) {
                        $count = [long](Get-OptimizerProperty -InputObject $detail -Name 'FileCount' -Default 0)
                        $null = $lines.Add("    For example: $($sample -join '; ')")
                        if ($count -gt $sample.Count) {
                            $null = $lines.Add("    ... and $(Format-JunkCount -Count ($count - $sample.Count)) more. The full list is in the plan, not in this summary.")
                        }
                        $null = $lines.Add('    That is what is on disk now, not a promise of space reclaimed.')
                    }
                    $plannedHex = [string](Get-OptimizerProperty -InputObject $detail -Name 'PlannedHex')
                    if (-not [string]::IsNullOrWhiteSpace($plannedHex)) {
                        $previousHex = ConvertTo-RemovalHexString -Byte (Get-OptimizerProperty -InputObject $detail -Name 'PreviousByte')
                        $null = $lines.Add("    Value now: $(if ([string]::IsNullOrWhiteSpace($previousHex)) { '(no value)' } else { $previousHex })")
                        $null = $lines.Add("    Value after: $plannedHex")
                    }
                }

                if ([bool](Get-OptimizerProperty -InputObject $step -Name 'RequiresInteraction' -Default $false)) {
                    $null = $lines.Add("    This one is not silent: the application's own uninstaller will appear and may ask questions.")
                }
                $null = $lines.Add("    To undo: $([string](Get-OptimizerProperty -InputObject $step -Name 'ReverseHint'))")
            }
        }
    }

    foreach ($note in @(Get-OptimizerProperty -InputObject $Plan -Name 'Note' -Default @())) {
        if ([string]::IsNullOrWhiteSpace($note)) { continue }
        $null = $lines.Add("  Note: $note")
    }

    $null = $lines.Add("  Administrator rights: $(if ([bool](Get-OptimizerProperty -InputObject $Plan -Name 'RequiresElevation' -Default $false)) { 'required' } else { 'not required' })")
    $null = $lines.Add("  Your explicit OK: $(if ([bool](Get-OptimizerProperty -InputObject $Plan -Name 'RequiresConsent' -Default $true)) { 'required before anything happens' } else { 'not required' })")
    $null = $lines.Add("  Can be undone: $(if ([bool](Get-OptimizerProperty -InputObject $Plan -Name 'IsReversible' -Default $false)) { 'yes, from the details recorded in this plan' } else { 'no' })")
    $null = $lines.Add('  This is a preview. Nothing on this PC has been changed.')

    [string[]] @($lines.ToArray())
}

#endregion

#region Public: the plan and the preview

function Get-RemovalPlan {
    <#
    .SYNOPSIS
        Returns the removal plan for a Finding. Plans only -- nothing is removed,
        disabled or written.

    .DESCRIPTION
        Routes a Finding on the PAIR (Category, RemovalMethod), verifies that the
        item is still there, and returns a Win11Optimizer.RemovalPlan describing
        exactly what would happen, as data: an ordered step list, the rollback
        material P3-C2 must capture before step 1, and the preview lines P4-C1
        renders.

        ONE INPUT, ONE PLAN, ALWAYS. It never throws for a bad Finding and never
        silently drops one: an object that fails Test-Finding produces a plan with
        Supported = $false carrying the validation problems as the reason, so a
        bad Finding in a batch of twenty does not cost you the other nineteen.
        Test-Finding's own documentation asks consumers to gate on it rather than
        trust the shape, because Findings arrive here deserialized from a run log
        or handed in by a GUI.

        An unrecognised (Category, RemovalMethod) pair fails CLOSED: route
        'Unsupported', with a reason, never a guess at the nearest mechanism.

        NOTHING HERE CHANGES THE STATE OF THE MACHINE. Every probe is a read.

    .PARAMETER Finding
        The Finding to plan for. Accepts pipeline input.

    .EXAMPLE
        (Invoke-JunkFileScan).Findings | Get-RemovalPlan | Get-RemovalPreview

    .EXAMPLE
        $plan = Get-RemovalPlan -Finding $finding
        $plan.Step | Format-Table Kind, Target, RequiresElevation
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $Finding
    )

    begin {
        # Resolved once per pipeline, not per Finding: the protected-path list
        # walks the shell's known folders and the drive table, and a batch of
        # twenty Findings would otherwise pay for it twenty times.
        $protectedPath = [psobject[]] @(Get-OptimizerProtectedPath)
        $appxCache = @{}
        $exclusionEntry = [psobject[]] @()
        try { $exclusionEntry = [psobject[]] @(Get-UnusedAppExclusionList) }
        catch {
            # A list that will not load must never read as "nothing is excluded".
            # It is not fatal here -- the other five routes do not use it -- but
            # the two routes that CAN reach security software refuse outright
            # rather than proceeding unprotected.
            Write-Warning "The shared exclusion list could not be loaded: $($_.Exception.Message). Service and startup findings will be refused rather than planned."
            $exclusionEntry = $null
        }
    }

    process {
        $verifiedUtc = [datetime]::UtcNow.ToString('o')

        # Assigned first and wrapped afterwards, NOT wrapped around the call.
        # Test-Finding -Detailed ends in `, $problems.ToArray()`, and the comma
        # preserves an empty array as ONE output item -- so
        # @(Test-Finding ... -Detailed).Count is 1 for a PERFECTLY VALID Finding
        # (an array containing an empty array) and also 1 for a broken one (an
        # array containing the seven problems). Both readings are wrong, and the
        # first would have refused every Finding on this machine. REVIEW.md
        # records the shape; this is its first appearance on a public API that
        # other code is told to gate on.
        $problemList = Test-Finding -InputObject $Finding -Detailed
        $problems = [string[]] @($problemList)

        if ($problems.Count -gt 0) {
            # Build the plan from whatever the object does carry, so the row is
            # still identifiable in a GUI, and say exactly what is wrong with it.
            $builder = New-RemovalPlanBuilder -Finding $Finding -Route $script:RemovalRouteUnsupported
            if ([string]::IsNullOrWhiteSpace($builder.DisplayName)) { $builder.DisplayName = '(invalid finding)' }
            Deny-RemovalPlan -Builder $builder -Reason "This finding does not satisfy the finding contract, so nothing is planned for it: $($problems -join ' ')"
            return (ConvertTo-RemovalPlan -Builder $builder -VerifiedUtc $verifiedUtc)
        }

        $key   = Get-RemovalRouteKey -Category $Finding.Category -RemovalMethod $Finding.RemovalMethod
        $route = $script:RemovalRouteTable[$key]

        if ([string]::IsNullOrWhiteSpace($route)) {
            $builder = New-RemovalPlanBuilder -Finding $Finding -Route $script:RemovalRouteUnsupported
            Deny-RemovalPlan -Builder $builder -Reason "Nothing in this tool knows how to act on a '$($Finding.Category)' finding whose removal method is '$($Finding.RemovalMethod)'. That combination has no route, and this tool will not guess at the nearest one."
            return (ConvertTo-RemovalPlan -Builder $builder -VerifiedUtc $verifiedUtc)
        }

        $builder = New-RemovalPlanBuilder -Finding $Finding -Route $route

        try {
            switch ($route) {
                $script:RemovalRouteAppx              { Add-RemovalAppxRoute -Builder $builder -Cache $appxCache }
                $script:RemovalRouteUninstallString   { Add-RemovalUninstallStringRoute -Builder $builder }
                $script:RemovalRoutePackageManagement { Add-RemovalPackageManagementRoute -Builder $builder }
                $script:RemovalRouteStartupApproved   {
                    if ($null -eq $exclusionEntry) {
                        Deny-RemovalPlan -Builder $builder -Reason 'The shared exclusion list could not be loaded, so this tool cannot tell whether this startup entry belongs to security software. A startup entry is never planned for without that check.'
                    }
                    else {
                        Add-RemovalStartupApprovedRoute -Builder $builder -ProtectedPath $protectedPath -ExclusionEntry $exclusionEntry
                    }
                }
                $script:RemovalRouteScheduledTask     { Add-RemovalScheduledTaskRoute -Builder $builder }
                $script:RemovalRouteServiceStartup    {
                    if ($null -eq $exclusionEntry) {
                        Deny-RemovalPlan -Builder $builder -Reason 'The shared exclusion list could not be loaded, so this tool cannot tell whether this service is security software. A service is never planned for without that check.'
                    }
                    else {
                        Add-RemovalServiceRoute -Builder $builder -ExclusionEntry $exclusionEntry
                    }
                }
                $script:RemovalRouteJunkFileSet       { Add-RemovalJunkFileSetRoute -Builder $builder -Finding $Finding -ProtectedPath $protectedPath }
                default {
                    Deny-RemovalPlan -Builder $builder -Reason "Route '$route' has no implementation in this version."
                }
            }
        }
        catch {
            # One bad Finding must not cost the caller the rest of the batch, and
            # an unexpected failure must not look like a plan that says "nothing
            # to do here".
            $inner = Get-OptimizerInnerException -Exception $_.Exception
            $builder.CurrentState = $script:RemovalStateUnverifiable
            Deny-RemovalPlan -Builder $builder -Reason "Planning failed for this item and nothing is planned for it: $($inner.GetType().Name): $($inner.Message)"
        }

        # Belt and braces: a step list can only ever contain steps a route added,
        # and a refused plan can never carry one.
        if (-not $builder.Supported -and $builder.Step.Count -gt 0) { $builder.Step.Clear() }

        # A plan needs elevation if ANY of its steps does.
        foreach ($step in $builder.Step) {
            if ([bool](Get-OptimizerProperty -InputObject $step -Name 'RequiresElevation' -Default $false)) {
                $builder.RequiresElevation = $true
            }
        }

        ConvertTo-RemovalPlan -Builder $builder -VerifiedUtc $verifiedUtc
    }
}

function Get-RemovalPreview {
    <#
    .SYNOPSIS
        Renders a removal plan as the human-readable dry run.

    .DESCRIPTION
        Returns the plan's lines as [string[]]. Derived from the plan object
        rather than read out of it, so it renders a plan that has been through a
        JSON round-trip -- out of a run log, or across the process boundary to the
        GUI -- exactly as it renders a fresh one.

        Nothing here changes anything. It is the same renderer Get-RemovalPlan
        used to fill in PreviewText, so the two can never disagree.

    .PARAMETER Plan
        A Win11Optimizer.RemovalPlan, or a deserialized one. Accepts pipeline
        input.

    .EXAMPLE
        Get-RemovalPlan -Finding $finding | Get-RemovalPreview
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $Plan
    )

    process {
        if ($null -eq $Plan) {
            return [string[]] @('(no plan)')
        }
        [string[]] @(Format-RemovalPlanText -Plan $Plan)
    }
}

#endregion
