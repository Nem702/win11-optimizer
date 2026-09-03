<#
    App\Bootstrap.ps1 -- chunk P5-C2, part C: the shortcut's target.

    THIS FILE IS A LAUNCHER, NOT A SOURCE FILE, and it is the SECOND one -- see
    App\Entry.ps1, which stays exactly as it is for a manual run from a shell you
    already have open. Both are excluded by name from the module's folder loader
    (the App\ line in Win11Optimizer.Engine.psm1); dot-sourcing either during the
    import would re-enter Import-Module and open the menu from inside the import
    of the module the menu lives in.

    WHY THERE ARE TWO. Entry.ps1 assumes a console that outlives it. The Start
    Menu shortcut does not have one: Explorer starts powershell.exe, and if the
    import throws, the window carrying the error closes with the process. The
    person sees a black rectangle flash and has nothing at all to report. So this
    file is Entry.ps1 with the one thing a shortcut needs wrapped round it: a log
    file, in %TEMP%, written before the process is gone.

        %TEMP%\win11-optimizer-bootstrap-<yyyyMMdd-HHmmss>.log

    It is written ONLY when there is something to say. A launcher that drops a
    file in %TEMP% on every successful start is a launcher that has taught the
    person to ignore its files.

    WHAT IT ADDS TO THE MENU: nothing. It imports the module, says something if
    the ledger folder is not what the installer should have made it, and calls
    Invoke-OptimizerMenu. Every decision about what the menu offers, when to
    elevate and what to do with a cancellation is still in App\Menu.ps1, where
    the test suite can reach it.

    EXIT CODES, because a shortcut cannot show you a stack trace:
        0  the menu ran and returned
        1  the module could not be imported
        2  the menu itself threw

    ASCII only -- see the note at the top of Removal\ActionLog.ps1.
#>
[CmdletBinding()]
param(
    # The menu choice to start on, by name. Same contract as App\Entry.ps1: this
    # is how an elevated relaunch says where to start.
    [Parameter()]
    [AllowNull()]
    [AllowEmptyString()]
    [string] $Choice,

    # What that choice needs: the action id, for Undo.
    [Parameter()]
    [AllowNull()]
    [AllowEmptyCollection()]
    [AllowEmptyString()]
    [string[]] $Argument = @()
)

$ErrorActionPreference = 'Stop'

# Resolved once, at the top, so that the name of the log file is the time the
# launcher started and not the time it happened to fail. UTC, like every other
# timestamp this project writes.
$script:BootstrapLogPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath (
    'win11-optimizer-bootstrap-{0}.log' -f ([datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')))

function Write-BootstrapLine {
    <#
    .SYNOPSIS
        Appends one line to the bootstrap log, and never throws.

    .DESCRIPTION
        The whole reason this file exists is that the console is about to
        disappear, so this function must survive anything: a %TEMP% that is not
        writable, a full disk, a locked file. It swallows its own failures on
        purpose. There is nowhere left to report them to.

        Carries the process's working directory on every line because a shortcut
        with a blank "Start In" inherits whatever Explorer felt like, and a
        relative path in an error message is unreadable without it.

    .PARAMETER Text
        What happened.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $line = '[{0}Z] {1} | process working directory: {2} | PowerShell location: {3} | shell: {4} {5} | script: {6}' -f
        ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss')),
        $Text,
        ([System.IO.Directory]::GetCurrentDirectory()),
        ((Get-Location).Path),
        $PSVersionTable.PSEdition,
        $PSVersionTable.PSVersion,
        $PSCommandPath

    try {
        [System.IO.File]::AppendAllText($script:BootstrapLogPath, $line + [Environment]::NewLine)
    }
    catch {
        # Deliberately empty. See the description.
    }

    # And to the console, for the case where there is one -- a manual run, or a
    # shortcut the person launched from an already-open terminal.
    try { Write-Host $line } catch { }
}

$modulePath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Win11Optimizer.Engine.psd1'

try {
    Import-Module -Name $modulePath -Force -ErrorAction Stop
}
catch {
    Write-BootstrapLine -Text ("win11-optimizer could not start: importing '$modulePath' failed: " +
        "$($_.Exception.GetType().Name): $($_.Exception.Message)")
    exit 1
}

# Q21, at startup and literally. The ledger's folder is created by the installer
# with an explicit ACL and this tool will not write a ledger anywhere else, so a
# person whose install is damaged should be told on the way in rather than three
# screens later when they confirm a removal.
#
# IT IS A WARNING HERE AND A REFUSAL THERE. Scanning does not touch the ledger
# and is still worth doing on a machine whose folder is wrong; anything that
# would CHANGE the machine goes through Write-OptimizerAction, which throws.
try {
    $ledgerFolder = Test-OptimizerLedgerFolder
    if (-not $ledgerFolder.IsUsable) {
        Write-BootstrapLine -Text ("The action ledger folder '$($ledgerFolder.Path)' is not usable " +
            "($($ledgerFolder.ErrorId)): $($ledgerFolder.Problem -join '; '). Scanning still works; " +
            'anything that changes this machine will refuse until it is fixed.')
    }
}
catch {
    Write-BootstrapLine -Text ("The action ledger folder could not be checked: " +
        "$($_.Exception.GetType().Name): $($_.Exception.Message)")
}

try {
    $null = Invoke-OptimizerMenu -InitialChoice $Choice -InitialArgument $Argument
}
catch {
    Write-BootstrapLine -Text ("win11-optimizer stopped: $($_.Exception.GetType().Name): $($_.Exception.Message)")
    exit 2
}

exit 0
