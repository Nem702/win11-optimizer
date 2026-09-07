<#
    App\Scan.ps1 -- chunk P6-C1: the JSON scan entry point.

    THIS FILE IS A LAUNCHER, NOT A SOURCE FILE, and it is the THIRD one -- see
    App\Entry.ps1 (the menu, for a person) and App\Bootstrap.ps1 (the Start Menu
    shortcut's target, which is Entry.ps1 with a log file wrapped round it). All
    three are excluded by name from the module's folder loader, because all
    three call Import-Module and dot-sourcing any of them during the import
    would re-enter Import-Module from inside the import of the module they load.

    WHAT IT IS FOR. A second process -- the GUI shell of P6-C2, or anything else
    -- runs this and reads stdout:

        powershell.exe -NoProfile -File <module root>\App\Scan.ps1

    One complete JSON object per line: 'progress' while it works, then exactly
    one 'result'. Or one 'error' line, a sentence on stderr and a non-zero exit
    code. A consumer must be able to tell a scan that found nothing from a scan
    that died, and that is what the exit code is for.

    IT HAS NO LOGIC AND DEFINES NOTHING, the same rule App\Entry.ps1 keeps.
    Everything a launcher could get wrong -- what the phases are, what the
    records carry, when to write the result line -- lives in Review\Json.ps1,
    where the test suite can reach it. The one exception is the import failure
    below, and it is an exception because nothing that could report it exists
    yet at that point.

    THE IMPORT-FAILURE LINE IS A CONSTANT. It carries no interpolated message,
    on purpose: hand-rolling JSON string escaping in a launcher is exactly the
    sort of thing that produces an unparseable line on the one run where it
    matters, and the writer that does it properly is inside the module that
    just failed to load. The detail goes to stderr, where it needs no escaping,
    and the line says so.

    STDOUT CARRIES PROTOCOL LINES AND NOTHING ELSE. The output encoding is
    pinned to BOM-less UTF-8 here rather than left to whatever the host
    inherited; every line the writer produces is pure ASCII, so this only has to
    rule out a wide encoding, and it does.

    ASCII only.
#>
[CmdletBinding()]
param(
    # Read the action ledger for the receipt from here instead of from
    # Get-OptimizerActionLogPath. Read-only, and the same contract
    # Get-ReviewScreen keeps.
    [Parameter()]
    [AllowNull()]
    [AllowEmptyString()]
    [string] $LedgerPath,

    # Leave the receipt block off the result entirely.
    [Parameter()]
    [switch] $SkipReceipt,

    # Do not work out a removal plan per finding. Every row then arrives without
    # its Plan, which also means without its PreviewText.
    [Parameter()]
    [switch] $SkipPlan
)

$ErrorActionPreference = 'Stop'

[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

try {
    Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Win11Optimizer.Engine.psd1') -Force -ErrorAction Stop
}
catch {
    [Console]::Out.Write('{"kind":"error","schemaVersion":1,"timestamp":"' + [datetime]::UtcNow.ToString('o') + '","Phase":"Import","ExceptionType":"ImportFailed","Message":"win11-optimizer could not load its engine module. The reason is on stderr."}' + "`n")
    [Console]::Out.Flush()
    [Console]::Error.WriteLine("win11-optimizer: the engine module could not be imported, so no scan was run and no result was produced. $($_.Exception.GetType().Name): $($_.Exception.Message)")
    exit 1
}

exit (Invoke-OptimizerScanJson -LedgerPath $LedgerPath -SkipReceipt:$SkipReceipt -SkipPlan:$SkipPlan)
