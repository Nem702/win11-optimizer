<#
    Support\Elevation.ps1 -- chunk P5-C1, part B: the UAC relaunch.

    ONE JOB. Re-run this tool as administrator, at a menu choice the caller
    names, and say whether that worked. It decides nothing about WHETHER
    elevation is needed -- App\Menu.ps1 owns that -- and it changes nothing about
    what an elevated route is then allowed to do. Elevation here is a DELIVERY
    MECHANISM and nothing else: the executor still refuses a plan it cannot
    perform, and a scan still reports what it could not read.

    THE DOUBLE WINDOW IS REAL AND IS NOT SOMETHING THIS CODE CAN FIX. A UAC
    relaunch is a new process, and a new process gets a new console; the old
    window is left behind with whatever was on it. Windows offers no way to raise
    the integrity level of the process you are already in, so the honest handling
    is to say so BEFORE the new window appears -- which is why the caller prints
    its "Relaunching elevated..." line on the OLD window and this function prints
    nothing at all.
#>

#region Constants

# Captured at dot-source time. $PSScriptRoot inside a dot-sourced file is that
# FILE's folder -- measured on 5.1 and 7.6.5, both agree -- so this resolves to
# src\Win11Optimizer.Engine, and the entry script sits one folder down from it.
$script:ElevationModuleRoot  = Split-Path -Path $PSScriptRoot -Parent
$script:ElevationEntryScript = Join-Path -Path $script:ElevationModuleRoot -ChildPath 'App\Entry.ps1'

# The last-resort host. Every Windows 11 install has it, at this path, always --
# which is the only claim being made for it. It is reached when $PSHOME names no
# host executable AND the current process is not a PowerShell one, i.e. when this
# module has been imported into something exotic.
$script:ElevationFallbackHost = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'WindowsPowerShell\v1.0\powershell.exe'

$script:ElevationHostExecutableName = @('pwsh.exe', 'powershell.exe')

# What a value handed to the elevated command line may not contain.
#
# There is NO SHELL between here and CreateProcess -- Start-Process builds one
# command line and hands it over -- so ';', '&' and '|' are not the hazard they
# would be under cmd. The hazard is one layer further in: powershell.exe /
# pwsh.exe parses that command line ITSELF, and a value carrying a quote can
# close the quoting this file put around it and turn the rest of the value into
# arguments nobody passed.
#
# So values are QUOTED AND VALIDATED, not escaped. Escaping is a running argument
# with a parser you do not own; refusing the handful of characters that could
# start that argument costs nothing here, because every value this tool actually
# passes is one of its own menu choice names or a GUID.
$script:ElevationForbiddenCharacter = @(
    [pscustomobject]@{ Character = '"';    Description = 'a double quote' }
    [pscustomobject]@{ Character = "'";    Description = 'a single quote' }
    [pscustomobject]@{ Character = '`';    Description = 'a backtick' }
    [pscustomobject]@{ Character = '$';    Description = 'a dollar sign' }
    [pscustomobject]@{ Character = "`r";   Description = 'a carriage return' }
    [pscustomobject]@{ Character = "`n";   Description = 'a line feed' }
    [pscustomobject]@{ Character = "`0";   Description = 'a null character' }
)

#endregion

#region Internal: where to relaunch from

function Get-OptimizerHostExecutable {
    <#
        The absolute path of a PowerShell host to relaunch with, or $null.

        RESOLUTION ORDER, and each step earns its place:

          1. $PSHOME plus the executable name for this edition. $PSHOME is the
             PowerShell INSTALLATION directory, not the host process, so it is
             still right inside the ISE and inside an embedded host -- both of
             which would give the wrong answer at step 2.
          2. The current process's own image, when that is itself a PowerShell
             host. Covers a layout where $PSHOME is not where the exe lives.
          3. Windows PowerShell at its fixed System32 path.

        ABSOLUTE, ALWAYS. Start-Process -Verb RunAs resolves a relative -File
        path against System32 rather than the working directory, and
        -WorkingDirectory is IGNORED when -Verb is used. A relative path here
        would not fail cleanly -- it would launch the wrong thing, or nothing,
        from a folder nobody chose.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $executableName = $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })

    $candidate = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($PSHOME)) {
        $null = $candidate.Add((Join-Path -Path $PSHOME -ChildPath $executableName))
    }

    try {
        $processPath = (Get-Process -Id $PID -ErrorAction Stop).Path
        if (-not [string]::IsNullOrWhiteSpace($processPath)) {
            $leaf = Split-Path -Path $processPath -Leaf
            if ($script:ElevationHostExecutableName -contains $leaf) {
                $null = $candidate.Add($processPath)
            }
            else {
                Write-Verbose "The current process is '$leaf', which is not a PowerShell host, so it is not a relaunch candidate."
            }
        }
    }
    catch {
        Write-Verbose "The current process image could not be read, so it is not a relaunch candidate: $($_.Exception.Message)"
    }

    $null = $candidate.Add($script:ElevationFallbackHost)

    foreach ($path in $candidate) {
        if ([System.IO.Path]::IsPathRooted($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $path
        }
        Write-Verbose "Not a usable host executable: '$path'."
    }

    $null
}

function Get-OptimizerEntryScript {
    <#
        The absolute path of App\Entry.ps1 -- the script an elevated relaunch
        runs. Returns the path whether or not it is there; the caller reports a
        missing one, because "the entry script is not installed" is a different
        failure from "the user said no to UAC" and must not read as the same.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $script:ElevationEntryScript
}

#endregion

#region Internal: the command line

function Assert-OptimizerElevationValue {
    <#
        Throws unless this value can be put on the elevated command line safely.

        THROWS rather than returning $false, and that is deliberate. Every value
        this tool passes is one of its own menu choice names or an action id
        taken at a prompt that already validated it, so a value rejected here is
        a bug in the caller rather than something that happens to users -- and
        Invoke-OptimizerElevated's $false means "the relaunch did not happen",
        which a caller reports to a person as "elevation was denied". Folding a
        caller's bug into that message would hide it behind a sentence about UAC.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Value,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Label
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Invoke-OptimizerElevated: $Label must not be empty. Nothing is guessed at and nothing is launched."
    }

    foreach ($forbidden in $script:ElevationForbiddenCharacter) {
        if ($Value.Contains([string] $forbidden.Character)) {
            throw "Invoke-OptimizerElevated: $Label contains $($forbidden.Description), which cannot be put on an elevated command line safely. Nothing is launched."
        }
    }

    # A value beginning with a dash is read as a PARAMETER NAME by the host about
    # to parse this command line, quoted or not. Refused for the same reason as
    # the quote: it would silently become something other than a value.
    if ($Value.StartsWith('-')) {
        throw "Invoke-OptimizerElevated: $Label begins with '-', which the elevated host would read as a parameter name rather than a value. Nothing is launched."
    }
}

function Get-OptimizerElevationCommandLine {
    <#
        The argument array for the elevated host: -NoProfile, -File, the entry
        script, then the choice and any arguments.

        PURE. It builds a list and launches nothing, which is what lets the
        interesting half of this file be tested without a UAC prompt.

        -NoProfile because a profile that writes to the console, or fails, would
        do it in a window the user did not ask for and cannot see the start of.

        Every element that came from a caller is validated and then quoted. The
        two fixed switches and the script path are not caller data.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $EntryScript,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Choice,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Argument = @()
    )

    Assert-OptimizerElevationValue -Value $Choice -Label 'the menu choice'

    $line = New-Object System.Collections.Generic.List[string]
    $null = $line.Add('-NoProfile')
    $null = $line.Add('-File')
    $null = $line.Add('"' + $EntryScript + '"')
    $null = $line.Add('-Choice')
    $null = $line.Add('"' + $Choice + '"')

    # Blank entries are dropped rather than passed as empty strings: an empty
    # element in a -File parameter's comma-separated list binds as an empty
    # string the receiving script then has to special-case, and nothing here ever
    # means to send one.
    $values = @(@($Argument) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($value in $values) {
        Assert-OptimizerElevationValue -Value $value -Label "the argument '$value'"
    }

    if ($values.Count -gt 0) {
        # ONE element, comma-joined. powershell.exe -File binds a [string[]]
        # parameter from a comma-separated list; passing the values as separate
        # elements would bind only the first and leave the rest to be read as
        # positional arguments to a script that has none.
        $null = $line.Add('-Argument')
        $null = $line.Add('"' + ($values -join ',') + '"')
    }

    [string[]] @($line.ToArray())
}

#endregion

#region Public

function Invoke-OptimizerElevated {
    <#
    .SYNOPSIS
        Relaunches this tool as administrator at the given menu choice. Returns
        $true if the elevated process ran and exited cleanly, $false if the user
        declined UAC or it could not be started.

    .DESCRIPTION
        Builds an absolute command line -- an absolute host executable, an
        absolute path to App\Entry.ps1 -- and hands it to
        Start-Process -Verb RunAs, which is the only way to raise a process's
        integrity level from PowerShell.

        IT PRINTS NOTHING. The elevated process owns its own window and its own
        output; a line from here would land on the old window, interleaved with
        whatever the new one is saying. The one line a person needs -- why their
        window is about to be replaced -- belongs BEFORE this call, on the window
        being replaced, and App\Menu.ps1 writes it there.

        WHAT $false MEANS. Exactly one thing: the elevated run did not complete
        cleanly. The user cancelling the UAC dialog, a host that could not be
        found, an entry script that is not installed, a process that would not
        start, a non-zero exit code -- all of them are $false, because there is
        only one thing a caller can do about any of them, which is stay where it
        is and say so. -Verbose tells them apart.

        A CALLER'S BUG IS NOT $false. A choice or argument that cannot be put on
        a command line safely THROWS -- see Assert-OptimizerElevationValue.

        IT DOES NOT CHECK WHETHER ELEVATION IS NEEDED. Called from an already
        elevated process it will dutifully start a second one. The decision is
        the menu's, in one place, off one table.

    .PARAMETER Choice
        The menu choice the elevated process should start on, by name. Passed
        through as an opaque token: the menu owns the list of valid names and
        validates against it, and this function checks only that the value can go
        on a command line at all. Keeping that list in one place is the point.

    .PARAMETER Argument
        Values the choice needs -- an action id, for Undo. Blank entries are
        dropped. Sent as a single comma-separated -Argument value, which is how
        powershell.exe -File binds a [string[]] parameter.

    .PARAMETER WindowStyle
        The window the elevated process gets. Normal by default and on purpose: a
        hidden window would mean a person answers a UAC prompt and then watches
        nothing at all happen.

    .EXAMPLE
        if (-not (Test-IsElevated)) { $null = Invoke-OptimizerElevated -Choice 'Scan and review' }

    .EXAMPLE
        Invoke-OptimizerElevated -Choice 'Undo' -Argument $actionId -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Choice,

        [Parameter(Position = 1)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $Argument = @(),

        [Parameter()]
        [ValidateSet('Normal', 'Maximized', 'Minimized')]
        [string] $WindowStyle = 'Normal'
    )

    $hostExecutable = Get-OptimizerHostExecutable
    if ([string]::IsNullOrWhiteSpace($hostExecutable)) {
        Write-Verbose 'No PowerShell host executable could be found to relaunch with, so nothing was launched.'
        return $false
    }

    $entryScript = Get-OptimizerEntryScript
    if (-not (Test-Path -LiteralPath $entryScript -PathType Leaf)) {
        # Reported apart from a UAC refusal because it is a different problem
        # with a different fix: the install is incomplete.
        Write-Verbose "The entry script is not at '$entryScript', so nothing was launched."
        return $false
    }

    # Built BEFORE ShouldProcess, so -WhatIf still validates the choice and the
    # arguments. A -WhatIf that skipped the validation would describe a relaunch
    # that a real run would refuse.
    $arguments = Get-OptimizerElevationCommandLine -EntryScript $entryScript -Choice $Choice -Argument $Argument

    if (-not $PSCmdlet.ShouldProcess("$hostExecutable $($arguments -join ' ')", 'Relaunch elevated')) {
        # $false, because nothing was launched. Under -WhatIf that reads as "the
        # relaunch did not happen", which is exactly what happened.
        Write-Verbose 'ShouldProcess declined, so nothing was launched.'
        return $false
    }

    $process = $null
    try {
        $process = Start-Process -FilePath $hostExecutable -ArgumentList $arguments `
            -Verb 'RunAs' -WindowStyle $WindowStyle -PassThru -ErrorAction Stop
    }
    catch {
        # A cancelled UAC dialog arrives here as a Win32Exception carrying native
        # error 1223, wrapped. Anything else that stopped the launch arrives the
        # same way and is treated the same way, because the caller's options are
        # identical either way.
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        Write-Verbose "The elevated process was not started: $($inner.GetType().Name): $($inner.Message)"
        return $false
    }

    if ($null -eq $process) {
        Write-Verbose 'Start-Process returned no process object, so there is nothing to wait for and nothing to report.'
        return $false
    }

    # WaitForExit() on the handle we were given, rather than Start-Process -Wait.
    # -Wait together with -Verb is reported to be the combination where ExitCode
    # comes back null on 5.1, and an exit code that is not there would read here
    # as a crash. NOT reproduced here -- this avoids the question rather than
    # answering it, and waiting on the handle we were handed is correct either
    # way, so the choice costs nothing whether or not the report is current.
    try {
        $process.WaitForExit()
    }
    catch {
        $inner = Get-OptimizerInnerException -Exception $_.Exception
        Write-Verbose "The elevated process could not be waited on: $($inner.GetType().Name): $($inner.Message)"
        return $false
    }

    $exitCode = $null
    try { $exitCode = $process.ExitCode }
    catch {
        Write-Verbose "The elevated process exited but its exit code could not be read: $($_.Exception.Message)"
        return $false
    }

    if ($null -eq $exitCode) {
        Write-Verbose 'The elevated process exited without an exit code, which cannot be read as success.'
        return $false
    }

    if ($exitCode -ne 0) {
        Write-Verbose "The elevated process exited with code $exitCode."
        return $false
    }

    Write-Verbose 'The elevated process exited cleanly.'
    $true
}

#endregion
