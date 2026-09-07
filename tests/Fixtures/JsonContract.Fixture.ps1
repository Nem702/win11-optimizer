<#
    The JSON contract's fixture -- chunk P6-C1.

    THIS IS A TEST FIXTURE, NOT A TEST FILE. It has no .Tests.ps1 suffix, so
    Invoke-Tests.ps1 does not discover it as a suite. Dot-source it, the way
    tests\ForbiddenPhrase.ps1 is dot-sourced.

    WHAT IT IS FOR. The acceptance criterion that matters most for this chunk is
    that BOTH SHELLS PRODUCE BYTE-IDENTICAL STDOUT FOR THE SAME SCAN INPUT. A
    real scan cannot be that input -- it reads a clock, a machine name and a
    disk, and none of the three holds still. So this file builds a scan that
    does hold still: fixed timestamps, fixed counts, fabricated Findings, a
    fabricated plan, and a machine name that is a constant.

    Get-JsonContractFixtureText is the whole of it, and it is what both shells
    run. Its output is compared byte for byte against the committed golden file
    (tests\Fixtures\json-contract-golden.jsonl) on each shell, and shell against
    shell by spawning the other one. If 5.1 and 7 ever disagree about a byte,
    one of those two comparisons fails.

    IT EXERCISES THE AWKWARD CASES ON PURPOSE, because a fixture made only of
    tidy values proves nothing about the two serializers this file exists to
    avoid:

      * the angle brackets, the ampersand and the apostrophe -- 5.1's
        ConvertTo-Json escapes all four and 7's does not;
      * a tab, a newline, a carriage return, a backslash and a double quote;
      * a character above 0x7E, which must come out as a \u escape so that the
        bytes on the wire do not depend on the console's encoding;
      * a [datetime], which is Q29 and is the reason every timestamp in this
        contract is a string;
      * a whole number, a fractional one, a very large one and a zero.

    ASCII ONLY IN THIS FILE, the non-ASCII test character included: it is built
    with [char]0x00E9 rather than typed, because one non-ASCII character in a
    source file takes down 137 unrelated tests on 5.1 (docs\REVIEW.md), and
    because `grep -n '[^ -~\t]'` over every file this chunk touched has to come
    back clean.
#>

function Get-JsonContractFixtureTimestamp {
    # The one timestamp everything in this fixture is stamped with. A constant,
    # so that two runs a second apart produce the same bytes.
    [CmdletBinding()]
    [OutputType([string])]
    param()

    '2026-09-06T12:34:56.7890123Z'
}

function Get-JsonContractFixtureAwkwardText {
    <#
        Every character this contract's writer has an opinion about, in one
        string. Built rather than typed: the file itself stays ASCII, and the
        two characters that matter most -- the one above 0x7E and the control
        characters -- cannot be written literally in a source file this project
        will accept.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    -join @(
        'quote:"'
        ' backslash:\'
        ' slash:/'
        " tab:$([char]9)"
        " newline:$([char]10)"
        " return:$([char]13)"
        " backspace:$([char]8)"
        " formfeed:$([char]12)"
        " unit-separator:$([char]31)"
        ' angles:<b>'
        ' ampersand:&'
        " apostrophe:'"
        " accented:$([char]0x00E9)clair"
        " cjk:$([char]0x4E2D)"
    )
}

function Get-JsonContractFixtureWriterPayload {
    <#
        The writer's torture test as one payload: every type it accepts, in an
        order that is fixed because [ordered] keeps it fixed.

        The [datetime] is deliberately NOT here. The writer refuses one, which
        is the point of it, and that refusal is asserted in the suite rather
        than serialized here. What IS here is the string the projection would
        have turned it into.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    [ordered]@{
        Text          = Get-JsonContractFixtureAwkwardText
        Empty         = ''
        Nothing       = $null
        Yes           = $true
        No            = $false
        Zero          = [long] 0
        Whole         = [long] 12345678901
        Negative      = [long] -42
        Fraction      = [double] 2.5
        NegativeZero  = [double] 0.0
        Rounded       = [double] 0.1234567
        EmptyArray    = @()
        StringArray   = [string[]] @('one', 'two')
        MixedArray    = @([long] 1, $true, $null, 'three')
        NestedObject  = [ordered]@{
            Inner     = [ordered]@{ Deepest = 'here' }
            InnerList = @([ordered]@{ A = [long] 1 }, [ordered]@{ A = [long] 2 })
        }
        # What Q29 looks like AFTER the projection has dealt with it: a string,
        # on both shells, and the same string. Run through the engine's own
        # normaliser rather than typed as a literal, because a literal would
        # prove only that this file can spell an ISO date. ConvertTo-RemovalUtcText
        # is module-private, so it is reached the way every other private
        # function in this fixture is.
        StampedUtc    = & (Get-Module Win11Optimizer.Engine) {
            param($Value) ConvertTo-RemovalUtcText -Value $Value
        } ([datetime]::new(2026, 9, 6, 12, 34, 56, 789, [System.DateTimeKind]::Utc))
    }
}

function New-JsonContractFixtureSource {
    # One ScanSource. Goes through the engine's own factory, so a fixture cannot
    # describe a source shape the engine would refuse to make -- notably a
    # non-success status with no Reason.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Status,
        [Parameter()] [AllowNull()] [string] $Reason,
        [Parameter()] [int] $ItemCount = 0,
        [Parameter()] [double] $DurationSeconds = 0
    )

    & (Get-Module Win11Optimizer.Engine) {
        param($Name, $Status, $Reason, $ItemCount, $DurationSeconds)
        $arguments = @{
            Name            = $Name
            Status          = $Status
            ItemCount       = $ItemCount
            DurationSeconds = $DurationSeconds
        }
        if (-not [string]::IsNullOrWhiteSpace($Reason)) { $arguments['Reason'] = $Reason }
        New-ScanSource @arguments
    } $Name $Status $Reason $ItemCount $DurationSeconds
}

function New-JsonContractFixtureScan {
    # One scan result, through New-ScanResult, so IsComplete / IncompleteReason
    # / RefusedSourceName are derived by the engine rather than asserted by the
    # fixture. StartedUtc is a REAL [datetime] here on purpose: that is what the
    # engine holds, and Q29 is a serialization problem, so the fixture has to
    # hand the projection the shape it will really meet.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Detector,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [int] $InventoryCount,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [psobject[]] $Source,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Finding,
        [Parameter()] [AllowNull()] $AdditionalProperty
    )

    & (Get-Module Win11Optimizer.Engine) {
        param($Detector, $Category, $InventoryCount, $Source, $Finding, $AdditionalProperty)
        New-ScanResult -Detector $Detector -Category $Category `
            -StartedUtc ([datetime]::new(2026, 9, 6, 12, 0, 0, [System.DateTimeKind]::Utc)) `
            -DurationSeconds 1.25 -IsElevated $false -InventoryCount $InventoryCount `
            -Source $Source -Finding $Finding -ScanLabel "$Detector fixture scan" `
            -AdditionalProperty $AdditionalProperty -WarningAction SilentlyContinue
    } $Detector $Category $InventoryCount $Source $Finding $AdditionalProperty
}

function Get-JsonContractFixtureScreen {
    <#
        A whole review screen, fabricated and deterministic.

        THE FOUR MACHINE-DEPENDENT FIELDS ARE OVERWRITTEN AFTER THE FACT.
        Get-ReviewScreen stamps GeneratedUtc from the clock and reads the
        machine name, the user name and the elevation state, and none of those
        four can be the same twice. Everything else it produces -- every
        headline, every count, every cell -- is a function of the scans it was
        given, which is what makes the rest of this deterministic.

        The receipt is skipped: it reads a ledger, and a ledger is a file whose
        contents are nobody's fixture.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    # ---- startup and services ------------------------------------------
    $startupFinding = New-Finding -Category StartupItem -Id 'HKCU\Run\Fixture' `
        -DisplayName 'Fixture startup item' -Confidence Heuristic `
        -Evidence 'Target file is missing.', (Get-JsonContractFixtureAwkwardText) `
        -RemovalMethod RegistryRunKey
    $startupFinding | Add-Member -MemberType NoteProperty -Name 'Mechanism' -Value 'RunKey'
    $startupFinding | Add-Member -MemberType NoteProperty -Name 'FindingReason' -Value 'Orphan'
    $startupFinding | Add-Member -MemberType NoteProperty -Name 'StartupEntryId' -Value 'fixture-run-key'

    $serviceFinding = New-Finding -Category Service -Id 'FixtureSvc' `
        -DisplayName 'Fixture service' -Confidence Known -RequiresConsent `
        -Evidence 'On the curated list.' -RemovalMethod ServiceDisable
    $serviceFinding | Add-Member -MemberType NoteProperty -Name 'Mechanism' -Value 'Service'
    $serviceFinding | Add-Member -MemberType NoteProperty -Name 'FindingReason' -Value 'Curated'
    $serviceFinding | Add-Member -MemberType NoteProperty -Name 'StartupEntryId' -Value 'fixture-service'

    $startupScan = New-JsonContractFixtureScan -Detector 'StartupItems' -Category 'StartupItem' `
        -InventoryCount 149 -Finding @($startupFinding, $serviceFinding) `
        -Source @(
            (New-JsonContractFixtureSource -Name 'RunKey' -Status 'Succeeded' -ItemCount 40 -DurationSeconds 0.5)
            (New-JsonContractFixtureSource -Name 'ScheduledTask' -Status 'Failed' -Reason 'The task scheduler service could not be reached.' -ItemCount 0 -DurationSeconds 0.25)
        ) `
        -AdditionalProperty ([ordered]@{
            DisabledCount         = 28
            EnabledCount          = 121
            UnknownStateCount     = 2
            ProtectedTaskCount    = 7
            ProtectedServiceCount = 10
            MechanismCount        = [ordered]@{ RunKey = 40; StartupFolder = 2; ScheduledTask = 17; Service = 90 }
            StartupItems          = [psobject[]] @([pscustomobject]@{ Mechanism = 'Service'; Id = 'FixtureSvc'; EnabledState = 'Enabled' })
        })

    # ---- unused apps ----------------------------------------------------
    $unusedScan = New-JsonContractFixtureScan -Detector 'UnusedApps' -Category 'UnusedApp' `
        -InventoryCount 286 -Finding @() `
        -Source @(
            (New-JsonContractFixtureSource -Name 'UserAssist' -Status 'Succeeded' -ItemCount 177 -DurationSeconds 0.75)
            (New-JsonContractFixtureSource -Name 'Prefetch' -Status 'Skipped' -Reason 'The prefetch folder cannot be read without administrator rights.' -ItemCount 0 -DurationSeconds 0.01)
            (New-JsonContractFixtureSource -Name 'FileSystemLastAccess' -Status 'Refused' -Reason 'Not used as a usage signal, by measurement rather than by assumption.' -ItemCount 0 -DurationSeconds 0.02)
        ) `
        -AdditionalProperty ([ordered]@{
            ConsideredCount = 286
            UnknownCount    = 234
            UsedCount       = 52
            UnusedCount     = 0
            ExcludedCount   = 33
        })

    # ---- OEM bloatware --------------------------------------------------
    $oemFinding = New-Finding -Category OemBloatware -Id 'Fixture.Widget_8wekyb3d8bbwe' `
        -DisplayName 'Fixture Widget' -Confidence Known `
        -Evidence 'Matches curated known-bloatware list entry fixture-widget.' -RemovalMethod Appx
    $oemFinding | Add-Member -MemberType NoteProperty -Name 'WhitelistEntryId' -Value 'fixture-widget'

    $oemScan = New-JsonContractFixtureScan -Detector 'OemBloatware' -Category 'OemBloatware' `
        -InventoryCount 343 -Finding @($oemFinding) `
        -Source @(
            (New-JsonContractFixtureSource -Name 'AppxPackage' -Status 'Succeeded' -ItemCount 146 -DurationSeconds 1.5)
        )

    # ---- junk files -----------------------------------------------------
    $junkFinding = New-Finding -Category JunkFile -Id 'fixture-cache' `
        -DisplayName 'Fixture web cache' -Confidence Known -RequiresConsent `
        -Evidence 'Fixture web cache -- 1,234 files older than 7 days.' -RemovalMethod FileDelete
    $junkFinding | Add-Member -MemberType NoteProperty -Name 'LocationId' -Value 'fixture-cache'
    $junkFinding | Add-Member -MemberType NoteProperty -Name 'LocationPath' -Value ([string[]] @('C:\Fixture\Profile 1\Cache', 'C:\Fixture\Profile 2\Cache'))
    $junkFinding | Add-Member -MemberType NoteProperty -Name 'EligibleFileCount' -Value ([long] 1234)
    $junkFinding | Add-Member -MemberType NoteProperty -Name 'EligibleBytes' -Value ([long] 1220410048)
    $junkFinding | Add-Member -MemberType NoteProperty -Name 'IsSizeFloor' -Value $true
    $junkFinding | Add-Member -MemberType NoteProperty -Name 'MinimumAgeDays' -Value 30
    $junkFinding | Add-Member -MemberType NoteProperty -Name 'ProfileBreakdown' -Value ([psobject[]] @(
        [pscustomobject]@{ Profile = 'Profile 1'; FileCount = [long] 900; TotalBytes = [long] 1000000000; EligibleFileCount = [long] 800; EligibleBytes = [long] 900000000 }
        [pscustomobject]@{ Profile = 'Profile 2'; FileCount = [long] 500; TotalBytes = [long] 400000000; EligibleFileCount = [long] 434; EligibleBytes = [long] 320410048 }
    ))
    # THE FILE LIST IS ON THE FIXTURE FINDING ON PURPOSE. It is what a real junk
    # Finding carries, it is 773 records on this machine, and the suite asserts
    # that the projection leaves it behind. A fixture without it could not.
    $junkFinding | Add-Member -MemberType NoteProperty -Name 'EligibleFile' -Value ([psobject[]] @(
        [pscustomobject]@{ Path = 'C:\Fixture\Profile 1\Cache\one.tmp'; SizeBytes = [long] 1024 }
        [pscustomobject]@{ Path = 'C:\Fixture\Profile 2\Cache\two.tmp'; SizeBytes = [long] 2048 }
    ))

    $junkScan = New-JsonContractFixtureScan -Detector 'JunkFiles' -Category 'JunkFile' `
        -InventoryCount 15 -Finding @($junkFinding) `
        -Source @(
            (New-JsonContractFixtureSource -Name 'fixture-cache' -Status 'Succeeded' -ItemCount 1400 -DurationSeconds 3.125)
            (New-JsonContractFixtureSource -Name 'windows-temp' -Status 'Skipped' -Reason 'One folder under it could not be listed at this privilege level.' -ItemCount 0 -DurationSeconds 0.5)
        ) `
        -AdditionalProperty ([ordered]@{
            MinimumAgeDays = 7
            SizeIsFloor    = $true
        })

    $screen = Get-ReviewScreen -StartupScan $startupScan -UnusedAppScan $unusedScan `
        -OemScan $oemScan -JunkScan $junkScan -SkipReceipt

    $screen.GeneratedUtc = Get-JsonContractFixtureTimestamp
    $screen.MachineName  = 'FIXTURE-PC'
    $screen.UserName     = 'fixture'
    $screen.IsElevated   = $false

    $screen
}

function Get-JsonContractFixturePlanner {
    <#
        A planner that fabricates a plan instead of asking the machine for one.

        Get-RemovalPlan re-probes the registry and the disk, so a fixture that
        used it would be a fixture whose bytes depend on what is installed. This
        returns the same shape -- including the two fields the projection has to
        leave behind, Step and RollbackData -- so the suite can assert that they
        do not reach the payload.
    #>
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()

    {
        param($Finding)

        $id = [string] $Finding.Id
        [pscustomobject]@{
            FindingId         = $id
            Category          = [string] $Finding.Category
            RemovalMethod     = [string] $Finding.RemovalMethod
            DisplayName       = [string] $Finding.DisplayName
            Confidence        = [string] $Finding.Confidence
            Route             = 'FixtureRoute'
            Supported         = $true
            UnsupportedReason = $null
            CurrentState      = 'Present'
            VerifiedUtc       = '2026-09-06T12:34:56.7890123Z'
            RequiresElevation = $true
            RequiresConsent   = [bool] $Finding.RequiresConsent
            SafetyLabel       = [string] $Finding.SafetyLabel
            IsReversible      = $false
            Step              = [psobject[]] @([pscustomobject]@{ Kind = 'FixtureStep'; Detail = 'must not reach the payload' })
            RollbackData      = [pscustomobject]@{ Secret = 'must not reach the payload either' }
            Note              = [string[]] @('A fixture plan.')
            PreviewText       = [string[]] @(
                "Plan for $id"
                '  This is what would happen. It is not a promise about what this PC will do afterwards.'
            )
        }
    }
}

function Get-JsonContractFixtureText {
    <#
        THE FIXTURE, SERIALIZED. This is the function both shells run and whose
        bytes are compared.

        Four records: the writer's torture payload, a progress line, an error
        line, and the whole fabricated screen as a result line. Joined with LF
        and terminated with one, which is the framing the runner writes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $stamp = Get-JsonContractFixtureTimestamp

    $lines = @(
        (ConvertTo-OptimizerScanJson -Kind 'progress' -TimestampUtc $stamp -Payload (Get-JsonContractFixtureWriterPayload))
        (ConvertTo-OptimizerScanJson -Kind 'progress' -TimestampUtc $stamp -Payload ([ordered]@{
            Phase          = 'JunkFiles'
            PhaseIndex     = [long] 3
            PhaseCount     = [long] 5
            Message        = 'Measuring Fixture web cache.'
            Item           = 'Fixture web cache'
            ItemIndex      = [long] 9
            ItemCount      = [long] 15
            FindingCount   = [long] 3
            InventoryCount = [long] 778
        }))
        (ConvertTo-OptimizerScanJson -Kind 'error' -TimestampUtc $stamp -Payload ([ordered]@{
            Phase         = 'JunkFiles'
            ExceptionType = 'UnauthorizedAccessException'
            Message       = 'Access to the path is denied.'
        }))
        (ConvertTo-OptimizerScanJson -Kind 'result' -TimestampUtc $stamp -Payload (
            ConvertTo-OptimizerScanPayload -Screen (Get-JsonContractFixtureScreen) -Planner (Get-JsonContractFixturePlanner)))
    )

    ($lines -join "`n") + "`n"
}
