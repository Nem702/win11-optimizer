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

function New-JsonContractFixtureVerdict {
    # One inventory verdict, through the engine's own factory so the fixture
    # cannot describe a shape the engine would refuse to make.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Class,
        [Parameter()] [AllowNull()] [string] $FindingId,
        [Parameter()] [AllowNull()] [string] $RuleId,
        [Parameter()] [AllowNull()] [string] $RuleClass,
        [Parameter()] [AllowNull()] [string] $Reason
    )

    & (Get-Module Win11Optimizer.Engine) {
        param($Id, $Class, $FindingId, $RuleId, $RuleClass, $Reason)
        $arguments = @{ Id = $Id; Class = $Class }
        foreach ($pair in @(
            @{ Name = 'FindingId'; Value = $FindingId }
            @{ Name = 'RuleId';    Value = $RuleId }
            @{ Name = 'RuleClass'; Value = $RuleClass }
            @{ Name = 'Reason';    Value = $Reason }
        )) {
            if (-not [string]::IsNullOrWhiteSpace($pair.Value)) { $arguments[$pair.Name] = $pair.Value }
        }
        New-InventoryVerdict @arguments
    } $Id $Class $FindingId $RuleId $RuleClass $Reason
}

function New-JsonContractFixtureStartupItem {
    # One startup inventory record, in the shape Get-StartupItemInventory
    # produces. TargetExists is a TRI-STATE and the fixture uses all three
    # values on purpose: only $false is an orphan, and $null must survive the
    # projection as null rather than collapsing into $false.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Mechanism,
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $DisplayName,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Scope,
        [Parameter(Mandatory)] [string] $EnabledState,
        [Parameter()] [AllowNull()] [string] $Publisher,
        [Parameter()] [AllowNull()] [Nullable[bool]] $TargetExists,
        [Parameter()] [bool] $IsProtectedNamespace = $false
    )

    [pscustomobject]@{
        Mechanism            = $Mechanism
        Id                   = $Id
        Name                 = $DisplayName
        DisplayName          = $DisplayName
        Category             = $Category
        Scope                = $Scope
        Publisher            = $Publisher
        EnabledState         = $EnabledState
        TargetExists         = $TargetExists
        IsProtectedNamespace = $IsProtectedNamespace
    }
}

function New-JsonContractFixtureApp {
    # One installed-app record, through the engine's own factory so the fixture
    # cannot describe a shape New-InstalledApp would refuse.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $DisplayName,
        [Parameter()] [AllowNull()] [string] $Publisher,
        [Parameter()] [AllowNull()] [string] $Detail
    )

    & (Get-Module Win11Optimizer.Engine) {
        param($Source, $Id, $DisplayName, $Publisher, $Detail)
        New-InstalledApp -Source $Source -Id $Id -Name $DisplayName -DisplayName $DisplayName `
            -Publisher $Publisher -Detail $Detail
    } $Source $Id $DisplayName $Publisher $Detail
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

    # THE INVENTORY, AND IT IS ARITHMETICALLY CONSISTENT WITH THE COUNTS BESIDE
    # IT. P6-C3 added Inventory[] to every section, and the assertion that makes
    # it worth anything is that its length and its held-back count agree with
    # the scan's own InventoryCount, ProtectedTaskCount and ProtectedServiceCount.
    # A fixture whose counts were free-standing numbers could not carry that
    # assertion at all, so these seven records ARE the counts below.
    #
    # Between them they exercise: every mechanism, all three EnabledStates, all
    # three values of the TargetExists tri-state, a protected-namespace task, a
    # service the exclusion list held back, and two items that became Findings.
    $startupItems = @(
        (New-JsonContractFixtureStartupItem -Mechanism 'RunKey' -Id 'HKCU\Run\Fixture' `
            -DisplayName 'Fixture startup item' -Category 'StartupItem' -Scope 'User' `
            -EnabledState 'Enabled' -Publisher 'Fixture Ltd' -TargetExists $false)
        (New-JsonContractFixtureStartupItem -Mechanism 'RunKey' -Id 'HKCU\Run\Quiet' `
            -DisplayName 'Fixture quiet entry' -Category 'StartupItem' -Scope 'User' `
            -EnabledState 'Enabled' -Publisher $null -TargetExists $null)
        (New-JsonContractFixtureStartupItem -Mechanism 'StartupFolder' -Id 'C:\Fixture\Startup\thing.lnk' `
            -DisplayName 'Fixture shortcut' -Category 'StartupItem' -Scope 'Machine' `
            -EnabledState 'Disabled' -Publisher 'Fixture Ltd' -TargetExists $true)
        (New-JsonContractFixtureStartupItem -Mechanism 'StartupFolder' -Id 'C:\Fixture\Startup\murky.lnk' `
            -DisplayName 'Fixture murky shortcut' -Category 'StartupItem' -Scope 'Machine' `
            -EnabledState 'Unknown' -Publisher $null -TargetExists $null)
        (New-JsonContractFixtureStartupItem -Mechanism 'ScheduledTask' -Id '\Microsoft\Windows\Fixture\Task' `
            -DisplayName 'Fixture protected task' -Category 'StartupItem' -Scope 'Machine' `
            -EnabledState 'Enabled' -Publisher 'Microsoft Corporation' -TargetExists $true `
            -IsProtectedNamespace $true)
        (New-JsonContractFixtureStartupItem -Mechanism 'Service' -Id 'FixtureSvc' `
            -DisplayName 'Fixture service' -Category 'Service' -Scope 'Machine' `
            -EnabledState 'Enabled' -Publisher 'Fixture Ltd' -TargetExists $true)
        (New-JsonContractFixtureStartupItem -Mechanism 'Service' -Id 'FixtureProtectedSvc' `
            -DisplayName 'Fixture protected service' -Category 'Service' -Scope 'Machine' `
            -EnabledState 'Enabled' -Publisher 'Fixture Security Inc' -TargetExists $true)
    )

    $startupScan = New-JsonContractFixtureScan -Detector 'StartupItems' -Category 'StartupItem' `
        -InventoryCount $startupItems.Count -Finding @($startupFinding, $serviceFinding) `
        -Source @(
            (New-JsonContractFixtureSource -Name 'RunKey' -Status 'Succeeded' -ItemCount 40 -DurationSeconds 0.5)
            (New-JsonContractFixtureSource -Name 'ScheduledTask' -Status 'Failed' -Reason 'The task scheduler service could not be reached.' -ItemCount 0 -DurationSeconds 0.25)
        ) `
        -AdditionalProperty ([ordered]@{
            DisabledCount         = 1
            EnabledCount          = 5
            UnknownStateCount     = 1
            ProtectedTaskCount    = 1
            ProtectedServiceCount = 1
            MechanismCount        = [ordered]@{ RunKey = 2; StartupFolder = 2; ScheduledTask = 1; Service = 2 }
            StartupItems          = [psobject[]] $startupItems
            InventoryVerdict      = [psobject[]] @(
                (New-JsonContractFixtureVerdict -Id 'FixtureProtectedSvc' -Class 'HeldBack' `
                    -RuleId 'fixture-security-class' -RuleClass 'security' `
                    -Reason 'Security software is never offered, whatever a usage heuristic says about it.')
            )
        })

    # ---- unused apps ----------------------------------------------------
    #
    # THE APPX FINDING IS KEYED ON THE PACKAGE FAMILY NAME AND THE CLASSIFICATION
    # ON THE APP'S OWN Id, and here they are deliberately different strings. That
    # is the whole reason an inventory entry carries FindingId rather than
    # leaving a consumer to match on Id: Find-UnusedApp rewrites an Appx
    # Finding's Id, so a join on Id alone would miss the row and draw the
    # application twice -- once as a finding, once as "nothing was said".
    $unusedFinding = New-Finding -Category UnusedApp -Id 'Fixture.Unused_8wekyb3d8bbwe' `
        -DisplayName 'Fixture unused app' -Confidence Heuristic `
        -Evidence 'Not used in the last 180 days: the most recent launch recorded for it is 2026-01-02, 247 days ago.' `
        -RemovalMethod Appx

    $classifications = @(
        [pscustomobject]@{
            App         = (New-JsonContractFixtureApp -Source 'AppxPackage' -Id 'Fixture.Widget_8wekyb3d8bbwe' `
                            -DisplayName 'Fixture Widget' -Publisher 'CN=Fixture' -Detail 'Fixture.Widget_1.0.0.0_x64__8wekyb3d8bbwe')
            DisplayName = 'Fixture Widget'
            State       = 'Unknown'
            Reason      = 'No usage signal on this machine names this application. That is absence of evidence, not evidence of absence -- it is never reported as unused.'
        }
        [pscustomobject]@{
            App         = (New-JsonContractFixtureApp -Source 'AppxPackage' -Id 'Fixture.Unused_1.0.0.0_x64__8wekyb3d8bbwe' `
                            -DisplayName 'Fixture unused app' -Publisher 'CN=Fixture' -Detail 'Fixture.Unused_1.0.0.0_x64__8wekyb3d8bbwe')
            DisplayName = 'Fixture unused app'
            State       = 'Unused'
            Reason      = 'No launch recorded in the last 180 days; the most recent one is 247 days old.'
        }
        [pscustomobject]@{
            App         = (New-JsonContractFixtureApp -Source 'AppxPackage' -Id 'Fixture.Protected_8wekyb3d8bbwe' `
                            -DisplayName 'Fixture Security Suite' -Publisher 'CN=Fixture Security Inc' -Detail 'Fixture.Protected_2.0.0.0_x64__8wekyb3d8bbwe')
            DisplayName = 'Fixture Security Suite'
            State       = 'Unused'
            Reason      = 'No launch recorded in the last 180 days; the most recent one is 300 days old.'
        }
        [pscustomobject]@{
            App         = (New-JsonContractFixtureApp -Source 'RegistryUninstall' -Id 'HKLM\Fixture\Uninstall\Used' `
                            -DisplayName 'Fixture used app' -Publisher 'Fixture Ltd' -Detail 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            DisplayName = 'Fixture used app'
            State       = 'Used'
            Reason      = 'Launched 4 days ago, inside the 180-day window.'
        }
        [pscustomobject]@{
            App         = (New-JsonContractFixtureApp -Source 'RegistryUninstall' -Id 'HKLM\Fixture\Uninstall\Silent' `
                            -DisplayName 'Fixture silent app' -Publisher $null -Detail 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            DisplayName = 'Fixture silent app'
            State       = 'Unknown'
            Reason      = 'No usage signal on this machine names this application. That is absence of evidence, not evidence of absence -- it is never reported as unused.'
        }
    )

    $unusedScan = New-JsonContractFixtureScan -Detector 'UnusedApps' -Category 'UnusedApp' `
        -InventoryCount $classifications.Count -Finding @($unusedFinding) `
        -Source @(
            (New-JsonContractFixtureSource -Name 'UserAssist' -Status 'Succeeded' -ItemCount 177 -DurationSeconds 0.75)
            (New-JsonContractFixtureSource -Name 'Prefetch' -Status 'Skipped' -Reason 'The prefetch folder cannot be read without administrator rights.' -ItemCount 0 -DurationSeconds 0.01)
            (New-JsonContractFixtureSource -Name 'FileSystemLastAccess' -Status 'Refused' -Reason 'Not used as a usage signal, by measurement rather than by assumption.' -ItemCount 0 -DurationSeconds 0.02)
        ) `
        -AdditionalProperty ([ordered]@{
            ConsideredCount  = $classifications.Count
            UnknownCount     = 2
            UsedCount        = 1
            UnusedCount      = 2
            ExcludedCount    = 1
            Classifications  = [psobject[]] $classifications
            InventoryVerdict = [psobject[]] @(
                (New-JsonContractFixtureVerdict -Id 'Fixture.Unused_1.0.0.0_x64__8wekyb3d8bbwe' -Class 'Flagged' `
                    -FindingId 'Fixture.Unused_8wekyb3d8bbwe')
                (New-JsonContractFixtureVerdict -Id 'Fixture.Protected_8wekyb3d8bbwe' -Class 'HeldBack' `
                    -RuleId 'antivirus-and-endpoint-security' -RuleClass 'security' `
                    -Reason 'Security software is never flagged as unused, full stop.')
            )
        })

    # ---- OEM bloatware --------------------------------------------------
    $oemFinding = New-Finding -Category OemBloatware -Id 'Fixture.Widget_8wekyb3d8bbwe' `
        -DisplayName 'Fixture Widget' -Confidence Known `
        -Evidence 'Matches curated known-bloatware list entry fixture-widget.' -RemovalMethod Appx
    $oemFinding | Add-Member -MemberType NoteProperty -Name 'WhitelistEntryId' -Value 'fixture-widget'

    # THIS SCAN PUBLISHES VERDICTS AND NO INVENTORY, which is the real shape:
    # the Installed apps section's inventory is the unused-app scan's
    # classifications, and the OEM scan contributes only its judgement of them.
    # InventoryCount is larger here than the classification count on purpose --
    # elevated, this scan reads provisioned packages the unused-app scan does
    # not, and the two counts really do diverge.
    $oemScan = New-JsonContractFixtureScan -Detector 'OemBloatware' -Category 'OemBloatware' `
        -InventoryCount 6 -Finding @($oemFinding) `
        -Source @(
            (New-JsonContractFixtureSource -Name 'AppxPackage' -Status 'Succeeded' -ItemCount 146 -DurationSeconds 1.5)
        ) `
        -AdditionalProperty ([ordered]@{
            InventoryVerdict = [psobject[]] @(
                (New-JsonContractFixtureVerdict -Id 'Fixture.Widget_8wekyb3d8bbwe' -Class 'Flagged' `
                    -FindingId 'Fixture.Widget_8wekyb3d8bbwe')
            )
        })

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

    # THREE CURATED LOCATIONS, AND ONLY ONE OF THEM PRODUCED A FINDING. That is
    # the shape the junk inventory exists for: New-JunkLocation reports EVERY
    # location, including the ones that produced nothing and the ones that could
    # not be read, because "Recycle Bin: 2.3 MiB, not flagged" is inventory the
    # user wants and "Recycle Bin" silently absent is the failure this project
    # is built against.
    #
    # The third one carries Exists = $null, the second of the two tri-states in
    # this payload. Null there means the scan could not tell, which is not the
    # same claim as "the folder is not there".
    $junkLocations = @(
        [pscustomobject]@{
            Id = 'fixture-cache'; DisplayName = 'Fixture web cache'
            Status = 'Succeeded'; StatusReason = $null; Exists = $true; IsAssessed = $true
            InventoryOnly = $false; InventoryOnlyReason = $null
            FileCount = [long] 1400; TotalBytes = [long] 1400000000
            EligibleFileCount = [long] 1234; EligibleBytes = [long] 1220410048
            IsSizeFloor = $true; MinimumAgeDays = 30
        }
        [pscustomobject]@{
            Id = 'fixture-prefetch'; DisplayName = 'Fixture prefetch folder'
            Status = 'Succeeded'; StatusReason = $null; Exists = $true; IsAssessed = $false
            InventoryOnly = $true
            InventoryOnlyReason = 'This location is reported for size only. The curated list marks it as never offered for removal.'
            FileCount = [long] 244; TotalBytes = [long] 52428800
            EligibleFileCount = [long] 0; EligibleBytes = [long] 0
            IsSizeFloor = $false; MinimumAgeDays = 7
        }
        [pscustomobject]@{
            Id = 'windows-temp'; DisplayName = 'System temporary files'
            Status = 'Skipped'
            StatusReason = 'One folder under it could not be listed at this privilege level.'
            Exists = $null; IsAssessed = $true
            InventoryOnly = $false; InventoryOnlyReason = $null
            FileCount = [long] 0; TotalBytes = [long] 0
            EligibleFileCount = [long] 0; EligibleBytes = [long] 0
            IsSizeFloor = $true; MinimumAgeDays = 7
        }
    )

    $junkScan = New-JsonContractFixtureScan -Detector 'JunkFiles' -Category 'JunkFile' `
        -InventoryCount $junkLocations.Count -Finding @($junkFinding) `
        -Source @(
            (New-JsonContractFixtureSource -Name 'fixture-cache' -Status 'Succeeded' -ItemCount 1400 -DurationSeconds 3.125)
            (New-JsonContractFixtureSource -Name 'windows-temp' -Status 'Skipped' -Reason 'One folder under it could not be listed at this privilege level.' -ItemCount 0 -DurationSeconds 0.5)
        ) `
        -AdditionalProperty ([ordered]@{
            MinimumAgeDays = 7
            SizeIsFloor    = $true
            Locations      = [psobject[]] $junkLocations
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
