#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Part A of chunk P4-C1: three fixes carried over from the P3-C3 report, each
    in a file that chunk was told not to touch. They are unrelated to each other
    and unrelated to the review screen, so they are tested here rather than in
    tests\ReviewScreen.Tests.ps1 and the two diffs stay separable.

      A1  Removal\RestorePoint.ps1  -- PreviousRestorePointUtc was a raw
          [datetime] on an object that reaches the APPEND-ONLY ledger inside a
          Note payload. 5.1's ConvertTo-Json writes /Date(ms)/ for one and
          PowerShell 7 writes ISO-8601, so the same code put different bytes in a
          file that is never rewritten depending on which shell ran it. Real
          instance: logs\actions.jsonl line 2.

      A2  Removal\ActionLog.ps1     -- the append retry caught [IOException] to
          retry sharing violations, and DirectoryNotFoundException IS one, so an
          impossible log root cost ~3.2 s of retries before failing. It always
          failed CORRECTLY; this is about the delay only.

      A3  Removal\Dispatcher.ps1    -- PreviousDelayedAutostart is a derived
          boolean, so $false means either "the value was 0" or "the value was
          absent", and those need different undos. DelayedAutostartExisted is
          added beside it, ADDITIVELY.

    THE TEST THAT MATTERS MOST HERE IS THE FIRST ONE, and it is deliberately not
    a test about restore points. P3-C2 already locked ISO-8601 timestamps and its
    test still passes, because it checks the ledger's OWN timestamp fields and
    A1's defect was nested two levels down inside Data. So the assertion this
    file adds is the general one: walk every record written to disk and require
    that ANY property whose name ends 'Utc', at any depth, is an ISO-8601 string.

    Run:  .\tests\Invoke-Tests.ps1        (and -On51, which is not optional)
#>

BeforeAll {
    $script:RepoRoot         = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot       = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath     = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:LedgerSource     = Join-Path $script:EngineRoot 'Removal\ActionLog.ps1'
    $script:RestoreSource    = Join-Path $script:EngineRoot 'Removal\RestorePoint.ps1'
    $script:DispatcherSource = Join-Path $script:EngineRoot 'Removal\Dispatcher.ps1'

    # A log root of our own. The real one is the repo's logs\ folder and its
    # ledger is the one file in this project that is never rotated, so nothing in
    # this suite may write to it.
    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-carried-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-carried-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    $script:Contract = Get-RemovalContract

    $script:LedgerCounter = 0
    function New-LedgerPath {
        $script:LedgerCounter++
        Join-Path $script:Scratch ("ledger-{0:d3}-{1}.jsonl" -f $script:LedgerCounter, [guid]::NewGuid().ToString('N'))
    }

    function New-TestFinding {
        param(
            [Parameter(Mandatory)] [string] $Category,
            [Parameter(Mandatory)] [string] $Id,
            [Parameter(Mandatory)] [string] $RemovalMethod,
            [string] $DisplayName = 'Fabricated item',
            [string] $Confidence = 'Known',
            [switch] $RequiresConsent
        )
        New-Finding -Category $Category -Id $Id -DisplayName $DisplayName `
            -Evidence 'Fabricated by the test suite so this route can be exercised.' `
            -Confidence $Confidence -RequiresConsent:$RequiresConsent -RemovalMethod $RemovalMethod
    }

    # A junk finding with real files behind it, so the plan carries a real
    # FileDeleteSet step and the ledger writes a real manifest sidecar. The
    # sidecar has a LastWriteUtc per file and is therefore part of what the
    # timestamp walk below has to cover -- it is a second file on disk written by
    # the same code path, and "every record on disk" means that one too.
    function New-TestJunkFinding {
        param([int] $FileCount = 3, [int] $Bytes = 32, [string] $Id = 'fabricated-junk')

        $folder = Join-Path $script:Scratch ('junk-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $folder -ItemType Directory -Force

        $files = New-Object System.Collections.Generic.List[psobject]
        for ($i = 1; $i -le $FileCount; $i++) {
            $filePath = Join-Path $folder ("file-$i.tmp")
            [System.IO.File]::WriteAllText($filePath, ('x' * $Bytes))
            $null = $files.Add([pscustomobject]@{
                Path         = $filePath
                SizeBytes    = [long] $Bytes
                # A REAL [datetime], because that is what the junk detector puts
                # on this record and it is the shape the manifest writer has to
                # normalise on its way to disk.
                LastWriteUtc = [datetime]::UtcNow.AddDays(-30)
                LocationId   = $Id
            })
        }

        $finding = New-Finding -Category JunkFile -Id $Id -DisplayName 'Fabricated junk location' `
            -Evidence 'Fabricated by the test suite.' -Confidence Known -RequiresConsent -RemovalMethod FileDelete
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFile'      -Value ([psobject[]] @($files.ToArray()))
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFileCount' -Value $files.Count
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleBytes'     -Value ([long] ($Bytes * $files.Count))
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationId'        -Value $Id
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationPath'      -Value ([string[]] @($folder))
        $finding | Add-Member -MemberType NoteProperty -Name 'IsSizeFloor'       -Value $false
        $finding | Add-Member -MemberType NoteProperty -Name 'MinimumAgeDays'    -Value 7
        $finding
    }

    # ---- THE WALKER (A1) ---------------------------------------------------
    #
    # It works on the RAW TEXT of each line and not on ConvertFrom-Json's output,
    # and that is not a shortcut -- it is the only reading that answers the
    # question. JSON has no date type: ConvertFrom-Json recognises an ISO-8601
    # string and hands back a [datetime] on BOTH shells, so a walk over parsed
    # objects sees [datetime] for a correctly stored string and cannot tell it
    # from the defect. docs\REVIEW.md records this after P3-C2, about this exact
    # class of test.
    #
    # Depth is free as a consequence: the regex does not care how deeply nested
    # the property is, which is the whole point -- A1's defect was two levels
    # down inside Data, where the existing ISO-8601 test does not look.
    $script:UtcPropertyPattern = '"(?<name>[A-Za-z0-9_]*Utc)"\s*:\s*(?<value>"(?:[^"\\]|\\.)*"|null|[^,}\]\s]+)'
    # Round-trip 'o' format, with or without the fractional part, and either a
    # Z or a numeric offset. Nothing else is accepted -- a locale-rendered
    # '08/28/2026 01:08:49' has to fail this as loudly as /Date(...) does.
    $script:UtcIsoPattern = '^"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})"$'

    function Get-UtcTextViolation {
        <#
            Every '*Utc' property in some JSON text that is not an ISO-8601
            string and not null, as a list of readable strings. Empty means
            clean.

            Also returns the count of properties it inspected, through the
            -TotalRef parameter, because a walker that matched nothing would
            report a clean file for the wrong reason and that is exactly the
            silent-pass this project keeps meeting.
        #>
        param(
            [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Line,
            [Parameter(Mandatory)] [string] $Label,
            [Parameter()] [ref] $TotalRef
        )

        $violations = New-Object System.Collections.Generic.List[string]
        $inspected  = 0
        $number     = 0

        foreach ($text in $Line) {
            $number++
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            foreach ($match in [regex]::Matches($text, $script:UtcPropertyPattern)) {
                $inspected++
                $name  = $match.Groups['name'].Value
                $value = $match.Groups['value'].Value
                if ($value -eq 'null') { continue }
                if ($value -match $script:UtcIsoPattern) { continue }
                $null = $violations.Add("${Label} line ${number}: '${name}' is ${value}")
            }
        }

        if ($null -ne $TotalRef) { $TotalRef.Value = $inspected }
        [string[]] @($violations.ToArray())
    }

    # ---- the ledger the walk runs over -------------------------------------
    #
    # Written once here rather than per test, because every It below is a
    # different question about the SAME bytes.
    $script:WalkLedger = New-LedgerPath

    # 1. An intent per route this machine can produce a plan for. Plans carry
    #    VerifiedUtc; the junk one additionally writes the manifest sidecar.
    $script:WalkPlan = [ordered]@{}
    $script:WalkPlan['JunkFileSet'] = Get-RemovalPlan -Finding (New-TestJunkFinding)
    $script:WalkPlan['ServiceStartupType'] = Get-RemovalPlan -Finding (New-TestFinding `
        -Category Service -Id 'w11o-absent-service-carried' -RemovalMethod ServiceDisable -RequiresConsent)

    $appx = @(Get-AppxPackage -ErrorAction SilentlyContinue |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.PackageFamilyName) } | Select-Object -First 1)
    if ($appx.Count -gt 0) {
        $script:WalkPlan['AppxPackage'] = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware `
            -Id ([string] $appx[0].PackageFamilyName) -DisplayName ([string] $appx[0].Name) -RemovalMethod Appx)
    }

    $script:WalkActionId = [ordered]@{}
    foreach ($routeName in @($script:WalkPlan.Keys)) {
        $script:WalkActionId[$routeName] = Write-OptimizerAction -Plan $script:WalkPlan[$routeName] -Path $script:WalkLedger
    }

    # 2. THE RECORD A1 IS ABOUT. A restore-point result carried as a Note
    #    payload, which is exactly how Removal\Executor.ps1 records one, built
    #    through the factory with real [datetime] values so the conversion is
    #    exercised on both shells rather than depending on what this machine's
    #    restore points happen to look like.
    $script:WalkRestoreResult = InModuleScope Win11Optimizer.Engine {
        New-OptimizerRestorePointResult -State 'Throttled' `
            -Reason 'Fabricated by the test suite so the timestamp fields are populated.' `
            -PreviousRestorePointUtc ([datetime]::UtcNow.AddHours(-5)) `
            -CreatedUtc ([datetime]::UtcNow.AddHours(-5)) `
            -ThrottleMinutes 1440 -MinutesSinceLast 300 -IsElevated $true `
            -RestorePointCountBefore 4 -RestorePointCountAfter 4 -DurationSeconds 0.5
    }

    $null = Write-OptimizerAction -Plan $script:WalkPlan['ServiceStartupType'] -RecordKind Note `
        -ActionId $script:WalkActionId['ServiceStartupType'] -Path $script:WalkLedger -Data $script:WalkRestoreResult

    # 3. A real restore-point attempt as well. Unelevated it reports Unavailable
    #    with no timestamps at all, which is a real state and worth having on the
    #    line; elevated it carries the fields the fix is about.
    $null = Write-OptimizerAction -Plan $script:WalkPlan['ServiceStartupType'] -RecordKind Note `
        -ActionId $script:WalkActionId['ServiceStartupType'] -Path $script:WalkLedger `
        -Data (New-OptimizerRestorePoint -ErrorAction SilentlyContinue)

    # 4. An outcome, so OutcomeUtc and the completed shape are on disk too.
    $null = Write-OptimizerAction -Plan $script:WalkPlan['ServiceStartupType'] -RecordKind Outcome `
        -ActionId $script:WalkActionId['ServiceStartupType'] -Path $script:WalkLedger `
        -Result Succeeded -DurationSeconds 0.25

    $script:WalkLine = [string[]] @([System.IO.File]::ReadAllLines($script:WalkLedger))

    # The manifest sidecar the junk action wrote, if there is one.
    $script:WalkManifestLine = [string[]] @()
    $script:WalkManifestPath = $null
    # The folder name is read out of the module rather than restated, so a rename
    # there cannot turn this into a test that skips itself.
    $manifestFolder = Join-Path (Split-Path -Path $script:WalkLedger -Parent) `
        (InModuleScope Win11Optimizer.Engine { $script:ActionManifestFolderName })
    if (Test-Path -LiteralPath $manifestFolder) {
        $manifestFile = @(Get-ChildItem -LiteralPath $manifestFolder -File | Select-Object -First 1)
        if ($manifestFile.Count -gt 0) {
            $script:WalkManifestPath = $manifestFile[0].FullName
            $script:WalkManifestLine = [string[]] @([System.IO.File]::ReadAllLines($script:WalkManifestPath))
        }
    }
}

AfterAll {
    foreach ($path in @($script:Scratch, $script:TestLogRoot)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item Env:\WIN11OPTIMIZER_LOGROOT -ErrorAction SilentlyContinue
}

Describe 'A1: every timestamp on every record on disk is an ISO-8601 string' {

    It 'has something to say -- the walk inspected real properties on real lines' {
        # The guard against the silent pass. A walker whose regex stopped
        # matching would report every file clean and this whole Describe would go
        # green while asserting nothing.
        $script:WalkLine.Count | Should -BeGreaterThan 3

        $total = 0
        $null = Get-UtcTextViolation -Line $script:WalkLine -Label 'ledger' -TotalRef ([ref] $total)
        $total | Should -BeGreaterThan 10 -Because 'each line carries TimestampUtc and a plan VerifiedUtc at minimum'
    }

    It 'catches the defect it was written for' {
        # THE NEGATIVE CONTROL, and it is the real bytes: logs\actions.jsonl line
        # 2 as it was written on 2026-08-28, trimmed to the payload that matters.
        # Without this the test above could pass by never recognising anything.
        $defect = '{"RecordKind":"Note","TimestampUtc":"2026-08-28T06:03:36.7102013Z","Data":{"State":"Throttled","PreviousRestorePointUtc":"\/Date(1787880163160)\/","CheckedUtc":"2026-08-28T06:03:36.6776093Z"}}'
        $found = @(Get-UtcTextViolation -Line @($defect) -Label 'control')
        $found.Count | Should -Be 1
        $found[0] | Should -Match 'PreviousRestorePointUtc'
        $found[0] | Should -Match 'Date\('
    }

    It 'rejects a locale-rendered datetime just as loudly as a /Date( blob' {
        # The other way this goes wrong: a [datetime] that reached the line
        # through a string conversion rather than through ConvertTo-Json.
        $defect = '{"TimestampUtc":"08/28/2026 01:08:49","OtherUtc":"2026-08-28T06:03:36.6776093Z"}'
        $found = @(Get-UtcTextViolation -Line @($defect) -Label 'control')
        $found.Count | Should -Be 1
        $found[0] | Should -Match 'TimestampUtc'
    }

    It 'finds no violation anywhere in the ledger, at any depth' {
        $found = @(Get-UtcTextViolation -Line $script:WalkLine -Label 'ledger')
        $found -join "`n" | Should -BeExactly ''
    }

    It 'finds no violation in the manifest sidecar either' {
        if ($script:WalkManifestLine.Count -lt 1) {
            Set-ItResult -Skipped -Because 'the junk plan produced no manifest on this machine'
            return
        }
        $total = 0
        $found = @(Get-UtcTextViolation -Line $script:WalkManifestLine -Label 'manifest' -TotalRef ([ref] $total))
        $total | Should -BeGreaterThan 0
        $found -join "`n" | Should -BeExactly ''
    }

    It 'reaches PreviousRestorePointUtc specifically -- the property nested inside Data' {
        # Named on purpose. The general assertion above is the one that would
        # have caught this, but a test that only ever asserted "no violations"
        # would also pass on a ledger where the restore-point Note never got
        # written, and this is the line that says it did.
        $matching = @($script:WalkLine | Where-Object { $_ -match '"PreviousRestorePointUtc"' })
        $matching.Count | Should -BeGreaterThan 0
        foreach ($line in $matching) {
            $line | Should -Not -Match 'Date\('
        }
        @($matching | Where-Object { $_ -match '"PreviousRestorePointUtc":"\d{4}-\d{2}-\d{2}T' }).Count |
            Should -BeGreaterThan 0
    }

    It 'keeps the restore-point result''s own timestamps as strings before it goes anywhere' {
        $script:WalkRestoreResult.PreviousRestorePointUtc | Should -BeOfType ([string])
        $script:WalkRestoreResult.CreatedUtc              | Should -BeOfType ([string])
        $script:WalkRestoreResult.CheckedUtc              | Should -BeOfType ([string])
        $script:WalkRestoreResult.PreviousRestorePointUtc | Should -Match '^\d{4}-\d{2}-\d{2}T'
    }

    It 'leaves $null as $null rather than turning it into an empty string' {
        # The tri-state rule this file already applies to Reason. "There was no
        # previous restore point" is not a time, and '' would read as "there was
        # one and its time was blank".
        $result = InModuleScope Win11Optimizer.Engine {
            New-OptimizerRestorePointResult -State 'Unavailable' -Reason 'Fabricated.'
        }
        $result.PreviousRestorePointUtc | Should -BeNullOrEmpty
        $null -eq $result.PreviousRestorePointUtc | Should -BeTrue
        $null -eq $result.CreatedUtc              | Should -BeTrue
    }

    It 'writes the same bytes for the same result whichever shell serialises it' {
        # The actual harm, stated directly: ConvertTo-Json over this object must
        # contain no /Date( at all. Under 5.1 that was false before the fix and
        # under 7 it was true, which is what made it invisible.
        $json = ConvertTo-Json -InputObject $script:WalkRestoreResult -Depth 8 -Compress
        $json | Should -Not -Match 'Date\('
        $json | Should -Match '"PreviousRestorePointUtc":"\d{4}-\d{2}-\d{2}T'
    }

    It 'normalises a [datetime] handed in by a future call site, not just this one' {
        # The fix is in the factory rather than at the four call sites, so a
        # route added later cannot reintroduce it by passing the [datetime] it
        # happens to be holding.
        $result = InModuleScope Win11Optimizer.Engine {
            New-OptimizerRestorePointResult -State 'Created' -CreatedUtc ([datetime]::new(2026, 8, 28, 6, 3, 36, [System.DateTimeKind]::Utc))
        }
        $result.CreatedUtc | Should -BeOfType ([string])
        $result.CreatedUtc | Should -Match '^2026-08-28T06:03:36'
    }
}

Describe 'A2: an impossible log root fails immediately, not 200 attempts later' {

    It 'throws in well under the retry budget' {
        # ~3.2 s before the fix, measured 2026-08-28 on 'Z:\nope\deeper'. The
        # budget is 200 attempts at a 2 ms floor plus up to 8 ms of jitter, so
        # anything under a second cannot have run the loop.
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $message = $null
        try {
            InModuleScope Win11Optimizer.Engine {
                Add-OptimizerActionLine -Path 'Z:\w11o-no-such-volume\deeper\actions.jsonl' -Line 'x' -ErrorAction SilentlyContinue
            }
        }
        catch { $message = $_.Exception.Message }
        $timer.Stop()

        $message | Should -Not -BeNullOrEmpty -Because 'it must still fail'
        $timer.Elapsed.TotalSeconds | Should -BeLessThan 1.0
    }

    It 'still refuses in the same terms -- the caller must not act' {
        # It always failed CORRECTLY. Nothing about the contract changes: the
        # sentence a caller keys on is still there, and the path is still named.
        $message = $null
        try {
            InModuleScope Win11Optimizer.Engine {
                Add-OptimizerActionLine -Path 'Z:\w11o-no-such-volume\deeper\actions.jsonl' -Line 'x' -ErrorAction SilentlyContinue
            }
        }
        catch { $message = $_.Exception.Message }

        $message | Should -Match 'must not be attempted'
        $message | Should -Match 'w11o-no-such-volume'
        $message | Should -Match 'DirectoryNotFoundException'
        $message | Should -Not -Match 'after 200 attempts' -Because 'it did not make 200 attempts'
    }

    It 'decides transient-or-permanent from the exception, not from a second catch clause' {
        # THE SHAPE IS THE FIX, and the obvious shape is wrong on 5.1.
        #
        # DirectoryNotFoundException and FileNotFoundException both derive from
        # IOException, so catching them ahead of it looks like the answer and was
        # the first thing written here. Measured on Windows PowerShell 5.1
        # (5.1.26100.9168, 2026-08-28): inside a retry loop the engine picks the
        # IOException clause for the first ~17-20 throws of an identical error
        # and then starts picking the FileNotFoundException clause instead, for
        # the SAME exception -- chain MethodInvocationException ->
        # System.IO.IOException, message "because it is being used by another
        # process" -- on every attempt. PowerShell 7 never does it.
        #
        # So the retry loop must have exactly ONE typed clause, and the decision
        # must be made against the exception object.
        $tokens = $null
        $errors = $null
        $parsed = [System.Management.Automation.Language.Parser]::ParseFile($script:LedgerSource, [ref] $tokens, [ref] $errors)
        @($errors).Count | Should -Be 0

        $function = @($parsed.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Add-OptimizerActionLine'
        }, $true))
        $function.Count | Should -Be 1

        $try = @($function[0].FindAll({
            param($node) $node -is [System.Management.Automation.Language.TryStatementAst]
        }, $true))
        $try.Count | Should -BeGreaterThan 0

        $caught = [string[]] @($try[0].CatchClauses | ForEach-Object {
            [string] @($_.CatchTypes)[0].TypeName.FullName
        })
        $caught -join ' -> ' | Should -BeExactly 'System.IO.IOException' -Because 'more than one typed clause is what 5.1 gets wrong'

        $invoked = [string[]] @($function[0].FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object {
            $element = $_.CommandElements[0]
            if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $element.Value } else { '' }
        })
        $invoked | Should -Contain 'Test-OptimizerActionLogPermanentFailure'
    }

    It 'reads a real exception object, whatever wrapped it' -ForEach @(
        @{ Case = 'directory not found'; Type = 'System.IO.DirectoryNotFoundException'; Permanent = $true }
        @{ Case = 'file not found';      Type = 'System.IO.FileNotFoundException';      Permanent = $true }
        @{ Case = 'sharing violation';   Type = 'System.IO.IOException';                Permanent = $false }
        @{ Case = 'access denied';       Type = 'System.UnauthorizedAccessException';   Permanent = $false }
    ) {
        # The discriminator on its own, against real exception objects wrapped
        # the way PowerShell wraps a .NET method's throw.
        $expected = $Permanent
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ TypeName = $Type } {
            param($TypeName)
            $exception = New-Object -TypeName $TypeName -ArgumentList 'fabricated'
            $wrapped = New-Object System.Management.Automation.MethodInvocationException 'fabricated', $exception
            $record = New-Object System.Management.Automation.ErrorRecord $wrapped, 'Fabricated', 'NotSpecified', $null
            Test-OptimizerActionLogPermanentFailure -ErrorRecord $record
        }
        $observed | Should -Be $expected
    }

    It 'says no for a null error record rather than throwing' {
        InModuleScope Win11Optimizer.Engine { Test-OptimizerActionLogPermanentFailure -ErrorRecord $null } | Should -BeFalse
    }

    It 'still retries a sharing violation, which is the failure that can clear' {
        # The other half of the fix, and the one that would be destroyed by
        # over-correcting: a second writer holding the file must still be waited
        # for. The reader share is what makes this observable without a second
        # process -- FileShare.Read lets us open it for reading, and the append
        # path asks for write access it cannot have while we hold it.
        #
        # THIS IS THE TEST THAT CAUGHT THE 5.1 CLAUSE-MATCHING DEFECT, and only
        # because it runs the whole retry budget rather than a handful of
        # attempts: the engine picks the right clause for the first ~17-20 and
        # the wrong one after that, so a three-attempt version of this test would
        # have passed on both shells and shipped the bug.
        $path = New-LedgerPath
        [System.IO.File]::WriteAllText($path, '')

        $holder = New-Object System.IO.FileStream(
            $path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
        try {
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            $message = $null
            try {
                InModuleScope Win11Optimizer.Engine -Parameters @{ Target = $path } {
                    param($Target)
                    Add-OptimizerActionLine -Path $Target -Line 'x' -ErrorAction SilentlyContinue
                }
            }
            catch { $message = $_.Exception.Message }
            $timer.Stop()
        }
        finally { $holder.Dispose() }

        $message | Should -Match 'after 200 attempts' -Because 'a sharing violation is the one failure worth waiting on'
        $timer.Elapsed.TotalSeconds | Should -BeGreaterThan 0.3
    }

    It 'writes normally when the folder simply does not exist yet' {
        # The fix must not turn "create the folder on first write" into a
        # failure. That is the ordinary case on a fresh install.
        $path = Join-Path $script:Scratch ('fresh-' + [guid]::NewGuid().ToString('N') + '\actions.jsonl')
        InModuleScope Win11Optimizer.Engine -Parameters @{ Target = $path } {
            param($Target)
            Add-OptimizerActionLine -Path $Target -Line 'hello'
        }
        [System.IO.File]::ReadAllText($path).Trim() | Should -BeExactly 'hello'
    }
}

Describe 'A3: DelayedAutostartExisted, beside PreviousDelayedAutostart and never instead of it' {

    It 'tells "the value was 0" apart from "the value was absent"' -ForEach @(
        @{ Case = 'absent';    Delayed = $null; Existed = $false; Previous = $false }
        @{ Case = 'present-0'; Delayed = 0;     Existed = $true;  Previous = $false }
        @{ Case = 'present-1'; Delayed = 1;     Existed = $true;  Previous = $true  }
    ) {
        # The three states, driven through the route function with the registry
        # reads mocked. This machine's one real Service finding covers only
        # 'present-0'; the other two are shapes it cannot produce, and creating a
        # service key to get them would be a machine change this project does not
        # make for a test.
        #
        # $Case / $Delayed are read into locals before anything pipes, because
        # $_ inside a Where-Object nested in a -ForEach block is the pipeline
        # element and not the -ForEach value. docs\REVIEW.md, after P3-C1a.
        $expectedExisted  = $Existed
        $expectedPrevious = $Previous

        $rollback = InModuleScope Win11Optimizer.Engine -Parameters @{ Delayed = $Delayed } {
            param($Delayed)

            Mock Get-RemovalRegistryKeyState {
                [pscustomobject]@{
                    Exists    = $true
                    ValueName = [string[]] @('Start', 'DelayedAutostart', 'ImagePath', 'DisplayName')
                    Reason    = $null
                }
            }
            Mock Test-RemovalServiceKeyWritable { $true }
            Mock Get-RemovalRegistryValue {
                switch ($Name) {
                    'Start'            { 2 }
                    'DelayedAutostart' { $Delayed }
                    'DisplayName'      { 'Fabricated service' }
                    'ImagePath'        { 'C:\Windows\System32\w11o-no-such-binary.exe' }
                    default            { $null }
                }
            }

            $finding = New-Finding -Category Service -Id 'w11o-fabricated-service' `
                -DisplayName 'Fabricated service' -Evidence 'Fabricated by the test suite.' `
                -Confidence Known -RequiresConsent -RemovalMethod ServiceDisable

            $builder = New-RemovalPlanBuilder -Finding $finding -Route $script:RemovalRouteServiceStartup
            Add-RemovalServiceRoute -Builder $builder -ExclusionEntry @()
            $builder.RollbackData
        }

        $rollback.DelayedAutostartExisted  | Should -BeOfType ([bool])
        $rollback.DelayedAutostartExisted  | Should -Be $expectedExisted
        $rollback.PreviousDelayedAutostart | Should -Be $expectedPrevious
    }

    It 'is on the plan a real Service finding produces on this machine' {
        $findings = @((Invoke-StartupItemScan 3>$null).Findings | Where-Object { $_.Category -eq 'Service' })
        if ($findings.Count -lt 1) {
            Set-ItResult -Skipped -Because 'this machine produced no Service finding'
            return
        }
        $plan = Get-RemovalPlan -Finding $findings[0]
        if ($null -eq $plan.RollbackData -or -not $plan.Supported) {
            Set-ItResult -Skipped -Because 'the one Service finding on this machine did not reach the capture'
            return
        }

        @($plan.RollbackData.PSObject.Properties.Name) | Should -Contain 'DelayedAutostartExisted'
        @($plan.RollbackData.PSObject.Properties.Name) | Should -Contain 'PreviousDelayedAutostart'
        $plan.RollbackData.DelayedAutostartExisted | Should -BeOfType ([bool])

        # And it agrees with the registry, read independently of the dispatcher.
        $live = $null
        try { $live = Get-ItemPropertyValue -LiteralPath $plan.RollbackData.KeyPath -Name 'DelayedAutostart' -ErrorAction Stop }
        catch { $live = $null }
        $plan.RollbackData.DelayedAutostartExisted | Should -Be ($null -ne $live)
    }

    It 'survives the ledger round trip as a real boolean' {
        # It only earns its place if it is still there when the ledger is read
        # back, which is the whole reason for capturing it now rather than later.
        $rollback = [pscustomobject][ordered]@{
            ServiceName              = 'w11o-fabricated-service'
            KeyPath                  = 'HKLM:\SYSTEM\CurrentControlSet\Services\w11o-fabricated-service'
            PreviousStartValue       = 2
            PreviousDelayedAutostart = $false
            DelayedAutostartExisted  = $true
        }
        $restored = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $rollback -Depth 8)
        $restored.DelayedAutostartExisted  | Should -BeOfType ([bool])
        $restored.DelayedAutostartExisted  | Should -BeTrue
        $restored.PreviousDelayedAutostart | Should -BeFalse
    }

    It 'leaves every other route''s RollbackData shape exactly as it was' {
        # The acceptance criterion, asserted against the SOURCE rather than
        # against whatever plans this machine can produce -- three of the seven
        # routes have never met a real Finding on this hardware, so a live check
        # could only ever pin four of them.
        #
        # Each row is one assignment to $Builder.RollbackData in Dispatcher.ps1,
        # in source order. Exactly one of them differs from the P3-C2 build, by
        # exactly one added name.
        $expected = @(
            'PackageFamilyName, PackageFullName, Version, ProvisionedPackageName, ProvisionedState, OtherUserRegistration, Note'
            'KeyPath, Note'
            'KeyPath, DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallValueName, UninstallString, Note'
            'ApprovalKeyPath, ValueName, Note'
            'ApprovalKeyPath, ValueName, ValueKind, ValueExisted, PreviousByte, PreviousHex, StartupItemPath, Scope, Note'
            'TaskPath, Note'
            'TaskPath, WasEnabled, Trigger, TaskXml, Note'
            'ServiceName, KeyPath, Note'
            'ServiceName, DisplayName, KeyPath, PreviousStartValue, PreviousStartupType, PreviousDelayedAutostart, DelayedAutostartExisted, Note'
            'LocationId, LocationPath, FileCount, TotalBytes, IsSizeFloor, FileManifest, Note'
        )

        $tokens = $null
        $errors = $null
        $parsed = [System.Management.Automation.Language.Parser]::ParseFile($script:DispatcherSource, [ref] $tokens, [ref] $errors)
        @($errors).Count | Should -Be 0

        $observed = [string[]] @($parsed.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$Builder.RollbackData'
        }, $true) | ForEach-Object {
            $table = @($_.Right.FindAll({
                param($node) $node -is [System.Management.Automation.Language.HashtableAst]
            }, $true))[0]
            (@($table.KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text })) -join ', '
        })

        $observed.Count | Should -Be $expected.Count
        for ($i = 0; $i -lt $expected.Count; $i++) {
            $observed[$i] | Should -BeExactly $expected[$i]
        }
    }

    It 'does not change Executor.ps1' {
        # The instruction, kept as an assertion rather than as a promise. The
        # executor's rule -- restore DelayedAutostart only where the record says
        # it was switched ON -- stays exactly as it is, and the new field is not
        # read by it.
        $executorSource = Join-Path $script:EngineRoot 'Removal\Executor.ps1'
        (Test-Path -LiteralPath $executorSource) | Should -BeTrue
        [System.IO.File]::ReadAllText($executorSource) | Should -Not -Match 'DelayedAutostartExisted'
    }
}
