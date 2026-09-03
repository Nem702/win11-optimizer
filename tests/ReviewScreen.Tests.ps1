#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the console review screen (chunk P4-C1,
    src\Win11Optimizer.Engine\Review\Screen.ps1).

    THE FIRST DESCRIBE IS THE ONE THAT MATTERS MOST. It re-applies the same
    no-removal enforcement P3-C1 and P3-C2 apply to their own files, to this one,
    and adds the rule this chunk exists under: this file must not call
    Invoke-RemovalPlan. Not behind a switch, not behind a -Force, not at all.
    Wiring a confirmed selection to the executor is P4-C2, and the moment this
    screen can start something it stops being a screen.

    After that the suite is about the failures a review screen actually has,
    which are failures of TRUTH rather than of code:

      * a category total printed without the per-row split that makes it
        readable -- one row here is 92% of the bytes;
      * a partial scan rendered as if it were complete;
      * a safety label re-derived instead of run through the contract's rule;
      * a benefit claim, in any of the words this project has banned;
      * a selection that quietly includes something nobody chose;
      * a confirmation that reads anything other than 'yes' as yes.

    The deciding functions are tested properly and the renderer is spot-checked,
    which is the split the chunk was asked for.

    Run:  .\tests\Invoke-Tests.ps1        (and -On51, which is not optional)
#>

# Discovery-time, for the -ForEach that makes one test per forbidden phrase.
# Pester runs a file's top level during discovery and its BeforeAll during the
# run, in separate scopes, so the list is dot-sourced in both.
. (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
$ForbiddenPhrase = Get-OptimizerForbiddenPhrase

BeforeAll {
    $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot   = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath   = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:ScreenSource = Join-Path $script:EngineRoot 'Review\Screen.ps1'

    # A log root of our own. The repo's real ledger is never rotated and nothing
    # in this suite may write to it -- and Get-ReviewScreen reads it for the
    # receipt, so this also keeps the rendered screen independent of whatever
    # this machine's ledger happens to contain.
    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-review-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot
    $null = New-Item -Path $script:TestLogRoot -ItemType Directory -Force

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-review-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    $script:FindingContract = Get-FindingContract

    $script:NewExport = @(
        'Get-ReviewScreen'
        'Format-ReviewScreen'
        'Get-ReviewSelection'
        'Get-ReviewConfirmation'
        'Show-ReviewScreen'
    )

    # ---- the source, comment-blanked, and the AST --------------------------
    #
    # Same machinery as tests\RemovalDispatcher.Tests.ps1 and
    # tests\ActionLog.Tests.ps1. Repeated rather than shared for the reason those
    # files give: a source-scanning assertion that lives somewhere else is one
    # refactor away from scanning nothing.
    $script:Raw = [System.IO.File]::ReadAllText($script:ScreenSource)
    $script:Tokens = $null
    $script:Errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScreenSource, [ref] $script:Tokens, [ref] $script:Errors)

    # Offsets preserved -- only non-newline characters inside a comment span
    # become spaces -- because this file has to be able to NAME the things it
    # never does, and -match is case-insensitive.
    $builder = New-Object System.Text.StringBuilder $script:Raw
    foreach ($token in @($script:Tokens | Where-Object { $_.Kind -eq 'Comment' })) {
        $start  = $token.Extent.StartOffset
        $length = $token.Extent.EndOffset - $start
        for ($i = 0; $i -lt $length; $i++) {
            if ($builder[$start + $i] -ne "`n" -and $builder[$start + $i] -ne "`r") {
                $builder[$start + $i] = ' '
            }
        }
    }
    $script:Blanked = $builder.ToString()

    $script:Invoked = [string[]] @(
        $script:Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object {
            $element = $_.CommandElements[0]
            if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $element.Value } else { "<dynamic:$($element.Extent.Text)>" }
        } | Sort-Object -Unique
    )

    # ---- the forbidden benefit-claim phrases -------------------------------
    #
    # One file, read by every suite that enforces them -- tests\ForbiddenPhrase.ps1,
    # P5-C3 change 5. It replaces the AST extractor that lived here, in
    # tests\ActionLog.Tests.ps1 and in tests\ExecutePlan.Tests.ps1, three copies
    # of the same twenty lines, needed only because the lists lived in two other
    # suites and disagreed with each other.
    . (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
    $script:ForbiddenPhrase = Get-OptimizerForbiddenPhrase

    # ---- fixtures: fabricated scans ----------------------------------------
    #
    # Every section is tested against a scan result built here, so the shapes the
    # screen has to survive -- an empty category, a partial scan, an age window
    # that differs per row -- are all reachable rather than dependent on what
    # this machine happens to look like today. The real machine gets its own
    # Describe at the end.

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
            -Evidence 'Fabricated by the test suite so this row can be rendered. It has a second sentence.' `
            -Confidence $Confidence -RequiresConsent:$RequiresConsent -RemovalMethod $RemovalMethod
    }

    function New-TestJunkFinding {
        param(
            [Parameter(Mandatory)] [string] $Id,
            [Parameter(Mandatory)] [string] $DisplayName,
            [Parameter(Mandatory)] [long] $Bytes,
            [long] $FileCount = 10,
            [int] $MinimumAgeDays = 7,
            [switch] $IsSizeFloor
        )
        $finding = New-Finding -Category JunkFile -Id $Id -DisplayName $DisplayName `
            -Evidence 'Fabricated by the test suite.' -Confidence Known -RequiresConsent -RemovalMethod FileDelete
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationId'        -Value $Id
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationPath'      -Value ([string[]] @("C:\w11o-fabricated\$Id"))
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleBytes'     -Value ([long] $Bytes)
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFileCount' -Value ([long] $FileCount)
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFile'      -Value ([psobject[]] @())
        $finding | Add-Member -MemberType NoteProperty -Name 'IsSizeFloor'       -Value ([bool] $IsSizeFloor)
        $finding | Add-Member -MemberType NoteProperty -Name 'MinimumAgeDays'    -Value $MinimumAgeDays
        $finding
    }

    # A scan result as data. Deliberately NOT built through New-ScanResult: the
    # screen has to render a scan that arrived deserialized from a log too, and
    # a fixture that could only ever be a live object would not prove that.
    function New-TestScan {
        param(
            [Parameter(Mandatory)] [hashtable] $Property,
            [Parameter()] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Finding = @()
        )
        $scan = [pscustomobject]@{ Findings = [psobject[]] @($Finding) }
        foreach ($key in @($Property.Keys)) {
            $scan | Add-Member -MemberType NoteProperty -Name ([string] $key) -Value $Property[$key]
        }
        $scan
    }

    $script:StartupScan = New-TestScan -Property @{
        IsComplete            = $true
        IncompleteReason      = $null
        RefusedSourceName     = [string[]] @()
        InventoryCount        = 149
        EnabledCount          = 121
        DisabledCount         = 28
        UnknownStateCount     = 0
        ProtectedTaskCount    = 41
        ProtectedServiceCount = 10
        MechanismCount        = [ordered]@{ RunKey = 15; StartupFolder = 0; ScheduledTask = 44; Service = 90 }
        StartupItems          = [psobject[]] @(
            [pscustomobject]@{ Mechanism = 'Service'; Id = 'w11o-fabricated-service'; EnabledState = 'Enabled' }
        )
    } -Finding @(
        (New-TestFinding -Category StartupItem -Id 'HKCU:\...\Run::Fabricated' -DisplayName 'Fabricated startup entry' -RemovalMethod RegistryRunKey -RequiresConsent)
        (New-TestFinding -Category Service -Id 'w11o-fabricated-service' -DisplayName 'Fabricated service' -RemovalMethod ServiceDisable -RequiresConsent)
    )

    # StartupItem findings carry a FindingReason; the fabricated ones above do
    # not, so one is given a real one to prove the mapping runs.
    @($script:StartupScan.Findings)[0] | Add-Member -MemberType NoteProperty -Name 'Mechanism' -Value 'RunKey'
    @($script:StartupScan.Findings)[0] | Add-Member -MemberType NoteProperty -Name 'FindingReason' -Value 'Orphan'

    $script:UnusedScan = New-TestScan -Property @{
        IsComplete        = $false
        IncompleteReason  = 'Prefetch [Skipped]: fabricated reason for the test suite.'
        RefusedSourceName = [string[]] @('FileSystemLastAccess')
        ConsideredCount   = 286
        UsedCount         = 46
        UnusedCount       = 0
        UnknownCount      = 234
        ExcludedCount     = 6
        InventoryCount    = 286
    }

    $script:OemScan = New-TestScan -Property @{
        IsComplete        = $true
        IncompleteReason  = $null
        RefusedSourceName = [string[]] @()
        InventoryCount    = 286
    } -Finding @(
        (New-TestFinding -Category OemBloatware -Id 'Fabricated.One_8wekyb3d8bbwe' -DisplayName 'Fabricated bloatware' -RemovalMethod Appx)
    )

    # 92.6% in one row, the shape docs\STATE.md pins as this screen's whole
    # reason for refusing a bare category total.
    $script:JunkScan = New-TestScan -Property @{
        IsComplete         = $true
        IncompleteReason   = $null
        RefusedSourceName  = [string[]] @()
        InventoryCount     = 15
        MinimumAgeDays     = 7
        SizeIsFloor        = $true
        # DELIBERATELY DIFFERENT from the sum of the findings below: locations
        # that produced no Finding are in this number, and the screen's total
        # must come from the rows and never from here.
        TotalEligibleBytes = [long] 99999999999
        TotalEligibleFiles = [long] 99999
    } -Finding @(
        (New-TestJunkFinding -Id 'nvidia-shader-cache' -DisplayName 'NVIDIA shader cache' -Bytes 29535260286 -FileCount 773 -MinimumAgeDays 30)
        (New-TestJunkFinding -Id 'user-temp' -DisplayName 'Per-user temporary files' -Bytes 1220410048 -FileCount 1335)
        (New-TestJunkFinding -Id 'wer-queue' -DisplayName 'Windows Error Reporting queues' -Bytes 65656 -FileCount 2 -IsSizeFloor)
    )

    $script:EmptyJunkScan = New-TestScan -Property @{
        IsComplete         = $true
        IncompleteReason   = $null
        RefusedSourceName  = [string[]] @()
        InventoryCount     = 15
        MinimumAgeDays     = 7
        SizeIsFloor        = $false
        TotalEligibleBytes = [long] 99999999999
        TotalEligibleFiles = [long] 99999
    } -Finding @()

    $script:Screen = Get-ReviewScreen -StartupScan $script:StartupScan -UnusedAppScan $script:UnusedScan `
        -OemScan $script:OemScan -JunkScan $script:JunkScan -SkipReceipt
    $script:Lines = [string[]] @(Format-ReviewScreen -Screen $script:Screen -Width 100)
    $script:Text  = ($script:Lines -join "`n")

    function Get-Section {
        param([Parameter(Mandatory)] [string] $Key)
        # $Key is captured before the pipeline: $_ inside a Where-Object is the
        # pipeline element. docs\REVIEW.md, after P3-C1a.
        $wanted = $Key
        @($script:Screen.Section | Where-Object { $_.Key -eq $wanted })[0]
    }

    # A reader that answers from a queue, so the interaction is driven by data
    # and the transcript can be asserted on exactly.
    function New-ScriptedRun {
        param([Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Answer)
        $queue = New-Object 'System.Collections.Generic.Queue[string]'
        foreach ($item in $Answer) { $queue.Enqueue($item) }
        $written = New-Object System.Collections.Generic.List[string]
        $asked   = New-Object System.Collections.Generic.List[string]
        [pscustomobject]@{
            Written = $written
            Asked   = $asked
            Reader  = { param($Prompt) $null = $asked.Add([string] $Prompt); $(if ($queue.Count -gt 0) { $queue.Dequeue() } else { '' }) }.GetNewClosure()
            Writer  = { param($Line) $null = $written.Add([string] $Line) }.GetNewClosure()
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

Describe 'The review screen collects a decision and runs nothing' {

    It 'parses' {
        @($script:Errors).Count | Should -Be 0
    }

    It 'never invokes the executor, under any name' {
        # THE RULE OF THIS CHUNK. Asserted against invoked CommandAst nodes, not
        # against a grep -- a grep is satisfied by splitting the string, and this
        # file legitimately NAMES Invoke-RemovalPlan in its own comments to say
        # that it does not call it.
        foreach ($forbidden in 'Invoke-RemovalPlan', 'Undo-RemovalAction', 'Write-OptimizerAction', 'New-OptimizerRestorePoint') {
            $script:Invoked | Should -Not -Contain $forbidden
        }
    }

    It 'invokes nothing that changes the machine' {
        # The same list P3-C1 and P3-C2 hold their own files to.
        foreach ($forbidden in
            'Remove-Item', 'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Clear-Item',
            'Set-Item', 'New-Item', 'Move-Item', 'Rename-Item', 'Set-Content', 'Add-Content', 'Out-File',
            'Remove-AppxPackage', 'Remove-AppxProvisionedPackage', 'Set-Service', 'Stop-Service',
            'Disable-ScheduledTask', 'Unregister-ScheduledTask', 'Start-Process', 'Checkpoint-Computer',
            'Invoke-Expression', 'Invoke-Item') {
            $script:Invoked | Should -Not -Contain $forbidden
        }
    }

    It 'runs no external program' {
        foreach ($forbidden in 'msiexec', 'winget', 'rundll32', 'cmd', 'powershell', 'pwsh', 'reg', 'sc') {
            $script:Invoked | Should -Not -Contain $forbidden
        }
    }

    It 'has no switch that could turn execution on' {
        # A parameter named for doing rather than showing would be the first
        # symptom of this file growing into P4-C2 by accident.
        $parameters = [string[]] @($script:Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.ParameterAst]
        }, $true) | ForEach-Object { $_.Name.VariablePath.UserPath } | Sort-Object -Unique)

        foreach ($forbidden in 'Execute', 'Run', 'Perform', 'Apply', 'Force', 'Remove', 'Commit') {
            $parameters | Should -Not -Contain $forbidden
        }
    }

    It 'says so in the object it hands back' {
        $run = New-ScriptedRun -Answer @('a', 'a', 'a', 'a', 'yes')
        $selection = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer
        $selection.Executed | Should -BeFalse
        $selection.Note     | Should -Match 'Nothing on this PC has been changed'
    }

    It 'is ASCII, every byte of it' {
        # One non-ASCII character in a comment takes down 137 unrelated tests on
        # 5.1 only, and the error names a line in the test harness rather than
        # the character. docs\REVIEW.md, after P3-C1a.
        $offenders = @([regex]::Matches($script:Raw, '[^\x09\x0A\x0D\x20-\x7E]'))
        $offenders.Count | Should -Be 0
    }

    It 'exports exactly the five functions this chunk adds' {
        $module = Get-Module Win11Optimizer.Engine
        foreach ($name in $script:NewExport) {
            @($module.ExportedFunctions.Keys) | Should -Contain $name
        }

        # And every function defined in this file that is NOT exported stays
        # internal, so the public surface is a decision rather than an accident.
        $defined = [string[]] @($script:Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | ForEach-Object { $_.Name })
        $defined.Count | Should -BeGreaterThan $script:NewExport.Count

        $exportedFromThisFile = @($defined | Where-Object { @($module.ExportedFunctions.Keys) -contains $_ })
        @($exportedFromThisFile | Sort-Object) -join ',' | Should -BeExactly (@($script:NewExport | Sort-Object) -join ',')
    }
}

Describe 'Nothing it prints makes a claim about what this PC will do afterwards' {

    It 'reads a real forbidden-phrase list out of the existing suites' {
        # The guard against a vacuous pass: if the extractor stops finding the
        # lists, every assertion below becomes a loop over nothing.
        $script:ForbiddenPhrase.Count | Should -BeGreaterOrEqual 10 -Because "ten phrases is the union tests\ForbiddenPhrase.ps1 ships; a shorter list means something silently stopped being enforced"
        $script:ForbiddenPhrase | Should -Contain 'free up'
    }

    It 'never says <_>' -ForEach $ForbiddenPhrase {
        # One named test per phrase, from tests\ForbiddenPhrase.ps1. This was a
        # hand-written subset of seven beside the extracted list; it is the whole
        # list now, so the two can no longer drift apart.
        $phrase = $PSItem
        $script:Text.IndexOf($phrase, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1
    }

    It 'never says any phrase on the extracted list, on a full screen' {
        foreach ($phrase in $script:ForbiddenPhrase) {
            $script:Text.IndexOf($phrase, [System.StringComparison]::OrdinalIgnoreCase) |
                Should -Be -1 -Because "the screen must not say '$phrase'"
        }
    }

    It 'says the opposite, plainly, where it prints a size' {
        $script:Text | Should -Match 'on disk now'
        $script:Text | Should -Match 'Nothing on this PC has been changed'
    }

    It 'never says any of them in the source, comments aside' {
        foreach ($phrase in $script:ForbiddenPhrase) {
            $script:Blanked.IndexOf($phrase, [System.StringComparison]::OrdinalIgnoreCase) |
                Should -Be -1 -Because "no literal in Screen.ps1 may say '$phrase'"
        }
    }
}

Describe 'Junk files: a category total is impossible without the per-row split' {

    BeforeAll {
        $script:JunkSection = Get-Section -Key 'JunkFiles'
        $script:EmptyJunkSection = InModuleScope Win11Optimizer.Engine -Parameters @{ Scan = $script:EmptyJunkScan } {
            param($Scan)
            Get-ReviewJunkSection -Scan $Scan
        }
    }

    It 'produces no total at all when there are no rows' {
        # THE STRUCTURAL HALF. There is no code path that computes a category
        # figure without rows, because the figure IS the rows summed.
        @($script:EmptyJunkSection.Row).Count | Should -Be 0
        $script:EmptyJunkSection.TotalLine | Should -BeNullOrEmpty
    }

    It 'prints no size at all when there are no rows' {
        $lines = InModuleScope Win11Optimizer.Engine -Parameters @{ Section = $script:EmptyJunkSection } {
            param($Section)
            Format-ReviewSection -Section $Section -Width 100 -Colour $false
        }
        $text = ($lines -join "`n")
        # Both spellings. P5-C3 changed the labels from KB/MB/GB to the binary
        # KiB/MiB/GiB the divisors always meant; on a NEGATIVE assertion keeping
        # the old three as well only widens what is forbidden, and it is the
        # spelling a regression would print.
        $text | Should -Not -Match '\d+(\.\d+)?\s*(bytes|KiB|MiB|GiB|KB|MB|GB)'
        $text | Should -Match 'No location holds anything'
    }

    It 'sums the rows and not the scan, where the two differ' {
        # The fixture's TotalEligibleBytes is 99999999999 and includes locations
        # that produced no Finding. The screen must never show that number.
        $rowSum = [long] 0
        foreach ($finding in @($script:JunkScan.Findings)) { $rowSum += [long] $finding.EligibleBytes }
        $rowSum | Should -Not -Be ([long] $script:JunkScan.TotalEligibleBytes)

        $script:JunkSection.TotalLine | Should -Match ([regex]::Escape((InModuleScope Win11Optimizer.Engine -Parameters @{ Bytes = $rowSum } {
            param($Bytes)
            Format-JunkSize -Bytes $Bytes
        })))

        $text = ($script:Lines -join "`n")
        # 93.1 is the fixture's TotalEligibleBytes rendered by Format-JunkSize;
        # the unit moved to GiB in P5-C3, and the bare number is forbidden with
        # either unit after it so this cannot go quietly vacuous again.
        $text | Should -Not -Match '93\.1 Gi?B' -Because 'that is the scan-wide figure the rows do not account for'
    }

    It 'prints the total only after every row' {
        $lines = InModuleScope Win11Optimizer.Engine -Parameters @{ Section = $script:JunkSection } {
            param($Section)
            Format-ReviewSection -Section $Section -Width 100 -Colour $false
        }
        $totalIndex = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match 'rows above come to') { $totalIndex = $i; break }
        }
        $totalIndex | Should -BeGreaterThan 0

        foreach ($row in @($script:JunkSection.Row)) {
            $rowIndex = -1
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i].Contains($row.DisplayName)) { $rowIndex = $i; break }
            }
            $rowIndex | Should -BeGreaterThan 0 -Because "row '$($row.DisplayName)' must be rendered"
            $rowIndex | Should -BeLessThan $totalIndex -Because 'the split comes before the figure it explains'
        }
    }

    It 'names the largest row''s share of that total' {
        # The measured reason this rule exists: one row is 92.6% of the bytes on
        # this machine, and a reader who sees only the total learns the opposite
        # of the truth.
        $script:JunkSection.TotalLine | Should -Match 'largest single row is 9[0-9](\.\d)?%'
    }

    It 'gives every row its own size, file count and age window' {
        $rows = @($script:JunkSection.Row)
        $rows.Count | Should -Be 3
        foreach ($row in $rows) {
            @($row.Cell).Count | Should -Be 6
            # Binary units, spelled as binary units -- see Format-JunkSize. The
            # decimal spellings are NOT accepted here: this is the positive
            # assertion, and accepting both would let the labels drift back.
            $row.Cell[2] | Should -Match '(bytes|KiB|MiB|GiB)'
            $row.Cell[4] | Should -Match '^\d+ days$'
        }
    }

    It 'shows a row''s own age window where it differs from the scan''s' {
        # The shader cache is measured at 30 days while the scan uses 7. A row
        # that quoted the scan's window would be saying something untrue about
        # that row in particular.
        $rows = @($script:JunkSection.Row)
        $shader = @($rows | Where-Object { $_.DisplayName -eq 'NVIDIA shader cache' })[0]
        $shader.Cell[4] | Should -BeExactly '30 days'

        $temp = @($rows | Where-Object { $_.DisplayName -eq 'Per-user temporary files' })[0]
        $temp.Cell[4] | Should -BeExactly '7 days'

        ($script:JunkSection.Note -join ' ') | Should -Match '7-day age window'
    }

    It 'marks a floored size as a floor rather than as a total' {
        $rows = @($script:JunkSection.Row)
        $floored = @($rows | Where-Object { $_.DisplayName -eq 'Windows Error Reporting queues' })[0]
        $floored.Cell[2] | Should -Match 'or more$'
        ($script:JunkSection.Note -join ' ') | Should -Match 'floor and not a total'
    }
}

Describe 'Startup items: the inventory is the headline, the finding is the annotation' {

    BeforeAll { $script:StartupSection = Get-Section -Key 'StartupItems' }

    It 'leads with how many things start with this PC and how many are already off' {
        $script:StartupSection.Headline[0] | Should -BeExactly '149 things start with your PC, 28 already off.'
    }

    It 'says it before it says anything about findings' {
        $lines = InModuleScope Win11Optimizer.Engine -Parameters @{ Section = $script:StartupSection } {
            param($Section)
            Format-ReviewSection -Section $Section -Width 100 -Colour $false
        }
        $inventoryIndex = -1
        $rowIndex = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($inventoryIndex -lt 0 -and $lines[$i] -match '149 things start with your PC') { $inventoryIndex = $i }
            if ($rowIndex -lt 0 -and $lines[$i].Contains('Fabricated startup entry')) { $rowIndex = $i }
        }
        $inventoryIndex | Should -BeGreaterThan 0
        $rowIndex | Should -BeGreaterThan $inventoryIndex
    }

    It 'breaks the inventory down by mechanism, reading the dictionary the scan actually carries' {
        # MechanismCount is an [ordered] hashtable and PSObject.Properties cannot
        # see its keys at all, so a naive read renders '0 Windows services' on a
        # machine with 90. Pinned here because the symptom is a plausible number
        # rather than an error.
        ($script:StartupSection.Headline -join ' ') | Should -Match '15 registry Run keys'
        ($script:StartupSection.Headline -join ' ') | Should -Match '90 Windows services'
    }

    It 'reads the same dictionary after a JSON round trip' {
        # The same field comes back as a PSCustomObject when the scan was read
        # out of a log, and the screen must not render differently for it.
        $restored = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $script:StartupScan -Depth 12)
        $section = InModuleScope Win11Optimizer.Engine -Parameters @{ Scan = $restored } {
            param($Scan)
            Get-ReviewStartupSection -Scan $Scan
        }
        ($section.Headline -join ' ') | Should -Match '90 Windows services'
    }

    It 'names the protected tasks it never considered' {
        ($script:StartupSection.Note -join ' ') | Should -Match '41 scheduled tasks in protected Windows namespaces'
    }

    It 'carries only StartupItem findings, never the services beside them' {
        $rows = @($script:StartupSection.Row)
        $rows.Count | Should -Be 1
        $rows[0].Category | Should -Be 'StartupItem'
    }

    It 'renders an inventory and no list when nothing is flagged, and says which that is' {
        $scan = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
            InventoryCount = 149; EnabledCount = 121; DisabledCount = 28; UnknownStateCount = 0
            ProtectedTaskCount = 41; ProtectedServiceCount = 10
            MechanismCount = [ordered]@{ RunKey = 15; StartupFolder = 0; ScheduledTask = 44; Service = 90 }
            StartupItems = [psobject[]] @()
        } -Finding @()

        $lines = InModuleScope Win11Optimizer.Engine -Parameters @{ Scan = $scan } {
            param($Scan)
            Format-ReviewSection -Section (Get-ReviewStartupSection -Scan $Scan) -Width 100 -Colour $false
        }
        $text = ($lines -join "`n")
        $text | Should -Match '149 things start with your PC'
        $text | Should -Match 'The inventory above is the answer, not an empty list'
    }
}

Describe 'Installed apps: it leads with what it could not judge' {

    BeforeAll { $script:InstalledSection = Get-Section -Key 'InstalledApps' }

    It 'opens with the count it could not judge, not with the findings' {
        $script:InstalledSection.Headline[0] | Should -BeExactly 'Could not judge 234 of 286 installed applications.'
    }

    It 'says used and unknown are not stable facts about this PC' {
        # Two elevated runs a day apart gave 52/234 and 46/240 with nothing done
        # in between, because Windows ages the prefetch folder on its own
        # schedule. A number printed without that reads as a property of the
        # machine. docs\STATE.md, Q11.
        ($script:InstalledSection.Note -join ' ') | Should -Match 'not stable facts about this PC'
    }

    It 'names the signals this project refuses to use, from the structured field' {
        ($script:InstalledSection.Note -join ' ') | Should -Match 'FileSystemLastAccess'
        $script:InstalledSection.RefusedSourceName | Should -Contain 'FileSystemLastAccess'
    }

    It 'carries both the OEM and the unused-app findings' {
        @($script:InstalledSection.Row).Count | Should -Be 1
        @($script:InstalledSection.Row)[0].Category | Should -Be 'OemBloatware'
    }

    It 'is incomplete when EITHER of its two scans is' {
        # The unused-app scan is partial in the fixture and the OEM one is not.
        # Reporting only the first would let an un-elevated OEM scan -- which
        # cannot read provisioned Appx packages at all -- present itself as
        # complete.
        $script:InstalledSection.IsComplete | Should -BeFalse
        $script:InstalledSection.IncompleteReason | Should -Match 'Prefetch'

        $bothComplete = InModuleScope Win11Optimizer.Engine -Parameters @{ Unused = $script:UnusedScan; Oem = $script:OemScan } {
            param($Unused, $Oem)
            $clean = $Unused.PSObject.Copy()
            $clean.IsComplete = $true
            $clean.IncompleteReason = $null
            (Get-ReviewInstalledAppSection -UnusedScan $clean -OemScan $Oem).IsComplete
        }
        $bothComplete | Should -BeTrue
    }
}

Describe 'Services: the protected count sits beside the findings' {

    BeforeAll { $script:ServiceSection = Get-Section -Key 'Services' }

    It 'says how many were held back as protected' {
        # A zero-Finding section and an exclusion list that swallowed everything
        # look identical without it, and telling those apart is close to this
        # project's whole thesis.
        ($script:ServiceSection.Headline -join ' ') | Should -Match '10 more were held back as protected'
    }

    It 'counts the services it looked at' {
        ($script:ServiceSection.Headline -join ' ') | Should -Match '90 Windows services were looked at'
    }

    It 'carries only Service findings' {
        $rows = @($script:ServiceSection.Row)
        $rows.Count | Should -Be 1
        $rows[0].Category | Should -Be 'Service'
        $rows[0].DisplayName | Should -Be 'Fabricated service'
    }

    It 'shows each flagged service''s live state from the inventory the scan already carries' {
        @($script:ServiceSection.Row)[0].Cell[2] | Should -BeExactly 'Enabled'
    }

    It 'says what it will and will not do to a service' {
        ($script:ServiceSection.Note -join ' ') | Should -Match 'does not delete a service'
        ($script:ServiceSection.Note -join ' ') | Should -Match 'does not stop one'
    }
}

Describe 'A partial scan says so, and nothing pretends otherwise' {

    It 'flags the screen as partial and names which lists' {
        $script:Screen.IsComplete | Should -BeFalse
        $script:Screen.PartialSection | Should -Contain 'Installed apps'
        $script:Screen.PartialSection | Should -Not -Contain 'Junk files'
    }

    It 'prints PARTIAL at the top and again in the section' {
        @($script:Lines | Where-Object { $_ -match '^\s*PARTIAL' }).Count | Should -BeGreaterOrEqual 2
    }

    It 'prints the reason in words, not just the flag' {
        $script:Text | Should -Match 'fabricated reason for the test suite'
    }

    It 'says nothing about being partial when every scan finished' {
        $clean = $script:UnusedScan.PSObject.Copy()
        $clean.IsComplete = $true
        $clean.IncompleteReason = $null
        $screen = Get-ReviewScreen -StartupScan $script:StartupScan -UnusedAppScan $clean `
            -OemScan $script:OemScan -JunkScan $script:JunkScan -SkipReceipt
        $screen.IsComplete | Should -BeTrue
        (@(Format-ReviewScreen -Screen $screen -Width 100) -join "`n") | Should -Not -Match 'PARTIAL'
    }
}

Describe 'The safety label is run through the contract, never re-derived' {

    It 'gives every row the label the Finding''s own rule gives' {
        $rows = @($script:Screen.Section | ForEach-Object { $_.Row })
        $rows.Count | Should -BeGreaterThan 0
        foreach ($row in $rows) {
            $row.SafetyLabel | Should -BeExactly ([string] $row.Finding.SafetyLabel)
        }
    }

    It 'uses only the two strings the contract allows' {
        $allowed = @($script:FindingContract.SafetyLabels)
        foreach ($row in @($script:Screen.Section | ForEach-Object { $_.Row })) {
            $allowed | Should -Contain $row.SafetyLabel
        }
    }

    It 'fails closed for a row whose consent flag arrived as something other than a boolean' {
        # A Finding deserialized from an older log, or handed in by something
        # that has not been reviewed. The screen must label it "Review needed"
        # for the same reason the contract does.
        $tampered = [pscustomobject]@{
            Category = 'OemBloatware'; Id = 'x'; DisplayName = 'Tampered'
            Evidence = [string[]] @('Fabricated.'); Confidence = 'Known'
            RequiresConsent = 'false'; RemovalMethod = 'Appx'
        }
        $label = InModuleScope Win11Optimizer.Engine -Parameters @{ Finding = $tampered } {
            param($Finding)
            Get-ReviewSafetyLabel -Finding $Finding
        }
        $label | Should -BeExactly ([string] @($script:FindingContract.SafetyLabels)[1])
    }

    It 'restates the two-axis rule nowhere in the source' {
        # The rule is Get-FindingContract().SafetyLabelRule and is invoked. A
        # second copy here would be a place for the two to drift apart.
        $script:Blanked | Should -Not -Match "Safe to remove"
        $script:Blanked | Should -Not -Match "Review needed"
        $script:Invoked | Should -Contain 'Get-FindingContract'
    }
}

Describe 'It prints PreviewText and ReceiptText, and does not re-render either' {

    It 'prints each selected plan''s own PreviewText, line for line' {
        $run = New-ScriptedRun -Answer @('', '', '', 'a', 'no')
        $selection = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer

        @($selection.Plan).Count | Should -Be 1
        $written = ($run.Written -join "`n")
        foreach ($line in @($selection.Plan[0].PreviewText)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $written | Should -Match ([regex]::Escape($line))
        }
    }

    It 'writes no preview text of its own' {
        # The phrases the dispatcher's renderer owns must not appear as literals
        # in this file: a second renderer of the same plan is one that will
        # eventually disagree with the record the ledger kept.
        foreach ($phrase in 'Found by:', 'This is a preview', 'Administrator rights:', 'Can be undone:', 'To undo:') {
            $script:Blanked.IndexOf($phrase, [System.StringComparison]::Ordinal) | Should -Be -1
        }
    }

    It 'carries the receipt''s own lines, unaltered' {
        $ledger = Join-Path $script:Scratch ('receipt-' + [guid]::NewGuid().ToString('N') + '.jsonl')
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category Service -Id 'w11o-absent-review-service' -RemovalMethod ServiceDisable -RequiresConsent)
        $null = Write-OptimizerAction -Plan $plan -Path $ledger

        $screen = Get-ReviewScreen -StartupScan $script:StartupScan -UnusedAppScan $script:UnusedScan `
            -OemScan $script:OemScan -JunkScan $script:JunkScan -LedgerPath $ledger
        $expected = [string[]] @((Get-OptimizerRunReceipt -Path $ledger).ReceiptText)

        @($screen.ReceiptText).Count | Should -Be $expected.Count
        $lines = @(Format-ReviewScreen -Screen $screen -Width 100)
        foreach ($line in $expected) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            @($lines | Where-Object { $_.Trim() -eq $line.Trim() }).Count | Should -BeGreaterThan 0
        }
    }

    It 'leaves the receipt out when there is no ledger, without complaining' {
        $screen = Get-ReviewScreen -StartupScan $script:StartupScan -UnusedAppScan $script:UnusedScan `
            -OemScan $script:OemScan -JunkScan $script:JunkScan `
            -LedgerPath (Join-Path $script:Scratch 'there-is-no-such-ledger.jsonl')
        $screen.ReceiptText | Should -BeNullOrEmpty
    }
}

Describe 'Get-ReviewSelection: numbers, a range, all, or nothing' {

    It 'reads blank as nothing' {
        $answer = Get-ReviewSelection -InputText '' -RowCount 5
        $answer.IsValid | Should -BeTrue
        $answer.IsNone  | Should -BeTrue
        @($answer.Number).Count | Should -Be 0
    }

    It 'reads whitespace as nothing too' {
        (Get-ReviewSelection -InputText "   `t " -RowCount 5).IsNone | Should -BeTrue
    }

    It 'reads <_> as every row' -ForEach @('a', 'A', 'all', 'ALL', ' all ') {
        $answer = Get-ReviewSelection -InputText $PSItem -RowCount 4
        $answer.IsValid | Should -BeTrue
        $answer.IsAll   | Should -BeTrue
        @($answer.Number) -join ',' | Should -BeExactly '1,2,3,4'
    }

    It 'reads a list of numbers in any separator' {
        (Get-ReviewSelection -InputText '1 3 5' -RowCount 5).Number -join ',' | Should -BeExactly '1,3,5'
        (Get-ReviewSelection -InputText '1,3,5' -RowCount 5).Number -join ',' | Should -BeExactly '1,3,5'
        (Get-ReviewSelection -InputText '1, 3,  5' -RowCount 5).Number -join ',' | Should -BeExactly '1,3,5'
    }

    It 'reads a range' {
        (Get-ReviewSelection -InputText '2-5' -RowCount 8).Number -join ',' | Should -BeExactly '2,3,4,5'
    }

    It 'mixes ranges and numbers, and de-duplicates' {
        (Get-ReviewSelection -InputText '1, 3-5, 4, 1' -RowCount 9).Number -join ',' | Should -BeExactly '1,3,4,5'
    }

    It 'rejects a row that is not on the list rather than dropping it' {
        # A selection screen that quietly ignores what it did not understand is
        # one that acts on a list the person did not choose.
        $answer = Get-ReviewSelection -InputText '2 9' -RowCount 4
        $answer.IsValid | Should -BeFalse
        $answer.Error   | Should -Match "'9' is not a row on this list"
        @($answer.Number).Count | Should -Be 0
    }

    It 'rejects 0, which is nobody''s row' {
        (Get-ReviewSelection -InputText '0' -RowCount 4).IsValid | Should -BeFalse
    }

    It 'rejects a backwards range and says which way round to write it' {
        $answer = Get-ReviewSelection -InputText '5-2' -RowCount 8
        $answer.IsValid | Should -BeFalse
        $answer.Error   | Should -Match 'runs backwards'
    }

    It 'rejects anything that is not a number, a range, all or blank' {
        foreach ($bad in 'x', '*', '1..3', '-2', '2-', 'yes', '1;2') {
            $answer = Get-ReviewSelection -InputText $bad -RowCount 5
            $answer.IsValid | Should -BeFalse -Because "'$bad' is not in the input language"
            $answer.Error   | Should -Not -BeNullOrEmpty
        }
    }

    It 'names the token it did not understand' {
        (Get-ReviewSelection -InputText '1 zzz 3' -RowCount 5).Error | Should -Match "'zzz'"
    }

    It 'handles a section with no rows without inventing one' {
        $answer = Get-ReviewSelection -InputText 'a' -RowCount 0
        $answer.IsValid | Should -BeTrue
        $answer.IsNone  | Should -BeTrue
        @($answer.Number).Count | Should -Be 0
    }
}

Describe 'Get-ReviewConfirmation: yes is yes and everything else is no' {

    It 'reads <_> as yes' -ForEach @('y', 'Y', 'yes', 'YES', ' Yes ') {
        Get-ReviewConfirmation -InputText $PSItem | Should -BeTrue
    }

    It 'reads <_> as no' -ForEach @('', ' ', 'n', 'no', 'nope', 'yeah', 'ok', 'sure', 'yesplease', '1', 'Y E S') {
        Get-ReviewConfirmation -InputText $PSItem | Should -BeFalse
    }

    It 'reads $null as no' {
        Get-ReviewConfirmation -InputText $null | Should -BeFalse
    }
}

Describe 'Show-ReviewScreen: one prompt per section, one question, then it stops' {

    It 'asks once per section that has rows, and never for one that has none' {
        $run = New-ScriptedRun -Answer @('a', 'a', 'a', 'a', 'no')
        $null = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer

        # All four sections have rows in the fixture, so four prompts and then
        # the confirmation. No nested menus and no modes: that is the whole
        # dialogue, and its length is the point of this assertion.
        @($run.Asked).Count | Should -Be 5
        $run.Asked[0] | Should -Match '^Startup items'
        $run.Asked[1] | Should -Match '^Installed apps'
        $run.Asked[2] | Should -Match '^Junk files'
        $run.Asked[3] | Should -Match '^Services'
        $run.Asked[4] | Should -Match "Type 'yes'"
    }

    It 'never prompts for a section with no rows' {
        $emptyScreen = Get-ReviewScreen -StartupScan $script:StartupScan -UnusedAppScan $script:UnusedScan `
            -OemScan $script:OemScan -JunkScan $script:EmptyJunkScan -SkipReceipt
        $run = New-ScriptedRun -Answer @('', '', '', '')
        $null = Show-ReviewScreen -Screen $emptyScreen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer
        @($run.Asked | Where-Object { $_ -match '^Junk files' }).Count | Should -Be 0
        @($run.Asked).Count | Should -Be 3
    }

    It 'takes exactly what was typed, section by section' {
        $run = New-ScriptedRun -Answer @('1', '', '1,3', 'a', 'no')
        $selection = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer

        $picked = @{}
        foreach ($pick in @($selection.Pick)) { $picked[$pick.SectionKey] = @($pick.Number) -join ',' }
        $picked['StartupItems'] | Should -BeExactly '1'
        $picked['InstalledApps'] | Should -BeExactly ''
        $picked['JunkFiles'] | Should -BeExactly '1,3'
        $picked['Services'] | Should -BeExactly '1'
        $selection.SelectedCount | Should -Be 4
    }

    It 'hands back the Finding objects themselves, not row numbers to resolve later' {
        $run = New-ScriptedRun -Answer @('', '', '1', '', 'no')
        $selection = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer
        @($selection.Finding).Count | Should -Be 1
        $selection.Finding[0].DisplayName | Should -BeExactly 'NVIDIA shader cache'
        Test-Finding -InputObject $selection.Finding[0] | Should -BeTrue
    }

    It 'stops without asking for confirmation when nothing was picked' {
        $run = New-ScriptedRun -Answer @('', '', '', '')
        $selection = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer
        $selection.Confirmed | Should -BeFalse
        $selection.SelectedCount | Should -Be 0
        @($run.Asked).Count | Should -Be 4 -Because 'one prompt per section and nothing to confirm'
        @($run.Asked | Where-Object { $_ -match "Type 'yes'" }).Count | Should -Be 0
        ($run.Written -join "`n") | Should -Match 'nothing to confirm'
    }

    It 'says what it did not understand and asks again, but not forever' {
        # A prompt that re-asks forever cannot be driven by a script and cannot
        # be escaped by a person who has stopped understanding it. Three tries,
        # then the section is skipped -- which is the safe direction.
        $run = New-ScriptedRun -Answer @('zzz', 'qqq', 'www', '', '', '', 'no')
        $selection = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer
        ($run.Written -join "`n") | Should -Match "'zzz' is not a number"
        @($run.Asked | Where-Object { $_ -match '^Startup items' }).Count | Should -Be 3
        @($selection.Pick | Where-Object { $_.SectionKey -eq 'StartupItems' })[0].Number.Count | Should -Be 0
    }

    It 'takes a correction on the second try' {
        $run = New-ScriptedRun -Answer @('9', '1', '', '', '', 'no')
        $selection = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer
        @($selection.Pick | Where-Object { $_.SectionKey -eq 'StartupItems' })[0].Number -join ',' | Should -BeExactly '1'
    }

    It 'asks the yes-or-no question exactly once' {
        $run = New-ScriptedRun -Answer @('a', '', '', '', 'maybe')
        $selection = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer
        @($run.Asked | Where-Object { $_ -match "Type 'yes'" }).Count | Should -Be 1
        $selection.Confirmed | Should -BeFalse -Because 'anything that is not yes is no'
        ($run.Written -join "`n") | Should -Match 'Stopped. Nothing on this PC has been changed'
    }

    It 'records a yes as a decision and says plainly that nothing happened' {
        $run = New-ScriptedRun -Answer @('a', 'a', 'a', 'a', 'yes')
        $selection = Show-ReviewScreen -Screen $script:Screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer
        $selection.Confirmed | Should -BeTrue
        $selection.Executed  | Should -BeFalse
        ($run.Written -join "`n") | Should -Match 'collects the decision and stops there'
    }

    It 'says when a selected row has nothing planned for it' {
        # A plan can come back Supported = $false, and a screen that printed the
        # refusal without counting it would let a person confirm a list that is
        # partly inert.
        #
        # PackageManagement is the route that refuses by design, on every machine
        # (docs\STATE.md Q2, closed 2026-08-27), so this shape is reachable
        # without depending on anything about this hardware.
        $refusedScan = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @(); InventoryCount = 286
        } -Finding @(
            (New-TestFinding -Category OemBloatware -Id 'Fabricated.Refused' -DisplayName 'Fabricated refusal' -RemovalMethod PackageManagement)
        )

        $screen = Get-ReviewScreen -StartupScan $script:StartupScan -UnusedAppScan $script:UnusedScan `
            -OemScan $refusedScan -JunkScan $script:EmptyJunkScan -SkipReceipt

        $run = New-ScriptedRun -Answer @('', 'a', '', 'no')
        $selection = Show-ReviewScreen -Screen $screen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer

        @($selection.Plan).Count | Should -Be 1
        $selection.Plan[0].Supported | Should -BeFalse
        ($run.Written -join "`n") | Should -Match 'have nothing planned for them'
        ($run.Written -join "`n") | Should -Match 'NOTHING IS PLANNED FOR THIS ONE'
    }
}

Describe 'The rendering itself' {

    It 'is ASCII, including the framing' {
        foreach ($line in $script:Lines) {
            $line | Should -Not -Match '[^\x20-\x7E]'
        }
    }

    It 'frames with +, - and | and nothing else' {
        $framing = @($script:Lines | Where-Object { $_ -match '^\+' })
        $framing.Count | Should -BeGreaterThan 4
        foreach ($line in $framing) {
            $line | Should -Match '^[+\-| A-Za-z0-9]*$'
        }
    }

    It 'never runs a line past the width it was given' {
        foreach ($width in 60, 80, 100, 140) {
            $lines = @(Format-ReviewScreen -Screen $script:Screen -Width $width)
            $longest = (@($lines | ForEach-Object { $_.Length }) | Measure-Object -Maximum).Maximum
            $longest | Should -BeLessOrEqual $width -Because "at width $width"
        }
    }

    It 'clamps a silly width rather than throwing' {
        { Format-ReviewScreen -Screen $script:Screen -Width 5 } | Should -Not -Throw
        { Format-ReviewScreen -Screen $script:Screen -Width 5000 } | Should -Not -Throw
    }

    It 'builds every escape sequence from [char]27, never from $PSStyle or the backtick-e shorthand' {
        # $PSStyle is PowerShell 7 only and `e does not exist in 5.1, and 5.1 is
        # this project's floor. Asserted against the source rather than the
        # output, because the output would look right on 7 either way.
        $script:Blanked | Should -Not -Match '\$PSStyle'
        $script:Blanked | Should -Not -Match '`e\['
        $script:Blanked | Should -Match '\[char\]27'
    }

    It 'differs from the plain render by escape sequences alone' {
        $plain    = @(Format-ReviewScreen -Screen $script:Screen -Width 100)
        $coloured = @(Format-ReviewScreen -Screen $script:Screen -Width 100 -Colour)
        $coloured.Count | Should -Be $plain.Count

        $escape = [string][char]27
        for ($i = 0; $i -lt $plain.Count; $i++) {
            $stripped = [regex]::Replace($coloured[$i], "$escape\[[0-9;]*m", '')
            $stripped | Should -BeExactly $plain[$i] -Because "line $i must be the same text either way"
        }
    }

    It 'keeps the columns aligned with colour on' {
        # The escapes are added AFTER padding, so a coloured table has the same
        # column positions as a plain one. This is the assertion that would fail
        # if that ever got reversed.
        $coloured = @(Format-ReviewScreen -Screen $script:Screen -Width 100 -Colour)
        $escape = [string][char]27
        $rows = @($coloured | Where-Object { [regex]::Replace($_, "$escape\[[0-9;]*m", '') -match '^\s+\d+\s\s' })
        $rows.Count | Should -BeGreaterThan 0

        $widths = @($rows | ForEach-Object { ([regex]::Replace($_, "$escape\[[0-9;]*m", '')).TrimEnd().Length })
        # Not all equal -- cells are trimmed at the end of a line -- but every
        # row of one table starts its second column at the same offset.
        $starts = @($rows | ForEach-Object {
            $plain = [regex]::Replace($_, "$escape\[[0-9;]*m", '')
            $plain.IndexOf('  ', 2)
        })
        @($starts | Sort-Object -Unique).Count | Should -BeLessOrEqual 4
    }

    It 'colours a safety label without making colour the only carrier' {
        $coloured = ((Format-ReviewScreen -Screen $script:Screen -Width 100 -Colour) -join "`n")
        $escape = [string][char]27
        $coloured | Should -Match ([regex]::Escape($escape))
        # The words are there in the plain render too, so a monochrome terminal
        # loses nothing but the colour.
        $script:Text | Should -Match 'Safe to remove'
        $script:Text | Should -Match 'Review needed'
    }

    It 'honours NO_COLOR' {
        $previous = [Environment]::GetEnvironmentVariable('NO_COLOR')
        try {
            $env:NO_COLOR = '1'
            InModuleScope Win11Optimizer.Engine { Test-ReviewColourSupport } | Should -BeFalse
        }
        finally {
            if ($null -eq $previous) { Remove-Item Env:\NO_COLOR -ErrorAction SilentlyContinue }
            else { $env:NO_COLOR = $previous }
        }
    }

    It 'wraps long prose instead of running off the edge' {
        $wrapped = InModuleScope Win11Optimizer.Engine {
            Split-ReviewText -Text ('word ' * 60) -Width 40 -Indent '    '
        }
        @($wrapped).Count | Should -BeGreaterThan 5
        foreach ($line in $wrapped) {
            $line.Length | Should -BeLessOrEqual 40
            $line | Should -Match '^    '
        }
    }

    It 'breaks a single unbreakable token rather than overflowing' {
        # The junk detector's incompleteness reasons quote absolute paths, and
        # one of them is 120 characters with no space in it.
        $wrapped = InModuleScope Win11Optimizer.Engine {
            Split-ReviewText -Text ('x' * 200) -Width 40 -Indent '  '
        }
        foreach ($line in $wrapped) { $line.Length | Should -BeLessOrEqual 40 }
        (($wrapped -join '') -replace '\s', '').Length | Should -Be 200
    }
}

Describe 'All four sections render from a real scan of this machine' {

    BeforeAll {
        $script:RealStartup = Invoke-StartupItemScan -WarningAction SilentlyContinue
        $script:RealUnused  = Invoke-UnusedAppScan -WarningAction SilentlyContinue
        $script:RealOem     = Invoke-OemBloatwareScan -WarningAction SilentlyContinue
        $script:RealJunk    = Invoke-JunkFileScan -WarningAction SilentlyContinue
        $script:RealScreen  = Get-ReviewScreen -StartupScan $script:RealStartup -UnusedAppScan $script:RealUnused `
            -OemScan $script:RealOem -JunkScan $script:RealJunk -SkipReceipt
        $script:RealLines   = [string[]] @(Format-ReviewScreen -Screen $script:RealScreen -Width 100)
        $script:RealText    = ($script:RealLines -join "`n")
    }

    It 'produces the four sections, in order' {
        @($script:RealScreen.Section | ForEach-Object { $_.Key }) -join ',' |
            Should -BeExactly 'StartupItems,InstalledApps,JunkFiles,Services'
    }

    It 'gives every section a headline that is not empty' {
        foreach ($section in @($script:RealScreen.Section)) {
            @($section.Headline).Count | Should -BeGreaterThan 0 -Because "section $($section.Key)"
            $section.Headline[0] | Should -Not -BeNullOrEmpty
        }
    }

    It 'numbers the rows of each section from 1' {
        foreach ($section in @($script:RealScreen.Section)) {
            $rows = @($section.Row)
            for ($i = 0; $i -lt $rows.Count; $i++) {
                $rows[$i].Number | Should -Be ($i + 1)
            }
        }
    }

    It 'gives every real row a cell for every column, none of them blank' {
        foreach ($section in @($script:RealScreen.Section)) {
            $columns = @($section.ColumnHeader).Count
            foreach ($row in @($section.Row)) {
                @($row.Cell).Count | Should -Be $columns -Because "row '$($row.DisplayName)' in $($section.Key)"
                foreach ($cell in @($row.Cell)) {
                    $cell | Should -Not -BeNullOrEmpty
                }
            }
        }
    }

    It 'renders every real Finding this machine produced, and no more' {
        $findings = @(
            @($script:RealStartup.Findings) + @($script:RealUnused.Findings) +
            @($script:RealOem.Findings) + @($script:RealJunk.Findings)
        )
        $script:RealScreen.RowCount | Should -Be $findings.Count
    }

    It 'says nothing forbidden about a real machine either' {
        foreach ($phrase in $script:ForbiddenPhrase) {
            $script:RealText.IndexOf($phrase, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1
        }
    }

    It 'stays inside the width on real data' {
        (@($script:RealLines | ForEach-Object { $_.Length }) | Measure-Object -Maximum).Maximum |
            Should -BeLessOrEqual 100
    }

    It 'agrees with the scan results it was built from' {
        $startup = @($script:RealScreen.Section | Where-Object { $_.Key -eq 'StartupItems' })[0]
        $startup.Headline[0] | Should -Match ("^{0} things start with your PC, {1} already off\.$" -f `
            [regex]::Escape((InModuleScope Win11Optimizer.Engine -Parameters @{ N = $script:RealStartup.InventoryCount } { param($N) Format-JunkCount -Count $N })),
            [regex]::Escape((InModuleScope Win11Optimizer.Engine -Parameters @{ N = $script:RealStartup.DisabledCount } { param($N) Format-JunkCount -Count $N })))

        $services = @($script:RealScreen.Section | Where-Object { $_.Key -eq 'Services' })[0]
        ($services.Headline -join ' ') | Should -Match ("{0} more" -f $script:RealStartup.ProtectedServiceCount)
    }

    It 'walks the whole thing end to end without running anything' {
        $run = New-ScriptedRun -Answer @('a', 'a', 'a', 'a', 'no')
        $selection = Show-ReviewScreen -Screen $script:RealScreen -Width 100 -NoColour -Reader $run.Reader -Writer $run.Writer
        $selection.SelectedCount | Should -Be $script:RealScreen.RowCount
        @($selection.Plan).Count  | Should -Be $script:RealScreen.RowCount
        $selection.Confirmed | Should -BeFalse
        $selection.Executed  | Should -BeFalse

        # Every plan came back from the dispatcher, which plans and removes
        # nothing. Nothing on this machine changed.
        foreach ($plan in @($selection.Plan)) {
            $plan.PSObject.TypeNames | Should -Contain (Get-RemovalContract).TypeName
        }
    }
}
