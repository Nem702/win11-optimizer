#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for chunk P3-C1a, the dispatcher and junk-list amendment
    (docs\handoff\09-dispatcher-junk-amendment.md).

    Six changes, none of them a new mechanism:

      1. a curated junk location may carry its own age window, and the NVIDIA
         shader cache uses one and becomes flaggable;
      2. the component servicing logs drop to inventory-only;
      3. the dispatcher's last gate covers startup entries pointing at security
         software, not only services (STATE.md Q15);
      4. rundll32-style uninstall strings fail closed (STATE.md Q17);
      5. two source-scanning assertions moved -- that half lives in
         tests\JunkFiles.Tests.ps1 and tests\SharedInventory.Tests.ps1, not here;
      6. 'Micro-Star*' moves to its exclusion entry's registryPublisher list.

    Everything this chunk ADDS is asserted here rather than in the four suites
    those changes touch, so that the only edits to existing test files are the two
    assertion moves change 5 asks for and a reviewer can read them line by line.

    LIKE THE REST OF THIS PROJECT, NOTHING HERE CHANGES THE MACHINE. The dispatcher
    plans and never acts. The one thing this file writes is a private HKCU subtree
    of fabricated uninstall keys, removed in AfterAll, exactly as
    tests\RemovalDispatcher.Tests.ps1 does.

    Run:  .\tests\Invoke-Tests.ps1
#>

# Discovery-time, for the -ForEach below. Pester runs a file's top level during
# discovery and its BeforeAll during the run, in separate scopes, so the list is
# dot-sourced in both -- see tests\ForbiddenPhrase.ps1.
. (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
$ForbiddenPhrase = Get-OptimizerForbiddenPhrase

BeforeAll {
    $script:RepoRoot      = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot    = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath  = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ListPath      = Join-Path $script:EngineRoot 'Data\junk-locations.json'
    $script:ExclusionPath = Join-Path $script:EngineRoot 'Data\unused-app-exclusions.json'

    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-amend-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-amend-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    # Under HKCU, where nothing needs elevation and nothing real lives.
    $script:TestRegistryRoot = "HKCU:\SOFTWARE\win11-optimizer-tests\" + [guid]::NewGuid().ToString('N')

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    # The phrases this project never uses about disk space. The list itself moved
    # to tests\ForbiddenPhrase.ps1 in P5-C3 -- it used to be written out here and
    # written out DIFFERENTLY in tests\RemovalDispatcher.Tests.ps1, and three
    # other suites read both by AST to get the union. One file now, and this
    # suite enforces the union rather than its old five.
    . (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
    $script:ForbiddenPhrase = Get-OptimizerForbiddenPhrase

    function New-AmendmentJunkList {
        param([Parameter(Mandatory)] [string] $Content)
        $path = Join-Path $script:Scratch ("junk-" + [guid]::NewGuid().ToString('N') + '.json')
        [System.IO.File]::WriteAllText($path, $Content)
        $path
    }

    # A tree whose file ages are known exactly, so an age window can be moved
    # across it and the answer predicted rather than observed.
    function New-AmendmentJunkTree {
        param([int[]] $AgeDays = @(3, 10, 40, 200))
        $root = Join-Path $script:Scratch ("tree-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $root -ItemType Directory -Force
        foreach ($age in $AgeDays) {
            $file = Join-Path $root "age-$age.tmp"
            [System.IO.File]::WriteAllText($file, ('x' * 128))
            $stamp = [datetime]::UtcNow.AddDays(-$age)
            [System.IO.File]::SetCreationTimeUtc($file, $stamp)
            [System.IO.File]::SetLastWriteTimeUtc($file, $stamp)
        }
        $root
    }

    # -MinimumAgeDaysJson is RAW JSON, not a number, so the malformed cases below
    # can hand the loader exactly what a bad list entry would.
    function New-AmendmentJunkListForTree {
        param(
            [Parameter(Mandatory)] [string] $Path,
            [AllowNull()] [AllowEmptyString()] [string] $MinimumAgeDaysJson
        )
        $escaped = $Path.Replace('\', '\\')
        $age = ''
        if (-not [string]::IsNullOrEmpty($MinimumAgeDaysJson)) {
            $age = ",`r`n      `"minimumAgeDays`": $MinimumAgeDaysJson"
        }
        New-AmendmentJunkList -Content @"
{
  "schemaVersion": 2,
  "entries": [
    {
      "id": "fabricated",
      "displayName": "Fabricated location",
      "reason": "A folder created by the test suite so the per-entry age window can be exercised against a tree whose file ages are known exactly.",
      "provenance": "measured",
      "paths": [ "$escaped" ]$age
    }
  ]
}
"@
    }

    function New-AmendmentFinding {
        param(
            [Parameter(Mandatory)] [string] $Category,
            [Parameter(Mandatory)] [string] $Id,
            [string] $DisplayName = 'Fabricated item',
            [Parameter(Mandatory)] [string] $RemovalMethod,
            [switch] $RequiresConsent
        )
        New-Finding -Category $Category -Id $Id -DisplayName $DisplayName `
            -Evidence 'Fabricated by the test suite so this gate can be exercised on a machine that does not produce one.' `
            -Confidence 'Known' -RequiresConsent:$RequiresConsent -RemovalMethod $RemovalMethod
    }

    function New-AmendmentUninstallKey {
        param(
            [Parameter(Mandatory)] [string] $Name,
            [hashtable] $Value = @{}
        )
        $path = Join-Path $script:TestRegistryRoot $Name
        $null = New-Item -Path $path -Force
        foreach ($key in $Value.Keys) {
            $null = New-ItemProperty -Path $path -Name $key -Value $Value[$key] -PropertyType String -Force
        }
        # The HKEY_* form, because that is what a registry key's .Name returns and
        # therefore what a Finding's Id carries.
        (Get-Item -LiteralPath $path).Name
    }

    # One real scan of each kind, shared by every Describe that needs one. The junk
    # scan reads tens of thousands of files; three of them would triple this
    # suite's wall clock for no extra coverage.
    $script:Entries      = @(Get-JunkLocationList)
    $script:Exclusions   = @(Get-UnusedAppExclusionList)
    $script:JunkScan     = Invoke-JunkFileScan -WarningAction SilentlyContinue
    $script:StartupItems = @((Get-StartupItemInventory 3>$null).Items)
    $script:RunItems     = @($script:StartupItems | Where-Object { $_.Mechanism -eq 'RunKey' })

    $script:AgeTree = New-AmendmentJunkTree
}

AfterAll {
    Remove-Module Win11Optimizer.Engine -Force -ErrorAction SilentlyContinue
    foreach ($path in @($script:TestLogRoot, $script:Scratch)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $parent = Split-Path -Path $script:TestRegistryRoot -Parent
    if (Test-Path -LiteralPath $parent) {
        Remove-Item -LiteralPath $parent -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\WIN11OPTIMIZER_LOGROOT -ErrorAction SilentlyContinue
}

Describe 'Change 1: an entry with no window of its own is untouched' {

    # The default path is the one that must not move: fourteen of the fifteen
    # shipped entries have no minimumAgeDays and have to behave exactly as they did
    # before this chunk existed.

    It 'reads as absent on <_>, so the scan-wide window applies' -ForEach @(
        'user-temp', 'windows-temp', 'chrome-http-cache', 'servicing-logs', 'prefetch', 'recycle-bin'
    ) {
        # Captured first: inside a Where-Object scriptblock $_ is the pipeline
        # element, not the -ForEach value, and the two would silently be the
        # same variable name meaning different things.
        $id = $_
        $entry = @($script:Entries | Where-Object { $_.Id -eq $id })
        $entry.Count | Should -Be 1
        $entry[0].MinimumAgeDays | Should -BeNullOrEmpty
    }

    It 'is declared by exactly one entry on the shipped list' {
        $declared = @($script:Entries | Where-Object { $null -ne $_.MinimumAgeDays })
        $declared.Count | Should -Be 1
        $declared[0].Id             | Should -Be 'nvidia-shader-cache'
        $declared[0].MinimumAgeDays | Should -Be 30
    }

    It 'measures a location with no window of its own against the scan window' {
        # The tree holds files aged 3, 10, 40 and 200 days. At 7 days, one is
        # inside the window and three are not.
        $entries = @(Get-JunkLocationList -Path (New-AmendmentJunkListForTree -Path $script:AgeTree))
        $location = @((Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7).Locations)[0]

        $location.MinimumAgeDays    | Should -Be 7
        $location.FileCount         | Should -Be 4
        $location.AgeHeldBackCount  | Should -Be 1
        $location.EligibleFileCount | Should -Be 3
    }

    It 'counts no age-window override when nothing declares one' {
        $entries = @(Get-JunkLocationList -Path (New-AmendmentJunkListForTree -Path $script:AgeTree))
        $inventory = Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7
        [long] $inventory.Statistic['AgeWindowOverrideCount'] | Should -Be 0
    }
}

Describe 'Change 1: the entry window is a FLOOR, not a replacement' {

    It 'uses the entry window when it is longer than the scan window' {
        $entries = @(Get-JunkLocationList -Path (New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson '30'))
        $location = @((Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7).Locations)[0]

        $location.MinimumAgeDays    | Should -Be 30
        $location.AgeHeldBackCount  | Should -Be 2
        $location.EligibleFileCount | Should -Be 2
    }

    It 'uses the SCAN window when the caller asked to be more conservative than the entry' {
        # -MinimumAgeDays 90 against an entry that says 30. The caller asked for
        # MORE holding back, and an entry that then computed at 30 would give them
        # less than they asked for. Only the 200-day file survives.
        $entries = @(Get-JunkLocationList -Path (New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson '30'))
        $location = @((Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 90).Locations)[0]

        $location.MinimumAgeDays    | Should -Be 90
        $location.AgeHeldBackCount  | Should -Be 3
        $location.EligibleFileCount | Should -Be 1
    }

    It 'is the greater of the two at every window, never the entry alone' -ForEach @(
        @{ Scan = 1;   Entry = '30'; Expected = 30 }
        @{ Scan = 7;   Entry = '30'; Expected = 30 }
        @{ Scan = 30;  Entry = '30'; Expected = 30 }
        @{ Scan = 90;  Entry = '30'; Expected = 90 }
        @{ Scan = 365; Entry = '30'; Expected = 365 }
    ) {
        $entries = @(Get-JunkLocationList -Path (New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson $Entry))
        $location = @((Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays $Scan).Locations)[0]
        $location.MinimumAgeDays | Should -Be $Expected
    }

    It 'counts the override only where it actually changed the window' {
        $entries = @(Get-JunkLocationList -Path (New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson '30'))

        $raised = Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7
        [long] $raised.Statistic['AgeWindowOverrideCount'] | Should -Be 1

        $outranked = Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 90
        [long] $outranked.Statistic['AgeWindowOverrideCount'] | Should -Be 0
    }
}

Describe 'Change 1: the evidence names the window it actually used' {

    It 'quotes the entry window, not the scan window, and says which it was' {
        $entries = @(Get-JunkLocationList -Path (New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson '30'))
        $inventory = Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7
        $finding = @(Find-JunkFileLocation -Location $inventory.Locations -MinimumAgeDays 7)[0]

        $finding | Should -Not -BeNullOrEmpty
        $evidence = $finding.Evidence -join ' '
        $evidence | Should -Match 'older than 30 days'
        $evidence | Should -Not -Match 'older than 7 days'
        $evidence | Should -Match 'its own 30-day window'
        $evidence | Should -Match 'the 7 days the rest of this scan used'
        $finding.MinimumAgeDays | Should -Be 30
    }

    It 'names the held-back count against the same window' {
        $entries = @(Get-JunkLocationList -Path (New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson '30'))
        $inventory = Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7
        $evidence = (@(Find-JunkFileLocation -Location $inventory.Locations -MinimumAgeDays 7)[0]).Evidence -join ' '
        $evidence | Should -Match 'modified in the last 30 days'
        $evidence | Should -Not -Match 'modified in the last 7 days'
    }

    It 'adds no age-window line at all when the two windows agree' {
        $entries = @(Get-JunkLocationList -Path (New-AmendmentJunkListForTree -Path $script:AgeTree))
        $inventory = Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7
        $evidence = (@(Find-JunkFileLocation -Location $inventory.Locations -MinimumAgeDays 7)[0]).Evidence -join ' '
        $evidence | Should -Match 'older than 7 days'
        $evidence | Should -Not -Match 'its own'
    }

    It 'falls back to the scan window for a record that carries none' {
        # A record built by hand, or read back from a run older than this chunk.
        $record = [pscustomobject]@{
            Id = 'legacy'; DisplayName = 'A record from before this chunk'
            Reason = 'Fabricated.'; Provenance = 'measured'; InventoryOnly = $false
            IsAssessed = $true; ResolvedPath = @('C:\fabricated')
            FileCount = 10; TotalBytes = 1000; EligibleFileCount = 4; EligibleBytes = 400
            AgeHeldBackCount = 2; AgeHeldBackBytes = 100; InUseCount = 0
            UndeterminedCount = 0; ReparsePointCount = 0; DuplicatePathCount = 0
            IsSizeFloor = $false; UnreadableDirectoryCount = 0; EligibleFile = @()
        }
        $finding = @(Find-JunkFileLocation -Location @($record) -MinimumAgeDays 14)[0]
        $finding.MinimumAgeDays | Should -Be 14
        ($finding.Evidence -join ' ') | Should -Match 'older than 14 days'
    }
}

Describe 'Change 1: a malformed minimumAgeDays fails the whole load, loudly' {

    # Rejected rather than ignored, and the WHOLE load rather than the entry: a
    # malformed curated entry is a bug in a file this project ships, not a
    # condition of the machine, and a junk list one location shorter looks exactly
    # like a slightly cleaner disk.

    It 'throws for minimumAgeDays <Json>' -ForEach @(
        @{ Json = '"30"';    Expected = '*whole JSON number*' }
        @{ Json = 'true';    Expected = '*whole JSON number*' }
        @{ Json = '30.5';    Expected = '*whole JSON number*' }
        @{ Json = '"thirty"'; Expected = '*whole JSON number*' }
        @{ Json = '0';       Expected = '*between 1 and*' }
        @{ Json = '-5';      Expected = '*between 1 and*' }
        @{ Json = '99999';   Expected = '*between 1 and*' }
    ) {
        $listPath = New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson $Json
        { Get-JunkLocationList -Path $listPath } | Should -Throw -ExpectedMessage $Expected
    }

    It 'names the entry it is complaining about' {
        $listPath = New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson '"30"'
        { Get-JunkLocationList -Path $listPath } | Should -Throw -ExpectedMessage "*'fabricated'*"
    }

    It 'takes a whole scan down with it rather than reporting one location fewer' {
        $listPath = New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson '0'
        { Invoke-JunkFileScan -LocationListPath $listPath } | Should -Throw
    }

    It 'accepts the bounds themselves' -ForEach @('1', '3650') {
        $listPath = New-AmendmentJunkListForTree -Path $script:AgeTree -MinimumAgeDaysJson $_
        { Get-JunkLocationList -Path $listPath } | Should -Not -Throw
    }
}

Describe 'Change 1: the NVIDIA shader cache is flaggable now' {

    BeforeAll {
        $script:Shader     = @($script:Entries | Where-Object { $_.Id -eq 'nvidia-shader-cache' })[0]
        $script:ShaderRow  = @($script:JunkScan.Locations | Where-Object { $_.Id -eq 'nvidia-shader-cache' })[0]
        $script:ShaderHits = @($script:JunkScan.Findings | Where-Object { $_.Id -eq 'nvidia-shader-cache' })
    }

    It 'is no longer inventory-only, and no code forces it to be' {
        $script:Shader.InventoryOnly     | Should -BeFalse
        $script:Shader.IsForcedInventory | Should -BeFalse
        $script:Shader.MinimumAgeDays    | Should -Be 30
    }

    It 'is reported as a location whatever is in it' {
        $script:ShaderRow | Should -Not -BeNullOrEmpty
        $script:ShaderRow.Status | Should -Not -Be 'Refused'
    }

    It 'pays for the in-use probe now, which is the price of being flaggable' {
        # As inventory-only it skipped the probe and built no file list. A
        # location that is not assessed can never produce a Finding, so if this
        # regressed the entry would be flaggable on paper and silent in practice.
        if ($script:ShaderRow.Exists -eq $true -and $script:ShaderRow.Status -ne 'Skipped') {
            $script:ShaderRow.IsAssessed | Should -BeTrue
        }
        else {
            # No NVIDIA driver here, or the folder could not be read. Either is a
            # complete answer and neither is a Finding.
            $script:ShaderHits.Count | Should -Be 0
        }
    }

    It 'was measured against 30 days, not against the scan''s 7' {
        $script:ShaderRow.MinimumAgeDays | Should -Be 30
        $script:JunkScan.MinimumAgeDays  | Should -Be 7
        [long] $script:JunkScan.AgeWindowOverrideCount | Should -Be 1
    }

    It 'produces a Finding when it holds anything old enough, and none when it does not' {
        if ([long] $script:ShaderRow.EligibleFileCount -gt 0) {
            $script:ShaderHits.Count | Should -Be 1
        }
        else {
            $script:ShaderHits.Count | Should -Be 0
        }
    }

    It 'is "Review needed" like every other row in this category, never "Safe to remove"' {
        foreach ($finding in $script:ShaderHits) {
            $finding.Confidence      | Should -Be 'Known'
            $finding.RequiresConsent | Should -BeTrue
            $finding.SafetyLabel     | Should -Be 'Review needed'
            $finding.RemovalMethod   | Should -Be 'FileDelete'
            $finding.MinimumAgeDays  | Should -Be 30
        }
    }

    It 'tells the user what emptying it costs, in words and without a time claim' {
        $script:Shader.Reason | Should -Match 'shader'
        $script:Shader.Reason | Should -Match 'rebuild'
        $script:Shader.Reason | Should -Match 'recompile'
        $script:Shader.Reason | Should -Match 'stutter'
        $script:Shader.Reason | Should -Match 'size limit'
        # No number of seconds or minutes anywhere: the rebuild cost has never been
        # measured by this project and the receipt-not-benchmark rule forbids
        # inventing one.
        $script:Shader.Reason | Should -Not -Match '\d+\s*(second|minute|hour)'
        $script:Shader.Reason | Should -Not -Match 'until this project has measured'
    }
}

Describe 'Change 2: the servicing logs are sized and never offered' {

    BeforeAll {
        $script:Logs    = @($script:Entries | Where-Object { $_.Id -eq 'servicing-logs' })[0]
        $script:LogsRow = @($script:JunkScan.Locations | Where-Object { $_.Id -eq 'servicing-logs' })[0]
    }

    It 'is inventory-only by the list, not forced by code' {
        # Unlike prefetch: nothing in the detector protects the CBS logs, so this
        # one is a curation decision and reads as one.
        $script:Logs.InventoryOnly     | Should -BeTrue
        $script:Logs.IsForcedInventory | Should -BeFalse
    }

    It 'produces no Finding, whatever is in it' {
        @($script:JunkScan.Findings | Where-Object { $_.Id -eq 'servicing-logs' }).Count | Should -Be 0
    }

    It 'is still enumerated and still sized -- this changed what is offered, not what is measured' {
        $script:LogsRow | Should -Not -BeNullOrEmpty
        $script:LogsRow.InventoryOnly | Should -BeTrue
        $script:LogsRow.Status        | Should -Not -Be 'Refused'
        [long] $script:LogsRow.TotalBytes | Should -BeGreaterOrEqual 0
    }

    It 'says what they are, and that this tool will not delete them' {
        $script:Logs.Reason | Should -Match 'troubleshoot'
        $script:Logs.Reason | Should -Match 'Windows Update'
        $script:Logs.Reason | Should -Match 'never offers to delete'
        # The old text argued FOR removal. It must not still be there arguing that
        # under an entry that is never offered.
        $script:Logs.Reason | Should -Not -Match 'nothing reads them back'
    }
}

Describe 'Changes 1 and 2: the amended list still promises nothing' {

    It 'the shipped list file never says "<_>"' -ForEach $ForbiddenPhrase {
        $raw = [System.IO.File]::ReadAllText($script:ListPath)
        $raw.IndexOf($PSItem, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1
    }

    It 'no Finding on this machine says any of them, and every one carries the negation' {
        foreach ($finding in @($script:JunkScan.Findings)) {
            $evidence = ($finding.Evidence -join ' ')
            foreach ($forbidden in $script:ForbiddenPhrase) {
                $evidence.IndexOf($forbidden, [System.StringComparison]::OrdinalIgnoreCase) |
                    Should -Be -1 -Because "'$($finding.Id)' must not say '$forbidden'"
            }
            $evidence | Should -Match 'not a promise of space reclaimed'
        }
    }

    It 'no removal preview on this machine says any of them' {
        foreach ($plan in @($script:JunkScan.Findings | Get-RemovalPlan)) {
            $preview = (($plan | Get-RemovalPreview) -join ' ')
            foreach ($forbidden in $script:ForbiddenPhrase) {
                $preview.IndexOf($forbidden, [System.StringComparison]::OrdinalIgnoreCase) |
                    Should -Be -1 -Because "the preview for '$($plan.FindingId)' must not say '$forbidden'"
            }
        }
    }

    It 'still gives every entry a reason long enough to be evidence' {
        foreach ($entry in $script:Entries) {
            $entry.Reason.Length | Should -BeGreaterThan 40
        }
    }
}

Describe 'Q15: the dispatcher last gate covers startup entries too' {

    It 'refuses a Run-key finding whose display name is security software, naming the class' {
        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'StartupItem' `
            -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::MBAMTray' `
            -DisplayName 'Malwarebytes Tray Application' -RemovalMethod 'RegistryRunKey')

        $plan.Route             | Should -Be 'StartupApproved'
        $plan.Supported         | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'security'
        $plan.UnsupportedReason | Should -Match 'antivirus-and-endpoint-security'
        @($plan.Step).Count     | Should -Be 0
    }

    It 'refuses a Startup-folder finding the same way, before it even resolves the store' {
        # The path is not in either Startup folder, so without the gate this would
        # be refused for THAT -- the right outcome reached by luck, under a sentence
        # that says the wrong thing.
        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'StartupItem' `
            -Id (Join-Path $script:Scratch 'Bitdefender Agent.lnk') `
            -DisplayName 'Bitdefender Agent' -RemovalMethod 'FileDelete')

        $plan.Route             | Should -Be 'StartupApproved'
        $plan.Supported         | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'security'
        $plan.UnsupportedReason | Should -Not -Match 'Startup folder'
        @($plan.Step).Count     | Should -Be 0
    }

    It 'refuses on the anti-cheat entry too, which is the same class from a different row' {
        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'StartupItem' `
            -Id 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::Riot Vanguard' `
            -DisplayName 'Riot Vanguard' -RemovalMethod 'RegistryRunKey')

        $plan.Supported         | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'security'
        $plan.UnsupportedReason | Should -Match 'anti-cheat'
    }

    It 'does NOT extend the refusal to driver or driver-utility' {
        # Those classes are the detector's business, and P2-C2a gave them a
        # measured orphan exemption that took a whole chunk to get right. A gate
        # here that refused every protected class would silently undo it.
        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'StartupItem' `
            -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::NoSuchRazerEntry2b6f' `
            -DisplayName 'Razer Synapse' -RemovalMethod 'RegistryRunKey')

        $plan.Supported | Should -BeTrue
        if ($null -ne $plan.UnsupportedReason) { $plan.UnsupportedReason | Should -Not -Match 'security' }
    }

    It 'still plans an ordinary Run-key finding, with the step and the bytes' {
        # Against REAL Run values on this machine, read-only. The gate must not
        # quietly break the route it guards.
        $planned = $null
        foreach ($item in $script:RunItems) {
            $candidate = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'StartupItem' `
                -Id $item.Id -DisplayName $item.DisplayName -RemovalMethod 'RegistryRunKey')
            if ($candidate.Supported -and @($candidate.Step).Count -eq 1) { $planned = $candidate; break }
        }

        $planned | Should -Not -BeNullOrEmpty -Because 'this machine has Run entries that are not security software'
        $planned.Route        | Should -Be 'StartupApproved'
        $planned.CurrentState | Should -Be 'Present'
        $planned.IsReversible | Should -BeTrue

        $step = @($planned.Step)[0]
        $step.Kind | Should -Be 'RegistryValueWrite'
        $step.Target | Should -Match 'StartupApproved'

        # Only byte 0 changes, to the measured disabled byte. Where a record
        # already exists the rest is PRESERVED rather than a timestamp being
        # invented; where none exists it is twelve bytes with the rest zero.
        $bytes = @($step.Detail.PlannedByte)
        $bytes.Count | Should -BeGreaterThan 0
        $bytes[0]    | Should -Be 1

        if ($step.Detail.ValueExisted) {
            $previous = @($step.Detail.PreviousByte)
            $bytes.Count | Should -Be $previous.Count
            for ($i = 1; $i -lt $bytes.Count; $i++) { $bytes[$i] | Should -Be $previous[$i] }
        }
        else {
            $bytes.Count | Should -Be 12
            for ($i = 1; $i -lt 12; $i++) { $bytes[$i] | Should -Be 0 }
        }
    }

    It 'still treats a Run value that is not there as AlreadyGone, not as a refusal' {
        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'StartupItem' `
            -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::NoSuchFabricatedEntry2b6f' `
            -DisplayName 'Not A Real Startup Entry' -RemovalMethod 'RegistryRunKey')

        $plan.Supported    | Should -BeTrue
        $plan.CurrentState | Should -Be 'AlreadyGone'
        @($plan.Step).Count | Should -Be 0
    }

    It 'denies the plan outright when the exclusion list will not load' {
        # Mirrors the service route exactly: a list that will not load must never
        # read as "nothing is excluded".
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-UnusedAppExclusionList -MockWith {
            throw 'fabricated exclusion-list failure'
        }

        $plan = Get-RemovalPlan -WarningAction SilentlyContinue -Finding (New-AmendmentFinding -Category 'StartupItem' `
            -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::Anything' `
            -DisplayName 'Anything At All' -RemovalMethod 'RegistryRunKey')

        $plan.Supported         | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'exclusion list could not be loaded'
        $plan.UnsupportedReason | Should -Match 'never planned for without that check'
        @($plan.Step).Count     | Should -Be 0
    }

    It 'denies a service the same way when the list will not load, unchanged from P3-C1' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-UnusedAppExclusionList -MockWith {
            throw 'fabricated exclusion-list failure'
        }

        $plan = Get-RemovalPlan -WarningAction SilentlyContinue -Finding (New-AmendmentFinding -Category 'Service' `
            -Id 'Spooler' -DisplayName 'Print Spooler' -RemovalMethod 'ServiceDisable' -RequiresConsent)

        $plan.Supported         | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'exclusion list could not be loaded'
    }

    It 'builds the match candidate from the entry name and the display name, and never a publisher' {
        # P2-C2a's rule: for an entry whose binary may be gone, only display-name
        # rules can ever match, because the binary carrying the publisher is gone
        # by definition. So the candidate says so rather than leaving it to chance.
        InModuleScope Win11Optimizer.Engine {
            $builder = [pscustomobject]@{
                FindingId     = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::MBAMTray'
                DisplayName   = 'Malwarebytes Tray Application'
                RemovalMethod = 'RegistryRunKey'
            }
            $candidate = ConvertTo-RemovalStartupExclusionCandidate -Builder $builder
            $candidate.Name        | Should -Be 'MBAMTray'
            $candidate.DisplayName | Should -Be 'Malwarebytes Tray Application'
            $candidate.Publisher   | Should -BeNullOrEmpty

            $shortcut = [pscustomobject]@{
                FindingId     = 'C:\Users\someone\Start Menu\Programs\Startup\Norton Security.lnk'
                DisplayName   = ''
                RemovalMethod = 'FileDelete'
            }
            $fromFile = ConvertTo-RemovalStartupExclusionCandidate -Builder $shortcut
            $fromFile.Name        | Should -Be 'Norton Security.lnk'
            # An empty display name falls back to the entry name, so a finding with
            # no display name is still testable against the list.
            $fromFile.DisplayName | Should -Be 'Norton Security.lnk'
        }
    }

    It 'still refuses a security-class SERVICE, so the service gate is untouched' {
        $service = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Malwarebytes*' }) |
            Select-Object -First 1
        if ($null -eq $service) {
            # No security service here to point at, so make the same claim against
            # a name the list covers by display name alone.
            $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'Service' `
                -Id 'NoSuchFabricatedService2b6f' -DisplayName 'Malwarebytes Service' `
                -RemovalMethod 'ServiceDisable' -RequiresConsent)
            $plan.Supported | Should -BeTrue   # AlreadyGone: the key is not there at all
            $plan.CurrentState | Should -Be 'AlreadyGone'
            return
        }

        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'Service' `
            -Id $service.Name -DisplayName $service.DisplayName -RemovalMethod 'ServiceDisable' -RequiresConsent)
        $plan.Supported         | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'security'
    }
}

Describe 'Q17: a rundll32 uninstall string fails closed' {

    It 'refuses the shape, naming rundll32 and where to uninstall it instead' {
        $key = New-AmendmentUninstallKey -Name 'rundll-shape' -Value @{
            DisplayName     = 'Fabricated Display Driver'
            UninstallString = '"C:\WINDOWS\SysWOW64\RunDll32.EXE" "C:\Program Files\Fabricated\Installer\NVI2.DLL",UninstallPackage Display.Driver'
        }
        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'OemBloatware' -Id $key -RemovalMethod 'RegistryUninstallString')

        $plan.Route             | Should -Be 'RegistryUninstallString'
        $plan.Supported         | Should -BeFalse
        $plan.CurrentState      | Should -Be 'Present'
        $plan.UnsupportedReason | Should -Match 'rundll32'
        $plan.UnsupportedReason | Should -Match 'Installed apps'
        @($plan.Step).Count     | Should -Be 0
    }

    It 'refuses it however the key spells the program' -ForEach @(
        '"C:\WINDOWS\SysWOW64\RunDll32.EXE" "C:\x\NVI2.DLL",UninstallPackage Display.Driver'
        '"C:\Windows\System32\rundll32.exe" "C:\x\thing.dll",RemoveIt /quiet'
        'C:\Windows\System32\RUNDLL32.EXE C:\x\thing.dll,Uninstall'
    ) {
        $key = New-AmendmentUninstallKey -Name ('rundll-' + [guid]::NewGuid().ToString('N')) -Value @{
            DisplayName = 'Fabricated'; UninstallString = $PSItem
        }
        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'OemBloatware' -Id $key -RemovalMethod 'RegistryUninstallString')
        $plan.Supported         | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'rundll32'
    }

    It 'needs BOTH signals: a rundll32 string with no comma-joined entry point still plans' {
        $key = New-AmendmentUninstallKey -Name 'rundll-no-entrypoint' -Value @{
            DisplayName     = 'Fabricated Ordinary Uninstaller'
            UninstallString = '"C:\WINDOWS\System32\RunDll32.EXE" /u /s'
        }
        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'OemBloatware' -Id $key -RemovalMethod 'RegistryUninstallString')

        $plan.Supported     | Should -BeTrue
        @($plan.Step).Count | Should -Be 1
        @($plan.Step)[0].Kind | Should -Be 'ProcessCommand'
    }

    It 'needs BOTH signals: a comma-joined argument to something that is not rundll32 still plans' {
        $key = New-AmendmentUninstallKey -Name 'comma-not-rundll' -Value @{
            DisplayName     = 'Fabricated Comma User'
            UninstallString = '"C:\Program Files\Fabricated\unins000.exe" --modules=C:\x\thing.dll,Extra'
        }
        $plan = Get-RemovalPlan -Finding (New-AmendmentFinding -Category 'OemBloatware' -Id $key -RemovalMethod 'RegistryUninstallString')

        $plan.Supported     | Should -BeTrue
        @($plan.Step).Count | Should -Be 1
    }

    It 'detects the two signals separately, so neither is doing the other''s work' {
        InModuleScope Win11Optimizer.Engine {
            Test-RemovalIsRunDll32 -Executable 'C:\WINDOWS\SysWOW64\RunDll32.EXE' | Should -BeTrue
            Test-RemovalIsRunDll32 -Executable 'C:\Windows\System32\rundll32'     | Should -BeTrue
            Test-RemovalIsRunDll32 -Executable 'C:\x\unins000.exe'                | Should -BeFalse
            Test-RemovalIsRunDll32 -Executable ''                                 | Should -BeFalse

            Test-RemovalHasEntryPointArgument -Argument @('C:\x\NVI2.DLL,UninstallPackage', 'Display.Driver') | Should -BeTrue
            Test-RemovalHasEntryPointArgument -Argument @('C:\x\thing.cpl,Run')  | Should -BeTrue
            Test-RemovalHasEntryPointArgument -Argument @('/u', '/s')            | Should -BeFalse
            Test-RemovalHasEntryPointArgument -Argument @('C:\x\thing.dll')      | Should -BeFalse
            Test-RemovalHasEntryPointArgument -Argument @('C:\x\thing.dll,')     | Should -BeFalse
            Test-RemovalHasEntryPointArgument -Argument @(',Uninstall')          | Should -BeFalse
            Test-RemovalHasEntryPointArgument -Argument @('a,b')                 | Should -BeFalse
            Test-RemovalHasEntryPointArgument -Argument @()                      | Should -BeFalse
        }
    }

    It 'leaves the parser itself alone: the argv is still correct, it is just not usable' {
        # The refusal is not a parser bug being papered over. The array is right;
        # rundll32 is the one program that does not read one.
        InModuleScope Win11Optimizer.Engine {
            $parsed = Split-RemovalCommandString -CommandString '"C:\WINDOWS\SysWOW64\RunDll32.EXE" "C:\x\NVI2.DLL",UninstallPackage Display.Driver'
            @($parsed.Argument).Count | Should -Be 2
            @($parsed.Argument)[0] | Should -Be 'C:\x\NVI2.DLL,UninstallPackage'
        }
    }

    It 'changes no real plan on this machine: nothing here is refused for this reason' {
        $findings = @((Invoke-OemBloatwareScan -WarningAction SilentlyContinue).Findings) +
                    @((Invoke-UnusedAppScan -WarningAction SilentlyContinue).Findings)
        foreach ($plan in @($findings | Get-RemovalPlan)) {
            if ($null -eq $plan.UnsupportedReason) { continue }
            $plan.UnsupportedReason | Should -Not -Match 'rundll32'
        }
    }
}

Describe 'Change 6: Micro-Star* is a publisher pattern, once' {

    BeforeAll {
        $script:OemEntry = @($script:Exclusions | Where-Object { $_.Id -eq 'oem-firmware-update-utility' })[0]
    }

    It 'appears exactly once in the exclusion list file' {
        # The check REVIEW.md's "does this list ship a pattern known to match
        # nothing" box exists to catch: keeping the inert copy next to the working
        # one is list padding.
        $raw = [System.IO.File]::ReadAllText($script:ExclusionPath)
        @([regex]::Matches($raw, [regex]::Escape('"Micro-Star*"'))).Count | Should -Be 1
    }

    It 'is on registryPublisher and no longer on registryDisplayName' {
        $script:OemEntry                     | Should -Not -BeNullOrEmpty
        $script:OemEntry.RegistryPublisher   | Should -Contain 'Micro-Star*'
        $script:OemEntry.RegistryDisplayName | Should -Not -Contain 'Micro-Star*'
    }

    It 'keeps the rest of the entry intact' {
        $script:OemEntry.Class | Should -Be 'driver-utility'
        foreach ($pattern in 'MSI Center*', 'Mystic_Light*', 'Lenovo Vantage*', 'Dell SupportAssist*') {
            $script:OemEntry.RegistryDisplayName | Should -Contain $pattern
        }
        $script:OemEntry.AppxPackageName | Should -Contain '9426MICRO-STARINTERNATION.*'
    }

    It 'now matches a record whose publisher is <_> and whose display name is nothing like it' -ForEach @(
        "Micro-Star Int'l Co., Ltd."
        'MICRO-STAR INTERNATIONAL CO., LTD.'
    ) {
        $publisher = $PSItem
        $match = InModuleScope Win11Optimizer.Engine -Parameters @{ Publisher = $publisher } {
            param($Publisher)
            Get-OptimizerExclusionMatch -ExclusionEntry (Get-UnusedAppExclusionList) -InstalledApp (
                New-InstalledApp -Source 'Service' -Id 'MSI_Case_Service' -Name 'MSI_Case_Service' `
                    -DisplayName 'MSI_Case_Service' -Publisher $Publisher)
        }
        $match | Should -Not -BeNullOrEmpty
        $match.Id | Should -Be 'oem-firmware-update-utility'
    }

    It 'catches LightKeeperService by publisher, which no display-name rule reaches' {
        $withPublisher = InModuleScope Win11Optimizer.Engine {
            Get-OptimizerExclusionMatch -ExclusionEntry (Get-UnusedAppExclusionList) -InstalledApp (
                New-InstalledApp -Source 'Service' -Id 'LightKeeperService' -Name 'LightKeeperService' `
                    -DisplayName 'LightKeeperService' -Publisher "Micro-Star Int'l Co., Ltd.")
        }
        $withPublisher.Id | Should -Be 'oem-firmware-update-utility'

        # And without a publisher it matches nothing at all, which is exactly why
        # P2-C2a's second-chance resolver had to exist for this to work.
        $withoutPublisher = InModuleScope Win11Optimizer.Engine {
            Get-OptimizerExclusionMatch -ExclusionEntry (Get-UnusedAppExclusionList) -InstalledApp (
                New-InstalledApp -Source 'Service' -Id 'LightKeeperService' -Name 'LightKeeperService' `
                    -DisplayName 'LightKeeperService' -Publisher '')
        }
        $withoutPublisher | Should -BeNullOrEmpty
    }

    It 'credits the DISPLAY-NAME rule for Mystic_Light_Service, not the new publisher one' {
        # Reported honestly: this one was already covered by 'Mystic_Light*', so
        # the new pattern must not be given credit for a match it did not make.
        $match = InModuleScope Win11Optimizer.Engine {
            Get-OptimizerExclusionMatch -ExclusionEntry (Get-UnusedAppExclusionList) -InstalledApp (
                New-InstalledApp -Source 'Service' -Id 'Mystic_Light_Service' -Name 'Mystic_Light_Service' `
                    -DisplayName 'Mystic_Light_Service' -Publisher '')
        }
        $match | Should -Not -BeNullOrEmpty
        $match.Id | Should -Be 'oem-firmware-update-utility'
        $match.RegistryDisplayName | Should -Contain 'Mystic_Light*'
    }

    It 'reaches nothing by display name on this machine, which is why the pattern was inert there' {
        # The measurement the move is built on, pinned so it is a fact rather than
        # a claim in a report. If a machine ever DOES carry a Micro-Star display
        # name, this fails and the move needs re-reading.
        @(Get-RegistryInstalledApp | Where-Object { $_.DisplayName -like 'Micro-Star*' }).Count | Should -Be 0
        @($script:StartupItems | Where-Object { $_.DisplayName -like 'Micro-Star*' }).Count     | Should -Be 0
    }

    It 'can only ever ADD an exclusion here, because registryPublisher stands alone on this list' {
        # The whitelist treats registryPublisher as an AND-guard; this list tests
        # it standalone. The move is only safe because of which list it is in, so
        # the difference is asserted rather than trusted.
        $publisherOnly = InModuleScope Win11Optimizer.Engine {
            Get-OptimizerExclusionMatch -ExclusionEntry (Get-UnusedAppExclusionList) -InstalledApp (
                New-InstalledApp -Source 'Service' -Id 'AnythingAtAll' -Name 'AnythingAtAll' `
                    -DisplayName 'Nothing On Any List' -Publisher 'Micro-Star Whatever')
        }
        $publisherOnly | Should -Not -BeNullOrEmpty
        $publisherOnly.Id | Should -Be 'oem-firmware-update-utility'
    }
}

Describe 'The absolute rule still holds: this chunk removes nothing' {

    # P3-C1's three enforcement tests live in tests\RemovalDispatcher.Tests.ps1 and
    # are unchanged. These are the same claim about the two files THIS chunk edits,
    # so a reviewer reading only this file can still see it made.

    It '<_> invokes no command that could change the machine' -ForEach @(
        'Removal\Dispatcher.ps1'
        'Detectors\JunkFiles.ps1'
    ) {
        $relative = $_
        $path = Join-Path $script:EngineRoot $relative
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)

        $invoked = [string[]] @(
            $ast.FindAll({
                param($node) $node -is [System.Management.Automation.Language.CommandAst]
            }, $true) | ForEach-Object {
                $element = $_.CommandElements[0]
                if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $element.Value } else { $null }
            } | Where-Object { $null -ne $_ } | Sort-Object -Unique
        )

        foreach ($name in $invoked) {
            $verb = ($name -split '-', 2)[0]
            @('Remove', 'Disable', 'Unregister', 'Uninstall', 'Stop', 'Restart', 'Clear', 'Set') |
                Should -Not -Contain $verb -Because "'$name' is invoked by $relative"
        }
        $invoked | Should -Not -Contain 'Start-Process'
        $invoked | Should -Not -Contain 'Invoke-Expression'
        $invoked | Should -Not -Contain 'Set-Service'
    }

    It 'Win32_Product is in neither the contract nor the two files this chunk edits' {
        (Get-FindingContract).RemovalMethods | Should -Not -Contain 'Win32_Product'
        foreach ($relative in 'Removal\Dispatcher.ps1', 'Detectors\JunkFiles.ps1') {
            $source = [System.IO.File]::ReadAllText((Join-Path $script:EngineRoot $relative))
            $source | Should -Not -Match 'Win32_Product'
        }
    }
}
