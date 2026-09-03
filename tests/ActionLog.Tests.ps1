#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the append-only action ledger (chunk P3-C2,
    src\Win11Optimizer.Engine\Removal\ActionLog.ps1) and for the best-effort
    System Restore checkpoint beside it (Removal\RestorePoint.ps1).

    The first Describe is the one that matters most, and it is the same shape as
    P3-C1's: it re-applies that chunk's three no-removal enforcement lists,
    UNCHANGED, to the two new source files. Nothing in this chunk may change the
    state of the machine except the one Checkpoint-Computer call, which is why
    that call lives alone in a file of its own and is named here by hand.

    After that the suite is about one failure and one failure only: AN ACTION
    THAT HAPPENED AND WAS NOT RECORDED. Every other test in this file is a
    variation on it --

      * a line written but not flushed, lost to a crash;
      * an Intent with no Outcome read back as "did not happen";
      * a malformed line silently skipped;
      * rollback data that degraded on the way through JSON;
      * two writers interleaving half a line each;
      * a receipt that leaves out what it cannot account for.

    Run:  .\tests\Invoke-Tests.ps1        (and -On51, which is not optional)
#>

# Discovery-time, for the -ForEach that makes one test per forbidden phrase.
# Pester runs a file's top level during discovery and its BeforeAll during the
# run, in separate scopes, so the list is dot-sourced in both.
. (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
$ForbiddenPhrase = Get-OptimizerForbiddenPhrase

BeforeAll {
    $script:RepoRoot      = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot    = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath  = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath    = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:LedgerSource  = Join-Path $script:EngineRoot 'Removal\ActionLog.ps1'
    $script:RestoreSource = Join-Path $script:EngineRoot 'Removal\RestorePoint.ps1'
    $script:NewSource     = @($script:LedgerSource, $script:RestoreSource)

    # A log root of our own. The real one is the repo's logs\ folder, and the
    # ledger is the one file in this project that is never rotated, so nothing
    # in this suite may write to it.
    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-ledger-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-ledger-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    $script:Contract = Get-RemovalContract

    # The five functions this chunk adds, and nothing else.
    $script:NewExport = @(
        'Get-OptimizerActionLogPath'
        'Write-OptimizerAction'
        'Get-OptimizerActionLog'
        'Get-OptimizerRunReceipt'
        'New-OptimizerRestorePoint'
    )

    # ---- the source, comment-blanked, and the ASTs -------------------------
    #
    # Same machinery as tests\RemovalDispatcher.Tests.ps1. It is repeated here
    # rather than shared because a source-scanning assertion that lives somewhere
    # else is one refactor away from scanning nothing, and this is the assertion
    # the whole chunk rests on.
    $script:Blanked    = @{}
    $script:Ast        = @{}
    $script:ParseError = @{}
    $script:Invoked    = @{}
    $script:Ampersand  = @{}

    foreach ($path in $script:NewSource) {
        $raw    = [System.IO.File]::ReadAllText($path)
        $tokens = $null
        $errors = $null
        $parsed = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref] $tokens, [ref] $errors)

        # Offsets are preserved -- only non-newline characters inside a comment
        # span become spaces -- because both files have to be able to NAME the
        # things they never do, and -match is case-insensitive.
        $builder = New-Object System.Text.StringBuilder $raw
        foreach ($token in @($tokens | Where-Object { $_.Kind -eq 'Comment' })) {
            $start  = $token.Extent.StartOffset
            $length = $token.Extent.EndOffset - $start
            for ($i = 0; $i -lt $length; $i++) {
                if ($builder[$start + $i] -ne "`n" -and $builder[$start + $i] -ne "`r") {
                    $builder[$start + $i] = ' '
                }
            }
        }

        $script:Blanked[$path]    = $builder.ToString()
        $script:Ast[$path]        = $parsed
        $script:ParseError[$path] = @($errors).Count

        $script:Invoked[$path] = [string[]] @(
            $parsed.FindAll({
                param($node) $node -is [System.Management.Automation.Language.CommandAst]
            }, $true) | ForEach-Object {
                $element = $_.CommandElements[0]
                if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $element.Value } else { "<dynamic:$($element.Extent.Text)>" }
            } | Sort-Object -Unique
        )

        $script:Ampersand[$path] = @($parsed.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand
        }, $true))
    }

    # ---- the forbidden benefit-claim phrases -------------------------------
    #
    # One file, read by every suite that enforces them -- tests\ForbiddenPhrase.ps1,
    # P5-C3 change 5. Until then the lists lived in two other suites, differed,
    # and were lifted out of both by AST here to take the union. The property
    # that made that worth doing survives the move and is now the obvious one: a
    # phrase added to the shared file is enforced here on the next run, with no
    # edit to this file.
    . (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
    $script:ForbiddenPhrase = Get-OptimizerForbiddenPhrase

    # ---- fixtures ----------------------------------------------------------

    $script:LedgerCounter = 0
    function New-LedgerPath {
        # A ledger of its own per test, so an append-only file cannot leak state
        # from one assertion into the next.
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

    function New-TestJunkFinding {
        param([int] $FileCount = 5, [int] $Bytes = 64, [string] $Id = 'fabricated-junk')

        $folder = Join-Path $script:Scratch ('junk-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $folder -ItemType Directory -Force

        $files = New-Object System.Collections.Generic.List[psobject]
        for ($i = 1; $i -le $FileCount; $i++) {
            $filePath = Join-Path $folder ("file-$i.tmp")
            [System.IO.File]::WriteAllText($filePath, ('x' * $Bytes))
            $null = $files.Add([pscustomobject]@{
                Path         = $filePath
                SizeBytes    = [long] $Bytes
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

    # A plan that never went near the dispatcher. Used where this machine cannot
    # produce a real one for a route, and to prove the ledger accepts a plan that
    # arrived as data -- which is the whole premise of the plan contract.
    function New-FabricatedPlan {
        param(
            [Parameter(Mandatory)] [string] $Route,
            [Parameter(Mandatory)] [string] $Category,
            [Parameter(Mandatory)] [string] $RemovalMethod,
            [Parameter()] [AllowNull()] $RollbackData = $null,
            [string] $Id = 'fabricated-plan',
            [string] $DisplayName = 'Fabricated plan',
            [bool] $Supported = $true,
            [string] $CurrentState = 'Present'
        )
        [pscustomobject]@{
            PSTypeName        = $script:Contract.TypeName
            FindingId         = $Id
            Category          = $Category
            RemovalMethod     = $RemovalMethod
            DisplayName       = $DisplayName
            Confidence        = 'Known'
            Route             = $Route
            Supported         = $Supported
            UnsupportedReason = $null
            CurrentState      = $CurrentState
            VerifiedUtc       = [datetime]::UtcNow.ToString('o')
            RequiresElevation = $false
            RequiresConsent   = $false
            SafetyLabel       = 'Safe to remove'
            IsReversible      = $false
            Step              = [psobject[]] @()
            RollbackData      = $RollbackData
            Note              = [string[]] @()
            PreviewText       = [string[]] @('Fabricated.')
        }
    }

    # ---- one plan per route, discovered rather than hard-coded --------------
    #
    # A route tested only against fabricated input is a weaker claim, so each row
    # looks for something real on THIS machine first and records which it got.
    # The report's round-trip table is this table.
    $script:RouteFixture = [ordered]@{}

    function Add-RouteFixture {
        param(
            [Parameter(Mandatory)] [string] $Route,
            [Parameter(Mandatory)] [string] $Provenance,
            [Parameter()] [AllowNull()] $Finding = $null,
            [Parameter()] [AllowNull()] $Plan = $null
        )
        $resolved = $Plan
        if ($null -eq $resolved) { $resolved = Get-RemovalPlan -Finding $Finding }
        $script:RouteFixture[$Route] = [pscustomobject]@{
            Route      = $Route
            Plan       = $resolved
            Provenance = $Provenance
        }
    }

    $appx = @(Get-AppxPackage -ErrorAction SilentlyContinue |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.PackageFamilyName) } | Select-Object -First 1)
    if ($appx.Count -gt 0) {
        Add-RouteFixture -Route 'AppxPackage' -Provenance 'real' -Finding (New-TestFinding -Category OemBloatware `
            -Id ([string] $appx[0].PackageFamilyName) -DisplayName ([string] $appx[0].Name) -RemovalMethod Appx)
    }
    else {
        Add-RouteFixture -Route 'AppxPackage' -Provenance 'fabricated' -Plan (New-FabricatedPlan `
            -Route 'AppxPackage' -Category OemBloatware -RemovalMethod Appx -RollbackData ([pscustomobject][ordered]@{
                PackageFamilyName = 'Fabricated.Package_8wekyb3d8bbwe'
                PackageFullName   = 'Fabricated.Package_1.0.0.0_neutral__8wekyb3d8bbwe'
                Version           = '1.0.0.0'
                Note              = 'Fabricated.'
            }))
    }

    $installed = @(Get-RegistryInstalledApp | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.UninstallString) -and $_.Id -like 'HKEY_*'
    } | Select-Object -First 1)
    if ($installed.Count -gt 0) {
        Add-RouteFixture -Route 'RegistryUninstallString' -Provenance 'real' -Finding (New-TestFinding -Category OemBloatware `
            -Id ([string] $installed[0].Id) -DisplayName ([string] $installed[0].DisplayName) -RemovalMethod RegistryUninstallString)
    }
    else {
        Add-RouteFixture -Route 'RegistryUninstallString' -Provenance 'fabricated' -Plan (New-FabricatedPlan `
            -Route 'RegistryUninstallString' -Category OemBloatware -RemovalMethod RegistryUninstallString -RollbackData ([pscustomobject][ordered]@{
                KeyPath            = 'HKEY_LOCAL_MACHINE\SOFTWARE\Fabricated'
                UninstallValueName = 'QuietUninstallString'
                UninstallString    = '"C:\Fabricated\uninstall.exe" /S'
                Note               = 'Fabricated.'
            }))
    }

    # Always a refusal by design (docs\STATE.md Q2, closed 2026-08-27), so there
    # is no rollback material for it and nothing to fabricate.
    Add-RouteFixture -Route 'PackageManagement' -Provenance 'real' -Finding (New-TestFinding `
        -Category OemBloatware -Id 'anything' -RemovalMethod PackageManagement)

    # A Run value that already has a StartupApproved record, so PreviousByte
    # carries real REG_BINARY rather than the twelve-zero shape.
    $script:StartupStorePath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    $script:StartupRunPath   = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    $approved = @()
    if ((Test-Path -LiteralPath $script:StartupStorePath) -and (Test-Path -LiteralPath $script:StartupRunPath)) {
        $runValues = @((Get-Item -LiteralPath $script:StartupRunPath).Property)
        $approved  = @((Get-Item -LiteralPath $script:StartupStorePath).Property | Where-Object { $runValues -contains $_ })
    }
    if ($approved.Count -gt 0) {
        Add-RouteFixture -Route 'StartupApproved' -Provenance 'real' -Finding (New-TestFinding -Category StartupItem `
            -Id "$($script:StartupRunPath)::$($approved[0])" -DisplayName ([string] $approved[0]) -RemovalMethod RegistryRunKey)
    }
    else {
        Add-RouteFixture -Route 'StartupApproved' -Provenance 'fabricated' -Plan (New-FabricatedPlan `
            -Route 'StartupApproved' -Category StartupItem -RemovalMethod RegistryRunKey -RollbackData ([pscustomobject][ordered]@{
                ApprovalKeyPath = $script:StartupStorePath
                ValueName       = 'Fabricated'
                ValueKind       = 'Binary'
                ValueExisted    = $true
                PreviousByte    = @(3, 0, 0, 0, 117, 248, 57, 193, 194, 138, 219, 1)
                PreviousHex     = '03-00-00-00-75-F8-39-C1-C2-8A-DB-01'
                Note            = 'Fabricated.'
            }))
    }

    $task = @((Get-StartupItemInventory 3>$null).Items | Where-Object {
        $_.Mechanism -eq 'ScheduledTask' -and -not $_.IsProtectedNamespace
    } | Select-Object -First 1)
    if ($task.Count -gt 0) {
        Add-RouteFixture -Route 'ScheduledTask' -Provenance 'real' -Finding (New-TestFinding -Category StartupItem `
            -Id ([string] $task[0].Id) -DisplayName ([string] $task[0].DisplayName) -RemovalMethod TaskScheduler)
    }
    else {
        Add-RouteFixture -Route 'ScheduledTask' -Provenance 'fabricated' -Plan (New-FabricatedPlan `
            -Route 'ScheduledTask' -Category StartupItem -RemovalMethod TaskScheduler -RollbackData ([pscustomobject][ordered]@{
                TaskPath   = '\Fabricated'
                WasEnabled = $true
                Trigger    = [psobject[]] @([pscustomobject]@{ Type = 'LogonTrigger'; Enabled = $true })
                TaskXml    = '<?xml version="1.0" encoding="UTF-16"?><Task><Triggers /></Task>'
                Note       = 'Fabricated.'
            }))
    }

    $service = @(Get-Service -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($service.Count -gt 0) {
        Add-RouteFixture -Route 'ServiceStartupType' -Provenance 'real' -Finding (New-TestFinding -Category Service `
            -Id ([string] $service[0].Name) -DisplayName ([string] $service[0].DisplayName) -RemovalMethod ServiceDisable -RequiresConsent)
    }
    else {
        Add-RouteFixture -Route 'ServiceStartupType' -Provenance 'fabricated' -Plan (New-FabricatedPlan `
            -Route 'ServiceStartupType' -Category Service -RemovalMethod ServiceDisable -RollbackData ([pscustomobject][ordered]@{
                ServiceName         = 'Fabricated'
                KeyPath             = 'HKLM:\SYSTEM\CurrentControlSet\Services\Fabricated'
                PreviousStartValue  = 2
                PreviousStartupType = 'Automatic'
                Note                = 'Fabricated.'
            }))
    }

    Add-RouteFixture -Route 'JunkFileSet' -Provenance 'real' -Finding (New-TestJunkFinding -FileCount 5)

    # A canonical serialisation, so "byte-identical" is something a test can
    # actually assert. Depth matches the module's own.
    function ConvertTo-Canonical {
        param([Parameter(Mandatory)] [AllowNull()] $InputObject)
        if ($null -eq $InputObject) { return '<null>' }
        ConvertTo-Json -InputObject $InputObject -Depth 24 -Compress
    }

    # Run a script in a CHILD process of the same shell this suite is running
    # under, so 5.1 stays on 5.1. Used for the two claims that cannot be made
    # in-process: a hard kill between Intent and Outcome, and two writers at once.
    $script:ShellPath = (Get-Process -Id $PID).Path

    function New-ChildScript {
        param([Parameter(Mandatory)] [string] $Body)
        $path = Join-Path $script:Scratch ('child-' + [guid]::NewGuid().ToString('N') + '.ps1')
        $text = "`$ErrorActionPreference = 'Stop'" + [Environment]::NewLine +
                "Import-Module '$($script:ManifestPath)' -Force" + [Environment]::NewLine + $Body
        [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
        $path
    }
}

AfterAll {
    Remove-Module Win11Optimizer.Engine -Force -ErrorAction SilentlyContinue
    foreach ($path in @($script:TestLogRoot, $script:Scratch)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item Env:\WIN11OPTIMIZER_LOGROOT -ErrorAction SilentlyContinue
}

Describe 'Nothing in this chunk can change the state of the machine' {

    It 'parses cleanly: <_>' -ForEach @('ActionLog.ps1', 'RestorePoint.ps1') {
        $leaf = $_
        $path = @($script:NewSource | Where-Object { (Split-Path -Path $_ -Leaf) -eq $leaf })[0]
        $script:ParseError[$path] | Should -Be 0
    }

    It 'ActionLog.ps1 contains no <_>' -ForEach @(
        'Remove-', 'Disable-', 'Unregister-', 'Uninstall-',
        'Set-Service', 'Stop-Service', 'Start-Service', 'New-Service',
        'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Item ', 'Clear-Item',
        'Start-Process', 'Invoke-Expression', 'Invoke-Command', 'Invoke-Item', 'Start-Job',
        'cmd /c', 'cmd.exe', 'powershell.exe',
        'Win32_Product', 'Get-WmiObject', 'Get-CimInstance', 'Invoke-CimMethod',
        'File]::Delete', 'Directory]::Delete', 'File]::Move', 'File]::WriteAll',
        'File]::Create', 'File]::AppendAll', 'Set-Acl', 'winget.exe', 'DeleteSubKey', 'DeleteValue'
    ) {
        # P3-C1's list, unchanged, applied to the file this chunk adds. Comment
        # spans are blanked, so this is the code alone.
        $script:Blanked[$script:LedgerSource] | Should -Not -Match ([regex]::Escape($_)) `
            -Because 'the ledger appends to its own log files and does nothing else to this PC'
    }

    It 'RestorePoint.ps1 contains no <_>' -ForEach @(
        'Remove-', 'Disable-', 'Unregister-', 'Uninstall-',
        'Set-Service', 'Stop-Service', 'Start-Service', 'New-Service',
        'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Item ', 'Clear-Item',
        'Start-Process', 'Invoke-Expression', 'Invoke-Command', 'Invoke-Item', 'Start-Job',
        'cmd /c', 'cmd.exe', 'powershell.exe',
        'Win32_Product', 'Get-WmiObject', 'Get-CimInstance', 'Invoke-CimMethod',
        'File]::Delete', 'Directory]::Delete', 'File]::Move', 'File]::WriteAll',
        'File]::Create', 'File]::AppendAll', 'Set-Acl', 'winget.exe', 'DeleteSubKey', 'DeleteValue'
    ) {
        $script:Blanked[$script:RestoreSource] | Should -Not -Match ([regex]::Escape($_)) `
            -Because 'the checkpoint is additive: it asks Windows for a restore point and touches nothing else'
    }

    It 'invokes no command that could change the machine' {
        # P3-C1's AST pass, unchanged, over both new files. The grep above cannot
        # cover a forbidden word that legitimately appears in a string, so this
        # asks what is actually invoked rather than what is written down.
        foreach ($path in $script:NewSource) {
            foreach ($forbidden in 'winget', 'msiexec', 'msiexec.exe', 'rundll32', 'rundll32.exe', 'sc', 'sc.exe', 'reg', 'reg.exe', 'dism', 'dism.exe', 'pnputil', 'takeown', 'icacls') {
                $script:Invoked[$path] | Should -Not -Contain $forbidden -Because "$(Split-Path $path -Leaf) must never run $forbidden"
            }
            foreach ($invoked in $script:Invoked[$path]) {
                $invoked | Should -Not -Match '^(Remove|Disable|Unregister|Uninstall|Stop|Restart|Clear|Set)-' `
                    -Because "$(Split-Path $path -Leaf) invoked '$invoked', which is a verb that changes something"
            }
        }
    }

    It 'uses the call operator nowhere at all' {
        # P3-C1's third pass. The dispatcher has exactly one legitimate ampersand
        # (the Finding contract's safety rule); neither of these files has any.
        foreach ($path in $script:NewSource) {
            $script:Ampersand[$path].Count | Should -Be 0 -Because "$(Split-Path $path -Leaf) turns no string into a command"
        }
    }

    It 'defines no Invoke-* function, and the only executor in the module is P3-C3''s' {
        foreach ($path in $script:NewSource) {
            foreach ($function in @($script:Ast[$path].FindAll({
                param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true))) {
                $function.Name | Should -Not -Match '^Invoke-' -Because 'this chunk is the ledger, not the executor'
            }
        }

        # AMENDED BY P3-C3, and the amendment is argued in
        # docs\handoff\11-executor.report.md. The original line asserted the
        # module exported NO Invoke-*Remov* at all, which was a true statement
        # about a build with no executor in it and became false the moment one
        # shipped. Deleting it would give the two files above a weaker guard than
        # they had; keeping the count at zero would forbid the chunk that follows.
        # So it now names what may exist and where it must live -- which is a
        # stronger claim than "there is none", because a second executor, or one
        # smuggled into either of the two files this Describe is about, still
        # fails it.
        $executor = @(Get-Command -Module Win11Optimizer.Engine | Where-Object { $_.Name -like 'Invoke-*Remov*' })
        $executor.Count | Should -Be 1
        $executor[0].Name | Should -Be 'Invoke-RemovalPlan'
        (Split-Path -Path $executor[0].ScriptBlock.File -Leaf) | Should -Be 'Executor.ps1'
    }

    It 'opens a file for writing in exactly one place, in append mode only' {
        $code = $script:Blanked[$script:LedgerSource]

        # One FileStream, and it is the append primitive.
        ([regex]::Matches($code, [regex]::Escape('New-Object System.IO.FileStream'))).Count | Should -Be 1
        $code | Should -Match 'FileMode\]::Append'
        $code | Should -Not -Match 'FileMode\]::Create'
        $code | Should -Not -Match 'FileMode\]::Truncate'
        $code | Should -Not -Match 'FileMode\]::OpenOrCreate'
        $code | Should -Not -Match 'SetLength'

        # The checkpoint file opens nothing at all.
        $script:Blanked[$script:RestoreSource] | Should -Not -Match 'FileStream'
    }

    It 'never rewrites, truncates or deletes anything it has written' {
        foreach ($path in $script:NewSource) {
            foreach ($forbidden in 'Set-Content', 'Out-File', 'Clear-Content', 'Move-Item', 'Rename-Item', 'Add-Content', 'WriteAllText', 'WriteAllLines', 'AppendAllText') {
                $script:Blanked[$path] | Should -Not -Match ([regex]::Escape($forbidden)) `
                    -Because 'a status change is a NEW record, never an edit to an old one'
            }
        }
    }

    It 'invokes Checkpoint-Computer exactly once, in RestorePoint.ps1, and never in the ledger' {
        # The ONE call in this project that changes the machine. It is additive --
        # it creates a restore point and removes nothing -- and it lives alone so
        # that this claim can be made about one file and audited in one place.
        #
        # Counted from the AST, not from the text: the file also NAMES the command
        # in a Get-Command probe and in the sentence a user reads when the shell
        # has no such command, and neither of those runs it. Same reason 'msiexec'
        # is on the dispatcher's AST list and not its grep list.
        $invocation = @($script:Ast[$script:RestoreSource].FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'Checkpoint-Computer'
        }, $true))
        $invocation.Count | Should -Be 1
        $script:Invoked[$script:RestoreSource] | Should -Contain 'Checkpoint-Computer'

        $script:Invoked[$script:LedgerSource] | Should -Not -Contain 'Checkpoint-Computer'
        $script:Blanked[$script:LedgerSource] | Should -Not -Match 'Checkpoint-Computer'
    }

    It 'writes to the ledger and its manifest folder and to nothing else' {
        # A positive allowlist, measured rather than grepped: a whole log root is
        # watched across a full write cycle and every file that appears in it is
        # named.
        $root = Join-Path $script:Scratch ('allowlist-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $root -ItemType Directory -Force
        $ledger = Join-Path $root 'actions.jsonl'

        $plan = $script:RouteFixture['JunkFileSet'].Plan
        $id   = Write-OptimizerAction -Plan $plan -Path $ledger
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result Succeeded -Path $ledger
        $null = Write-OptimizerAction -Plan $plan -RecordKind Note -ActionId $id -Path $ledger -Data ([pscustomobject]@{ What = 'a note' })

        $written = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
            $_.FullName.Substring($root.Length).TrimStart('\')
        } | Sort-Object)

        @($written | Where-Object { $_ -eq 'actions.jsonl' }).Count | Should -Be 1
        @($written | Where-Object { $_ -like 'action-manifests\*.files.jsonl' }).Count | Should -Be 1
        $written.Count | Should -Be 2 -Because "the only files written were: $($written -join ', ')"
    }

    It 'is ASCII only, in every file this chunk touches' {
        # One non-ASCII character in a comment fails a whole container under 5.1
        # only, and the error names a line in the test harness rather than the
        # character. docs\REVIEW.md, after P3-C1a.
        foreach ($path in @($script:NewSource + @($PSCommandPath, $script:ManifestPath, $script:ModulePath))) {
            $text = [System.IO.File]::ReadAllText($path)
            $bad  = @([regex]::Matches($text, '[^\x20-\x7E\t\r\n]'))
            $bad.Count | Should -Be 0 -Because "$(Split-Path $path -Leaf) must be ASCII only; first offender at offset $(if ($bad.Count -gt 0) { $bad[0].Index } else { -1 })"
        }
    }
}

Describe 'Get-OptimizerActionLogPath: one location, the log root''s' {

    It 'is actions.jsonl in the log root' {
        Get-OptimizerActionLogPath | Should -Be (Join-Path (Get-OptimizerLogRoot) 'actions.jsonl')
    }

    It 'follows the same WIN11OPTIMIZER_LOGROOT override as the run log, not a second mechanism' {
        $previous = $env:WIN11OPTIMIZER_LOGROOT
        try {
            $other = Join-Path $script:Scratch 'override-root'
            $env:WIN11OPTIMIZER_LOGROOT = $other
            Get-OptimizerActionLogPath | Should -Be (Join-Path $other 'actions.jsonl')
        }
        finally { $env:WIN11OPTIMIZER_LOGROOT = $previous }
    }

    It 'creates neither the file nor the folder' {
        $previous = $env:WIN11OPTIMIZER_LOGROOT
        try {
            $other = Join-Path $script:Scratch ('untouched-' + [guid]::NewGuid().ToString('N'))
            $env:WIN11OPTIMIZER_LOGROOT = $other
            $path = Get-OptimizerActionLogPath
            Test-Path -LiteralPath $path  | Should -BeFalse
            Test-Path -LiteralPath $other | Should -BeFalse
        }
        finally { $env:WIN11OPTIMIZER_LOGROOT = $previous }
    }

    It 'is not the run log' {
        # A run log records a scan session and is disposable; the ledger records
        # changes to the machine and is not.
        $null = Start-OptimizerLog -Path (Join-Path $script:Scratch ('runlog-' + [guid]::NewGuid().ToString('N') + '.jsonl'))
        try { Get-OptimizerActionLogPath | Should -Not -Be (Get-OptimizerLogPath) }
        finally { $null = Stop-OptimizerLog }
    }
}

Describe 'The ledger is append-only' {

    It 'returns an empty collection for a ledger that is not there' {
        $entries = @(Get-OptimizerActionLog -Path (New-LedgerPath))
        $entries.Count | Should -Be 0
    }

    It 'returns an empty collection for a ledger that exists and is empty' {
        # `return , $array` would hand the caller an array containing an empty
        # array, and @(...).Count would be 1. docs\REVIEW.md.
        $path = New-LedgerPath
        [System.IO.File]::WriteAllText($path, '')
        $entries = @(Get-OptimizerActionLog -Path $path)
        $entries.Count | Should -Be 0
    }

    It 'writes exactly one line per record' {
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $id = Write-OptimizerAction -Plan $plan -Path $path
        @([System.IO.File]::ReadAllLines($path)).Count | Should -Be 1
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result Succeeded -Path $path
        @([System.IO.File]::ReadAllLines($path)).Count | Should -Be 2
    }

    It 'supersedes by appending, and never edits a line already written' {
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan

        $id = Write-OptimizerAction -Plan $plan -Path $path
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result Failed -ErrorText 'first attempt' -Path $path
        $before = @([System.IO.File]::ReadAllLines($path))

        # The supersede: a SECOND Outcome for the same action.
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result Succeeded -Path $path
        $after = @([System.IO.File]::ReadAllLines($path))

        $after.Count | Should -Be 3
        for ($i = 0; $i -lt $before.Count; $i++) {
            $after[$i] | Should -BeExactly $before[$i] -Because 'no line the ledger has written is ever rewritten'
        }

        # The reader shows the current view: the last Outcome wins, and every
        # record is still there to be read.
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        $entry.Result      | Should -Be 'Succeeded'
        $entry.RecordCount | Should -Be 3
        @($entry.Record | Where-Object { $_.Result -eq 'Failed' }).Count | Should -Be 1
    }

    It 'grows and never shrinks across a long sequence of writes' {
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $length = 0
        foreach ($i in 1..10) {
            $id = Write-OptimizerAction -Plan $plan -Path $path
            $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result Succeeded -Path $path
            $now = (Get-Item -LiteralPath $path).Length
            $now | Should -BeGreaterThan $length
            $length = $now
        }
        @(Get-OptimizerActionLog -Path $path).Count | Should -Be 10
    }

    It 'is UTF-8 without a BOM, one JSON object per line' {
        $path = New-LedgerPath
        $null = Write-OptimizerAction -Plan $script:RouteFixture['ServiceStartupType'].Plan -Path $path
        $bytes = [System.IO.File]::ReadAllBytes($path)
        # No BOM: an appended file that started with one would carry it mid-stream
        # on the next process to open it.
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
        foreach ($line in @([System.IO.File]::ReadAllLines($path))) {
            { ConvertFrom-Json -InputObject $line -ErrorAction Stop } | Should -Not -Throw
        }
    }
}

Describe 'An intent with no outcome is a first-class state' {

    It 'reads back as OutcomeUnknown, not as absent and not as failed' {
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $script:RouteFixture['ServiceStartupType'].Plan -Path $path

        $entries = @(Get-OptimizerActionLog -Path $path)
        $entries.Count | Should -Be 1
        $entries[0].ActionId   | Should -Be $id
        $entries[0].Result     | Should -Be 'OutcomeUnknown'
        $entries[0].HasIntent  | Should -BeTrue
        $entries[0].HasOutcome | Should -BeFalse
        $entries[0].Result     | Should -Not -Be 'Failed'
    }

    It 'survives the writing process being killed between the intent and the outcome' {
        # The claim is that the Intent is on DISK before the caller gets control
        # back, so this kills the process outright between the two writes. If the
        # line were buffered it would not be there afterwards.
        $path = New-LedgerPath
        $child = New-ChildScript -Body @"
`$plan = Get-RemovalPlan -Finding (New-Finding -Category Service -Id 'KilledMidAction' -DisplayName 'Killed mid action' ``
    -Evidence 'test' -Confidence Known -RemovalMethod ServiceDisable)
`$id = Write-OptimizerAction -Plan `$plan -Path '$path'
[System.Diagnostics.Process]::GetCurrentProcess().Kill()
`$null = Write-OptimizerAction -Plan `$plan -RecordKind Outcome -ActionId `$id -Result Succeeded -Path '$path'
"@
        $process = Start-Process -FilePath $script:ShellPath -ArgumentList @('-NoProfile', '-File', $child) -PassThru -WindowStyle Hidden
        $null = $process.WaitForExit(120000)

        Test-Path -LiteralPath $path | Should -BeTrue -Because 'the Intent is flushed to disk before the attempt, not after it'
        $entries = @(Get-OptimizerActionLog -Path $path)
        $entries.Count       | Should -Be 1
        $entries[0].HasIntent  | Should -BeTrue
        $entries[0].HasOutcome | Should -BeFalse
        $entries[0].Result     | Should -Be 'OutcomeUnknown'
        $entries[0].Plan       | Should -Not -BeNullOrEmpty -Because 'the rollback material has to be there before the attempt, or it is not a net'
    }

    It 'keeps the rollback material on the intent, before anything is attempted' {
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $id = Write-OptimizerAction -Plan $plan -Path $path
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        ConvertTo-Canonical $entry.RollbackData | Should -BeExactly (ConvertTo-Canonical $plan.RollbackData)
    }

    It 'shows OutcomeUnknown alongside actions that did finish' {
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $done   = Write-OptimizerAction -Plan $plan -Path $path
        $null   = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $done -Result Succeeded -Path $path
        $unknown = Write-OptimizerAction -Plan $plan -Path $path

        $entries = @(Get-OptimizerActionLog -Path $path)
        $entries.Count | Should -Be 2
        (@($entries | Where-Object { $_.ActionId -eq $done })[0]).Result    | Should -Be 'Succeeded'
        (@($entries | Where-Object { $_.ActionId -eq $unknown })[0]).Result | Should -Be 'OutcomeUnknown'
    }

    It 'reads an Outcome that arrived without its Intent rather than dropping it' {
        # The other half of the same rule: a record that cannot be joined to an
        # Intent is still history.
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $orphan = [guid]::NewGuid().ToString()
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $orphan -Result Failed -ErrorText 'no intent' -Path $path

        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $orphan)[0]
        $entry.HasIntent | Should -BeFalse
        $entry.Result    | Should -Be 'Failed'
        $entry.Category  | Should -Be $plan.Category
    }
}

Describe 'A malformed line is surfaced, counted and never dropped' {

    BeforeAll {
        $script:BadPath = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $script:GoodId = Write-OptimizerAction -Plan $plan -Path $script:BadPath
        [System.IO.File]::AppendAllText($script:BadPath, '{"ActionId":"half-a-line",' + [Environment]::NewLine)
        [System.IO.File]::AppendAllText($script:BadPath, 'not json at all' + [Environment]::NewLine)
        # Parses as JSON, but carries no ActionId, so it cannot be joined to
        # anything -- which is a parse error in every sense that matters.
        [System.IO.File]::AppendAllText($script:BadPath, '{"RecordKind":"Intent"}' + [Environment]::NewLine)
        $script:GoodId2 = Write-OptimizerAction -Plan $plan -Path $script:BadPath
        $script:BadRead = @(Get-OptimizerActionLog -Path $script:BadPath -WarningAction SilentlyContinue)
    }

    It 'does not stop the read' {
        @($script:BadRead | Where-Object { -not $_.IsParseError }).Count | Should -Be 2
    }

    It 'surfaces every unreadable line as its own entry' {
        @($script:BadRead | Where-Object { $_.IsParseError }).Count | Should -Be 3
    }

    It 'carries the line number, the error and the raw text on each one' {
        foreach ($bad in @($script:BadRead | Where-Object { $_.IsParseError })) {
            $bad.LineNumber | Should -BeGreaterThan 0
            $bad.ParseError | Should -Not -BeNullOrEmpty
            $bad.RawLine    | Should -Not -BeNullOrEmpty
            $bad.Result     | Should -Be 'ParseError'
            $bad.LedgerPath | Should -Be $script:BadPath
        }
    }

    It 'warns rather than failing silently' {
        $warnings = @()
        $null = Get-OptimizerActionLog -Path $script:BadPath -WarningVariable warnings -WarningAction SilentlyContinue
        @($warnings).Count | Should -BeGreaterThan 0
        ($warnings -join ' ') | Should -Match '3'
    }

    It 'puts parse errors first, so a caller that takes the first few still sees them' {
        $script:BadRead[0].IsParseError | Should -BeTrue
    }

    It 'does not filter parse errors out with -ActionId or -Category' {
        # The line you filtered for is exactly the one that might be unreadable.
        $filtered = @(Get-OptimizerActionLog -Path $script:BadPath -ActionId $script:GoodId -WarningAction SilentlyContinue)
        @($filtered | Where-Object { $_.IsParseError }).Count | Should -Be 3
        @($filtered | Where-Object { -not $_.IsParseError }).Count | Should -Be 1

        $byCategory = @(Get-OptimizerActionLog -Path $script:BadPath -Category 'JunkFile' -WarningAction SilentlyContinue)
        @($byCategory | Where-Object { $_.IsParseError }).Count | Should -Be 3
        @($byCategory | Where-Object { -not $_.IsParseError }).Count | Should -Be 0
    }

    It 'counts them on the receipt, which says it may be incomplete' {
        $receipt = Get-OptimizerRunReceipt -Path $script:BadPath -WarningAction SilentlyContinue
        $receipt.ParseErrorCount | Should -Be 3
        ($receipt.ReceiptText -join ' ') | Should -Match 'could not be read'
    }

    It 'gives every entry every field, parse errors included' {
        # Everything downstream runs under Set-StrictMode -Version Latest, where a
        # missing property is a throw rather than a $null.
        $names = @($script:BadRead[0].PSObject.Properties.Name)
        $full  = @(($script:BadRead | Where-Object { -not $_.IsParseError })[0].PSObject.Properties.Name)
        foreach ($name in $full) { $names | Should -Contain $name }
    }
}

Describe 'RollbackData round-trips losslessly on every route' {

    It 'covers all seven routes in the contract' {
        foreach ($route in @($script:Contract.RouteIds)) {
            @($script:RouteFixture.Keys) | Should -Contain $route
        }
        @($script:RouteFixture.Keys).Count | Should -Be 7
    }

    It 'writes and reads back <_> byte-identically' -ForEach @(
        'AppxPackage', 'RegistryUninstallString', 'PackageManagement',
        'StartupApproved', 'ScheduledTask', 'ServiceStartupType', 'JunkFileSet'
    ) {
        # Capture first: $_ inside a Where-Object nested in a -ForEach block is
        # the pipeline element, not the -ForEach value. docs\REVIEW.md.
        $route   = $_
        $fixture = $script:RouteFixture[$route]
        $path    = New-LedgerPath

        $id    = Write-OptimizerAction -Plan $fixture.Plan -Path $path
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]

        ConvertTo-Canonical $entry.RollbackData | Should -BeExactly (ConvertTo-Canonical $fixture.Plan.RollbackData) `
            -Because "route $route was covered by $($fixture.Provenance) input"
    }

    It 'keeps the whole plan header, not just the rollback data' -ForEach @(
        'AppxPackage', 'RegistryUninstallString', 'PackageManagement',
        'StartupApproved', 'ScheduledTask', 'ServiceStartupType'
    ) {
        $route   = $_
        $fixture = $script:RouteFixture[$route]
        $path    = New-LedgerPath

        $id    = Write-OptimizerAction -Plan $fixture.Plan -Path $path
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        $plan  = $(if ($null -ne $entry.Plan) { $entry.Plan } else { $entry.Record[0].Plan })

        $plan.FindingId     | Should -Be $fixture.Plan.FindingId
        $plan.Route         | Should -Be $fixture.Plan.Route
        $plan.Supported     | Should -Be $fixture.Plan.Supported
        $plan.CurrentState  | Should -Be $fixture.Plan.CurrentState
        $plan.SafetyLabel   | Should -Be $fixture.Plan.SafetyLabel
        $plan.PreviewText   | Should -Not -BeNullOrEmpty
    }

    It 'keeps the REG_BINARY bytes on the StartupApproved route, as bytes and as hex' {
        $fixture = $script:RouteFixture['StartupApproved']
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $fixture.Plan -Path $path
        $back = (@(Get-OptimizerActionLog -Path $path -ActionId $id)[0]).RollbackData

        $original = $fixture.Plan.RollbackData
        $back.ApprovalKeyPath | Should -Be $original.ApprovalKeyPath
        $back.ValueName       | Should -Be $original.ValueName
        $back.ValueKind       | Should -Be 'Binary'
        $back.PreviousHex     | Should -BeExactly ([string] $original.PreviousHex)

        $expected = [int[]] @($original.PreviousByte)
        $actual   = [int[]] @($back.PreviousByte)
        $actual.Count | Should -Be $expected.Count
        for ($i = 0; $i -lt $expected.Count; $i++) {
            $actual[$i] | Should -Be $expected[$i] -Because "byte $i of the StartupApproved record must survive JSON exactly"
        }
        # The hex string is stored precisely so JSON cannot eat the bytes; it must
        # still agree with them after the round trip.
        (($actual | ForEach-Object { '{0:X2}' -f $_ }) -join '-') | Should -BeExactly ([string] $back.PreviousHex)
    }

    It 'keeps the task XML on the ScheduledTask route, character for character' {
        $fixture = $script:RouteFixture['ScheduledTask']
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $fixture.Plan -Path $path
        $back = (@(Get-OptimizerActionLog -Path $path -ActionId $id)[0]).RollbackData

        $expected = [string] $fixture.Plan.RollbackData.TaskXml
        $expected | Should -Not -BeNullOrEmpty
        ([string] $back.TaskXml) | Should -BeExactly $expected
        # It has to still be XML, not a string that merely looks like one.
        { [xml] ([string] $back.TaskXml) } | Should -Not -Throw
        $back.TaskPath   | Should -Be $fixture.Plan.RollbackData.TaskPath
        $back.WasEnabled | Should -Be $fixture.Plan.RollbackData.WasEnabled
        @($back.Trigger).Count | Should -Be @($fixture.Plan.RollbackData.Trigger).Count
    }

    It 'keeps the package family name, and no version is used as a key' {
        # Copilot reported 152.0.4191.42 and 2026.821.207.0 for the same package
        # at the same moment. The family name is the only safe join key.
        $fixture = $script:RouteFixture['AppxPackage']
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $fixture.Plan -Path $path
        $back = (@(Get-OptimizerActionLog -Path $path -ActionId $id)[0]).RollbackData
        $back.PackageFamilyName | Should -BeExactly ([string] $fixture.Plan.RollbackData.PackageFamilyName)
        $back.PackageFamilyName | Should -Not -BeNullOrEmpty
    }

    It 'keeps the key path and the captured values on the RegistryUninstallString route' {
        $fixture = $script:RouteFixture['RegistryUninstallString']
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $fixture.Plan -Path $path
        $back = (@(Get-OptimizerActionLog -Path $path -ActionId $id)[0]).RollbackData
        $back.KeyPath         | Should -BeExactly ([string] $fixture.Plan.RollbackData.KeyPath)
        $back.UninstallString | Should -BeExactly ([string] $fixture.Plan.RollbackData.UninstallString)
    }

    It 'keeps ServiceName, KeyPath and PreviousStartupType on the service route' {
        $fixture = $script:RouteFixture['ServiceStartupType']
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $fixture.Plan -Path $path
        $back = (@(Get-OptimizerActionLog -Path $path -ActionId $id)[0]).RollbackData
        $back.ServiceName         | Should -BeExactly ([string] $fixture.Plan.RollbackData.ServiceName)
        $back.KeyPath             | Should -BeExactly ([string] $fixture.Plan.RollbackData.KeyPath)
        $back.PreviousStartupType | Should -BeExactly ([string] $fixture.Plan.RollbackData.PreviousStartupType)
        $back.PreviousStartValue  | Should -Be $fixture.Plan.RollbackData.PreviousStartValue
    }

    It 'records that the PackageManagement route has no rollback material at all' {
        # Not a gap in this chunk: the route is a deliberate refusal (Q2, closed
        # 2026-08-27), so there is nothing to capture and the ledger says so by
        # recording the refusal instead of an intent.
        $fixture = $script:RouteFixture['PackageManagement']
        $fixture.Plan.Supported | Should -BeFalse
        $fixture.Plan.RollbackData | Should -BeNullOrEmpty

        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $fixture.Plan -Path $path
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        $entry.IsRefused | Should -BeTrue
        $entry.Result    | Should -Be 'Refused'
    }

    It 'keeps a plan that arrived as data, not from the dispatcher' {
        # A plan is data and must survive a round trip -- so one that came out of
        # a log rather than out of Get-RemovalPlan is written just the same.
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $deserialized = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $plan -Depth 24)
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $deserialized -Path $path
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        ConvertTo-Canonical $entry.RollbackData | Should -BeExactly (ConvertTo-Canonical $plan.RollbackData)
    }

    It 'keeps every timestamp as an ISO-8601 UTC string, never a shell-dependent datetime' {
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $script:RouteFixture['ServiceStartupType'].Plan -Path $path

        # Asserted against the TEXT ON DISK, not against ConvertFrom-Json's output.
        # JSON has no date type: ConvertFrom-Json recognises an ISO-8601 string and
        # hands back a [datetime], which then renders '08/28/2026 01:08:49' in the
        # reader's locale. The storage is what this test is about, and the storage
        # is a string.
        $line = @([System.IO.File]::ReadAllLines($path))[0]
        $line | Should -Match '"TimestampUtc":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z"'
        $line | Should -Match '"VerifiedUtc":"\d{4}-\d{2}-\d{2}T'

        # And the reader turns it back into a real UTC [datetime], so a caller can
        # sort and filter on it without parsing strings itself.
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        $entry.IntentUtc | Should -BeOfType ([datetime])
        $entry.IntentUtc.Kind | Should -Be ([System.DateTimeKind]::Utc)
    }

    It 'renders a plan read back out of the ledger identically to a fresh one' {
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $plan -Path $path
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        (@(Get-RemovalPreview -Plan $entry.Plan) -join "`n") | Should -BeExactly ((@(Get-RemovalPreview -Plan $plan)) -join "`n")
    }

    It 'carries no dictionary where a consumer will read properties' {
        # [ordered]@{} and [hashtable] serialise fine and are invisible to
        # PSObject.Properties, so a round-trip test passes while every consumer
        # reads nothing. docs\REVIEW.md, after P3-C1.
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $script:RouteFixture['JunkFileSet'].Plan -Path $path
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        foreach ($candidate in @($entry.RollbackData, $entry.ManifestRef, $entry.Plan)) {
            $candidate | Should -Not -BeOfType ([hashtable])
            @($candidate.PSObject.Properties.Name).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'The junk manifest is a sidecar, not a ledger line' {

    BeforeAll {
        $script:ManifestLedger = New-LedgerPath
        $script:ManifestFinding = New-TestJunkFinding -FileCount 40 -Id 'manifest-sidecar'
        $script:ManifestPlan = Get-RemovalPlan -Finding $script:ManifestFinding
        $script:ManifestActionId = Write-OptimizerAction -Plan $script:ManifestPlan -Path $script:ManifestLedger
        $script:ManifestEntry = @(Get-OptimizerActionLog -Path $script:ManifestLedger -ActionId $script:ManifestActionId)[0]
        $script:ManifestLine = @([System.IO.File]::ReadAllLines($script:ManifestLedger))[0]
    }

    It 'keeps the file list off the ledger line' {
        @($script:ManifestPlan.Step[0].Detail.File).Count | Should -Be 40

        # The step's own File array is gone from the line entirely.
        $script:ManifestLine | Should -Not -Match '"File":\['
        $onLine = ConvertFrom-Json -InputObject $script:ManifestLine
        @($onLine.Plan.Step[0].Detail.PSObject.Properties.Name) | Should -Not -Contain 'File'

        # What IS on the line is the preview's three-path sample, which is bounded
        # and is the text a human read before approving. Everything past it is in
        # the sidecar: files 4 through 40 appear nowhere on the line.
        $sample = [string[]] @($script:ManifestPlan.Step[0].Detail.SamplePath)
        $sample.Count | Should -Be 3
        foreach ($file in @($script:ManifestPlan.Step[0].Detail.File)) {
            if ($sample -contains $file.Path) { continue }
            $script:ManifestLine.IndexOf($file.Path, [System.StringComparison]::OrdinalIgnoreCase) |
                Should -Be -1 -Because "'$($file.Path)' belongs in the sidecar, not on the ledger line"
        }
    }

    It 'keeps the counts, the byte total and a reference on the line' {
        $script:ManifestEntry.ManifestRef                | Should -Not -BeNullOrEmpty
        $script:ManifestEntry.ManifestRef.RecordCount    | Should -Be 40
        $script:ManifestEntry.ManifestRef.TotalBytes     | Should -Be $script:ManifestPlan.RollbackData.TotalBytes
        $script:ManifestEntry.SizeBeforeBytes            | Should -Be $script:ManifestPlan.RollbackData.TotalBytes
        $step = @($script:ManifestEntry.Plan.Step)[0]
        $step.Detail.FileCount  | Should -Be 40
        $step.Detail.FileOnLine | Should -BeFalse
    }

    It 'writes the sidecar beside the ledger, named from the ActionId' {
        $sidecar = Join-Path (Join-Path (Split-Path -Path $script:ManifestLedger -Parent) 'action-manifests') $script:ManifestEntry.ManifestRef.FileName
        Test-Path -LiteralPath $sidecar | Should -BeTrue
        $script:ManifestEntry.ManifestRef.FileName | Should -Match ([regex]::Escape($script:ManifestActionId))
        @([System.IO.File]::ReadAllLines($sidecar)).Count | Should -Be 40
    }

    It 'does not read the sidecar when listing history' {
        $script:ManifestEntry.Manifest | Should -BeNullOrEmpty
    }

    It 'reads it only when asked, and then every record is there' {
        $withManifest = @(Get-OptimizerActionLog -Path $script:ManifestLedger -ActionId $script:ManifestActionId -IncludeManifest)[0]
        @($withManifest.Manifest).Count | Should -Be 40
        $withManifest.ManifestError | Should -BeNullOrEmpty
        foreach ($record in @($withManifest.Manifest)) {
            $record.Path      | Should -Not -BeNullOrEmpty
            $record.SizeBytes | Should -Be 64
        }
    }

    It 'keeps every path in the manifest, in plan order' {
        $withManifest = @(Get-OptimizerActionLog -Path $script:ManifestLedger -ActionId $script:ManifestActionId -IncludeManifest)[0]
        $expected = [string[]] @($script:ManifestPlan.Step[0].Detail.File | ForEach-Object { $_.Path })
        $actual   = [string[]] @($withManifest.Manifest | ForEach-Object { $_.Path })
        $actual.Count | Should -Be $expected.Count
        for ($i = 0; $i -lt $expected.Count; $i++) { $actual[$i] | Should -BeExactly $expected[$i] }
    }

    It 'keeps the ledger line small however big the set is' {
        # The reason the sidecar exists: one Chrome plan was 14 MB of JSON inline.
        $big = Get-RemovalPlan -Finding (New-TestJunkFinding -FileCount 400 -Id 'manifest-big')
        $path = New-LedgerPath
        $null = Write-OptimizerAction -Plan $big -Path $path
        $line = @([System.IO.File]::ReadAllLines($path))[0]

        $inline = (ConvertTo-Json -InputObject $big -Depth 24 -Compress).Length
        $line.Length | Should -BeLessThan ($inline / 4) -Because "the line is $($line.Length) bytes against $inline inline"
        $line.Length | Should -BeLessThan 8192
    }

    It 'says so rather than throwing when the sidecar has gone' {
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan (Get-RemovalPlan -Finding (New-TestJunkFinding -FileCount 3 -Id 'manifest-lost')) -Path $path
        $folder = Join-Path (Split-Path -Path $path -Parent) 'action-manifests'
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        Remove-Item -LiteralPath (Join-Path $folder $entry.ManifestRef.FileName) -Force

        $again = @(Get-OptimizerActionLog -Path $path -ActionId $id -IncludeManifest)[0]
        $again.ManifestError | Should -Not -BeNullOrEmpty
        $again.ManifestRef.RecordCount | Should -Be 3 -Because 'the line still records how many files there were'
    }

    It 'writes no sidecar for a route that has no file set' {
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $script:RouteFixture['ServiceStartupType'].Plan -Path $path
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        $entry.ManifestRef | Should -BeNullOrEmpty
        Test-Path -LiteralPath (Join-Path (Split-Path -Path $path -Parent) 'action-manifests') | Should -BeTrue -Because 'the folder is shared with the other ledgers in this scratch directory'
    }
}

Describe 'Write-OptimizerAction refuses what it must not record' {

    It 'throws for something that is not a plan, and writes nothing' {
        $path = New-LedgerPath
        { Write-OptimizerAction -Plan ([pscustomobject]@{ Nope = $true }) -Path $path } | Should -Throw '*not a removal plan*'
        Test-Path -LiteralPath $path | Should -BeFalse
    }

    It 'throws for a null plan' {
        { Write-OptimizerAction -Plan $null -Path (New-LedgerPath) } | Should -Throw '*not a removal plan*'
    }

    It 'names every problem it found' {
        $broken = [pscustomobject]@{
            FindingId = 'x'; Category = 'NotACategory'; RemovalMethod = 'Appx'; DisplayName = 'x'
            Route = 'NotARoute'; Supported = 'true'; CurrentState = 'NotAState'; VerifiedUtc = 'x'
        }
        $message = $null
        try { Write-OptimizerAction -Plan $broken -Path (New-LedgerPath) } catch { $message = $_.Exception.Message }
        $message | Should -Match 'NotACategory'
        $message | Should -Match 'NotARoute'
        $message | Should -Match 'NotAState'
        $message | Should -Match 'Supported'
    }

    It 'refuses a Supported = $false plan with a Note that carries the reason, not a silent skip' {
        $path = New-LedgerPath
        $plan = $script:RouteFixture['PackageManagement'].Plan
        $id = Write-OptimizerAction -Plan $plan -Path $path
        $id | Should -Not -BeNullOrEmpty

        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        $entry.IsRefused   | Should -BeTrue
        $entry.Result      | Should -Be 'Refused'
        $entry.HasIntent   | Should -BeFalse
        $entry.RecordKind  | Should -Contain 'Note'
        @($entry.Note)[0].Data.UnsupportedReason | Should -BeExactly ([string] $plan.UnsupportedReason)
    }

    It 'still records the plan on a refusal, so the decision can be read back' {
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $script:RouteFixture['PackageManagement'].Plan -Path $path
        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        $entry.Plan | Should -Not -BeNullOrEmpty
        $entry.Plan.Supported | Should -BeFalse
    }

    It 'refuses an Outcome or a Note with no ActionId rather than orphaning it' {
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        { Write-OptimizerAction -Plan $plan -RecordKind Outcome -Result Succeeded -Path (New-LedgerPath) } | Should -Throw '*ActionId*'
        { Write-OptimizerAction -Plan $plan -RecordKind Note -Path (New-LedgerPath) } | Should -Throw '*ActionId*'
    }

    It 'requires a Result from the closed set on an Outcome' {
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $id = [guid]::NewGuid().ToString()
        { Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Path (New-LedgerPath) } | Should -Throw '*Result*'
        { Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result 'Nope' -Path (New-LedgerPath) } | Should -Throw '*Result*'
    }

    It 'accepts each of the four Outcome results' -ForEach @('Succeeded', 'Failed', 'Skipped', 'Partial') {
        $result = $_
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $id = Write-OptimizerAction -Plan $plan -Path $path
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result $result -Path $path
        (@(Get-OptimizerActionLog -Path $path -ActionId $id)[0]).Result | Should -Be $result
    }

    It 'refuses a Result on anything that is not an Outcome' {
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        { Write-OptimizerAction -Plan $plan -Result Succeeded -Path (New-LedgerPath) } | Should -Throw '*Outcome record*'
    }

    It 'throws rather than returning quietly when the ledger cannot be written' {
        # A caller that cannot record what it is about to do must not do it.
        $blocked = Join-Path $script:Scratch ('blocked-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $blocked -ItemType Directory -Force
        { Write-OptimizerAction -Plan $script:RouteFixture['ServiceStartupType'].Plan -Path $blocked } | Should -Throw
    }

    It 'returns the ActionId, and the same one for every record of that action' {
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $id = Write-OptimizerAction -Plan $plan -Path $path
        $id | Should -Match '^[0-9a-f]{8}-'
        $again = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result Succeeded -Path $path
        $again | Should -Be $id
        @(Get-OptimizerActionLog -Path $path).Count | Should -Be 1
    }

    It 'records the run id from the open run log without being told' {
        $path = New-LedgerPath
        $state = Start-OptimizerLog -Path (Join-Path $script:Scratch ('runlog-' + [guid]::NewGuid().ToString('N') + '.jsonl')) -PassThru
        try {
            $id = Write-OptimizerAction -Plan $script:RouteFixture['ServiceStartupType'].Plan -Path $path
            (@(Get-OptimizerActionLog -Path $path -ActionId $id)[0]).RunId | Should -Be $state.RunId
        }
        finally { $null = Stop-OptimizerLog }
    }

    It 'records who and what wrote the line' {
        $path = New-LedgerPath
        $null = Write-OptimizerAction -Plan $script:RouteFixture['ServiceStartupType'].Plan -Path $path
        $raw = ConvertFrom-Json -InputObject (@([System.IO.File]::ReadAllLines($path))[0])
        $raw.Host.MachineName       | Should -Be ([Environment]::MachineName)
        $raw.Host.UserName          | Should -Be ([Environment]::UserName)
        $raw.Host.IsElevated        | Should -Be ([bool](Test-IsElevated))
        $raw.Host.PowerShellVersion | Should -Be ($PSVersionTable.PSVersion.ToString())
    }
}

Describe 'Get-OptimizerActionLog: filtering, ordering and the schema version' {

    BeforeAll {
        $script:FilterLedger = New-LedgerPath
        $script:FilterIds = @{}
        foreach ($route in 'ServiceStartupType', 'JunkFileSet', 'AppxPackage') {
            $plan = $script:RouteFixture[$route].Plan
            $script:FilterIds[$route] = Write-OptimizerAction -Plan $plan -Path $script:FilterLedger
            Start-Sleep -Milliseconds 30
        }
    }

    It 'returns one object per action, not per record' {
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $null = Write-OptimizerAction -Plan $plan -RecordKind Note -ActionId $script:FilterIds['ServiceStartupType'] -Path $script:FilterLedger -Data ([pscustomobject]@{ What = 'a note' })
        @(Get-OptimizerActionLog -Path $script:FilterLedger).Count | Should -Be 3
        (@(Get-OptimizerActionLog -Path $script:FilterLedger -ActionId $script:FilterIds['ServiceStartupType'])[0]).RecordCount | Should -Be 2
    }

    It 'filters by ActionId' {
        $wanted = $script:FilterIds['JunkFileSet']
        $entries = @(Get-OptimizerActionLog -Path $script:FilterLedger -ActionId $wanted)
        $entries.Count | Should -Be 1
        $entries[0].ActionId | Should -Be $wanted
    }

    It 'filters by Category' {
        @(Get-OptimizerActionLog -Path $script:FilterLedger -Category 'JunkFile').Count    | Should -Be 1
        @(Get-OptimizerActionLog -Path $script:FilterLedger -Category 'Service').Count      | Should -Be 1
        @(Get-OptimizerActionLog -Path $script:FilterLedger -Category 'OemBloatware').Count | Should -Be 1
        @(Get-OptimizerActionLog -Path $script:FilterLedger -Category 'Service', 'JunkFile').Count | Should -Be 2
        @(Get-OptimizerActionLog -Path $script:FilterLedger -Category 'NoSuchCategory').Count | Should -Be 0
    }

    It 'filters by UTC date range, in both directions' {
        $all = @(Get-OptimizerActionLog -Path $script:FilterLedger)
        $all.Count | Should -Be 3

        @(Get-OptimizerActionLog -Path $script:FilterLedger -FromUtc ([datetime]::UtcNow.AddMinutes(5))).Count | Should -Be 0
        @(Get-OptimizerActionLog -Path $script:FilterLedger -ToUtc ([datetime]::UtcNow.AddMinutes(-5))).Count  | Should -Be 0
        @(Get-OptimizerActionLog -Path $script:FilterLedger -FromUtc ([datetime]::UtcNow.AddMinutes(-5)) -ToUtc ([datetime]::UtcNow.AddMinutes(5))).Count | Should -Be 3

        # Half-open on the newest record, so a supersede moves an action into a
        # window it was not in before -- which is what "current view" means.
        $middle = $all[1].LastRecordUtc
        @(Get-OptimizerActionLog -Path $script:FilterLedger -FromUtc $middle).Count | Should -BeGreaterOrEqual 2
    }

    It 'returns newest first' {
        $entries = @(Get-OptimizerActionLog -Path $script:FilterLedger)
        for ($i = 1; $i -lt $entries.Count; $i++) {
            $entries[$i - 1].LastRecordUtc | Should -BeGreaterOrEqual $entries[$i].LastRecordUtc
        }
    }

    It 'reports a schema version it does not know rather than reinterpreting the line' {
        $path = New-LedgerPath
        $id = Write-OptimizerAction -Plan $script:RouteFixture['ServiceStartupType'].Plan -Path $path
        $line = @([System.IO.File]::ReadAllLines($path))[0]
        $future = ConvertFrom-Json -InputObject $line
        $future.SchemaVersion = 99
        $future.ActionId = [guid]::NewGuid().ToString()
        [System.IO.File]::AppendAllText($path, (ConvertTo-Json -InputObject $future -Depth 24 -Compress) + [Environment]::NewLine)

        $entries = @(Get-OptimizerActionLog -Path $path -WarningAction SilentlyContinue)
        $entries.Count | Should -Be 2
        $known = @($entries | Where-Object { $_.ActionId -eq $id })[0]
        $known.IsSchemaVersionKnown | Should -BeTrue
        $known.SchemaVersion | Should -Be 1

        $unknown = @($entries | Where-Object { $_.ActionId -ne $id })[0]
        $unknown.IsSchemaVersionKnown | Should -BeFalse
        $unknown.SchemaVersion | Should -Be 99
        $unknown.Result | Should -Be 'OutcomeUnknown' -Because 'an unknown version is reported as-is, not discarded'
    }

    It 'throws with the path in the message when the ledger cannot be read at all' {
        $folder = Join-Path $script:Scratch ('unreadable-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $folder -ItemType Directory -Force
        { Get-OptimizerActionLog -Path $folder } | Should -Throw '*could not be read*'
    }
}

Describe 'Get-OptimizerRunReceipt: a receipt, not a benchmark' {

    BeforeAll {
        $script:ReceiptLedger = New-LedgerPath
        $script:ReceiptRunId  = 'run-' + [guid]::NewGuid().ToString('N')

        $junkPlan    = Get-RemovalPlan -Finding (New-TestJunkFinding -FileCount 10 -Bytes 1024 -Id 'receipt-junk')
        $servicePlan = $script:RouteFixture['ServiceStartupType'].Plan
        $refusedPlan = $script:RouteFixture['PackageManagement'].Plan

        $script:ReceiptJunkId = Write-OptimizerAction -Plan $junkPlan -Path $script:ReceiptLedger -RunId $script:ReceiptRunId
        $null = Write-OptimizerAction -Plan $junkPlan -RecordKind Outcome -ActionId $script:ReceiptJunkId -Result Succeeded -DurationSeconds 3.5 -Path $script:ReceiptLedger -RunId $script:ReceiptRunId

        $failedId = Write-OptimizerAction -Plan $servicePlan -Path $script:ReceiptLedger -RunId $script:ReceiptRunId
        $null = Write-OptimizerAction -Plan $servicePlan -RecordKind Outcome -ActionId $failedId -Result Failed -ErrorText 'access denied' -Path $script:ReceiptLedger -RunId $script:ReceiptRunId

        $script:ReceiptUnknownId = Write-OptimizerAction -Plan $servicePlan -Path $script:ReceiptLedger -RunId $script:ReceiptRunId
        $null = Write-OptimizerAction -Plan $refusedPlan -Path $script:ReceiptLedger -RunId $script:ReceiptRunId

        # A second run, so the RunId filter has something to exclude.
        $null = Write-OptimizerAction -Plan $servicePlan -Path $script:ReceiptLedger -RunId 'some-other-run'

        $script:Receipt = Get-OptimizerRunReceipt -Path $script:ReceiptLedger -RunId $script:ReceiptRunId
        $script:ReceiptText = ($script:Receipt.ReceiptText -join "`n")
        $script:JunkPlan = $junkPlan
    }

    It 'is derived from the ledger alone' {
        $script:Receipt.LedgerPath | Should -Be $script:ReceiptLedger
        $script:Receipt.ActionCount | Should -Be 4
    }

    It 'counts each result separately' {
        $script:Receipt.SucceededCount      | Should -Be 1
        $script:Receipt.FailedCount         | Should -Be 1
        $script:Receipt.RefusedCount        | Should -Be 1
        $script:Receipt.OutcomeUnknownCount | Should -Be 1
    }

    It 'sums bytes from SizeBeforeBytes, over completed actions only' {
        $script:Receipt.SizeBeforeBytes | Should -Be $script:JunkPlan.RollbackData.TotalBytes
        $script:Receipt.SizeBeforeBytes | Should -Be 10240
    }

    It 'counts an action with no size measurement separately rather than as zero' {
        # Zero is a measurement; absent is not. Adding the two together is how a
        # receipt starts lying.
        $script:Receipt.UnmeasuredCount | Should -Be 0 -Because 'only the junk action completed, and it carries a size'
        $script:Receipt.MeasuredCount   | Should -Be 1
        $everything = Get-OptimizerRunReceipt -Path $script:ReceiptLedger
        $everything.ActionCount | Should -Be 5
    }

    It 'says "not measured", never "0 bytes", when nothing that completed carried a size' {
        # Caught by the P3-C2 machine survey: every action that completed happened
        # to be on a route that records no size, and the receipt headline read
        # "0 bytes" -- a figure that looks like a measurement and is not one.
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $id = Write-OptimizerAction -Plan $plan -Path $path
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result Succeeded -Path $path

        $receipt = Get-OptimizerRunReceipt -Path $path
        $receipt.MeasuredCount   | Should -Be 0
        $receipt.UnmeasuredCount | Should -Be 1

        $text = ($receipt.ReceiptText -join "`n")
        $text | Should -Match 'not measured'
        $text | Should -Not -Match '0 bytes'
        $text | Should -Match 'no total to give'

        # And the category line does not say it either.
        @($receipt.Category)[0].MeasuredCount  | Should -Be 0
        @($receipt.Category)[0].SizeBeforeText | Should -Be 'no size measured'
        $text | Should -Match 'no size measured'
    }

    It 'gives a real figure as soon as one completed action carries a size' {
        $path = New-LedgerPath
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -FileCount 4 -Bytes 512 -Id 'receipt-measured')
        $id = Write-OptimizerAction -Plan $plan -Path $path
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result Succeeded -Path $path

        $receipt = Get-OptimizerRunReceipt -Path $path
        $receipt.MeasuredCount  | Should -Be 1
        $receipt.SizeBeforeBytes | Should -Be 2048
        ($receipt.ReceiptText -join "`n") | Should -Not -Match 'not measured'
        ($receipt.ReceiptText -join "`n") | Should -Match 'Measured before each action'
    }

    It 'says nothing completed rather than 0 bytes when only intents were recorded' {
        $path = New-LedgerPath
        $null = Write-OptimizerAction -Plan $script:RouteFixture['ServiceStartupType'].Plan -Path $path
        $receipt = Get-OptimizerRunReceipt -Path $path
        $receipt.ActionCount   | Should -Be 1
        $receipt.MeasuredCount | Should -Be 0
        ($receipt.ReceiptText -join "`n") | Should -Match 'Nothing completed, so there is nothing to measure'
    }

    It 'breaks the counts down per category' {
        $junk = @($script:Receipt.Category | Where-Object { $_.Category -eq 'JunkFile' })[0]
        $junk.ActionCount     | Should -Be 1
        $junk.SucceededCount  | Should -Be 1
        $junk.SizeBeforeBytes | Should -Be 10240

        $service = @($script:Receipt.Category | Where-Object { $_.Category -eq 'Service' })[0]
        $service.ActionCount         | Should -Be 2
        $service.FailedCount         | Should -Be 1
        $service.OutcomeUnknownCount | Should -Be 1
        $service.SizeBeforeBytes     | Should -Be 0
        $service.MeasuredCount       | Should -Be 0
        $service.SizeBeforeText      | Should -Be 'no size measured'
    }

    It 'filters by run id' {
        $script:Receipt.RunId | Should -Be $script:ReceiptRunId
        @($script:Receipt.Item | Where-Object { $_.ActionId -eq $script:ReceiptUnknownId }).Count | Should -Be 1
        $other = Get-OptimizerRunReceipt -Path $script:ReceiptLedger -RunId 'some-other-run'
        $other.ActionCount | Should -Be 1
    }

    It 'lists an item per action, with what was acted on' {
        @($script:Receipt.Item).Count | Should -Be 4
        foreach ($item in @($script:Receipt.Item)) {
            $item.ActionId    | Should -Not -BeNullOrEmpty
            $item.Category    | Should -Not -BeNullOrEmpty
            $item.DisplayName | Should -Not -BeNullOrEmpty
            $item.Result      | Should -Not -BeNullOrEmpty
        }
    }

    It 'shows the actions whose outcome was never recorded, and says what that means' {
        $script:ReceiptText | Should -Match 'outcome unknown'
        $script:ReceiptText | Should -Match 'never recorded as finishing'
        $script:ReceiptText | Should -Match 'cannot say whether they happened'
    }

    It 'never says "<_>"' -ForEach $ForbiddenPhrase {
        # The same phrases the junk detector's evidence is already held to, from
        # tests\ForbiddenPhrase.ps1. This used to be a readable copy written out
        # by hand beside an extracted one; there is one list now, and this gives
        # a named failing test per phrase rather than one loop that stops at the
        # first.
        $phrase = $_
        $script:ReceiptText.IndexOf($phrase, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1
    }

    It 'never says anything on the extracted list either, and the list is not empty' {
        @($script:ForbiddenPhrase).Count | Should -BeGreaterOrEqual 10 -Because "ten phrases is the union tests\ForbiddenPhrase.ps1 ships; a shorter list means something silently stopped being enforced"
        $script:ForbiddenPhrase | Should -Contain 'free up'
        foreach ($phrase in $script:ForbiddenPhrase) {
            $script:ReceiptText.IndexOf($phrase, [System.StringComparison]::OrdinalIgnoreCase) |
                Should -Be -1 -Because "the receipt must not say '$phrase'"
        }
    }

    It 'says in words that it is not a benchmark' {
        $script:ReceiptText | Should -Match 'not a benchmark'
        $script:ReceiptText | Should -Match 'makes no claim about how this PC performs'
    }

    It 'makes no boot-time, memory or speed claim of any kind' -ForEach @(
        'boot', 'startup time', 'memory', 'RAM', 'faster', 'performance improve', 'seconds saved'
    ) {
        $phrase = $_
        $script:ReceiptText.IndexOf($phrase, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1
    }

    It 'describes an empty selection as nothing recorded, not as a clean run' {
        $empty = Get-OptimizerRunReceipt -Path (New-LedgerPath)
        $empty.ActionCount | Should -Be 0
        ($empty.ReceiptText -join ' ') | Should -Match 'Nothing has been recorded'
        ($empty.ReceiptText -join ' ') | Should -Not -Match 'Completed'
    }

    It 'renders every line as text a person could read' {
        @($script:Receipt.ReceiptText).Count | Should -BeGreaterThan 5
        $script:Receipt.ReceiptText | Should -BeOfType ([string])
    }
}

Describe 'New-OptimizerRestorePoint: tri-state plus a reason, never a bare bool' {

    BeforeAll {
        $script:Checkpoint = New-OptimizerRestorePoint -Description 'win11-optimizer test suite'
    }

    It 'returns one of the four states and nothing else' {
        $script:Checkpoint.State | Should -BeIn @('Created', 'Throttled', 'Unavailable', 'Failed')
    }

    It 'is not a boolean' {
        $script:Checkpoint | Should -Not -BeOfType ([bool])
        $script:Checkpoint.State | Should -BeOfType ([string])
    }

    It 'carries a reason on every state except Created' {
        if ($script:Checkpoint.State -eq 'Created') {
            $script:Checkpoint.CreatedUtc | Should -Not -BeNullOrEmpty
        }
        else {
            $script:Checkpoint.Reason | Should -Not -BeNullOrEmpty
            ([string] $script:Checkpoint.Reason).Length | Should -BeGreaterThan 20
        }
    }

    It 'holds a genuinely absent reason as $null, never as an empty string' {
        # $Reason = $null on a [string]-constrained variable becomes '', and ''
        # reads as "there was a reason and it was blank". docs\REVIEW.md.
        $result = InModuleScope Win11Optimizer.Engine {
            New-OptimizerRestorePointResult -State 'Created' -Reason $null
        }
        $null -eq $result.Reason | Should -BeTrue
        $result.Reason | Should -Not -Be ''
    }

    It 'never throws, whatever the machine is like' {
        { New-OptimizerRestorePoint } | Should -Not -Throw
        { New-OptimizerRestorePoint -RestorePointType APPLICATION_UNINSTALL } | Should -Not -Throw
    }

    It 'reports not being elevated as Unavailable with a reason, never as Failed' {
        if (Test-IsElevated) {
            $script:Checkpoint.IsElevated | Should -BeTrue
        }
        else {
            $script:Checkpoint.State  | Should -Be 'Unavailable'
            $script:Checkpoint.Reason | Should -Match 'administrator'
            $script:Checkpoint.IsElevated | Should -BeFalse
        }
    }

    It 'treats System Protection being switched off as Unavailable, not Failed' {
        # The normal state on a great many machines. Asserted against the branch
        # itself so the claim holds on hardware where it is switched on.
        $result = InModuleScope Win11Optimizer.Engine {
            Mock Test-IsElevated { $true }
            Mock Test-OptimizerSystemProtectionEnabled { $false }
            New-OptimizerRestorePoint
        }
        $result.State  | Should -Be 'Unavailable'
        $result.Reason | Should -Match 'System Protection'
        $result.Reason | Should -Match 'not a fault'
        $result.Reason | Should -Match 'action log'
    }

    It 'detects the 24-hour throttle rather than believing the return value' {
        # Windows accepts the call and reports SUCCESS when it declines inside its
        # own window, so nothing may be concluded from the exit status.
        $result = InModuleScope Win11Optimizer.Engine {
            Mock Test-IsElevated { $true }
            Mock Test-OptimizerSystemProtectionEnabled { $true }
            Mock Get-OptimizerSystemRestoreValue { $null }
            Mock Get-OptimizerRestorePointInventory {
                , [psobject[]] @([pscustomobject]@{ SequenceNumber = 42; Description = 'earlier'; CreatedUtc = [datetime]::UtcNow.AddHours(-2) })
            }
            Mock Checkpoint-Computer { throw 'Checkpoint-Computer must not be called inside the frequency window.' }
            New-OptimizerRestorePoint
        }
        $result.State           | Should -Be 'Throttled'
        $result.ThrottleMinutes | Should -Be 1440
        $result.Reason          | Should -Match 'Nothing was attempted'
        $result.MinutesSinceLast | Should -BeGreaterThan 100
    }

    It 'calls a checkpoint that returned cleanly and created nothing Throttled, not Created' {
        $result = InModuleScope Win11Optimizer.Engine {
            Mock Test-IsElevated { $true }
            Mock Test-OptimizerSystemProtectionEnabled { $true }
            Mock Get-OptimizerSystemRestoreValue { $null }
            Mock Get-OptimizerRestorePointInventory { , [psobject[]] @() }
            Mock Checkpoint-Computer { }
            New-OptimizerRestorePoint
        }
        $result.State  | Should -Be 'Throttled'
        $result.Reason | Should -Match 'reported no error and created no restore point'
    }

    It 'confirms a Created by looking, not by the call returning' {
        $result = InModuleScope Win11Optimizer.Engine {
            $script:CheckpointCallCount = 0
            Mock Test-IsElevated { $true }
            Mock Test-OptimizerSystemProtectionEnabled { $true }
            Mock Get-OptimizerSystemRestoreValue { $null }
            Mock Checkpoint-Computer { $script:CheckpointCallCount++ }
            Mock Get-OptimizerRestorePointInventory {
                if ($script:CheckpointCallCount -lt 1) { return , [psobject[]] @() }
                , [psobject[]] @([pscustomobject]@{ SequenceNumber = 7; Description = 'win11-optimizer'; CreatedUtc = [datetime]::UtcNow })
            }
            New-OptimizerRestorePoint
        }
        $result.State          | Should -Be 'Created'
        $result.SequenceNumber | Should -Be 7
        $result.CreatedUtc     | Should -Not -BeNullOrEmpty
        $null -eq $result.Reason | Should -BeTrue
    }

    It 'reports an error from Windows as Failed, with the message' {
        $result = InModuleScope Win11Optimizer.Engine {
            Mock Test-IsElevated { $true }
            Mock Test-OptimizerSystemProtectionEnabled { $true }
            Mock Get-OptimizerSystemRestoreValue { $null }
            Mock Get-OptimizerRestorePointInventory { , [psobject[]] @() }
            Mock Checkpoint-Computer { throw 'the volume shadow copy service is not running' }
            New-OptimizerRestorePoint
        }
        $result.State  | Should -Be 'Failed'
        $result.Reason | Should -Match 'volume shadow copy'
    }

    It 'says unknown rather than created when the restore points cannot be listed afterwards' {
        $result = InModuleScope Win11Optimizer.Engine {
            Mock Test-IsElevated { $true }
            Mock Test-OptimizerSystemProtectionEnabled { $true }
            Mock Get-OptimizerSystemRestoreValue { $null }
            Mock Get-OptimizerRestorePointInventory { $null }
            Mock Checkpoint-Computer { }
            New-OptimizerRestorePoint
        }
        $result.State  | Should -Be 'Unavailable'
        $result.Reason | Should -Match 'not one it may rely on'
    }

    It 'never collapses "could not tell" into "switched off"' {
        # Test-OptimizerSystemProtectionEnabled is tri-state, and $null means the
        # registry could not be read, never that protection is off.
        $answer = InModuleScope Win11Optimizer.Engine {
            Mock Get-OptimizerSystemRestoreValue { $null }
            Test-OptimizerSystemProtectionEnabled
        }
        $null -eq $answer | Should -BeTrue
    }

    It 'gives every field on every result, whatever the state' {
        $expected = @('State', 'Reason', 'SequenceNumber', 'CreatedUtc', 'PreviousRestorePointUtc',
                      'ThrottleMinutes', 'MinutesSinceLast', 'IsElevated', 'DurationSeconds',
                      'RestorePointCountBefore', 'RestorePointCountAfter', 'CheckedUtc')
        $names = @($script:Checkpoint.PSObject.Properties.Name)
        foreach ($name in $expected) { $names | Should -Contain $name }
    }

    It 'goes onto the ledger as a Note and does not fail the action' {
        $path = New-LedgerPath
        $plan = $script:RouteFixture['ServiceStartupType'].Plan
        $id = Write-OptimizerAction -Plan $plan -Path $path
        $null = Write-OptimizerAction -Plan $plan -RecordKind Note -ActionId $id -Path $path -Data $script:Checkpoint
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $id -Result Succeeded -Path $path

        $entry = @(Get-OptimizerActionLog -Path $path -ActionId $id)[0]
        $entry.Result | Should -Be 'Succeeded' -Because 'whatever the checkpoint says, the ledger is the net'
        @($entry.Note).Count | Should -Be 1
        @($entry.Note)[0].Data.State | Should -Be $script:Checkpoint.State
    }
}

Describe 'Two writers do not interleave a partial line' {

    It 'keeps every line whole when several processes append at once' {
        $path = New-LedgerPath
        $writers = 3
        $perWriter = 20

        $processes = @()
        foreach ($writer in 1..$writers) {
            $child = New-ChildScript -Body @"
`$plan = Get-RemovalPlan -Finding (New-Finding -Category Service -Id 'ConcurrentWriter$writer' ``
    -DisplayName 'Concurrent writer $writer' -Evidence 'test' -Confidence Known -RemovalMethod ServiceDisable)
foreach (`$i in 1..$perWriter) { `$null = Write-OptimizerAction -Plan `$plan -Path '$path' }
"@
            $processes += Start-Process -FilePath $script:ShellPath -ArgumentList @('-NoProfile', '-File', $child) -PassThru -WindowStyle Hidden
        }
        foreach ($process in $processes) { $null = $process.WaitForExit(180000) }

        $lines = @([System.IO.File]::ReadAllLines($path) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $lines.Count | Should -Be ($writers * $perWriter) -Because 'no writer may lose a line and none may write half of one'

        # Every line parses: a partial line is a parse error, and there are none.
        $entries = @(Get-OptimizerActionLog -Path $path)
        @($entries | Where-Object { $_.IsParseError }).Count | Should -Be 0
        $entries.Count | Should -Be ($writers * $perWriter)

        # And every action is distinct, so nothing was overwritten either.
        @($entries | ForEach-Object { $_.ActionId } | Sort-Object -Unique).Count | Should -Be ($writers * $perWriter)
    }
}

Describe 'The five new functions, and only those five' {

    It 'exports <_> from both the .psm1 and the .psd1' -ForEach @(
        'Get-OptimizerActionLogPath', 'Write-OptimizerAction', 'Get-OptimizerActionLog',
        'Get-OptimizerRunReceipt', 'New-OptimizerRestorePoint'
    ) {
        # A function missing from the .psd1 is invisible to callers with no error
        # anywhere -- this project's signature failure, in a manifest.
        $name = $_
        [System.IO.File]::ReadAllText($script:ModulePath)   | Should -Match ([regex]::Escape("'$name'"))
        [System.IO.File]::ReadAllText($script:ManifestPath) | Should -Match ([regex]::Escape("'$name'"))
        Get-Command -Module Win11Optimizer.Engine -Name $name -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'adds exactly five, and no more' {
        $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
        $exported = @(Get-Command -Module Win11Optimizer.Engine | ForEach-Object { $_.Name })
        @($manifest.FunctionsToExport).Count | Should -Be $exported.Count
        # THE RUNNING TOTAL IS READ FROM THE .psd1, NOT WRITTEN HERE. It was 29
        # before this chunk (P3-C1a's report, section 13), 34 after it, 36 when
        # P3-C3 added its two, 41 when P4-C1 added the review screen's five and
        # 43 when P4-C2 added its two -- a number that moves every chunk and that
        # two separate test files were each hand-editing to keep up. The claim
        # this It actually makes -- that THIS chunk added exactly five -- is the
        # line below it, and that one does not move.
        $exported.Count | Should -Be @($manifest.FunctionsToExport).Count
        @($exported | Where-Object { $script:NewExport -contains $_ }).Count | Should -Be 5
    }

    It 'defines every name it exports' {
        $undefined = @($script:NewExport | Where-Object { -not (Get-Command -Module Win11Optimizer.Engine -Name $_ -ErrorAction SilentlyContinue) })
        $undefined.Count | Should -Be 0 -Because "undefined: $($undefined -join ', ')"
    }

    It 'imports in a fresh session with nothing undefined' {
        $child = New-ChildScript -Body @"
`$module = Get-Module Win11Optimizer.Engine
`$declared = (Import-PowerShellDataFile -LiteralPath '$($script:ManifestPath)').FunctionsToExport
`$missing = @(`$declared | Where-Object { -not `$module.ExportedFunctions.ContainsKey(`$_) })
Write-Output "exported=`$(`$module.ExportedFunctions.Count) undefined=`$(@(`$missing).Count)"
"@
        $output = (& $script:ShellPath -NoProfile -File $child) -join ' '
        # Derived from the .psd1 for the same reason as the total above: it moves
        # with every chunk that adds an export. The assertion that matters here
        # is undefined=0 -- a name in FunctionsToExport with no function behind it
        # is invisible to callers with no error anywhere.
        $declared = @((Import-PowerShellDataFile -LiteralPath $script:ManifestPath).FunctionsToExport).Count
        $output | Should -Match "exported=$declared"
        $output | Should -Match 'undefined=0'
    }
}
