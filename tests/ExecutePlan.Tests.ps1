#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for chunk P4-C2 -- execution, the plan preview, and the three fixes
    carried over from P4-C1.

      Part A  the disambiguating FindingId column (Review\Screen.ps1), the
              reworded confirmation, and the export totals two other test files
              were hand-editing every chunk.

      Part B  New-OptimizerExecutionPlan and Invoke-OptimizerExecutionPlan
              (Review\Execute.ps1) -- picks to plans, and a confirmed set of
              plans to the executor.

    THE FIRST DESCRIBE IS THE ONE THAT MATTERS MOST, and it is a positive
    allowlist rather than the blanket "this file changes nothing" the screen
    could assert: Execute.ps1 is allowed to change the machine, and its whole
    write surface is two calls -- Invoke-RemovalPlan and Undo-RemovalAction. It
    writes no registry value of its own, starts no process, touches no file, and
    -- the one that is easy to get wrong -- does not write the ledger, because
    the ordering that makes an action safe belongs to the function that performs
    it and must not be reimplemented one layer up.

    After that the suite is about the claim the chunk is accepted on: ALL OF THEM
    OR NONE OF THEM. That claim is achievable in full only up to the first write,
    so it is tested in two halves:

      * the pre-flight refuses the whole run before anything is attempted, and
        the ledger FILE DOES NOT EXIST afterwards -- the strongest form of
        "nothing was written" this project can assert;
      * a failure after that stops the run and puts back what was already done,
        and the ledger says both things happened, because an undo is a new action
        and nothing here ever rewrites a line.

    NOTHING IN THIS FILE WRITES TO THE REGISTRY. Every fabricated plan names a
    service that does not exist on this or any machine, and the one write is
    mocked -- so a gate that ever failed open would meet a key that is not there
    and be refused by the write path itself.

    MOCK BODIES READ $script: VARIABLES AND ARE NEVER CLOSURES. Measured while
    writing this file: .GetNewClosure() on a Mock body stops Pester binding the
    mocked function's parameters, so $KeyPath arrives $null and the failure reads
    "You cannot call a method on a null-valued expression" a long way from the
    cause. The scenario helper therefore parks its inputs on the module's own
    script scope, which the mock bodies read.

    Run:  .\tests\Invoke-Tests.ps1        (and -On51, which is not optional)
#>

BeforeAll {
    $script:RepoRoot      = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot    = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath  = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath    = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:SourcePath    = Join-Path $script:EngineRoot 'Review\Execute.ps1'
    $script:ScreenSource  = Join-Path $script:EngineRoot 'Review\Screen.ps1'

    # A log root of our own. The repo's real ledger is the one file in this
    # project that is never rotated, and nothing in this suite may write to it.
    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-exec2-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-exec2-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    $script:Contract = Get-RemovalContract
    $script:NewExport = @('New-OptimizerExecutionPlan', 'Invoke-OptimizerExecutionPlan')

    # ---- the source, comment-blanked, and the AST --------------------------
    #
    # Same machinery as tests\Executor.Tests.ps1 and tests\ReviewScreen.Tests.ps1.
    # Repeated rather than shared for the reason those files give: a
    # source-scanning assertion that lives somewhere else is one refactor away
    # from scanning nothing, and this is the assertion the chunk rests on.
    $script:Raw = [System.IO.File]::ReadAllText($script:SourcePath)
    $script:Tokens = $null
    $script:Errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:SourcePath, [ref] $script:Tokens, [ref] $script:Errors)

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
    $script:Code = $builder.ToString()

    $script:Invoked = [string[]] @(
        $script:Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object {
            $element = $_.CommandElements[0]
            if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $element.Value } else { "<dynamic:$($element.Extent.Text)>" }
        } | Sort-Object -Unique
    )

    # ---- the forbidden benefit-claim phrases, READ OUT OF THE EXISTING TESTS -
    #
    # The same extractor tests\ReviewScreen.Tests.ps1 and tests\ActionLog.Tests.ps1
    # use: the lists live in the two suites that own them and are lifted out by
    # AST at run time, so anything added to either is picked up here without an
    # edit.
    function Get-ForbiddenPhraseFromSuite {
        param([Parameter(Mandatory)] [string] $Path)

        $tokens = $null
        $errors = $null
        $parsed = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors)

        $found = New-Object System.Collections.Generic.List[string]
        foreach ($array in @($parsed.FindAll({
            param($node) $node -is [System.Management.Automation.Language.ArrayLiteralAst]
        }, $true))) {
            $values = @($array.Elements | Where-Object { $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] } | ForEach-Object { $_.Value })
            if (@($values).Count -ne @($array.Elements).Count) { continue }
            if (@($values | Where-Object { $_ -eq 'free up' }).Count -lt 1) { continue }
            foreach ($value in $values) { $null = $found.Add($value) }
        }
        [string[]] @($found.ToArray() | Sort-Object -Unique)
    }

    $script:ForbiddenPhrase = [string[]] @(@(
        @(Get-ForbiddenPhraseFromSuite -Path (Join-Path $PSScriptRoot 'DispatcherJunkAmendment.Tests.ps1')) +
        @(Get-ForbiddenPhraseFromSuite -Path (Join-Path $PSScriptRoot 'RemovalDispatcher.Tests.ps1'))
    ) | Sort-Object -Unique)

    # ---- fixtures ----------------------------------------------------------

    $script:LedgerCounter = 0
    function New-LedgerPath {
        $script:LedgerCounter++
        Join-Path $script:Scratch ("ledger-{0:d3}-{1}.jsonl" -f $script:LedgerCounter, [guid]::NewGuid().ToString('N'))
    }

    # A service name nothing on this or any machine has.
    function New-AbsentServiceName {
        'w11o-absent-' + [guid]::NewGuid().ToString('N')
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
            -Evidence 'Fabricated by the test suite so this row can be rendered. It has a second sentence.' `
            -Confidence $Confidence -RequiresConsent:$RequiresConsent -RemovalMethod $RemovalMethod
    }

    # A scan result as data, not through New-ScanResult: the screen has to render
    # a scan that arrived deserialized from a log too.
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

    # A ServiceStartupType plan in the exact shape Add-RemovalServiceRoute
    # produces, for a service that does not exist.
    function New-FabricatedServicePlan {
        param(
            [string] $ServiceName = (New-AbsentServiceName),
            [int] $PreviousStartValue = 2,
            [int] $PlannedStartValue = 4,
            [string] $DisplayName = ''
        )
        $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $name = $(if ([string]::IsNullOrWhiteSpace($DisplayName)) { $ServiceName } else { $DisplayName })

        [pscustomobject]@{
            PSTypeName        = $script:Contract.TypeName
            FindingId         = $ServiceName
            Category          = 'Service'
            RemovalMethod     = 'ServiceDisable'
            DisplayName       = $name
            Confidence        = 'Known'
            Route             = 'ServiceStartupType'
            Supported         = $true
            UnsupportedReason = $null
            CurrentState      = 'Present'
            VerifiedUtc       = [datetime]::UtcNow.ToString('o')
            RequiresElevation = $true
            RequiresConsent   = $true
            SafetyLabel       = 'Review needed'
            IsReversible      = $true
            Step              = [psobject[]] @([pscustomobject]@{
                PSTypeName          = $script:Contract.StepTypeName
                Kind                = 'ServiceStartupTypeChange'
                Description         = 'Fabricated step.'
                Target              = $ServiceName
                Executable          = $null
                Argument            = $null
                RequiresElevation   = $true
                RequiresInteraction = $false
                ReverseHint         = 'Fabricated.'
                Detail              = [pscustomobject]@{
                    KeyPath             = $keyPath
                    PreviousStartValue  = $PreviousStartValue
                    PreviousStartupType = 'Automatic'
                    PlannedStartValue   = $PlannedStartValue
                    PlannedStartupType  = 'Disabled'
                }
            })
            RollbackData      = [pscustomobject]@{
                ServiceName              = $ServiceName
                DisplayName              = $name
                KeyPath                  = $keyPath
                PreviousStartValue       = $PreviousStartValue
                PreviousStartupType      = 'Automatic'
                PreviousDelayedAutostart = $false
                Note                     = 'Fabricated.'
            }
            Note              = [string[]] @()
            PreviewText       = [string[]] @('Fabricated preview.')
        }
    }

    function New-FabricatedAppxPlan {
        param([string] $DisplayName = 'Fabricated app')
        [pscustomobject]@{
            PSTypeName        = $script:Contract.TypeName
            FindingId         = 'Fabricated.App_8wekyb3d8bbwe'
            Category          = 'OemBloatware'
            RemovalMethod     = 'Appx'
            DisplayName       = $DisplayName
            Confidence        = 'Known'
            Route             = 'AppxPackage'
            Supported         = $true
            UnsupportedReason = $null
            CurrentState      = 'Present'
            VerifiedUtc       = [datetime]::UtcNow.ToString('o')
            RequiresElevation = $false
            RequiresConsent   = $true
            SafetyLabel       = 'Review needed'
            IsReversible      = $false
            Step              = [psobject[]] @()
            RollbackData      = $null
            Note              = [string[]] @()
            PreviewText       = [string[]] @('Fabricated preview.')
        }
    }

    # ---- the scenario driver -----------------------------------------------
    #
    # Everything the executor reads on its way to the one write, mocked, so a
    # fabricated plan for an absent service can be driven all the way through
    # without a registry key existing anywhere.
    #
    # The mock bodies read $script: variables parked on the MODULE's script scope
    # rather than closing over this function's locals -- see the header. Plans
    # are built outside and passed in, because a function defined in this file is
    # not visible inside InModuleScope.
    function Invoke-ExecutionScenario {
        param(
            [Parameter(Mandatory)] [string] $Ledger,
            [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Plan,
            [Parameter()] [hashtable] $LiveStart = @{},
            [Parameter()] [AllowEmptyCollection()] [string[]] $FailWriteFor = @(),
            [Parameter()] [AllowEmptyString()] [string] $RunId = '',
            [Parameter()] [bool] $Elevated = $true,
            [switch] $DryRun
        )

        InModuleScope Win11Optimizer.Engine -Parameters @{
            Ledger = $Ledger; Plan = $Plan; LiveStart = $LiveStart; FailWriteFor = $FailWriteFor
            RunId = $RunId; Elevated = $Elevated; DryRun = [bool] $DryRun
        } {
            param($Ledger, $Plan, $LiveStart, $FailWriteFor, $RunId, $Elevated, $DryRun)

            $script:ExecutorRestorePoint = $null
            $script:ScenarioLiveStart    = $LiveStart
            $script:ScenarioFailWrite    = [string[]] @($FailWriteFor)
            $script:ScenarioElevated     = [bool] $Elevated

            Mock Test-IsElevated { $script:ScenarioElevated }
            Mock Get-ExecutorPlanDisagreement { [string[]] @() }
            Mock Get-ExecutorServiceRunState { 'Stopped' }
            Mock New-OptimizerRestorePoint { [pscustomobject]@{ State = 'Throttled'; Reason = 'One already exists inside the frequency window.' } }

            Mock Get-ExecutorServiceRegistryState {
                $leaf = $KeyPath.Substring($KeyPath.LastIndexOf('\') + 1)
                [pscustomobject]@{
                    Exists         = $true
                    Start          = [int] $script:ScenarioLiveStart[$leaf]
                    StartPresent   = $true
                    Delayed        = $null
                    DelayedPresent = $false
                    Reason         = $null
                }
            }

            # Stands in for the one real write, which P3-C3 proved elevated
            # against a real service and pasted into its report.
            Mock Write-ExecutorServiceRegistryValue {
                $leaf = $KeyPath.Substring($KeyPath.LastIndexOf('\') + 1)
                if ($script:ScenarioFailWrite -contains $leaf) {
                    throw "The fabricated key for '$leaf' refuses this write."
                }
                [pscustomobject]@{
                    KeyPath              = $KeyPath
                    ValueName            = $Name
                    PreviousValue        = 2
                    PreviousValuePresent = $true
                    WrittenValue         = $Value
                    VerifiedValue        = $Value
                    IsVerified           = $true
                    WrittenUtc           = [datetime]::UtcNow.ToString('o')
                }
            }

            $written = New-Object System.Collections.Generic.List[string]
            $writer  = { param($Line) $null = $written.Add([string] $Line) }.GetNewClosure()

            $argument = @{ Plan = $Plan; LedgerPath = $Ledger; Writer = $writer; SkipRestorePoint = $true }
            if (-not [string]::IsNullOrWhiteSpace($RunId)) { $argument['RunId'] = $RunId }
            if ($DryRun) { $argument['WhatIf'] = $true } else { $argument['Confirm'] = $false }

            $run = Invoke-OptimizerExecutionPlan @argument
            [pscustomobject]@{ Run = $run; Written = [string[]] @($written.ToArray()) }
        }
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

Describe 'Execute.ps1 calls the executor and does nothing else that changes anything' {

    It 'parses cleanly' {
        @($script:Errors).Count | Should -Be 0
    }

    It 'is ASCII, in every file this chunk touches' {
        # One non-ASCII character in a comment fails a whole container under 5.1
        # only, and the error names a line in the test harness rather than the
        # character. docs\REVIEW.md, after P3-C1a.
        foreach ($path in @($script:SourcePath, $script:ScreenSource, $PSCommandPath, $script:ManifestPath, $script:ModulePath,
                            (Join-Path $PSScriptRoot 'ActionLog.Tests.ps1'), (Join-Path $PSScriptRoot 'Executor.Tests.ps1'))) {
            $text = [System.IO.File]::ReadAllText($path)
            $bad  = @([regex]::Matches($text, '[^\x20-\x7E\t\r\n]'))
            $bad.Count | Should -Be 0 -Because "$(Split-Path $path -Leaf) must be ASCII only"
        }
    }

    It 'invokes exactly two things that can change this PC' {
        # THE POSITIVE ALLOWLIST. Every other file outside Removal\ asserts "it
        # changes nothing"; this one is allowed to, through the executor, and the
        # claim is that it does it in two places and no others.
        $script:Invoked | Should -Contain 'Invoke-RemovalPlan'
        $script:Invoked | Should -Contain 'Undo-RemovalAction'

        foreach ($invoked in $script:Invoked) {
            $invoked | Should -Not -Match '\.(exe|com|bat|cmd|msi|dll|vbs|ps1)$' `
                -Because "it invoked '$invoked', which is a program and not a cmdlet"
            $invoked | Should -Not -Match '^(Remove|Disable|Unregister|Uninstall|Stop|Restart|Clear|Set)-' `
                -Because "it invoked '$invoked', which is a verb that changes something"
        }
    }

    It 'does not write the ledger itself' {
        # The ordering that makes an action safe -- the Intent flushed to disk
        # before the first write -- is a property of Invoke-RemovalPlan. A second
        # writer one layer up would be a second place for that ordering to be got
        # wrong, and the ledger would then carry records for actions nobody
        # attempted.
        $script:Invoked | Should -Not -Contain 'Write-OptimizerAction'
        $script:Invoked | Should -Not -Contain 'New-OptimizerRestorePoint'
        $script:Invoked | Should -Not -Contain 'Add-OptimizerActionLine'
    }

    It 'contains no <_>' -ForEach @(
        'Remove-', 'Disable-', 'Unregister-', 'Uninstall-',
        'Set-Service', 'Stop-Service', 'Start-Service', 'New-Service',
        'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Clear-Item',
        'Start-Process', 'Invoke-Expression', 'Invoke-Command', 'Invoke-Item', 'Start-Job',
        'Microsoft.Win32.Registry', 'Checkpoint-Computer',
        'Win32_Product', 'Get-WmiObject', 'Get-CimInstance', 'Invoke-CimMethod',
        'File]::Delete', 'Directory]::Delete', 'File]::Move', 'File]::WriteAll',
        'File]::Create', 'File]::AppendAll', 'Set-Acl', 'DeleteSubKey', 'DeleteValue'
    ) {
        # P3-C1's list, applied to the code with comment spans blanked -- this
        # file has to be able to NAME what it never does, and -match is
        # case-insensitive. Undo-RemovalAction is the one legitimate hit this
        # list would otherwise catch, and it is asserted positively above.
        $script:Code | Should -Not -Match ([regex]::Escape($_))
    }

    It 'runs no external program' {
        foreach ($forbidden in 'winget', 'msiexec', 'rundll32', 'sc', 'reg', 'net', 'wmic',
                               'dism', 'cmd', 'powershell', 'pwsh', 'takeown', 'icacls') {
            $script:Invoked | Should -Not -Contain $forbidden
        }
    }

    It 'turns no string into a command' {
        $ampersand = @($script:Ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            ($node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand -or
             $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot)
        }, $true))

        # Every one of them is a writer scriptblock, which is the only thing this
        # file invokes by reference.
        $ampersand.Count | Should -BeGreaterThan 0
        foreach ($node in $ampersand) {
            $node.CommandElements[0].Extent.Text | Should -Match '^\$(emit|Writer)$'
        }
    }

    It 'exports exactly the two functions this chunk adds, and keeps the rest internal' {
        $module = Get-Module Win11Optimizer.Engine
        foreach ($name in $script:NewExport) {
            [System.IO.File]::ReadAllText($script:ModulePath)   | Should -Match ([regex]::Escape("'$name'"))
            [System.IO.File]::ReadAllText($script:ManifestPath) | Should -Match ([regex]::Escape("'$name'"))
            @($module.ExportedFunctions.Keys) | Should -Contain $name
        }

        $defined = [string[]] @($script:Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | ForEach-Object { $_.Name })
        $defined.Count | Should -BeGreaterThan $script:NewExport.Count

        $exportedFromThisFile = @($defined | Where-Object { @($module.ExportedFunctions.Keys) -contains $_ })
        @($exportedFromThisFile | Sort-Object) -join ',' | Should -BeExactly (@($script:NewExport | Sort-Object) -join ',')
    }

    It 'adds exactly two to the module''s exports, and the manifest agrees' {
        $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
        $exported = @(Get-Command -Module Win11Optimizer.Engine | ForEach-Object { $_.Name })
        @($manifest.FunctionsToExport).Count | Should -Be $exported.Count
        @($exported | Where-Object { $script:NewExport -contains $_ }).Count | Should -Be 2
    }

    It 'declares SupportsShouldProcess with ConfirmImpact High on the one that acts' {
        $command = Get-Command -Module Win11Optimizer.Engine -Name 'Invoke-OptimizerExecutionPlan'
        $command.Parameters.ContainsKey('WhatIf')  | Should -BeTrue
        $command.Parameters.ContainsKey('Confirm') | Should -BeTrue

        $function = @($script:Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | Where-Object { $_.Name -eq 'Invoke-OptimizerExecutionPlan' })
        $attribute = @($function[0].Body.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' })
        $attribute[0].Extent.Text | Should -Match "ConfirmImpact\s*=\s*'High'"
    }

    It 'takes the whole set at once and not one plan at a time' {
        # All-or-nothing is a property of the SET. A process block sees one plan
        # at a time and cannot refuse a run because of the plan after it, so the
        # absence of pipeline binding here is load-bearing rather than an
        # oversight.
        $command = Get-Command -Module Win11Optimizer.Engine -Name 'Invoke-OptimizerExecutionPlan'
        $attributes = @($command.Parameters['Plan'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] })
        $attributes.Count | Should -BeGreaterThan 0
        foreach ($attribute in $attributes) { $attribute.ValueFromPipeline | Should -BeFalse }
    }
}

Describe 'New-OptimizerExecutionPlan: one output per pick, in pick order' {

    BeforeAll {
        $script:PickFindings = @(
            (New-TestFinding -Category Service -Id 'w11o-absent-alpha' -DisplayName 'Alpha service' -RemovalMethod ServiceDisable -RequiresConsent)
            (New-TestFinding -Category OemBloatware -Id 'Fabricated.Beta_8wekyb3d8bbwe' -DisplayName 'Beta app' -RemovalMethod Appx)
            (New-TestFinding -Category OemBloatware -Id 'Fabricated.Gamma_8wekyb3d8bbwe' -DisplayName 'Gamma app' -RemovalMethod Appx)
        )
    }

    It 'returns one plan per pick, in the order they were picked' {
        $plans = @(New-OptimizerExecutionPlan -Finding $script:PickFindings -Pick @('Fabricated.Gamma_8wekyb3d8bbwe', 'w11o-absent-alpha'))
        $plans.Count | Should -Be 2
        $plans[0].FindingId | Should -BeExactly 'Fabricated.Gamma_8wekyb3d8bbwe'
        $plans[1].FindingId | Should -BeExactly 'w11o-absent-alpha'
    }

    It 'hands back real removal plans, from the dispatcher' {
        $plans = @(New-OptimizerExecutionPlan -Finding $script:PickFindings -Pick @('w11o-absent-alpha'))
        $plans[0].PSObject.TypeNames | Should -Contain $script:Contract.TypeName
        $plans[0].Route | Should -BeExactly 'ServiceStartupType'
        @($plans[0].PreviewText).Count | Should -BeGreaterThan 0
    }

    It 'puts a $null IN ITS PLACE for a pick that matches nothing' {
        # Not a shorter list. The Nth output is the Nth pick, and a run built from
        # a list that quietly lost an entry would be acting on something nobody
        # chose. Invoke-OptimizerExecutionPlan refuses the $null on purpose.
        $plans = @(New-OptimizerExecutionPlan -Finding $script:PickFindings -Pick @('w11o-absent-alpha', 'nothing-carries-this-id', 'Fabricated.Beta_8wekyb3d8bbwe'))
        $plans.Count | Should -Be 3
        $plans[0] | Should -Not -BeNullOrEmpty
        $plans[1] | Should -BeNullOrEmpty
        $plans[2] | Should -Not -BeNullOrEmpty
    }

    It 'reads a blank pick as no plan rather than as every plan' {
        $plans = @(New-OptimizerExecutionPlan -Finding $script:PickFindings -Pick @('', '   '))
        $plans.Count | Should -Be 2
        @($plans | Where-Object { $null -ne $_ }).Count | Should -Be 0
    }

    It 'matches an id whose case differs, because a registry path is a case-insensitive key' {
        $findings = @((New-TestFinding -Category OemBloatware `
            -Id 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Fabricated' `
            -DisplayName 'Fabricated registry app' -RemovalMethod RegistryUninstallString))
        $plans = @(New-OptimizerExecutionPlan -Finding $findings -Pick @('hkey_local_machine\software\microsoft\windows\currentversion\uninstall\fabricated'))
        $plans.Count | Should -Be 1
        $plans[0] | Should -Not -BeNullOrEmpty
    }

    It 'plans for every Finding a pick matches rather than dropping the second' {
        # Ids are unique within a category by construction, so this is a guard and
        # not an expected shape -- but dropping one silently is the failure this
        # project exists to prevent, and a count larger than the pick list is
        # something a caller can see.
        $twins = @(
            (New-TestFinding -Category OemBloatware -Id 'Fabricated.Twin' -DisplayName 'Twin one' -RemovalMethod Appx)
            (New-TestFinding -Category UnusedApp -Id 'Fabricated.Twin' -DisplayName 'Twin two' -RemovalMethod Appx)
        )
        $plans = @(New-OptimizerExecutionPlan -Finding $twins -Pick @('Fabricated.Twin'))
        $plans.Count | Should -Be 2
    }

    It 'survives an empty finding list and an empty pick list' {
        @(New-OptimizerExecutionPlan -Finding @() -Pick @()).Count | Should -Be 0
        $plans = @(New-OptimizerExecutionPlan -Finding @() -Pick @('anything'))
        $plans.Count | Should -Be 1
        $plans[0] | Should -BeNullOrEmpty
    }

    It 'writes nothing at all' {
        # It is Get-RemovalPlan with a lookup in front of it, and Get-RemovalPlan
        # reads. No ledger comes into existence from asking what would happen.
        $ledger = Get-OptimizerActionLogPath
        $before = Test-Path -LiteralPath $ledger
        $null = New-OptimizerExecutionPlan -Finding $script:PickFindings -Pick @('w11o-absent-alpha', 'Fabricated.Beta_8wekyb3d8bbwe')
        (Test-Path -LiteralPath $ledger) | Should -Be $before
    }
}

Describe 'A1: a repeated DisplayName gets a FindingId column' {

    BeforeAll {
        # The real shape from this machine: 'Microsoft Copilot' twice, one Appx
        # package and one Win32 install, needing two different removal calls.
        $script:CollidingScan = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @(); InventoryCount = 292
        } -Finding @(
            (New-TestFinding -Category OemBloatware -Id 'Microsoft.Copilot_8wekyb3d8bbwe' -DisplayName 'Microsoft Copilot' -RemovalMethod Appx)
            (New-TestFinding -Category OemBloatware -Id 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Copilot' -DisplayName 'Microsoft Copilot' -RemovalMethod RegistryUninstallString)
            (New-TestFinding -Category OemBloatware -Id 'Microsoft.Windows.DevHome_8wekyb3d8bbwe' -DisplayName 'Dev Home' -RemovalMethod Appx)
        )

        $script:DistinctScan = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @(); InventoryCount = 292
        } -Finding @(
            (New-TestFinding -Category OemBloatware -Id 'Microsoft.Copilot_8wekyb3d8bbwe' -DisplayName 'Microsoft Copilot' -RemovalMethod Appx)
            (New-TestFinding -Category OemBloatware -Id 'Microsoft.Windows.DevHome_8wekyb3d8bbwe' -DisplayName 'Dev Home' -RemovalMethod Appx)
        )

        $script:EmptyUnusedScan = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
            ConsideredCount = 292; UsedCount = 40; UnusedCount = 0; UnknownCount = 252; ExcludedCount = 0
        }

        function Get-InstalledSection {
            param([Parameter(Mandatory)] $OemScan)
            InModuleScope Win11Optimizer.Engine -Parameters @{ Oem = $OemScan; Unused = $script:EmptyUnusedScan } {
                param($Oem, $Unused)
                Get-ReviewInstalledAppSection -UnusedScan $Unused -OemScan $Oem
            }
        }
    }

    It 'shows the column, with both ids, when a name repeats' {
        $section = Get-InstalledSection -OemScan $script:CollidingScan
        $section.ColumnHeader | Should -Contain 'FindingId'
        @($section.ColumnHeader).Count | Should -Be 6

        $copilot = @($section.Row | Where-Object { $_.DisplayName -eq 'Microsoft Copilot' })
        $copilot.Count | Should -Be 2
        $copilot[0].Cell[2] | Should -BeExactly 'Microsoft.Copilot_8wekyb3d8bbwe'
        $copilot[1].Cell[2] | Should -Match 'WOW6432Node'
    }

    It 'shows no column at all when no name repeats' {
        $section = Get-InstalledSection -OemScan $script:DistinctScan
        $section.ColumnHeader | Should -Not -Contain 'FindingId'
        @($section.ColumnHeader).Count | Should -Be 5
        @($section.ColumnMinimumWidth).Count | Should -Be 0
    }

    It 'gives every row a cell for every column, including the ones that did not collide' {
        # A cell that is blank by design is indistinguishable from a cell that
        # came out blank by accident.
        $section = Get-InstalledSection -OemScan $script:CollidingScan
        foreach ($row in @($section.Row)) {
            @($row.Cell).Count  | Should -Be @($section.ColumnHeader).Count
            @($row.Style).Count | Should -Be @($section.ColumnHeader).Count
            foreach ($cell in @($row.Cell)) { $cell | Should -Not -BeNullOrEmpty }
        }
    }

    It 'renders the two ids differently at every width the screen supports' {
        # THE POINT OF THE COLUMN. A disambiguating column squeezed until its two
        # cells truncate to the same string disambiguates nothing, and does it
        # silently.
        $section = Get-InstalledSection -OemScan $script:CollidingScan
        foreach ($width in 60, 80, 100, 140) {
            $lines = InModuleScope Win11Optimizer.Engine -Parameters @{ Section = $section; Width = $width } {
                param($Section, $Width)
                Format-ReviewSection -Section $Section -Width $Width -Colour $false
            }
            $rows = @($lines | Where-Object { $_ -match '^\s+[12]\s\s' })
            $rows.Count | Should -Be 2 -Because "at width $width"

            # THE ROW NUMBER IS STRIPPED FIRST, and that is what makes this
            # assertion mean anything: rows 1 and 2 differ by their leading '1'
            # and '2' whatever else is true, so comparing whole lines would pass
            # even with the column gone. These two fixture rows are identical in
            # every other cell -- same name, same 'Found by', same reason, same
            # safety label -- so what is left after the number can only differ in
            # the id.
            $stripped = @($rows | ForEach-Object { $_ -replace '^\s*\d+\s\s', '' })
            $stripped[0] | Should -Not -BeExactly $stripped[1] -Because "at width $width the two Copilot rows must be tellable apart"
        }
    }

    It 'would fail if the column were not there, which is what makes the test above mean something' {
        # The negative control. The same two rows, rendered by the same code with
        # the id column removed from the section, are indistinguishable once the
        # row number is taken off -- so the assertion above is testing the column
        # and not the numbering.
        $section = Get-InstalledSection -OemScan $script:CollidingScan
        $withoutId = InModuleScope Win11Optimizer.Engine -Parameters @{ Section = $section } {
            param($Section)
            $stripped = $Section.PSObject.Copy()
            $stripped.ColumnHeader = [string[]] @($Section.ColumnHeader | Where-Object { $_ -ne 'FindingId' })
            $stripped.ColumnMinimumWidth = [int[]] @()
            $stripped.Row = [psobject[]] @($Section.Row | ForEach-Object {
                $row = $_.PSObject.Copy()
                $row.Cell  = [string[]] @(@($_.Cell)[0], @($_.Cell)[1]) + [string[]] @(@($_.Cell)[3..(@($_.Cell).Count - 1)])
                $row.Style = [string[]] @(@($_.Style)[0], @($_.Style)[1]) + [string[]] @(@($_.Style)[3..(@($_.Style).Count - 1)])
                $row
            })
            Format-ReviewSection -Section $stripped -Width 100 -Colour $false
        }

        $rows = @($withoutId | Where-Object { $_ -match '^\s+[12]\s\s' })
        $rows.Count | Should -Be 2
        $stripped = @($rows | ForEach-Object { $_ -replace '^\s*\d+\s\s', '' })
        $stripped[0] | Should -BeExactly $stripped[1] -Because 'without the id column the two Copilot rows are the same row twice'
    }

    It 'widens the column when the two ids only differ late in the string' {
        # The floor, and the reason it is computed rather than fixed. Two registry
        # keys under the same parent share 80 characters, and a column squeezed to
        # the shared minimum of 8 would show 'HKEY_L...' twice.
        $prefix = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Fabricated'
        $scan = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @(); InventoryCount = 2
        } -Finding @(
            (New-TestFinding -Category OemBloatware -Id ($prefix + 'One') -DisplayName 'Same name' -RemovalMethod RegistryUninstallString)
            (New-TestFinding -Category OemBloatware -Id ($prefix + 'Two') -DisplayName 'Same name' -RemovalMethod RegistryUninstallString)
        )

        $section = Get-InstalledSection -OemScan $scan
        @($section.ColumnMinimumWidth)[2] | Should -BeGreaterThan 8

        $lines = InModuleScope Win11Optimizer.Engine -Parameters @{ Section = $section } {
            param($Section)
            Format-ReviewSection -Section $Section -Width 60 -Colour $false
        }
        $rows = @($lines | Where-Object { $_ -match '^\s+[12]\s\s' })
        $rows.Count | Should -Be 2
        # The number stripped first, for the reason given above: these two rows
        # are identical in every cell but the id.
        $stripped = @($rows | ForEach-Object { $_ -replace '^\s*\d+\s\s', '' })
        $stripped[0] | Should -Not -BeExactly $stripped[1]
    }

    It 'does not widen anything when the ids are already tellable apart' {
        # The non-vacuity control for the test above: without it, a floor that was
        # always huge would pass that one and wreck every other layout.
        $section = Get-InstalledSection -OemScan $script:CollidingScan
        @($section.ColumnMinimumWidth)[2] | Should -Be 8
    }

    It 'falls back to the shared floor for two Findings that carry the same id as well as the same name' {
        # No width separates them. Widening a column to pretend otherwise would be
        # worse than leaving it, so the rule gives up rather than loops.
        $column = InModuleScope Win11Optimizer.Engine {
            $one = New-Finding -Category OemBloatware -Id 'Fabricated.Same' -DisplayName 'Same' -Evidence 'x' -Confidence Known -RemovalMethod Appx
            $two = New-Finding -Category UnusedApp -Id 'Fabricated.Same' -DisplayName 'Same' -Evidence 'x' -Confidence Known -RemovalMethod Appx
            Get-ReviewIdColumn -Finding @($one, $two)
        }
        $column.Show | Should -BeTrue
        @($column.MinimumWidth)[2] | Should -Be 8
    }

    It 'treats two names that differ only in case as a collision' {
        $scan = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @(); InventoryCount = 2
        } -Finding @(
            (New-TestFinding -Category OemBloatware -Id 'Fabricated.Lower' -DisplayName 'microsoft copilot' -RemovalMethod Appx)
            (New-TestFinding -Category OemBloatware -Id 'Fabricated.Upper' -DisplayName 'Microsoft Copilot' -RemovalMethod Appx)
        )
        (Get-InstalledSection -OemScan $scan).ColumnHeader | Should -Contain 'FindingId'
    }

    It 'applies the same rule to the other three sections' {
        $startupScan = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
            InventoryCount = 10; EnabledCount = 8; DisabledCount = 2; UnknownStateCount = 0
            ProtectedTaskCount = 0; ProtectedServiceCount = 0
            MechanismCount = [ordered]@{ RunKey = 2; StartupFolder = 0; ScheduledTask = 0; Service = 8 }
            StartupItems = [psobject[]] @()
        } -Finding @(
            (New-TestFinding -Category StartupItem -Id 'HKCU:\...\Run::One' -DisplayName 'Discord' -RemovalMethod RegistryRunKey -RequiresConsent)
            (New-TestFinding -Category StartupItem -Id 'HKLM:\...\Run::Two' -DisplayName 'Discord' -RemovalMethod RegistryRunKey -RequiresConsent)
            (New-TestFinding -Category Service -Id 'w11o-absent-one' -DisplayName 'Gaming Services' -RemovalMethod ServiceDisable -RequiresConsent)
            (New-TestFinding -Category Service -Id 'w11o-absent-two' -DisplayName 'Gaming Services' -RemovalMethod ServiceDisable -RequiresConsent)
        )

        $sections = InModuleScope Win11Optimizer.Engine -Parameters @{ Scan = $startupScan } {
            param($Scan)
            [pscustomobject]@{
                Startup = Get-ReviewStartupSection -Scan $Scan
                Service = Get-ReviewServiceSection -Scan $Scan
            }
        }
        $sections.Startup.ColumnHeader | Should -Contain 'FindingId'
        $sections.Service.ColumnHeader | Should -Contain 'FindingId'
        @($sections.Service.Row)[0].Cell[2] | Should -BeExactly 'w11o-absent-one'
    }
}

Describe 'A2: the confirmation cannot be answered by muscle memory' {

    BeforeAll {
        $script:PromptScreen = Get-ReviewScreen -SkipReceipt `
            -StartupScan (New-TestScan -Property @{
                IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
                InventoryCount = 10; EnabledCount = 8; DisabledCount = 2; UnknownStateCount = 0
                ProtectedTaskCount = 0; ProtectedServiceCount = 0
                MechanismCount = [ordered]@{ RunKey = 2; StartupFolder = 0; ScheduledTask = 0; Service = 8 }
                StartupItems = [psobject[]] @()
            }) `
            -UnusedAppScan (New-TestScan -Property @{
                IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
                ConsideredCount = 2; UsedCount = 0; UnusedCount = 0; UnknownCount = 2; ExcludedCount = 0
            }) `
            -OemScan (New-TestScan -Property @{
                IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @(); InventoryCount = 2
            } -Finding @(
                (New-TestFinding -Category OemBloatware -Id 'Fabricated.One_8wekyb3d8bbwe' -DisplayName 'Fabricated app one' -RemovalMethod Appx)
                (New-TestFinding -Category OemBloatware -Id 'Fabricated.Two_8wekyb3d8bbwe' -DisplayName 'Fabricated app two' -RemovalMethod Appx)
            )) `
            -JunkScan (New-TestScan -Property @{
                IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
                InventoryCount = 15; MinimumAgeDays = 7; SizeIsFloor = $false
            })

        function Invoke-PromptRun {
            param([Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Answer)
            $queue = New-Object 'System.Collections.Generic.Queue[string]'
            foreach ($item in $Answer) { $queue.Enqueue($item) }
            $written = New-Object System.Collections.Generic.List[string]
            $asked   = New-Object System.Collections.Generic.List[string]
            $selection = Show-ReviewScreen -Screen $script:PromptScreen -Width 100 -NoColour `
                -Reader { param($Prompt) $null = $asked.Add([string] $Prompt); $(if ($queue.Count -gt 0) { $queue.Dequeue() } else { '' }) }.GetNewClosure() `
                -Writer { param($Line) $null = $written.Add([string] $Line) }.GetNewClosure()
            [pscustomobject]@{ Selection = $selection; Written = [string[]] @($written.ToArray()); Asked = [string[]] @($asked.ToArray()) }
        }
    }

    It 'names the token that is a yes, and the token that is not' {
        $run = Invoke-PromptRun -Answer @('a', 'no')
        $confirm = @($run.Asked)[-1]
        $confirm | Should -Match "Type 'yes' to confirm"
        $confirm | Should -Match "'a' included"
        $confirm | Should -Match 'stops'
    }

    It 'reads differently from the section prompt one line above it' {
        # The whole defect: 'a' is a perfectly good answer to a section prompt and
        # is not a yes here, so the two prompts must not read alike.
        $run = Invoke-PromptRun -Answer @('a', 'no')
        $section = @($run.Asked)[0]
        $confirm = @($run.Asked)[-1]
        $section | Should -Match "'a' for all"
        $section | Should -Not -Match "Type 'yes'"
        $confirm | Should -Not -Match "for all"
    }

    It 'still stops on a, because the fail-safe was never the problem' {
        $run = Invoke-PromptRun -Answer @('a', 'a')
        $run.Selection.Confirmed | Should -BeFalse
        ($run.Written -join "`n") | Should -Match 'Stopped. Nothing on this PC has been changed'
    }

    It 'still takes yes as yes, and still executes nothing' {
        $run = Invoke-PromptRun -Answer @('a', 'yes')
        $run.Selection.Confirmed | Should -BeTrue
        $run.Selection.Executed  | Should -BeFalse
        ($run.Written -join "`n") | Should -Match 'collects the decision and stops there'
    }
}

Describe 'B: the preview says when elevation is in the way' {

    BeforeAll {
        $script:ElevationScreen = Get-ReviewScreen -SkipReceipt `
            -StartupScan (New-TestScan -Property @{
                IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
                InventoryCount = 10; EnabledCount = 8; DisabledCount = 2; UnknownStateCount = 0
                ProtectedTaskCount = 0; ProtectedServiceCount = 0
                MechanismCount = [ordered]@{ RunKey = 0; StartupFolder = 0; ScheduledTask = 0; Service = 8 }
                StartupItems = [psobject[]] @([pscustomobject]@{ Mechanism = 'Service'; Id = 'w11o-absent-elev'; EnabledState = 'Enabled' })
            } -Finding @(
                (New-TestFinding -Category Service -Id 'w11o-absent-elev' -DisplayName 'Fabricated service' -RemovalMethod ServiceDisable -RequiresConsent)
            )) `
            -UnusedAppScan (New-TestScan -Property @{
                IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
                ConsideredCount = 1; UsedCount = 0; UnusedCount = 0; UnknownCount = 1; ExcludedCount = 0
            }) `
            -OemScan (New-TestScan -Property @{
                IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @(); InventoryCount = 1
            }) `
            -JunkScan (New-TestScan -Property @{
                IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
                InventoryCount = 15; MinimumAgeDays = 7; SizeIsFloor = $false
            })

        # The plan the screen prints is mocked rather than built, because the one
        # thing this Describe is about -- RequiresElevation -- is derived from
        # what the dispatcher could read, and a plan for an absent service has no
        # steps and therefore needs no rights.
        function Invoke-ElevationRun {
            param([Parameter(Mandatory)] [bool] $Elevated, [Parameter()] [bool] $NeedsElevation = $true)
            InModuleScope Win11Optimizer.Engine -Parameters @{
                Screen = $script:ElevationScreen; Elevated = $Elevated; Needs = $NeedsElevation
            } {
                param($Screen, $Elevated, $Needs)

                $script:ScenarioElevated = [bool] $Elevated
                $script:ScenarioPlan = [pscustomobject]@{
                    PSTypeName = 'Win11Optimizer.RemovalPlan'
                    FindingId = 'w11o-absent-elev'; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                    DisplayName = 'Fabricated service'; Confidence = 'Known'; Route = 'ServiceStartupType'
                    Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                    VerifiedUtc = [datetime]::UtcNow.ToString('o')
                    RequiresElevation = [bool] $Needs; RequiresConsent = $true
                    SafetyLabel = 'Review needed'; IsReversible = $true
                    Step = [psobject[]] @(); RollbackData = $null; Note = [string[]] @()
                    PreviewText = [string[]] @('Fabricated preview line for the elevation test.')
                }

                Mock Test-IsElevated { $script:ScenarioElevated }
                Mock Get-RemovalPlan { $script:ScenarioPlan }

                $queue = New-Object 'System.Collections.Generic.Queue[string]'
                foreach ($item in @('a', 'no')) { $queue.Enqueue($item) }
                $written = New-Object System.Collections.Generic.List[string]
                $null = Show-ReviewScreen -Screen $Screen -Width 100 -NoColour `
                    -Reader { $(if ($queue.Count -gt 0) { $queue.Dequeue() } else { '' }) }.GetNewClosure() `
                    -Writer { param($Line) $null = $written.Add([string] $Line) }.GetNewClosure()
                [string[]] @($written.ToArray())
            }
        }
    }

    It 'says so, in the sentence the handoff asked for, when a plan needs rights this process has not got' {
        $written = Invoke-ElevationRun -Elevated $false
        ($written -join "`n") | Should -Match 'Elevation required to execute these changes\.'
    }

    It 'says nothing about elevation when the process already has it' {
        $written = Invoke-ElevationRun -Elevated $true
        ($written -join "`n") | Should -Not -Match 'Elevation required'
    }

    It 'says nothing about elevation when no plan needs it' {
        $written = Invoke-ElevationRun -Elevated $false -NeedsElevation $false
        ($written -join "`n") | Should -Not -Match 'Elevation required'
    }

    It 'does not prompt for elevation, ask to relaunch, or offer to' {
        # Reporting is this chunk's; the UAC shim is P5-C1's, and a line that
        # implied this build could relaunch itself would be a promise the code
        # cannot keep.
        $written = Invoke-ElevationRun -Elevated $false
        foreach ($forbidden in 'relaunch', 'restart as administrator', 'run as administrator to continue') {
            ($written -join "`n") | Should -Not -Match $forbidden
        }
    }

    It 'still prints the plan''s own PreviewText and does not re-render it' {
        $written = Invoke-ElevationRun -Elevated $false
        $text = ($written -join "`n")
        $text | Should -Match 'What would happen'
        $text | Should -Match 'Fabricated preview line for the elevation test\.'
    }
}

Describe 'Invoke-OptimizerExecutionPlan: all of them or none of them' {

    BeforeEach {
        $script:Ledger = New-LedgerPath
    }

    It 'refuses the run, naming the position, when a pick resolved to no plan' {
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @((New-FabricatedServicePlan), $null)

        $observed.Run.Result    | Should -Be 'Refused'
        $observed.Run.Reason    | Should -Match '1 of the 2 given are not something this tool can act on'
        $observed.Run.Performed | Should -BeFalse

        # The position is named, in the data and in what a person reads.
        @($observed.Run.Refusal).Count | Should -Be 1
        @($observed.Run.Refusal)[0].DisplayName | Should -BeExactly 'Pick 2 of 2'
        @($observed.Run.Refusal)[0].Reason | Should -Match 'resolved to no plan at all'
        ($observed.Written -join "`n") | Should -Match 'Pick 2 of 2 \(\(no plan\)\)'
        (Test-Path -LiteralPath $script:Ledger) | Should -BeFalse -Because 'a refused run writes nothing at all'
    }

    It 'refuses the run when something in the set is not a plan' {
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @([pscustomobject]@{ Nonsense = $true })
        $observed.Run.Result | Should -Be 'Refused'
        @($observed.Run.Refusal)[0].Reason | Should -Match 'is not a removal plan'
        (Test-Path -LiteralPath $script:Ledger) | Should -BeFalse
    }

    It 'does nothing, and says so, for an empty set' {
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @()
        $observed.Run.Result    | Should -Be 'Skipped'
        $observed.Run.PlanCount | Should -Be 0
        $observed.Run.Reason    | Should -Match 'nothing to do'
        (Test-Path -LiteralPath $script:Ledger) | Should -BeFalse
    }

    It 'refuses the WHOLE run when one plan is on a route this build will not perform' {
        # THE ACCEPTANCE CRITERION, and on this machine it is the common case:
        # this build performs one route of seven, so a selection that mixes an
        # app with a service stops here having written nothing.
        $service = New-FabricatedServicePlan -DisplayName 'Fabricated service'
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger `
            -Plan @($service, (New-FabricatedAppxPlan -DisplayName 'Fabricated app')) `
            -LiveStart @{ "$($service.FindingId)" = 2 }

        $observed.Run.Result | Should -Be 'Refused'
        $observed.Run.Reason | Should -Match '1 of the 2 selected cannot be carried out'
        $observed.Run.AttemptedCount | Should -Be 0

        # ONE ENTRY PER REFUSED ROW, carrying the executor's own reason, and only
        # for the row that was actually refused: the service plan passed the
        # pre-flight and was still not attempted, because the run is all or none.
        @($observed.Run.Refusal).Count | Should -Be 1
        @($observed.Run.Refusal)[0].DisplayName | Should -BeExactly 'Fabricated app'
        @($observed.Run.Refusal)[0].Route       | Should -BeExactly 'AppxPackage'
        @($observed.Run.Refusal)[0].Reason      | Should -Match 'performs one kind of change only'

        # And a person reads it as its own block, headed by the row it belongs to.
        ($observed.Written -join "`n") | Should -Match 'Fabricated app \(AppxPackage\)'

        (Test-Path -LiteralPath $script:Ledger) | Should -BeFalse -Because 'the ledger must not exist after a run refused before it started'
        ($observed.Written -join "`n") | Should -Match 'Nothing on this PC was changed and nothing was written to the action log'

        # No receipt, and that is the decision rather than an omission: a run
        # that wrote nothing under a brand-new run id can only ever produce
        # "Actions recorded: 0", and a derivation that cannot come out any other
        # way is not evidence. An empty ReceiptText is how a caller tells a
        # refused run from one that reached the ledger.
        @($observed.Run.ReceiptText).Count | Should -Be 0
        ($observed.Written -join "`n") | Should -Not -Match 'Actions recorded'
    }

    It 'refuses the whole run for a plan that needs rights this process has not got' {
        $service = New-FabricatedServicePlan
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @($service) `
            -LiveStart @{ "$($service.FindingId)" = 2 } -Elevated $false

        $observed.Run.Result | Should -Be 'Refused'
        @($observed.Run.Refusal)[0].Reason | Should -Match 'needs administrator rights'
        (Test-Path -LiteralPath $script:Ledger) | Should -BeFalse
    }

    It 'writes nothing under -WhatIf' {
        $service = New-FabricatedServicePlan
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @($service) `
            -LiveStart @{ "$($service.FindingId)" = 2 } -DryRun

        $observed.Run.Result   | Should -Be 'Skipped'
        $observed.Run.IsWhatIf | Should -BeTrue
        (Test-Path -LiteralPath $script:Ledger) | Should -BeFalse
    }

    It 'performs every plan in order and prints the receipt for THIS run' {
        $one = New-FabricatedServicePlan -DisplayName 'Fabricated service one'
        $two = New-FabricatedServicePlan -DisplayName 'Fabricated service two'
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @($one, $two) `
            -LiveStart @{ "$($one.FindingId)" = 2; "$($two.FindingId)" = 2 }

        $observed.Run.Result         | Should -Be 'Succeeded'
        $observed.Run.Performed      | Should -BeTrue
        $observed.Run.AttemptedCount | Should -Be 2
        $observed.Run.SucceededCount | Should -Be 2
        $observed.Run.RolledBack     | Should -BeFalse
        @($observed.Run.UndoResult).Count | Should -Be 0

        @($observed.Run.ActionResult)[0].DisplayName | Should -BeExactly 'Fabricated service one'
        @($observed.Run.ActionResult)[1].DisplayName | Should -BeExactly 'Fabricated service two'

        $entries = @(Get-OptimizerActionLog -Path $script:Ledger | Where-Object { -not $_.IsParseError })
        $entries.Count | Should -Be 2
        @($entries | Where-Object { $_.Result -eq 'Succeeded' }).Count | Should -Be 2

        # The receipt is the ledger's own text, printed and not re-rendered.
        @($observed.Run.ReceiptText).Count | Should -BeGreaterThan 0
        $transcript = ($observed.Written -join "`n")
        foreach ($line in @($observed.Run.ReceiptText)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $transcript | Should -Match ([regex]::Escape($line))
        }
        $transcript | Should -Match 'Actions recorded: 2'
        $transcript | Should -Match 'All 2 of the selected change'
    }

    It 'counts only this run, not everything the ledger has ever held' {
        # P4-C1's report: the receipt on the review screen is the whole ledger,
        # which is right for a screen that opens with "what this tool has ever
        # done" and wrong for the run that just happened.
        $old = New-FabricatedServicePlan -DisplayName 'An earlier run'
        $new = New-FabricatedServicePlan -DisplayName 'This run'
        $live = @{ "$($old.FindingId)" = 2; "$($new.FindingId)" = 2 }

        $null = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @($old) -LiveStart $live -RunId 'run-that-already-happened'
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @($new) -LiveStart $live -RunId 'the-run-under-test'

        $observed.Run.Result | Should -Be 'Succeeded'
        $observed.Run.Receipt.ActionCount | Should -Be 1
        $observed.Run.Receipt.RunId | Should -BeExactly 'the-run-under-test'
        # Both are on the ledger; only one is on the receipt.
        @(Get-OptimizerActionLog -Path $script:Ledger | Where-Object { -not $_.IsParseError }).Count | Should -Be 2
    }

    It 'stops at the first failure, does not attempt the rest, and puts back what it had done' {
        $one   = New-FabricatedServicePlan -DisplayName 'Goes through'
        $two   = New-FabricatedServicePlan -DisplayName 'Does not go through'
        $three = New-FabricatedServicePlan -DisplayName 'Never attempted'

        # One is written and reads back 4; two throws on the write so nothing
        # changed for it and its live value is still 2; three is never reached.
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @($one, $two, $three) `
            -FailWriteFor @($two.FindingId) `
            -LiveStart @{ "$($one.FindingId)" = 4; "$($two.FindingId)" = 2; "$($three.FindingId)" = 2 }

        $observed.Run.Result         | Should -Be 'Failed'
        $observed.Run.AttemptedCount | Should -Be 2 -Because 'the third plan must never have been attempted'
        $observed.Run.RolledBack     | Should -BeTrue
        $observed.Run.Reason         | Should -Match 'Does not go through'

        # Newest first, and both recorded actions were offered to the undo.
        @($observed.Run.UndoResult).Count | Should -Be 2
        @($observed.Run.UndoResult)[0].UndoOfActionId | Should -BeExactly @($observed.Run.ActionResult)[1].ActionId
        @($observed.Run.UndoResult)[1].UndoOfActionId | Should -BeExactly @($observed.Run.ActionResult)[0].ActionId

        # The one that was actually changed was actually put back; the one that
        # failed was already where it started and nothing was written for it.
        @($observed.Run.UndoResult)[1].Result | Should -Be 'Succeeded'
        @($observed.Run.UndoResult)[0].Result | Should -Be 'Skipped'

        $entries = @(Get-OptimizerActionLog -Path $script:Ledger | Where-Object { -not $_.IsParseError })
        $entries.Count | Should -Be 4 -Because 'two actions and two undos, and an undo is a new action rather than an edit'
        @($entries | Where-Object { [string] $_.FindingId -eq $three.FindingId }).Count | Should -Be 0

        ($observed.Written -join "`n") | Should -Match 'everything it had already done was put back'
        ($observed.Written -join "`n") | Should -Match 'were not attempted'
    }

    It 'says Partial, not Failed, when putting it back did not work either' {
        # The one state that is neither before nor after. Rounding it to Failed
        # would tell a person this PC is where it started when it is not.
        $one = New-FabricatedServicePlan -DisplayName 'Goes through'
        $two = New-FabricatedServicePlan -DisplayName 'Does not go through'

        # 3 is neither what this tool wrote (4) nor what it was before (2), so the
        # undo refuses to overwrite somebody else's change.
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @($one, $two) `
            -FailWriteFor @($two.FindingId) `
            -LiveStart @{ "$($one.FindingId)" = 3; "$($two.FindingId)" = 2 }

        $observed.Run.Result     | Should -Be 'Partial'
        $observed.Run.RolledBack | Should -BeFalse
        @($observed.Run.UndoResult | Where-Object { $_.Result -eq 'Refused' }).Count | Should -Be 1
        ($observed.Written -join "`n") | Should -Match 'NOT where it started'
    }

    It 'asks once for the run and never once per plan' {
        # A person who has read a preview and typed 'yes' must not then be asked
        # seven more times. Asserted structurally: one ShouldProcess call in the
        # function, and -Confirm:$false on every executor call it makes.
        $function = @($script:Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | Where-Object { $_.Name -eq 'Invoke-OptimizerExecutionPlan' })

        $shouldProcess = @($function[0].FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            [string] $node.Member.Value -eq 'ShouldProcess'
        }, $true))
        $shouldProcess.Count | Should -Be 1

        $script:Code | Should -Match "Confirm\s*=\s*\`$false"
    }

    It 'says nothing that claims a benefit, on any path' {
        $one = New-FabricatedServicePlan -DisplayName 'Fabricated service'
        $live = @{ "$($one.FindingId)" = 2 }

        $transcript = @(
            @((Invoke-ExecutionScenario -Ledger (New-LedgerPath) -Plan @()).Written)
            @((Invoke-ExecutionScenario -Ledger (New-LedgerPath) -Plan @($one, $null) -LiveStart $live).Written)
            @((Invoke-ExecutionScenario -Ledger (New-LedgerPath) -Plan @($one) -LiveStart $live).Written)
        ) -join "`n"

        $script:ForbiddenPhrase.Count | Should -BeGreaterThan 4
        $script:ForbiddenPhrase | Should -Contain 'free up'

        $transcript.Length | Should -BeGreaterThan 200
        foreach ($phrase in $script:ForbiddenPhrase) {
            $transcript.IndexOf($phrase, [System.StringComparison]::OrdinalIgnoreCase) |
                Should -Be -1 -Because "the run report must not say '$phrase'"
        }
    }

    It 'is ASCII in everything it prints' {
        $one = New-FabricatedServicePlan -DisplayName 'Fabricated service'
        $observed = Invoke-ExecutionScenario -Ledger $script:Ledger -Plan @($one) -LiveStart @{ "$($one.FindingId)" = 2 }
        foreach ($line in @($observed.Written)) { $line | Should -Not -Match '[^\x20-\x7E]' }
    }
}

Describe 'The screen and the executor, end to end, without touching this machine' {

    It 'takes a selection, builds plans from its ids, and refuses a run it cannot carry out' {
        # The whole chunk in one test: what P4-C1 hands back goes into
        # New-OptimizerExecutionPlan, whose output goes into
        # Invoke-OptimizerExecutionPlan, which refuses because nothing on this
        # fabricated screen is on the one route this build performs -- and writes
        # nothing while refusing.
        $ledger = New-LedgerPath

        $oem = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @(); InventoryCount = 2
        } -Finding @(
            (New-TestFinding -Category OemBloatware -Id 'Fabricated.One_8wekyb3d8bbwe' -DisplayName 'Fabricated app' -RemovalMethod Appx)
        )
        $unused = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
            ConsideredCount = 2; UsedCount = 0; UnusedCount = 0; UnknownCount = 2; ExcludedCount = 0
        }
        $blank = New-TestScan -Property @{
            IsComplete = $true; IncompleteReason = $null; RefusedSourceName = [string[]] @()
            InventoryCount = 0; EnabledCount = 0; DisabledCount = 0; UnknownStateCount = 0
            ProtectedTaskCount = 0; ProtectedServiceCount = 0; MinimumAgeDays = 7; SizeIsFloor = $false
            MechanismCount = [ordered]@{ RunKey = 0; StartupFolder = 0; ScheduledTask = 0; Service = 0 }
            StartupItems = [psobject[]] @()
        }

        $screen = Get-ReviewScreen -StartupScan $blank -UnusedAppScan $unused -OemScan $oem -JunkScan $blank -SkipReceipt

        $queue = New-Object 'System.Collections.Generic.Queue[string]'
        foreach ($item in @('a', 'yes')) { $queue.Enqueue($item) }
        $selection = Show-ReviewScreen -Screen $screen -Width 100 -NoColour `
            -Reader { $(if ($queue.Count -gt 0) { $queue.Dequeue() } else { '' }) }.GetNewClosure() `
            -Writer { param($Line) }

        $selection.Confirmed | Should -BeTrue
        $selection.Executed  | Should -BeFalse

        $picks = [string[]] @($selection.Finding | ForEach-Object { $_.Id })
        $plans = @(New-OptimizerExecutionPlan -Finding $selection.Finding -Pick $picks)
        $plans.Count | Should -Be $selection.SelectedCount
        @($plans | Where-Object { $null -eq $_ }).Count | Should -Be 0

        $run = Invoke-OptimizerExecutionPlan -Plan $plans -LedgerPath $ledger -Confirm:$false -Writer { param($Line) }
        $run.Result    | Should -Be 'Refused'
        $run.Performed | Should -BeFalse
        (Test-Path -LiteralPath $ledger) | Should -BeFalse
    }
}
