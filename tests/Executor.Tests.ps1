#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the executor (chunk P3-C3,
    src\Win11Optimizer.Engine\Removal\Executor.ps1).

    This is the first file in the project that changes the machine on purpose, so
    the first Describe is a positive allowlist rather than the blanket "this
    changes nothing" the earlier chunks could assert: it reads the source and
    pins down that the whole write surface is TWO registry value names on ONE
    service key, that the two names are enforced by a ValidateSet the shell
    checks on every call rather than by a test reading a comment, and that no
    external process is invoked anywhere. P3-C1's entire forbidden-string list
    still applies unchanged, and is applied.

    Everything after that is about one question: CAN THIS TOUCH SOMETHING IT WAS
    NOT ASKED TO TOUCH? Which is why the fabricated service plans in this file
    name a service that does not exist -- if a gate ever fails open, the real
    write path meets a key that is not there and refuses, so a regression costs a
    red test and not somebody's service.

    NOTHING IN THIS FILE WRITES TO THE REGISTRY. The one real write is proved
    once, elevated, against the one real Service finding on the development
    machine, and the three registry readings are in
    docs\handoff\11-executor.report.md.

    Run:  .\tests\Invoke-Tests.ps1        (and -On51, which is not optional)
#>

BeforeAll {
    $script:RepoRoot      = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot    = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath  = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath    = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:SourcePath    = Join-Path $script:EngineRoot 'Removal\Executor.ps1'

    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-exec-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-exec-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    $script:Contract = Get-RemovalContract

    # The two functions this chunk adds, and nothing else.
    $script:NewExport = @('Invoke-RemovalPlan', 'Undo-RemovalAction')

    # ---- the source, comment-blanked, and the AST --------------------------
    #
    # Same machinery as tests\RemovalDispatcher.Tests.ps1 and
    # tests\ActionLog.Tests.ps1. Repeated rather than shared because a
    # source-scanning assertion that lives somewhere else is one refactor away
    # from scanning nothing, and this is the assertion the chunk rests on.
    $script:Raw = [System.IO.File]::ReadAllText($script:SourcePath)
    $script:Tokens = $null
    $script:Errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:SourcePath, [ref] $script:Tokens, [ref] $script:Errors)

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
    $script:Code = $builder.ToString()

    $script:Invoked = [string[]] @(
        $script:Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object {
            $element = $_.CommandElements[0]
            if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $element.Value } else { "<dynamic:$($element.Extent.Text)>" }
        } | Sort-Object -Unique
    )

    function Get-ExecutorFunctionAst {
        param([Parameter(Mandatory)] [string] $Name)
        @($script:Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | Where-Object { $_.Name -eq $Name })
    }

    function Get-CommandAstIn {
        param(
            [Parameter(Mandatory)] $Scope,
            [Parameter(Mandatory)] [string] $Name
        )
        @($Scope.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | Where-Object { $_.GetCommandName() -eq $Name } | Sort-Object { $_.Extent.StartOffset })
    }

    # ---- fixtures ----------------------------------------------------------

    $script:LedgerCounter = 0
    function New-LedgerPath {
        $script:LedgerCounter++
        Join-Path $script:Scratch ("ledger-{0:d3}-{1}.jsonl" -f $script:LedgerCounter, [guid]::NewGuid().ToString('N'))
    }

    # A service name nothing on this or any machine has. Every fabricated plan
    # below points at it, so a gate that failed open would meet a key that is not
    # there and be refused by the write path itself.
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
            -Evidence 'Fabricated by the test suite so this route can be exercised.' `
            -Confidence $Confidence -RequiresConsent:$RequiresConsent -RemovalMethod $RemovalMethod
    }

    # A plan that never went near the dispatcher, because the premise of the plan
    # contract is that a plan is data and can arrive from a log or a GUI.
    function New-FabricatedPlan {
        param(
            [Parameter(Mandatory)] [string] $Route,
            [Parameter(Mandatory)] [string] $Category,
            [Parameter(Mandatory)] [string] $RemovalMethod,
            [string] $Id = 'fabricated-plan',
            [string] $DisplayName = 'Fabricated plan',
            [bool] $Supported = $true,
            [string] $CurrentState = 'Present',
            [string] $UnsupportedReason = $null,
            [bool] $RequiresElevation = $false,
            [bool] $IsReversible = $false,
            [AllowNull()] $RollbackData = $null,
            [AllowEmptyCollection()] [psobject[]] $Step = @()
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
            UnsupportedReason = $UnsupportedReason
            CurrentState      = $CurrentState
            VerifiedUtc       = [datetime]::UtcNow.ToString('o')
            RequiresElevation = $RequiresElevation
            RequiresConsent   = $true
            SafetyLabel       = 'Review needed'
            IsReversible      = $IsReversible
            Step              = [psobject[]] @($Step)
            RollbackData      = $RollbackData
            Note              = [string[]] @()
            PreviewText       = [string[]] @('Fabricated.')
        }
    }

    # A Present ServiceStartupType plan, in the exact shape Add-RemovalServiceRoute
    # produces -- but for a service that does not exist.
    function New-FabricatedServicePlan {
        param(
            [string] $ServiceName = (New-AbsentServiceName),
            [int] $PreviousStartValue = 2,
            [int] $PlannedStartValue = 4,
            [bool] $PreviousDelayedAutostart = $false,
            [string] $CurrentState = 'Present',
            [bool] $WithStep = $true
        )
        $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $step = @()
        if ($WithStep) {
            $step = @([pscustomobject]@{
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
        }
        New-FabricatedPlan -Route 'ServiceStartupType' -Category 'Service' -RemovalMethod 'ServiceDisable' `
            -Id $ServiceName -DisplayName $ServiceName -CurrentState $CurrentState `
            -RequiresElevation $WithStep -IsReversible $true -Step ([psobject[]] $step) `
            -RollbackData ([pscustomobject]@{
                ServiceName              = $ServiceName
                DisplayName              = $ServiceName
                KeyPath                  = $keyPath
                PreviousStartValue       = $PreviousStartValue
                PreviousStartupType      = 'Automatic'
                PreviousDelayedAutostart = $PreviousDelayedAutostart
                Note                     = 'Fabricated.'
            })
    }

    # A verified write record, the shape Write-ExecutorServiceRegistryValue
    # returns, for the tests that stand in for the one real write.
    function New-FakeWriteRecord {
        param(
            [Parameter(Mandatory)] [string] $KeyPath,
            [Parameter(Mandatory)] [string] $ValueName,
            [Parameter(Mandatory)] [int] $Value,
            [AllowNull()] $Previous = 2
        )
        [pscustomobject]@{
            KeyPath              = $KeyPath
            ValueName            = $ValueName
            PreviousValue        = $Previous
            PreviousValuePresent = $true
            WrittenValue         = $Value
            VerifiedValue        = $Value
            IsVerified           = $true
            WrittenUtc           = [datetime]::UtcNow.ToString('o')
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

Describe 'Executor.ps1 writes two registry values and nothing else' {

    It 'parses cleanly' {
        @($script:Errors).Count | Should -Be 0
    }

    It 'contains no <_>' -ForEach @(
        'Remove-', 'Disable-', 'Unregister-', 'Uninstall-',
        'Set-Service', 'Stop-Service', 'Start-Service', 'New-Service',
        'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Item ', 'Clear-Item',
        'Start-Process', 'Invoke-Expression', 'Invoke-Command', 'Invoke-Item', 'Start-Job',
        'cmd /c', 'cmd.exe', 'powershell.exe',
        'Win32_Product', 'Get-WmiObject', 'Get-CimInstance', 'Invoke-CimMethod',
        'File]::Delete', 'Directory]::Delete', 'File]::Move', 'File]::WriteAll',
        'File]::Create', 'File]::AppendAll', 'Set-Acl', 'winget.exe', 'DeleteSubKey', 'DeleteValue'
    ) {
        # P3-C1's list, UNCHANGED, applied to a file that does change the machine.
        # It still passes every line of it: the executor writes two REG_DWORDs
        # through Microsoft.Win32.Registry and does nothing else at all. Comment
        # spans are blanked above, so this is the code alone.
        $script:Code | Should -Not -Match ([regex]::Escape($_)) `
            -Because 'the executor sets a startup type; it does not remove, disable, uninstall, delete or run anything'
    }

    It 'invokes no external process' {
        foreach ($forbidden in 'winget', 'msiexec', 'msiexec.exe', 'rundll32', 'rundll32.exe',
                               'sc', 'sc.exe', 'reg', 'reg.exe', 'net', 'net.exe', 'wmic',
                               'dism', 'dism.exe', 'pnputil', 'takeown', 'icacls',
                               'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe') {
            $script:Invoked | Should -Not -Contain $forbidden -Because "the executor must never run $forbidden"
        }
        foreach ($invoked in $script:Invoked) {
            $invoked | Should -Not -Match '\.(exe|com|bat|cmd|msi|dll|vbs|ps1)$' `
                -Because "the executor invoked '$invoked', which is a program and not a cmdlet"
            $invoked | Should -Not -Match '^(Remove|Disable|Unregister|Uninstall|Stop|Restart|Clear|Set)-' `
                -Because "the executor invoked '$invoked', which is a verb that changes something it was not asked to"
        }
        # No process is started by hand either.
        $script:Code | Should -Not -Match 'ProcessStartInfo'
        $script:Code | Should -Not -Match 'Diagnostics\.Process'
    }

    It 'turns no string into a command' {
        # The dispatcher has exactly one legitimate ampersand (the Finding
        # contract's safety rule); the ledger and the checkpoint have none, and
        # neither has this.
        $ampersand = @($script:Ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            ($node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand -or
             $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot)
        }, $true))
        $ampersand.Count | Should -Be 0
    }

    It 'opens no file, for reading or for writing' {
        # Everything this chunk records goes through the ledger, which is the one
        # file in the project allowed to open a stream.
        foreach ($forbidden in 'FileStream', 'File]::Open', 'File]::WriteAllText', 'File]::AppendAllText',
                               'Set-Content', 'Out-File', 'Add-Content', 'New-Item', 'Move-Item', 'Rename-Item') {
            $script:Code | Should -Not -Match ([regex]::Escape($forbidden))
        }
    }

    It 'declares the two writable value names as a ValidateSet the shell enforces' {
        # THE CENTRAL CLAIM OF THIS CHUNK, read out of the parameter attribute
        # rather than out of a comment: a future edit that tried to write a third
        # value name would fail at run time, not merely fail a source scan.
        $function = Get-ExecutorFunctionAst -Name 'Write-ExecutorServiceRegistryValue'
        $function.Count | Should -Be 1

        $parameter = @($function[0].Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Name' })
        $parameter.Count | Should -Be 1

        $validateSet = @($parameter[0].Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' })
        $validateSet.Count | Should -Be 1

        $allowed = [string[]] @($validateSet[0].PositionalArguments | ForEach-Object { $_.Value })
        $allowed.Count | Should -Be 2
        $allowed | Should -Contain 'Start'
        $allowed | Should -Contain 'DelayedAutostart'
    }

    It 'refuses a value name outside that set, at run time' {
        {
            InModuleScope Win11Optimizer.Engine {
                Write-ExecutorServiceRegistryValue -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Services\anything' -Name 'ImagePath' -Value 1
            }
        } | Should -Throw
    }

    It 'sets exactly one registry value, in exactly one function' {
        ([regex]::Matches($script:Code, '\.SetValue\(')).Count | Should -Be 1

        $function = Get-ExecutorFunctionAst -Name 'Write-ExecutorServiceRegistryValue'
        $setValue = @($script:Ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            [string] $node.Member.Value -eq 'SetValue'
        }, $true))
        $setValue.Count | Should -Be 1
        $setValue[0].Extent.StartOffset | Should -BeGreaterThan $function[0].Extent.StartOffset
        $setValue[0].Extent.EndOffset   | Should -BeLessThan $function[0].Extent.EndOffset
    }

    It 'opens a registry key for writing in exactly one place, and never with the boolean overload' {
        # The boolean overload asks for the full write-access set. The explicit
        # rights overload asks for SetValue and QueryValues and nothing else, and
        # says so where anyone auditing this can read it.
        ([regex]::Matches($script:Code, 'ReadWriteSubTree')).Count | Should -Be 1
        $script:Code | Should -Not -Match 'OpenSubKey\([^)]*\$true'
        $script:Code | Should -Match 'RegistryRights\]::SetValue'
        $script:Code | Should -Match 'RegistryKeyPermissionCheck\]::ReadSubTree'

        $function = Get-ExecutorFunctionAst -Name 'Write-ExecutorServiceRegistryValue'
        $offset = $script:Code.IndexOf('ReadWriteSubTree')
        $offset | Should -BeGreaterThan $function[0].Extent.StartOffset
        $offset | Should -BeLessThan $function[0].Extent.EndOffset
    }

    It 'creates no registry key and deletes no registry value' {
        foreach ($forbidden in 'CreateSubKey', 'DeleteSubKey', 'DeleteValue', 'DeleteSubKeyTree', 'SetAccessControl') {
            $script:Code | Should -Not -Match ([regex]::Escape($forbidden))
        }
    }

    It 'writes the Intent to the ledger BEFORE the first registry write, in <_>' -ForEach @('Invoke-RemovalPlan', 'Undo-RemovalAction') {
        # The gate, asserted structurally as well as behaviourally. An action that
        # cannot be recorded must not be attempted, and "must not" is an ordering
        # claim about this source.
        $name = $_
        $function = Get-ExecutorFunctionAst -Name $name
        $function.Count | Should -Be 1

        $ledgerCall = Get-CommandAstIn -Scope $function[0] -Name 'Write-OptimizerAction'
        $writeCall  = Get-CommandAstIn -Scope $function[0] -Name 'Write-ExecutorServiceRegistryValue'

        $ledgerCall.Count | Should -BeGreaterThan 0
        $writeCall.Count  | Should -BeGreaterThan 0
        $ledgerCall[0].Extent.StartOffset | Should -BeLessThan $writeCall[0].Extent.StartOffset

        # And the first one is the Intent: RecordKind defaults to Intent, so the
        # first ledger call in each function must not name a different kind.
        $arguments = [string[]] @($ledgerCall[0].CommandElements | ForEach-Object { $_.Extent.Text })
        $arguments | Should -Not -Contain '-RecordKind'
    }

    It 'is ASCII only, in every file this chunk touches' {
        # One non-ASCII character in a comment fails a whole container under 5.1
        # only, and the error names a line in the test harness rather than the
        # character. docs\REVIEW.md, after P3-C1a.
        foreach ($path in @($script:SourcePath, $PSCommandPath, $script:ManifestPath, $script:ModulePath)) {
            $text = [System.IO.File]::ReadAllText($path)
            $bad  = @([regex]::Matches($text, '[^\x20-\x7E\t\r\n]'))
            $bad.Count | Should -Be 0 -Because "$(Split-Path $path -Leaf) must be ASCII only; first offender at offset $(if ($bad.Count -gt 0) { $bad[0].Index } else { -1 })"
        }
    }
}

Describe 'The write path refuses any key that is not one service key' {

    It 'refuses <_>' -ForEach @(
        'HKCU:\SOFTWARE\Anything'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SYSTEM\CurrentControlSet\Services'
        'HKLM:\SYSTEM\CurrentControlSet\Services\Foo\Parameters'
        'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Foo'
        ''
    ) {
        # A ledger is data. It can be hand-edited, or arrive from another machine,
        # so the key path a rollback record carries is checked and never trusted.
        $path = $_
        $parts = InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $path } {
            Get-ExecutorServiceKeyPart -KeyPath $Path
        }
        $null -eq $parts | Should -BeTrue
    }

    It 'accepts exactly one service key, and splits it for the .NET call' {
        $parts = InModuleScope Win11Optimizer.Engine {
            Get-ExecutorServiceKeyPart -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Example Service'
        }
        $parts | Should -Not -BeNullOrEmpty
        $parts.SubKey      | Should -Be 'SYSTEM\CurrentControlSet\Services\Example Service'
        $parts.ServiceName | Should -Be 'Example Service'
    }

    It 'throws rather than writing when handed a key outside the services root' {
        {
            InModuleScope Win11Optimizer.Engine {
                Write-ExecutorServiceRegistryValue -KeyPath 'HKCU:\SOFTWARE\win11-optimizer-should-never-happen' -Name 'Start' -Value 4
            }
        } | Should -Throw -ExpectedMessage '*only ever writes to a single service key*'
    }

    It 'throws rather than creating a service key that is not there' {
        # The property that makes every fabricated plan in this file safe: if a
        # gate ever failed open, this is what the write would meet.
        $name = New-AbsentServiceName
        {
            InModuleScope Win11Optimizer.Engine -Parameters @{ ServiceName = $name } {
                Write-ExecutorServiceRegistryValue -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name 'Start' -Value 4
            }
        } | Should -Throw -ExpectedMessage '*is not there*'
    }

    It 'reads a key that is not there as absent, and one it cannot parse as unreadable' {
        $name = New-AbsentServiceName
        $state = InModuleScope Win11Optimizer.Engine -Parameters @{ ServiceName = $name } {
            [pscustomobject]@{
                Absent     = Get-ExecutorServiceRegistryState -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
                Unreadable = Get-ExecutorServiceRegistryState -KeyPath 'HKCU:\SOFTWARE\nope'
            }
        }
        # $false is "it is not there"; $null is "we could not look". Never mixed.
        $state.Absent.Exists     | Should -BeFalse
        $null -eq $state.Unreadable.Exists | Should -BeTrue
        $state.Unreadable.Reason | Should -Not -BeNullOrEmpty
    }
}

Describe 'Only ServiceStartupType executes' {

    It 'refuses the <_> route, naming it' -ForEach @(
        'AppxPackage', 'RegistryUninstallString', 'PackageManagement',
        'StartupApproved', 'ScheduledTask', 'JunkFileSet', 'Unsupported'
    ) {
        $route = $_
        $ledger = New-LedgerPath
        $plan = New-FabricatedPlan -Route $route -Category 'OemBloatware' -RemovalMethod 'Appx' -DisplayName 'Fabricated row'
        $result = Invoke-RemovalPlan -Plan $plan -LedgerPath $ledger -Confirm:$false

        $result.Result    | Should -Be 'Refused'
        $result.Performed | Should -BeFalse
        $result.Reason    | Should -Match ([regex]::Escape($route))
        $result.Reason    | Should -Match 'ServiceStartupType'
        Test-Path -LiteralPath $ledger | Should -BeFalse -Because 'a refusal changes nothing, so it records nothing'
    }

    It 'refuses a real junk plan built by the dispatcher' {
        $folder = Join-Path $script:Scratch ('junk-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $folder -ItemType Directory -Force
        $file = Join-Path $folder 'file.tmp'
        [System.IO.File]::WriteAllText($file, 'xxxx')

        $finding = New-Finding -Category JunkFile -Id 'fabricated-location' -DisplayName 'Fabricated junk location' `
            -Evidence 'Fabricated by the test suite.' -Confidence Known -RequiresConsent -RemovalMethod FileDelete
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFile' -Value ([psobject[]] @([pscustomobject]@{
            Path = $file; SizeBytes = [long] 4; LastWriteUtc = [datetime]::UtcNow.AddDays(-30); LocationId = 'fabricated-location' }))
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFileCount' -Value 1
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleBytes'     -Value ([long] 4)
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationId'        -Value 'fabricated-location'
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationPath'      -Value ([string[]] @($folder))
        $finding | Add-Member -MemberType NoteProperty -Name 'IsSizeFloor'       -Value $false
        $finding | Add-Member -MemberType NoteProperty -Name 'MinimumAgeDays'    -Value 7

        $ledger = New-LedgerPath
        $result = Get-RemovalPlan -Finding $finding | Invoke-RemovalPlan -LedgerPath $ledger -Confirm:$false

        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'JunkFileSet'
        Test-Path -LiteralPath $file | Should -BeTrue -Because 'the file this tool refused to delete is still there'
        Test-Path -LiteralPath $ledger | Should -BeFalse
    }

    It 'refuses a real Appx plan built by the dispatcher' {
        $appx = @(Get-AppxPackage -ErrorAction SilentlyContinue |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.PackageFamilyName) } | Select-Object -First 1)
        $finding = $(if ($appx.Count -gt 0) {
                New-TestFinding -Category OemBloatware -Id ([string] $appx[0].PackageFamilyName) `
                    -DisplayName ([string] $appx[0].Name) -RemovalMethod Appx
            } else {
                New-TestFinding -Category OemBloatware -Id 'Fabricated.Package_8wekyb3d8bbwe' -RemovalMethod Appx
            })

        $ledger = New-LedgerPath
        $result = Get-RemovalPlan -Finding $finding | Invoke-RemovalPlan -LedgerPath $ledger -Confirm:$false

        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'AppxPackage'
        Test-Path -LiteralPath $ledger | Should -BeFalse
    }

    It 'refuses an object that is not a plan at all, rather than throwing' {
        $result = Invoke-RemovalPlan -Plan ([pscustomobject]@{ Looks = 'nothing like a plan' }) -LedgerPath (New-LedgerPath) -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'not a removal plan'
    }

    It 'refuses a null plan rather than dropping it' {
        $result = Invoke-RemovalPlan -Plan $null -LedgerPath (New-LedgerPath) -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'Plan is null'
    }

    It 'does not let one refused plan cost the caller the others' {
        # ONE PLAN IN, ONE RESULT OUT, ALWAYS -- the mirror of Get-RemovalPlan's
        # contract, so a batch of twenty never loses nineteen.
        $ledger = New-LedgerPath
        $plans = @(
            (New-FabricatedPlan -Route 'JunkFileSet' -Category 'JunkFile' -RemovalMethod 'FileDelete')
            ([pscustomobject]@{ not = 'a plan' })
            (New-FabricatedPlan -Route 'AppxPackage' -Category 'OemBloatware' -RemovalMethod 'Appx')
        )
        $results = @($plans | Invoke-RemovalPlan -LedgerPath $ledger -Confirm:$false)
        $results.Count | Should -Be 3
        @($results | Where-Object { $_.Result -eq 'Refused' }).Count | Should -Be 3
    }
}

Describe 'The refusal ladder, in the order the handoff fixed' {

    It 'reports the route refusal before the unsupported one' {
        $plan = New-FabricatedPlan -Route 'AppxPackage' -Category 'OemBloatware' -RemovalMethod 'Appx' `
            -Supported $false -UnsupportedReason 'A reason that must not be the one reported.'
        $result = Invoke-RemovalPlan -Plan $plan -LedgerPath (New-LedgerPath) -Confirm:$false
        $result.Reason | Should -Match 'one kind of change only'
        $result.Reason | Should -Not -Match 'must not be the one reported'
    }

    It 'reports the unsupported refusal before the Unverifiable one, quoting the plan''s own reason' {
        $plan = New-FabricatedPlan -Route 'ServiceStartupType' -Category 'Service' -RemovalMethod 'ServiceDisable' `
            -Supported $false -CurrentState 'Unverifiable' -UnsupportedReason 'The service key could not be read.'
        $result = Invoke-RemovalPlan -Plan $plan -LedgerPath (New-LedgerPath) -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'The service key could not be read'
        $result.Reason | Should -Match 'says nothing can be done'
    }

    It 'refuses an Unverifiable plan, and the gate is here rather than in a caller' {
        # P3-C1 locked that Unverifiable is never collapsed into AlreadyGone.
        # This is the other half: it is not collapsed into Present either, and the
        # check lives where the damage would happen.
        $plan = New-FabricatedServicePlan -CurrentState 'Unverifiable'
        $result = Invoke-RemovalPlan -Plan $plan -LedgerPath (New-LedgerPath) -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'could not be read'
        $result.Reason | Should -Match 'Nothing is assumed either way'
    }

    It 'refuses a plan the machine no longer agrees with, and says what changed' {
        # The fabricated plan claims a service is Present; re-checking against this
        # machine finds it was never there. That disagreement is the refusal.
        $plan = New-FabricatedServicePlan
        $result = Invoke-RemovalPlan -Plan $plan -LedgerPath (New-LedgerPath) -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'not in the state the plan was made against'
        $result.Reason | Should -Match 'CurrentState'
        $result.Reason | Should -Match 'AlreadyGone'
    }

    It 'treats a re-verification that cannot be performed as a disagreement, never as agreement' {
        $problems = InModuleScope Win11Optimizer.Engine {
            Mock Get-RemovalPlan { throw 'the dispatcher fell over' }
            $plan = [pscustomobject]@{
                FindingId = 'x'; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = 'x'; Confidence = 'Known'; RequiresConsent = $true
            }
            [string[]] @(Get-ExecutorPlanDisagreement -Plan $plan)
        }
        $problems.Count | Should -BeGreaterThan 0
        $problems -join ' ' | Should -Match 'fell over'
    }

    It 'refuses when the plan needs administrator rights and this process has none' {
        $result = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = (New-LedgerPath) } {
            Mock Test-IsElevated { $false }
            Mock Get-ExecutorPlanDisagreement { [string[]] @() }
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = 'w11o-absent-service'; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = 'w11o-absent-service'; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @(); RollbackData = $null; Note = [string[]] @(); PreviewText = [string[]] @()
            }
            Invoke-RemovalPlan -Plan $plan -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint
        }
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'administrator'
        $result.Reason | Should -Match 'Nothing was attempted'
    }

    It 'reports the Unverifiable refusal before the elevation one' {
        $result = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = (New-LedgerPath) } {
            Mock Test-IsElevated { $false }
            Mock Get-ExecutorPlanDisagreement { [string[]] @() }
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = 'w11o-absent-service'; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = 'w11o-absent-service'; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Unverifiable'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @(); RollbackData = $null; Note = [string[]] @(); PreviewText = [string[]] @()
            }
            Invoke-RemovalPlan -Plan $plan -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint
        }
        # Both refusals mention administrator rights -- the Unverifiable one
        # suggests re-running the scan elevated -- so the assertion is on which
        # refusal fired, not on a word they share.
        $result.Reason | Should -Match 'Nothing is assumed either way'
        $result.Reason | Should -Not -Match 'not running as administrator'
    }

    It 'never writes a ledger record for any refusal' {
        # An executor refusal changed nothing. An Intent with no Outcome reads back
        # as 'OutcomeUnknown' -- "attempted, outcome unknown" -- which would be a
        # lie about the one state this project is most careful with.
        $ledger = New-LedgerPath
        $null = Invoke-RemovalPlan -Plan (New-FabricatedPlan -Route 'JunkFileSet' -Category 'JunkFile' -RemovalMethod 'FileDelete') -LedgerPath $ledger -Confirm:$false
        $null = Invoke-RemovalPlan -Plan (New-FabricatedServicePlan -CurrentState 'Unverifiable') -LedgerPath $ledger -Confirm:$false
        $null = Invoke-RemovalPlan -Plan (New-FabricatedServicePlan) -LedgerPath $ledger -Confirm:$false
        Test-Path -LiteralPath $ledger | Should -BeFalse
    }
}

Describe 'AlreadyGone is a success with an empty step list' {

    BeforeAll {
        # A real plan, from the real dispatcher, for a service that is genuinely
        # not registered. It is Supported, AlreadyGone, needs no elevation and has
        # no steps -- so it exercises the whole Intent/Outcome path end to end
        # without touching this PC.
        $script:GonePlan = Get-RemovalPlan -Finding (New-TestFinding -Category Service `
            -Id (New-AbsentServiceName) -RemovalMethod ServiceDisable -RequiresConsent)
    }

    It 'is planned as a supported AlreadyGone with no steps' {
        $script:GonePlan.Supported         | Should -BeTrue
        $script:GonePlan.CurrentState      | Should -Be 'AlreadyGone'
        $script:GonePlan.RequiresElevation | Should -BeFalse
        @($script:GonePlan.Step).Count     | Should -Be 0
    }

    It 'succeeds, performs nothing, and says why' {
        $ledger = New-LedgerPath
        $result = Invoke-RemovalPlan -Plan $script:GonePlan -LedgerPath $ledger -Confirm:$false

        $result.Result             | Should -Be 'Succeeded'
        $result.Performed          | Should -BeFalse
        @($result.StepResult).Count | Should -Be 0
        ($result.Note -join ' ')   | Should -Match 'nothing to change'
        $result.ActionId           | Should -Not -BeNullOrEmpty
    }

    It 'records an Intent and an Outcome, and the ledger reads back Succeeded' {
        $ledger = New-LedgerPath
        $result = Invoke-RemovalPlan -Plan $script:GonePlan -LedgerPath $ledger -Confirm:$false

        @([System.IO.File]::ReadAllLines($ledger)).Count | Should -Be 2
        $entry = @(Get-OptimizerActionLog -Path $ledger -ActionId $result.ActionId | Where-Object { -not $_.IsParseError })
        $entry.Count           | Should -Be 1
        $entry[0].HasIntent    | Should -BeTrue
        $entry[0].HasOutcome   | Should -BeTrue
        $entry[0].Result       | Should -Be 'Succeeded'
        $entry[0].Route        | Should -Be 'ServiceStartupType'
    }

    It 'takes no restore point for a plan with nothing to do' {
        # A twelve-second checkpoint for a no-op is a cost with no matching risk.
        $taken = InModuleScope Win11Optimizer.Engine -Parameters @{ Plan = $script:GonePlan; Ledger = (New-LedgerPath) } {
            $script:ExecutorRestorePoint = $null
            Mock New-OptimizerRestorePoint { [pscustomobject]@{ State = 'Created'; Reason = $null } }
            $null = Invoke-RemovalPlan -Plan $Plan -LedgerPath $Ledger -Confirm:$false
            $script:ExecutorRestorePoint
        }
        $null -eq $taken | Should -BeTrue
    }
}

Describe '-WhatIf writes nothing at all' {

    It 'writes no ledger record' {
        $ledger = New-LedgerPath
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category Service -Id (New-AbsentServiceName) -RemovalMethod ServiceDisable)
        $result = Invoke-RemovalPlan -Plan $plan -LedgerPath $ledger -WhatIf

        $result.IsWhatIf | Should -BeTrue
        $result.Result   | Should -Be 'Skipped'
        $result.Reason   | Should -Match 'Nothing was written'
        $result.ActionId | Should -BeNullOrEmpty
        Test-Path -LiteralPath $ledger | Should -BeFalse
    }

    It 'writes no registry value and takes no restore point' {
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = (New-LedgerPath); ServiceName = (New-AbsentServiceName) } {
            $script:ExecutorRestorePoint = $null
            Mock Test-IsElevated { $true }
            Mock Get-ExecutorPlanDisagreement { [string[]] @() }
            Mock Write-ExecutorServiceRegistryValue { throw 'the executor must write nothing under -WhatIf' }
            Mock New-OptimizerRestorePoint { throw 'the executor must take no checkpoint under -WhatIf' }
            Mock Get-ExecutorServiceRunState { 'Stopped' }

            $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = $ServiceName; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = $ServiceName; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @([pscustomobject]@{
                    Kind = 'ServiceStartupTypeChange'; Description = 'x'; Target = $ServiceName
                    RequiresElevation = $true; ReverseHint = 'x'
                    Detail = [pscustomobject]@{ KeyPath = $keyPath; PreviousStartValue = 2; PlannedStartValue = 4 }
                })
                RollbackData = [pscustomobject]@{ ServiceName = $ServiceName; KeyPath = $keyPath; PreviousStartValue = 2; PreviousDelayedAutostart = $false }
                Note = [string[]] @(); PreviewText = [string[]] @()
            }
            $result = Invoke-RemovalPlan -Plan $plan -LedgerPath $Ledger -WhatIf
            [pscustomobject]@{
                Result       = $result
                LedgerExists = (Test-Path -LiteralPath $Ledger)
                Checkpoint   = $script:ExecutorRestorePoint
            }
        }

        $observed.Result.IsWhatIf | Should -BeTrue
        $observed.LedgerExists    | Should -BeFalse
        $null -eq $observed.Checkpoint | Should -BeTrue
    }
}

Describe 'A failed Intent write leaves the machine untouched' {

    It 'does not reach the registry write when the ledger will not accept the Intent' {
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ ServiceName = (New-AbsentServiceName) } {
            Mock Test-IsElevated { $true }
            Mock Get-ExecutorPlanDisagreement { [string[]] @() }
            Mock Get-ExecutorServiceRunState { 'Stopped' }
            Mock Write-ExecutorServiceRegistryValue { throw 'THE GATE FAILED: the registry was written after the Intent could not be.' }
            Mock Write-OptimizerAction { throw 'The action ledger could not be written after 200 attempts.' }

            $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = $ServiceName; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = $ServiceName; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @([pscustomobject]@{
                    Kind = 'ServiceStartupTypeChange'; Description = 'x'; Target = $ServiceName
                    RequiresElevation = $true; ReverseHint = 'x'
                    Detail = [pscustomobject]@{ KeyPath = $keyPath; PreviousStartValue = 2; PlannedStartValue = 4 }
                })
                RollbackData = [pscustomobject]@{ ServiceName = $ServiceName; KeyPath = $keyPath; PreviousStartValue = 2; PreviousDelayedAutostart = $false }
                Note = [string[]] @(); PreviewText = [string[]] @()
            }
            $result = Invoke-RemovalPlan -Plan $plan -LedgerPath 'C:\w11o-there-is-no-such-place\actions.jsonl' -Confirm:$false -SkipRestorePoint -WarningAction SilentlyContinue
            # THE GATE. If the Intent cannot be written, the work does not happen.
            Should -Invoke Write-ExecutorServiceRegistryValue -Times 0 -Exactly
            $result
        }

        $observed.Result    | Should -Be 'Failed'
        $observed.Performed | Should -BeFalse
        $observed.ActionId  | Should -BeNullOrEmpty
        $observed.Reason    | Should -Match 'Nothing on this PC was changed'
        $observed.Reason    | Should -Match 'could not be written to the action log'
    }

    It 'reports the real ledger failure rather than a stack trace, and warns' {
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category Service -Id (New-AbsentServiceName) -RemovalMethod ServiceDisable)
        # A volume that is not there, so this is the REAL ledger throwing rather
        # than a mock standing in for it.
        #
        # It used to be slow -- the append retry loop caught [IOException], and
        # DirectoryNotFoundException is one, so a bad path was retried 200 times
        # for ~3.2 s before giving up. Fixed in P4-C1 part A; the ledger now
        # throws immediately for a directory that is not there. What this test
        # asserts is unchanged, because what the executor does with the failure
        # was always right: it refuses, and nothing is attempted.
        $result = Invoke-RemovalPlan -Plan $plan -LedgerPath 'Z:\w11o-no-such-volume\actions.jsonl' `
            -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $result.Result | Should -Be 'Failed'
        $result.Reason | Should -Match 'must not be attempted'
    }
}

Describe 'Performing a plan: the records it writes' {

    BeforeEach {
        $script:ExecLedger = New-LedgerPath
        $script:ExecService = New-AbsentServiceName
    }

    It 'writes an Intent, then the value, then an Outcome carrying the step result' {
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $script:ExecLedger; ServiceName = $script:ExecService } {
            $script:ExecutorRestorePoint = $null
            Mock Test-IsElevated { $true }
            Mock Get-ExecutorPlanDisagreement { [string[]] @() }
            Mock Get-ExecutorServiceRunState { 'Stopped' }
            Mock New-OptimizerRestorePoint { [pscustomobject]@{ State = 'Throttled'; Reason = 'One already exists inside the frequency window.' } }
            # Stands in for the one real write, which is proved elevated against a
            # real service and pasted in the report.
            Mock Write-ExecutorServiceRegistryValue {
                [pscustomobject]@{
                    KeyPath = $KeyPath; ValueName = $Name; PreviousValue = 2; PreviousValuePresent = $true
                    WrittenValue = $Value; VerifiedValue = $Value; IsVerified = $true
                    WrittenUtc = [datetime]::UtcNow.ToString('o')
                }
            }

            $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = $ServiceName; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = $ServiceName; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @([pscustomobject]@{
                    Kind = 'ServiceStartupTypeChange'; Description = 'x'; Target = $ServiceName
                    RequiresElevation = $true; ReverseHint = 'x'
                    Detail = [pscustomobject]@{ KeyPath = $keyPath; PreviousStartValue = 2; PlannedStartValue = 4 }
                })
                RollbackData = [pscustomobject]@{
                    ServiceName = $ServiceName; DisplayName = $ServiceName; KeyPath = $keyPath
                    PreviousStartValue = 2; PreviousStartupType = 'Automatic'; PreviousDelayedAutostart = $false
                }
                Note = [string[]] @(); PreviewText = [string[]] @()
            }
            Invoke-RemovalPlan -Plan $plan -LedgerPath $Ledger -Confirm:$false
        }

        $observed.Result    | Should -Be 'Succeeded'
        $observed.Performed | Should -BeTrue
        @($observed.StepResult).Count | Should -Be 1
        $observed.StepResult[0].Kind   | Should -Be 'ServiceStartupTypeChange'
        $observed.StepResult[0].Result | Should -Be 'Succeeded'
        @($observed.StepResult[0].Detail.Write).Count | Should -Be 1
        $observed.StepResult[0].Detail.Write[0].ValueName    | Should -Be 'Start'
        $observed.StepResult[0].Detail.Write[0].WrittenValue | Should -Be 4
        $observed.RestorePoint.State | Should -Be 'Throttled'

        # Intent, restore-point Note, Outcome -- three lines, one action.
        @([System.IO.File]::ReadAllLines($script:ExecLedger)).Count | Should -Be 3
        $entry = @(Get-OptimizerActionLog -Path $script:ExecLedger | Where-Object { -not $_.IsParseError })
        $entry.Count         | Should -Be 1
        $entry[0].Result     | Should -Be 'Succeeded'
        $entry[0].HasIntent  | Should -BeTrue
        $entry[0].HasOutcome | Should -BeTrue
        @($entry[0].Note).Count | Should -Be 1
        $entry[0].Note[0].Data.State | Should -Be 'Throttled'
        $entry[0].RollbackData.PreviousStartValue | Should -Be 2
        $entry[0].StepResult[0].Detail.Write[0].WrittenValue | Should -Be 4
    }

    It 'reports a write that did not read back as written as a failed step' {
        # Confirmed by looking, not by the call returning -- the same rule that
        # makes a silently declined restore point Throttled rather than Created.
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $script:ExecLedger; ServiceName = $script:ExecService } {
            Mock Test-IsElevated { $true }
            Mock Get-ExecutorPlanDisagreement { [string[]] @() }
            Mock Get-ExecutorServiceRunState { 'Stopped' }
            Mock Write-ExecutorServiceRegistryValue {
                [pscustomobject]@{
                    KeyPath = $KeyPath; ValueName = $Name; PreviousValue = 2; PreviousValuePresent = $true
                    WrittenValue = $Value; VerifiedValue = 2; IsVerified = $false
                    WrittenUtc = [datetime]::UtcNow.ToString('o')
                }
            }
            $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = $ServiceName; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = $ServiceName; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @([pscustomobject]@{
                    Kind = 'ServiceStartupTypeChange'; Description = 'x'; Target = $ServiceName
                    RequiresElevation = $true; ReverseHint = 'x'
                    Detail = [pscustomobject]@{ KeyPath = $keyPath; PreviousStartValue = 2; PlannedStartValue = 4 }
                })
                RollbackData = [pscustomobject]@{ ServiceName = $ServiceName; KeyPath = $keyPath; PreviousStartValue = 2; PreviousDelayedAutostart = $false }
                Note = [string[]] @(); PreviewText = [string[]] @()
            }
            Invoke-RemovalPlan -Plan $plan -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint
        }

        $observed.Result | Should -Be 'Failed'
        $observed.StepResult[0].Result    | Should -Be 'Failed'
        $observed.StepResult[0].ErrorText | Should -Match 'read back as'
    }

    It 'records that a running service was not stopped' {
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $script:ExecLedger; ServiceName = $script:ExecService } {
            Mock Test-IsElevated { $true }
            Mock Get-ExecutorPlanDisagreement { [string[]] @() }
            Mock Get-ExecutorServiceRunState { 'Running' }
            Mock Write-ExecutorServiceRegistryValue {
                [pscustomobject]@{
                    KeyPath = $KeyPath; ValueName = $Name; PreviousValue = 2; PreviousValuePresent = $true
                    WrittenValue = $Value; VerifiedValue = $Value; IsVerified = $true
                    WrittenUtc = [datetime]::UtcNow.ToString('o')
                }
            }
            $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = $ServiceName; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = $ServiceName; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @([pscustomobject]@{
                    Kind = 'ServiceStartupTypeChange'; Description = 'x'; Target = $ServiceName
                    RequiresElevation = $true; ReverseHint = 'x'
                    Detail = [pscustomobject]@{ KeyPath = $keyPath; PreviousStartValue = 2; PlannedStartValue = 4 }
                })
                RollbackData = [pscustomobject]@{ ServiceName = $ServiceName; KeyPath = $keyPath; PreviousStartValue = 2; PreviousDelayedAutostart = $false }
                Note = [string[]] @(); PreviewText = [string[]] @()
            }
            Invoke-RemovalPlan -Plan $plan -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint
        }
        ($observed.Note -join ' ') | Should -Match 'was NOT stopped'
    }

    It 'performs no step of a kind this build does not do, even inside a service plan' {
        # Fails closed. The route gate should make this unreachable; "unreachable"
        # is a claim about today's code.
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $script:ExecLedger; ServiceName = $script:ExecService } {
            Mock Test-IsElevated { $true }
            Mock Get-ExecutorPlanDisagreement { [string[]] @() }
            Mock Get-ExecutorServiceRunState { 'Stopped' }
            Mock Write-ExecutorServiceRegistryValue { throw 'no step of this kind may be performed' }
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = $ServiceName; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = $ServiceName; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @([pscustomobject]@{
                    Kind = 'FileDeleteSet'; Description = 'x'; Target = 'somewhere'
                    RequiresElevation = $true; ReverseHint = 'x'; Detail = $null
                })
                RollbackData = [pscustomobject]@{ ServiceName = $ServiceName; KeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\x'; PreviousStartValue = 2; PreviousDelayedAutostart = $false }
                Note = [string[]] @(); PreviewText = [string[]] @()
            }
            Invoke-RemovalPlan -Plan $plan -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint
        }
        $observed.StepResult[0].Result    | Should -Be 'Skipped'
        $observed.StepResult[0].ErrorText | Should -Match 'FileDeleteSet'
    }
}

Describe 'Undo-RemovalAction refuses what it cannot know' {

    It 'refuses an action id the ledger has never seen' {
        $result = Undo-RemovalAction -ActionId ([guid]::NewGuid().ToString()) -LedgerPath (New-LedgerPath) -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'nothing recorded to put back'
    }

    It 'refuses an OutcomeUnknown action without guessing whether it happened' {
        # THE ONE THE HANDOFF NAMES. An Intent with no Outcome means "attempted,
        # outcome unknown" and is never collapsed into "did not happen".
        $ledger = New-LedgerPath
        $service = New-AbsentServiceName
        $plan = New-FabricatedServicePlan -ServiceName $service
        $actionId = Write-OptimizerAction -Plan $plan -Path $ledger

        $entry = @(Get-OptimizerActionLog -Path $ledger -ActionId $actionId | Where-Object { -not $_.IsParseError })
        $entry[0].Result | Should -Be 'OutcomeUnknown' -Because 'the fixture has to be the state under test'

        $result = Undo-RemovalAction -ActionId $actionId -LedgerPath $ledger -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'cannot say whether'
        $result.Reason | Should -Match 'not the same as'
        $result.Reason | Should -Match 'will not guess'
        # And it wrote nothing of its own.
        @([System.IO.File]::ReadAllLines($ledger)).Count | Should -Be 1
    }

    It 'refuses an action the ledger recorded as a refusal, because nothing changed' {
        $ledger = New-LedgerPath
        $plan = New-FabricatedPlan -Route 'ServiceStartupType' -Category 'Service' -RemovalMethod 'ServiceDisable' `
            -Supported $false -UnsupportedReason 'Fabricated refusal.'
        $actionId = Write-OptimizerAction -Plan $plan -Path $ledger

        $result = Undo-RemovalAction -ActionId $actionId -LedgerPath $ledger -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'nothing to put back'
    }

    It 'refuses an action on a route this build cannot put back' {
        $ledger = New-LedgerPath
        $plan = New-FabricatedPlan -Route 'JunkFileSet' -Category 'JunkFile' -RemovalMethod 'FileDelete'
        $actionId = Write-OptimizerAction -Plan $plan -Path $ledger
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $actionId -Result Succeeded -Path $ledger

        $result = Undo-RemovalAction -ActionId $actionId -LedgerPath $ledger -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'JunkFileSet'
    }

    It 'refuses an action whose record does not carry the previous startup type' {
        $ledger = New-LedgerPath
        $plan = New-FabricatedPlan -Route 'ServiceStartupType' -Category 'Service' -RemovalMethod 'ServiceDisable' `
            -RollbackData ([pscustomobject]@{ ServiceName = 'x'; KeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\x'; Note = 'no previous value here' })
        $actionId = Write-OptimizerAction -Plan $plan -Path $ledger
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $actionId -Result Succeeded -Path $ledger

        $result = Undo-RemovalAction -ActionId $actionId -LedgerPath $ledger -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'does not carry the startup type'
    }

    It 'refuses a rollback record pointing anywhere but a single service key' {
        $ledger = New-LedgerPath
        $plan = New-FabricatedPlan -Route 'ServiceStartupType' -Category 'Service' -RemovalMethod 'ServiceDisable' `
            -RollbackData ([pscustomobject]@{ ServiceName = 'x'; KeyPath = 'HKCU:\SOFTWARE\somewhere-else'; PreviousStartValue = 2; PreviousDelayedAutostart = $false })
        $actionId = Write-OptimizerAction -Plan $plan -Path $ledger
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $actionId -Result Succeeded -Path $ledger

        $result = Undo-RemovalAction -ActionId $actionId -LedgerPath $ledger -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'not a single service key'
    }

    It 'refuses when the service is no longer registered' {
        $ledger = New-LedgerPath
        $plan = New-FabricatedServicePlan
        $actionId = Write-OptimizerAction -Plan $plan -Path $ledger
        $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $actionId -Result Succeeded -Path $ledger

        $result = Undo-RemovalAction -ActionId $actionId -LedgerPath $ledger -Confirm:$false
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'no longer registered'
    }

    It 'refuses when somebody else has changed the startup type since' {
        # Putting back a value a third party set is not an undo.
        $result = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = (New-LedgerPath); ServiceName = (New-AbsentServiceName) } {
            $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = $ServiceName; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = $ServiceName; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @([pscustomobject]@{
                    Kind = 'ServiceStartupTypeChange'; Description = 'x'; Target = $ServiceName
                    RequiresElevation = $true; ReverseHint = 'x'
                    Detail = [pscustomobject]@{ KeyPath = $keyPath; PreviousStartValue = 2; PlannedStartValue = 4 }
                })
                RollbackData = [pscustomobject]@{
                    ServiceName = $ServiceName; DisplayName = $ServiceName; KeyPath = $keyPath
                    PreviousStartValue = 2; PreviousStartupType = 'Automatic'; PreviousDelayedAutostart = $false
                }
                Note = [string[]] @(); PreviewText = [string[]] @()
            }
            $actionId = Write-OptimizerAction -Plan $plan -Path $Ledger
            $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $actionId -Result Succeeded -Path $Ledger

            # Start is 3 (Manual): neither what this tool wrote (4) nor what it
            # found (2).
            Mock Get-ExecutorServiceRegistryState {
                [pscustomobject]@{ Exists = $true; Start = 3; StartPresent = $true; Delayed = $null; DelayedPresent = $false; Reason = $null }
            }
            Mock Write-ExecutorServiceRegistryValue { throw 'nothing may be written over a third party change' }
            Undo-RemovalAction -ActionId $actionId -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint
        }
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'neither what this tool set it to'
        $result.Reason | Should -Match 'not an undo'
    }

    It 'refuses without administrator rights when a write would be needed' {
        $result = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = (New-LedgerPath); ServiceName = (New-AbsentServiceName) } {
            $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = $ServiceName; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = $ServiceName; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @(); RollbackData = [pscustomobject]@{
                    ServiceName = $ServiceName; DisplayName = $ServiceName; KeyPath = $keyPath
                    PreviousStartValue = 2; PreviousStartupType = 'Automatic'; PreviousDelayedAutostart = $false
                }
                Note = [string[]] @(); PreviewText = [string[]] @()
            }
            $actionId = Write-OptimizerAction -Plan $plan -Path $Ledger
            $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $actionId -Result Succeeded -Path $Ledger `
                -StepResult ([psobject[]] @([pscustomobject]@{ StepIndex = 0; Detail = [pscustomobject]@{ Write = [psobject[]] @([pscustomobject]@{ ValueName = 'Start'; WrittenValue = 4 }) } }))

            Mock Test-IsElevated { $false }
            Mock Get-ExecutorServiceRegistryState {
                [pscustomobject]@{ Exists = $true; Start = 4; StartPresent = $true; Delayed = $null; DelayedPresent = $false; Reason = $null }
            }
            Undo-RemovalAction -ActionId $actionId -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint
        }
        $result.Result | Should -Be 'Refused'
        $result.Reason | Should -Match 'administrator'
    }
}

Describe 'Undo-RemovalAction puts it back' {

    BeforeAll {
        # One fixture, used by the whole Describe: a completed action on a service
        # that does not exist, with the state reads mocked so no registry is
        # touched. The real round trip is in the report.
        function New-CompletedUndoFixture {
            param(
                [Parameter(Mandatory)] [string] $Ledger,
                [Parameter(Mandatory)] [string] $ServiceName,
                [int] $PreviousStartValue = 2,
                [int] $WrittenStartValue = 4,
                [bool] $PreviousDelayed = $false
            )
            $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $plan = [pscustomobject]@{
                PSTypeName = 'Win11Optimizer.RemovalPlan'
                FindingId = $ServiceName; Category = 'Service'; RemovalMethod = 'ServiceDisable'
                DisplayName = $ServiceName; Confidence = 'Known'; Route = 'ServiceStartupType'
                Supported = $true; UnsupportedReason = $null; CurrentState = 'Present'
                VerifiedUtc = [datetime]::UtcNow.ToString('o'); RequiresElevation = $true
                RequiresConsent = $true; SafetyLabel = 'Review needed'; IsReversible = $true
                Step = [psobject[]] @([pscustomobject]@{
                    Kind = 'ServiceStartupTypeChange'; Description = 'x'; Target = $ServiceName
                    RequiresElevation = $true; ReverseHint = 'x'
                    Detail = [pscustomobject]@{ KeyPath = $keyPath; PreviousStartValue = $PreviousStartValue; PlannedStartValue = $WrittenStartValue }
                })
                RollbackData = [pscustomobject]@{
                    ServiceName = $ServiceName; DisplayName = $ServiceName; KeyPath = $keyPath
                    PreviousStartValue = $PreviousStartValue; PreviousStartupType = 'Automatic'
                    PreviousDelayedAutostart = $PreviousDelayed
                }
                Note = [string[]] @(); PreviewText = [string[]] @()
            }
            $actionId = Write-OptimizerAction -Plan $plan -Path $Ledger
            $null = Write-OptimizerAction -Plan $plan -RecordKind Outcome -ActionId $actionId -Result Succeeded -Path $Ledger `
                -StepResult ([psobject[]] @([pscustomobject]@{
                    StepIndex = 0; Kind = 'ServiceStartupTypeChange'; Target = $ServiceName; Result = 'Succeeded'
                    Detail = [pscustomobject]@{ Write = [psobject[]] @([pscustomobject]@{
                        ValueName = 'Start'; PreviousValue = $PreviousStartValue; WrittenValue = $WrittenStartValue
                        VerifiedValue = $WrittenStartValue; IsVerified = $true }) }
                }))
            $actionId
        }
    }

    It 'writes back the recorded previous value, and only Start' {
        $ledger = New-LedgerPath
        $actionId = New-CompletedUndoFixture -Ledger $ledger -ServiceName (New-AbsentServiceName)
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $ledger; ActionId = $actionId } {
            $script:ExecutorRestorePoint = $null
            Mock Test-IsElevated { $true }
            Mock New-OptimizerRestorePoint { [pscustomobject]@{ State = 'Throttled'; Reason = 'x' } }
            Mock Get-ExecutorServiceRegistryState {
                [pscustomobject]@{ Exists = $true; Start = 4; StartPresent = $true; Delayed = $null; DelayedPresent = $false; Reason = $null }
            }
            Mock Write-ExecutorServiceRegistryValue {
                [pscustomobject]@{
                    KeyPath = $KeyPath; ValueName = $Name; PreviousValue = 4; PreviousValuePresent = $true
                    WrittenValue = $Value; VerifiedValue = $Value; IsVerified = $true
                    WrittenUtc = [datetime]::UtcNow.ToString('o')
                }
            }
            Undo-RemovalAction -ActionId $ActionId -LedgerPath $Ledger -Confirm:$false
        }

        $observed.Result         | Should -Be 'Succeeded'
        $observed.Performed      | Should -BeTrue
        $observed.UndoOfActionId | Should -Be $actionId
        $observed.ActionId       | Should -Not -Be $actionId

        $writes = @($observed.StepResult[0].Detail.Write)
        $writes.Count | Should -Be 1
        $writes[0].ValueName    | Should -Be 'Start'
        $writes[0].WrittenValue | Should -Be 2
    }

    It 'writes its own Intent and Outcome pair, carrying the original action id, and rewrites nothing' {
        $ledger = New-LedgerPath
        $actionId = New-CompletedUndoFixture -Ledger $ledger -ServiceName (New-AbsentServiceName)
        $before = @([System.IO.File]::ReadAllLines($ledger))
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $ledger; ActionId = $actionId } {
            Mock Test-IsElevated { $true }
            Mock Get-ExecutorServiceRegistryState {
                [pscustomobject]@{ Exists = $true; Start = 4; StartPresent = $true; Delayed = $null; DelayedPresent = $false; Reason = $null }
            }
            Mock Write-ExecutorServiceRegistryValue {
                [pscustomobject]@{
                    KeyPath = $KeyPath; ValueName = $Name; PreviousValue = 4; PreviousValuePresent = $true
                    WrittenValue = $Value; VerifiedValue = $Value; IsVerified = $true
                    WrittenUtc = [datetime]::UtcNow.ToString('o')
                }
            }
            Undo-RemovalAction -ActionId $ActionId -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint
        }

        # Two new lines, and the two that were there are byte-identical.
        $after = @([System.IO.File]::ReadAllLines($ledger))
        $after.Count | Should -Be ($before.Count + 2)
        for ($i = 0; $i -lt $before.Count; $i++) {
            $after[$i] | Should -Be $before[$i] -Because 'nothing in this ledger is ever rewritten'
        }

        $entries = @(Get-OptimizerActionLog -Path $ledger | Where-Object { -not $_.IsParseError })
        $entries.Count | Should -Be 2

        $original = @($entries | Where-Object { $_.ActionId -eq $actionId })
        $original.Count     | Should -Be 1
        $original[0].Result | Should -Be 'Succeeded' -Because 'the original action still reads exactly as it did'

        $undoEntry = @($entries | Where-Object { $_.ActionId -eq $observed.ActionId })
        $undoEntry.Count      | Should -Be 1
        $undoEntry[0].Result  | Should -Be 'Succeeded'
        $undoEntry[0].HasIntent  | Should -BeTrue
        $undoEntry[0].HasOutcome | Should -BeTrue
        $undoEntry[0].Record[0].Data.IsUndo         | Should -BeTrue
        $undoEntry[0].Record[0].Data.UndoOfActionId | Should -Be $actionId
    }

    It 'writes nothing when the startup type is already back where it was' {
        $ledger = New-LedgerPath
        $actionId = New-CompletedUndoFixture -Ledger $ledger -ServiceName (New-AbsentServiceName)
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $ledger; ActionId = $actionId } {
            # Not elevated, deliberately: an undo with nothing to write must not
            # ask for rights it will not use.
            Mock Test-IsElevated { $false }
            Mock Get-ExecutorServiceRegistryState {
                [pscustomobject]@{ Exists = $true; Start = 2; StartPresent = $true; Delayed = $null; DelayedPresent = $false; Reason = $null }
            }
            Mock Write-ExecutorServiceRegistryValue { throw 'nothing may be written when there is nothing to put back' }
            Undo-RemovalAction -ActionId $ActionId -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint
        }
        $observed.Result    | Should -Be 'Skipped'
        $observed.Performed | Should -BeFalse
        ($observed.Note -join ' ') | Should -Match 'already'
    }

    It 'restores DelayedAutostart only where the record says it was switched on' {
        # PreviousDelayedAutostart is a DERIVED BOOLEAN, so $false cannot tell "the
        # value was 0" from "the key had no such value". Creating a value the
        # service never had would be a change beyond the undo, so $false writes
        # nothing. See the report; this is a gap in the record's shape.
        $ledger = New-LedgerPath
        $serviceName = New-AbsentServiceName
        $onId  = New-CompletedUndoFixture -Ledger $ledger -ServiceName ($serviceName + '-on')  -PreviousDelayed $true
        $offId = New-CompletedUndoFixture -Ledger $ledger -ServiceName ($serviceName + '-off') -PreviousDelayed $false
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $ledger; OnId = $onId; OffId = $offId } {
            Mock Test-IsElevated { $true }
            Mock Get-ExecutorServiceRegistryState {
                [pscustomobject]@{ Exists = $true; Start = 4; StartPresent = $true; Delayed = 0; DelayedPresent = $true; Reason = $null }
            }
            Mock Write-ExecutorServiceRegistryValue {
                [pscustomobject]@{
                    KeyPath = $KeyPath; ValueName = $Name; PreviousValue = 0; PreviousValuePresent = $true
                    WrittenValue = $Value; VerifiedValue = $Value; IsVerified = $true
                    WrittenUtc = [datetime]::UtcNow.ToString('o')
                }
            }
            [pscustomobject]@{
                On  = (Undo-RemovalAction -ActionId $OnId  -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint)
                Off = (Undo-RemovalAction -ActionId $OffId -LedgerPath $Ledger -Confirm:$false -SkipRestorePoint)
            }
        }

        $onNames = [string[]] @($observed.On.StepResult[0].Detail.Write | ForEach-Object { $_.ValueName })
        $onNames | Should -Contain 'Start'
        $onNames | Should -Contain 'DelayedAutostart'

        $offNames = [string[]] @($observed.Off.StepResult[0].Detail.Write | ForEach-Object { $_.ValueName })
        $offNames | Should -Contain 'Start'
        $offNames | Should -Not -Contain 'DelayedAutostart'
    }

    It 'writes nothing at all under -WhatIf' {
        $ledger = New-LedgerPath
        $actionId = New-CompletedUndoFixture -Ledger $ledger -ServiceName (New-AbsentServiceName)
        $before = @([System.IO.File]::ReadAllLines($ledger)).Count
        $observed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $ledger; ActionId = $actionId } {
            Mock Test-IsElevated { $true }
            Mock Get-ExecutorServiceRegistryState {
                [pscustomobject]@{ Exists = $true; Start = 4; StartPresent = $true; Delayed = $null; DelayedPresent = $false; Reason = $null }
            }
            Mock Write-ExecutorServiceRegistryValue { throw 'the undo must write nothing under -WhatIf' }
            Mock New-OptimizerRestorePoint { throw 'the undo must take no checkpoint under -WhatIf' }
            Undo-RemovalAction -ActionId $ActionId -LedgerPath $Ledger -WhatIf
        }
        $observed.IsWhatIf | Should -BeTrue
        $observed.Result   | Should -Be 'Skipped'
        @([System.IO.File]::ReadAllLines($ledger)).Count | Should -Be $before
    }

    It 'builds its undo plan with the dispatcher''s own factories, so it renders like every other plan' {
        $ledger = New-LedgerPath
        $plan = InModuleScope Win11Optimizer.Engine -Parameters @{ ServiceName = (New-AbsentServiceName) } {
            $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $entry = [pscustomobject]@{
                ActionId = 'original-action-id'
                Plan     = [pscustomobject]@{ Confidence = 'Known'; RequiresConsent = $true }
            }
            $live = [pscustomobject]@{ Exists = $true; Start = 4; StartPresent = $true; Delayed = $null; DelayedPresent = $false; Reason = $null }
            New-ExecutorUndoPlan -Entry $entry -ServiceName $ServiceName -DisplayName $ServiceName `
                -KeyPath $keyPath -RestoreStartValue 2 -RestoreDelayed $false -Live $live
        }

        # It is a real plan: the ledger's own validator accepts it.
        @(InModuleScope Win11Optimizer.Engine -Parameters @{ Plan = $plan } { Test-OptimizerActionPlan -Plan $Plan }).Count | Should -Be 0
        $plan.Route        | Should -Be 'ServiceStartupType'
        $plan.Supported    | Should -BeTrue
        $plan.IsReversible | Should -BeTrue
        # Its rollback data is the state right now, so the undo is itself undoable.
        $plan.RollbackData.PreviousStartValue | Should -Be 4
        $plan.Step[0].Detail.PlannedStartValue | Should -Be 2
        ($plan.PreviewText -join ' ') | Should -Match 'undo of action original-action-id'
        ($plan.Note -join ' ')        | Should -Match 'ever rewritten'
    }
}

Describe 'The restore point is taken once and never fails an action' {

    It 'reuses the first result rather than asking Windows again' {
        $observed = InModuleScope Win11Optimizer.Engine {
            $script:ExecutorRestorePoint = $null
            Mock New-OptimizerRestorePoint { [pscustomobject]@{ State = 'Created'; Reason = $null } }
            $first  = Get-ExecutorRestorePoint
            $second = Get-ExecutorRestorePoint
            [pscustomobject]@{ First = $first; Second = $second }
        }
        $observed.First.State  | Should -Be 'Created'
        $observed.Second.State | Should -Be 'Created'
        InModuleScope Win11Optimizer.Engine { $script:ExecutorRestorePoint = $null }
    }

    It 'turns a checkpoint that throws into a Failed state rather than an exception' {
        # New-OptimizerRestorePoint documents that it never throws. This wraps it
        # anyway: an action refused because a checkpoint nobody depends on went
        # wrong is the one thing that must not happen.
        $observed = InModuleScope Win11Optimizer.Engine {
            $script:ExecutorRestorePoint = $null
            Mock New-OptimizerRestorePoint { throw 'the volume shadow copy service is not running' }
            $result = Get-ExecutorRestorePoint
            $script:ExecutorRestorePoint = $null
            $result
        }
        $observed.State  | Should -Be 'Failed'
        $observed.Reason | Should -Match 'volume shadow copy'
        $observed.Reason | Should -Match 'action was not affected'
    }
}

Describe 'The two new exports' {

    It 'lists <_> in the .psm1 and the .psd1, and defines it' -ForEach @('Invoke-RemovalPlan', 'Undo-RemovalAction') {
        # A function missing from the .psd1 is invisible to callers with no error
        # anywhere -- this project's signature failure, in a manifest.
        $name = $_
        [System.IO.File]::ReadAllText($script:ModulePath)   | Should -Match ([regex]::Escape("'$name'"))
        [System.IO.File]::ReadAllText($script:ManifestPath) | Should -Match ([regex]::Escape("'$name'"))
        Get-Command -Module Win11Optimizer.Engine -Name $name -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'adds exactly two, and no more' {
        $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
        $exported = @(Get-Command -Module Win11Optimizer.Engine | ForEach-Object { $_.Name })
        @($manifest.FunctionsToExport).Count | Should -Be $exported.Count
        # THE RUNNING TOTAL IS READ FROM THE .psd1, NOT WRITTEN HERE. It was 34
        # before this chunk (P3-C2's report), 36 after it, 41 when P4-C1 added
        # the review screen's five and 43 when P4-C2 added its two -- and this
        # file and tests\ActionLog.Tests.ps1 were each being hand-edited every
        # chunk to keep a number neither of them is about. The claim this It
        # actually makes -- that THIS chunk added exactly two -- is the line
        # below it, and that one does not move.
        $exported.Count | Should -Be @($manifest.FunctionsToExport).Count
        @($exported | Where-Object { $script:NewExport -contains $_ }).Count | Should -Be 2
    }

    It 'declares SupportsShouldProcess with ConfirmImpact High on both' -ForEach @('Invoke-RemovalPlan', 'Undo-RemovalAction') {
        $command = Get-Command -Module Win11Optimizer.Engine -Name $_
        $command.Parameters.ContainsKey('WhatIf')  | Should -BeTrue
        $command.Parameters.ContainsKey('Confirm') | Should -BeTrue

        $function = Get-ExecutorFunctionAst -Name $_
        $attribute = @($function[0].Body.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' })
        $attribute.Count | Should -Be 1
        $text = $attribute[0].Extent.Text
        $text | Should -Match 'SupportsShouldProcess'
        $text | Should -Match "ConfirmImpact\s*=\s*'High'"
    }
}
