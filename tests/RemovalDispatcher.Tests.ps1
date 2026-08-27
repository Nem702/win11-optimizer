#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the removal dispatcher (chunk P3-C1,
    src\Win11Optimizer.Engine\Removal\Dispatcher.ps1) and for the module loader
    fix that shipped with it.

    The dispatcher is the first thing in this project that describes changing the
    machine, so the first Describe below is the one that matters most: it proves
    the source contains no call that could change anything. Everything else is
    about the two ways a plan can be wrong --

      * it says it CAN act on something it cannot, or
      * it acts on something it must never touch.

    Both are tested against fabricated Findings as well as real ones, because the
    dispatcher's whole premise is that a Finding is just data and can arrive from
    a run log or a GUI rather than from a detector.

    Run:  .\tests\Invoke-Tests.ps1
#>

BeforeAll {
    $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot   = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath   = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:SourcePath   = Join-Path $script:EngineRoot 'Removal\Dispatcher.ps1'

    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-removal-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-removal-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    # A registry area of our own, under HKCU where no elevation is needed. The
    # TEST writes here; the module never does, which is what the source scan
    # below asserts.
    $script:TestRegistryRoot = "HKCU:\SOFTWARE\win11-optimizer-tests\" + [guid]::NewGuid().ToString('N')

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    $script:Contract        = Get-RemovalContract
    $script:FindingContract = Get-FindingContract

    $script:Source = [System.IO.File]::ReadAllText($script:SourcePath)

    # The source with every comment span BLANKED IN PLACE. The "this file never
    # calls X" assertions have to run against this rather than the raw text: this
    # file names Remove-*, Disable-*, Set-Service, Invoke-Expression and cmd /c
    # precisely because it does not do any of them, and PowerShell's -match is
    # case-insensitive, so a prose mention reads exactly like a call.
    #
    # docs\handoff\07-junk-files.report.md section 10 records this biting its own
    # author. Offsets are preserved (only non-newline characters are replaced with
    # spaces) so a positional pattern still matches.
    $script:SourceTokens = $null
    $script:SourceErrors = $null
    $script:SourceAst = [System.Management.Automation.Language.Parser]::ParseFile($script:SourcePath, [ref] $script:SourceTokens, [ref] $script:SourceErrors)

    $builder = New-Object System.Text.StringBuilder $script:Source
    foreach ($token in @($script:SourceTokens | Where-Object { $_.Kind -eq 'Comment' })) {
        $start = $token.Extent.StartOffset
        $length = $token.Extent.EndOffset - $start
        for ($i = 0; $i -lt $length; $i++) {
            if ($builder[$start + $i] -ne "`n" -and $builder[$start + $i] -ne "`r") {
                $builder[$start + $i] = ' '
            }
        }
    }
    $script:SourceCode = $builder.ToString()

    # Every command NAME the source actually invokes, from the AST. Stronger than
    # a grep for the cases where the forbidden thing legitimately appears in a
    # string: this file has to be able to SAY 'msiexec' and 'winget' in a plan
    # step and in a refusal a user reads, while never running either.
    $script:InvokedCommand = [string[]] @(
        $script:SourceAst.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object {
            $element = $_.CommandElements[0]
            if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $element.Value } else { "<dynamic:$($element.Extent.Text)>" }
        } | Sort-Object -Unique
    )

    # A Finding built by hand, so a route can be exercised against input no
    # detector on this machine produces.
    function New-TestFinding {
        param(
            [Parameter(Mandatory)] [string] $Category,
            [Parameter(Mandatory)] [string] $Id,
            [string] $DisplayName = 'Fabricated item',
            [string] $Confidence = 'Known',
            [Parameter(Mandatory)] [string] $RemovalMethod,
            [switch] $RequiresConsent
        )
        New-Finding -Category $Category -Id $Id -DisplayName $DisplayName `
            -Evidence 'Fabricated by the test suite so this route can be exercised on a machine that does not produce one.' `
            -Confidence $Confidence -RequiresConsent:$RequiresConsent -RemovalMethod $RemovalMethod
    }

    function New-TestUninstallKey {
        param(
            [Parameter(Mandatory)] [string] $Name,
            [hashtable] $Value = @{}
        )
        $path = Join-Path $script:TestRegistryRoot $Name
        $null = New-Item -Path $path -Force
        foreach ($key in $Value.Keys) {
            $null = New-ItemProperty -Path $path -Name $key -Value $Value[$key] -PropertyType String -Force
        }
        # The Finding carries the HKEY_* form, because that is what a registry
        # key's .Name property returns and therefore what the detectors record.
        (Get-Item -LiteralPath $path).Name
    }

    function New-TestFile {
        param([string] $Name = ([guid]::NewGuid().ToString('N') + '.tmp'), [int] $Bytes = 64)
        $path = Join-Path $script:Scratch $Name
        [System.IO.File]::WriteAllText($path, ('x' * $Bytes))
        $path
    }

    # A JunkFile Finding with the detector-specific fields attached the way
    # Find-JunkFileLocation attaches them.
    function New-TestJunkFinding {
        param(
            [AllowEmptyCollection()] [string[]] $Path = @(),
            [string] $Id = 'fabricated-location',
            [string[]] $LocationPath = @(),
            [switch] $NoEligibleFile,
            [switch] $IsSizeFloor
        )
        $finding = New-Finding -Category JunkFile -Id $Id -DisplayName 'Fabricated junk location' `
            -Evidence 'Fabricated by the test suite.' -Confidence Known -RequiresConsent -RemovalMethod FileDelete

        if (-not $NoEligibleFile) {
            $files = @($Path | ForEach-Object {
                [pscustomobject]@{
                    Path         = $_
                    SizeBytes    = [long] 64
                    LastWriteUtc = [datetime]::UtcNow.AddDays(-30)
                    LocationId   = $Id
                }
            })
            $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFile'      -Value ([psobject[]] $files)
            $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFileCount' -Value $files.Count
            $finding | Add-Member -MemberType NoteProperty -Name 'EligibleBytes'     -Value ([long] (64 * $files.Count))
        }
        $locations = $LocationPath
        if ($locations.Count -lt 1) { $locations = [string[]] @($script:Scratch) }
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationId'     -Value $Id
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationPath'   -Value ([string[]] $locations)
        $finding | Add-Member -MemberType NoteProperty -Name 'IsSizeFloor'    -Value ([bool] $IsSizeFloor)
        $finding | Add-Member -MemberType NoteProperty -Name 'MinimumAgeDays' -Value 7
        $finding
    }
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

Describe 'Dispatcher.ps1 plans removals and performs none' {

    It 'parses cleanly' {
        @($script:SourceErrors).Count | Should -Be 0
    }

    It 'contains no <_>' -ForEach @(
        'Remove-', 'Disable-', 'Unregister-', 'Uninstall-',
        'Set-Service', 'Stop-Service', 'Start-Service', 'New-Service',
        'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Item ', 'Clear-Item',
        'Start-Process', 'Invoke-Expression', 'Invoke-Command', 'Invoke-Item', 'Start-Job',
        'cmd /c', 'cmd.exe', 'powershell.exe', 'rundll32',
        'Win32_Product', 'Get-WmiObject', 'Get-CimInstance', 'Invoke-CimMethod',
        'File]::Delete', 'Directory]::Delete', 'File]::Move', 'File]::WriteAll',
        'File]::Create', 'File]::AppendAll', 'Set-Acl', 'winget.exe', 'DeleteSubKey', 'DeleteValue'
    ) {
        # Comment spans are blanked above; this is the code alone.
        $script:SourceCode | Should -Not -Match ([regex]::Escape($_)) `
            -Because 'this chunk removes nothing, disables nothing and writes nothing -- naming a command in a plan step is the deliverable, calling one is not'
    }

    It 'invokes no command that could change the machine' {
        # The grep above cannot cover the cases where the forbidden word
        # legitimately appears in a STRING: the dispatcher has to be able to
        # name msiexec in a plan step and winget in a refusal a user reads. So
        # the AST is asked what is actually invoked.
        foreach ($forbidden in 'winget', 'msiexec', 'msiexec.exe', 'sc', 'sc.exe', 'reg', 'reg.exe', 'dism', 'dism.exe', 'pnputil', 'takeown', 'icacls') {
            $script:InvokedCommand | Should -Not -Contain $forbidden
        }
        foreach ($invoked in $script:InvokedCommand) {
            $invoked | Should -Not -Match '^(Remove|Disable|Unregister|Uninstall|Stop|Restart|Clear|Set)-' `
                -Because "the dispatcher invoked '$invoked', which is a verb that changes something"
        }
    }

    It 'uses the call operator exactly once, on the Finding contract''s own safety rule' {
        # An ampersand invocation is how a string becomes a command, so every one
        # of them is checked by hand. The single legitimate use is running the
        # scriptblock Get-FindingContract hands out, which is the whole point of
        # not restating the two-axis safety rule here.
        $ampersand = @($script:SourceAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand
        }, $true))

        $ampersand.Count | Should -Be 1
        $ampersand[0].CommandElements[0].Extent.Text | Should -Be '$contract.SafetyLabelRule'
    }

    It 'never opens a file for anything but reading, and never opens one at all' {
        $script:SourceCode | Should -Not -Match 'FileAccess\]::Write'
        $script:SourceCode | Should -Not -Match 'FileAccess\]::ReadWrite'
        $script:SourceCode | Should -Not -Match 'FileMode\]::Create'
        # The in-use probe lives in Shared\Inventory.ps1 now; this file only ever
        # calls it by name.
        $script:SourceCode | Should -Not -Match 'File\]::Open'
        $script:SourceCode | Should -Match 'Test-OptimizerFileInUse'
    }

    It 'opens registry keys read-only' {
        # OpenSubKey is used once, for the service permission probe, and it asks
        # for ReadPermissions on a ReadSubTree handle.
        $script:SourceCode | Should -Not -Match 'OpenSubKey\([^)]*\$true'
        $script:SourceCode | Should -Match 'RegistryKeyPermissionCheck\]::ReadSubTree'
        $script:SourceCode | Should -Match 'RegistryRights\]::ReadPermissions'
    }

    It 'reads registry value names with (Get-Item).Property, never with Get-ItemProperty' {
        # REVIEW.md: Get-ItemProperty prints nothing at all, with no error, for a
        # key that has no values, which is indistinguishable from a key that is
        # not there. Three of the seven routes read registry values.
        $script:SourceCode | Should -Not -Match 'Get-ItemProperty\b'
        $script:SourceCode | Should -Match 'Get-ItemPropertyValue'
    }
}

Describe 'Get-RemovalContract: the vocabulary, stated once' {

    It 'is exported from the .psm1 and the .psd1' -ForEach @('Get-RemovalContract', 'Get-RemovalPlan', 'Get-RemovalPreview') {
        # Missing from the second makes a function silently invisible to callers,
        # which is on REVIEW.md's failure-mode list.
        [System.IO.File]::ReadAllText($script:ModulePath) | Should -Match ([regex]::Escape("'$_'"))
        [System.IO.File]::ReadAllText($script:ManifestPath) | Should -Match ([regex]::Escape("'$_'"))
        (Get-Command -Module Win11Optimizer.Engine -Name $_ -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }

    It 'publishes the seven routes' {
        @($script:Contract.RouteIds).Count | Should -Be 7
        $script:Contract.UnsupportedRoute | Should -Be 'Unsupported'
        @($script:Contract.RouteIds) | Should -Not -Contain 'Unsupported'
    }

    It 'publishes the step kinds and the four current states' {
        @($script:Contract.CurrentStates) | Should -Be @('Present', 'AlreadyGone', 'Changed', 'Unverifiable')
        @($script:Contract.StepKinds).Count | Should -BeGreaterThan 0
    }

    It 'routes every (Category, RemovalMethod) pair a detector can produce' {
        # Read from the two contracts rather than restated, so a new Category or
        # RemovalMethod cannot be added without this failing.
        $producible = @(
            'OemBloatware|Appx'
            'OemBloatware|RegistryUninstallString'
            'UnusedApp|Appx'
            'UnusedApp|RegistryUninstallString'
            'StartupItem|RegistryRunKey'
            'StartupItem|FileDelete'
            'StartupItem|TaskScheduler'
            'Service|ServiceDisable'
            'JunkFile|FileDelete'
        )
        foreach ($pair in $producible) {
            $script:Contract.Routes.Contains($pair) | Should -BeTrue -Because "$pair is a pair a detector in this project actually emits"
            @($script:Contract.RouteIds) | Should -Contain $script:Contract.Routes[$pair]
        }
    }

    It 'gives PackageManagement a route even though nothing produces it' {
        $script:Contract.Routes.Contains('OemBloatware|PackageManagement') | Should -BeTrue
        $script:Contract.Routes.Contains('UnusedApp|PackageManagement') | Should -BeTrue
    }

    It 'routes FileDelete to two different places depending on the category' {
        # The reason the table is keyed on the PAIR. StartupItem + FileDelete is
        # one shortcut that gets switched off; JunkFile + FileDelete is a set of
        # files that get deleted. Same method string, nothing in common.
        $script:Contract.Routes['StartupItem|FileDelete'] |
            Should -Not -Be $script:Contract.Routes['JunkFile|FileDelete']
    }

    It 'hands out a copy of the route table, not the module''s own' {
        $first = Get-RemovalContract
        $first.Routes['JunkFile|FileDelete'] = 'Tampered'
        (Get-RemovalContract).Routes['JunkFile|FileDelete'] | Should -Not -Be 'Tampered'
    }

    It 'still has no Win32_Product in the allowed RemovalMethod set' {
        @($script:FindingContract.RemovalMethods) | Should -Not -Contain 'Win32_Product'
        @($script:FindingContract.RemovalMethods).Count | Should -Be 7
    }
}

Describe 'One input, one plan, always' {

    It 'plans for a Finding that fails Test-Finding without throwing' {
        $broken = [pscustomobject]@{ Category = 'Nope'; Id = ''; RemovalMethod = 'Appx' }
        $plan = $null
        { $script:PlanForBroken = Get-RemovalPlan -Finding $broken } | Should -Not -Throw
        $plan = $script:PlanForBroken

        $plan | Should -Not -BeNullOrEmpty
        $plan.Supported | Should -BeFalse
        $plan.Route | Should -Be 'Unsupported'
        @($plan.Step).Count | Should -Be 0
        $plan.UnsupportedReason | Should -Match 'finding contract'
        $plan.UnsupportedReason | Should -Match 'Category'
    }

    It 'plans for a null Finding rather than dropping it' {
        $plan = Get-RemovalPlan -Finding $null
        $plan | Should -Not -BeNullOrEmpty
        $plan.Supported | Should -BeFalse
    }

    It 'does not let one bad Finding cost the caller the others' {
        $good = @(1..19 | ForEach-Object {
            New-TestFinding -Category OemBloatware -Id "Not.Installed.$_`_8wekyb3d8bbwe" -RemovalMethod Appx
        })
        $batch = @($good[0..8]) + @([pscustomobject]@{ Category = 'Nonsense' }) + @($good[9..18])

        $plans = @($batch | Get-RemovalPlan)
        $plans.Count | Should -Be 20
        @($plans | Where-Object { -not $_.Supported }).Count | Should -Be 1
    }

    It 'fails closed on a (Category, RemovalMethod) pair with no route' {
        # A pair that is legal on the Finding contract and that nothing routes.
        $finding = New-TestFinding -Category JunkFile -Id 'whatever' -RemovalMethod TaskScheduler
        $plan = Get-RemovalPlan -Finding $finding

        $plan.Route | Should -Be 'Unsupported'
        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'no route'
        @($plan.Step).Count | Should -Be 0
    }

    It 'copies the finding''s own fields rather than re-deriving them' {
        $finding = New-TestFinding -Category Service -Id 'NoSuchServiceHere' -DisplayName 'A Name' -RemovalMethod ServiceDisable -RequiresConsent
        $plan = Get-RemovalPlan -Finding $finding

        $plan.FindingId       | Should -Be 'NoSuchServiceHere'
        $plan.Category        | Should -Be 'Service'
        $plan.RemovalMethod   | Should -Be 'ServiceDisable'
        $plan.DisplayName     | Should -Be 'A Name'
        $plan.RequiresConsent | Should -BeTrue
    }

    It 'derives SafetyLabel by running the contract''s rule, never by restating it' {
        foreach ($confidence in 'Known', 'Heuristic') {
            foreach ($consent in $true, $false) {
                $finding = New-TestFinding -Category UnusedApp -Id 'Nothing.Here_8wekyb3d8bbwe' -Confidence $confidence -RemovalMethod Appx -RequiresConsent:$consent
                $plan = Get-RemovalPlan -Finding $finding
                $plan.SafetyLabel | Should -Be (& $script:FindingContract.SafetyLabelRule $confidence $consent)
            }
        }
    }
}

Describe 'The plan survives a JSON round trip' {

    BeforeAll {
        $script:RoundTripSource = New-TestFile
        $script:RoundTripPlan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @($script:RoundTripSource))
        $script:RoundTripBack = $script:RoundTripPlan | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    }

    It 'carries no scriptblock' {
        foreach ($property in $script:RoundTripPlan.PSObject.Properties) {
            $property.Value | Should -Not -BeOfType ([scriptblock])
        }
    }

    It 'keeps Supported, RequiresConsent and the step list intact' {
        $script:RoundTripBack.Supported       | Should -BeOfType ([bool])
        $script:RoundTripBack.Supported       | Should -Be $script:RoundTripPlan.Supported
        $script:RoundTripBack.RequiresConsent | Should -BeOfType ([bool])
        $script:RoundTripBack.RequiresConsent | Should -Be $script:RoundTripPlan.RequiresConsent
        @($script:RoundTripBack.Step).Count   | Should -Be @($script:RoundTripPlan.Step).Count
        $script:RoundTripBack.Step[0].Kind    | Should -Be $script:RoundTripPlan.Step[0].Kind
        $script:RoundTripBack.CurrentState    | Should -Be $script:RoundTripPlan.CurrentState
    }

    It 'still derives SafetyLabel from the contract rule after the round trip' {
        # Both halves the rule reads have to survive, or the label can only be
        # taken on trust from a string in a log file.
        $script:RoundTripBack.SafetyLabel |
            Should -Be (& $script:FindingContract.SafetyLabelRule $script:RoundTripBack.Confidence $script:RoundTripBack.RequiresConsent)
    }

    It 'renders the same preview from the deserialized plan' {
        $before = @($script:RoundTripPlan | Get-RemovalPreview)
        $after  = @($script:RoundTripBack | Get-RemovalPreview)
        ($after -join "`n") | Should -Be ($before -join "`n")
    }

    It 'keeps VerifiedUtc as a string rather than a shell-dependent datetime' {
        # ConvertFrom-Json turns an ISO-8601 string back into a [datetime] under
        # 5.1 and leaves it a string under 7, so the plan stores the string the
        # run log already uses and both shells agree.
        $script:RoundTripPlan.VerifiedUtc | Should -BeOfType ([string])
        [datetime]::Parse($script:RoundTripPlan.VerifiedUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) |
            Should -BeOfType ([datetime])
    }
}

Describe 'Route: RegistryUninstallString' {

    It 'reads the uninstall string at plan time and turns it into a program plus arguments' {
        $key = New-TestUninstallKey -Name 'quiet' -Value @{
            DisplayName            = 'Fabricated App'
            QuietUninstallString   = '"C:\Program Files\Fabricated\unins000.exe" /SILENT /NORESTART'
            UninstallString        = '"C:\Program Files\Fabricated\unins000.exe"'
        }
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id $key -RemovalMethod RegistryUninstallString)

        $plan.Supported    | Should -BeTrue
        $plan.CurrentState | Should -Be 'Present'
        @($plan.Step).Count | Should -Be 1

        $step = $plan.Step[0]
        $step.Kind                | Should -Be 'ProcessCommand'
        $step.Executable          | Should -Be 'C:\Program Files\Fabricated\unins000.exe'
        @($step.Argument)         | Should -Be @('/SILENT', '/NORESTART')
        $step.RequiresInteraction | Should -BeFalse
        $plan.RollbackData.UninstallValueName | Should -Be 'QuietUninstallString'
    }

    It 'marks a plan that has only UninstallString as not silent, and invents no flag' {
        $key = New-TestUninstallKey -Name 'loud' -Value @{
            DisplayName     = 'Fabricated Loud App'
            UninstallString = '"C:\Program Files\Fabricated\setup.exe" --uninstall'
        }
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category UnusedApp -Id $key -Confidence Heuristic -RemovalMethod RegistryUninstallString)

        $plan.Supported | Should -BeTrue
        $plan.Step[0].RequiresInteraction | Should -BeTrue
        @($plan.Step[0].Argument) | Should -Be @('--uninstall')
        # No guessed silent switch.
        @($plan.Step[0].Argument) | Should -Not -Contain '/S'
        @($plan.Step[0].Argument) | Should -Not -Contain '/quiet'
        @($plan.Step[0].Argument) | Should -Not -Contain '/qn'
    }

    It 'rewrites MsiExec /I into the documented /X uninstall form' {
        $key = New-TestUninstallKey -Name 'msi' -Value @{
            DisplayName     = 'Fabricated MSI App'
            UninstallString = 'MsiExec.exe /I{02247819-03CD-414E-AC8D-FD518BFBA445}'
        }
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id $key -RemovalMethod RegistryUninstallString)

        $plan.Supported | Should -BeTrue
        $step = $plan.Step[0]
        $step.Executable | Should -Match 'msiexec\.exe$'
        @($step.Argument) | Should -Be @('/X{02247819-03CD-414E-AC8D-FD518BFBA445}', '/qn', '/norestart')
        $step.Description | Should -Match 'rewritten'
        $step.RequiresInteraction | Should -BeFalse
    }

    It 'keeps a public property the original MsiExec string carried' {
        # Measured on this machine: one Advanced Installer package writes
        # 'msiexec.exe /i {GUID} AI_UNINSTALLER_CTP=1', and the property tells its
        # custom action which mode to run in.
        $key = New-TestUninstallKey -Name 'msiprop' -Value @{
            DisplayName     = 'Fabricated AI App'
            UninstallString = 'msiexec.exe /i {02247819-03CD-414E-AC8D-FD518BFBA445} AI_UNINSTALLER_CTP=1'
        }
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id $key -RemovalMethod RegistryUninstallString)
        @($plan.Step[0].Argument) | Should -Contain 'AI_UNINSTALLER_CTP=1'
    }

    It 'refuses an MsiExec string with no product code rather than inventing one' {
        $key = New-TestUninstallKey -Name 'msinoguid' -Value @{
            DisplayName     = 'Fabricated Broken MSI'
            UninstallString = 'MsiExec.exe /I'
        }
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id $key -RemovalMethod RegistryUninstallString)
        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'product code'
    }

    It 'refuses a key with no usable uninstall value, naming the key' {
        $key = New-TestUninstallKey -Name 'novalue' -Value @{ DisplayName = 'Fabricated Valueless App' }
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id $key -RemovalMethod RegistryUninstallString)

        $plan.Supported | Should -BeFalse
        $plan.CurrentState | Should -Be 'Present'
        $plan.UnsupportedReason | Should -Match ([regex]::Escape($key))
        @($plan.Step).Count | Should -Be 0
    }

    It 'refuses an identifier that is not a registry key in a hive this tool reads' {
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id 'HKEY_CLASSES_ROOT\Nope' -RemovalMethod RegistryUninstallString)
        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'HKEY_LOCAL_MACHINE'
    }

    It 'treats a key that has gone as AlreadyGone -- a success shape, not an error' {
        $key = New-TestUninstallKey -Name 'transient' -Value @{
            DisplayName          = 'Fabricated Transient App'
            QuietUninstallString = '"C:\Program Files\Fabricated\unins000.exe" /SILENT'
        }

        $before = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id $key -RemovalMethod RegistryUninstallString)
        $before.CurrentState | Should -Be 'Present'
        @($before.Step).Count | Should -Be 1

        # The TEST removes the fabricated key. The module never does.
        Remove-Item -LiteralPath (Join-Path $script:TestRegistryRoot 'transient') -Recurse -Force

        $after = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id $key -RemovalMethod RegistryUninstallString)
        $after.CurrentState      | Should -Be 'AlreadyGone'
        $after.Supported         | Should -BeTrue
        $after.UnsupportedReason | Should -BeNullOrEmpty
        @($after.Step).Count     | Should -Be 0
        $after.RequiresElevation | Should -BeFalse
        ($after | Get-RemovalPreview) -join ' ' | Should -Match 'no longer registered'
    }
}

Describe 'The uninstall-string parser' {

    It 'reads a quoted executable path' {
        $parsed = InModuleScope Win11Optimizer.Engine {
            Split-RemovalCommandString -CommandString '"C:\Program Files\App\unins000.exe" /SILENT'
        }
        $parsed.Executable | Should -Be 'C:\Program Files\App\unins000.exe'
        @($parsed.Argument) | Should -Be @('/SILENT')
    }

    It 'reads an UNQUOTED executable path that contains spaces' {
        # The ugly common case: five of this machine's 140 uninstall entries.
        # Splitting on the first space gives 'C:\Program', which is a path that
        # does not exist pointing at a drive root.
        $parsed = InModuleScope Win11Optimizer.Engine {
            Split-RemovalCommandString -CommandString 'C:\Program Files\AMD\RyzenMaster\bin\Setup.exe /U {02247819-03CD-414E-AC8D-FD518BFBA445}'
        }
        $parsed.Executable | Should -Be 'C:\Program Files\AMD\RyzenMaster\bin\Setup.exe'
        @($parsed.Argument) | Should -Be @('/U', '{02247819-03CD-414E-AC8D-FD518BFBA445}')
    }

    It 'reads an unquoted path with spaces and no arguments at all' {
        $parsed = InModuleScope Win11Optimizer.Engine {
            Split-RemovalCommandString -CommandString 'C:\Program Files (x86)\Steam\uninstall.exe'
        }
        $parsed.Executable | Should -Be 'C:\Program Files (x86)\Steam\uninstall.exe'
        @($parsed.Argument).Count | Should -Be 0
    }

    It 'unquotes a quoted value embedded inside one argument' {
        # Blizzard writes --displayname="Battle.net". A receiving process's argv
        # holds --displayname=Battle.net, one argument.
        $parsed = InModuleScope Win11Optimizer.Engine {
            Split-RemovalCommandString -CommandString '"C:\ProgramData\Battle.net\Agent\Blizzard Uninstaller.exe" --lang=enUS --uid=wow --displayname="World of Warcraft"'
        }
        $parsed.Executable | Should -Be 'C:\ProgramData\Battle.net\Agent\Blizzard Uninstaller.exe'
        @($parsed.Argument).Count | Should -Be 3
        @($parsed.Argument)[2] | Should -Be '--displayname=World of Warcraft'
    }

    It 'keeps a comma-joined rundll32 entry point in one argument' {
        # NVIDIA writes "...RunDll32.EXE" "...NVI2.DLL",UninstallPackage Display.Driver
        $parsed = InModuleScope Win11Optimizer.Engine {
            Split-RemovalCommandString -CommandString '"C:\WINDOWS\SysWOW64\RunDll32.EXE" "C:\Program Files\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage Display.Driver'
        }
        @($parsed.Argument).Count | Should -Be 2
        @($parsed.Argument)[0] | Should -Be 'C:\Program Files\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL,UninstallPackage'
        @($parsed.Argument)[1] | Should -Be 'Display.Driver'
    }

    It 'survives an unterminated quote without guessing' {
        $parsed = InModuleScope Win11Optimizer.Engine {
            Split-RemovalCommandString -CommandString '"C:\Program Files\App\unins000.exe /SILENT'
        }
        $parsed.Executable | Should -BeNullOrEmpty
        $parsed.Note | Should -Match 'never closed'
    }

    It 'returns nothing for an empty string' {
        $parsed = InModuleScope Win11Optimizer.Engine { Split-RemovalCommandString -CommandString '   ' }
        $parsed | Should -BeNullOrEmpty
    }
}

Describe 'No ProcessCommand step ever carries a command line' {

    It 'gives every ProcessCommand step an executable and an argument ARRAY' {
        $keys = @(
            (New-TestUninstallKey -Name 'shape1' -Value @{ DisplayName = 'One'; QuietUninstallString = '"C:\Program Files\A B\unins000.exe" /SILENT /NORESTART' })
            (New-TestUninstallKey -Name 'shape2' -Value @{ DisplayName = 'Two'; UninstallString = 'C:\Program Files\A B\setup.exe /U {02247819-03CD-414E-AC8D-FD518BFBA445}' })
            (New-TestUninstallKey -Name 'shape3' -Value @{ DisplayName = 'Three'; UninstallString = 'MsiExec.exe /X{02247819-03CD-414E-AC8D-FD518BFBA445}' })
        )
        $plans = @($keys | ForEach-Object { Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id $_ -RemovalMethod RegistryUninstallString) })
        $steps = @($plans | ForEach-Object { $_.Step } | Where-Object { $_.Kind -eq 'ProcessCommand' })

        $steps.Count | Should -Be 3
        foreach ($step in $steps) {
            $step.Executable | Should -Not -BeNullOrEmpty
            # An executable path, not a command line: no argument switch may have
            # been left glued onto it.
            $step.Executable | Should -Not -Match '\s[/-]'
            $step.Argument | Should -BeOfType ([string])   # an array of strings, element-wise
            @($step.Argument).Count | Should -BeGreaterThan 0
            foreach ($argument in @($step.Argument)) {
                $argument | Should -Not -Match '^"'
            }
            # And no property that is a command line at all.
            @($step.PSObject.Properties.Name) | Should -Not -Contain 'CommandLine'
        }
    }
}

Describe 'Route: PackageManagement -- defined behaviour for a route nothing produces' {

    It 'is explicitly unsupported and says why' {
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id 'Whatever' -RemovalMethod PackageManagement)

        $plan.Route             | Should -Be 'PackageManagement'
        $plan.Supported         | Should -BeFalse
        $plan.CurrentState      | Should -Be 'Unverifiable'
        @($plan.Step).Count     | Should -Be 0
        $plan.UnsupportedReason | Should -Match 'No detector'
        $plan.UnsupportedReason | Should -Match 'Q2'
    }

    It 'is still in the Finding contract, not deleted from it' {
        @($script:FindingContract.RemovalMethods) | Should -Contain 'PackageManagement'
    }
}

Describe 'Route: StartupApproved -- disable, never delete' {

    It 'plans a registry value write into the StartupApproved store, not a deletion' {
        $runKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category StartupItem -Id "$runKey`::NotARealStartupEntry" -RemovalMethod RegistryRunKey)

        # The value is not there, so this is the AlreadyGone shape -- which is
        # itself the point: nothing plans a deletion either way.
        $plan.Route | Should -Be 'StartupApproved'
        $plan.Supported | Should -BeTrue
        $plan.CurrentState | Should -Be 'AlreadyGone'
        @($plan.Step | Where-Object { $_.Kind -notin @('RegistryValueWrite') }).Count | Should -Be 0
    }

    It 'refuses a RunOnce entry, because RunOnce has no approval-store record' {
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category StartupItem `
            -Id 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce::Anything' -RemovalMethod RegistryRunKey)

        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'RunOnce'
        $plan.UnsupportedReason | Should -Match 'never deletes a Run value'
        @($plan.Step).Count | Should -Be 0
    }

    It 'refuses a Run key this tool does not read rather than fabricating a store' {
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category StartupItem `
            -Id 'HKCU:\SOFTWARE\Somewhere\Else::Thing' -RemovalMethod RegistryRunKey)
        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'not one of the Run'
    }

    It 'refuses an identifier that is not in the run-key form' {
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category StartupItem -Id 'just-a-name' -RemovalMethod RegistryRunKey)
        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'value name'
    }

    It 'refuses a Startup-folder shortcut that is not in either Startup folder' {
        $file = New-TestFile -Name 'fabricated.lnk'
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category StartupItem -Id $file -RemovalMethod FileDelete)

        $plan.Route | Should -Be 'StartupApproved'
        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'Startup folder'
    }

    It 'plans a disable, and the byte it plans is the measured disabled byte' {
        $store = InModuleScope Win11Optimizer.Engine { $script:RemovalStartupApprovedDisabledByte }
        # 0x01, measured in P2-C2 against Task Manager's own display. The closed
        # decoding table's disabled values are 0x01 / 0x03 / 0x07.
        $store | Should -Be 1
    }
}

Describe 'Route: ScheduledTask -- disable, and capture the XML anyway' {

    It 'refuses anything in the \Microsoft\Windows\ namespace, whatever the finding says' {
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category StartupItem `
            -Id '\Microsoft\Windows\UpdateOrchestrator\Reboot' -RemovalMethod TaskScheduler)

        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'Microsoft'
        @($plan.Step).Count | Should -Be 0
    }

    It 'treats a task that is not there as AlreadyGone, not as an error' {
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category StartupItem `
            -Id '\NoSuchFabricatedTask-2b6f' -RemovalMethod TaskScheduler)

        $plan.Supported | Should -BeTrue
        $plan.CurrentState | Should -Be 'AlreadyGone'
        @($plan.Step).Count | Should -Be 0
    }

    It 'plans a disable rather than an unregister, and records the per-trigger state' {
        # Against a real task on this machine that is not in the protected
        # namespace, if there is one. Skipped rather than faked when there is not:
        # a route tested only against fabricated input is a different claim.
        $inventory = Get-StartupItemInventory 3>$null
        $task = @($inventory.Items | Where-Object {
            $_.Mechanism -eq 'ScheduledTask' -and -not $_.IsProtectedNamespace
        }) | Select-Object -First 1

        if ($null -eq $task) {
            Set-ItResult -Skipped -Because 'this machine has no scheduled task outside the \Microsoft\Windows\ namespace'
            return
        }

        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category StartupItem -Id $task.Id -RemovalMethod TaskScheduler)
        $plan.Route | Should -Be 'ScheduledTask'
        $plan.Supported | Should -BeTrue

        if (@($plan.Step).Count -gt 0) {
            $plan.Step[0].Kind | Should -Be 'ScheduledTaskDisable'
            $plan.IsReversible | Should -BeTrue
        }
        # The XML and the prior enabled state are captured regardless.
        $plan.RollbackData.TaskXml | Should -Not -BeNullOrEmpty
        @($plan.RollbackData.PSObject.Properties.Name) | Should -Contain 'WasEnabled'
        @($plan.RollbackData.PSObject.Properties.Name) | Should -Contain 'Trigger'
    }
}

Describe 'Route: ServiceStartupType -- startup type only' {

    It 'treats a service that is not there as AlreadyGone' {
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category Service -Id 'NoSuchFabricatedService2b6f' -RemovalMethod ServiceDisable -RequiresConsent)
        $plan.Supported | Should -BeTrue
        $plan.CurrentState | Should -Be 'AlreadyGone'
        @($plan.Step).Count | Should -Be 0
    }

    It 'refuses a service on the security exclusion class, whatever the finding says' {
        # Malwarebytes is on this machine and on the antivirus-and-endpoint-security
        # exclusion entry. The finding is fabricated on purpose: the point is that
        # the dispatcher refuses it even when something upstream did not.
        $service = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Malwarebytes*' }) | Select-Object -First 1
        if ($null -eq $service) {
            Set-ItResult -Skipped -Because 'this machine has no service matching the security exclusion class'
            return
        }

        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category Service -Id $service.Name -DisplayName $service.DisplayName -RemovalMethod ServiceDisable -RequiresConsent)
        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'security'
        @($plan.Step).Count | Should -Be 0
    }

    It 'plans a startup-type change and never a delete or a stop' {
        $findings = @((Invoke-StartupItemScan 3>$null).Findings | Where-Object { $_.Category -eq 'Service' })
        if ($findings.Count -lt 1) {
            Set-ItResult -Skipped -Because 'this machine produced no Service finding'
            return
        }

        $plan = Get-RemovalPlan -Finding $findings[0]
        $plan.Route | Should -Be 'ServiceStartupType'
        $plan.RequiresConsent | Should -BeTrue
        $plan.SafetyLabel | Should -Be 'Review needed'

        foreach ($step in @($plan.Step)) {
            $step.Kind | Should -Be 'ServiceStartupTypeChange'
            $step.Detail.PlannedStartValue | Should -Be 4
            $step.Detail.PreviousStartValue | Should -Not -Be 4
        }
        $plan.RollbackData.PreviousStartupType | Should -Not -BeNullOrEmpty

        # It is not enough that no step deletes: the preview has to SAY so, or a
        # user reading "disable this service" has no way to know the service is
        # still there afterwards.
        $preview = ($plan | Get-RemovalPreview) -join ' '
        $preview | Should -Match 'not deleted'
        $preview | Should -Match 'not stopped'
        @($plan.Step | Where-Object { $_.Kind -in @('FileDeleteSet', 'AppxRemovePackage', 'AppxRemoveProvisionedPackage') }).Count | Should -Be 0
    }

    It 'reads the previous startup type from the registry Start value' {
        $findings = @((Invoke-StartupItemScan 3>$null).Findings | Where-Object { $_.Category -eq 'Service' })
        if ($findings.Count -lt 1) {
            Set-ItResult -Skipped -Because 'this machine produced no Service finding'
            return
        }
        $plan = Get-RemovalPlan -Finding $findings[0]
        $plan.RollbackData.PreviousStartValue | Should -BeOfType ([int])
        $plan.RollbackData.KeyPath | Should -Match 'CurrentControlSet\\Services'
    }
}

Describe 'Route: JunkFileSet' {

    It 'plans ONE step for a whole set of files, never one per file' {
        $files = @(1..25 | ForEach-Object { New-TestFile })
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path $files)

        $plan.Route | Should -Be 'JunkFileSet'
        $plan.Supported | Should -BeTrue
        @($plan.Step).Count | Should -Be 1
        $plan.Step[0].Kind | Should -Be 'FileDeleteSet'
        $plan.Step[0].Detail.FileCount | Should -Be 25
        @($plan.Step[0].Detail.File).Count | Should -Be 25
    }

    It 'takes SizeBytes from the finding rather than re-reading the file' {
        # The finding says 64 bytes per file. The file on disk is 4096. The plan
        # must use the finding's number: it is the disk-size-before capture the
        # receipt is built from, and by removal time a re-read may fail.
        $file = New-TestFile -Bytes 4096
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @($file))

        $plan.Step[0].Detail.TotalBytes | Should -Be 64
        $plan.Step[0].Detail.File[0].SizeBytes | Should -Be 64
    }

    It 'treats a file that has vanished since the scan as success, not failure' {
        $kept    = New-TestFile
        $missing = Join-Path $script:Scratch ('gone-' + [guid]::NewGuid().ToString('N') + '.tmp')

        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @($kept, $missing))

        $plan.Supported | Should -BeTrue
        $plan.CurrentState | Should -Be 'Changed'
        $plan.Step[0].Detail.FileCount | Should -Be 1
        $plan.Step[0].Detail.VanishedCount | Should -Be 1
        ($plan | Get-RemovalPreview) -join ' ' | Should -Match 'already gone'
    }

    It 're-checks the in-use gate at plan time and leaves a held file alone' {
        $held = New-TestFile
        $free = New-TestFile

        $stream = [System.IO.File]::Open($held, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        try {
            $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @($held, $free))
        }
        finally {
            $stream.Dispose()
        }

        $plan.Step[0].Detail.FileCount  | Should -Be 1
        $plan.Step[0].Detail.InUseCount | Should -Be 1
        @($plan.Step[0].Detail.File)[0].Path | Should -Be $free
    }

    It 'plans AlreadyGone when the whole set has gone, and calls it a success' {
        $missing = @(1..3 | ForEach-Object { Join-Path $script:Scratch ("gone-$_.tmp") })
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path $missing)

        $plan.Supported | Should -BeTrue
        $plan.CurrentState | Should -Be 'AlreadyGone'
        @($plan.Step).Count | Should -Be 0
    }

    It 'never plans a directory' {
        $directory = Join-Path $script:Scratch ('dir-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $directory -ItemType Directory -Force
        $file = New-TestFile

        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @($directory, $file))

        @($plan.Step[0].Detail.File | Where-Object { $_.Path -eq $directory }).Count | Should -Be 0
        $plan.Step[0].Detail.FileCount | Should -Be 1
    }

    It 'refuses a finding that carries no file list at all' {
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @() -NoEligibleFile)
        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'never deletes a location'
        @($plan.Step).Count | Should -Be 0
    }

    It 'puts IsSizeFloor into the preview in words' {
        $file = New-TestFile
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @($file) -IsSizeFloor)
        ($plan | Get-RemovalPreview) -join ' ' | Should -Match 'floor, not a total'
    }

    It 'shows counts and a small sample, never the whole list' {
        $files = @(1..40 | ForEach-Object { New-TestFile })
        $preview = @(Get-RemovalPlan -Finding (New-TestJunkFinding -Path $files) | Get-RemovalPreview)

        $text = $preview -join "`n"
        $text | Should -Match 'For example'
        $text | Should -Match 'and 37 more'
        @($files | Where-Object { $text -like "*$_*" }).Count | Should -BeLessOrEqual 3
    }
}

Describe 'The last safety gate' {

    It 'refuses a junk finding pointing at the user''s Documents folder' {
        $documents = [Environment]::GetFolderPath('MyDocuments')
        $documents | Should -Not -BeNullOrEmpty

        $target = Join-Path $documents 'a-file-this-tool-must-never-plan.txt'
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @($target) -LocationPath @($documents))

        $plan.Supported | Should -BeFalse
        $plan.UnsupportedReason | Should -Match 'refused'
        $plan.UnsupportedReason | Should -Match ([regex]::Escape($documents))
        @($plan.Step).Count | Should -Be 0
    }

    It 'refuses each of the protected roots in turn' -ForEach @('MyDocuments', 'MyPictures', 'MyVideos', 'MyMusic', 'Desktop') {
        $folder = [Environment]::GetFolderPath($_)
        if ([string]::IsNullOrWhiteSpace($folder)) {
            Set-ItResult -Skipped -Because "this machine does not resolve the $_ folder"
            return
        }
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @((Join-Path $folder 'x.tmp')) -LocationPath @($folder))
        $plan.Supported | Should -BeFalse
    }

    It 'refuses a drive root, the Windows folder and the profile root' -ForEach @(
        'C:\', 'SystemRoot', 'UserProfile'
    ) {
        $folder = switch ($_) {
            'SystemRoot'  { [Environment]::GetEnvironmentVariable('SystemRoot') }
            'UserProfile' { [Environment]::GetFolderPath('UserProfile') }
            default       { $_ }
        }
        if ([string]::IsNullOrWhiteSpace($folder)) {
            Set-ItResult -Skipped -Because "this machine does not resolve $_"
            return
        }
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @((Join-Path $folder 'x.tmp')) -LocationPath @($folder))
        $plan.Supported | Should -BeFalse
    }

    It 'still allows a location that merely lives INSIDE the profile or inside Windows' {
        # The direction matters: %TEMP% is inside the profile and %SystemRoot%\Logs
        # is inside Windows, and both are legitimate. A check that ran both
        # directions on a Root entry would reject them, which is the bug
        # docs\handoff\07-junk-files.report.md deviation 7 records.
        $file = New-TestFile
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @($file) -LocationPath @($script:Scratch))
        $plan.Supported | Should -BeTrue
    }
}

Describe 'The preview' {

    It 'never promises space that will be freed' {
        $files = @(1..5 | ForEach-Object { New-TestFile })
        $preview = @(Get-RemovalPlan -Finding (New-TestJunkFinding -Path $files) | Get-RemovalPreview) -join ' '

        # The rule is about the CLAIM, not the vocabulary: the shipped junk
        # detector's own evidence line ends "not a promise of space reclaimed",
        # and the preview repeats it. Forbidding the bare word 'reclaim' would
        # therefore ban the sentence that exists to make the promise explicitly.
        foreach ($forbidden in 'free up', 'frees up', 'freed up', 'will reclaim', 'space you will', 'will save', 'you will get back', 'speed up', 'run faster') {
            $preview | Should -Not -Match ([regex]::Escape($forbidden))
        }
        $preview | Should -Match 'on disk now'
        $preview | Should -Match 'not a promise of space reclaimed'
    }

    It 'says, on every plan, that nothing has been changed' {
        $plans = @(
            Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id 'Nothing.Here_8wekyb3d8bbwe' -RemovalMethod Appx)
            Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id 'Whatever' -RemovalMethod PackageManagement)
            Get-RemovalPlan -Finding (New-TestJunkFinding -Path @((New-TestFile)))
        )
        foreach ($plan in $plans) {
            (@($plan | Get-RemovalPreview) -join "`n") | Should -Match 'Nothing on this PC has been changed'
        }
    }

    It 'states the Appx scope in words, not by implication' {
        $installed = @(Get-AppxPackage -ErrorAction SilentlyContinue) | Select-Object -First 1
        if ($null -eq $installed) {
            Set-ItResult -Skipped -Because 'no Appx package could be read on this machine'
            return
        }
        $plan = Get-RemovalPlan -Finding (New-TestFinding -Category OemBloatware -Id $installed.PackageFamilyName -RemovalMethod Appx)
        $text = @($plan | Get-RemovalPreview) -join ' '

        $text | Should -Match 'for your account only'
    }

    It 'prints the safety label rather than re-deriving one' {
        $plan = Get-RemovalPlan -Finding (New-TestJunkFinding -Path @((New-TestFile)))
        (@($plan | Get-RemovalPreview)[0]) | Should -Match ([regex]::Escape($plan.SafetyLabel))
    }
}

Describe 'The module loader fails loud' {

    It 'throws for a required source folder that is missing, naming the folder' {
        $missing = Join-Path $script:Scratch ('no-such-folder-' + [guid]::NewGuid().ToString('N'))
        # Pointed at a fabricated folder, never by breaking the real one.
        { InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $missing } {
            Get-OptimizerSourceFile -Path $Path -Name 'Fabricated'
        } } | Should -Throw -ExpectedMessage '*Fabricated*'
    }

    It 'names the path and the underlying reason in the message' {
        $missing = Join-Path $script:Scratch ('no-such-folder-' + [guid]::NewGuid().ToString('N'))
        $message = $null
        try {
            InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $missing } {
                Get-OptimizerSourceFile -Path $Path -Name 'Fabricated'
            }
        }
        catch { $message = $_.Exception.Message }

        $message | Should -Match ([regex]::Escape($missing))
        $message | Should -Match 'DirectoryNotFoundException'
        $message | Should -Match 'cannot be imported'
    }

    It 'returns an empty list without error for a folder that is real and empty' {
        # A readable, empty folder is a real answer, not a gap.
        $empty = Join-Path $script:Scratch ('empty-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $empty -ItemType Directory -Force

        $files = InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $empty } {
            Get-OptimizerSourceFile -Path $Path -Name 'Fabricated'
        }
        @($files).Count | Should -Be 0
    }

    It 'loads Shared, Detectors and Removal, in that order' {
        # Same shape as P2-C3's assertion in SharedInventory.Tests.ps1, extended
        # to the third folder. Removal\ has to come last: the dispatcher reads
        # the Run-key view table and the StartupApproved store paths out of
        # Detectors\StartupItems.ps1's module-scope constants rather than
        # restating them, and those are defined at dot-source time.
        $source = [System.IO.File]::ReadAllText($script:ModulePath)
        $sharedIndex    = $source.IndexOf("Join-Path `$PSScriptRoot 'Shared'")
        $detectorIndex  = $source.IndexOf("Join-Path `$PSScriptRoot 'Detectors'")
        $removalIndex   = $source.IndexOf("Join-Path `$PSScriptRoot 'Removal'")

        $sharedIndex   | Should -BeGreaterThan -1
        $detectorIndex | Should -BeGreaterThan -1
        $removalIndex  | Should -BeGreaterThan -1
        $sharedIndex   | Should -BeLessThan $detectorIndex
        $detectorIndex | Should -BeLessThan $removalIndex
    }

    It 'requires all three folders, and names each one in its own error' -ForEach @('Shared', 'Detectors', 'Removal') {
        $source = [System.IO.File]::ReadAllText($script:ModulePath)
        $source | Should -Match ([regex]::Escape("-Name '$_'"))
    }

    It 'does not enumerate its source folders with Get-ChildItem' {
        # REVIEW.md: Get-ChildItem returns zero items and raises no error on a
        # folder the current user cannot list, even with -ErrorAction Stop. That
        # bug used to be in the loader itself, which is the one place it would
        # produce a module exporting names it had never defined.
        $moduleText = [System.IO.File]::ReadAllText($script:ModulePath)
        $tokens = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:ModulePath, [ref] $tokens, [ref] $null)
        $stripped = New-Object System.Text.StringBuilder $moduleText
        foreach ($token in @($tokens | Where-Object { $_.Kind -eq 'Comment' })) {
            for ($i = $token.Extent.StartOffset; $i -lt $token.Extent.EndOffset; $i++) {
                if ($stripped[$i] -ne "`n" -and $stripped[$i] -ne "`r") { $stripped[$i] = ' ' }
            }
        }
        $stripped.ToString() | Should -Not -Match 'Get-ChildItem'
        $stripped.ToString() | Should -Match '\[System\.IO\.Directory\]::GetFiles'
    }

    It 'exports every name it declares' {
        # The failure the loader fix exists to prevent: a module that imports
        # "successfully" with names in FunctionsToExport and none of them defined.
        $manifest = Import-PowerShellDataFile -Path $script:ManifestPath
        foreach ($name in $manifest.FunctionsToExport) {
            (Get-Command -Module Win11Optimizer.Engine -Name $name -ErrorAction SilentlyContinue) |
                Should -Not -BeNullOrEmpty -Because "$name is in FunctionsToExport"
        }
    }
}

Describe 'The promoted shared helpers' {

    It 'exposes the in-use probe from Shared, and the junk detector still delegates to it' {
        $file = New-TestFile
        $verdict = InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $file } {
            [pscustomobject]@{
                Shared = Test-OptimizerFileInUse -Path $Path
                Junk   = Test-JunkFileInUse -Path $Path
            }
        }
        $verdict.Shared | Should -Be 'Free'
        $verdict.Junk   | Should -Be 'Free'
    }

    It 'refuses to be talked into opening a file for writing' {
        $file = New-TestFile
        { InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $file } {
            Test-OptimizerFileInUse -Path $Path -Access ([System.IO.FileAccess]::Write)
        } } | Should -Throw -ExpectedMessage '*read-only probe*'
    }

    It 'answers Undetermined rather than Free for a path it cannot probe' {
        $verdict = InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $script:Scratch } {
            Test-OptimizerFileInUse -Path $Path
        }
        $verdict | Should -Be 'Undetermined'
    }

    It 'exposes the protected-path list from Shared, and the junk detector adds only WinSxS' {
        $lists = InModuleScope Win11Optimizer.Engine {
            [pscustomobject]@{
                Shared = @(Get-OptimizerProtectedPath)
                Junk   = @(Get-JunkProtectedPath)
            }
        }
        $lists.Junk.Count | Should -Be ($lists.Shared.Count + 1)
        @($lists.Junk | Where-Object { $_.Path -like '*WinSxS' }).Count | Should -Be 1
        @($lists.Shared | Where-Object { $_.Path -like '*WinSxS' }).Count | Should -Be 0
    }

    It 'keeps the protected-path check directional' {
        $result = InModuleScope Win11Optimizer.Engine {
            $protected = @(Get-OptimizerProtectedPath)
            $temp = [System.IO.Path]::GetTempPath()
            $documents = [Environment]::GetFolderPath('MyDocuments')
            [pscustomobject]@{
                # inside the profile (a Root entry) -- allowed
                Temp      = Get-OptimizerProtectedPathConflict -Path $temp -ProtectedPath $protected
                # inside Documents (a Subtree entry) -- refused
                InsideDoc = Get-OptimizerProtectedPathConflict -Path (Join-Path $documents 'x') -ProtectedPath $protected
                # the profile root itself -- refused
                Profile   = Get-OptimizerProtectedPathConflict -Path ([Environment]::GetFolderPath('UserProfile')) -ProtectedPath $protected
            }
        }
        $result.Temp      | Should -BeNullOrEmpty
        $result.InsideDoc | Should -Not -BeNullOrEmpty
        $result.Profile   | Should -Not -BeNullOrEmpty
    }
}

Describe 'Every route on this machine' {

    BeforeAll {
        $script:MachineFindings = @(
            @((Invoke-OemBloatwareScan 3>$null).Findings)
            @((Invoke-UnusedAppScan 3>$null).Findings)
            @((Invoke-StartupItemScan 3>$null).Findings)
            @((Invoke-JunkFileScan 3>$null).Findings)
        )
        $script:MachinePlans = @($script:MachineFindings | Get-RemovalPlan)
    }

    It 'produces exactly one plan per finding' {
        $script:MachinePlans.Count | Should -Be $script:MachineFindings.Count
    }

    It 'gives every plan a route from the contract' {
        foreach ($plan in $script:MachinePlans) {
            (@($script:Contract.RouteIds) + @($script:Contract.UnsupportedRoute)) | Should -Contain $plan.Route
        }
    }

    It 'gives every plan a current state from the contract' {
        foreach ($plan in $script:MachinePlans) {
            @($script:Contract.CurrentStates) | Should -Contain $plan.CurrentState
        }
    }

    It 'gives every step a kind from the contract' {
        foreach ($plan in $script:MachinePlans) {
            foreach ($step in @($plan.Step)) {
                @($script:Contract.StepKinds) | Should -Contain $step.Kind
            }
        }
    }

    It 'never leaves a step on an unsupported plan' {
        foreach ($plan in @($script:MachinePlans | Where-Object { -not $_.Supported })) {
            @($plan.Step).Count | Should -Be 0
            $plan.UnsupportedReason | Should -Not -BeNullOrEmpty
        }
    }

    It 'marks a plan as needing elevation whenever any of its steps does' {
        foreach ($plan in $script:MachinePlans) {
            $anyStep = @($plan.Step | Where-Object { $_.RequiresElevation }).Count -gt 0
            if ($anyStep) { $plan.RequiresElevation | Should -BeTrue }
        }
    }

    It 'gives every plan a preview' {
        foreach ($plan in $script:MachinePlans) {
            @($plan.PreviewText).Count | Should -BeGreaterThan 0
            (@($plan | Get-RemovalPreview) -join "`n") | Should -Be (@($plan.PreviewText) -join "`n")
        }
    }
}
