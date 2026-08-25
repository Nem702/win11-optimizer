#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Smoke tests for Win11Optimizer.Engine (chunk P1-C1).

    Covers only what this chunk builds: the module imports, the Finding contract
    holds (including the Known/Heuristic safety distinction), the elevation check
    returns a boolean without throwing, and the JSON-lines run log round-trips.

    Run:  .\tests\Invoke-Tests.ps1
#>

BeforeAll {
    $script:RepoRoot   = Split-Path -Path $PSScriptRoot -Parent
    $script:ManifestPath = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine\Win11Optimizer.Engine.psd1'

    # Log somewhere disposable so the suite never litters the repo's logs\ folder.
    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-tests-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    Import-Module $script:ManifestPath -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module Win11Optimizer.Engine -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\WIN11OPTIMIZER_LOGROOT -ErrorAction SilentlyContinue
    if ($script:TestLogRoot -and (Test-Path -LiteralPath $script:TestLogRoot)) {
        Remove-Item -LiteralPath $script:TestLogRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Module import' {

    It 'imports from the manifest without errors' {
        $module = Get-Module Win11Optimizer.Engine
        $module | Should -Not -BeNullOrEmpty
        $module.Version | Should -Be ([version]'0.1.0')
    }

    It 'declares Windows PowerShell 5.1 as its floor' {
        $manifest = Import-PowerShellDataFile -Path $script:ManifestPath
        $manifest.PowerShellVersion | Should -Be '5.1'
    }

    It 'exports every function the manifest advertises' {
        $manifest = Import-PowerShellDataFile -Path $script:ManifestPath
        $exported = (Get-Module Win11Optimizer.Engine).ExportedFunctions.Keys
        foreach ($name in $manifest.FunctionsToExport) {
            $exported | Should -Contain $name
        }
    }
}

Describe 'Finding contract' {

    It 'constructs a Finding with all required fields' {
        $finding = New-Finding -Category OemBloatware `
            -Id 'Acme.Widget_8wekyb3d8bbwe' `
            -DisplayName 'Acme Widget' `
            -Evidence 'Matches curated OEM list entry Acme.Widget' `
            -Confidence Known `
            -RemovalMethod Appx

        $finding.PSObject.TypeNames | Should -Contain 'Win11Optimizer.Finding'
        $finding.Category      | Should -Be 'OemBloatware'
        $finding.Id            | Should -Be 'Acme.Widget_8wekyb3d8bbwe'
        $finding.DisplayName   | Should -Be 'Acme Widget'
        $finding.Evidence      | Should -Contain 'Matches curated OEM list entry Acme.Widget'
        $finding.Confidence    | Should -Be 'Known'
        $finding.RemovalMethod | Should -Be 'Appx'
    }

    It 'keeps multiple evidence strings as an array' {
        $finding = New-Finding -Category UnusedApp -Id 'HKLM:\SOFTWARE\...\Uninstall\{GUID}' `
            -DisplayName 'Old App' `
            -Evidence 'not launched in 214 days', 'unsigned publisher' `
            -Confidence Heuristic -RemovalMethod RegistryUninstallString

        @($finding.Evidence).Count | Should -Be 2
    }

    It 'refuses a Finding with no evidence' {
        { New-Finding -Category JunkFile -Id 'C:\Temp\x' -DisplayName 'x' `
            -Evidence @() -Confidence Heuristic -RemovalMethod FileDelete } | Should -Throw
    }

    It 'refuses values outside the contract' -ForEach @(
        @{ Field = 'Category';      Splat = @{ Category = 'NotACategory'; Id = 'x'; DisplayName = 'x'; Evidence = 'why'; Confidence = 'Known'; RemovalMethod = 'Appx' } }
        @{ Field = 'Confidence';    Splat = @{ Category = 'JunkFile'; Id = 'x'; DisplayName = 'x'; Evidence = 'why'; Confidence = 'Probably'; RemovalMethod = 'FileDelete' } }
        @{ Field = 'RemovalMethod'; Splat = @{ Category = 'JunkFile'; Id = 'x'; DisplayName = 'x'; Evidence = 'why'; Confidence = 'Known'; RemovalMethod = 'Win32_Product' } }
    ) {
        { New-Finding @Splat } | Should -Throw -Because "$Field is constrained by the contract"
    }

    It 'refuses an empty Id or DisplayName' {
        { New-Finding -Category JunkFile -Id '' -DisplayName 'x' -Evidence 'why' -Confidence Known -RemovalMethod FileDelete } | Should -Throw
        { New-Finding -Category JunkFile -Id 'x' -DisplayName '' -Evidence 'why' -Confidence Known -RemovalMethod FileDelete } | Should -Throw
    }

    Context 'safety model (docs/PLAN.md)' {

        It 'labels a curated-whitelist match as safe' {
            $known = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'curated list match' -Confidence Known -RemovalMethod Appx
            $known.SafetyLabel | Should -Be 'Safe to remove'
        }

        It 'never labels a heuristic finding as safe' {
            $heuristic = New-Finding -Category UnusedApp -Id 'x' -DisplayName 'x' `
                -Evidence 'not launched in 214 days' -Confidence Heuristic -RemovalMethod RegistryUninstallString
            $heuristic.SafetyLabel | Should -Be 'Review needed'
        }

        It 'does not let a caller re-label a heuristic finding as safe' {
            $heuristic = New-Finding -Category UnusedApp -Id 'x' -DisplayName 'x' `
                -Evidence 'not launched in 214 days' -Confidence Heuristic -RemovalMethod RegistryUninstallString

            { $heuristic.SafetyLabel = 'Safe to remove' } | Should -Throw
            $heuristic.SafetyLabel | Should -Be 'Review needed'
        }
    }

    Context 'safety model: the second axis (chunk P2-C1a)' {

        # Confidence and RequiresConsent answer different questions and the label is
        # an AND of both. All four combinations are asserted rather than the two
        # interesting ones, because an AND is exactly the kind of thing that quietly
        # becomes an OR and only one of the four cases would notice.
        It 'labels Confidence=<Confidence> RequiresConsent=<Consent> as "<Expected>"' -ForEach @(
            @{ Confidence = 'Known';     Consent = $false; Expected = 'Safe to remove' }
            @{ Confidence = 'Known';     Consent = $true;  Expected = 'Review needed' }
            @{ Confidence = 'Heuristic'; Consent = $false; Expected = 'Review needed' }
            @{ Confidence = 'Heuristic'; Consent = $true;  Expected = 'Review needed' }
        ) {
            $finding = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'why' -Confidence $Confidence -RemovalMethod Appx -RequiresConsent:$Consent

            $finding.SafetyLabel | Should -Be $Expected
        }

        It 'always carries RequiresConsent as a real boolean, set explicitly' {
            $withoutSwitch = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'why' -Confidence Known -RemovalMethod Appx
            $withSwitch = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'why' -Confidence Known -RemovalMethod Appx -RequiresConsent

            foreach ($finding in $withoutSwitch, $withSwitch) {
                $finding.PSObject.Properties.Name | Should -Contain 'RequiresConsent'
                $finding.RequiresConsent | Should -BeOfType [bool]
            }

            $withoutSwitch.RequiresConsent | Should -BeFalse
            $withSwitch.RequiresConsent    | Should -BeTrue
        }

        # Fail closed. This direction is the whole point: a Finding that lost the
        # field -- deserialized from a run log written before P2-C1a, say -- must
        # degrade to "review needed" and must never be upgraded to "safe".
        It 'falls back to "Review needed" when RequiresConsent is a string' {
            $finding = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'why' -Confidence Known -RemovalMethod Appx
            $finding.SafetyLabel | Should -Be 'Safe to remove' -Because 'otherwise the test proves nothing about the change'

            $finding.RequiresConsent = 'true'
            $finding.SafetyLabel | Should -Be 'Review needed'
        }

        It 'falls back to "Review needed" when RequiresConsent is null' {
            $finding = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'why' -Confidence Known -RemovalMethod Appx
            $finding.RequiresConsent = $null
            $finding.SafetyLabel | Should -Be 'Review needed'
        }

        It 'falls back to "Review needed" when RequiresConsent is absent entirely' {
            $finding = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'why' -Confidence Known -RemovalMethod Appx
            $finding.PSObject.Properties.Remove('RequiresConsent')

            $finding.PSObject.Properties.Name | Should -Not -Contain 'RequiresConsent'
            $finding.SafetyLabel | Should -Be 'Review needed'
        }

        It 'still refuses to let SafetyLabel be assigned once RequiresConsent is gone' {
            $finding = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'why' -Confidence Known -RemovalMethod Appx
            $finding.PSObject.Properties.Remove('RequiresConsent')

            { $finding.SafetyLabel = 'Safe to remove' } | Should -Throw
            $finding.SafetyLabel | Should -Be 'Review needed'
        }

        It 'survives a JSON round-trip without changing the label' {
            foreach ($consent in $true, $false) {
                $finding = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                    -Evidence 'why' -Confidence Known -RemovalMethod Appx -RequiresConsent:$consent
                $revived = $finding | ConvertTo-Json -Depth 6 | ConvertFrom-Json

                $revived.RequiresConsent | Should -BeOfType [bool]
                $revived.RequiresConsent | Should -Be $consent
                Test-Finding -InputObject $revived | Should -BeTrue
            }
        }
    }

    Context 'Test-Finding' {

        It 'accepts a Finding built by New-Finding' {
            $finding = New-Finding -Category StartupItem -Id 'HKCU:\...\Run\Acme' -DisplayName 'Acme' `
                -Evidence 'runs at logon' -Confidence Known -RemovalMethod RegistryRunKey
            Test-Finding -InputObject $finding | Should -BeTrue
        }

        It 'accepts a Finding that has round-tripped through JSON' {
            $finding = New-Finding -Category Service -Id 'AcmeUpdater' -DisplayName 'Acme Updater' `
                -Evidence 'auto-start service from a removed app' -Confidence Heuristic -RemovalMethod ServiceDisable
            $revived = $finding | ConvertTo-Json -Depth 6 | ConvertFrom-Json
            Test-Finding -InputObject $revived | Should -BeTrue
        }

        It 'rejects a bare hashtable missing contract fields' {
            $bogus = [pscustomobject]@{ Category = 'JunkFile'; Id = 'C:\Temp\x' }
            Test-Finding -InputObject $bogus | Should -BeFalse

            $reasons = Test-Finding -InputObject $bogus -Detailed
            $reasons | Should -Not -BeNullOrEmpty
            ($reasons -join ' ') | Should -Match 'DisplayName'
        }

        It 'rejects $null' {
            Test-Finding -InputObject $null | Should -BeFalse
        }

        It 'rejects a Finding with no RequiresConsent field' {
            $finding = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'why' -Confidence Known -RemovalMethod Appx
            $finding.PSObject.Properties.Remove('RequiresConsent')

            Test-Finding -InputObject $finding | Should -BeFalse
            ((Test-Finding -InputObject $finding -Detailed) -join ' ') | Should -Match 'RequiresConsent'
        }

        It 'rejects a RequiresConsent that is not a boolean' {
            $finding = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                -Evidence 'why' -Confidence Known -RemovalMethod Appx
            $finding.RequiresConsent = 'true'

            Test-Finding -InputObject $finding | Should -BeFalse
            ((Test-Finding -InputObject $finding -Detailed) -join ' ') | Should -Match 'must be a boolean'
        }
    }

    Context 'Get-FindingContract' {

        It 'reports the allowed values the module actually enforces' {
            $contract = Get-FindingContract
            $contract.Categories     | Should -Be @('OemBloatware', 'StartupItem', 'Service', 'UnusedApp', 'JunkFile')
            $contract.Confidences    | Should -Be @('Known', 'Heuristic')
            $contract.RemovalMethods | Should -Contain 'PackageManagement'
            $contract.RemovalMethods | Should -Not -Contain 'Win32_Product'
        }

        It 'agrees with what New-Finding accepts' {
            $contract = Get-FindingContract
            foreach ($category in $contract.Categories) {
                $finding = New-Finding -Category $category -Id 'x' -DisplayName 'x' `
                    -Evidence 'why' -Confidence Known -RemovalMethod Appx
                $finding.Category | Should -Be $category
            }
        }

        It 'hands out the two-axis safety rule so no consumer has to restate it' {
            $contract = Get-FindingContract
            $contract.SafetyLabels    | Should -Be @('Safe to remove', 'Review needed')
            $contract.SafetyLabelRule | Should -BeOfType [scriptblock]

            (& $contract.SafetyLabelRule 'Known'     $false)  | Should -Be 'Safe to remove'
            (& $contract.SafetyLabelRule 'Known'     $true)   | Should -Be 'Review needed'
            (& $contract.SafetyLabelRule 'Heuristic' $false)  | Should -Be 'Review needed'
            (& $contract.SafetyLabelRule 'Heuristic' $true)   | Should -Be 'Review needed'

            # Fails closed for a caller holding two loose field values too.
            (& $contract.SafetyLabelRule 'Known'     $null)   | Should -Be 'Review needed'
            (& $contract.SafetyLabelRule 'Known'     'true')  | Should -Be 'Review needed'
            (& $contract.SafetyLabelRule 'Known'     'false') | Should -Be 'Review needed'
        }

        It 'exposes the same rule the SafetyLabel property actually runs' {
            $contract = Get-FindingContract
            foreach ($confidence in $contract.Confidences) {
                foreach ($consent in $true, $false) {
                    $finding = New-Finding -Category OemBloatware -Id 'x' -DisplayName 'x' `
                        -Evidence 'why' -Confidence $confidence -RemovalMethod Appx -RequiresConsent:$consent
                    $finding.SafetyLabel | Should -Be (& $contract.SafetyLabelRule $confidence $consent)
                }
            }
        }
    }
}

Describe 'Test-IsElevated' {

    It 'returns a boolean without throwing' {
        $result = $null
        { $script:result = Test-IsElevated } | Should -Not -Throw
        $script:result | Should -BeOfType [bool]
    }

    It 'agrees with the WindowsPrincipal check done independently' {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $expected = (New-Object System.Security.Principal.WindowsPrincipal($identity)).IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)
        Test-IsElevated | Should -Be $expected
    }
}

Describe 'Run log' {

    AfterEach {
        Stop-OptimizerLog -ErrorAction SilentlyContinue
    }

    It 'honours the WIN11OPTIMIZER_LOGROOT override' {
        Get-OptimizerLogRoot | Should -Be $script:TestLogRoot
    }

    It 'creates a .jsonl file and reports its path' {
        $state = Start-OptimizerLog -PassThru
        $state.Path | Should -Match '\.jsonl$'
        Test-Path -LiteralPath $state.Path | Should -BeTrue
        Get-OptimizerLogPath | Should -Be $state.Path
    }

    It 'reports no open log after Stop-OptimizerLog' {
        Start-OptimizerLog | Out-Null
        Stop-OptimizerLog
        Get-OptimizerLogPath | Should -BeNullOrEmpty
    }

    It 'writes exactly one parseable JSON object per line' {
        $state = Start-OptimizerLog -PassThru
        Write-OptimizerLog -EventName 'Probe' -Message 'first'
        Write-OptimizerLog -EventName 'Probe' -Message 'second' -Level Warning
        Stop-OptimizerLog

        $lines = [System.IO.File]::ReadAllLines($state.Path) | Where-Object { $_ }
        # RunStart + 2 probes + RunEnd
        $lines.Count | Should -Be 4
        foreach ($line in $lines) {
            { $line | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    It 'stamps every record with the run id, an ISO-8601 UTC timestamp and a level' {
        $state = Start-OptimizerLog -PassThru
        Write-OptimizerLog -EventName 'Probe' -Message 'hello'
        Stop-OptimizerLog

        foreach ($record in Get-OptimizerLog -Path $state.Path) {
            $record.RunId | Should -Be $state.RunId
            $record.Level | Should -BeIn @('Debug', 'Info', 'Warning', 'Error')
        }

        # Asserted against the raw text, not the parsed object: ConvertFrom-Json
        # on PowerShell 7 hands back a [datetime] here while 5.1 hands back a
        # string, so only the file itself proves what was actually written.
        foreach ($line in [System.IO.File]::ReadAllLines($state.Path) | Where-Object { $_ }) {
            $line | Should -Match '"Timestamp":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"'
        }
    }

    It 'opens with a RunStart record describing the environment and closes with RunEnd' {
        $state = Start-OptimizerLog -PassThru
        Stop-OptimizerLog

        $records = @(Get-OptimizerLog -Path $state.Path)
        $records[0].Event  | Should -Be 'RunStart'
        $records[-1].Event | Should -Be 'RunEnd'
        $records[0].Data.PowerShellVersion | Should -Be $PSVersionTable.PSVersion.ToString()
        $records[0].Data.IsElevated        | Should -Be (Test-IsElevated)
    }

    It 'round-trips a Finding through the log without losing its fields' {
        $state = Start-OptimizerLog -PassThru
        $finding = New-Finding -Category UnusedApp -Id 'HKLM:\SOFTWARE\...\Uninstall\{GUID}' `
            -DisplayName 'Old App' -Evidence 'not launched in 214 days', 'unsigned publisher' `
            -Confidence Heuristic -RemovalMethod RegistryUninstallString
        Write-OptimizerLog -EventName 'FindingRecorded' -Message 'candidate surfaced' -Data $finding
        Stop-OptimizerLog

        $logged = @(Get-OptimizerLog -Path $state.Path | Where-Object { $_.Event -eq 'FindingRecorded' })
        $logged.Count | Should -Be 1
        Test-Finding -InputObject $logged[0].Data | Should -BeTrue
        $logged[0].Data.SafetyLabel | Should -Be 'Review needed'
        @($logged[0].Data.Evidence).Count | Should -Be 2
    }

    It 'writes UTF-8 without a BOM so line-by-line parsing works' {
        $state = Start-OptimizerLog -PassThru
        Write-OptimizerLog -EventName 'Probe' -Message 'unicode: café — ok'
        Stop-OptimizerLog

        $bytes = [System.IO.File]::ReadAllBytes($state.Path)
        # A UTF-8 BOM here would put EF BB BF in front of the first '{'.
        $bytes[0] | Should -Be ([byte][char]'{')

        $record = @(Get-OptimizerLog -Path $state.Path | Where-Object { $_.Event -eq 'Probe' })[0]
        $record.Message | Should -Be 'unicode: café — ok'
    }

    It 'starts a log on demand when one was never opened' {
        Get-OptimizerLogPath | Should -BeNullOrEmpty
        Write-OptimizerLog -EventName 'Probe' -Message 'implicit start'
        Get-OptimizerLogPath | Should -Not -BeNullOrEmpty
    }

    It 'skips a corrupted line instead of failing the whole read' {
        $state = Start-OptimizerLog -PassThru
        Write-OptimizerLog -EventName 'Probe' -Message 'good'
        Stop-OptimizerLog

        Add-Content -LiteralPath $state.Path -Value '{ this is not json'
        $records = @(Get-OptimizerLog -Path $state.Path -WarningAction SilentlyContinue)
        $records.Count | Should -Be 3
    }

    It 'does not write anything under -WhatIf' {
        $before = @(Get-ChildItem -Path $script:TestLogRoot -Filter '*.jsonl' -ErrorAction SilentlyContinue).Count
        Start-OptimizerLog -WhatIf
        $after = @(Get-ChildItem -Path $script:TestLogRoot -Filter '*.jsonl' -ErrorAction SilentlyContinue).Count
        $after | Should -Be $before
    }
}
