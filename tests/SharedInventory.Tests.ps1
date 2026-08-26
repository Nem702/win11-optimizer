#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the shared inventory and scan-result plumbing promoted out of
    Detectors\OemBloatware.ps1 by chunk P2-C3 (src\...\Shared\Inventory.ps1).

    Two things are being checked here:
      * the promoted pieces work on their own terms -- the registry walk reads all
        three uninstall views, and the three fields P2-C3 added are read
        defensively rather than trusted;
      * and the promotion did not change what P2-C1 hands back. The old suite
        passing is necessary but not sufficient, so Invoke-OemBloatwareScan's shape
        and derived semantics are asserted directly here.

    Run:  .\tests\Invoke-Tests.ps1
#>

BeforeAll {
    $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot   = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath   = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:SharedPath   = Join-Path $script:EngineRoot 'Shared\Inventory.ps1'

    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-shared-" + [guid]::NewGuid().ToString('N'))
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

Describe 'Shared inventory registration' {

    It 'lists Get-RegistryInstalledApp in the manifest FunctionsToExport' {
        $manifest = Import-PowerShellDataFile -Path $script:ManifestPath
        $manifest.FunctionsToExport | Should -Contain 'Get-RegistryInstalledApp'
    }

    It 'lists Get-RegistryInstalledApp in the .psm1 Export-ModuleMember block' {
        $source = [System.IO.File]::ReadAllText($script:ModulePath)
        $source | Should -BeLike "*'Get-RegistryInstalledApp'*"
    }

    It 'actually exports Get-RegistryInstalledApp from a freshly imported module' {
        (Get-Module Win11Optimizer.Engine).ExportedFunctions.Keys | Should -Contain 'Get-RegistryInstalledApp'
    }

    It 'dot-sources the Shared folder before the Detectors folder' {
        # Detector files read module-scope constants defined in Shared at
        # dot-source time, so the order is load-bearing, not cosmetic.
        $source = [System.IO.File]::ReadAllText($script:ModulePath)
        $sharedIndex   = $source.IndexOf("Join-Path `$PSScriptRoot 'Shared'")
        $detectorIndex = $source.IndexOf("Join-Path `$PSScriptRoot 'Detectors'")
        $sharedIndex   | Should -BeGreaterThan -1
        $detectorIndex | Should -BeGreaterThan -1
        $sharedIndex   | Should -BeLessThan $detectorIndex
    }
}

Describe 'Shared inventory is read-only' {

    It 'contains no Remove-* cmdlet call anywhere in the shared source' {
        $source = [System.IO.File]::ReadAllText($script:SharedPath)
        $forbidden = 'Remove' + '-'
        $source.Contains($forbidden) | Should -BeFalse -Because 'the shared inventory reads; the dispatcher (P3-C1) owns removal'
    }

    It 'never touches Win32_Product / WMI' {
        $source = [System.IO.File]::ReadAllText($script:SharedPath)
        $source | Should -Not -Match 'Get-WmiObject'
        $source | Should -Not -Match 'Get-CimInstance'
        # The name appears once, in the header comment explaining why it is avoided.
        @([regex]::Matches($source, 'Win32_Product')).Count | Should -BeLessOrEqual 1
    }
}

Describe 'Get-RegistryInstalledApp' {

    BeforeAll { $script:Apps = @(Get-RegistryInstalledApp) }

    It 'returns installed applications from the real machine' {
        $script:Apps.Count | Should -BeGreaterThan 0
    }

    It 'tags every record as Win11Optimizer.InstalledApp' {
        foreach ($app in $script:Apps) {
            $app.PSObject.TypeNames | Should -Contain 'Win11Optimizer.InstalledApp'
        }
    }

    It 'gives every record the full normalised shape, even where a field is absent' {
        $expected = @(
            'Source', 'Id', 'Name', 'DisplayName', 'PackageFamilyName', 'Publisher',
            'Version', 'UninstallString', 'Detail', 'InstallDate', 'EstimatedSizeKb', 'InstallLocation'
        )
        foreach ($app in $script:Apps) {
            foreach ($field in $expected) {
                $app.PSObject.Properties.Name | Should -Contain $field
            }
        }
    }

    It 'reads the WOW6432Node view as well as the 64-bit and per-user ones' {
        # Omitting WOW6432Node hides most 32-bit software. Asserted against the
        # real machine because that is where the view actually has content.
        $roots = @($script:Apps | ForEach-Object { $_.Detail } | Select-Object -Unique)
        @($roots | Where-Object { $_ -like '*WOW6432Node*' }).Count | Should -BeGreaterThan 0
    }

    It 'defaults to all three uninstall views' {
        $command = Get-Command Get-RegistryInstalledApp
        $default = $command.Parameters['Path'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
        $default | Should -Not -BeNullOrEmpty
        # The values themselves are asserted through behaviour above; here we only
        # check the caller does not have to opt in to the 32-bit view.
        @(Get-RegistryInstalledApp).Count | Should -BeGreaterOrEqual @(Get-RegistryInstalledApp -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall').Count
    }

    It 'ignores an uninstall view that does not exist rather than throwing' {
        { Get-RegistryInstalledApp -Path 'HKCU:\SOFTWARE\Win11Optimizer\NoSuchViewForTests' } | Should -Not -Throw
    }

    It 'never returns a malformed InstallDate as a real date' {
        # This machine has a Unix epoch second count in a Riot Vanguard key. A
        # garbage install date feeds the minimum-age rule, so it has to come back
        # absent rather than as a guess.
        foreach ($app in $script:Apps) {
            if ($null -ne $app.InstallDate) {
                $app.InstallDate | Should -BeOfType [datetime]
                $app.InstallDate.Year | Should -BeGreaterOrEqual 1990
            }
        }
    }

    It 'never returns a negative EstimatedSizeKb' {
        foreach ($app in $script:Apps) {
            if ($null -ne $app.EstimatedSizeKb) {
                [long]$app.EstimatedSizeKb | Should -BeGreaterOrEqual 0
            }
        }
    }

    It 'only reports an InstallLocation that actually exists on disk' {
        foreach ($app in $script:Apps) {
            if (-not [string]::IsNullOrWhiteSpace($app.InstallLocation)) {
                Test-Path -LiteralPath $app.InstallLocation | Should -BeTrue -Because "InstallLocation '$($app.InstallLocation)' was reported for '$($app.DisplayName)'"
            }
        }
    }
}

Describe 'Defensive field converters' {

    It 'parses a well-formed yyyyMMdd InstallDate' {
        InModuleScope Win11Optimizer.Engine {
            $parsed = ConvertTo-OptimizerInstallDate -Value '20240115'
            $parsed | Should -Not -BeNullOrEmpty
            $parsed.Year  | Should -Be 2024
            $parsed.Month | Should -Be 1
            $parsed.Day   | Should -Be 15
        }
    }

    It 'returns nothing for the malformed InstallDate <_> rather than guessing' -ForEach @(
        '1750011767'   # a Unix epoch, observed on this machine
        '2024-01-15'
        ''
        'notadate'
        '20241332'     # month 13, day 32
        '19700101'     # before the sanity floor
    ) {
        $value = $_
        InModuleScope Win11Optimizer.Engine -Parameters @{ Value = $value } {
            param($Value)
            ConvertTo-OptimizerInstallDate -Value $Value | Should -BeNullOrEmpty
        }
    }

    It 'reads EstimatedSize as a number and rejects <_>' -ForEach @('', 'lots', '-5') {
        $value = $_
        InModuleScope Win11Optimizer.Engine -Parameters @{ Value = $value } {
            param($Value)
            ConvertTo-OptimizerEstimatedSize -Value $Value | Should -BeNullOrEmpty
        }
    }

    It 'reads a valid EstimatedSize' {
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerEstimatedSize -Value '262144' | Should -Be 262144
        }
    }

    It 'strips quotes and a trailing separator from InstallLocation' {
        InModuleScope Win11Optimizer.Engine {
            $windows = [Environment]::GetFolderPath('Windows')
            ConvertTo-OptimizerInstallLocation -Value ('"' + $windows + '\"') | Should -Be $windows
        }
    }

    It 'returns nothing for an InstallLocation that is not there' {
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerInstallLocation -Value 'C:\NoSuchFolderForWin11OptimizerTests' | Should -BeNullOrEmpty
        }
    }

    It 'returns nothing for a bare drive root' {
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerInstallLocation -Value 'C:\' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Shared scan-result wrapper' {

    It 'derives IsComplete, IncompleteReason and SummaryText from the sources' {
        InModuleScope Win11Optimizer.Engine {
            $sources = @(
                (New-ScanSource -Name 'A' -Status 'Succeeded' -ItemCount 3)
                (New-ScanSource -Name 'B' -Status 'Skipped' -Reason 'Not elevated.')
            )
            $result = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $false -InventoryCount 3 `
                -Source $sources -Finding @() -ScanLabel 'Test scan' -WarningAction SilentlyContinue

            $result.IsComplete       | Should -BeFalse
            $result.IncompleteReason | Should -Match 'Not elevated'
            $result.SummaryText      | Should -Match 'PARTIAL'
        }
    }

    It 'reports a complete scan when every source succeeded' {
        InModuleScope Win11Optimizer.Engine {
            $result = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $true -InventoryCount 2 `
                -Source @((New-ScanSource -Name 'A' -Status 'Succeeded')) -Finding @() -ScanLabel 'Test scan'

            $result.IsComplete       | Should -BeTrue
            $result.IncompleteReason | Should -BeNullOrEmpty
            $result.SummaryText      | Should -Match 'Complete scan'
        }
    }

    It 'refuses to let a caller overwrite IsComplete' {
        InModuleScope Win11Optimizer.Engine {
            $result = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $true -InventoryCount 0 `
                -Source @((New-ScanSource -Name 'A' -Status 'Succeeded')) -Finding @() -ScanLabel 'Test scan'

            { $result.IsComplete = $false } | Should -Throw
        }
    }

    It 'warns on the warning stream when the scan is incomplete, so no detector can forget to' {
        InModuleScope Win11Optimizer.Engine {
            $warnings = @()
            $null = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $false -InventoryCount 0 `
                -Source @((New-ScanSource -Name 'A' -Status 'Failed' -Reason 'It broke.')) -Finding @() `
                -ScanLabel 'Test scan' -WarningVariable warnings -WarningAction SilentlyContinue
            ($warnings -join ' ') | Should -Match 'INCOMPLETE'
        }
    }

    It 'accepts the Refused status' {
        InModuleScope Win11Optimizer.Engine {
            $source = New-ScanSource -Name 'A' -Status 'Refused' -Reason 'Never used, on any machine.'
            $source.Status | Should -Be 'Refused'
            $source.Reason | Should -Be 'Never used, on any machine.'
        }
    }

    It 'rejects a <_> source that states no reason' -ForEach @('Skipped', 'Failed', 'Refused') {
        $status = $_
        InModuleScope Win11Optimizer.Engine -Parameters @{ Status = $status } {
            param($Status)
            # A source that is not Succeeded and carries no reason reaches the user
            # as an unexplained gap, which is the silent under-report this project
            # exists to prevent.
            { New-ScanSource -Name 'A' -Status $Status } | Should -Throw
            { New-ScanSource -Name 'A' -Status $Status -Reason '   ' } | Should -Throw
        }
    }

    It 'gives a Succeeded source a null Reason rather than an empty string, even if one is passed' {
        InModuleScope Win11Optimizer.Engine {
            $source = New-ScanSource -Name 'A' -Status 'Succeeded' -Reason 'ignored'
            $null -eq $source.Reason | Should -BeTrue
        }
    }

    It 'does not let a Refused source make a scan incomplete' {
        InModuleScope Win11Optimizer.Engine {
            $sources = @(
                (New-ScanSource -Name 'Real' -Status 'Succeeded' -ItemCount 3)
                (New-ScanSource -Name 'NeverUsed' -Status 'Refused' -Reason 'Refused by design: the signal is saturated on every machine.')
            )
            $result = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $true -InventoryCount 3 `
                -Source $sources -Finding @() -ScanLabel 'Test scan'

            $result.IsComplete       | Should -BeTrue
            $result.IncompleteReason | Should -BeNullOrEmpty
            $result.SummaryText      | Should -Not -Match 'PARTIAL'
        }
    }

    It 'keeps a Refused source visible in Sources with its reason intact' {
        InModuleScope Win11Optimizer.Engine {
            $reason = 'Refused by design: measured saturated on the development machine 2026-08-25.'
            $result = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $true -InventoryCount 3 `
                -Source @(
                    (New-ScanSource -Name 'Real' -Status 'Succeeded')
                    (New-ScanSource -Name 'NeverUsed' -Status 'Refused' -Reason $reason)
                ) -Finding @() -ScanLabel 'Test scan'

            $refused = @($result.Sources | Where-Object { $_.Name -eq 'NeverUsed' })[0]
            $refused.Status           | Should -Be 'Refused'
            $refused.Reason           | Should -Be $reason
            $result.RefusedSourceName | Should -Be @('NeverUsed')
        }
    }

    It 'acknowledges refused sources in the summary by name, without PARTIAL and without the full reason' {
        InModuleScope Win11Optimizer.Engine {
            $reason = 'A very long reason that runs to several sentences and must not be inlined into a one-line summary. It explains a measurement.'
            $result = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $true -InventoryCount 286 `
                -Source @(
                    (New-ScanSource -Name 'Real' -Status 'Succeeded')
                    (New-ScanSource -Name 'FileSystemLastAccess' -Status 'Refused' -Reason $reason)
                ) -Finding @() -ScanLabel 'Test scan' -FindingNoun 'unused-app findings'

            $result.SummaryText | Should -Match '^Complete scan of 286 installed items: 0 unused-app findings\. '
            $result.SummaryText | Should -Match '1 signal not used by design \(FileSystemLastAccess\) -- see Sources\.$'
            $result.SummaryText | Should -Not -Match 'PARTIAL'
            $result.SummaryText | Should -Not -Match 'runs to several sentences'
        }
    }

    It 'pluralises and names every refused source when there is more than one' {
        InModuleScope Win11Optimizer.Engine {
            $result = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $true -InventoryCount 1 `
                -Source @(
                    (New-ScanSource -Name 'AlphaSignal' -Status 'Refused' -Reason 'No.')
                    (New-ScanSource -Name 'BetaSignal' -Status 'Refused' -Reason 'Also no.')
                ) -Finding @() -ScanLabel 'Test scan'

            $result.SummaryText | Should -Match '2 signals not used by design \(AlphaSignal, BetaSignal\) -- see Sources\.'
        }
    }

    It 'still counts Skipped and Failed as incomplete alongside a Refused source' {
        InModuleScope Win11Optimizer.Engine {
            $result = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $false -InventoryCount 1 `
                -Source @(
                    (New-ScanSource -Name 'Elevated' -Status 'Skipped' -Reason 'Not elevated.')
                    (New-ScanSource -Name 'Broken' -Status 'Failed' -Reason 'It broke.')
                    (New-ScanSource -Name 'NeverUsed' -Status 'Refused' -Reason 'Refused by design.')
                ) -Finding @() -ScanLabel 'Test scan' -WarningAction SilentlyContinue

            $result.IsComplete       | Should -BeFalse
            $result.IncompleteReason | Should -Match 'Not elevated'
            $result.IncompleteReason | Should -Match 'It broke'
            $result.IncompleteReason | Should -Not -Match 'NeverUsed'
            $result.SummaryText      | Should -Match 'PARTIAL'
            $result.SummaryText      | Should -Match 'not used by design \(NeverUsed\)'
        }
    }

    It 'does not warn on the warning stream when the only non-success source is Refused' {
        InModuleScope Win11Optimizer.Engine {
            $warnings = @()
            $null = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $true -InventoryCount 1 `
                -Source @(
                    (New-ScanSource -Name 'Real' -Status 'Succeeded')
                    (New-ScanSource -Name 'NeverUsed' -Status 'Refused' -Reason 'Refused by design.')
                ) -Finding @() -ScanLabel 'Test scan' -WarningVariable warnings
            ($warnings -join ' ') | Should -Not -Match 'INCOMPLETE'
        }
    }

    It 'carries the detector type tag in front of the shared one' {
        InModuleScope Win11Optimizer.Engine {
            $result = New-ScanResult -Detector 'D' -Category 'UnusedApp' -StartedUtc ([datetime]::UtcNow) `
                -DurationSeconds 1.0 -IsElevated $true -InventoryCount 0 `
                -Source @((New-ScanSource -Name 'A' -Status 'Succeeded')) -Finding @() `
                -ScanLabel 'Test scan' -TypeName 'Win11Optimizer.SomeDetectorScanResult'

            $result.PSObject.TypeNames[0] | Should -Be 'Win11Optimizer.SomeDetectorScanResult'
            $result.PSObject.TypeNames    | Should -Contain 'Win11Optimizer.ScanResult'
        }
    }
}

Describe 'Invoke-OemBloatwareScan survives the promotion unchanged' {

    # The 141 tests from P2-C1 and P2-C1a passing is necessary but not sufficient:
    # they were written before the shared wrapper existed. These assert the shape
    # directly, so a future change to New-ScanResult that quietly drops one of
    # P2-C1's properties fails here rather than in the GUI.

    BeforeAll { $script:OemScan = Invoke-OemBloatwareScan -WarningAction SilentlyContinue }

    It 'still exposes every property P2-C1 published' -ForEach @(
        'Detector', 'Category', 'StartedUtc', 'DurationSeconds', 'IsElevated',
        'WhitelistPath', 'WhitelistCount', 'InventoryCount', 'Sources', 'Findings',
        'IsComplete', 'IncompleteReason', 'SummaryText'
    ) {
        $script:OemScan.PSObject.Properties.Name | Should -Contain $_
    }

    It 'still carries the Win11Optimizer.OemScanResult type tag' {
        $script:OemScan.PSObject.TypeNames | Should -Contain 'Win11Optimizer.OemScanResult'
    }

    It 'also carries the shared scan-result tag, a superset of what P2-C1 had' {
        $script:OemScan.PSObject.TypeNames | Should -Contain 'Win11Optimizer.ScanResult'
    }

    It 'still worded its summary the way P2-C1 did' {
        if ($script:OemScan.IsComplete) {
            $script:OemScan.SummaryText | Should -Match '^Complete scan of \d+ installed items: \d+ known-bloatware findings\.$'
        }
        else {
            $script:OemScan.SummaryText | Should -Match '^PARTIAL scan of \d+ installed items: \d+ known-bloatware findings so far\. '
        }
    }

    It 'still tags each source record as Win11Optimizer.OemScanSource' {
        foreach ($source in $script:OemScan.Sources) {
            $source.PSObject.TypeNames | Should -Contain 'Win11Optimizer.OemScanSource'
            $source.PSObject.TypeNames | Should -Contain 'Win11Optimizer.ScanSource'
        }
    }

    It 'gives a succeeded source a null Reason rather than an empty string' {
        foreach ($source in $script:OemScan.Sources) {
            if ($source.Status -eq 'Succeeded') { $source.Reason | Should -BeNullOrEmpty }
        }
    }

    It 'still uses the shared registry walk rather than a second copy' {
        $detector = [System.IO.File]::ReadAllText((Join-Path $script:EngineRoot 'Detectors\OemBloatware.ps1'))
        $detector | Should -Match 'Get-RegistryInstalledApp'
        $detector | Should -Not -Match 'HKLM:\\SOFTWARE\\WOW6432Node'
    }
}
