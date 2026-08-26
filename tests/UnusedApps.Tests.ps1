#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the UnusedApps detector (chunk P2-C3).

    The three states are the point of this suite, and they are all tested against
    fabricated inventory and fabricated signals, with a pinned reference time, so
    nothing here depends on what happens to be installed on the machine running it
    or on what date it is run.

    The single most important test in the file is the Unknown one: an app with no
    signal at all must produce no Finding. The second most important is the
    "every signal unavailable" scan test -- a machine this detector cannot see
    usage on must not come back looking clean.

    Run:  .\tests\Invoke-Tests.ps1
#>

BeforeAll {
    $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot   = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath   = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:DetectorPath = Join-Path $script:EngineRoot 'Detectors\UnusedApps.ps1'
    $script:ListPath     = Join-Path $script:EngineRoot 'Data\unused-app-exclusions.json'

    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-unused-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-unused-data-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    # Everything is measured against this instant, so a fixture cannot age out.
    $script:Now = [datetime]::new(2026, 8, 25, 12, 0, 0, [System.DateTimeKind]::Utc)

    function New-TestExclusionFile {
        param(
            [Parameter(Mandatory)] [string] $Content,
            [string] $Name = ([guid]::NewGuid().ToString('N') + '.json')
        )
        $path = Join-Path $script:Scratch $Name
        [System.IO.File]::WriteAllText($path, $Content, (New-Object System.Text.UTF8Encoding($false)))
        $path
    }

    function New-TestApp {
        param(
            [string] $Source = 'RegistryUninstall',
            [string] $Id = 'HKLM:\Uninstall\Test',
            [string] $Name,
            [string] $DisplayName,
            [string] $PackageFamilyName,
            [string] $Publisher,
            [string] $Version,
            [string] $UninstallString,
            [string] $InstallLocation,
            $InstallDate,
            $EstimatedSizeKb,
            [string[]] $ExecutableName
        )
        [pscustomobject]@{
            Source            = $Source
            Id                = $Id
            Name              = $Name
            DisplayName       = $DisplayName
            PackageFamilyName = $PackageFamilyName
            Publisher         = $Publisher
            Version           = $Version
            UninstallString   = $UninstallString
            InstallLocation   = $InstallLocation
            InstallDate       = $InstallDate
            EstimatedSizeKb   = $EstimatedSizeKb
            ExecutableName    = $ExecutableName
        }
    }

    function New-TestSignal {
        param(
            [string] $Signal = 'UserAssist',
            [Parameter(Mandatory)] [string] $MatchType,
            [Parameter(Mandatory)] [string] $Value,
            $LastUsedUtc,
            [string] $Detail = 'fabricated signal'
        )
        [pscustomobject]@{
            Signal      = $Signal
            MatchType   = $MatchType
            Value       = $Value
            LastUsedUtc = $LastUsedUtc
            Detail      = $Detail
        }
    }

    # The exclusion list most matching tests run against: one entry per class the
    # chunk requires the shipped list to cover.
    $script:FabricatedExclusionJson = @'
{
  "schemaVersion": 1,
  "entries": [
    {
      "id": "fabricated-runtime",
      "displayName": "Fabricated runtime",
      "class": "runtime",
      "reason": "Test fixture: a redistributable runtime nobody launches.",
      "match": { "registryDisplayName": ["Microsoft Visual C++*"] }
    },
    {
      "id": "fabricated-driver-utility",
      "displayName": "Fabricated driver utility",
      "class": "driver-utility",
      "reason": "Test fixture: an OEM firmware and driver update utility.",
      "match": { "registryDisplayName": ["Fabricated Driver Updater"] }
    },
    {
      "id": "fabricated-security",
      "displayName": "Fabricated security product",
      "class": "security",
      "reason": "Test fixture: security software is never flagged as unused.",
      "match": { "registryDisplayName": ["Malwarebytes*"] }
    },
    {
      "id": "fabricated-os-component",
      "displayName": "Fabricated shell component",
      "class": "os-component",
      "reason": "Test fixture: a Windows shell component.",
      "match": { "appxPackageName": ["Fabricated.Shell.*"] }
    },
    {
      "id": "fabricated-background",
      "displayName": "Fabricated background sync client",
      "class": "background",
      "reason": "Test fixture: a sync client with no window to open.",
      "match": { "registryDisplayName": ["Fabricated Sync Client"] }
    },
    {
      "id": "fabricated-driver-publisher",
      "displayName": "Fabricated driver vendor",
      "class": "driver",
      "reason": "Test fixture: publisher stands alone on the exclusion list.",
      "match": { "registryPublisher": ["Fabricated Silicon Inc."] }
    }
  ]
}
'@

    $script:FabricatedExclusionPath = New-TestExclusionFile -Content $script:FabricatedExclusionJson -Name 'fabricated-exclusions.json'
    $script:FabricatedExclusions = @(Get-UnusedAppExclusionList -Path $script:FabricatedExclusionPath)
}

AfterAll {
    Remove-Module Win11Optimizer.Engine -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\WIN11OPTIMIZER_LOGROOT -ErrorAction SilentlyContinue
    foreach ($folder in $script:TestLogRoot, $script:Scratch) {
        if ($folder -and (Test-Path -LiteralPath $folder)) {
            Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'UnusedApps detector registration' {

    $script:DetectorFunctions = @(
        'Get-UnusedAppExclusionList'
        'Get-AppUsageClassification'
        'Find-UnusedApp'
        'Invoke-UnusedAppScan'
    )

    It 'lists <_> in the manifest FunctionsToExport' -ForEach $script:DetectorFunctions {
        $manifest = Import-PowerShellDataFile -Path $script:ManifestPath
        $manifest.FunctionsToExport | Should -Contain $_
    }

    It 'lists <_> in the .psm1 Export-ModuleMember block' -ForEach $script:DetectorFunctions {
        $source = [System.IO.File]::ReadAllText($script:ModulePath)
        $source | Should -BeLike "*'$_'*"
    }

    It 'actually exports <_> from a freshly imported module' -ForEach $script:DetectorFunctions {
        (Get-Module Win11Optimizer.Engine).ExportedFunctions.Keys | Should -Contain $_
    }
}

Describe 'UnusedApps detector is read-only' {

    It 'contains no Remove-* cmdlet call anywhere in the detector source' {
        $source = [System.IO.File]::ReadAllText($script:DetectorPath)
        $forbidden = 'Remove' + '-'
        $source.Contains($forbidden) | Should -BeFalse -Because 'chunk P2-C3 detects only; the dispatcher (P3-C1) owns removal'
    }

    It 'never touches Win32_Product / WMI' {
        $source = [System.IO.File]::ReadAllText($script:DetectorPath)
        $source | Should -Not -Match 'Get-WmiObject'
        $source | Should -Not -Match 'Get-CimInstance'
        @([regex]::Matches($source, 'Win32_Product')).Count | Should -BeLessOrEqual 1
    }

    It 'never reaches for Confidence Known' {
        $source = [System.IO.File]::ReadAllText($script:DetectorPath)
        $source | Should -Not -Match "-Confidence 'Known'"
    }

    It 'keeps the detector source ASCII-only so 5.1 can parse it' {
        $bytes = [System.IO.File]::ReadAllBytes($script:DetectorPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'The three states' {

    # THE central contract of this chunk. Used and Unused are the easy half; the
    # Unknown case is what stops the detector flagging every application on a
    # machine it cannot see usage on.

    It 'classifies an app with recent-use evidence as Used and yields no Finding' {
        $app = New-TestApp -DisplayName 'Recently Used App' -InstallLocation 'C:\Apps\Recent'
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'Recently Used App' -LastUsedUtc $script:Now.AddDays(-10)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification.Count | Should -Be 1
        $classification[0].State | Should -Be 'Used'

        @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions).Count | Should -Be 0
    }

    It 'classifies an app with a usable signal showing no use in the window as Unused and yields one Finding' {
        $app = New-TestApp -DisplayName 'Long Forgotten App' -InstallDate $script:Now.AddDays(-900)
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'Long Forgotten App' -LastUsedUtc $script:Now.AddDays(-400)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State | Should -Be 'Unused'

        $findings = @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions)
        $findings.Count | Should -Be 1
        $findings[0].DisplayName | Should -Be 'Long Forgotten App'
    }

    It 'classifies an app with NO signal at all as Unknown and yields no Finding' {
        # The most important test in the chunk. "No evidence it was used" is not
        # "it was not used", and conflating the two would flag the whole machine.
        $app = New-TestApp -DisplayName 'Nothing Known About This' -InstallDate $script:Now.AddDays(-900)
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'A Completely Different App' -LastUsedUtc $script:Now.AddDays(-400)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State  | Should -Be 'Unknown'
        $classification[0].Reason | Should -Match 'absence of evidence'

        @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions).Count | Should -Be 0
    }

    It 'treats a signal that names the app but carries no launch time as Unknown, not as never-used' {
        # A UserAssist entry with a zero FILETIME exists but records nothing.
        $app = New-TestApp -DisplayName 'Entry But No Time' -InstallDate $script:Now.AddDays(-900)
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'Entry But No Time' -LastUsedUtc $null

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State | Should -Be 'Unknown'
    }

    It 'classifies every app as Unknown when there are no signals at all' {
        $apps = @(
            (New-TestApp -DisplayName 'App One'   -Id 'k1' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -DisplayName 'App Two'   -Id 'k2' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -DisplayName 'App Three' -Id 'k3' -InstallDate $script:Now.AddDays(-900))
        )

        $classification = @(Get-AppUsageClassification -InstalledApp $apps -UsageSignal @() -ReferenceUtc $script:Now)
        @($classification | Where-Object { $_.State -eq 'Unknown' }).Count | Should -Be 3
        @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions).Count | Should -Be 0
    }

    It 'records the state on every classification and never invents a fourth one' {
        $apps = @(
            (New-TestApp -DisplayName 'Used App'    -Id 'k1')
            (New-TestApp -DisplayName 'Unused App'  -Id 'k2')
            (New-TestApp -DisplayName 'Unknown App' -Id 'k3')
        )
        $signals = @(
            (New-TestSignal -MatchType 'DisplayName' -Value 'Used App'   -LastUsedUtc $script:Now.AddDays(-1))
            (New-TestSignal -MatchType 'DisplayName' -Value 'Unused App' -LastUsedUtc $script:Now.AddDays(-400))
        )

        $classification = @(Get-AppUsageClassification -InstalledApp $apps -UsageSignal $signals -ReferenceUtc $script:Now)
        @($classification.State | Sort-Object) | Should -Be @('Unknown', 'Unused', 'Used')
    }
}

Describe 'Signal joins' {

    It 'joins an Appx package by package family name' {
        $app = New-TestApp -Source 'AppxPackage' -Name 'Fabricated.Game' -DisplayName 'Fabricated.Game' `
            -PackageFamilyName 'Fabricated.Game_abcdefghijklm' -Id 'Fabricated.Game_abcdefghijklm'
        $signal = New-TestSignal -MatchType 'PackageFamilyName' -Value 'Fabricated.Game_abcdefghijklm' -LastUsedUtc $script:Now.AddDays(-400)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State | Should -Be 'Unused'
    }

    It 'joins a Win32 app by an executable path under its install location' {
        $app = New-TestApp -DisplayName 'Path Joined App' -InstallLocation 'C:\Program Files\PathJoined'
        $signal = New-TestSignal -MatchType 'ExecutablePath' -Value 'C:\Program Files\PathJoined\app.exe' -LastUsedUtc $script:Now.AddDays(-400)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State | Should -Be 'Unused'
    }

    It 'does not join an executable path that merely shares a prefix with the install location' {
        $app = New-TestApp -DisplayName 'Prefix App' -InstallLocation 'C:\Program Files\App'
        $signal = New-TestSignal -MatchType 'ExecutablePath' -Value 'C:\Program Files\AppOther\other.exe' -LastUsedUtc $script:Now.AddDays(-400)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State | Should -Be 'Unknown'
    }

    It 'joins a prefetch record by executable name' {
        $app = New-TestApp -DisplayName 'Prefetch Joined App' -ExecutableName @('THING.EXE')
        $signal = New-TestSignal -Signal 'Prefetch' -MatchType 'ExecutableName' -Value 'thing.exe' -LastUsedUtc $script:Now.AddDays(-400)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State          | Should -Be 'Unused'
        $classification[0].MatchedSignals | Should -Contain 'Prefetch'
    }

    It 'takes the most recent launch when two signals disagree, which favours keeping the app' {
        $app = New-TestApp -DisplayName 'Disputed App' -ExecutableName @('disputed.exe')
        $signals = @(
            (New-TestSignal -Signal 'UserAssist' -MatchType 'DisplayName'    -Value 'Disputed App'  -LastUsedUtc $script:Now.AddDays(-400))
            (New-TestSignal -Signal 'Prefetch'   -MatchType 'ExecutableName' -Value 'disputed.exe'  -LastUsedUtc $script:Now.AddDays(-5))
        )

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal $signals -ReferenceUtc $script:Now)
        $classification[0].State           | Should -Be 'Used'
        $classification[0].LastUsedAgeDays | Should -BeLessThan 10
        $classification[0].MatchedSignals.Count | Should -Be 2
    }

    It 'puts the disagreement in the Evidence when both signals still leave the app unused' {
        $app = New-TestApp -DisplayName 'Both Old App' -ExecutableName @('bothold.exe') -InstallDate $script:Now.AddDays(-900)
        $signals = @(
            (New-TestSignal -Signal 'UserAssist' -MatchType 'DisplayName'    -Value 'Both Old App' -LastUsedUtc $script:Now.AddDays(-500))
            (New-TestSignal -Signal 'Prefetch'   -MatchType 'ExecutableName' -Value 'bothold.exe'  -LastUsedUtc $script:Now.AddDays(-300))
        )

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal $signals -ReferenceUtc $script:Now)
        $finding = @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions)[0]

        ($finding.Evidence -join ' ') | Should -Match 'Signals disagreed'
        ($finding.Evidence -join ' ') | Should -Match 'UserAssist'
        ($finding.Evidence -join ' ') | Should -Match 'Prefetch'
        # The more recent of the two is the one that decided it.
        ($finding.Evidence -join ' ') | Should -Match '300 days ago'
    }
}

Describe 'The minimum-age rule' {

    It 'does not flag an app installed two days ago that has never been run' {
        $app = New-TestApp -DisplayName 'Brand New App' -InstallDate $script:Now.AddDays(-2)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @() -ReferenceUtc $script:Now)
        $classification[0].State | Should -Be 'Unknown'
        @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions).Count | Should -Be 0
    }

    It 'does not flag an app installed two days ago whose launch record predates the install' {
        # The case the rule actually exists for: UserAssist outlives the software
        # it describes, so a reinstall inherits last year's launch time.
        $app = New-TestApp -DisplayName 'Reinstalled App' -InstallDate $script:Now.AddDays(-2)
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'Reinstalled App' -LastUsedUtc $script:Now.AddDays(-400)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State  | Should -Be 'Unknown'
        $classification[0].Reason | Should -Match 'minimum age'

        @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions).Count | Should -Be 0
    }

    It 'flags the same app once it is past the minimum age' {
        $app = New-TestApp -DisplayName 'Reinstalled App' -InstallDate $script:Now.AddDays(-200)
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'Reinstalled App' -LastUsedUtc $script:Now.AddDays(-400)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State | Should -Be 'Unused'
    }

    It 'honours a raised minimum age' {
        $app = New-TestApp -DisplayName 'Fairly New App' -InstallDate $script:Now.AddDays(-60)
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'Fairly New App' -LastUsedUtc $script:Now.AddDays(-400)

        (@(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now -MinimumAgeDays 30))[0].State  | Should -Be 'Unused'
        (@(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now -MinimumAgeDays 90))[0].State  | Should -Be 'Unknown'
    }

    It 'still flags an app with no recorded install date, because the signal is all there is' {
        $app = New-TestApp -DisplayName 'No Install Date App' -InstallDate $null
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'No Install Date App' -LastUsedUtc $script:Now.AddDays(-400)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $classification[0].State | Should -Be 'Unused'

        $finding = @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions)[0]
        ($finding.Evidence -join ' ') | Should -Match 'no usable install date'
    }
}

Describe 'Thresholds are parameters, not magic numbers' {

    BeforeAll {
        $script:ThresholdApps = @(
            (New-TestApp -DisplayName 'Used 45 days ago'  -Id 'k1' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -DisplayName 'Used 200 days ago' -Id 'k2' -InstallDate $script:Now.AddDays(-900))
        )
        $script:ThresholdSignals = @(
            (New-TestSignal -MatchType 'DisplayName' -Value 'Used 45 days ago'  -LastUsedUtc $script:Now.AddDays(-45))
            (New-TestSignal -MatchType 'DisplayName' -Value 'Used 200 days ago' -LastUsedUtc $script:Now.AddDays(-200))
        )
    }

    It 'flags only the 200-day app at the 180-day default' {
        $classification = @(Get-AppUsageClassification -InstalledApp $script:ThresholdApps -UsageSignal $script:ThresholdSignals -ReferenceUtc $script:Now)
        $findings = @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions)
        @($findings.DisplayName) | Should -Be @('Used 200 days ago')
    }

    It 'flags both once the window drops to 30 days' {
        $classification = @(Get-AppUsageClassification -InstalledApp $script:ThresholdApps -UsageSignal $script:ThresholdSignals -ReferenceUtc $script:Now -UnusedWindowDays 30)
        $findings = @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions)
        @($findings.DisplayName | Sort-Object) | Should -Be @('Used 200 days ago', 'Used 45 days ago')
    }

    It 'flags neither once the window rises to 365 days' {
        $classification = @(Get-AppUsageClassification -InstalledApp $script:ThresholdApps -UsageSignal $script:ThresholdSignals -ReferenceUtc $script:Now -UnusedWindowDays 365)
        @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions).Count | Should -Be 0
    }

    It 'documents 180 and 30 as the defaults in comment help' {
        $help = Get-Help Get-AppUsageClassification -Full
        ($help | Out-String) | Should -Match 'Default 180'
        ($help | Out-String) | Should -Match 'Default 30'
    }

    It 'uses the documented defaults when no threshold is supplied' {
        $classification = @(Get-AppUsageClassification -InstalledApp $script:ThresholdApps -UsageSignal $script:ThresholdSignals -ReferenceUtc $script:Now)
        $classification[0].UnusedWindowDays | Should -Be 180
        $classification[0].MinimumAgeDays   | Should -Be 30
    }
}

Describe 'The exclusion list suppresses Findings' {

    It 'produces zero Findings for runtimes, a driver utility, security software, a shell component and a background sync client, even with signals showing no use' {
        $apps = @(
            (New-TestApp -Id 'k1' -DisplayName 'Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.30501' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -Id 'k2' -DisplayName 'Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.51.36247' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -Id 'k3' -DisplayName 'Fabricated Driver Updater' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -Id 'k4' -DisplayName 'Malwarebytes version 5.6.3.284' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -Id 'k5' -Source 'AppxPackage' -Name 'Fabricated.Shell.LockApp' -DisplayName 'Fabricated.Shell.LockApp' -PackageFamilyName 'Fabricated.Shell.LockApp_abcdefghijklm' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -Id 'k6' -DisplayName 'Fabricated Sync Client' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -Id 'k7' -DisplayName 'Fabricated GPIO Driver' -Publisher 'Fabricated Silicon Inc.' -InstallDate $script:Now.AddDays(-900))
        )
        $signals = @($apps | ForEach-Object {
            New-TestSignal -MatchType 'DisplayName' -Value $_.DisplayName -LastUsedUtc $script:Now.AddDays(-800)
        })

        $classification = @(Get-AppUsageClassification -InstalledApp $apps -UsageSignal $signals -ReferenceUtc $script:Now)
        # They are honestly classified Unused -- the exclusion list suppresses the
        # Finding, it does not rewrite the evidence.
        @($classification | Where-Object { $_.State -eq 'Unused' }).Count | Should -Be 7

        @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions).Count | Should -Be 0
    }

    It 'still flags an unrelated app in the same batch' {
        $apps = @(
            (New-TestApp -Id 'k1' -DisplayName 'Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.30501' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -Id 'k2' -DisplayName 'Some Ordinary Program' -InstallDate $script:Now.AddDays(-900))
        )
        $signals = @($apps | ForEach-Object {
            New-TestSignal -MatchType 'DisplayName' -Value $_.DisplayName -LastUsedUtc $script:Now.AddDays(-800)
        })

        $classification = @(Get-AppUsageClassification -InstalledApp $apps -UsageSignal $signals -ReferenceUtc $script:Now)
        $findings = @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions)
        @($findings.DisplayName) | Should -Be @('Some Ordinary Program')
    }

    It 'treats registryPublisher as a match in its own right, unlike the OEM whitelist' {
        $app = New-TestApp -DisplayName 'Anything At All' -Publisher 'Fabricated Silicon Inc.' -InstallDate $script:Now.AddDays(-900)
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'Anything At All' -LastUsedUtc $script:Now.AddDays(-800)

        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions).Count | Should -Be 0
    }
}

Describe 'The shipped exclusion list' {

    BeforeAll { $script:Entries = @(Get-UnusedAppExclusionList) }

    It 'loads from JSON and returns at least one entry' {
        $script:Entries.Count | Should -BeGreaterThan 0
    }

    It 'lives in Data\ as JSON, not hard-coded in a .ps1' {
        Test-Path -LiteralPath $script:ListPath -PathType Leaf | Should -BeTrue
    }

    It 'gives every entry a non-empty reason, display name and class' {
        foreach ($entry in $script:Entries) {
            $entry.Id          | Should -Not -BeNullOrEmpty
            $entry.DisplayName | Should -Not -BeNullOrEmpty
            $entry.Class       | Should -Not -BeNullOrEmpty
            $entry.Reason      | Should -Not -BeNullOrEmpty
        }
    }

    It 'gives every entry at least one match rule' {
        foreach ($entry in $script:Entries) {
            $ruleCount = @($entry.AppxPackageName).Count + @($entry.AppxPackageFamilyName).Count +
                         @($entry.RegistryDisplayName).Count + @($entry.RegistryPublisher).Count
            $ruleCount | Should -BeGreaterThan 0 -Because "entry '$($entry.Id)' must match something"
        }
    }

    It 'covers the class <_>, which the chunk requires' -ForEach @(
        'runtime', 'driver', 'driver-utility', 'security', 'os-component', 'background'
    ) {
        $class = $_
        @($script:Entries | Where-Object { $_.Class -eq $class }).Count | Should -BeGreaterThan 0
    }

    It 'covers a Visual C++ redistributable by its real display name' {
        $app = New-TestApp -DisplayName 'Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030'
        InModuleScope Win11Optimizer.Engine -Parameters @{ App = $app; Entries = $script:Entries } {
            param($App, $Entries)
            Get-UnusedAppExclusionMatch -InstalledApp $App -ExclusionEntry $Entries | Should -Not -BeNullOrEmpty
        }
    }

    It 'covers <Name> published by <Publisher>' -ForEach @(
        @{ Name = 'NVIDIA Container';                  Publisher = 'NVIDIA Corporation' }
        @{ Name = 'AMD Chipset Software';              Publisher = 'Advanced Micro Devices, Inc.' }
        @{ Name = 'Realtek Ethernet Controller Driver'; Publisher = 'Realtek' }
        @{ Name = 'ENE_MousePad_HAL';                  Publisher = 'ENE TECHNOLOGY INC.' }
        @{ Name = 'Corsair Device Control Service';    Publisher = 'Corsair' }
        @{ Name = 'Malwarebytes version 5.6.3.284';    Publisher = 'Malwarebytes' }
        @{ Name = 'Riot Vanguard';                     Publisher = 'Riot Games, Inc.' }
        @{ Name = 'Microsoft OneDrive';                Publisher = 'Microsoft Corporation' }
        @{ Name = 'Google Drive';                      Publisher = 'Google LLC' }
        @{ Name = 'Epic Online Services';              Publisher = 'Epic Games, Inc.' }
        @{ Name = 'Microsoft Edge WebView2 Runtime';   Publisher = 'Microsoft Corporation' }
        @{ Name = 'Surfshark';                         Publisher = 'Surfshark' }
        @{ Name = 'Python 3.14.5 Core Interpreter (64-bit)'; Publisher = 'Python Software Foundation' }
    ) {
        $app = New-TestApp -DisplayName $Name -Publisher $Publisher
        InModuleScope Win11Optimizer.Engine -Parameters @{ App = $app; Entries = $script:Entries } {
            param($App, $Entries)
            Get-UnusedAppExclusionMatch -InstalledApp $App -ExclusionEntry $Entries | Should -Not -BeNullOrEmpty
        }
    }

    It 'covers the Store-published driver utility <_>' -ForEach @(
        '9426MICRO-STARINTERNATION.MSICenter'
        'NVIDIACorp.NVIDIAControlPanel'
        'RealtekSemiconductorCorp.RealtekAudioControl'
        'Malwarebytes.AntiMalware'
        'MicrosoftCorporationII.WinAppRuntime.Main.1.8'
    ) {
        $app = New-TestApp -Source 'AppxPackage' -Name $_ -DisplayName $_
        InModuleScope Win11Optimizer.Engine -Parameters @{ App = $app; Entries = $script:Entries } {
            param($App, $Entries)
            Get-UnusedAppExclusionMatch -InstalledApp $App -ExclusionEntry $Entries | Should -Not -BeNullOrEmpty
        }
    }

    It 'does not exclude an ordinary third-party application' {
        $app = New-TestApp -DisplayName 'Some Ordinary Program' -Publisher 'Some Vendor Ltd.'
        InModuleScope Win11Optimizer.Engine -Parameters @{ App = $app; Entries = $script:Entries } {
            param($App, $Entries)
            Get-UnusedAppExclusionMatch -InstalledApp $App -ExclusionEntry $Entries | Should -BeNullOrEmpty
        }
    }
}

Describe 'Exclusion list loading fails loudly' {

    BeforeAll {
        $script:MinimalMatch = '"match": { "registryDisplayName": ["Fabricated App"] }'
    }

    It 'throws when the exclusion file is missing' {
        $missing = Join-Path $script:Scratch 'nope-exclusions.json'
        { Get-UnusedAppExclusionList -Path $missing } | Should -Throw -ExpectedMessage '*not found*'
    }

    It 'throws when the exclusion file is empty' {
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content '   ') } | Should -Throw -ExpectedMessage '*is empty*'
    }

    It 'throws when the exclusion file is not valid JSON' {
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content '{ "entries": [ {') } | Should -Throw
    }

    It 'throws when there is no entries array' {
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content '{ "schemaVersion": 1 }') } | Should -Throw -ExpectedMessage "*no 'entries' array*"
    }

    It 'throws when the entries array is empty' {
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content '{ "entries": [] }') } | Should -Throw -ExpectedMessage '*no entries*'
    }

    It 'throws when an entry has no reason' {
        $json = '{ "entries": [ { "id": "x", "displayName": "X", "class": "runtime", ' + $script:MinimalMatch + ' } ] }'
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json) } | Should -Throw -ExpectedMessage "*'reason'*"
    }

    It 'throws when an entry has no class' {
        $json = '{ "entries": [ { "id": "x", "displayName": "X", "reason": "R", ' + $script:MinimalMatch + ' } ] }'
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json) } | Should -Throw -ExpectedMessage "*'class'*"
    }

    It 'throws on an unknown class rather than treating it as an ordinary entry' {
        $json = '{ "entries": [ { "id": "x", "displayName": "X", "class": "runtimes", "reason": "R", ' + $script:MinimalMatch + ' } ] }'
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json) } | Should -Throw -ExpectedMessage "*unknown 'class'*"
    }

    It 'throws when an entry has no match block' {
        $json = '{ "entries": [ { "id": "x", "displayName": "X", "class": "runtime", "reason": "R" } ] }'
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json) } | Should -Throw -ExpectedMessage "*'match'*"
    }

    It 'throws on a duplicate entry id' {
        $one  = '{ "id": "x", "displayName": "X", "class": "runtime", "reason": "R", ' + $script:MinimalMatch + ' }'
        $json = '{ "entries": [ ' + $one + ', ' + $one + ' ] }'
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json) } | Should -Throw -ExpectedMessage '*duplicate*'
    }

    It 'throws on an unknown match field rather than silently disabling the entry' {
        $json = '{ "entries": [ { "id": "x", "displayName": "X", "class": "runtime", "reason": "R", "match": { "serviceName": ["thing"] } } ] }'
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json) } | Should -Throw -ExpectedMessage '*unknown match field*'
    }

    It 'rejects the over-broad pattern <_>' -ForEach @('*', 'A*', 'Some*Package', '*Package') {
        $json = '{ "entries": [ { "id": "x", "displayName": "X", "class": "runtime", "reason": "R", "match": { "registryDisplayName": ["' + $_ + '"] } } ] }'
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json) } | Should -Throw
    }

    It 'accepts a constrained trailing wildcard' {
        $json = '{ "entries": [ { "id": "x", "displayName": "X", "class": "runtime", "reason": "R", "match": { "registryDisplayName": ["Fabricat*"] } } ] }'
        $entries = @(Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json))
        $entries.Count | Should -Be 1
        $entries[0].RegistryDisplayName | Should -Be @('Fabricat*')
    }

    It 'reports an empty match block in its own words, not in strict mode''s' {
        # $match.PSObject.Properties.Name throws "the property 'Name' cannot be
        # found" under Set-StrictMode -Version Latest when the collection is EMPTY,
        # which turned a bad list entry into a message about nothing. Cosmetic --
        # it threw either way -- but the loader has to be the one talking.
        $json = '{ "entries": [ { "id": "x", "displayName": "X", "class": "runtime", "reason": "R", "match": { } } ] }'
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json) } | Should -Throw -ExpectedMessage "*empty 'match' block*"
    }

    It 'throws on a match field declared with no patterns' {
        $json = '{ "entries": [ { "id": "x", "displayName": "X", "class": "runtime", "reason": "R", "match": { "registryDisplayName": [] } } ] }'
        { Get-UnusedAppExclusionList -Path (New-TestExclusionFile -Content $json) } | Should -Throw
    }
}

Describe 'Finding output contract' {

    BeforeAll {
        $apps = @(
            (New-TestApp -Id 'HKLM:\Uninstall\A' -DisplayName 'Unused Win32 App' -Publisher 'A Vendor' -Version '1.2.3' `
                -InstallLocation 'C:\Program Files\UnusedWin32' -InstallDate $script:Now.AddDays(-900) -EstimatedSizeKb 262144)
            (New-TestApp -Id 'Unused.Appx_abcdefghijklm' -Source 'AppxPackage' -Name 'Unused.Appx' -DisplayName 'Unused.Appx' `
                -PackageFamilyName 'Unused.Appx_abcdefghijklm' -InstallDate $script:Now.AddDays(-900))
        )
        $signals = @(
            (New-TestSignal -MatchType 'DisplayName' -Value 'Unused Win32 App' -LastUsedUtc $script:Now.AddDays(-400) -Detail "Start-menu or taskbar shortcut 'Unused Win32 App'")
            (New-TestSignal -MatchType 'PackageFamilyName' -Value 'Unused.Appx_abcdefghijklm' -LastUsedUtc $script:Now.AddDays(-400) -Detail 'AppUserModelID Unused.Appx_abcdefghijklm!App')
        )
        $script:Classifications = @(Get-AppUsageClassification -InstalledApp $apps -UsageSignal $signals -ReferenceUtc $script:Now)
        $script:Findings = @(Find-UnusedApp -Classification $script:Classifications -ExclusionEntry $script:FabricatedExclusions)
    }

    It 'produced findings to assert on' {
        $script:Findings.Count | Should -Be 2
    }

    It 'returns only objects that pass Test-Finding' {
        foreach ($finding in $script:Findings) { Test-Finding -InputObject $finding | Should -BeTrue }
    }

    It 'tags every finding as Win11Optimizer.Finding' {
        foreach ($finding in $script:Findings) {
            $finding.PSObject.TypeNames | Should -Contain 'Win11Optimizer.Finding'
        }
    }

    It 'puts every finding in the UnusedApp category' {
        foreach ($finding in $script:Findings) { $finding.Category | Should -Be 'UnusedApp' }
    }

    It 'emits Confidence = Heuristic on every finding, never Known' {
        foreach ($finding in $script:Findings) { $finding.Confidence | Should -Be 'Heuristic' }
    }

    It 'labels every finding "Review needed"' {
        foreach ($finding in $script:Findings) { $finding.SafetyLabel | Should -Be 'Review needed' }
    }

    It 'leaves RequiresConsent false -- consent is a different question from uncertainty' {
        foreach ($finding in $script:Findings) {
            $finding.RequiresConsent | Should -BeFalse
            $finding.RequiresConsent | Should -BeOfType [bool]
        }
    }

    It 'assigns Appx to a package and RegistryUninstallString to an uninstall entry' {
        $byName = @{}
        foreach ($finding in $script:Findings) { $byName[$finding.DisplayName] = $finding }
        $byName['Unused Win32 App'].RemovalMethod | Should -Be 'RegistryUninstallString'
        $byName['Unused.Appx'].RemovalMethod      | Should -Be 'Appx'
    }

    It 'never assigns PackageManagement' {
        foreach ($finding in $script:Findings) { $finding.RemovalMethod | Should -Not -Be 'PackageManagement' }
    }

    It 'assigns a removal method that is in the Finding contract' {
        $contract = Get-FindingContract
        foreach ($finding in $script:Findings) { $contract.RemovalMethods | Should -Contain $finding.RemovalMethod }
    }

    It 'emits one Finding per app even when the same app is inventoried twice' {
        $duplicate = @(
            (New-TestApp -Id 'Unused.Appx_abcdefghijklm' -Source 'AppxPackage' -Name 'Unused.Appx' -DisplayName 'Unused.Appx' -PackageFamilyName 'Unused.Appx_abcdefghijklm' -InstallDate $script:Now.AddDays(-900))
            (New-TestApp -Id 'Unused.Appx_abcdefghijklm' -Source 'AppxProvisionedPackage' -Name 'Unused.Appx' -DisplayName 'Unused.Appx' -PackageFamilyName 'Unused.Appx_abcdefghijklm' -InstallDate $script:Now.AddDays(-900))
        )
        $signal = New-TestSignal -MatchType 'PackageFamilyName' -Value 'Unused.Appx_abcdefghijklm' -LastUsedUtc $script:Now.AddDays(-400)
        $classification = @(Get-AppUsageClassification -InstalledApp $duplicate -UsageSignal @($signal) -ReferenceUtc $script:Now)
        @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions).Count | Should -Be 1
    }
}

Describe 'Evidence content' {

    BeforeAll {
        $app = New-TestApp -Id 'HKLM:\Uninstall\Evidence' -DisplayName 'Evidence App' -Publisher 'Evidence Vendor' `
            -Version '4.5.6' -InstallLocation 'C:\Program Files\Evidence' -InstallDate ([datetime]::new(2024, 4, 2)) -EstimatedSizeKb 204800
        $signal = New-TestSignal -Signal 'UserAssist' -MatchType 'DisplayName' -Value 'Evidence App' `
            -LastUsedUtc ([datetime]::new(2026, 2, 19, 0, 0, 0, [System.DateTimeKind]::Utc)) `
            -Detail "Start-menu or taskbar shortcut 'Evidence App'"
        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now)
        $script:EvidenceFinding = @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions)[0]
        $script:EvidenceText = ($script:EvidenceFinding.Evidence -join ' ')
    }

    It 'produced a finding to assert on' {
        $script:EvidenceFinding | Should -Not -BeNullOrEmpty
    }

    It 'names which signal produced the judgement' {
        $script:EvidenceText | Should -Match 'UserAssist'
    }

    It 'says what that signal actually said' {
        $script:EvidenceText | Should -Match "shortcut 'Evidence App'"
    }

    It 'gives the last-use date and its age' {
        $script:EvidenceText | Should -Match '2026-02-19'
        $script:EvidenceText | Should -Match '187\.5 days ago'
    }

    It 'gives the install date' {
        $script:EvidenceText | Should -Match '2024-04-02'
    }

    It 'states BOTH threshold values as the actual numbers used' {
        $script:EvidenceText | Should -Match 'unused window 180 days'
        $script:EvidenceText | Should -Match 'minimum age 30 days'
    }

    It 'carries the changed threshold, not the default, when one is overridden' {
        $app = New-TestApp -DisplayName 'Evidence App' -InstallDate ([datetime]::new(2024, 4, 2))
        $signal = New-TestSignal -MatchType 'DisplayName' -Value 'Evidence App' -LastUsedUtc $script:Now.AddDays(-60)
        $classification = @(Get-AppUsageClassification -InstalledApp @($app) -UsageSignal @($signal) -ReferenceUtc $script:Now -UnusedWindowDays 45 -MinimumAgeDays 10)
        $finding = @(Find-UnusedApp -Classification $classification -ExclusionEntry $script:FabricatedExclusions)[0]
        ($finding.Evidence -join ' ') | Should -Match 'unused window 45 days'
        ($finding.Evidence -join ' ') | Should -Match 'minimum age 10 days'
    }

    It 'identifies the application and where it lives' {
        $script:EvidenceText | Should -Match 'Evidence Vendor'
        $script:EvidenceText | Should -Match '4\.5\.6'
        $script:EvidenceText | Should -Match 'C:\\Program Files\\Evidence'
    }

    It 'reports the disk size the uninstall key claims' {
        $script:EvidenceText | Should -Match '200 MB'
    }

    It 'says out loud that this is a heuristic and not proof' {
        $script:EvidenceText | Should -Match 'heuristic finding'
    }
}

Describe 'Signal readers' {

    It 'decodes a ROT13 UserAssist value name' {
        InModuleScope Win11Optimizer.Engine {
            ConvertFrom-UnusedAppRot13 -Value 'Zvpebfbsg.JvaqbjfAbgrcnq_8jrxlo3q8oojr!Ncc' |
                Should -Be 'Microsoft.WindowsNotepad_8wekyb3d8bbwe!App'
        }
    }

    It 'leaves digits, braces and separators alone when decoding' {
        InModuleScope Win11Optimizer.Engine {
            ConvertFrom-UnusedAppRot13 -Value '{123-nop}' | Should -Be '{123-abc}'
        }
    }

    It 'reads the real UserAssist hive without throwing and returns dated signals only' {
        InModuleScope Win11Optimizer.Engine {
            $signals = @(Get-UserAssistUsageSignal)
            foreach ($signal in $signals) {
                $signal.LastUsedUtc | Should -Not -BeNullOrEmpty
                $signal.Signal      | Should -Be 'UserAssist'
                $signal.MatchType   | Should -BeIn @('PackageFamilyName', 'ExecutablePath', 'DisplayName')
            }
        }
    }

    It 'never emits an Explorer session counter as a usage signal' {
        InModuleScope Win11Optimizer.Engine {
            foreach ($signal in @(Get-UserAssistUsageSignal)) {
                $signal.Value | Should -Not -Match '^UEME_'
            }
        }
    }

    It 'never emits a UserAssist timestamp from before 2000' {
        # Explorer writes nonsense into some records -- this machine has one dated
        # 1641. A launch in the seventeenth century is not evidence of anything.
        InModuleScope Win11Optimizer.Engine {
            foreach ($signal in @(Get-UserAssistUsageSignal)) {
                ([datetime]$signal.LastUsedUtc).Year | Should -BeGreaterOrEqual 2000
            }
        }
    }

    It 'throws rather than returning nothing when the UserAssist key is missing' {
        InModuleScope Win11Optimizer.Engine {
            { Get-UserAssistUsageSignal -Path 'HKCU:\Software\Win11Optimizer\NoSuchUserAssist' } | Should -Throw
        }
    }

    It 'reports a prefetch folder that does not exist as unavailable, with a reason' {
        InModuleScope Win11Optimizer.Engine {
            $status = Test-UnusedAppPrefetchAvailable -Path (Join-Path ([System.IO.Path]::GetTempPath()) ('nope-' + [guid]::NewGuid().ToString('N')))
            $status.Available | Should -BeFalse
            $status.Reason    | Should -Match 'does not exist'
        }
    }

    It 'reports a readable prefetch folder as available' {
        $folder = Join-Path $script:Scratch ('pf-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $folder -ItemType Directory -Force
        InModuleScope Win11Optimizer.Engine -Parameters @{ Folder = $folder } {
            param($Folder)
            (Test-UnusedAppPrefetchAvailable -Path $Folder).Available | Should -BeTrue
        }
    }

    It 'parses a .pf filename into the executable name and takes its write time as the last run' {
        $folder = Join-Path $script:Scratch ('pf2-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $folder -ItemType Directory -Force
        $file = Join-Path $folder 'NOTEPAD.EXE-D8414F97.pf'
        [System.IO.File]::WriteAllText($file, 'not a real prefetch file')
        $stamp = [datetime]::new(2025, 3, 4, 5, 6, 7, [System.DateTimeKind]::Utc)
        [System.IO.File]::SetLastWriteTimeUtc($file, $stamp)

        InModuleScope Win11Optimizer.Engine -Parameters @{ Folder = $folder; Stamp = $stamp } {
            param($Folder, $Stamp)
            $signals = @(Get-PrefetchUsageSignal -Path $Folder)
            $signals.Count           | Should -Be 1
            $signals[0].Signal       | Should -Be 'Prefetch'
            $signals[0].MatchType    | Should -Be 'ExecutableName'
            $signals[0].Value        | Should -Be 'NOTEPAD.EXE'
            ([datetime]$signals[0].LastUsedUtc).ToString('o') | Should -Be $Stamp.ToString('o')
        }
    }

    It 'always reports filesystem last-access as unavailable, with the machine setting in the reason' {
        InModuleScope Win11Optimizer.Engine {
            $status = Get-UnusedAppLastAccessStatus
            $status.Available | Should -BeFalse
            $status.Reason    | Should -Match 'NtfsDisableLastAccessUpdate|not set'
            $status.Reason    | Should -Match 'saturated'
        }
    }
}

Describe 'Invoke-UnusedAppScan result shape' {

    BeforeAll { $script:Scan = Invoke-UnusedAppScan -WarningAction SilentlyContinue }

    It 'returns a single scan-result object, not a bare array of findings' {
        @($script:Scan).Count | Should -Be 1
        $script:Scan.PSObject.TypeNames | Should -Contain 'Win11Optimizer.UnusedAppScanResult'
        $script:Scan.PSObject.TypeNames | Should -Contain 'Win11Optimizer.ScanResult'
        $script:Scan.PSObject.Properties.Name | Should -Contain 'Findings'
    }

    It 'reports one source record per inventory source and per usage signal' {
        @($script:Scan.Sources).Name | Should -Be @(
            'AppxPackage', 'RegistryUninstall', 'UserAssist', 'Prefetch', 'FileSystemLastAccess'
        )
    }

    It 'gives every non-succeeded source a stated reason' {
        foreach ($source in $script:Scan.Sources) {
            if ($source.Status -ne 'Succeeded') { $source.Reason | Should -Not -BeNullOrEmpty }
        }
    }

    It 'reports the three-state counts and the total considered' -ForEach @(
        'ConsideredCount', 'UsedCount', 'UnusedCount', 'UnknownCount', 'ExcludedCount'
    ) {
        $script:Scan.PSObject.Properties.Name | Should -Contain $_
    }

    It 'has the three states add up to the total considered' {
        ($script:Scan.UsedCount + $script:Scan.UnusedCount + $script:Scan.UnknownCount) | Should -Be $script:Scan.ConsideredCount
    }

    It 'reports the thresholds it actually used' {
        $script:Scan.UnusedWindowDays | Should -Be 180
        $script:Scan.MinimumAgeDays   | Should -Be 30
    }

    It 'never emits more Findings than it classified Unused' {
        @($script:Scan.Findings).Count | Should -BeLessOrEqual $script:Scan.UnusedCount
    }

    It 'accounts for every suppressed Unused app in ExcludedCount' {
        (@($script:Scan.Findings).Count + $script:Scan.ExcludedCount) | Should -Be $script:Scan.UnusedCount
    }

    It 'returns findings that all pass the Finding contract' {
        foreach ($finding in @($script:Scan.Findings)) {
            Test-Finding -InputObject $finding | Should -BeTrue
            $finding.Category    | Should -Be 'UnusedApp'
            $finding.Confidence  | Should -Be 'Heuristic'
            $finding.SafetyLabel | Should -Be 'Review needed'
            @($finding.Evidence).Count | Should -BeGreaterThan 0
        }
    }

    It 'records a duration for the scan and for each source' {
        $script:Scan.DurationSeconds | Should -BeGreaterOrEqual 0
        foreach ($source in $script:Scan.Sources) { $source.DurationSeconds | Should -BeGreaterOrEqual 0 }
    }

    It 'logs the scan start, each source outcome and the three-state counts' {
        $records = @(Get-OptimizerLog)
        @($records | Where-Object { $_.Event -eq 'UnusedAppScanStarted' }).Count   | Should -BeGreaterThan 0
        @($records | Where-Object { $_.Event -eq 'UnusedAppScanSource' }).Count    | Should -BeGreaterOrEqual 5
        $completed = @($records | Where-Object { $_.Event -eq 'UnusedAppScanCompleted' })
        $completed.Count | Should -BeGreaterThan 0
        $completed[-1].Data.PSObject.Properties.Name | Should -Contain 'UnknownCount'
    }
}

Describe 'Invoke-UnusedAppScan when no signal is available' {

    # The "silently returned nothing" test. A machine this detector cannot see
    # usage on must not come back looking like a clean machine.

    BeforeAll {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-UserAssistUsageSignal -MockWith { throw 'UserAssist hive unreadable.' }
        $script:BlindScan = Invoke-UnusedAppScan -PrefetchPath (Join-Path $script:Scratch ('nope-' + [guid]::NewGuid().ToString('N'))) -WarningAction SilentlyContinue
    }

    It 'returns zero Findings' {
        @($script:BlindScan.Findings).Count | Should -Be 0
    }

    It 'classifies every app it considered as Unknown' {
        $script:BlindScan.UnknownCount | Should -Be $script:BlindScan.ConsideredCount
        $script:BlindScan.UnknownCount | Should -BeGreaterThan 0
        $script:BlindScan.UsedCount    | Should -Be 0
        $script:BlindScan.UnusedCount  | Should -Be 0
    }

    It 'reports itself incomplete' {
        $script:BlindScan.IsComplete  | Should -BeFalse
        $script:BlindScan.SummaryText | Should -Match 'PARTIAL'
    }

    It 'names every unavailable signal in the incomplete reason' {
        # FileSystemLastAccess deliberately does NOT appear here as of chunk P2-C2:
        # it is Refused, not unavailable. A signal this project will never use on
        # any machine is not a degradation of this run, and counting it as one made
        # every scan PARTIAL forever. It is still named in Sources with its full
        # reason -- asserted below.
        $script:BlindScan.IncompleteReason | Should -Match 'UserAssist'
        $script:BlindScan.IncompleteReason | Should -Match 'Prefetch'
        $script:BlindScan.IncompleteReason | Should -Not -Match 'FileSystemLastAccess'
    }

    It 'still carries the refused last-access signal in Sources, with its reason' {
        $lastAccess = @($script:BlindScan.Sources | Where-Object { $_.Name -eq 'FileSystemLastAccess' })[0]
        $lastAccess.Status | Should -Be 'Refused'
        $lastAccess.Reason | Should -Match 'saturated'
        $script:BlindScan.RefusedSourceName | Should -Contain 'FileSystemLastAccess'
    }

    It 'warns on the warning stream' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-UserAssistUsageSignal -MockWith { throw 'UserAssist hive unreadable.' }
        $warnings = @()
        $null = Invoke-UnusedAppScan -PrefetchPath (Join-Path $script:Scratch 'still-nope') -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join ' ') | Should -Match 'INCOMPLETE'
    }

    It 'still inventoried the machine, so zero Findings is visibly not zero apps' {
        $script:BlindScan.InventoryCount | Should -BeGreaterThan 0
    }
}

Describe 'Invoke-UnusedAppScan source failures' {

    It 'reports a failed Appx source instead of silently returning nothing' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-OemAppxPackageItem -MockWith { throw 'Appx subsystem unavailable.' }
        $scan = Invoke-UnusedAppScan -WarningAction SilentlyContinue
        $appx = @($scan.Sources | Where-Object { $_.Name -eq 'AppxPackage' })[0]
        $appx.Status     | Should -Be 'Failed'
        $appx.Reason     | Should -Match 'Appx subsystem unavailable'
        $scan.IsComplete | Should -BeFalse
    }

    It 'skips prefetch with an actionable reason when it cannot be read' {
        $scan = Invoke-UnusedAppScan -WarningAction SilentlyContinue
        $prefetch = @($scan.Sources | Where-Object { $_.Name -eq 'Prefetch' })[0]
        if ($prefetch.Status -ne 'Succeeded') {
            $prefetch.Status | Should -Be 'Skipped'
            $prefetch.Reason | Should -Not -BeNullOrEmpty
        }
    }

    It 'always reports FileSystemLastAccess as refused, never as silence' {
        # Was 'Skipped' before chunk P2-C2. The status changed because the two
        # words mean different things: 'Skipped' is environmental and could have
        # gone the other way somewhere else, and this signal never can. What has
        # not changed is that the source is present and carries its reason.
        $scan = Invoke-UnusedAppScan -WarningAction SilentlyContinue
        $lastAccess = @($scan.Sources | Where-Object { $_.Name -eq 'FileSystemLastAccess' })[0]
        $lastAccess.Status | Should -Be 'Refused'
        $lastAccess.Reason | Should -Not -BeNullOrEmpty
    }

    It 'reports a complete scan when every real signal succeeds, with the refused one still in Sources' {
        # The shape a fully-elevated run has. Asserted with prefetch mocked
        # available rather than by requiring an elevated test host, so it holds on
        # any machine: before chunk P2-C2 this exact scan still said PARTIAL.
        Mock -ModuleName Win11Optimizer.Engine -CommandName Test-IsElevated -MockWith { $true }
        Mock -ModuleName Win11Optimizer.Engine -CommandName Test-UnusedAppPrefetchAvailable -MockWith { [pscustomobject]@{ Available = $true; Reason = $null } }
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-PrefetchUsageSignal -MockWith { @() }

        $scan = Invoke-UnusedAppScan -WarningAction SilentlyContinue

        $scan.IsComplete       | Should -BeTrue
        $scan.IncompleteReason | Should -BeNullOrEmpty
        $scan.SummaryText      | Should -Not -Match 'PARTIAL'
        $scan.SummaryText      | Should -Match 'not used by design \(FileSystemLastAccess\)'

        $lastAccess = @($scan.Sources | Where-Object { $_.Name -eq 'FileSystemLastAccess' })[0]
        $lastAccess.Status | Should -Be 'Refused'
        $lastAccess.Reason | Should -Match 'saturated'
        $lastAccess.Reason.Length | Should -BeGreaterThan 200
    }

    It 'is not made incomplete by the refused last-access signal alone' {
        # The bug this replaced: a fully-elevated scan with every real signal
        # succeeding still reported PARTIAL, forever, on every machine, because of
        # this one source. Asserted structurally rather than against this machine's
        # elevation, so it holds either way.
        $scan = Invoke-UnusedAppScan -WarningAction SilentlyContinue
        $degraded = @($scan.Sources | Where-Object { $_.Status -eq 'Skipped' -or $_.Status -eq 'Failed' })
        if ($degraded.Count -eq 0) {
            $scan.IsComplete  | Should -BeTrue
            $scan.SummaryText | Should -Not -Match 'PARTIAL'
            $scan.SummaryText | Should -Match 'FileSystemLastAccess'
        }
        else {
            # Something genuinely degraded this run; the refused source still must
            # not be one of the reasons.
            $scan.IncompleteReason | Should -Not -Match 'FileSystemLastAccess'
        }
    }
}

Describe 'Invoke-UnusedAppScan exclusion-list failure' {

    It 'throws rather than returning an apparently-clean result when the exclusion list is missing' {
        $missing = Join-Path $script:Scratch 'gone-exclusions.json'
        { Invoke-UnusedAppScan -ExclusionPath $missing } | Should -Throw -ExpectedMessage '*not found*'
    }

    It 'throws rather than flagging every runtime when the exclusion list is malformed' {
        $path = New-TestExclusionFile -Content '{ "entries": [ {'
        { Invoke-UnusedAppScan -ExclusionPath $path } | Should -Throw
    }
}
