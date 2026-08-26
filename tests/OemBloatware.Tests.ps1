#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the OemBloatware detector (chunk P2-C1).

    Everything that asserts matching, deduplication or completeness behaviour runs
    against fabricated whitelists and fabricated inventory records, so the suite does
    not depend on any particular software being installed on the machine running it.
    The few tests that do touch the real machine assert invariants only (shape,
    contract, completeness bookkeeping), never a specific app.

    Run:  .\tests\Invoke-Tests.ps1
#>

BeforeAll {
    $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot   = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath   = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:DetectorPath = Join-Path $script:EngineRoot 'Detectors\OemBloatware.ps1'
    $script:ListPath     = Join-Path $script:EngineRoot 'Data\known-bloatware.json'

    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-oem-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-oem-data-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    # Writes a whitelist file and returns its path. Kept as a helper so each test can
    # state exactly the whitelist it needs rather than sharing a fixture.
    function New-TestWhitelist {
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
            [Parameter(Mandatory)] [string] $Source,
            [string] $Id = 'test-id',
            [string] $Name,
            [string] $DisplayName,
            [string] $PackageFamilyName,
            [string] $Publisher,
            [string] $Version,
            [string] $UninstallString,
            [string] $Detail
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
            Detail            = $Detail
        }
    }

    # The fabricated whitelist most matching tests run against.
    $script:FabricatedJson = @'
{
  "schemaVersion": 1,
  "entries": [
    {
      "id": "fabricated-appx",
      "displayName": "Fabricated Appx Bloat",
      "vendor": "Fabricated OEM Inc.",
      "reason": "Test fixture entry: exact Appx package-name match.",
      "match": { "appxPackageName": ["Fabricated.AppxBloat"] }
    },
    {
      "id": "fabricated-win32",
      "displayName": "Fabricated Win32 Bloat",
      "vendor": "Fabricated OEM Inc.",
      "reason": "Test fixture entry: registry display-name match guarded by publisher.",
      "match": {
        "registryDisplayName": ["Fabricated Win32 Bloat*"],
        "registryPublisher": ["Fabricated OEM Inc."]
      }
    },
    {
      "id": "fabricated-prefix",
      "displayName": "Fabricated Prefix Family",
      "vendor": "Fabricated OEM Inc.",
      "reason": "Test fixture entry: constrained trailing-wildcard match.",
      "match": { "appxPackageName": ["fabricated.prefix.*"] }
    },
    {
      "id": "fabricated-family",
      "displayName": "Fabricated Family Match",
      "vendor": "Fabricated OEM Inc.",
      "reason": "Test fixture entry: package-family-name match.",
      "match": { "appxPackageFamilyName": ["Fabricated.ByFamily_abcdefghijklm"] }
    }
  ]
}
'@

    $script:FabricatedPath = New-TestWhitelist -Content $script:FabricatedJson -Name 'fabricated.json'
    $script:Fabricated = @(Get-KnownBloatwareList -Path $script:FabricatedPath)
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

Describe 'OemBloatware detector registration' {

    # Handoff 01 recorded "registered in one place but not the other" as the standard
    # failure mode for a detector, so all three registrations are asserted separately.
    $script:DetectorFunctions = @('Get-KnownBloatwareList', 'Find-KnownBloatware', 'Invoke-OemBloatwareScan')

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

Describe 'OemBloatware detector is read-only' {

    It 'contains no Remove-* cmdlet call anywhere in the detector source' {
        # The hard constraint for this chunk: detection only. Not behind a flag, not
        # behind -WhatIf, not commented out.
        $source = [System.IO.File]::ReadAllText($script:DetectorPath)
        $forbidden = 'Remove' + '-'
        $source.Contains($forbidden) | Should -BeFalse -Because 'chunk P2-C1 detects only; the dispatcher (P3-C1) owns removal'
    }

    It 'never touches Win32_Product / WMI' {
        $source = [System.IO.File]::ReadAllText($script:DetectorPath)
        $source | Should -Not -Match 'Get-WmiObject'
        $source | Should -Not -Match 'Get-CimInstance'
        # The name appears once, in the header comment explaining why it is avoided.
        @([regex]::Matches($source, 'Win32_Product')).Count | Should -BeLessOrEqual 1
    }
}

Describe 'Known-bloatware whitelist file' {

    BeforeAll { $script:Entries = @(Get-KnownBloatwareList) }

    It 'loads from JSON and returns at least one entry' {
        $script:Entries.Count | Should -BeGreaterThan 0
    }

    It 'gives every entry a non-empty reason, display name and vendor' {
        foreach ($entry in $script:Entries) {
            $entry.Id          | Should -Not -BeNullOrEmpty
            $entry.DisplayName | Should -Not -BeNullOrEmpty
            $entry.Vendor      | Should -Not -BeNullOrEmpty
            $entry.Reason      | Should -Not -BeNullOrEmpty
        }
    }

    It 'gives every entry at least one match rule' {
        foreach ($entry in $script:Entries) {
            $ruleCount = @($entry.AppxPackageName).Count + @($entry.AppxPackageFamilyName).Count + @($entry.RegistryDisplayName).Count
            $ruleCount | Should -BeGreaterThan 0 -Because "entry '$($entry.Id)' would otherwise match nothing"
        }
    }

    It 'never whitelists an OS component, the Store, security software, a driver or a runtime' {
        # A sample of the categories Data\README.md puts permanently out of scope.
        # Getting one of these wrong breaks a machine.
        $mustNeverMatch = @(
            'Microsoft.WindowsStore'
            'Microsoft.SecHealthUI'
            'Microsoft.DesktopAppInstaller'
            'MicrosoftWindows.Client.CBS'
            'MicrosoftWindows.Client.Core'
            'Microsoft.VCLibs.140.00'
            'Microsoft.NET.Native.Runtime.2.2'
            'NVIDIACorp.NVIDIAControlPanel'
            'RealtekSemiconductorCorp.RealtekAudioControl'
            'Malwarebytes.AntiMalware'
            '9426MICRO-STARINTERNATION.MSICenter'
            'E046963F.LenovoCompanion'
        )

        $apps = foreach ($name in $mustNeverMatch) {
            New-TestApp -Source 'AppxPackage' -Id "$($name)_hash" -Name $name -DisplayName $name -PackageFamilyName "$($name)_hash"
        }

        $findings = @(Find-KnownBloatware -InstalledApp $apps -KnownBloatwareEntry $script:Entries)
        $findings | Should -BeNullOrEmpty
    }

    # --- chunk P2-C1a: the security-software carve-out -------------------------

    It 'gives every security-trial entry requiresConsent and no wildcard in any field' {
        # The whole safety case for naming security software at all rests on these
        # two properties. The loader enforces them; this pins the shipped file, so a
        # future edit cannot pass the loader while quietly relaxing the list itself.
        $trials = @($script:Entries | Where-Object { $_.SensitiveClass -eq 'security-trial' })
        $trials.Count | Should -BeGreaterThan 0 -Because 'the carve-out exists to be used; an empty one means the entries were lost in an edit'

        foreach ($entry in $trials) {
            $entry.RequiresConsent | Should -BeTrue -Because "entry '$($entry.Id)' must never be presentable as safe to remove"

            $patterns = @($entry.AppxPackageName) + @($entry.AppxPackageFamilyName) +
                        @($entry.RegistryDisplayName) + @($entry.RegistryPublisher)
            foreach ($pattern in $patterns) {
                $pattern | Should -Not -Match '\*' -Because "entry '$($entry.Id)' is security software: exact identifiers only, in every field"
            }
        }
    }

    It 'surfaces a shipped security-trial match at "Review needed", never "Safe to remove"' {
        $trials = @($script:Entries | Where-Object { $_.SensitiveClass -eq 'security-trial' })

        $apps = foreach ($entry in $trials) {
            foreach ($name in @($entry.RegistryDisplayName)) {
                New-TestApp -Source 'RegistryUninstall' `
                    -Id "HKEY_LOCAL_MACHINE\SOFTWARE\Fake\Uninstall\$($entry.Id)" `
                    -DisplayName $name -Publisher $entry.Vendor -UninstallString '"C:\fake\uninstall.exe" /S'
            }
        }

        $findings = @(Find-KnownBloatware -InstalledApp @($apps) -KnownBloatwareEntry $script:Entries)
        $findings.Count | Should -Be $trials.Count

        foreach ($finding in $findings) {
            $finding.Confidence      | Should -Be 'Known'
            $finding.RequiresConsent | Should -BeTrue
            $finding.SafetyLabel     | Should -Be 'Review needed'
        }
    }

    It 'never matches a security product the user chose and paid for' {
        # The carve-out lets the list name OEM trial/nagware editions by exact
        # display name. These are the products on the other side of that line: real
        # protection a user installed on purpose, including the retail editions of
        # the very vendors the carve-out entries come from.
        $apps = @(
            New-TestApp -Source 'AppxPackage' -Id 'Malwarebytes.AntiMalware_x' -Name 'Malwarebytes.AntiMalware' -PackageFamilyName 'Malwarebytes.AntiMalware_x'
            New-TestApp -Source 'AppxPackage' -Id 'Microsoft.SecHealthUI_8wekyb3d8bbwe' -Name 'Microsoft.SecHealthUI' -PackageFamilyName 'Microsoft.SecHealthUI_8wekyb3d8bbwe'
            New-TestApp -Source 'RegistryUninstall' -Id 's1' -DisplayName 'Malwarebytes version 5.6.3.284' -Publisher 'Malwarebytes'
            New-TestApp -Source 'RegistryUninstall' -Id 's2' -DisplayName 'Windows Defender' -Publisher 'Microsoft Corporation'
            New-TestApp -Source 'RegistryUninstall' -Id 's3' -DisplayName 'Microsoft Defender for Endpoint' -Publisher 'Microsoft Corporation'
            New-TestApp -Source 'RegistryUninstall' -Id 's4' -DisplayName 'McAfee Total Protection' -Publisher 'McAfee, LLC'
            New-TestApp -Source 'RegistryUninstall' -Id 's5' -DisplayName 'McAfee LiveSafe' -Publisher 'McAfee, LLC'
            New-TestApp -Source 'RegistryUninstall' -Id 's6' -DisplayName 'Norton 360' -Publisher 'Gen Digital Inc.'
            New-TestApp -Source 'RegistryUninstall' -Id 's7' -DisplayName 'Norton AntiVirus Plus' -Publisher 'Gen Digital Inc.'
            New-TestApp -Source 'RegistryUninstall' -Id 's8' -DisplayName 'Bitdefender Total Security' -Publisher 'Bitdefender'
            New-TestApp -Source 'RegistryUninstall' -Id 's9' -DisplayName 'ESET Security' -Publisher 'ESET, spol. s r.o.'
        )

        @(Find-KnownBloatware -InstalledApp $apps -KnownBloatwareEntry $script:Entries) | Should -BeNullOrEmpty
    }

    It 'never whitelists a Visual C++ redistributable or a driver by registry display name' {
        $apps = @(
            New-TestApp -Source 'RegistryUninstall' -Id 'k1' -DisplayName 'Microsoft Visual C++ v14 Redistributable (x64) - 14.51.36247' -Publisher 'Microsoft Corporation'
            New-TestApp -Source 'RegistryUninstall' -Id 'k2' -DisplayName 'NVIDIA Graphics Driver 610.88' -Publisher 'NVIDIA Corporation'
            New-TestApp -Source 'RegistryUninstall' -Id 'k3' -DisplayName 'AMD Chipset Software' -Publisher 'Advanced Micro Devices, Inc.'
            New-TestApp -Source 'RegistryUninstall' -Id 'k4' -DisplayName 'Malwarebytes version 5.6.3.284' -Publisher 'Malwarebytes'
        )

        @(Find-KnownBloatware -InstalledApp $apps -KnownBloatwareEntry $script:Entries) | Should -BeNullOrEmpty
    }
}

Describe 'Known-bloatware whitelist loading fails loudly' {

    # Silently returning nothing is the dangerous failure mode on this project: a
    # scan that found nothing must never be confusable with a scan that broke.

    It 'throws when the whitelist file is missing' {
        $missing = Join-Path $script:Scratch 'does-not-exist.json'
        { Get-KnownBloatwareList -Path $missing } | Should -Throw -ExpectedMessage '*not found*'
    }

    It 'throws when the whitelist file is empty' {
        $path = New-TestWhitelist -Content '   '
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage '*empty*'
    }

    It 'throws when the whitelist file is not valid JSON' {
        $path = New-TestWhitelist -Content '{ "entries": [ '
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage '*not valid JSON*'
    }

    It 'throws when there is no entries array' {
        $path = New-TestWhitelist -Content '{ "schemaVersion": 1 }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage "*no 'entries' array*"
    }

    It 'throws when the entries array is empty' {
        $path = New-TestWhitelist -Content '{ "entries": [] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage '*contains no entries*'
    }

    It 'throws when an entry has no reason' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "x", "displayName": "X", "vendor": "V", "match": { "appxPackageName": ["Some.Package"] } } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage "*'reason'*"
    }

    It 'throws when an entry has no match block' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "x", "displayName": "X", "vendor": "V", "reason": "R" } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage "*no 'match' block*"
    }

    It 'throws on a duplicate entry id' {
        $entry = '{ "id": "dupe", "displayName": "X", "vendor": "V", "reason": "R", "match": { "appxPackageName": ["Some.Package"] } }'
        $path = New-TestWhitelist -Content "{ ""entries"": [ $entry, $entry ] }"
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage '*duplicate entry id*'
    }

    It 'throws on an unknown match field rather than silently disabling the entry' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "x", "displayName": "X", "vendor": "V", "reason": "R", "match": { "appxPackageNam": ["Some.Package"] } } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage '*unknown match field*'
    }

    It 'reports an empty match block in its own words, not in strict mode''s' {
        # $match.PSObject.Properties.Name throws "the property 'Name' cannot be
        # found" under Set-StrictMode -Version Latest when the collection is EMPTY,
        # which turned a bad list entry into a message about nothing. Cosmetic --
        # it threw either way -- but the loader has to be the one talking.
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "x", "displayName": "X", "vendor": "V", "reason": "R", "match": { } } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage "*empty 'match' block*"
    }

    It 'throws when registryPublisher is used without registryDisplayName' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "x", "displayName": "X", "vendor": "V", "reason": "R", "match": { "registryPublisher": ["Some Vendor"] } } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage '*without*registryDisplayName*'
    }

    It 'rejects the over-broad pattern <_>' -ForEach @('*', 'A*', 'Some*Package', '*Package') {
        $path = New-TestWhitelist -Content ('{ "entries": [ { "id": "x", "displayName": "X", "vendor": "V", "reason": "R", "match": { "appxPackageName": ["' + $_ + '"] } } ] }')
        { Get-KnownBloatwareList -Path $path } | Should -Throw
    }

    It 'accepts a constrained trailing wildcard' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "x", "displayName": "X", "vendor": "V", "reason": "R", "match": { "appxPackageName": ["SomeVendor.Thing*"] } } ] }'
        @(Get-KnownBloatwareList -Path $path).Count | Should -Be 1
    }

    # --- chunk P2-C1a ----------------------------------------------------------
    # Each rule gets its own test, and each asserts the message names the offending
    # entry: a loader that throws without saying which of eleven entries is at fault
    # turns a one-line fix into a hunt through the JSON.

    It 'throws when requiresConsent is the string "true" rather than a JSON boolean' {
        # "true" is truthy in PowerShell, so accepting it would leave the entry
        # looking enforced while the Finding contract -- which fails closed on a
        # non-boolean -- and the carve-out check disagreed about what it meant.
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "stringly-consent", "displayName": "X", "vendor": "V", "reason": "R", "requiresConsent": "true", "match": { "appxPackageName": ["Some.Package"] } } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage "*'stringly-consent'*JSON boolean*"
    }

    It 'accepts requiresConsent as a real JSON boolean' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "real-consent", "displayName": "X", "vendor": "V", "reason": "R", "requiresConsent": true, "match": { "appxPackageName": ["Some.Package"] } } ] }'
        $entry = @(Get-KnownBloatwareList -Path $path)[0]
        $entry.RequiresConsent | Should -BeOfType [bool]
        $entry.RequiresConsent | Should -BeTrue
    }

    It 'defaults requiresConsent to false when the entry does not mention it' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "no-consent-key", "displayName": "X", "vendor": "V", "reason": "R", "match": { "appxPackageName": ["Some.Package"] } } ] }'
        $entry = @(Get-KnownBloatwareList -Path $path)[0]
        $entry.RequiresConsent | Should -BeOfType [bool]
        $entry.RequiresConsent | Should -BeFalse
        $entry.SensitiveClass  | Should -BeNullOrEmpty
    }

    It 'throws on an unknown sensitiveClass rather than treating it as an ordinary entry' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "odd-class", "displayName": "X", "vendor": "V", "reason": "R", "sensitiveClass": "security-suite", "match": { "appxPackageName": ["Some.Package"] } } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage "*'odd-class'*unknown 'sensitiveClass'*"
    }

    It 'throws when a security-trial entry does not require consent' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "trial-without-consent", "displayName": "X", "vendor": "V", "reason": "The preinstalled trial edition.", "sensitiveClass": "security-trial", "match": { "registryDisplayName": ["Vendor Security Scan"] } } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage "*'trial-without-consent'*requiresConsent*"
    }

    It 'throws when a security-trial entry wildcards its <Field> pattern' -ForEach @(
        @{ Field = 'appxPackageName';       Rules = '"appxPackageName": ["VendorSecurity*"]' }
        @{ Field = 'appxPackageFamilyName'; Rules = '"appxPackageFamilyName": ["VendorSecurity*"]' }
        @{ Field = 'registryDisplayName';   Rules = '"registryDisplayName": ["Vendor Security*"]' }
        @{ Field = 'registryPublisher';     Rules = '"registryDisplayName": ["Vendor Security Scan"], "registryPublisher": ["Vendor Inc*"]' }
    ) {
        # Every field, no exceptions. A prefix match on a security product is how a
        # list that meant to catch the OEM trial catches the suite the user paid for.
        $json = '{ "entries": [ { "id": "wildcarded-trial", "displayName": "X", "vendor": "V", "reason": "The preinstalled trial edition.", "requiresConsent": true, "sensitiveClass": "security-trial", "match": { ' + $Rules + ' } } ] }'
        { Get-KnownBloatwareList -Path (New-TestWhitelist -Content $json) } |
            Should -Throw -ExpectedMessage "*'wildcarded-trial'*'$Field'*"
    }

    It 'throws when a security-trial entry has an empty reason' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "reasonless-trial", "displayName": "X", "vendor": "V", "reason": "", "requiresConsent": true, "sensitiveClass": "security-trial", "match": { "registryDisplayName": ["Vendor Security Scan"] } } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage "*'reasonless-trial'*'reason'*"
    }

    It 'throws when a security-trial reason never says it is the trial edition' {
        # The reason is what the user reads before approving a removal. For security
        # software it has to state which edition is being flagged, so the check is
        # structural rather than left to review discipline.
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "vague-trial", "displayName": "X", "vendor": "V", "reason": "It is unwanted software.", "requiresConsent": true, "sensitiveClass": "security-trial", "match": { "registryDisplayName": ["Vendor Security Scan"] } } ] }'
        { Get-KnownBloatwareList -Path $path } | Should -Throw -ExpectedMessage "*'vague-trial'*trial*"
    }

    It 'accepts a well-formed security-trial entry' {
        $path = New-TestWhitelist -Content '{ "entries": [ { "id": "good-trial", "displayName": "X", "vendor": "V", "reason": "The preinstalled trial edition, not the paid product.", "requiresConsent": true, "sensitiveClass": "security-trial", "match": { "registryDisplayName": ["Vendor Security Scan"] } } ] }'
        $entry = @(Get-KnownBloatwareList -Path $path)[0]
        $entry.SensitiveClass  | Should -Be 'security-trial'
        $entry.RequiresConsent | Should -BeTrue
    }
}

Describe 'Find-KnownBloatware matching' {

    It 'produces exactly one Appx Finding for a fabricated Appx match' {
        $app = New-TestApp -Source 'AppxPackage' -Id 'Fabricated.AppxBloat_abcdefghijklm' `
            -Name 'Fabricated.AppxBloat' -DisplayName 'Fabricated.AppxBloat' `
            -PackageFamilyName 'Fabricated.AppxBloat_abcdefghijklm' -Version '1.2.3.4'

        $findings = @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated)

        $findings.Count               | Should -Be 1
        $findings[0].Category         | Should -Be 'OemBloatware'
        $findings[0].Confidence       | Should -Be 'Known'
        $findings[0].RemovalMethod    | Should -Be 'Appx'
        $findings[0].DisplayName      | Should -Be 'Fabricated Appx Bloat'
        $findings[0].Id               | Should -Be 'Fabricated.AppxBloat_abcdefghijklm'
        $findings[0].SafetyLabel      | Should -Be 'Safe to remove'
        Test-Finding -InputObject $findings[0] | Should -BeTrue
    }

    It 'produces exactly one RegistryUninstallString Finding for a fabricated Win32 match' {
        $app = New-TestApp -Source 'RegistryUninstall' `
            -Id 'HKEY_LOCAL_MACHINE\SOFTWARE\Fake\Uninstall\FabBloat' `
            -DisplayName 'Fabricated Win32 Bloat 3.1' -Publisher 'Fabricated OEM Inc.' `
            -Version '3.1' -UninstallString '"C:\fake\uninstall.exe" /S'

        $findings = @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated)

        $findings.Count            | Should -Be 1
        $findings[0].RemovalMethod | Should -Be 'RegistryUninstallString'
        $findings[0].Id            | Should -Be 'HKEY_LOCAL_MACHINE\SOFTWARE\Fake\Uninstall\FabBloat'
    }

    It 'treats registryPublisher as an AND-guard, not a match' {
        $app = New-TestApp -Source 'RegistryUninstall' -Id 'k' `
            -DisplayName 'Fabricated Win32 Bloat 3.1' -Publisher 'Some Other Vendor'

        @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated) | Should -BeNullOrEmpty
    }

    It 'matches on package family name when the entry uses appxPackageFamilyName' {
        $app = New-TestApp -Source 'AppxPackage' -Id 'Fabricated.ByFamily_abcdefghijklm' `
            -Name 'Fabricated.ByFamily' -PackageFamilyName 'Fabricated.ByFamily_abcdefghijklm'

        $findings = @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated)
        $findings.Count          | Should -Be 1
        $findings[0].DisplayName | Should -Be 'Fabricated Family Match'
    }

    It 'matches a trailing wildcard as a prefix' {
        $app = New-TestApp -Source 'AppxPackage' -Id 'p' -Name 'fabricated.prefix.SomethingElse' -PackageFamilyName 'fabricated.prefix.SomethingElse_x'
        @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated).Count | Should -Be 1
    }

    It 'does not let a trailing wildcard match a substring' {
        $app = New-TestApp -Source 'AppxPackage' -Id 'p' -Name 'other.fabricated.prefix.Thing' -PackageFamilyName 'other.fabricated.prefix.Thing_x'
        @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated) | Should -BeNullOrEmpty
    }

    It 'treats "." as a literal, not a regex or wildcard character' {
        $app = New-TestApp -Source 'AppxPackage' -Id 'p' -Name 'FabricatedXAppxBloat' -PackageFamilyName 'FabricatedXAppxBloat_x'
        @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated) | Should -BeNullOrEmpty
    }

    It 'matches case-insensitively' {
        $app = New-TestApp -Source 'AppxPackage' -Id 'p' -Name 'fabricated.appxbloat' -PackageFamilyName 'fabricated.appxbloat_x'
        @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated).Count | Should -Be 1
    }

    It 'returns nothing for an inventory with no matches' {
        $app = New-TestApp -Source 'AppxPackage' -Id 'p' -Name 'Contoso.PerfectlyFineApp' -PackageFamilyName 'Contoso.PerfectlyFineApp_x'
        @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated) | Should -BeNullOrEmpty
    }

    It 'accepts an empty inventory without throwing' {
        { Find-KnownBloatware -InstalledApp @() -KnownBloatwareEntry $script:Fabricated } | Should -Not -Throw
    }

    It 'tolerates inventory records with missing properties' {
        $sparse = [pscustomobject]@{ Source = 'AppxPackage'; Name = 'Fabricated.AppxBloat' }
        $findings = @(Find-KnownBloatware -InstalledApp $sparse -KnownBloatwareEntry $script:Fabricated)
        $findings.Count | Should -Be 1
    }

    It 'ignores inventory records from an unrecognized source' {
        $app = New-TestApp -Source 'SomethingElse' -Id 'p' -Name 'Fabricated.AppxBloat' -PackageFamilyName 'Fabricated.AppxBloat_x'
        @(Find-KnownBloatware -InstalledApp $app -KnownBloatwareEntry $script:Fabricated) | Should -BeNullOrEmpty
    }
}

Describe 'Find-KnownBloatware deduplication' {

    It 'emits one Finding, not two, for an app present as both a per-user and a provisioned Appx package' {
        $apps = @(
            New-TestApp -Source 'AppxPackage' -Id 'Fabricated.AppxBloat_abcdefghijklm' `
                -Name 'Fabricated.AppxBloat' -PackageFamilyName 'Fabricated.AppxBloat_abcdefghijklm' -Version '1.2.3.4'
            New-TestApp -Source 'AppxProvisionedPackage' -Id 'Fabricated.AppxBloat_abcdefghijklm' `
                -Name 'Fabricated.AppxBloat' -PackageFamilyName 'Fabricated.AppxBloat_abcdefghijklm' `
                -Detail 'Fabricated.AppxBloat_1.2.3.4_neutral_~_abcdefghijklm'
        )

        $findings = @(Find-KnownBloatware -InstalledApp $apps -KnownBloatwareEntry $script:Fabricated)

        $findings.Count            | Should -Be 1
        $findings[0].RemovalMethod | Should -Be 'Appx'
    }

    It 'records both sources in the Evidence of the merged Finding' {
        $apps = @(
            New-TestApp -Source 'AppxPackage' -Id 'Fabricated.AppxBloat_abcdefghijklm' `
                -Name 'Fabricated.AppxBloat' -PackageFamilyName 'Fabricated.AppxBloat_abcdefghijklm'
            New-TestApp -Source 'AppxProvisionedPackage' -Id 'Fabricated.AppxBloat_abcdefghijklm' `
                -Name 'Fabricated.AppxBloat' -PackageFamilyName 'Fabricated.AppxBloat_abcdefghijklm' `
                -Detail 'Fabricated.AppxBloat_1.2.3.4_neutral_~_abcdefghijklm'
        )

        $evidence = (@(Find-KnownBloatware -InstalledApp $apps -KnownBloatwareEntry $script:Fabricated)[0].Evidence) -join "`n"

        $evidence | Should -Match 'per-user'
        $evidence | Should -Match 'Provisioned for all users'
        $evidence | Should -Match 'needs both'
    }

    It 'emits one Finding when the same package appears twice in the same source' {
        $app = New-TestApp -Source 'AppxPackage' -Id 'Fabricated.AppxBloat_abcdefghijklm' `
            -Name 'Fabricated.AppxBloat' -PackageFamilyName 'Fabricated.AppxBloat_abcdefghijklm'

        @(Find-KnownBloatware -InstalledApp @($app, $app) -KnownBloatwareEntry $script:Fabricated).Count | Should -Be 1
    }

    It 'keeps two Findings when one product is installed twice by two different mechanisms' {
        # Deliberate: RemovalMethod holds one value, so collapsing these would throw
        # away the removal path the dispatcher needs for one of the two installs.
        $json = @'
{
  "entries": [
    {
      "id": "two-install-product",
      "displayName": "Two-Install Product",
      "vendor": "Fabricated OEM Inc.",
      "reason": "Test fixture entry: ships as both an Appx package and a Win32 install.",
      "match": {
        "appxPackageName": ["Fabricated.TwoInstall"],
        "registryDisplayName": ["Two-Install Product"]
      }
    }
  ]
}
'@
        $entries = @(Get-KnownBloatwareList -Path (New-TestWhitelist -Content $json))

        $apps = @(
            New-TestApp -Source 'AppxPackage' -Id 'Fabricated.TwoInstall_x' -Name 'Fabricated.TwoInstall' -PackageFamilyName 'Fabricated.TwoInstall_x'
            New-TestApp -Source 'RegistryUninstall' -Id 'HKEY_LOCAL_MACHINE\SOFTWARE\Fake\TwoInstall' -DisplayName 'Two-Install Product' -Publisher 'Fabricated OEM Inc.'
        )

        $findings = @(Find-KnownBloatware -InstalledApp $apps -KnownBloatwareEntry $entries)

        $findings.Count | Should -Be 2
        @($findings.RemovalMethod | Sort-Object) | Should -Be @('Appx', 'RegistryUninstallString')
    }
}

Describe 'Find-KnownBloatware output contract' {

    BeforeAll {
        $script:ContractApps = @(
            New-TestApp -Source 'AppxPackage' -Id 'Fabricated.AppxBloat_x' -Name 'Fabricated.AppxBloat' -PackageFamilyName 'Fabricated.AppxBloat_x' -Version '1.0'
            New-TestApp -Source 'RegistryUninstall' -Id 'HKEY_LOCAL_MACHINE\SOFTWARE\Fake\FabBloat' -DisplayName 'Fabricated Win32 Bloat 3.1' -Publisher 'Fabricated OEM Inc.'
            New-TestApp -Source 'AppxPackage' -Id 'p' -Name 'fabricated.prefix.Thing' -PackageFamilyName 'fabricated.prefix.Thing_x'
        )
        $script:ContractFindings = @(Find-KnownBloatware -InstalledApp $script:ContractApps -KnownBloatwareEntry $script:Fabricated)
    }

    It 'produced findings to assert on' {
        $script:ContractFindings.Count | Should -Be 3
    }

    It 'returns only objects that pass Test-Finding' {
        foreach ($finding in $script:ContractFindings) {
            Test-Finding -InputObject $finding | Should -BeTrue
        }
    }

    It 'tags every finding as Win11Optimizer.Finding' {
        foreach ($finding in $script:ContractFindings) {
            $finding.PSObject.TypeNames | Should -Contain 'Win11Optimizer.Finding'
        }
    }

    It 'emits Confidence = Known exclusively -- this chunk has no heuristics' {
        foreach ($finding in $script:ContractFindings) {
            $finding.Confidence | Should -Be 'Known'
        }
    }

    It 'gives every finding non-empty Evidence that includes the whitelist reason' {
        foreach ($finding in $script:ContractFindings) {
            @($finding.Evidence).Count | Should -BeGreaterThan 0
            (($finding.Evidence) -join "`n") | Should -Match 'Test fixture entry'
        }
    }

    It 'only ever assigns Appx or RegistryUninstallString as the removal method' {
        foreach ($finding in $script:ContractFindings) {
            $finding.RemovalMethod | Should -BeIn @('Appx', 'RegistryUninstallString')
        }
    }

    It 'assigns a removal method that is in the Finding contract' {
        $allowed = (Get-FindingContract).RemovalMethods
        foreach ($finding in $script:ContractFindings) {
            $allowed | Should -Contain $finding.RemovalMethod
        }
    }
}

Describe 'Find-KnownBloatware provenance and consent (chunk P2-C1a)' {

    BeforeAll {
        # One entry per provenance case, so each assertion has an unambiguous target.
        $script:ProvenanceJson = @'
{
  "schemaVersion": 2,
  "entries": [
    {
      "id": "provenance-measured",
      "displayName": "Measured Fixture App",
      "vendor": "Fabricated OEM Inc.",
      "reason": "Test fixture entry: the identifier was observed on a real machine.",
      "evidenceSource": "measured",
      "match": { "appxPackageName": ["Fabricated.Measured"] }
    },
    {
      "id": "provenance-public",
      "displayName": "Public-List Fixture App",
      "vendor": "Fabricated OEM Inc.",
      "reason": "Test fixture entry: the identifier came from a published list.",
      "evidenceSource": "public-list",
      "match": { "appxPackageName": ["Fabricated.PublicList"] }
    },
    {
      "id": "provenance-trial",
      "displayName": "Fixture Security Trial",
      "vendor": "Fabricated Security Inc.",
      "reason": "Test fixture entry: the preinstalled trial edition, not the paid product.",
      "evidenceSource": "public-list",
      "requiresConsent": true,
      "sensitiveClass": "security-trial",
      "match": { "registryDisplayName": ["Fixture Security Scan"] }
    }
  ]
}
'@

        $script:ProvenanceEntries = @(Get-KnownBloatwareList -Path (New-TestWhitelist -Content $script:ProvenanceJson))

        $script:ProvenanceApps = @(
            New-TestApp -Source 'AppxPackage' -Id 'Fabricated.Measured_x' -Name 'Fabricated.Measured' -PackageFamilyName 'Fabricated.Measured_x'
            New-TestApp -Source 'AppxPackage' -Id 'Fabricated.PublicList_x' -Name 'Fabricated.PublicList' -PackageFamilyName 'Fabricated.PublicList_x'
            New-TestApp -Source 'RegistryUninstall' -Id 'HKEY_LOCAL_MACHINE\SOFTWARE\Fake\Uninstall\FixtureSec' `
                -DisplayName 'Fixture Security Scan' -Publisher 'Fabricated Security Inc.'
        )

        $script:ProvenanceFindings = @(Find-KnownBloatware -InstalledApp $script:ProvenanceApps -KnownBloatwareEntry $script:ProvenanceEntries)
    }

    It 'produced one finding per fixture entry to assert on' {
        $script:ProvenanceFindings.Count | Should -Be 3
    }

    It 'carries WhitelistEntryId on every finding' {
        foreach ($finding in $script:ProvenanceFindings) {
            $finding.PSObject.Properties.Name | Should -Contain 'WhitelistEntryId'
            $finding.WhitelistEntryId | Should -Not -BeNullOrEmpty
        }

        @($script:ProvenanceFindings.WhitelistEntryId | Sort-Object) |
            Should -Be @('provenance-measured', 'provenance-public', 'provenance-trial')
    }

    It 'round-trips WhitelistEntryId as a join key back into the whitelist' {
        # The point of the field: a caller reads provenance structurally instead of
        # string-matching the evidence prose. Looking the id up must land on exactly
        # one entry, and it must be the entry whose reason is in the evidence.
        foreach ($finding in $script:ProvenanceFindings) {
            $entry = @($script:ProvenanceEntries | Where-Object { $_.Id -eq $finding.WhitelistEntryId })
            $entry.Count | Should -Be 1
            $finding.Evidence | Should -Contain $entry[0].Reason
        }
    }

    It 'says in plain words that a public-list identifier is unverified' {
        $finding = @($script:ProvenanceFindings | Where-Object { $_.WhitelistEntryId -eq 'provenance-public' })[0]
        ($finding.Evidence -join "`n") | Should -Match 'never been observed on real hardware'
        ($finding.Evidence -join "`n") | Should -Match 'published bloatware list'
    }

    It 'stays silent for a measured identifier -- silence means measured' {
        $finding = @($script:ProvenanceFindings | Where-Object { $_.WhitelistEntryId -eq 'provenance-measured' })[0]
        ($finding.Evidence -join "`n") | Should -Not -Match 'never been observed on real hardware'
    }

    It 'gives a matched security-trial entry Known + RequiresConsent + "Review needed"' {
        $finding = @($script:ProvenanceFindings | Where-Object { $_.WhitelistEntryId -eq 'provenance-trial' })[0]

        $finding.Confidence      | Should -Be 'Known'
        $finding.RequiresConsent | Should -BeTrue
        $finding.SafetyLabel     | Should -Be 'Review needed'
        $finding.RemovalMethod   | Should -Be 'RegistryUninstallString'
        Test-Finding -InputObject $finding | Should -BeTrue
    }

    It 'leaves an ordinary entry at RequiresConsent = false and "Safe to remove"' {
        foreach ($id in 'provenance-measured', 'provenance-public') {
            $finding = @($script:ProvenanceFindings | Where-Object { $_.WhitelistEntryId -eq $id })[0]
            $finding.RequiresConsent | Should -BeFalse
            $finding.SafetyLabel     | Should -Be 'Safe to remove'
        }
    }
}

Describe 'Invoke-OemBloatwareScan result shape' {

    BeforeAll { $script:Scan = Invoke-OemBloatwareScan -WarningAction SilentlyContinue }

    It 'returns a single scan-result object, not a bare array of findings' {
        # The completeness requirement is structural: findings are reachable only
        # through the result, so a partial list cannot be mistaken for a full one.
        @($script:Scan).Count | Should -Be 1
        $script:Scan.PSObject.TypeNames | Should -Contain 'Win11Optimizer.OemScanResult'
        $script:Scan.PSObject.Properties.Name | Should -Contain 'Findings'
    }

    It 'reports one source record per inventory source' {
        @($script:Scan.Sources).Name | Should -Be @('AppxPackage', 'AppxProvisionedPackage', 'RegistryUninstall')
    }

    It 'gives every non-succeeded source a stated reason' {
        foreach ($source in $script:Scan.Sources) {
            if ($source.Status -ne 'Succeeded') {
                $source.Reason | Should -Not -BeNullOrEmpty
            }
        }
    }

    It 'derives IsComplete from the source statuses' {
        $expected = (@($script:Scan.Sources | Where-Object { $_.Status -ne 'Succeeded' }).Count -eq 0)
        $script:Scan.IsComplete | Should -Be $expected
    }

    It 'cannot have IsComplete overwritten by a caller' {
        { $script:Scan.IsComplete = $true } | Should -Throw
    }

    It 'states an IncompleteReason exactly when the scan is incomplete' {
        if ($script:Scan.IsComplete) {
            $script:Scan.IncompleteReason | Should -BeNullOrEmpty
        }
        else {
            $script:Scan.IncompleteReason | Should -Not -BeNullOrEmpty
            $script:Scan.SummaryText | Should -Match 'PARTIAL'
        }
    }

    It 'returns findings that all pass the Finding contract' {
        foreach ($finding in @($script:Scan.Findings)) {
            Test-Finding -InputObject $finding | Should -BeTrue
            $finding.Category   | Should -Be 'OemBloatware'
            $finding.Confidence | Should -Be 'Known'
            @($finding.Evidence).Count | Should -BeGreaterThan 0
        }
    }

    It 'gives every finding a WhitelistEntryId that resolves to exactly one entry' {
        $entries = @(Get-KnownBloatwareList)
        foreach ($finding in @($script:Scan.Findings)) {
            $finding.WhitelistEntryId | Should -Not -BeNullOrEmpty
            @($entries | Where-Object { $_.Id -eq $finding.WhitelistEntryId }).Count | Should -Be 1
        }
    }

    It 'records a duration for the scan and for each source' {
        $script:Scan.DurationSeconds | Should -BeGreaterOrEqual 0
        foreach ($source in $script:Scan.Sources) {
            $source.DurationSeconds | Should -BeGreaterOrEqual 0
        }
    }

    It 'logs the scan start, each source outcome and the finding count' {
        $records = @(Get-OptimizerLog)
        @($records | Where-Object { $_.Event -eq 'OemScanStarted' }).Count   | Should -BeGreaterThan 0
        @($records | Where-Object { $_.Event -eq 'OemScanSource' }).Count    | Should -BeGreaterOrEqual 3
        @($records | Where-Object { $_.Event -eq 'OemScanCompleted' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Invoke-OemBloatwareScan completeness' {

    It 'reports itself incomplete and names elevation when not running as administrator' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Test-IsElevated -MockWith { $false }

        $scan = Invoke-OemBloatwareScan -WarningAction SilentlyContinue

        $scan.IsElevated | Should -BeFalse
        $scan.IsComplete | Should -BeFalse

        $provisioned = @($scan.Sources | Where-Object { $_.Name -eq 'AppxProvisionedPackage' })[0]
        $provisioned.Status | Should -Be 'Skipped'
        $provisioned.Reason | Should -Match 'administrator'
        $scan.SummaryText   | Should -Match 'PARTIAL'
    }

    It 'reports the not-elevated source as Skipped, never as Refused' {
        # The safety property behind the Refused status added in chunk P2-C2:
        # 'Refused' means "this project will never use this signal, on any machine,
        # at any privilege level". Elevation is environmental -- it could have gone
        # the other way on the very next run -- so it must never borrow the status
        # that stops a scan being called incomplete. If this ever flips, a
        # non-elevated scan starts claiming to be complete while seeing less than
        # the truth.
        Mock -ModuleName Win11Optimizer.Engine -CommandName Test-IsElevated -MockWith { $false }

        $scan = Invoke-OemBloatwareScan -WarningAction SilentlyContinue

        $provisioned = @($scan.Sources | Where-Object { $_.Name -eq 'AppxProvisionedPackage' })[0]
        $provisioned.Status | Should -Be 'Skipped'
        $provisioned.Status | Should -Not -Be 'Refused'
        @($scan.RefusedSourceName).Count | Should -Be 0
        $scan.IsComplete    | Should -BeFalse
    }

    It 'warns on the warning stream when the scan is incomplete' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Test-IsElevated -MockWith { $false }

        $warnings = @()
        $null = Invoke-OemBloatwareScan -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join ' ') | Should -Match 'INCOMPLETE'
    }

    It 'still returns the other sources when the provisioned source is skipped' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Test-IsElevated -MockWith { $false }

        $scan = Invoke-OemBloatwareScan -WarningAction SilentlyContinue
        @($scan.Sources | Where-Object { $_.Status -eq 'Succeeded' }).Count | Should -BeGreaterThan 0
        $scan.InventoryCount | Should -BeGreaterThan 0
    }

    It 'treats a busy DISM servicing session as "this source did not run", not a fatal error' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Test-IsElevated -MockWith { $true }
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-OemProvisionedAppxItem -MockWith { throw 'The requested operation could not be completed due to a servicing operation in progress.' }

        # A throw here fails the test outright, which is the assertion: a busy
        # servicing session must not take the whole scan down.
        $scan = Invoke-OemBloatwareScan -WarningAction SilentlyContinue

        $provisioned = @($scan.Sources | Where-Object { $_.Name -eq 'AppxProvisionedPackage' })[0]
        $provisioned.Status | Should -Be 'Failed'
        $provisioned.Reason | Should -Match 'servicing'
        $scan.IsComplete    | Should -BeFalse
    }

    It 'reports a failed Appx source instead of silently returning nothing' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-OemAppxPackageItem -MockWith { throw 'Appx subsystem unavailable.' }

        $scan = Invoke-OemBloatwareScan -WarningAction SilentlyContinue

        $appx = @($scan.Sources | Where-Object { $_.Name -eq 'AppxPackage' })[0]
        $appx.Status     | Should -Be 'Failed'
        $appx.Reason     | Should -Match 'Appx subsystem unavailable'
        $scan.IsComplete | Should -BeFalse
    }

    It 'reports IsComplete = $true when every source succeeds' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Test-IsElevated -MockWith { $true }
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-OemProvisionedAppxItem -MockWith { @() }

        $scan = Invoke-OemBloatwareScan
        $scan.IsComplete       | Should -BeTrue
        $scan.IncompleteReason | Should -BeNullOrEmpty
        $scan.SummaryText      | Should -Match 'Complete scan'
    }
}

Describe 'Invoke-OemBloatwareScan whitelist failure' {

    It 'throws rather than returning an empty, apparently-clean result when the whitelist is missing' {
        $missing = Join-Path $script:Scratch 'nope.json'
        { Invoke-OemBloatwareScan -WhitelistPath $missing } | Should -Throw -ExpectedMessage '*not found*'
    }

    It 'throws rather than returning an empty result when the whitelist is malformed' {
        $path = New-TestWhitelist -Content '{ "entries": [ {'
        { Invoke-OemBloatwareScan -WhitelistPath $path } | Should -Throw
    }

    It 'finds nothing -- without throwing -- when the whitelist matches nothing on the machine' {
        $json = '{ "entries": [ { "id": "matches-nothing", "displayName": "Nothing", "vendor": "V", "reason": "Test fixture: matches nothing.", "match": { "appxPackageName": ["Nonexistent.Vendor.Package.For.Tests"] } } ] }'
        $scan = Invoke-OemBloatwareScan -WhitelistPath (New-TestWhitelist -Content $json) -WarningAction SilentlyContinue

        @($scan.Findings).Count | Should -Be 0
        $scan.WhitelistCount    | Should -Be 1
        $scan.InventoryCount    | Should -BeGreaterThan 0
    }
}
