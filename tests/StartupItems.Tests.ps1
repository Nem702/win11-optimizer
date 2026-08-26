#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the StartupItems detector (chunk P2-C2,
    src\Win11Optimizer.Engine\Detectors\StartupItems.ps1).

    The two failure modes this suite is really guarding:

      * "autostarting is not evidence of being unwanted" -- the matcher tests
        below are mostly about what must NOT produce a Finding, because that is
        where this category goes wrong;
      * "a startup source you did not read is not an empty startup source" -- a
        mechanism that could not be read has to say so and make the scan
        incomplete, never return quietly.

    Run:  .\tests\Invoke-Tests.ps1
#>

BeforeAll {
    $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot   = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath   = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:SourcePath   = Join-Path $script:EngineRoot 'Detectors\StartupItems.ps1'
    $script:ListPath     = Join-Path $script:EngineRoot 'Data\known-startup-items.json'

    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-startup-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-startup-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    function New-TestStartupList {
        param([Parameter(Mandatory)] [string] $Content)
        $path = Join-Path $script:Scratch ("startup-" + [guid]::NewGuid().ToString('N') + '.json')
        [System.IO.File]::WriteAllText($path, $Content)
        $path
    }

    # Fabricated inventory records. Deliberately plain PSCustomObjects rather than
    # the module's own New-StartupItem: the matcher reads everything through
    # Get-OptimizerProperty, and a test that built its input with the code under
    # test would not notice a field being renamed.
    function New-TestStartupItem {
        param(
            [string] $Mechanism = 'RunKey',
            [string] $Id = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::Thing',
            [string] $Name = 'Thing',
            [string] $DisplayName = 'Thing',
            [string] $Command = 'C:\Program Files\Thing\thing.exe',
            [AllowNull()] [string] $TargetPath = 'C:\Program Files\Thing\thing.exe',
            [AllowNull()] $TargetExists = $true,
            [AllowNull()] [string] $Publisher = 'Thing Software Ltd.',
            [string] $Scope = 'User',
            [AllowNull()] [string] $View = 'Native',
            [string] $Location = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            [string] $EnabledState = 'Enabled',
            [string] $Trigger = 'Every logon',
            [bool] $IsProtectedNamespace = $false
        )

        [pscustomobject]@{
            Mechanism            = $Mechanism
            Id                   = $Id
            Name                 = $Name
            DisplayName          = $DisplayName
            Command              = $Command
            TargetPath           = $TargetPath
            TargetExists         = $TargetExists
            Publisher            = $Publisher
            Scope                = $Scope
            View                 = $View
            Location             = $Location
            EnabledState         = $EnabledState
            EnabledStateDetail   = 'Fabricated for tests.'
            Trigger              = $Trigger
            IsProtectedNamespace = $IsProtectedNamespace
            Detail               = $null
        }
    }

    # A fabricated SERVICE record, named the way the exclusion list sees one: the
    # display name is the only thing an orphan can be matched on.
    function New-TestServiceItem {
        param(
            [Parameter(Mandatory)] [string] $Display,
            [AllowNull()] $TargetExists,
            [AllowNull()] [string] $Publisher = $null
        )

        New-TestStartupItem -Mechanism 'Service' -Id $Display -Name $Display -DisplayName $Display `
            -Publisher $Publisher -Scope 'Machine' -View $null `
            -TargetExists $TargetExists -TargetPath 'C:\Program Files\Vendor\bin\svc.exe'
    }
}

AfterAll {
    Remove-Module Win11Optimizer.Engine -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\WIN11OPTIMIZER_LOGROOT -ErrorAction SilentlyContinue
    foreach ($path in $script:TestLogRoot, $script:Scratch) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'StartupItems registration' {

    It 'lists <_> in the manifest FunctionsToExport' -ForEach @(
        'Get-KnownStartupItemList', 'Get-StartupItemInventory', 'Find-UnwantedStartupItem', 'Invoke-StartupItemScan'
    ) {
        $manifest = Import-PowerShellDataFile -Path $script:ManifestPath
        $manifest.FunctionsToExport | Should -Contain $_
    }

    It 'lists <_> in the .psm1 Export-ModuleMember block' -ForEach @(
        'Get-KnownStartupItemList', 'Get-StartupItemInventory', 'Find-UnwantedStartupItem', 'Invoke-StartupItemScan'
    ) {
        # A function missing from either list is invisible to callers with no error
        # anywhere, which is one of this project's standing traps.
        $source = [System.IO.File]::ReadAllText($script:ModulePath)
        $source | Should -BeLike "*'$_'*"
    }

    It 'actually exports <_> from a freshly imported module' -ForEach @(
        'Get-KnownStartupItemList', 'Get-StartupItemInventory', 'Find-UnwantedStartupItem', 'Invoke-StartupItemScan'
    ) {
        (Get-Module Win11Optimizer.Engine).ExportedFunctions.Keys | Should -Contain $_
    }
}

Describe 'StartupItems detects only' {

    BeforeAll { $script:Source = [System.IO.File]::ReadAllText($script:SourcePath) }

    It 'contains no Remove-* cmdlet call' {
        $forbidden = 'Remove' + '-'
        $script:Source.Contains($forbidden) | Should -BeFalse -Because 'disabling and removal belong to the dispatcher (P3-C1), not to a detector'
    }

    It 'contains no <_> call' -ForEach @('Set-Service', 'Disable-ScheduledTask', 'Stop-Service', 'Set-ItemProperty', 'New-ItemProperty', 'Set-ScheduledTask', 'Unregister-ScheduledTask') {
        $script:Source | Should -Not -Match ([regex]::Escape($_))
    }

    It 'never touches Win32_Product or WMI' {
        $script:Source | Should -Not -Match 'Get-WmiObject'
        # The name appears once, in the header comment explaining why it is avoided.
        @([regex]::Matches($script:Source, 'Win32_Product')).Count | Should -BeLessOrEqual 1
    }

    It 'does not read startup entries through Win32_StartupCommand' {
        # Measured during P2-C2: on this machine it misses the WOW6432Node view and
        # RunOnce entirely, and cannot see tasks or services at all. It looks like a
        # one-call answer for this whole category and is not one.
        $script:Source | Should -Not -Match 'Get-CimInstance'
        # The class name appears only in the header comment saying why it is unused.
        @([regex]::Matches($script:Source, 'Win32_StartupCommand')).Count | Should -BeLessOrEqual 1
    }

    It 'enumerates the Startup folders with the .NET call, not Get-ChildItem' {
        # REVIEW.md: Get-ChildItem returns zero items and raises no error on a
        # folder the current user cannot list, even with -ErrorAction Stop. A
        # silently empty Startup folder is indistinguishable from a clean one.
        $script:Source | Should -Match '\[System\.IO\.Directory\]::GetFiles'
        $script:Source | Should -Not -Match 'Get-ChildItem[^\r\n]*Startup'
    }
}

Describe 'Get-KnownStartupItemList' {

    BeforeAll { $script:Entries = @(Get-KnownStartupItemList) }

    It 'loads the shipped list' {
        $script:Entries.Count | Should -BeGreaterThan 0
    }

    It 'ships the list as data, not code' {
        Test-Path -LiteralPath $script:ListPath -PathType Leaf | Should -BeTrue
        { ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($script:ListPath)) } | Should -Not -Throw
    }

    It 'gives every entry the full normalised shape' {
        $expected = @(
            'Id', 'DisplayName', 'Vendor', 'Reason', 'Provenance', 'RequiresConsent', 'Note',
            'RunValueName', 'StartupFolderFileName', 'ScheduledTaskName', 'ServiceName',
            'ServiceDisplayName', 'TargetFileName'
        )
        foreach ($entry in $script:Entries) {
            foreach ($field in $expected) { $entry.PSObject.Properties.Name | Should -Contain $field }
        }
    }

    It 'gives every entry a stated reason -- that reason is what the user reads' {
        foreach ($entry in $script:Entries) {
            $entry.Reason | Should -Not -BeNullOrEmpty
            $entry.Reason.Length | Should -BeGreaterThan 40
        }
    }

    It 'gives every entry a provenance of measured or published' {
        foreach ($entry in $script:Entries) {
            @('measured', 'published') | Should -Contain $entry.Provenance
        }
    }

    It 'gives every entry at least one match rule' {
        foreach ($entry in $script:Entries) {
            $rules = @($entry.RunValueName) + @($entry.StartupFolderFileName) + @($entry.ScheduledTaskName) +
                     @($entry.ServiceName) + @($entry.ServiceDisplayName) + @($entry.TargetFileName)
            @($rules | Where-Object { $_ }).Count | Should -BeGreaterThan 0
        }
    }

    It 'never names an updater, which is what keeps a machine patched' {
        # Documented in Data/README.md. An updater that stops running is a machine
        # that stops getting security fixes, so it is off this list by rule.
        $forbidden = @('Adobe ARM', 'AdobeAAMUpdater', 'edgeupdate', 'GoogleUpdate', 'BraveUpdate', 'Acrobat Update Service')
        foreach ($entry in $script:Entries) {
            foreach ($pattern in @($entry.RunValueName) + @($entry.ServiceName) + @($entry.ServiceDisplayName)) {
                foreach ($name in $forbidden) {
                    $pattern | Should -Not -BeExactly $name
                }
            }
        }
    }

    It 'throws rather than yielding nothing when the list is missing' {
        # A list that silently fails to load leaves only the orphan rule running,
        # which looks exactly like a machine with nothing to flag.
        { Get-KnownStartupItemList -Path (Join-Path $script:Scratch 'no-such-list.json') } | Should -Throw -ExpectedMessage '*not found*'
    }

    It 'throws on malformed JSON' {
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content '{ "entries": [ {') } | Should -Throw
    }

    It 'throws on an empty file' {
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content '   ') } | Should -Throw -ExpectedMessage '*empty*'
    }

    It 'throws when there is no entries array' {
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content '{ "schemaVersion": 1 }') } | Should -Throw -ExpectedMessage "*no 'entries' array*"
    }

    It 'throws when entries is empty' {
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content '{ "entries": [] }') } | Should -Throw -ExpectedMessage '*no entries*'
    }

    It 'throws when an entry is missing <_>' -ForEach @('id', 'displayName', 'vendor', 'reason', 'provenance') {
        $fields = [ordered]@{
            id          = 'x-entry'
            displayName = 'X'
            vendor      = 'V'
            reason      = 'Because.'
            provenance  = 'published'
        }
        $fields.Remove($_)
        $body = (@($fields.Keys | ForEach-Object { """$_"": ""$($fields[$_])""" }) -join ', ')
        $json = "{ ""entries"": [ { $body, ""match"": { ""runValueName"": [""SomeValue""] } } ] }"
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content $json) } | Should -Throw
    }

    It 'throws on an unknown provenance value' {
        $json = '{ "entries": [ { "id": "a", "displayName": "A", "vendor": "V", "reason": "Because.", "provenance": "guessed", "match": { "runValueName": ["SomeValue"] } } ] }'
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content $json) } | Should -Throw -ExpectedMessage "*provenance*"
    }

    It 'throws on a duplicate entry id' {
        $one = '{ "id": "dupe", "displayName": "A", "vendor": "V", "reason": "Because.", "provenance": "published", "match": { "runValueName": ["SomeValue"] } }'
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content "{ ""entries"": [ $one, $one ] }") } | Should -Throw -ExpectedMessage '*duplicate*'
    }

    It 'throws on an unknown match field' {
        $json = '{ "entries": [ { "id": "a", "displayName": "A", "vendor": "V", "reason": "Because.", "provenance": "published", "match": { "runValueNames": ["SomeValue"] } } ] }'
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content $json) } | Should -Throw -ExpectedMessage '*unknown match field*'
    }

    It 'throws on an empty match block' {
        $json = '{ "entries": [ { "id": "a", "displayName": "A", "vendor": "V", "reason": "Because.", "provenance": "published", "match": { } } ] }'
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content $json) } | Should -Throw -ExpectedMessage '*empty*'
    }

    It 'throws on the over-broad pattern <_>' -ForEach @('*', 'A*', 'Some*Value', 'Value**') {
        $pattern = $_
        $json = "{ ""entries"": [ { ""id"": ""a"", ""displayName"": ""A"", ""vendor"": ""V"", ""reason"": ""Because."", ""provenance"": ""published"", ""match"": { ""runValueName"": [""$pattern""] } } ] }"
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content $json) } | Should -Throw
    }

    It 'throws when a scheduled-task rule tries to name a path rather than a task' {
        # Which task namespaces are off limits is decided in code. A list entry
        # must not be able to address a task by path at all.
        $json = '{ "entries": [ { "id": "a", "displayName": "A", "vendor": "V", "reason": "Because.", "provenance": "published", "match": { "scheduledTaskName": ["\\Microsoft\\Windows\\Defrag"] } } ] }'
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content $json) } | Should -Throw -ExpectedMessage '*path separator*'
    }

    It 'throws on a wildcarded target file name' {
        # 'Update*' would match the updater of every product on the machine.
        $json = '{ "entries": [ { "id": "a", "displayName": "A", "vendor": "V", "reason": "Because.", "provenance": "published", "match": { "targetFileName": ["Update*"] } } ] }'
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content $json) } | Should -Throw -ExpectedMessage '*exact strings only*'
    }

    It 'throws when requiresConsent is the string "true" rather than a JSON boolean' {
        $json = '{ "entries": [ { "id": "a", "displayName": "A", "vendor": "V", "reason": "Because.", "provenance": "published", "requiresConsent": "true", "match": { "runValueName": ["SomeValue"] } } ] }'
        { Get-KnownStartupItemList -Path (New-TestStartupList -Content $json) } | Should -Throw -ExpectedMessage '*JSON boolean*'
    }
}

Describe 'Get-StartupTargetPath' {

    It 'reads a quoted path with arguments' {
        InModuleScope Win11Optimizer.Engine {
            Get-StartupTargetPath -Command '"C:\Program Files\Thing\thing.exe" --flag' | Should -Be 'C:\Program Files\Thing\thing.exe'
        }
    }

    It 'reads an unquoted path with spaces, by finding the executable extension' {
        InModuleScope Win11Optimizer.Engine {
            # 'C:\Program Files\NZXT CAM\NZXT CAM.exe --startup' is a real Run value
            # on the development machine, and splitting on the first space gets it
            # wrong.
            Get-StartupTargetPath -Command 'C:\Program Files\NZXT CAM\NZXT CAM.exe --startup' | Should -Be 'C:\Program Files\NZXT CAM\NZXT CAM.exe'
        }
    }

    It 'strips the NT object-manager prefix a service ImagePath can carry' {
        InModuleScope Win11Optimizer.Engine {
            Get-StartupTargetPath -Command '\??\C:\Windows\System32\thing.exe' | Should -Be 'C:\Windows\System32\thing.exe'
        }
    }

    It 'expands environment variables' {
        InModuleScope Win11Optimizer.Engine {
            $expected = Join-Path ([Environment]::GetFolderPath('Windows')) 'system32\SecurityHealthSystray.exe'
            Get-StartupTargetPath -Command '%windir%\system32\SecurityHealthSystray.exe' | Should -Be $expected
        }
    }

    It 'resolves a bare relative service image against System32' {
        InModuleScope Win11Optimizer.Engine {
            $expected = Join-Path ([Environment]::GetFolderPath('System')) 'svchost.exe'
            Get-StartupTargetPath -Command 'svchost.exe -k netsvcs' | Should -Be $expected
        }
    }

    It 'returns nothing for <_> rather than guessing' -ForEach @('', '   ', '"unterminated quote') {
        $value = $_
        InModuleScope Win11Optimizer.Engine -Parameters @{ Value = $value } {
            param($Value)
            # A guessed path gets probed for existence, and a parse failure would
            # then manufacture an orphan Finding out of nothing.
            Get-StartupTargetPath -Command $Value | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-StartupTargetPresent' {

    BeforeAll {
        $script:PresentDir  = Join-Path $script:Scratch 'present'
        $null = New-Item -Path $script:PresentDir -ItemType Directory -Force
        $script:PresentFile = Join-Path $script:PresentDir 'here.exe'
        [System.IO.File]::WriteAllText($script:PresentFile, 'x')
    }

    It 'reports a file that is there as present' {
        $path = $script:PresentFile
        InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $path } {
            param($Path)
            Test-StartupTargetPresent -Path $Path | Should -BeTrue
        }
    }

    It 'reports a file missing from a readable folder as PROVED absent' {
        $path = Join-Path $script:PresentDir 'gone.exe'
        InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $path } {
            param($Path)
            $result = Test-StartupTargetPresent -Path $Path
            $result | Should -BeOfType [bool]
            $result | Should -BeFalse
        }
    }

    It 'reports a file under a folder that does not exist at all as absent' {
        $path = Join-Path $script:Scratch 'no-such-folder\nested\gone.exe'
        InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $path } {
            param($Path)
            Test-StartupTargetPresent -Path $Path | Should -BeFalse
        }
    }

    It 'returns null, not false, for <_>' -ForEach @('', '   ', 'relative\path.exe') {
        $value = $_
        InModuleScope Win11Optimizer.Engine -Parameters @{ Value = $value } {
            param($Value)
            # Null is "we do not know", and the matcher never turns that into an
            # orphan. Collapsing it into $false would offer to delete working
            # software whenever a path could not be parsed.
            $null -eq (Test-StartupTargetPresent -Path $Value) | Should -BeTrue
        }
    }
}

Describe 'StartupApproved decoding' {

    It 'decodes byte 0 = <Flag> as <Expected>' -ForEach @(
        # Measured on the development machine 2026-08-25 and confirmed against
        # Task Manager: 0x01 is what this build of Windows writes for "off".
        @{ Flag = 1; Expected = 'Disabled' }
        @{ Flag = 2; Expected = 'Enabled' }
        @{ Flag = 3; Expected = 'Disabled' }
        @{ Flag = 4; Expected = 'Enabled' }
        @{ Flag = 6; Expected = 'Enabled' }
        @{ Flag = 7; Expected = 'Disabled' }
    ) {
        $flag = $Flag
        $expected = $Expected
        InModuleScope Win11Optimizer.Engine -Parameters @{ Flag = $flag; Expected = $expected } {
            param($Flag, $Expected)
            $bytes = [byte[]]::new(12)
            $bytes[0] = [byte] $Flag
            ConvertFrom-StartupApprovedValue -Value $bytes | Should -Be $Expected
        }
    }

    It 'reads a disabled entry as disabled even when its timestamp is all zeros' {
        InModuleScope Win11Optimizer.Engine {
            # 'Docker Desktop' on the development machine: 01 00 00 00 followed by
            # eight zero bytes, and Task Manager shows it as off. Reading "zero
            # timestamp means enabled" gets exactly this one backwards.
            $bytes = [byte[]] @(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            ConvertFrom-StartupApprovedValue -Value $bytes | Should -Be 'Disabled'
        }
    }

    It 'reports an undecodable value as Unknown rather than guessing Enabled' -ForEach @(0, 5, 8, 255) {
        $flag = $_
        InModuleScope Win11Optimizer.Engine -Parameters @{ Flag = $flag } {
            param($Flag)
            # Guessing 'Enabled' is the unsafe direction: it is the only state that
            # lets an entry become a Finding.
            $bytes = [byte[]]::new(12)
            $bytes[0] = [byte] $Flag
            ConvertFrom-StartupApprovedValue -Value $bytes | Should -Be 'Unknown'
        }
    }

    It 'reports a null or empty value as Unknown' {
        InModuleScope Win11Optimizer.Engine {
            ConvertFrom-StartupApprovedValue -Value $null | Should -Be 'Unknown'
            ConvertFrom-StartupApprovedValue -Value ([byte[]]::new(0)) | Should -Be 'Unknown'
            ConvertFrom-StartupApprovedValue -Value 'not bytes at all' | Should -Be 'Unknown'
        }
    }

    It 'treats an entry with no approval record as enabled, and says so' {
        InModuleScope Win11Optimizer.Engine {
            $table = [pscustomobject]@{ Readable = $true; Present = $true; State = @{}; Reason = $null }
            $resolved = Resolve-StartupApprovalState -Table $table -Name 'NeverTouched'
            $resolved.State  | Should -Be 'Enabled'
            $resolved.Detail | Should -Match 'never been turned off'
        }
    }

    It 'treats an entry whose approval store could not be read as Unknown' {
        InModuleScope Win11Optimizer.Engine {
            $table = [pscustomobject]@{ Readable = $false; Present = $true; State = @{}; Reason = 'Access denied.' }
            (Resolve-StartupApprovalState -Table $table -Name 'Whatever').State | Should -Be 'Unknown'
        }
    }
}

Describe 'Get-StartupFolderItem' {

    BeforeAll {
        $script:FolderScratch = Join-Path $script:Scratch 'startupfolder'
        $null = New-Item -Path $script:FolderScratch -ItemType Directory -Force

        # Windows drops a desktop.ini into both real Startup folders.
        [System.IO.File]::WriteAllText((Join-Path $script:FolderScratch 'desktop.ini'), '[.ShellClassInfo]')

        $script:LiveTarget = Join-Path $script:FolderScratch 'live.exe'
        [System.IO.File]::WriteAllText($script:LiveTarget, 'x')

        $shell = New-Object -ComObject WScript.Shell
        $good = $shell.CreateShortcut((Join-Path $script:FolderScratch 'Good.lnk'))
        $good.TargetPath = $script:LiveTarget
        $good.Save()
        $broken = $shell.CreateShortcut((Join-Path $script:FolderScratch 'Broken.lnk'))
        $broken.TargetPath = (Join-Path $script:FolderScratch 'vanished.exe')
        $broken.Save()

        $folder = $script:FolderScratch
        $script:FolderItems = @(InModuleScope Win11Optimizer.Engine -Parameters @{ Folder = $folder } {
            param($Folder)
            Get-StartupFolderItem -Path $Folder -Scope User
        })
    }

    It 'ignores desktop.ini, which Windows puts in both real Startup folders' {
        @($script:FolderItems | Where-Object { $_.Name -eq 'desktop.ini' }).Count | Should -Be 0
    }

    It 'reads the shortcuts and the loose executable' {
        @($script:FolderItems).Count | Should -Be 3
    }

    It 'resolves a shortcut to its target and sees that the target is there' {
        $good = @($script:FolderItems | Where-Object { $_.Name -eq 'Good.lnk' })[0]
        $good.TargetPath   | Should -Be $script:LiveTarget
        $good.TargetExists | Should -BeTrue
    }

    It 'reports a shortcut whose target is gone as an orphan' {
        $broken = @($script:FolderItems | Where-Object { $_.Name -eq 'Broken.lnk' })[0]
        $broken.TargetExists | Should -BeOfType [bool]
        $broken.TargetExists | Should -BeFalse
    }

    It 'maps a Startup-folder entry to the FileDelete removal method' {
        foreach ($item in $script:FolderItems) { $item.RemovalMethod | Should -Be 'FileDelete' }
    }

    It 'returns nothing for a folder that is not there, rather than throwing' {
        $missing = Join-Path $script:Scratch 'no-such-startup-folder'
        { InModuleScope Win11Optimizer.Engine -Parameters @{ Folder = $missing } {
            param($Folder)
            $null = @(Get-StartupFolderItem -Path $Folder -Scope User)
        } } | Should -Not -Throw
    }
}

Describe 'Find-UnwantedStartupItem: what becomes a Finding' {

    BeforeAll {
        $script:CuratedEntry = [pscustomobject]@{
            Id                    = 'test-junk'
            DisplayName           = 'Test Junk Startup Entry'
            Vendor                = 'Test Vendor'
            Reason                = 'Fabricated curated entry used by the test suite.'
            Provenance            = 'published'
            RequiresConsent       = $false
            Note                  = $null
            RunValueName          = [string[]] @('TestJunk')
            StartupFolderFileName = [string[]] @('TestJunk.lnk')
            ScheduledTaskName     = [string[]] @('TestJunkTask')
            ServiceName           = [string[]] @('TestJunkService')
            ServiceDisplayName    = [string[]] @()
            TargetFileName        = [string[]] @('testjunk.exe')
        }
    }

    It 'flags a curated-list match' {
        $item = New-TestStartupItem -Name 'TestJunk' -DisplayName 'TestJunk'
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($script:CuratedEntry))

        $findings.Count           | Should -Be 1
        $findings[0].Confidence   | Should -Be 'Known'
        $findings[0].FindingReason | Should -Be 'CuratedList'
        $findings[0].StartupEntryId | Should -Be 'test-junk'
        $findings[0].Category     | Should -Be 'StartupItem'
        $findings[0].RemovalMethod | Should -Be 'RegistryRunKey'
        ($findings[0].Evidence -join ' ') | Should -Match 'Fabricated curated entry'
    }

    It 'says so in the evidence when a curated entry has never been seen on real hardware' {
        $item = New-TestStartupItem -Name 'TestJunk'
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($script:CuratedEntry))
        ($findings[0].Evidence -join ' ') | Should -Match 'never been observed on real hardware'
    }

    It 'flags an orphan, with no curated entry involved' {
        $item = New-TestStartupItem -Name 'SomethingLeftBehind' -TargetExists $false -TargetPath 'C:\Gone\app.exe'
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @())

        $findings.Count            | Should -Be 1
        $findings[0].FindingReason | Should -Be 'Orphan'
        $findings[0].Confidence    | Should -Be 'Known'
        ($findings[0].Evidence -join ' ') | Should -Match 'not on disk'
        ($findings[0].Evidence -join ' ') | Should -Match 'listed successfully'
    }

    It 'does NOT flag an entry whose target existence could not be determined' {
        # Absence of evidence is not evidence of absence -- the rule this project
        # keeps relearning.
        $item = New-TestStartupItem -Name 'Unknowable' -TargetExists $null -TargetPath 'C:\Locked\app.exe'
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @()).Count | Should -Be 0
    }

    It 'does NOT flag an ordinary third-party entry the user chose' {
        # The whole point of the chunk. Steam, Discord, Overwolf and friends all
        # look exactly like this record.
        $item = New-TestStartupItem -Name 'Steam' -DisplayName 'Steam' -Publisher 'Valve Corporation' `
            -Command '"C:\Program Files (x86)\Steam\steam.exe" -silent'
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($script:CuratedEntry)).Count | Should -Be 0
    }

    It 'has no publisher tier: a non-Microsoft publisher is not a reason on its own' {
        $items = @(
            (New-TestStartupItem -Name 'A' -Publisher 'Some Random Vendor GmbH')
            (New-TestStartupItem -Name 'B' -Publisher $null)
            (New-TestStartupItem -Name 'C' -Publisher 'Definitely Not Microsoft')
        )
        @(Find-UnwantedStartupItem -StartupItem $items -KnownStartupItemEntry @($script:CuratedEntry)).Count | Should -Be 0
    }

    It 'matches a curated entry on the target file name, whatever the entry is called' {
        $item = New-TestStartupItem -Name 'SomeOtherValueName' -TargetPath 'C:\Vendor\testjunk.exe' `
            -Command 'C:\Vendor\testjunk.exe'
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($script:CuratedEntry))
        $findings.Count | Should -Be 1
    }
}

Describe 'Find-UnwantedStartupItem: what must never be flagged' {

    BeforeAll {
        $script:MatchEverything = [pscustomobject]@{
            Id                    = 'over-eager'
            DisplayName           = 'Deliberately over-eager test entry'
            Vendor                = 'Test'
            Reason                = 'Fabricated entry that matches the records below, to prove the code rules beat the list.'
            Provenance            = 'published'
            RequiresConsent       = $false
            Note                  = $null
            RunValueName          = [string[]] @('AlreadyOff', 'Undecodable')
            StartupFolderFileName = [string[]] @()
            ScheduledTaskName     = [string[]] @('Defrag')
            ServiceName           = [string[]] @('NvContainerLocalSystem', 'MBAMService', 'HarmlessService')
            ServiceDisplayName    = [string[]] @()
            TargetFileName        = [string[]] @()
        }
    }

    It 'never flags an entry the user has already turned off' {
        # Flagging something already handled is the padding that makes a tool in
        # this category look like it is inventing work.
        $item = New-TestStartupItem -Name 'AlreadyOff' -EnabledState 'Disabled' -TargetExists $false
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($script:MatchEverything)).Count | Should -Be 0
    }

    It 'never flags an entry whose enabled state could not be decoded' {
        $item = New-TestStartupItem -Name 'Undecodable' -EnabledState 'Unknown' -TargetExists $false
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($script:MatchEverything)).Count | Should -Be 0
    }

    It 'never flags a task under \Microsoft\Windows\, even one the curated list names' {
        # Enforced in code, not by list entry, so no future list edit can reach in.
        $item = New-TestStartupItem -Mechanism 'ScheduledTask' `
            -Id '\Microsoft\Windows\Defrag\ScheduledDefrag' -Name 'Defrag' -DisplayName 'Defrag' `
            -Scope 'Machine' -View $null -TargetExists $false -IsProtectedNamespace $true
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($script:MatchEverything)).Count | Should -Be 0
    }

    It 'flags a task outside that namespace normally, so the rule is a namespace rule and not a blanket one' {
        $item = New-TestStartupItem -Mechanism 'ScheduledTask' `
            -Id '\SomeVendor\Defrag' -Name 'Defrag' -DisplayName 'Defrag' `
            -Scope 'Machine' -View $null
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($script:MatchEverything))
        $findings.Count | Should -Be 1
        $findings[0].RemovalMethod | Should -Be 'TaskScheduler'
    }

    It 'never flags a <Class>-class service, using P2-C3 exclusion list' -ForEach @(
        @{ Class = 'driver';         Name = 'NvContainerLocalSystem'; Display = 'NVIDIA LocalSystem Container'; Publisher = 'NVIDIA Corporation' }
        @{ Class = 'security';       Name = 'MBAMService';            Display = 'Malwarebytes Service';         Publisher = 'Malwarebytes' }
        @{ Class = 'driver-utility'; Name = 'MSI_Center_Service';     Display = 'MSI Center Service';           Publisher = 'Micro-Star' }
    ) {
        # TargetExists $true: this is the plain class-exclusion rule, on a service
        # that is RUNNING SOFTWARE. What happens when the same service is a proved
        # orphan is a different rule and has its own Describe block below.
        $item = New-TestStartupItem -Mechanism 'Service' -Id $Name -Name $Name -DisplayName $Display `
            -Publisher $Publisher -Scope 'Machine' -View $null -TargetExists $true

        $entry = [pscustomobject]@{
            Id = 'over-eager'; DisplayName = 'x'; Vendor = 'V'; Reason = 'Fabricated.'; Provenance = 'published'
            RequiresConsent = $false; Note = $null
            RunValueName = [string[]] @(); StartupFolderFileName = [string[]] @(); ScheduledTaskName = [string[]] @()
            ServiceName = [string[]] @($Name); ServiceDisplayName = [string[]] @(); TargetFileName = [string[]] @()
        }

        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) `
            -KnownStartupItemEntry @($entry) `
            -ExclusionEntry (Get-UnusedAppExclusionList))
        $findings.Count | Should -Be 0
    }

    It 'still flags a service that no exclusion class covers' {
        $item = New-TestStartupItem -Mechanism 'Service' -Id 'HarmlessService' -Name 'HarmlessService' `
            -DisplayName 'Harmless Service' -Publisher 'Nobody In Particular Ltd.' `
            -Scope 'Machine' -View $null -TargetExists $false
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) `
            -KnownStartupItemEntry @($script:MatchEverything) `
            -ExclusionEntry (Get-UnusedAppExclusionList))
        $findings.Count | Should -Be 1
    }
}

Describe 'Find-UnwantedStartupItem: a proved orphan and the class exclusion' {
    # Chunk P2-C2a / docs\STATE.md 2026-08-26. Two halves of one decision, and
    # collapsing either into the other is the refactor these tests exist to stop:
    #   * for 'driver' and 'driver-utility', a PROVED ORPHAN beats the exclusion --
    #     a device utility whose binary is gone is managing no hardware;
    #   * for 'security' it never does -- anti-tamper minifilters hide binaries from
    #     enumeration, so the orphan proof is the unreliable half there, and the
    #     cost of believing it is offering to disable live antivirus.

    BeforeAll { $script:Exclusions = @(Get-UnusedAppExclusionList) }

    It 'flags a driver-utility service whose binary is proved absent' {
        $item = New-TestServiceItem -Display 'MSI Center Service' -TargetExists $false
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @() -ExclusionEntry $script:Exclusions)

        $findings.Count            | Should -Be 1
        $findings[0].FindingReason | Should -Be 'Orphan'
        $findings[0].RequiresConsent | Should -BeTrue
    }

    It 'never flags a security service, even one whose binary is proved absent' {
        # The test that stops a future refactor from collapsing the two branches.
        # 'Malwarebytes Service' matches antivirus-and-endpoint-security, class
        # 'security', and TargetExists $false is the strongest orphan proof there is.
        $item = New-TestServiceItem -Display 'Malwarebytes Service' -TargetExists $false
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @() -ExclusionEntry $script:Exclusions).Count |
            Should -Be 0
    }

    It 'still never flags a driver-class service that is not an orphan, curated list or no' {
        # The rule where nothing changed. A curated entry names it, so the test
        # cannot pass merely because nothing made it a candidate.
        $entry = [pscustomobject]@{
            Id = 'nv'; DisplayName = 'NVIDIA container'; Vendor = 'NVIDIA'; Reason = 'Fabricated.'; Provenance = 'published'
            RequiresConsent = $false; Note = $null
            RunValueName = [string[]] @(); StartupFolderFileName = [string[]] @(); ScheduledTaskName = [string[]] @()
            ServiceName = [string[]] @('NVIDIA LocalSystem Container'); ServiceDisplayName = [string[]] @()
            TargetFileName = [string[]] @()
        }
        $item = New-TestServiceItem -Display 'NVIDIA LocalSystem Container' -TargetExists $true -Publisher 'NVIDIA Corporation'
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($entry) -ExclusionEntry $script:Exclusions).Count |
            Should -Be 0
    }

    It 'does not treat a driver-utility service with an undeterminable target as an orphan' {
        # Absence of proof is not proof of absence. The same record with $false is
        # flagged one line below, which is the whole contrast.
        $unknowable = New-TestServiceItem -Display 'MSI Center Service' -TargetExists $null
        $proved     = New-TestServiceItem -Display 'MSI Center Service' -TargetExists $false

        @(Find-UnwantedStartupItem -StartupItem @($unknowable) -KnownStartupItemEntry @() -ExclusionEntry $script:Exclusions).Count | Should -Be 0
        @(Find-UnwantedStartupItem -StartupItem @($proved)     -KnownStartupItemEntry @() -ExclusionEntry $script:Exclusions).Count | Should -Be 1
    }

    It 'takes the orphan-proof classes from a parameter, not from a literal in the matcher' {
        # Move driver-utility onto the orphan-proof list and the same orphan stops
        # being flagged: proof that 'security' is a default and not a hard-coded string.
        $item = New-TestServiceItem -Display 'MSI Center Service' -TargetExists $false
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @() `
            -ExclusionEntry $script:Exclusions -OrphanProofServiceClass @('security', 'driver-utility')).Count | Should -Be 0
    }

    It 'defaults OrphanProofServiceClass to security' {
        InModuleScope Win11Optimizer.Engine {
            $script:StartupOrphanProofServiceClass | Should -Be @('security')
        }
        (Get-Command Find-UnwantedStartupItem).Parameters.Keys | Should -Contain 'OrphanProofServiceClass'
    }

    It 'says in the evidence which class was matched and why the usual protection did not apply' {
        $item = New-TestServiceItem -Display 'MSI Center Service' -TargetExists $false
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @() -ExclusionEntry $script:Exclusions)
        $evidence = ($findings[0].Evidence -join ' ')

        $evidence | Should -Match "'driver-utility'"
        $evidence | Should -Match 'oem-firmware-update-utility'
        $evidence | Should -Match 'set aside'
        $evidence | Should -Match 'proved absent'
    }

    It 'still flags a peripheral-control-software orphan after Razer joined that entry' {
        # Pins the P2-C2a pair. Change 2 (Razer onto peripheral-control-software)
        # on its own would delete the only Finding this project has produced on real
        # hardware; change 1 is what keeps it. Revert either half and this fails.
        $item = New-TestServiceItem -Display 'Razer Chroma SDK Server' -TargetExists $false
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @() -ExclusionEntry $script:Exclusions)

        $findings.Count            | Should -Be 1
        $findings[0].FindingReason | Should -Be 'Orphan'
        ($findings[0].Evidence -join ' ') | Should -Match 'peripheral-control-software'
    }

    It 'confirms Razer reaches that entry by display name, the only rule an orphan can match' {
        # An orphan's binary is gone, so no publisher of any kind can be resolved
        # for it. A registryPublisher rule would have been inert here.
        InModuleScope Win11Optimizer.Engine {
            $entry = @(Get-UnusedAppExclusionList | Where-Object { $_.Id -eq 'peripheral-control-software' })[0]
            @($entry.RegistryDisplayName | Where-Object { $_ -like 'Razer*' }).Count | Should -BeGreaterThan 0
            $entry.Class | Should -Be 'driver-utility'
        }
    }
}

Describe 'Find-UnwantedStartupItem: the injected publisher resolver' {

    BeforeAll { $script:Exclusions = @(Get-UnusedAppExclusionList) }

    It 'performs no I/O of its own: the resolver is injected and defaults to null' {
        (Get-Command Find-UnwantedStartupItem).Parameters['ServicePublisherResolver'].ParameterType.Name |
            Should -Be 'ScriptBlock'

        # The function body itself must not read the machine. Extracted by the
        # parser rather than by searching the whole file, which would also see
        # Invoke-StartupItemScan and the inventory readers.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:SourcePath, [ref]$null, [ref]$null)
        $function = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Find-UnwantedStartupItem'
        }, $true)
        $body = $function.Extent.Text

        # The .PARAMETER help names the resolver Invoke-StartupItemScan supplies,
        # so the assertion is about CALLS that touch the machine, not about the
        # word appearing anywhere in the function.
        $code = ($body -split "#>", 2)[-1]
        foreach ($forbidden in 'Get-AuthenticodeSignature', 'Get-ItemProperty', 'Get-ChildItem', 'System.IO.File', 'System.IO.Directory', 'Get-Service', 'Get-StartupTargetPublisher', 'Get-StartupTargetCompany', 'Test-StartupTargetPresent') {
            $code | Should -Not -Match ([regex]::Escape($forbidden)) -Because 'Find-UnwantedStartupItem is the pure half of the detector'
        }
    }

    It 'uses the record Publisher when no resolver is supplied' {
        # Today's behaviour, unchanged: a driver-class publisher rule still gates.
        $item = New-TestStartupItem -Mechanism 'Service' -Id 'SomeSvc' -Name 'SomeSvc' -DisplayName 'Some Vendor Service' `
            -Publisher 'NVIDIA Corporation' -Scope 'Machine' -View $null -TargetExists $true
        $entry = [pscustomobject]@{
            Id = 'x'; DisplayName = 'X'; Vendor = 'V'; Reason = 'Fabricated.'; Provenance = 'published'
            RequiresConsent = $false; Note = $null
            RunValueName = [string[]] @(); StartupFolderFileName = [string[]] @(); ScheduledTaskName = [string[]] @()
            ServiceName = [string[]] @('SomeSvc'); ServiceDisplayName = [string[]] @(); TargetFileName = [string[]] @()
        }
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($entry) -ExclusionEntry $script:Exclusions).Count |
            Should -Be 0
    }

    It 'lets a resolved publisher reach the exclusion gate that the blank record could not' {
        # NvContainerLocalSystem's shape: no CompanyName on the binary, so the
        # nvidia-driver-stack publisher rule never fired until the signer answered.
        $item = New-TestStartupItem -Mechanism 'Service' -Id 'SomeSvc' -Name 'SomeSvc' -DisplayName 'Some Vendor Service' `
            -Publisher $null -Scope 'Machine' -View $null -TargetExists $true
        $entry = [pscustomobject]@{
            Id = 'x'; DisplayName = 'X'; Vendor = 'V'; Reason = 'Fabricated.'; Provenance = 'published'
            RequiresConsent = $false; Note = $null
            RunValueName = [string[]] @(); StartupFolderFileName = [string[]] @(); ScheduledTaskName = [string[]] @()
            ServiceName = [string[]] @('SomeSvc'); ServiceDisplayName = [string[]] @(); TargetFileName = [string[]] @()
        }

        $withoutResolver = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($entry) -ExclusionEntry $script:Exclusions)
        $withResolver    = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($entry) -ExclusionEntry $script:Exclusions `
            -ServicePublisherResolver { param($Path) 'NVIDIA Corporation' })

        $withoutResolver.Count | Should -Be 1
        $withResolver.Count    | Should -Be 0
    }

    It 'treats a resolver that answers null as "no publisher", never as "not that vendor"' {
        # 'Corsair' is a registryPublisher rule on peripheral-control-software and
        # the display name reaches nothing, so the record's own publisher is the
        # only thing holding this service back. A resolver answering $null must
        # leave it exactly where it was.
        $item = New-TestStartupItem -Mechanism 'Service' -Id 'SomeSvc' -Name 'SomeSvc' -DisplayName 'Some Vendor Service' `
            -Publisher 'Corsair' -Scope 'Machine' -View $null -TargetExists $true
        $entry = [pscustomobject]@{
            Id = 'x'; DisplayName = 'X'; Vendor = 'V'; Reason = 'Fabricated.'; Provenance = 'published'
            RequiresConsent = $false; Note = $null
            RunValueName = [string[]] @(); StartupFolderFileName = [string[]] @(); ScheduledTaskName = [string[]] @()
            ServiceName = [string[]] @('SomeSvc'); ServiceDisplayName = [string[]] @(); TargetFileName = [string[]] @()
        }
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($entry) -ExclusionEntry $script:Exclusions `
            -ServicePublisherResolver { param($Path) $null }).Count | Should -Be 0
    }

    It 'never loses an exclusion the record already made, whatever the resolver answers' {
        # Measured on this machine: the signer and the version resource disagree
        # about the same vendor -- 'Razer USA Ltd.' vs 'Razer Inc.', and
        # NvContainerLocalSystem is signed by the WHQL attestation publisher rather
        # than by NVIDIA. Overwriting the publisher would break a registryPublisher
        # rule written from a CompanyName, and a LOST exclusion is a spurious
        # Finding -- the one direction this list may not fail in.
        $item = New-TestStartupItem -Mechanism 'Service' -Id 'SomeSvc' -Name 'SomeSvc' -DisplayName 'Some Vendor Service' `
            -Publisher 'Corsair' -Scope 'Machine' -View $null -TargetExists $true
        $entry = [pscustomobject]@{
            Id = 'x'; DisplayName = 'X'; Vendor = 'V'; Reason = 'Fabricated.'; Provenance = 'published'
            RequiresConsent = $false; Note = $null
            RunValueName = [string[]] @(); StartupFolderFileName = [string[]] @(); ScheduledTaskName = [string[]] @()
            ServiceName = [string[]] @('SomeSvc'); ServiceDisplayName = [string[]] @(); TargetFileName = [string[]] @()
        }
        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($entry) -ExclusionEntry $script:Exclusions `
            -ServicePublisherResolver { param($Path) 'Corsair Memory, Inc.' }).Count | Should -Be 0
    }

    It 'does not pay for a signature when the record already excluded the service' {
        $script:ResolverCalls = New-Object System.Collections.Generic.List[string]
        $resolver = { param($Path) $script:ResolverCalls.Add([string]$Path); 'Some Vendor' }

        $item = New-TestStartupItem -Mechanism 'Service' -Id 'MBAMService' -Name 'MBAMService' -DisplayName 'Malwarebytes Service' `
            -Publisher $null -Scope 'Machine' -View $null -TargetExists $false -TargetPath 'C:\Gone\mbam.exe'

        @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @() `
            -ExclusionEntry $script:Exclusions -ServicePublisherResolver $resolver).Count | Should -Be 0
        $script:ResolverCalls.Count | Should -Be 0
    }

    It 'is lazy: the resolver runs once for the one candidate service and not for the other twenty records' {
        # This assertion IS the design. A resolver that ran across the inventory
        # would be ~90 signature checks per scan on this machine.
        $script:ResolverCalls = New-Object System.Collections.Generic.List[string]
        $resolver = { param($Path) $script:ResolverCalls.Add([string]$Path); $null }

        $items = New-Object System.Collections.Generic.List[psobject]
        # A candidate: an orphaned service, no exclusion class.
        $items.Add((New-TestStartupItem -Mechanism 'Service' -Id 'Candidate' -Name 'Candidate' -DisplayName 'Candidate Service' `
            -Publisher $null -Scope 'Machine' -View $null -TargetExists $false -TargetPath 'C:\Gone\candidate.exe'))
        # Non-candidates, one per reason: healthy service, disabled service,
        # undecodable service, and a pile of ordinary Run keys.
        $items.Add((New-TestStartupItem -Mechanism 'Service' -Id 'Healthy' -Name 'Healthy' -DisplayName 'Healthy Service' `
            -Scope 'Machine' -View $null -TargetExists $true -TargetPath 'C:\Here\healthy.exe'))
        $items.Add((New-TestStartupItem -Mechanism 'Service' -Id 'Off' -Name 'Off' -DisplayName 'Disabled Service' `
            -Scope 'Machine' -View $null -TargetExists $false -EnabledState 'Disabled' -TargetPath 'C:\Gone\off.exe'))
        $items.Add((New-TestStartupItem -Mechanism 'Service' -Id 'Undecodable' -Name 'Undecodable' -DisplayName 'Undecodable Service' `
            -Scope 'Machine' -View $null -TargetExists $false -EnabledState 'Unknown' -TargetPath 'C:\Gone\undecodable.exe'))
        1..17 | ForEach-Object { $items.Add((New-TestStartupItem -Name "Ordinary$_" -DisplayName "Ordinary $_")) }

        $findings = @(Find-UnwantedStartupItem -StartupItem $items.ToArray() -KnownStartupItemEntry @() `
            -ExclusionEntry $script:Exclusions -ServicePublisherResolver $resolver)

        $findings.Count               | Should -Be 1
        $script:ResolverCalls.Count   | Should -Be 1
        $script:ResolverCalls[0]      | Should -Be 'C:\Gone\candidate.exe'
    }

    It 'never runs the resolver for a non-service mechanism' {
        $script:ResolverCalls = New-Object System.Collections.Generic.List[string]
        $resolver = { param($Path) $script:ResolverCalls.Add([string]$Path); 'Some Vendor' }

        $item = New-TestStartupItem -Name 'BrokenRunKey' -TargetExists $false -TargetPath 'C:\Gone\app.exe'
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @() `
            -ExclusionEntry $script:Exclusions -ServicePublisherResolver $resolver)

        $findings.Count             | Should -Be 1
        $script:ResolverCalls.Count | Should -Be 0
    }
}

Describe 'Get-StartupTargetPublisher' {

    It 'returns the Authenticode signer for a signed binary on this machine' {
        # An OS binary is the only file guaranteed to be here and signed.
        $signed = Join-Path $env:SystemRoot 'System32\notepad.exe'
        InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $signed } {
            param($Path)
            $signer = Get-StartupTargetSigner -Path $Path
            $signer | Should -Not -BeNullOrEmpty
            $signer | Should -Match 'Microsoft'
            # The CN, not the whole X.500 subject and not the path.
            $signer | Should -Not -Match 'CN='
            $signer | Should -Not -Match ([regex]::Escape($Path))
        }
    }

    It 'returns null for <Case> rather than guessing a vendor' -ForEach @(
        @{ Case = 'a file that is not there'; Relative = $false }
        @{ Case = 'an unsigned file';         Relative = $false }
        @{ Case = 'a relative path';          Relative = $true  }
    ) {
        $path = switch ($Case) {
            'a file that is not there' { Join-Path $script:Scratch 'no-such-binary.exe' }
            'an unsigned file' {
                $unsigned = Join-Path $script:Scratch ('unsigned-' + [guid]::NewGuid().ToString('N') + '.exe')
                [System.IO.File]::WriteAllText($unsigned, 'not a real executable')
                $unsigned
            }
            'a relative path' { 'notepad.exe' }
        }

        InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $path } {
            param($Path)
            Get-StartupTargetSigner -Path $Path | Should -BeNullOrEmpty
        }
    }

    It 'returns null for an empty or null path' {
        InModuleScope Win11Optimizer.Engine {
            Get-StartupTargetSigner -Path $null    | Should -BeNullOrEmpty
            Get-StartupTargetSigner -Path ''       | Should -BeNullOrEmpty
            Get-StartupTargetPublisher -Path $null | Should -BeNullOrEmpty
        }
    }

    It 'falls back to the version-resource CompanyName when there is no usable signature' {
        InModuleScope Win11Optimizer.Engine {
            Mock Get-StartupTargetSigner  { $null }
            Mock Get-StartupTargetCompany { 'Fallback Vendor Ltd.' }
            Get-StartupTargetPublisher -Path 'C:\Whatever\thing.exe' | Should -Be 'Fallback Vendor Ltd.'
        }
    }

    It 'prefers the signer over the version resource when both answer' {
        InModuleScope Win11Optimizer.Engine {
            Mock Get-StartupTargetSigner  { 'Signed Vendor Inc.' }
            Mock Get-StartupTargetCompany { 'Version Resource Vendor' }
            Get-StartupTargetPublisher -Path 'C:\Whatever\thing.exe' | Should -Be 'Signed Vendor Inc.'
        }
    }

    It 'returns null when neither the signer nor the version resource answers' {
        InModuleScope Win11Optimizer.Engine {
            Mock Get-StartupTargetSigner  { $null }
            Mock Get-StartupTargetCompany { $null }
            Get-StartupTargetPublisher -Path 'C:\Whatever\thing.exe' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Find-UnwantedStartupItem: services are review-only, always' {

    It 'gives every Service Finding RequiresConsent and therefore "Review needed"' {
        # docs/STATE.md, 2026-08-23 and 2026-08-25: services are flag-for-review
        # only in v1, because the blast radius is higher than a Run key. The label
        # is derived by the contract; nothing here re-derives it.
        $item = New-TestStartupItem -Mechanism 'Service' -Id 'OrphanedService' -Name 'OrphanedService' `
            -DisplayName 'Orphaned Service' -Publisher 'Nobody Ltd.' -Scope 'Machine' -View $null `
            -TargetExists $false -TargetPath 'C:\Gone\svc.exe'

        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @())
        $findings.Count               | Should -Be 1
        $findings[0].Category         | Should -Be 'Service'
        $findings[0].Confidence       | Should -Be 'Known'
        $findings[0].RequiresConsent  | Should -BeTrue
        $findings[0].SafetyLabel      | Should -Be 'Review needed'
        $findings[0].RemovalMethod    | Should -Be 'ServiceDisable'
        ($findings[0].Evidence -join ' ') | Should -Match 'flag-for-review only'
    }

    It 'lets a non-service Finding be "Safe to remove" when the curated entry does not ask for consent' {
        $entry = [pscustomobject]@{
            Id = 'plain'; DisplayName = 'Plain'; Vendor = 'V'; Reason = 'Fabricated plain entry.'; Provenance = 'measured'
            RequiresConsent = $false; Note = $null
            RunValueName = [string[]] @('PlainThing'); StartupFolderFileName = [string[]] @()
            ScheduledTaskName = [string[]] @(); ServiceName = [string[]] @(); ServiceDisplayName = [string[]] @()
            TargetFileName = [string[]] @()
        }
        $item = New-TestStartupItem -Name 'PlainThing'
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($entry))
        $findings[0].SafetyLabel | Should -Be 'Safe to remove'
    }

    It 'honours requiresConsent on a curated entry for a non-service mechanism too' {
        $entry = [pscustomobject]@{
            Id = 'consenty'; DisplayName = 'Consenty'; Vendor = 'V'; Reason = 'Fabricated consent entry.'; Provenance = 'measured'
            RequiresConsent = $true; Note = $null
            RunValueName = [string[]] @('ConsentThing'); StartupFolderFileName = [string[]] @()
            ScheduledTaskName = [string[]] @(); ServiceName = [string[]] @(); ServiceDisplayName = [string[]] @()
            TargetFileName = [string[]] @()
        }
        $item = New-TestStartupItem -Name 'ConsentThing'
        $findings = @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @($entry))
        $findings[0].RequiresConsent | Should -BeTrue
        $findings[0].SafetyLabel     | Should -Be 'Review needed'
    }

    It 'returns only New-Finding output' {
        $item = New-TestStartupItem -Name 'Anything' -TargetExists $false
        foreach ($finding in @(Find-UnwantedStartupItem -StartupItem @($item) -KnownStartupItemEntry @())) {
            $finding.PSObject.TypeNames | Should -Contain 'Win11Optimizer.Finding'
            Test-Finding -InputObject $finding | Should -BeTrue
        }
    }

    It 'tolerates an empty inventory and an empty list without throwing' {
        { Find-UnwantedStartupItem -StartupItem @() -KnownStartupItemEntry @() } | Should -Not -Throw
        @(Find-UnwantedStartupItem -StartupItem @() -KnownStartupItemEntry @()).Count | Should -Be 0
    }
}

Describe 'Get-StartupItemInventory on this machine' {

    BeforeAll { $script:Inventory = Get-StartupItemInventory }

    It 'reports one source per mechanism, in a stable order' {
        @($script:Inventory.Sources).Name | Should -Be @('RunKeys', 'StartupFolders', 'ScheduledTasks', 'Services')
    }

    It 'gives every non-succeeded source a stated reason' {
        foreach ($source in $script:Inventory.Sources) {
            if ($source.Status -ne 'Succeeded') { $source.Reason | Should -Not -BeNullOrEmpty }
        }
    }

    It 'covers HKLM 64-bit, HKLM WOW6432Node and HKCU by default' {
        # Omitting WOW6432Node is this project's oldest recurring bug: on the
        # development machine the only machine-scope 32-bit Run entry lives there
        # and appears in no other view.
        InModuleScope Win11Optimizer.Engine {
            $paths = @($script:StartupRunKeyView | ForEach-Object { $_.Path })
            @($paths | Where-Object { $_ -like 'HKLM:\SOFTWARE\Microsoft\*' }).Count     | Should -BeGreaterThan 0
            @($paths | Where-Object { $_ -like 'HKLM:\SOFTWARE\WOW6432Node\*' }).Count   | Should -BeGreaterThan 0
            @($paths | Where-Object { $_ -like 'HKCU:*' }).Count                          | Should -BeGreaterThan 0
            @($paths | Where-Object { $_ -like '*\RunOnce' }).Count                       | Should -BeGreaterThan 0
        }
    }

    It 'resolves the Startup folders from the shell known folders, not hard-coded paths' {
        $source = [System.IO.File]::ReadAllText($script:SourcePath)
        $source | Should -Match "GetFolderPath\('Startup'\)"
        $source | Should -Match "GetFolderPath\('CommonStartup'\)"
        $source | Should -Not -Match 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu'
        $source | Should -Not -Match 'ProgramData\\Microsoft\\Windows\\Start Menu'
    }

    It 'gives every item the full normalised shape' {
        $expected = @(
            'Mechanism', 'Id', 'Name', 'DisplayName', 'Command', 'TargetPath', 'TargetExists',
            'Publisher', 'Scope', 'View', 'Location', 'EnabledState', 'EnabledStateDetail',
            'Trigger', 'IsProtectedNamespace', 'RemovalMethod', 'Category'
        )
        foreach ($item in @($script:Inventory.Items)) {
            foreach ($field in $expected) { $item.PSObject.Properties.Name | Should -Contain $field }
        }
    }

    It 'gives every item one of the three enabled states' {
        foreach ($item in @($script:Inventory.Items)) {
            @('Enabled', 'Disabled', 'Unknown') | Should -Contain $item.EnabledState
        }
    }

    It 'only ever reports a scheduled task with a logon or boot trigger' {
        foreach ($item in @($script:Inventory.Items | Where-Object { $_.Mechanism -eq 'ScheduledTask' })) {
            $item.Trigger | Should -Match 'LogonTrigger|BootTrigger'
        }
    }

    It 'marks every task under \Microsoft\Windows\ as protected' {
        foreach ($item in @($script:Inventory.Items | Where-Object { $_.Mechanism -eq 'ScheduledTask' })) {
            if ($item.Id -like '\Microsoft\Windows\*') { $item.IsProtectedNamespace | Should -BeTrue }
        }
    }

    It 'never reports a driver as a service' {
        # Structural, from the service Type bits: 24 of the 114 automatic-start
        # keys on the development machine are kernel or filesystem drivers.
        foreach ($item in @($script:Inventory.Items | Where-Object { $_.Mechanism -eq 'Service' })) {
            $item.Detail | Should -Match 'Service type 0x'
        }
    }

    It 'records a duration for every source' {
        foreach ($source in $script:Inventory.Sources) { $source.DurationSeconds | Should -BeGreaterOrEqual 0 }
    }

    It 'reads every mechanism without elevation on this machine' {
        # If this ever fails, the answer is not to lower the bar: it is to check
        # which source degraded and whether its reason says so usefully.
        $degraded = @($script:Inventory.Sources | Where-Object { $_.Status -ne 'Succeeded' })
        foreach ($source in $degraded) {
            $source.Reason | Should -Not -BeNullOrEmpty -Because "source '$($source.Name)' is $($source.Status) and must explain itself"
        }
    }
}

Describe 'Invoke-StartupItemScan result shape' {

    BeforeAll { $script:Scan = Invoke-StartupItemScan -WarningAction SilentlyContinue }

    It 'returns a single scan-result object, not a bare array of findings' {
        @($script:Scan).Count | Should -Be 1
        $script:Scan.PSObject.TypeNames | Should -Contain 'Win11Optimizer.StartupScanResult'
        $script:Scan.PSObject.TypeNames | Should -Contain 'Win11Optimizer.ScanResult'
        $script:Scan.PSObject.Properties.Name | Should -Contain 'Findings'
    }

    It 'reaches the full startup inventory, not just the Findings' {
        # P4-C1 shows the user everything that autostarts; the Findings are the
        # small remainder. A category tab that rendered only the Findings would be
        # an empty screen on most machines.
        $script:Scan.PSObject.Properties.Name | Should -Contain 'StartupItems'
        @($script:Scan.StartupItems).Count | Should -Be $script:Scan.InventoryCount
        @($script:Scan.StartupItems).Count | Should -BeGreaterThan 0
    }

    It 'publishes <_>' -ForEach @(
        'CuratedListPath', 'CuratedListCount', 'ExclusionPath', 'ExclusionCount', 'MechanismCount',
        'EnabledCount', 'DisabledCount', 'UnknownStateCount', 'ProtectedTaskCount',
        'ProtectedServiceCount', 'OrphanCount', 'CuratedMatchCount', 'ReadStatistic'
    ) {
        $script:Scan.PSObject.Properties.Name | Should -Contain $_
    }

    It 'has the three enabled states add up to the inventory' {
        ($script:Scan.EnabledCount + $script:Scan.DisabledCount + $script:Scan.UnknownStateCount) | Should -Be $script:Scan.InventoryCount
    }

    It 'has the two Finding reasons add up to the Finding count' {
        ($script:Scan.OrphanCount + $script:Scan.CuratedMatchCount) | Should -Be @($script:Scan.Findings).Count
    }

    It 'returns findings that all pass the Finding contract' {
        foreach ($finding in @($script:Scan.Findings)) {
            Test-Finding -InputObject $finding | Should -BeTrue
            @('StartupItem', 'Service') | Should -Contain $finding.Category
            $finding.Confidence | Should -Be 'Known'
            @($finding.Evidence).Count | Should -BeGreaterThan 0
        }
    }

    It 'gives every finding one of the two allowed reasons and nothing else' {
        foreach ($finding in @($script:Scan.Findings)) {
            @('CuratedList', 'Orphan') | Should -Contain $finding.FindingReason
        }
    }

    It 'flags nothing the user had already turned off' {
        $disabled = @($script:Scan.StartupItems | Where-Object { $_.EnabledState -ne 'Enabled' } | ForEach-Object { $_.Id })
        foreach ($finding in @($script:Scan.Findings)) {
            $disabled | Should -Not -Contain $finding.Id
        }
    }

    It 'flags no task under \Microsoft\Windows\' {
        foreach ($finding in @($script:Scan.Findings | Where-Object { $_.Mechanism -eq 'ScheduledTask' })) {
            $finding.Id | Should -Not -BeLike '\Microsoft\Windows\*'
        }
    }

    It 'makes every Service finding "Review needed"' {
        foreach ($finding in @($script:Scan.Findings | Where-Object { $_.Category -eq 'Service' })) {
            $finding.RequiresConsent | Should -BeTrue
            $finding.SafetyLabel     | Should -Be 'Review needed'
        }
    }

    It 'gives every curated-match finding an id that resolves to exactly one list entry' {
        $entries = @(Get-KnownStartupItemList)
        foreach ($finding in @($script:Scan.Findings | Where-Object { $_.FindingReason -eq 'CuratedList' })) {
            @($entries | Where-Object { $_.Id -eq $finding.StartupEntryId }).Count | Should -Be 1
        }
    }

    It 'logs the scan start, each source outcome and the finding count' {
        $records = @(Get-OptimizerLog)
        @($records | Where-Object { $_.Event -eq 'StartupScanStarted' }).Count   | Should -BeGreaterThan 0
        @($records | Where-Object { $_.Event -eq 'StartupScanSource' }).Count    | Should -BeGreaterOrEqual 4
        @($records | Where-Object { $_.Event -eq 'StartupScanCompleted' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Invoke-StartupItemScan resolves service publishers lazily' {

    It 'reads a signature only for the handful of services that could still become a Finding' {
        # The end-to-end half of the laziness assertion. Resolving eagerly would be
        # one Authenticode check per automatic service -- 90 on this machine --
        # against a scan budget of a couple of seconds. The exact call count is
        # pinned against fabricated input above; here the bound is what matters,
        # because it is the number that would explode on someone else's machine.
        InModuleScope Win11Optimizer.Engine { $script:TestPublisherResolverCalls = 0 }
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-StartupTargetPublisher -MockWith {
            $script:TestPublisherResolverCalls++
            $null
        }

        $json = '{ "entries": [ { "id": "matches-nothing", "displayName": "Nothing", "vendor": "V", "reason": "Test fixture: this entry matches nothing on any machine.", "provenance": "published", "match": { "runValueName": ["NoSuchStartupValueForTests"] } } ] }'
        $scan = Invoke-StartupItemScan -CuratedListPath (New-TestStartupList -Content $json) -WarningAction SilentlyContinue

        # With a curated list that matches nothing, only an orphaned service can
        # reach the gate at all -- and only one whose own publisher did not already
        # exclude it pays for a signature.
        $services = @($scan.StartupItems | Where-Object { $_.Mechanism -eq 'Service' })
        $orphans  = @($services | Where-Object { $_.EnabledState -eq 'Enabled' -and $_.TargetExists -is [bool] -and -not $_.TargetExists })
        $calls    = InModuleScope Win11Optimizer.Engine { $script:TestPublisherResolverCalls }

        $calls         | Should -BeLessOrEqual $orphans.Count
        $orphans.Count | Should -BeLessThan $services.Count -Because 'a resolver that ran across the inventory would not be lazy'
    }
}

Describe 'Invoke-StartupItemScan: found nothing vs broke' {

    It 'reports itself incomplete and names the mechanism when a source is skipped' {
        $scan = Invoke-StartupItemScan -SkipScheduledTask -WarningAction SilentlyContinue
        $tasks = @($scan.Sources | Where-Object { $_.Name -eq 'ScheduledTasks' })[0]
        $tasks.Status     | Should -Be 'Skipped'
        $tasks.Reason     | Should -Not -BeNullOrEmpty
        $scan.IsComplete  | Should -BeFalse
        $scan.SummaryText | Should -Match 'PARTIAL'
        $scan.IncompleteReason | Should -Match 'ScheduledTasks'
    }

    It 'warns on the warning stream when a mechanism could not be read' {
        $warnings = @()
        $null = Invoke-StartupItemScan -SkipService -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join ' ') | Should -Match 'INCOMPLETE'
    }

    It 'still returns the other mechanisms when one is skipped' {
        $scan = Invoke-StartupItemScan -SkipService -WarningAction SilentlyContinue
        @($scan.Sources | Where-Object { $_.Status -eq 'Succeeded' }).Count | Should -BeGreaterThan 0
        $scan.InventoryCount | Should -BeGreaterThan 0
    }

    It 'reports a failed Run-key read instead of silently returning nothing' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-StartupRunKeyItem -MockWith { throw 'Registry hive unavailable.' }

        $scan = Invoke-StartupItemScan -WarningAction SilentlyContinue
        $runKeys = @($scan.Sources | Where-Object { $_.Name -eq 'RunKeys' })[0]
        $runKeys.Status  | Should -Be 'Failed'
        $runKeys.Reason  | Should -Match 'Registry hive unavailable'
        $scan.IsComplete | Should -BeFalse
    }

    It 'reports a failed Task Scheduler read instead of silently returning nothing' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-StartupScheduledTaskItem -MockWith { throw 'Task Scheduler service is not running.' }

        $scan = Invoke-StartupItemScan -WarningAction SilentlyContinue
        $tasks = @($scan.Sources | Where-Object { $_.Name -eq 'ScheduledTasks' })[0]
        $tasks.Status    | Should -Be 'Failed'
        $tasks.Reason    | Should -Match 'Task Scheduler service is not running'
        $scan.IsComplete | Should -BeFalse
    }

    It 'reports an unreadable Startup folder rather than an empty one' {
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-StartupFolderItem -MockWith { throw 'Access to the path is denied.' }

        $scan = Invoke-StartupItemScan -WarningAction SilentlyContinue
        $folders = @($scan.Sources | Where-Object { $_.Name -eq 'StartupFolders' })[0]
        $folders.Status  | Should -Be 'Failed'
        $folders.Reason  | Should -Match 'denied'
        $scan.IsComplete | Should -BeFalse
    }

    It 'reports a scan that found nothing as complete, not as broken' {
        # The other half of the same requirement: zero Findings on a clean machine
        # must be distinguishable from zero Findings because everything broke.
        $json = '{ "entries": [ { "id": "matches-nothing", "displayName": "Nothing", "vendor": "V", "reason": "Test fixture: this entry matches nothing on any machine.", "provenance": "published", "match": { "runValueName": ["NoSuchStartupValueForTests"] } } ] }'
        $scan = Invoke-StartupItemScan -CuratedListPath (New-TestStartupList -Content $json) -WarningAction SilentlyContinue

        $scan.CuratedListCount  | Should -Be 1
        $scan.CuratedMatchCount | Should -Be 0
        $scan.InventoryCount    | Should -BeGreaterThan 0
    }
}

Describe 'Invoke-StartupItemScan list failures' {

    It 'throws rather than returning an apparently-clean result when the curated list is missing' {
        { Invoke-StartupItemScan -CuratedListPath (Join-Path $script:Scratch 'gone-list.json') } | Should -Throw -ExpectedMessage '*not found*'
    }

    It 'throws rather than running on half its rules when the curated list is malformed' {
        { Invoke-StartupItemScan -CuratedListPath (New-TestStartupList -Content '{ "entries": [ {') } | Should -Throw
    }

    It 'throws rather than flagging a driver service when the exclusion list is missing' {
        { Invoke-StartupItemScan -ExclusionPath (Join-Path $script:Scratch 'gone-exclusions.json') } | Should -Throw -ExpectedMessage '*not found*'
    }
}
