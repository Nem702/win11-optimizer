#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the JunkFiles detector (chunk P2-C4,
    src\Win11Optimizer.Engine\Detectors\JunkFiles.ps1).

    This is the most dangerous detector in the project: every other one points at
    software with an uninstall path, and this one points at files. So most of what
    is below is about what must NOT happen --

      * nothing under Downloads / Documents / Desktop / Pictures / Videos / Music
        is enumerated, sized or reported, and a list entry naming one fails the
        whole load rather than being skipped;
      * a reparse point is detected, never traversed, and excluded from both the
        size and the file list;
      * a file inside the age window, or held open, or whose state cannot be
        determined, never reaches a Finding's file list;
      * a location that could not be read makes the scan incomplete via Skipped,
        never Refused, and an unreadable subtree makes the size an explicit floor
        rather than silently shrinking it.

    Run:  .\tests\Invoke-Tests.ps1
#>

BeforeAll {
    $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot   = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath   = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:SourcePath   = Join-Path $script:EngineRoot 'Detectors\JunkFiles.ps1'
    $script:SharedPath   = Join-Path $script:EngineRoot 'Shared\Inventory.ps1'
    $script:ListPath     = Join-Path $script:EngineRoot 'Data\junk-locations.json'

    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-junk-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-junk-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    $script:Source = [System.IO.File]::ReadAllText($script:SourcePath)

    # The source with every comment removed. The "this file never calls X"
    # assertions below have to run against this rather than against the raw text:
    # the header comment names Get-ChildItem, DISM and cleanmgr precisely because
    # they are the things this detector does not do, and PowerShell's -match is
    # case-insensitive, so a prose mention reads exactly like a call.
    #
    # Every comment span is blanked out in place rather than the tokens being
    # re-joined, so the remaining text is byte-for-byte the original code and a
    # pattern like 'FileAccess]::Read' still matches.
    $script:SourceTokens = $null
    $script:SourceErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($script:SourcePath, [ref] $script:SourceTokens, [ref] $script:SourceErrors)

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

    # A junk-location list file with the given entries, written to scratch.
    function New-TestJunkList {
        param([Parameter(Mandatory)] [string] $Content)
        $path = Join-Path $script:Scratch ("junk-" + [guid]::NewGuid().ToString('N') + '.json')
        [System.IO.File]::WriteAllText($path, $Content)
        $path
    }

    # A single-entry list pointing at a fabricated folder. The reason is long
    # because the loader requires a non-empty one and the shipped list's reasons
    # are what the user reads.
    function New-TestJunkListForPath {
        param(
            [Parameter(Mandatory)] [string] $Path,
            [string] $Id = 'fabricated',
            [string] $Provenance = 'measured',
            [switch] $InventoryOnly
        )
        $escaped = $Path.Replace('\', '\\')
        $inventory = if ($InventoryOnly) { 'true' } else { 'false' }
        New-TestJunkList -Content @"
{
  "schemaVersion": 1,
  "entries": [
    {
      "id": "$Id",
      "displayName": "Fabricated location",
      "reason": "A folder created by the test suite so the gates can be exercised against a tree whose contents are known exactly.",
      "provenance": "$Provenance",
      "inventoryOnly": $inventory,
      "paths": [ "$escaped" ]
    }
  ]
}
"@
    }

    # A fabricated tree with a known age split.
    function New-TestJunkTree {
        param(
            [int] $OldFileCount = 3,
            [int] $NewFileCount = 2,
            [int] $BytesPerFile = 100
        )
        $root = Join-Path $script:Scratch ("tree-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $root -ItemType Directory -Force

        $old = [datetime]::UtcNow.AddDays(-90)
        for ($i = 0; $i -lt $OldFileCount; $i++) {
            $file = Join-Path $root "old-$i.tmp"
            [System.IO.File]::WriteAllText($file, ('x' * $BytesPerFile))
            [System.IO.File]::SetCreationTimeUtc($file, $old)
            [System.IO.File]::SetLastWriteTimeUtc($file, $old)
        }
        for ($i = 0; $i -lt $NewFileCount; $i++) {
            $file = Join-Path $root "new-$i.tmp"
            [System.IO.File]::WriteAllText($file, ('x' * $BytesPerFile))
        }
        $root
    }

    # A location record shaped like Get-JunkLocationInventory's output, built by
    # hand rather than by the code under test -- the matcher reads everything
    # through Get-OptimizerProperty, and a test that built its input with the
    # detector would not notice a field being renamed.
    function New-TestJunkLocation {
        param(
            [string] $Id = 'fabricated',
            [string] $DisplayName = 'Fabricated location',
            [string] $Reason = 'A fabricated location used by the test suite.',
            [string] $Provenance = 'measured',
            [bool] $InventoryOnly = $false,
            [bool] $IsAssessed = $true,
            [string] $Status = 'Succeeded',
            [long] $FileCount = 10,
            [long] $TotalBytes = 1000,
            [long] $EligibleFileCount = 4,
            [long] $EligibleBytes = 400,
            [bool] $IsSizeFloor = $false,
            [long] $UnreadableDirectoryCount = 0,
            [long] $AgeHeldBackCount = 3,
            [long] $InUseCount = 2,
            [long] $UndeterminedCount = 1,
            [long] $ReparsePointCount = 0,
            [long] $DuplicatePathCount = 0,
            [string[]] $ResolvedPath = @('C:\fabricated'),
            [psobject[]] $EligibleFile = @()
        )

        [pscustomobject]@{
            Id                        = $Id
            DisplayName               = $DisplayName
            Reason                    = $Reason
            Provenance                = $Provenance
            Owner                     = 'the test suite'
            InventoryOnly             = $InventoryOnly
            InventoryOnlyReason       = $null
            DeclaredPath              = $ResolvedPath
            ResolvedPath              = $ResolvedPath
            Status                    = $Status
            StatusReason              = $null
            Exists                    = $true
            IsAssessed                = $IsAssessed
            FileCount                 = $FileCount
            TotalBytes                = $TotalBytes
            IsSizeFloor               = $IsSizeFloor
            UnreadableDirectoryCount  = $UnreadableDirectoryCount
            UnreadableDirectorySample = @()
            ReparsePointCount         = $ReparsePointCount
            ReparsePointSample        = @()
            DuplicatePathCount        = $DuplicatePathCount
            AgeHeldBackCount          = $AgeHeldBackCount
            AgeHeldBackBytes          = 300
            InUseCount                = $InUseCount
            UndeterminedCount         = $UndeterminedCount
            EligibleFileCount         = $EligibleFileCount
            EligibleBytes             = $EligibleBytes
            EligibleFile              = $EligibleFile
            DurationSeconds           = 0.1
            Detail                    = $null
        }
    }

    # One real scan for every Describe that needs one. It reads several thousand
    # files, so running it three times would triple the suite's wall clock for no
    # extra coverage.
    $script:SharedScan = Invoke-JunkFileScan -WarningAction SilentlyContinue
}

AfterAll {
    if ($script:Scratch -and (Test-Path -LiteralPath $script:Scratch)) {
        # Any deny ACE the tests added has to come off before the folder can be
        # removed, or the cleanup fails and leaves an unreadable folder in %TEMP%.
        foreach ($directory in @(Get-ChildItem -LiteralPath $script:Scratch -Recurse -Directory -Force -ErrorAction SilentlyContinue)) {
            try {
                $acl = Get-Acl -LiteralPath $directory.FullName -ErrorAction Stop
                $changed = $false
                foreach ($rule in @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })) {
                    $null = $acl.RemoveAccessRule($rule)
                    $changed = $true
                }
                if ($changed) { Set-Acl -LiteralPath $directory.FullName -AclObject $acl -ErrorAction Stop }
            }
            catch { }
        }
        Remove-Item -LiteralPath $script:Scratch -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($script:TestLogRoot -and (Test-Path -LiteralPath $script:TestLogRoot)) {
        Remove-Item -LiteralPath $script:TestLogRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\WIN11OPTIMIZER_LOGROOT -ErrorAction SilentlyContinue
}

Describe 'JunkFiles.ps1 is a detector, not a cleaner' {

    It 'parses cleanly' {
        @($script:SourceErrors).Count | Should -Be 0
    }

    It 'contains no <_> call' -ForEach @('Remove-Item', 'Remove-ItemProperty', 'Clear-RecycleBin', 'Clear-Content', 'Clear-Item', 'cleanmgr', 'Set-Content', 'Out-File', 'New-Item', 'Move-Item', 'File]::Delete', 'Directory]::Delete', 'File]::Move', 'File]::WriteAll', 'File]::Create', 'File]::AppendAll', 'Set-ItemProperty', 'New-ItemProperty', 'Set-Acl', 'Remove-WindowsPackage', 'Repair-WindowsImage', 'Dismount-', 'Reset-ComputerMachinePassword') {
        $script:SourceCode | Should -Not -Match ([regex]::Escape($_)) -Because 'deleting belongs to the dispatcher (P3-C1), not to a detector'
    }

    It 'shells out to nothing' {
        foreach ($forbidden in 'Start-Process', 'Invoke-Expression', 'Invoke-Command', '.exe', 'cmd /c') {
            $script:SourceCode | Should -Not -Match ([regex]::Escape($forbidden))
        }
    }

    It 'opens files for READ only, and never for write' {
        # The in-use probe was the one place this file opened a handle at all, and
        # chunk P3-C1 promoted it to Shared\Inventory.ps1 as
        # Test-OptimizerFileInUse. The POSITIVE half of this assertion --
        # Should -Match 'FileAccess]::Read' -- moved to
        # tests\SharedInventory.Tests.ps1 with it, and P3-C1a then deleted the
        # -Access argument that was keeping it matching here. The negatives stay:
        # they are statements about THIS file and they must keep holding whether
        # or not it opens anything.
        $script:SourceCode | Should -Not -Match 'FileAccess\]::Write'
        $script:SourceCode | Should -Not -Match 'FileAccess\]::ReadWrite'
        $script:SourceCode | Should -Not -Match 'FileMode\]::Create'
        $script:SourceCode | Should -Not -Match 'FileMode\]::Truncate'
        $script:SourceCode | Should -Not -Match 'FileMode\]::Append'
    }

    It 'never touches Win32_Product or WMI' {
        $script:SourceCode | Should -Not -Match 'Get-WmiObject'
        $script:SourceCode | Should -Not -Match 'Get-CimInstance'
        $script:SourceCode | Should -Not -Match 'Win32_Product'
    }

    It 'enumerates directories with the .NET call, never Get-ChildItem' {
        # REVIEW.md: Get-ChildItem returns zero items and raises no error on a
        # folder the current user cannot list, even with -ErrorAction Stop. A
        # silently empty junk location is indistinguishable from a clean one.
        $script:SourceCode | Should -Match '\[System\.IO\.Directory\]::GetFiles'
        $script:SourceCode | Should -Match '\[System\.IO\.Directory\]::GetDirectories'
        $script:SourceCode | Should -Not -Match 'Get-ChildItem'
    }

    It 'never recurses with SearchOption.AllDirectories' {
        # Measured during P2-C4 on the Windows Error Reporting archive
        # un-elevated: GetFiles(path, '*', AllDirectories) threw
        # UnauthorizedAccessException and returned NOTHING, while the explicit
        # per-directory walk returned the files it could see and counted the
        # folders it could not.
        $script:SourceCode | Should -Not -Match 'AllDirectories'
    }

    It 'hard-codes no absolute path at all' {
        # P2-C2 has the equivalent assertion. Every location resolves through an
        # environment variable, GetFolderPath or a drive root read from
        # DriveInfo -- never a literal. A drive letter anywhere in this file would
        # be one.
        # \b so the one registry path in the file ('HKCU:\Software\...', which is
        # a provider path and not a place on disk) is not read as a drive letter.
        $script:SourceCode | Should -Not -Match '\b[A-Za-z]:\\'
        foreach ($forbidden in 'AppData\Local\Temp', 'My Documents', 'Users\') {
            $script:SourceCode | Should -Not -Match ([regex]::Escape($forbidden))
        }
    }

    It 'resolves the protected folders from the shell, not from literals' {
        # The known-user-folder half moved to Shared\Inventory.ps1 as
        # Get-OptimizerKnownUserFolderPath (P3-C1), and its
        # Should -Match 'GetFolderPath' assertion moved to
        # tests\SharedInventory.Tests.ps1 with it (P3-C1a).
        #
        # SystemRoot stays here: the WinSxS protected-path entry did NOT move --
        # Get-JunkProtectedPath returns the shared list plus that one entry, and a
        # test below pins the difference at exactly one -- so this file still
        # resolves it, and still resolves it from the environment.
        $script:SourceCode | Should -Match "GetEnvironmentVariable\('SystemRoot'\)"
    }

    It 'does not reach for Test-Path or a bare Exists to judge a path' {
        # REVIEW.md, P2-C2: [System.IO.File]::Exists and Test-Path both answer
        # "not there" for a path the caller may not look at. Everything this
        # detector judges goes through the tri-state probe.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:SourcePath, [ref]$null, [ref]$null)
        foreach ($name in 'Resolve-JunkLocationPath', 'Get-JunkLocationInventory') {
            $function = $ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true)
            $function | Should -Not -BeNullOrEmpty
            $code = ($function.Extent.Text -split "#>", 2)[-1]
            $code | Should -Not -Match 'Test-Path'
            $code | Should -Not -Match 'System\.IO\.File\]::Exists'
        }
    }
}

Describe 'The Finding contract is unchanged' {

    It 'adds no Category, Confidence or RemovalMethod value' {
        $contract = Get-FindingContract
        $contract.Categories     | Should -Contain 'JunkFile'
        $contract.RemovalMethods | Should -Contain 'FileDelete'
        @($contract.Categories).Count     | Should -Be 5
        @($contract.Confidences).Count    | Should -Be 2
        @($contract.RemovalMethods).Count | Should -Be 7
    }

    It 'exports its public functions from both the .psm1 and the .psd1' {
        # A function missing from the manifest is invisible to callers with no
        # error anywhere -- REVIEW.md's standing check.
        $psm1 = [System.IO.File]::ReadAllText($script:ModulePath)
        $psd1 = [System.IO.File]::ReadAllText($script:ManifestPath)
        foreach ($name in 'Get-JunkLocationList', 'Get-JunkLocationInventory', 'Find-JunkFileLocation', 'Invoke-JunkFileScan') {
            $psm1 | Should -Match ([regex]::Escape("'$name'"))
            $psd1 | Should -Match ([regex]::Escape("'$name'"))
            Get-Command -Module Win11Optimizer.Engine -Name $name -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Get-JunkLocationList: the shipped list' {

    BeforeAll { $script:Entries = @(Get-JunkLocationList) }

    It 'loads the shipped list' {
        $script:Entries.Count | Should -BeGreaterThan 0
    }

    It 'ships the list as data, not code' {
        Test-Path -LiteralPath $script:ListPath -PathType Leaf | Should -BeTrue
        { ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($script:ListPath)) } | Should -Not -Throw
    }

    It 'gives every entry the full normalised shape' {
        $expected = @(
            'Id', 'DisplayName', 'Owner', 'Reason', 'Provenance', 'Resolver',
            'InventoryOnly', 'InventoryOnlyReason', 'IsForcedInventory', 'Path',
            'ProfileChildPath', 'Note'
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

    It 'gives every entry a provenance from the closed set' {
        foreach ($entry in $script:Entries) {
            @('measured', 'published') | Should -Contain $entry.Provenance
        }
    }

    It 'has at least one measured entry' {
        # REVIEW.md, added after P2-C2: a list whose coverage claim is entirely
        # untested is a hypothesis. This is the first list in the project that can
        # carry measured entries, because the evidence is on this disk.
        @($script:Entries | Where-Object { $_.Provenance -eq 'measured' }).Count | Should -BeGreaterThan 0
    }

    It 'names no known user folder, in any entry' {
        $userFolders = @(
            [Environment]::GetFolderPath('Desktop')
            [Environment]::GetFolderPath('MyDocuments')
            [Environment]::GetFolderPath('MyPictures')
            [Environment]::GetFolderPath('MyVideos')
            [Environment]::GetFolderPath('MyMusic')
            (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads')
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        foreach ($entry in $script:Entries) {
            foreach ($declared in @($entry.Path)) {
                $expanded = [System.Environment]::ExpandEnvironmentVariables($declared)
                foreach ($folder in $userFolders) {
                    $expanded.StartsWith($folder, [System.StringComparison]::OrdinalIgnoreCase) | Should -BeFalse -Because "$declared must not reach $folder"
                }
            }
        }
    }

    It 'names neither WinSxS nor the page or hibernation file' {
        $raw = [System.IO.File]::ReadAllText($script:ListPath)
        foreach ($forbidden in 'WinSxS', 'pagefile.sys', 'hiberfil.sys', 'swapfile.sys', 'Windows.old', 'System Volume Information') {
            $raw | Should -Not -Match ([regex]::Escape($forbidden))
        }
    }

    It 'flags Prefetch as inventory-only, and marks it as forced by code' {
        $prefetch = @($script:Entries | Where-Object { $_.Id -eq 'prefetch' })
        $prefetch.Count | Should -Be 1
        $prefetch[0].InventoryOnly       | Should -BeTrue
        $prefetch[0].IsForcedInventory   | Should -BeTrue
        $prefetch[0].InventoryOnlyReason | Should -Match 'unused-application'
    }

    It 'flags the Recycle Bin as inventory-only' {
        $bin = @($script:Entries | Where-Object { $_.Id -eq 'recycle-bin' })
        $bin.Count | Should -Be 1
        $bin[0].InventoryOnly | Should -BeTrue
    }
}

Describe 'Get-JunkLocationList: a load failure is loud' {

    It 'throws when the list file is missing' {
        { Get-JunkLocationList -Path (Join-Path $script:Scratch 'no-such-list.json') } |
            Should -Throw -ExpectedMessage '*not found*'
    }

    It 'throws when the list file is empty' {
        $path = New-TestJunkList -Content '   '
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage '*is empty*'
    }

    It 'throws when the list file is not JSON' {
        $path = New-TestJunkList -Content 'this is not json {'
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage '*not valid JSON*'
    }

    It 'throws when there is no entries array' {
        $path = New-TestJunkList -Content '{ "schemaVersion": 1 }'
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage "*no 'entries' array*"
    }

    It 'throws on an empty entries array rather than yielding zero locations' {
        # The signature failure mode: a junk detector that silently finds nothing
        # looks exactly like a clean disk.
        $path = New-TestJunkList -Content '{ "schemaVersion": 1, "entries": [] }'
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage '*contains no entries*'
    }

    It 'throws on an entry missing <_>' -ForEach @('id', 'displayName', 'reason', 'provenance') {
        $field = $_
        $entry = [ordered]@{
            id          = 'x'
            displayName = 'X'
            reason      = 'A reason long enough to satisfy the loader and to mean something to a person reading it.'
            provenance  = 'measured'
            paths       = @('%TEMP%')
        }
        $entry.Remove($field)
        $path = New-TestJunkList -Content (ConvertTo-Json -InputObject @{ entries = @([pscustomobject] $entry) } -Depth 5)
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage "*'$field'*"
    }

    It 'throws on a duplicate id' {
        $path = New-TestJunkList -Content @'
{
  "entries": [
    { "id": "dupe", "displayName": "A", "reason": "A reason long enough to satisfy the loader and mean something.", "provenance": "measured", "paths": [ "%TEMP%" ] },
    { "id": "dupe", "displayName": "B", "reason": "A reason long enough to satisfy the loader and mean something.", "provenance": "measured", "paths": [ "%TEMP%" ] }
  ]
}
'@
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage '*duplicate entry id*'
    }

    It 'throws on an unknown provenance' {
        $path = New-TestJunkList -Content @'
{ "entries": [ { "id": "x", "displayName": "X", "reason": "A reason long enough to satisfy the loader and mean something.", "provenance": "guessed", "paths": [ "%TEMP%" ] } ] }
'@
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage "*unknown 'provenance'*"
    }

    It 'throws on an unknown resolver' {
        $path = New-TestJunkList -Content @'
{ "entries": [ { "id": "x", "displayName": "X", "reason": "A reason long enough to satisfy the loader and mean something.", "provenance": "measured", "resolver": "wholeDisk" } ] }
'@
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage "*unknown 'resolver'*"
    }

    It 'throws when inventoryOnly is the string "true" rather than a boolean' {
        # Same rule and same reasoning as the other three lists: "true" is truthy
        # in PowerShell and would leave an entry looking enforced while the code
        # that reads it disagreed.
        $path = New-TestJunkList -Content @'
{ "entries": [ { "id": "x", "displayName": "X", "reason": "A reason long enough to satisfy the loader and mean something.", "provenance": "measured", "inventoryOnly": "true", "paths": [ "%TEMP%" ] } ] }
'@
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage '*JSON boolean*'
    }

    It 'throws on an entry with no paths and no resolver' {
        $path = New-TestJunkList -Content @'
{ "entries": [ { "id": "x", "displayName": "X", "reason": "A reason long enough to satisfy the loader and mean something.", "provenance": "measured" } ] }
'@
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage "*no 'paths' array*"
    }

    It 'throws on a path containing ..' {
        $path = New-TestJunkList -Content @'
{ "entries": [ { "id": "x", "displayName": "X", "reason": "A reason long enough to satisfy the loader and mean something.", "provenance": "measured", "paths": [ "%TEMP%\\..\\..\\Documents" ] } ] }
'@
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage "*contains '..'*"
    }

    It 'throws on an absolute profileChildPath' {
        $path = New-TestJunkList -Content @'
{ "entries": [ { "id": "x", "displayName": "X", "reason": "A reason long enough to satisfy the loader and mean something.", "provenance": "measured", "paths": [ "%LOCALAPPDATA%" ], "profileChildPath": [ "C:\\Windows" ] } ] }
'@
        { Get-JunkLocationList -Path $path } | Should -Throw -ExpectedMessage '*absolute path*'
    }
}

Describe 'The user folders are out of scope entirely' {

    # Acceptance criterion 3. Asserted by a test, not by inspection: a curated
    # entry that names one of these fails the WHOLE load, so it can never be
    # enumerated, sized or reported as inventory.

    It 'refuses to load a list naming <Name>' -ForEach @(
        @{ Name = 'Downloads';  Path = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads') }
        @{ Name = 'Documents';  Path = [Environment]::GetFolderPath('MyDocuments') }
        @{ Name = 'Desktop';    Path = [Environment]::GetFolderPath('Desktop') }
        @{ Name = 'Pictures';   Path = [Environment]::GetFolderPath('MyPictures') }
        @{ Name = 'Videos';     Path = [Environment]::GetFolderPath('MyVideos') }
        @{ Name = 'Music';      Path = [Environment]::GetFolderPath('MyMusic') }
    ) {
        $listPath = New-TestJunkListForPath -Path $Path
        { Get-JunkLocationList -Path $listPath } | Should -Throw -ExpectedMessage '*collides*'
    }

    It 'refuses a subfolder of Downloads as well as Downloads itself' {
        $nested = Join-Path (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads') 'installers\old'
        $listPath = New-TestJunkListForPath -Path $nested
        { Get-JunkLocationList -Path $listPath } | Should -Throw -ExpectedMessage '*collides*'
    }

    It 'refuses a path that CONTAINS a user folder, not only one inside it' {
        # The profile root contains Documents. A list entry naming it would
        # enumerate every user folder there is.
        $listPath = New-TestJunkListForPath -Path ([Environment]::GetFolderPath('UserProfile'))
        { Get-JunkLocationList -Path $listPath } | Should -Throw -ExpectedMessage '*collides*'
    }

    It 'refuses a drive root' {
        # With the trailing separator: 'C:' on its own is the current directory of
        # drive C:, not its root, and would not be testing what it looks like.
        $root = (Split-Path -Qualifier ([Environment]::GetFolderPath('UserProfile'))) + '\'
        $listPath = New-TestJunkListForPath -Path $root
        { Get-JunkLocationList -Path $listPath } | Should -Throw -ExpectedMessage '*collides*'
    }

    It 'refuses WinSxS and the Windows folder itself' {
        foreach ($candidate in (Join-Path $env:SystemRoot 'WinSxS'), $env:SystemRoot) {
            $listPath = New-TestJunkListForPath -Path $candidate
            { Get-JunkLocationList -Path $listPath } | Should -Throw -ExpectedMessage '*collides*'
        }
    }

    It 'still accepts a temp folder that lives inside the profile' {
        # The reason the containment rule is directional: everything a person owns
        # lives under the profile root, so "inside the profile" cannot be the test.
        $listPath = New-TestJunkListForPath -Path $env:TEMP
        { Get-JunkLocationList -Path $listPath } | Should -Not -Throw
    }

    It 'reports no location whose resolved path is inside a user folder' {
        $scan = $script:SharedScan
        $userFolders = @(
            [Environment]::GetFolderPath('Desktop')
            [Environment]::GetFolderPath('MyDocuments')
            [Environment]::GetFolderPath('MyPictures')
            [Environment]::GetFolderPath('MyVideos')
            [Environment]::GetFolderPath('MyMusic')
            (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads')
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        foreach ($location in @($scan.Locations)) {
            foreach ($resolved in @($location.ResolvedPath)) {
                foreach ($folder in $userFolders) {
                    $resolved.StartsWith($folder, [System.StringComparison]::OrdinalIgnoreCase) | Should -BeFalse -Because "$resolved must not be inside $folder"
                }
            }
        }
    }
}

Describe 'Prefetch is evidence another detector relies on' {

    It 'forces a prefetch entry to inventory-only even when the list says otherwise' {
        # Enforced in code, not by the list entry, so no future edit can flip it.
        # docs\STATE.md Q11 measured the cost: the folder losing 244 .pf files took
        # six applications' Used verdict with it.
        $listPath = New-TestJunkListForPath -Path (Join-Path $env:SystemRoot 'Prefetch') -Id 'prefetch-attempt'
        $entries = @(Get-JunkLocationList -Path $listPath)
        $entries.Count | Should -Be 1
        $entries[0].InventoryOnly     | Should -BeTrue
        $entries[0].IsForcedInventory | Should -BeTrue
    }

    It 'produces no Finding for an inventory-only location however much is in it' {
        $location = New-TestJunkLocation -InventoryOnly $true -EligibleFileCount 9999 -EligibleBytes 999999999
        @(Find-JunkFileLocation -Location @($location)).Count | Should -Be 0
    }
}

Describe 'Find-JunkFileLocation: one Finding per location' {

    It 'produces exactly one Finding for a location holding many files' {
        $location = New-TestJunkLocation -FileCount 4000 -EligibleFileCount 3500
        $findings = @(Find-JunkFileLocation -Location @($location))
        $findings.Count | Should -Be 1
    }

    It 'uses the curated location id as the Finding id, not a file path' {
        $location = New-TestJunkLocation -Id 'user-temp'
        $finding = @(Find-JunkFileLocation -Location @($location))[0]
        $finding.Id | Should -Be 'user-temp'
        $finding.Id | Should -Not -Match '\\'
    }

    It 'carries the file count and the total size in its evidence' {
        $location = New-TestJunkLocation -FileCount 1964 -TotalBytes 1729000000 -EligibleFileCount 1381 -EligibleBytes 782000000
        $finding = @(Find-JunkFileLocation -Location @($location))[0]
        ($finding.Evidence -join ' ') | Should -Match '1,381 files'
        ($finding.Evidence -join ' ') | Should -Match '1,964 files'
        ($finding.Evidence -join ' ') | Should -Match 'MB|GB'
    }

    It 'is Known confidence, requires consent, and reads "Review needed"' {
        # Acceptance criterion 2. No fast path, no exceptions for "obviously safe"
        # caches -- exactly as every Service Finding does it.
        $finding = @(Find-JunkFileLocation -Location @(New-TestJunkLocation))[0]
        $finding.Category        | Should -Be 'JunkFile'
        $finding.Confidence      | Should -Be 'Known'
        $finding.RequiresConsent | Should -BeTrue
        $finding.RequiresConsent | Should -BeOfType [bool]
        $finding.SafetyLabel     | Should -Be 'Review needed'
        $finding.RemovalMethod   | Should -Be 'FileDelete'
    }

    It 'returns only objects that satisfy the Finding contract' {
        foreach ($finding in @(Find-JunkFileLocation -Location @(New-TestJunkLocation))) {
            Test-Finding -InputObject $finding | Should -BeTrue
        }
    }

    It 'names every gate that held something back' {
        $location = New-TestJunkLocation -AgeHeldBackCount 589 -InUseCount 9 -UndeterminedCount 6 -ReparsePointCount 2 -DuplicatePathCount 4
        $evidence = (@(Find-JunkFileLocation -Location @($location))[0]).Evidence -join ' '
        $evidence | Should -Match '589'
        $evidence | Should -Match '9 open in another process'
        $evidence | Should -Match 'counts as in use'
        $evidence | Should -Match 'junction'
        $evidence | Should -Match 'already counted under another location'
    }

    It 'says the size is a FLOOR when part of the location could not be read' {
        $location = New-TestJunkLocation -IsSizeFloor $true -UnreadableDirectoryCount 150
        $finding = @(Find-JunkFileLocation -Location @($location))[0]
        ($finding.Evidence -join ' ') | Should -Match 'FLOOR'
        ($finding.Evidence -join ' ') | Should -Match '150'
        $finding.IsSizeFloor | Should -BeTrue
    }

    It 'adds the unverified-identifier line for a published location and not for a measured one' {
        $published = @(Find-JunkFileLocation -Location @(New-TestJunkLocation -Provenance 'published'))[0]
        ($published.Evidence -join ' ') | Should -Match 'published source'

        $measured = @(Find-JunkFileLocation -Location @(New-TestJunkLocation -Provenance 'measured'))[0]
        ($measured.Evidence -join ' ') | Should -Not -Match 'published source'
    }

    It 'never phrases the size as space that will be freed' {
        # docs\PLAN.md: the post-run summary is a receipt, not a benchmark, and it
        # is derived from what P3-C2 actually deleted -- not from what a detector
        # predicted.
        $evidence = (@(Find-JunkFileLocation -Location @(New-TestJunkLocation))[0]).Evidence -join ' '
        $evidence | Should -Not -Match 'free up'
        $evidence | Should -Not -Match 'reclaim '
        $evidence | Should -Not -Match 'will save'
        $evidence | Should -Match 'not a promise of space reclaimed'
    }

    It 'produces no Finding for a location with nothing eligible' {
        @(Find-JunkFileLocation -Location @(New-TestJunkLocation -EligibleFileCount 0 -EligibleBytes 0)).Count | Should -Be 0
    }

    It 'produces no Finding for a location that was never assessed' {
        # A location measured with the in-use probe skipped has no verdict on its
        # files, so it cannot produce one on the strength of the age gate alone.
        @(Find-JunkFileLocation -Location @(New-TestJunkLocation -IsAssessed $false)).Count | Should -Be 0
    }

    It 'performs no I/O of its own' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:SourcePath, [ref]$null, [ref]$null)
        $function = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Find-JunkFileLocation'
        }, $true)
        $code = ($function.Extent.Text -split "#>", 2)[-1]
        foreach ($forbidden in 'System.IO.Directory', 'System.IO.File', 'Get-Item', 'Test-Path') {
            $code | Should -Not -Match ([regex]::Escape($forbidden)) -Because 'Find-JunkFileLocation is the pure half of the detector'
        }
    }
}

Describe 'The age gate' {

    BeforeAll {
        $script:AgeTree = New-TestJunkTree -OldFileCount 4 -NewFileCount 3
        $script:AgeList = @(Get-JunkLocationList -Path (New-TestJunkListForPath -Path $script:AgeTree))
    }

    It 'holds back every file modified inside the window' {
        $inventory = Get-JunkLocationInventory -LocationEntry $script:AgeList -MinimumAgeDays 7
        $location = @($inventory.Locations)[0]
        $location.FileCount         | Should -Be 7
        $location.AgeHeldBackCount  | Should -Be 3
        $location.EligibleFileCount | Should -Be 4
    }

    It 'never puts a file inside the window in a Finding file list' {
        $inventory = Get-JunkLocationInventory -LocationEntry $script:AgeList -MinimumAgeDays 7
        $finding = @(Find-JunkFileLocation -Location $inventory.Locations)[0]
        foreach ($file in @($finding.EligibleFile)) {
            [System.IO.Path]::GetFileName($file.Path) | Should -Match '^old-'
        }
        @($finding.EligibleFile).Count | Should -Be 4
    }

    It 'is a named parameter with a stated default, not a literal in a comparison' {
        (Get-Command Invoke-JunkFileScan).Parameters.Keys | Should -Contain 'MinimumAgeDays'
        (Get-Command Get-JunkLocationInventory).Parameters.Keys | Should -Contain 'MinimumAgeDays'
        InModuleScope Win11Optimizer.Engine {
            $script:JunkDefaultMinimumAgeDays | Should -Be 7
        }
    }

    It 'holds everything back at a window wider than the tree' {
        $inventory = Get-JunkLocationInventory -LocationEntry $script:AgeList -MinimumAgeDays 3650
        @($inventory.Locations)[0].EligibleFileCount | Should -Be 0
        @($inventory.Locations)[0].AgeHeldBackCount  | Should -Be 7
    }

    It 'uses the newer of last-write and creation time as the anchor' {
        # A file copied into place with its write time preserved is new on disk
        # and old by its timestamp. The newer of the two is the safe reading.
        $tree = Join-Path $script:Scratch ("anchor-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $tree -ItemType Directory -Force
        $file = Join-Path $tree 'backdated.tmp'
        [System.IO.File]::WriteAllText($file, 'x')
        [System.IO.File]::SetLastWriteTimeUtc($file, [datetime]::UtcNow.AddDays(-400))

        $entries = @(Get-JunkLocationList -Path (New-TestJunkListForPath -Path $tree))
        $location = @((Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7).Locations)[0]
        $location.FileCount         | Should -Be 1
        $location.AgeHeldBackCount  | Should -Be 1
        $location.EligibleFileCount | Should -Be 0
    }
}

Describe 'The in-use gate' {

    It 'reports a file nobody has open as free' {
        $tree = New-TestJunkTree -OldFileCount 1 -NewFileCount 0
        $file = @([System.IO.Directory]::GetFiles($tree))[0]
        InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $file } {
            param($Path)
            Test-JunkFileInUse -Path $Path | Should -Be 'Free'
        }
    }

    It 'reports a file another handle holds as in use' {
        $tree = New-TestJunkTree -OldFileCount 1 -NewFileCount 0
        $file = @([System.IO.Directory]::GetFiles($tree))[0]
        $stream = [System.IO.File]::Open($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $file } {
                param($Path)
                Test-JunkFileInUse -Path $Path | Should -Be 'InUse'
            }
        }
        finally { $stream.Dispose() }
    }

    It 'reports "cannot tell" rather than free when the probe cannot answer' {
        $tree = New-TestJunkTree -OldFileCount 0 -NewFileCount 0
        InModuleScope Win11Optimizer.Engine -Parameters @{ Path = $tree } {
            param($Path)
            # A directory cannot be opened as a file: the probe cannot answer, and
            # "cannot answer" must never read as "free".
            Test-JunkFileInUse -Path $Path | Should -Be 'Undetermined'
            Test-JunkFileInUse -Path ''    | Should -Be 'Undetermined'
        }
    }

    It 'keeps a held-open file out of the eligible set end to end' {
        $tree = New-TestJunkTree -OldFileCount 3 -NewFileCount 0
        $held = @([System.IO.Directory]::GetFiles($tree))[0]
        $stream = [System.IO.File]::Open($held, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $entries = @(Get-JunkLocationList -Path (New-TestJunkListForPath -Path $tree))
            $location = @((Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7).Locations)[0]
            $location.FileCount         | Should -Be 3
            $location.InUseCount        | Should -Be 1
            $location.EligibleFileCount | Should -Be 2
            @($location.EligibleFile | Where-Object { $_.Path -eq $held }).Count | Should -Be 0
        }
        finally { $stream.Dispose() }
    }

    It 'treats "cannot tell" as in use, not as eligible' {
        $tree = New-TestJunkTree -OldFileCount 3 -NewFileCount 0
        $entries = @(Get-JunkLocationList -Path (New-TestJunkListForPath -Path $tree))

        Mock -ModuleName Win11Optimizer.Engine -CommandName Test-JunkFileInUse -MockWith { 'Undetermined' }

        $location = @((Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7).Locations)[0]
        $location.UndeterminedCount | Should -Be 3
        $location.EligibleFileCount | Should -Be 0
        @(Find-JunkFileLocation -Location @($location)).Count | Should -Be 0
    }

    It 'reports the location Skipped, and flags it unassessed, when the probe is skipped' {
        $tree = New-TestJunkTree -OldFileCount 2 -NewFileCount 0
        $entries = @(Get-JunkLocationList -Path (New-TestJunkListForPath -Path $tree))
        $inventory = Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7 -SkipInUseProbe
        $location = @($inventory.Locations)[0]
        $location.Status     | Should -Be 'Skipped'
        $location.IsAssessed | Should -BeFalse
        $location.FileCount  | Should -Be 2
        @(Find-JunkFileLocation -Location @($location)).Count | Should -Be 0
    }
}

Describe 'Reparse points are detected, never traversed' {

    BeforeAll {
        $script:RpRoot = Join-Path $script:Scratch ("rp-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $script:RpRoot -ItemType Directory -Force

        # The target sits OUTSIDE the scoped tree, exactly as a junction inside
        # %TEMP% could point at a real user folder.
        $script:RpTarget = Join-Path $script:Scratch ("rp-target-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $script:RpTarget -ItemType Directory -Force
        $old = [datetime]::UtcNow.AddDays(-90)
        foreach ($name in 'secret-1.txt', 'secret-2.txt') {
            $file = Join-Path $script:RpTarget $name
            [System.IO.File]::WriteAllText($file, ('y' * 5000))
            [System.IO.File]::SetCreationTimeUtc($file, $old)
            [System.IO.File]::SetLastWriteTimeUtc($file, $old)
        }

        $inside = Join-Path $script:RpRoot 'plain.txt'
        [System.IO.File]::WriteAllText($inside, 'z')
        [System.IO.File]::SetCreationTimeUtc($inside, $old)
        [System.IO.File]::SetLastWriteTimeUtc($inside, $old)

        $script:RpJunction = Join-Path $script:RpRoot 'link'
        $script:RpCreated = $true
        try { $null = New-Item -Path $script:RpJunction -ItemType Junction -Value $script:RpTarget -ErrorAction Stop }
        catch { $script:RpCreated = $false }

        $script:RpLocation = $null
        if ($script:RpCreated) {
            $entries = @(Get-JunkLocationList -Path (New-TestJunkListForPath -Path $script:RpRoot))
            $script:RpLocation = @((Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7).Locations)[0]
        }
    }

    It 'counts the junction' {
        if (-not $script:RpCreated) { Set-ItResult -Skipped -Because 'this filesystem would not create a junction' }
        $script:RpLocation.ReparsePointCount | Should -Be 1
        @($script:RpLocation.ReparsePointSample) | Should -Contain $script:RpJunction
    }

    It 'excludes everything behind it from the file count and the size' {
        if (-not $script:RpCreated) { Set-ItResult -Skipped -Because 'this filesystem would not create a junction' }
        # One file in the scoped tree; the two 5,000-byte files behind the
        # junction are neither counted nor sized.
        $script:RpLocation.FileCount  | Should -Be 1
        $script:RpLocation.TotalBytes | Should -BeLessThan 5000
    }

    It 'excludes everything behind it from the eligible file list' {
        if (-not $script:RpCreated) { Set-ItResult -Skipped -Because 'this filesystem would not create a junction' }
        $paths = @($script:RpLocation.EligibleFile | ForEach-Object { $_.Path })
        foreach ($path in $paths) {
            $path | Should -Not -Match 'secret'
            $path | Should -Not -Match ([regex]::Escape('rp-target'))
        }
    }

    It 'says so in the evidence' {
        if (-not $script:RpCreated) { Set-ItResult -Skipped -Because 'this filesystem would not create a junction' }
        $finding = @(Find-JunkFileLocation -Location @($script:RpLocation))[0]
        ($finding.Evidence -join ' ') | Should -Match 'junction'
    }
}

Describe 'An unreadable subtree makes the size a floor' {

    BeforeAll {
        $script:FloorRoot = Join-Path $script:Scratch ("floor-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $script:FloorRoot -ItemType Directory -Force

        $old = [datetime]::UtcNow.AddDays(-90)
        $visible = Join-Path $script:FloorRoot 'visible.txt'
        [System.IO.File]::WriteAllText($visible, 'v')
        [System.IO.File]::SetCreationTimeUtc($visible, $old)
        [System.IO.File]::SetLastWriteTimeUtc($visible, $old)

        $script:FloorDenied = Join-Path $script:FloorRoot 'denied'
        $null = New-Item -Path $script:FloorDenied -ItemType Directory -Force
        [System.IO.File]::WriteAllText((Join-Path $script:FloorDenied 'hidden.txt'), ('h' * 4096))

        $script:FloorReady = $false
        try {
            $acl = Get-Acl -LiteralPath $script:FloorDenied -ErrorAction Stop
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                ([System.Security.Principal.WindowsIdentity]::GetCurrent().User),
                'ListDirectory', 'ContainerInherit,ObjectInherit', 'None', 'Deny')
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $script:FloorDenied -AclObject $acl -ErrorAction Stop
            try { $null = [System.IO.Directory]::GetFiles($script:FloorDenied) }
            catch { $script:FloorReady = $true }
        }
        catch { $script:FloorReady = $false }

        $script:FloorLocation = $null
        if ($script:FloorReady) {
            $entries = @(Get-JunkLocationList -Path (New-TestJunkListForPath -Path $script:FloorRoot))
            $script:FloorLocation = @((Get-JunkLocationInventory -LocationEntry $entries -MinimumAgeDays 7).Locations)[0]
        }
    }

    It 'counts the folder it could not list and marks the size a floor' {
        if (-not $script:FloorReady) { Set-ItResult -Skipped -Because 'a deny ACE did not make the folder unreadable here' }
        $script:FloorLocation.UnreadableDirectoryCount | Should -Be 1
        $script:FloorLocation.IsSizeFloor              | Should -BeTrue
    }

    It 'still reports what it could read rather than nothing' {
        if (-not $script:FloorReady) { Set-ItResult -Skipped -Because 'a deny ACE did not make the folder unreadable here' }
        # The failure this guards: GetFiles with AllDirectories throws on the
        # first denied subtree and returns NOTHING.
        $script:FloorLocation.FileCount | Should -Be 1
    }

    It 'reports the location Skipped, never Refused' {
        if (-not $script:FloorReady) { Set-ItResult -Skipped -Because 'a deny ACE did not make the folder unreadable here' }
        $script:FloorLocation.Status       | Should -Be 'Skipped'
        $script:FloorLocation.Status       | Should -Not -Be 'Refused'
        $script:FloorLocation.StatusReason | Should -Match 'FLOOR'
        $script:FloorLocation.StatusReason | Should -Match 'administrator'
    }
}

Describe 'Elevation: an unreadable location is Skipped, never Refused' {

    # Acceptance criterion 8, and the equivalent of the assertion in
    # tests\OemBloatware.Tests.ps1. 'Refused' means "never used, on any machine,
    # at any privilege level"; a location that needs administrator rights could
    # have gone the other way on the very next run, so borrowing that status
    # would let a scan that saw less than the truth call itself complete.

    BeforeAll { $script:Scan = $script:SharedScan }

    It 'uses no Refused source at all' {
        @($script:Scan.RefusedSourceName).Count | Should -Be 0
        @($script:Scan.Sources | Where-Object { $_.Status -eq 'Refused' }).Count | Should -Be 0
    }

    It 'gives every non-succeeded source a reason naming the location' {
        foreach ($source in @($script:Scan.Sources | Where-Object { $_.Status -ne 'Succeeded' })) {
            $source.Reason | Should -Not -BeNullOrEmpty
            $source.Reason | Should -Match ([regex]::Escape($source.Name))
        }
    }

    It 'reports itself incomplete when any location could not be fully read' {
        $unfinished = @($script:Scan.Sources | Where-Object { @('Skipped', 'Failed') -contains $_.Status })
        if ($unfinished.Count -gt 0) {
            $script:Scan.IsComplete | Should -BeFalse
            $script:Scan.SummaryText | Should -Match 'PARTIAL'
        }
        else {
            $script:Scan.IsComplete | Should -BeTrue
        }
    }

    It 'names elevation in the reason for a location that needs it' {
        $needsAdmin = @($script:Scan.Sources | Where-Object { $_.Status -eq 'Skipped' -and $_.Reason -match 'administrator' })
        if (-not (Test-IsElevated)) {
            $needsAdmin.Count | Should -BeGreaterThan 0 -Because 'this machine hides %SystemRoot%\Temp and Prefetch from a normal user'
        }
    }
}

Describe 'Invoke-JunkFileScan: the shape of the result' {

    BeforeAll { $script:Scan = $script:SharedScan }

    It 'reports one source per curated location' {
        $entries = @(Get-JunkLocationList)
        @($script:Scan.Sources).Count   | Should -Be $entries.Count
        @($script:Scan.Locations).Count | Should -Be $entries.Count
        $script:Scan.InventoryCount     | Should -Be $entries.Count
    }

    It 'reports every location, including the ones that produced no Finding' {
        # "Recycle Bin: 2.3 MB, not flagged" is inventory the user wants; a
        # silently absent Recycle Bin is the failure mode this project is built
        # against.
        foreach ($id in 'recycle-bin', 'prefetch', 'user-temp', 'windows-temp') {
            @($script:Scan.Locations | Where-Object { $_.Id -eq $id }).Count | Should -Be 1
        }
    }

    It 'sizes the Recycle Bin and never flags it' {
        $bin = @($script:Scan.Locations | Where-Object { $_.Id -eq 'recycle-bin' })[0]
        $bin.InventoryOnly | Should -BeTrue
        $bin.TotalBytes    | Should -BeGreaterOrEqual 0
        @($script:Scan.Findings | Where-Object { $_.Id -eq 'recycle-bin' }).Count | Should -Be 0
    }

    It 'makes the enumerated file list reachable from every Finding' {
        foreach ($finding in @($script:Scan.Findings)) {
            $finding.PSObject.Properties.Name | Should -Contain 'EligibleFile'
            @($finding.EligibleFile).Count    | Should -Be $finding.EligibleFileCount
            foreach ($file in @($finding.EligibleFile)) {
                $file.Path      | Should -Not -BeNullOrEmpty
                $file.SizeBytes | Should -BeGreaterOrEqual 0
            }
        }
    }

    It 'publishes the age window it used' {
        $script:Scan.MinimumAgeDays | Should -Be 7
        $script:Scan.CutoffUtc      | Should -BeOfType [datetime]
    }

    It 'publishes the totals a caller would otherwise re-derive' {
        foreach ($name in 'TotalFileCount', 'TotalBytesSeen', 'TotalEligibleFiles', 'TotalEligibleBytes', 'SizeIsFloor', 'ReparsePointCount', 'InUseCount', 'InventoryOnlyCount', 'AbsentLocationCount', 'LocationListPath', 'LocationListCount') {
            $script:Scan.PSObject.Properties.Name | Should -Contain $name
        }
    }

    It 'returns only Findings that satisfy the contract, all requiring consent' {
        foreach ($finding in @($script:Scan.Findings)) {
            Test-Finding -InputObject $finding | Should -BeTrue
            $finding.Category        | Should -Be 'JunkFile'
            $finding.RequiresConsent | Should -BeTrue
            $finding.SafetyLabel     | Should -Be 'Review needed'
        }
    }

    It 'produces at most one Finding per location id' {
        $ids = @($script:Scan.Findings | ForEach-Object { $_.Id })
        @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'counts no file twice across two overlapping locations' {
        $paths = New-Object System.Collections.Generic.HashSet[string]
        foreach ($location in @($script:Scan.Locations)) {
            foreach ($file in @($location.EligibleFile)) {
                $paths.Add($file.Path.ToLowerInvariant()) | Should -BeTrue -Because "$($file.Path) appears under more than one location"
            }
        }
    }

    It 'writes the scan to the run log' {
        $log = @(Get-OptimizerLog -Path (Get-OptimizerLogPath))
        @($log | Where-Object { $_.Event -eq 'JunkScanCompleted' }).Count | Should -BeGreaterThan 0
    }

    It 'throws rather than returning nothing when the list will not load' {
        { Invoke-JunkFileScan -LocationListPath (Join-Path $script:Scratch 'missing.json') } | Should -Throw
    }
}

Describe 'Test-OptimizerPathPresent: the promoted tri-state probe' {

    BeforeAll {
        $script:ProbeDir = Join-Path $script:Scratch 'probe'
        $null = New-Item -Path $script:ProbeDir -ItemType Directory -Force
        $script:ProbeFile = Join-Path $script:ProbeDir 'here.txt'
        [System.IO.File]::WriteAllText($script:ProbeFile, 'x')
    }

    It 'answers about a directory as well as a file' {
        $dir = $script:ProbeDir
        $file = $script:ProbeFile
        InModuleScope Win11Optimizer.Engine -Parameters @{ Dir = $dir; File = $file } {
            param($Dir, $File)
            Test-OptimizerPathPresent -Path $Dir  -PathType Directory | Should -BeTrue
            Test-OptimizerPathPresent -Path $File -PathType File      | Should -BeTrue
            Test-OptimizerPathPresent -Path $File -PathType Any       | Should -BeTrue

            # A directory is not a file, and the answer is a PROVED absence
            # because the parent listed successfully.
            $asFile = Test-OptimizerPathPresent -Path $Dir -PathType File
            $asFile | Should -BeOfType [bool]
            $asFile | Should -BeFalse
        }
    }

    It 'proves absence only when the parent could be listed' {
        $missing = Join-Path $script:ProbeDir 'not-here'
        InModuleScope Win11Optimizer.Engine -Parameters @{ Missing = $missing } {
            param($Missing)
            Test-OptimizerPathPresent -Path $Missing -PathType Directory | Should -BeFalse
        }
    }

    It 'returns null, not false, for <_>' -ForEach @('', '   ', 'relative\path') {
        $value = $_
        InModuleScope Win11Optimizer.Engine -Parameters @{ Value = $value } {
            param($Value)
            $null -eq (Test-OptimizerPathPresent -Path $Value -PathType Directory) | Should -BeTrue
        }
    }

    It 'still backs Test-StartupTargetPresent, which is now a delegation' {
        $file = $script:ProbeFile
        InModuleScope Win11Optimizer.Engine -Parameters @{ File = $file } {
            param($File)
            Test-StartupTargetPresent -Path $File | Should -BeTrue
        }
    }
}

Describe 'A location that is simply absent is not an incompleteness' {

    It 'reports Succeeded with a proved absence, so a missing browser cannot make every scan PARTIAL' {
        # The PARTIAL-forever trap from docs\STATE.md, in this chunk's clothing:
        # a machine without Firefox must not warn that its scan was incomplete.
        $absent = Join-Path $script:Scratch ("absent-" + [guid]::NewGuid().ToString('N'))
        $entries = @(Get-JunkLocationList -Path (New-TestJunkListForPath -Path $absent))
        $inventory = Get-JunkLocationInventory -LocationEntry $entries

        $location = @($inventory.Locations)[0]
        $location.Status | Should -Be 'Succeeded'
        $location.Exists | Should -BeFalse
        $location.Detail | Should -Match 'does not exist'

        @($inventory.Sources)[0].Status | Should -Be 'Succeeded'
        @($inventory.Sources)[0].Reason | Should -BeNullOrEmpty
    }
}
