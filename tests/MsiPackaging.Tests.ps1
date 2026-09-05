#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for chunk P5-C2 -- packaging: Q21 (where the action ledger lives and
    who may write it), the WiX installer source, and App\Bootstrap.ps1. Extended
    in P5-C4 for the publisher, the About link, the icon, the two documents that
    now ship, and the installer UI.

    NOTHING IN THIS FILE INSTALLS ANYTHING. No .msi is run, nothing is written to
    the real %ProgramData%, and no ACL on this machine is changed. The three ways
    the ledger folder is exercised are, in order of how much they prove:

      1. A REAL folder created with New-Item under a redirected %ProgramData%.
         Its ACL is whatever it inherits, which is the exact mistake this check
         exists to catch -- "somebody made the folder by hand" -- and catching it
         needs no mocking and no privilege.
      2. A CONSTRUCTED DirectorySecurity handed straight to the ACL reader. This
         is how the shapes that cannot be created without administrator rights
         (a correct ACL, a Deny entry, an inherit-only CREATOR OWNER grant) are
         tested, and it is all in memory.
      3. Get-Acl MOCKED to throw, for the unreadable case.

    Locking a real temp folder down to Administrators-only and then unlocking it
    again needs privileges an un-elevated test run does not have, so this file
    deliberately never does that. What it loses is the claim "Get-Acl returns
    what we think it returns", and Get-Acl's return shape is Windows' claim, not
    this project's.

    TWO LEVELS, AND THE SECOND ONE IS CONDITIONAL. Most of what is asserted here
    is read out of packaging\win11-optimizer.wxs, which is always present. The
    last Describe instead reads the BUILT PACKAGE'S OWN TABLES -- the .msi says
    what it contains, rather than this file inferring it from the source -- and
    it is the only place that can prove the source produces the rows it means to.

    It runs when packaging\dist\ holds a package, which is whenever somebody has
    run packaging\Build-Msi.ps1. That folder is gitignored, so on a fresh clone
    the block generates NO tests rather than skipped ones, and every claim it
    makes is also made against the .wxs above so nothing goes unenforced. A
    package OLDER than the .wxs is a failure, not a pass: the message says to
    rebuild.

    The tables are read through WindowsInstaller.Installer, the COM automation
    interface built into Windows, and not through WiX's
    Microsoft.Deployment.WindowsInstaller. Same tables, and this needs nothing
    installed -- a suite that can only run where the WiX toolset is unpacked is a
    suite that does not run.

    Run:  .\tests\Invoke-Tests.ps1        (and -On51, which is not optional)
#>

# Discovery-time, because -ForEach on the last Describe is read then. BeforeAll
# works this out again for the run phase; the two must agree, so both go through
# the same one-liner.
$MsiUnderTest = @(
    Get-ChildItem -Path (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'packaging\dist') `
                  -Filter 'win11-optimizer-*.msi' -File -ErrorAction SilentlyContinue |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -First 1 |
        ForEach-Object { @{ MsiPath = $_.FullName } }
)

BeforeAll {
    $script:RepoRoot      = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot    = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath  = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath    = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:LedgerSource  = Join-Path $script:EngineRoot 'Removal\ActionLog.ps1'
    $script:BootstrapPath = Join-Path $script:EngineRoot 'App\Bootstrap.ps1'
    $script:EntryPath     = Join-Path $script:EngineRoot 'App\Entry.ps1'
    $script:AppFolder     = Join-Path $script:EngineRoot 'App'
    $script:PackagingRoot = Join-Path $script:RepoRoot 'packaging'
    $script:WxsPath       = Join-Path $script:PackagingRoot 'win11-optimizer.wxs'
    $script:BuildPath     = Join-Path $script:PackagingRoot 'Build-Msi.ps1'
    $script:PackagingDoc  = Join-Path $script:PackagingRoot 'README.md'
    $script:IcoPath       = Join-Path $script:PackagingRoot 'win11-optimizer.ico'

    # The five that used to be installed to C:\Program Files\win11-optimizer\docs\.
    # STATE.md is the one that matters: 91 KB of measured detail about the machine
    # this project was developed on, copied onto every machine that installed the
    # .msi. The other four are the chunk board and the research notes.
    $script:InternalDocument = @('CHECKLIST.md', 'PLAN.md', 'RESEARCH.md', 'REVIEW.md', 'STATE.md')

    # A log root of our own. The real ledger is the one file in this project that
    # is never rotated, and nothing in this suite may go near it.
    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-msi-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-msi-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    $script:NewExport = @('Get-OptimizerActionLogRoot', 'Test-OptimizerLedgerFolder', 'Assert-OptimizerLedgerFolder')

    $script:AdministratorSid = 'S-1-5-32-544'
    $script:UserSid          = 'S-1-5-32-545'
    $script:SystemSid        = 'S-1-5-18'
    $script:CreatorOwnerSid  = 'S-1-3-0'
    $script:EveryoneSid      = 'S-1-1-0'

    # ---- the .wxs, parsed once ---------------------------------------------
    $script:Wxs = $null
    $script:WxsParseError = ''
    try { $script:Wxs = [xml] ([System.IO.File]::ReadAllText($script:WxsPath)) }
    catch { $script:WxsParseError = $_.Exception.Message }

    function Select-WxsNode {
        param([Parameter(Mandatory)] [string] $Name)
        if ($null -eq $script:Wxs) { return @() }
        @($script:Wxs.SelectNodes("//*[local-name()='$Name']"))
    }

    # A File's Source, or an Icon's SourceFile, with the preprocessor variable
    # resolved, as a full path.
    function Resolve-WxsSource {
        param([Parameter(Mandatory)] [string] $Source)
        $expanded = $Source.Replace('$(var.SourceRoot)', $script:RepoRoot)
        try { [System.IO.Path]::GetFullPath($expanded) } catch { $expanded }
    }

    # Every file the .wxs names, whether it is installed or merely carried: File
    # elements plus the Icon element, whose attribute is SourceFile and not
    # Source. The icon is a stream in the .msi rather than an installed file, so
    # a check that only walks File nodes would never notice it going missing.
    function Get-WxsSourceFile {
        @(
            @(Select-WxsNode -Name 'File') | ForEach-Object { Resolve-WxsSource -Source $_.Source }
            @(Select-WxsNode -Name 'Icon') | ForEach-Object { Resolve-WxsSource -Source $_.SourceFile }
        )
    }

    # The Property elements the .wxs sets, as a hashtable. Nothing sets the same
    # property twice -- light rejects that as a duplicate symbol -- so a straight
    # map is the right shape.
    function Get-WxsProperty {
        $map = @{}
        foreach ($node in (Select-WxsNode -Name 'Property')) { $map[[string] $node.Id] = [string] $node.Value }
        $map
    }

    # ---- reading a built .msi ------------------------------------------------
    #
    # WindowsInstaller.Installer is the COM automation interface Windows itself
    # ships; nothing has to be installed for this to work, on 5.1 or on 7. The
    # InvokeMember dance is not decoration: StringData is a PARAMETERISED
    # property, and neither shell can bind $record.StringData(1) directly.
    function Get-MsiRow {
        param(
            [Parameter(Mandatory)] [string] $Path,
            [Parameter(Mandatory)] [string] $Query
        )

        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.GetType().InvokeMember(
            'OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
        $view = $database.GetType().InvokeMember(
            'OpenView', 'InvokeMethod', $null, $database, @($Query))
        $null = $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)

        $row = New-Object System.Collections.Generic.List[object]
        while ($true) {
            $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if ($null -eq $record) { break }
            $fieldCount = $record.GetType().InvokeMember('FieldCount', 'GetProperty', $null, $record, $null)
            $cell = @()
            for ($index = 1; $index -le $fieldCount; $index++) {
                $cell += [string] $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @($index))
            }
            $row.Add($cell)
        }
        $null = $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)

        # ONE PIPELINE ITEM PER ROW, and the unary comma is what keeps it that
        # way: without it PowerShell unrolls each row into its own cells and the
        # caller gets a flat list of strings with no row boundaries in it.
        foreach ($one in $row) { , $one }
    }

    # One column, flattened, because most of these questions have one-word answers.
    function Get-MsiValue {
        param(
            [Parameter(Mandatory)] [string] $Path,
            [Parameter(Mandatory)] [string] $Query
        )
        @(Get-MsiRow -Path $Path -Query $Query | ForEach-Object { $_[0] })
    }

    # The names of the tables the package actually has. An ABSENT table is the
    # interesting assertion here -- no RemoveFile and no RemoveFolder is the
    # mechanical form of "uninstall leaves %ProgramData%\win11-optimizer alone".
    function Get-MsiTable {
        param([Parameter(Mandatory)] [string] $Path)
        Get-MsiValue -Path $Path -Query 'SELECT `Name` FROM `_Tables`'
    }

    # The directory an installed file ends up in, walked up to TARGETDIR, as a
    # relative path. The File table names a component, the Component table names
    # a directory, and the Directory table is a linked list -- so "which files
    # land in docs\" takes all three.
    function Get-MsiFileFolder {
        param([Parameter(Mandatory)] [string] $Path)

        # DefaultDir is "target:source", and either half can itself be
        # "short|long" -- light generates a short name for anything Windows
        # Installer would consider a long one. The target's long name is the
        # folder that appears on disk. "." means "no folder of its own", which is
        # what the standard directories (ProgramFiles64Folder and friends) say.
        $parent = @{}
        $name   = @{}
        foreach ($directory in (Get-MsiRow -Path $Path -Query 'SELECT `Directory`,`Directory_Parent`,`DefaultDir` FROM `Directory`')) {
            $parent[$directory[0]] = $directory[1]
            $target = ($directory[2] -split ':')[0]
            $name[$directory[0]]   = ($target -split '\|')[-1]
        }

        $componentFolder = @{}
        foreach ($component in (Get-MsiRow -Path $Path -Query 'SELECT `Component`,`Directory_` FROM `Component`')) {
            $componentFolder[$component[0]] = $component[1]
        }

        $result = @{}
        foreach ($file in (Get-MsiRow -Path $Path -Query 'SELECT `File`,`FileName`,`Component_` FROM `File`')) {
            $segment = New-Object System.Collections.Generic.List[string]
            $walk = $componentFolder[$file[2]]
            while ($walk -and $walk -ne 'TARGETDIR') {
                if ($name[$walk] -ne '.') { $segment.Insert(0, $name[$walk]) }
                $walk = $parent[$walk]
            }
            # FileName is "short|long" when a short name was generated for it.
            $result[$file[0]] = @{
                Folder = ($segment -join '\')
                Name   = ($file[1] -split '\|')[-1]
            }
        }
        $result
    }

    # ---- ACL fixtures, built in memory --------------------------------------
    #
    # Nothing here touches the file system. Test-OptimizerLedgerAcl reads exactly
    # one property -- .Access -- so a DirectorySecurity with rules added to it is
    # the same input Get-Acl would hand it.
    function New-TestAcl {
        param([Parameter()] [AllowEmptyCollection()] [psobject[]] $Rule = @())

        $security = New-Object System.Security.AccessControl.DirectorySecurity
        foreach ($one in @($Rule)) {
            $inheritance = [System.Security.AccessControl.InheritanceFlags] 'ContainerInherit, ObjectInherit'
            if ($one.PSObject.Properties.Name -contains 'Inheritance' -and $one.Inheritance) {
                $inheritance = [System.Security.AccessControl.InheritanceFlags] $one.Inheritance
            }
            $propagation = [System.Security.AccessControl.PropagationFlags]::None
            if ($one.PSObject.Properties.Name -contains 'Propagation' -and $one.Propagation) {
                $propagation = [System.Security.AccessControl.PropagationFlags] $one.Propagation
            }
            $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                (New-Object System.Security.Principal.SecurityIdentifier($one.Sid)),
                ([System.Security.AccessControl.FileSystemRights] $one.Rights),
                $inheritance,
                $propagation,
                ([System.Security.AccessControl.AccessControlType] $one.Type))))
        }
        $security
    }

    function New-CorrectAcl {
        New-TestAcl -Rule @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'ReadAndExecute'; Type = 'Allow' }
        )
    }

    # What %ProgramData%'s own entries produce on a folder that merely inherits
    # them. This is the shape the whole check exists to refuse.
    function New-InheritedProgramDataAcl {
        New-TestAcl -Rule @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'ReadAndExecute'; Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'CreateDirectories'; Type = 'Allow'; Inheritance = 'ContainerInherit' }
            [pscustomobject]@{ Sid = $script:CreatorOwnerSid;  Rights = 'FullControl';    Type = 'Allow'; Propagation = 'InheritOnly' }
        )
    }

    function Test-AclProblem {
        param([Parameter(Mandatory)] $Acl)
        InModuleScope Win11Optimizer.Engine -Parameters @{ Acl = $Acl } {
            param($Acl)
            [string[]] @(Test-OptimizerLedgerAcl -Acl $Acl)
        }
    }

    # ---- a redirected %ProgramData% ----------------------------------------
    #
    # Get-OptimizerProgramDataRoot reads the environment variable first, so a
    # whole per-machine tree can be stood up in a temp folder and the REAL
    # default path resolution exercised against it. Nothing writes to the real
    # C:\ProgramData at any point in this file.
    function Invoke-WithProgramData {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [Parameter(Mandatory)] [scriptblock] $Body
        )

        $savedProgramData = $env:ProgramData
        $savedLogRoot     = $env:WIN11OPTIMIZER_LOGROOT
        $savedLedgerRoot  = $env:WIN11OPTIMIZER_LEDGERROOT
        try {
            $env:ProgramData = $Root
            Remove-Item -LiteralPath 'Env:\WIN11OPTIMIZER_LOGROOT'    -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath 'Env:\WIN11OPTIMIZER_LEDGERROOT' -ErrorAction SilentlyContinue
            & $Body
        }
        finally {
            $env:ProgramData = $savedProgramData
            if ($savedLogRoot)    { $env:WIN11OPTIMIZER_LOGROOT = $savedLogRoot }
            if ($savedLedgerRoot) { $env:WIN11OPTIMIZER_LEDGERROOT = $savedLedgerRoot }
        }
    }

    function New-ProgramDataRoot {
        param([switch] $WithFolder)
        $root = Join-Path $script:Scratch ('pd-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $root -ItemType Directory -Force
        if ($WithFolder) { $null = New-Item -Path (Join-Path $root 'win11-optimizer') -ItemType Directory -Force }
        $root
    }

    # ---- a plan to try to record -------------------------------------------
    #
    # The same fabricated shape tests\ActionLog.Tests.ps1 uses, and it has to be
    # a REAL plan: Write-OptimizerAction validates the plan before it looks at
    # where the ledger is, so an invalid one would fail for the wrong reason and
    # the test would prove nothing about Q21.
    $script:Contract = Get-RemovalContract
    $script:Plan = [pscustomobject]@{
        PSTypeName        = $script:Contract.TypeName
        FindingId         = 'fabricated-plan'
        Category          = 'Service'
        RemovalMethod     = 'ServiceDisable'
        DisplayName       = 'Fabricated plan'
        Confidence        = 'Known'
        Route             = 'ServiceStartupType'
        Supported         = $true
        UnsupportedReason = $null
        CurrentState      = 'Present'
        VerifiedUtc       = [datetime]::UtcNow.ToString('o')
        RequiresElevation = $false
        RequiresConsent   = $false
        SafetyLabel       = 'Safe to remove'
        IsReversible      = $false
        Step              = [psobject[]] @()
        RollbackData      = [pscustomobject][ordered]@{
            ServiceName         = 'Fabricated'
            KeyPath             = 'HKLM:\SYSTEM\CurrentControlSet\Services\Fabricated'
            PreviousStartValue  = 2
            PreviousStartupType = 'Automatic'
        }
        Note              = [string[]] @()
        PreviewText       = [string[]] @('Fabricated.')
    }

    # ---- child processes ----------------------------------------------------
    $script:ShellPath = (Get-Process -Id $PID).Path

    # Runs a launcher in a child process of the same shell, with its own %TEMP%
    # so the bootstrap log it may write is findable and nobody else's.
    function Invoke-BootstrapChild {
        param(
            [Parameter(Mandatory)] [string] $ScriptPath,
            [Parameter()] [AllowEmptyString()] [string] $Choice = 'Quit',
            [Parameter()] [AllowEmptyString()] [string] $LedgerRoot = ''
        )

        $temp = Join-Path $script:Scratch ('temp-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $temp -ItemType Directory -Force

        $wrapper = Join-Path $script:Scratch ('run-' + [guid]::NewGuid().ToString('N') + '.ps1')
        $body = @(
            "`$env:TEMP = '$temp'"
            "`$env:TMP  = '$temp'"
            $(if ($LedgerRoot) { "`$env:WIN11OPTIMIZER_LEDGERROOT = '$LedgerRoot'" } else { "Remove-Item -LiteralPath 'Env:\WIN11OPTIMIZER_LEDGERROOT' -ErrorAction SilentlyContinue" })
            "Remove-Item -LiteralPath 'Env:\WIN11OPTIMIZER_LOGROOT' -ErrorAction SilentlyContinue"
            "& '$ScriptPath' -Choice '$Choice'"
            'exit $LASTEXITCODE'
        ) -join [Environment]::NewLine
        [System.IO.File]::WriteAllText($wrapper, $body, (New-Object System.Text.UTF8Encoding($false)))

        $output = & $script:ShellPath -NoProfile -File $wrapper 2>&1
        $code = $LASTEXITCODE

        [pscustomobject]@{
            ExitCode = $code
            Output   = [string] (@($output) -join [Environment]::NewLine)
            TempPath = $temp
            LogFile  = @(Get-ChildItem -LiteralPath $temp -File -Filter 'win11-optimizer-bootstrap-*.log' -ErrorAction SilentlyContinue)
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
    Remove-Item Env:\WIN11OPTIMIZER_LEDGERROOT -ErrorAction SilentlyContinue
}

Describe 'Q21: the ledger has moved out of the repo' {

    It 'defaults to %ProgramData%\win11-optimizer\actions.jsonl' {
        $root = New-ProgramDataRoot
        Invoke-WithProgramData -Root $root -Body {
            Get-OptimizerActionLogRoot  | Should -Be (Join-Path $root 'win11-optimizer')
            Get-OptimizerActionLogPath  | Should -Be (Join-Path $root 'win11-optimizer\actions.jsonl')
        }
    }

    It 'is no longer anywhere under the repository' {
        $root = New-ProgramDataRoot
        Invoke-WithProgramData -Root $root -Body {
            $path = Get-OptimizerActionLogPath
            $path.StartsWith($script:RepoRoot, [System.StringComparison]::OrdinalIgnoreCase) | Should -BeFalse `
                -Because "the packaged ledger must not live in a working tree, and this one is at '$path'"
        }
    }

    It 'is not the run log''s folder any more' {
        $root = New-ProgramDataRoot
        Invoke-WithProgramData -Root $root -Body {
            Get-OptimizerActionLogRoot | Should -Not -Be (Get-OptimizerLogRoot)
        }
    }

    It 'puts the run log somewhere every user can write: %LOCALAPPDATA%' {
        # The other half of the same problem. An installed build has its module
        # under %ProgramFiles%, so the old repo-relative run log root resolved to
        # a folder the first un-elevated scan could neither create nor write.
        $saved = $env:WIN11OPTIMIZER_LOGROOT
        try {
            Remove-Item -LiteralPath 'Env:\WIN11OPTIMIZER_LOGROOT' -ErrorAction SilentlyContinue
            $expected = Join-Path (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'win11-optimizer') 'logs'
            Get-OptimizerLogRoot | Should -Be $expected
        }
        finally { $env:WIN11OPTIMIZER_LOGROOT = $saved }
    }

    It 'honours WIN11OPTIMIZER_LEDGERROOT, which moves the ledger and nothing else' {
        $savedLedger = $env:WIN11OPTIMIZER_LEDGERROOT
        try {
            $other = Join-Path $script:Scratch 'ledger-override'
            $env:WIN11OPTIMIZER_LEDGERROOT = $other
            Get-OptimizerActionLogRoot | Should -Be $other
            Get-OptimizerLogRoot       | Should -Be $script:TestLogRoot
        }
        finally {
            Remove-Item -LiteralPath 'Env:\WIN11OPTIMIZER_LEDGERROOT' -ErrorAction SilentlyContinue
            if ($savedLedger) { $env:WIN11OPTIMIZER_LEDGERROOT = $savedLedger }
        }
    }

    It 'still honours WIN11OPTIMIZER_LOGROOT for both, so nothing that already worked has to change' {
        Get-OptimizerActionLogRoot | Should -Be $script:TestLogRoot
        Get-OptimizerLogRoot       | Should -Be $script:TestLogRoot
        Get-OptimizerActionLogPath | Should -Be (Join-Path $script:TestLogRoot 'actions.jsonl')
    }

    It 'prefers WIN11OPTIMIZER_LEDGERROOT over WIN11OPTIMIZER_LOGROOT' {
        $savedLedger = $env:WIN11OPTIMIZER_LEDGERROOT
        try {
            $env:WIN11OPTIMIZER_LEDGERROOT = Join-Path $script:Scratch 'wins'
            Get-OptimizerActionLogRoot | Should -Be (Join-Path $script:Scratch 'wins')
        }
        finally {
            Remove-Item -LiteralPath 'Env:\WIN11OPTIMIZER_LEDGERROOT' -ErrorAction SilentlyContinue
            if ($savedLedger) { $env:WIN11OPTIMIZER_LEDGERROOT = $savedLedger }
        }
    }

    It 'creates neither the folder nor the file, and does not throw, when asked where it is' {
        $root = New-ProgramDataRoot
        Invoke-WithProgramData -Root $root -Body {
            $path = Get-OptimizerActionLogPath
            Test-Path -LiteralPath $path | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $root 'win11-optimizer') | Should -BeFalse
        }
    }
}

Describe 'Q21: the ACL, read by effect' {

    It 'accepts the three grants the installer sets' {
        @(Test-AclProblem -Acl (New-CorrectAcl)).Count | Should -Be 0
    }

    It 'accepts Modify where the installer grants Full Control' {
        $acl = New-TestAcl -Rule @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'Modify';         Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'Modify';         Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'Read';           Type = 'Allow' }
        )
        @(Test-AclProblem -Acl $acl).Count | Should -Be 0
    }

    It 'REFUSES a folder that merely inherits %ProgramData%''s own permissions' {
        # The headline case. Everything looks right -- administrators can write,
        # users can read -- and a standard user can still append a forged line
        # and delete the file afterwards.
        $problem = @(Test-AclProblem -Acl (New-InheritedProgramDataAcl))
        $problem.Count | Should -Be 2
        ($problem -join ' ') | Should -Match ([regex]::Escape($script:UserSid))
        ($problem -join ' ') | Should -Match ([regex]::Escape($script:CreatorOwnerSid))
        ($problem -join ' ') | Should -Match 'can write here'
    }

    It 'refuses any other principal that can write: <_>' -ForEach @('S-1-1-0', 'S-1-5-11', 'S-1-3-0') {
        $acl = New-TestAcl -Rule @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'ReadAndExecute'; Type = 'Allow' }
            [pscustomobject]@{ Sid = $_;                       Rights = 'Modify';         Type = 'Allow' }
        )
        $problem = @(Test-AclProblem -Acl $acl)
        $problem.Count | Should -Be 1
        $problem[0] | Should -Match 'can write here'
    }

    It 'lets another principal READ without complaint' {
        # Read is not the threat. A monitoring account that can see the ledger is
        # fine; one that can edit it is not.
        $acl = New-TestAcl -Rule @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'ReadAndExecute'; Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:EveryoneSid;      Rights = 'ReadAndExecute'; Type = 'Allow' }
        )
        @(Test-AclProblem -Acl $acl).Count | Should -Be 0
    }

    It 'refuses a folder <_> cannot use at all' -ForEach @('Administrators', 'SYSTEM') {
        $missing = $(if ($_ -eq 'Administrators') { $script:AdministratorSid } else { $script:SystemSid })
        $rule = @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'ReadAndExecute'; Type = 'Allow' }
        ) | Where-Object { $_.Sid -ne $missing }

        $problem = @(Test-AclProblem -Acl (New-TestAcl -Rule $rule))
        $problem.Count | Should -Be 1
        $problem[0] | Should -Match 'is not granted Modify'
    }

    It 'refuses a folder Users cannot read' {
        # A ledger only administrators can READ defeats half the reason for
        # moving it out of the repo: a standard user is entitled to see what was
        # done to the machine they are using.
        $acl = New-TestAcl -Rule @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'FullControl'; Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'FullControl'; Type = 'Allow' }
        )
        $problem = @(Test-AclProblem -Acl $acl)
        $problem.Count | Should -Be 1
        $problem[0] | Should -Match 'Users .* is not granted Read'
    }

    It 'reads Deny as subtracting from Allow, not as decoration' {
        $acl = New-TestAcl -Rule @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'Write';          Type = 'Deny' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'ReadAndExecute'; Type = 'Allow' }
        )
        $problem = @(Test-AclProblem -Acl $acl)
        $problem.Count | Should -Be 1
        $problem[0] | Should -Match 'Administrators .* is not granted Modify'
    }

    It 'reads Deny on a third party as removing the write it was flagged for' {
        $acl = New-TestAcl -Rule @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'Modify';         Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'; Type = 'Deny' }
        )
        @(Test-AclProblem -Acl $acl).Count | Should -Be 0
    }
}

Describe 'Q21: the refusal, by name of the error' {

    It 'names Win11Optimizer.LedgerFolderMissing when the folder is not there' {
        $root = New-ProgramDataRoot
        Invoke-WithProgramData -Root $root -Body {
            (Test-OptimizerLedgerFolder).ErrorId | Should -Be 'Win11Optimizer.LedgerFolderMissing'
            { Assert-OptimizerLedgerFolder } | Should -Throw -ErrorId 'Win11Optimizer.LedgerFolderMissing'
        }
    }

    It 'names Win11Optimizer.LedgerFolderAcl for a folder somebody made by hand' {
        # No mock and no privilege: a folder created with New-Item inherits, and
        # inheriting is the mistake.
        $root = New-ProgramDataRoot -WithFolder
        Invoke-WithProgramData -Root $root -Body {
            $report = Test-OptimizerLedgerFolder
            $report.Exists   | Should -BeTrue
            $report.IsUsable | Should -BeFalse
            $report.ErrorId  | Should -Be 'Win11Optimizer.LedgerFolderAcl'
            { Assert-OptimizerLedgerFolder } | Should -Throw -ErrorId 'Win11Optimizer.LedgerFolderAcl'
        }
    }

    It 'names Win11Optimizer.LedgerFolderUnreadable when the permissions cannot be read' {
        $root = New-ProgramDataRoot -WithFolder
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-Acl -MockWith {
            throw (New-Object System.UnauthorizedAccessException('Attempted to perform an unauthorized operation.'))
        }
        Invoke-WithProgramData -Root $root -Body {
            (Test-OptimizerLedgerFolder).ErrorId | Should -Be 'Win11Optimizer.LedgerFolderUnreadable'
            { Assert-OptimizerLedgerFolder } | Should -Throw -ErrorId 'Win11Optimizer.LedgerFolderUnreadable'
        }
    }

    It 'says nothing at all when the ACL is the one the installer sets' {
        $root = New-ProgramDataRoot -WithFolder
        # The descriptor is built HERE and closed over, not built inside the mock:
        # a -ModuleName mock body runs where the module can see it, and the
        # fixture helpers in this file are not there.
        $correct = New-CorrectAcl
        Mock -ModuleName Win11Optimizer.Engine -CommandName Get-Acl -MockWith ({ $correct }.GetNewClosure())
        Invoke-WithProgramData -Root $root -Body {
            $report = Test-OptimizerLedgerFolder
            $report.IsUsable | Should -BeTrue
            $report.ErrorId  | Should -BeNullOrEmpty
            $report.Problem.Count | Should -Be 0
            { Assert-OptimizerLedgerFolder } | Should -Not -Throw
        }
    }

    It 'names the folder and explains the ACL in the message' {
        $root = New-ProgramDataRoot -WithFolder
        Invoke-WithProgramData -Root $root -Body {
            $folder = Join-Path $root 'win11-optimizer'
            $message = ''
            try { Assert-OptimizerLedgerFolder } catch { $message = [string] $_.Exception.Message }

            $message | Should -Match ([regex]::Escape($folder))
            $message | Should -Match 'Administrators: Modify'
            $message | Should -Match 'SYSTEM: Modify'
            $message | Should -Match 'Users: Read'
            $message | Should -Match 'no fallback'
            $message | Should -Match 'icacls'
        }
    }

    It 'checks nothing at all when the ledger is not under %ProgramData%' {
        # The scratch folder this whole suite writes to. It has no ACL claim to
        # make and none is read.
        $report = Test-OptimizerLedgerFolder
        $report.IsPerMachine | Should -BeFalse
        $report.IsUsable     | Should -BeTrue
        { Assert-OptimizerLedgerFolder } | Should -Not -Throw
    }
}

Describe 'Q21: there is no fallback' {

    It 'refuses to WRITE an action, and records nothing anywhere' {
        $root = New-ProgramDataRoot -WithFolder
        Invoke-WithProgramData -Root $root -Body {
            { Write-OptimizerAction -Plan $script:Plan } | Should -Throw -ErrorId 'Win11Optimizer.LedgerFolderAcl'

            # Not in the folder it refused...
            @(Get-ChildItem -LiteralPath (Join-Path $root 'win11-optimizer') -Recurse -File).Count | Should -Be 0
            # ...and not in the repo's logs\ folder, which is where it used to go.
            $old = Join-Path $script:RepoRoot 'logs\actions.jsonl'
            $wasThere = Test-Path -LiteralPath $old
            if ($wasThere) {
                # If a real ledger is sitting there from before the move, this
                # test must not be the thing that appends to it.
                (Get-Item -LiteralPath $old).LastWriteTimeUtc | Should -BeLessThan ([datetime]::UtcNow.AddSeconds(-5))
            }
            else {
                Test-Path -LiteralPath $old | Should -BeFalse
            }
        }
    }

    It 'refuses to READ, rather than reporting a clean history it cannot vouch for' {
        # A missing per-machine folder and an empty ledger read back identically
        # -- as "nothing has ever been done to this PC" -- and only one of them
        # is true.
        $root = New-ProgramDataRoot
        Invoke-WithProgramData -Root $root -Body {
            { Get-OptimizerActionLog } | Should -Throw -ErrorId 'Win11Optimizer.LedgerFolderMissing'
        }
    }

    It 'still writes and reads normally when the ledger is somewhere with no ACL claim' {
        $path = Join-Path $script:Scratch ('ok-' + [guid]::NewGuid().ToString('N') + '\actions.jsonl')
        $null = New-Item -Path (Split-Path -Path $path -Parent) -ItemType Directory -Force
        $id = Write-OptimizerAction -Plan $script:Plan -Path $path
        $id | Should -Not -BeNullOrEmpty
        @(Get-OptimizerActionLog -Path $path).Count | Should -Be 1
    }
}

Describe 'P5-C2 the three new exports' {

    It 'exports <_> from both the .psm1 and the .psd1' -ForEach @(
        'Get-OptimizerActionLogRoot', 'Test-OptimizerLedgerFolder', 'Assert-OptimizerLedgerFolder'
    ) {
        $name = $_
        [System.IO.File]::ReadAllText($script:ModulePath)   | Should -Match ([regex]::Escape("'$name'"))
        [System.IO.File]::ReadAllText($script:ManifestPath) | Should -Match ([regex]::Escape("'$name'"))
        Get-Command -Module Win11Optimizer.Engine -Name $name -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'adds exactly three, and the manifest and the module still agree' {
        $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
        $exported = @(Get-Command -Module Win11Optimizer.Engine | ForEach-Object { $_.Name })
        @($manifest.FunctionsToExport).Count | Should -Be $exported.Count
        @($exported | Where-Object { $script:NewExport -contains $_ }).Count | Should -Be 3
    }

    It 'keeps the ACL check in the logger, where the prompt put it' {
        # Not in a new Support\ file. The rule is "the thing that writes the
        # ledger is the thing that refuses to write it", and a check one file
        # away from the writer is a check a future writer can forget to call.
        foreach ($name in @('Get-OptimizerActionLogRoot', 'Test-OptimizerLedgerFolder', 'Assert-OptimizerLedgerFolder')) {
            $command = Get-Command -Module Win11Optimizer.Engine -Name $name
            (Split-Path -Path $command.ScriptBlock.File -Leaf) | Should -Be 'ActionLog.ps1'
        }
    }

    It 'sets no permissions anywhere: the check reads and the installer writes' {
        $text = [System.IO.File]::ReadAllText($script:LedgerSource)
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref] $null, [ref] $null)
        $invoked = @($ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })

        foreach ($forbidden in 'Set-Acl', 'icacls', 'takeown', 'Set-Owner') {
            $invoked | Should -Not -Contain $forbidden -Because 'ActionLog.ps1 reads the ACL and never sets one'
        }
        $invoked | Should -Contain 'Get-Acl'

        # And it does not create the ledger folder either. Counted from the AST,
        # not the text: the file also NAMES New-Item in the comment explaining
        # why a folder made with it is not good enough, and that sentence runs
        # nothing. The one real call makes the manifest sidecar folder BESIDE an
        # existing ledger.
        @($invoked | Where-Object { $_ -eq 'New-Item' }).Count | Should -Be 1
    }
}

Describe 'P5-C2 part B: the installer source' {

    It 'is there, and it is well-formed XML' {
        Test-Path -LiteralPath $script:WxsPath | Should -BeTrue
        $script:WxsParseError | Should -BeNullOrEmpty
        $script:Wxs | Should -Not -BeNullOrEmpty
    }

    It 'installs every file in the engine folder, and every file it names is really there' {
        # BOTH DIRECTIONS, and the second one is the one that matters: a source
        # file added to the module and not added here would install a module that
        # cannot load, and the first person to find that out would be a user.
        $onDisk = @(Get-ChildItem -LiteralPath $script:EngineRoot -Recurse -File |
            ForEach-Object { $_.FullName } | Sort-Object)

        $inWxs = @(Select-WxsNode -Name 'File' |
            ForEach-Object { Resolve-WxsSource -Source $_.Source } |
            Where-Object { $_.StartsWith($script:EngineRoot, [System.StringComparison]::OrdinalIgnoreCase) } |
            Sort-Object)

        $missing = @($onDisk | Where-Object { $inWxs -notcontains $_ })
        $extra   = @($inWxs  | Where-Object { $onDisk -notcontains $_ })

        $missing.Count | Should -Be 0 -Because "these engine files are not in the .msi: $($missing -join ', ')"
        $extra.Count   | Should -Be 0 -Because "these .msi entries point at files that do not exist: $($extra -join ', ')"
    }

    It 'installs LICENSE.md, README.md and USAGE.md into docs\, and no other document' {
        # Keyed on the component group rather than on the source folder: all
        # three live at the repository ROOT now, and two engine folders ship a
        # README.md of their own, so a filter on the leaf name would be wrong in
        # both directions.
        #
        # LICENSE.md JOINED THE LIST IN P5-C5, and not as decoration: Apache-2.0
        # 4(a) requires giving every recipient of the Work a copy of the licence,
        # and shipping this .msi is distributing it. The installer's licence page
        # is a dialog somebody clicks past; this is the copy they keep.
        $node = @(Select-WxsNode -Name 'ComponentGroup' | Where-Object { $_.Id -eq 'CG.Docs' })
        $docs = @($node |
            ForEach-Object { $_.SelectNodes(".//*[local-name()='File']") } |
            ForEach-Object { [string] $_.Name } | Sort-Object)

        $docs | Should -Be @('LICENSE.md', 'README.md', 'USAGE.md')

        foreach ($group in $node) { $group.Directory | Should -Be 'DocsFolder' }

        # And it is the repository's own LICENSE.md, not the generated .rtf and
        # not a copy of it. The one copy of the licence text is the point.
        $source = @($node |
            ForEach-Object { $_.SelectNodes(".//*[local-name()='File']") } |
            Where-Object { [string] $_.Name -eq 'LICENSE.md' } |
            ForEach-Object { Resolve-WxsSource -Source ([string] $_.Source) })
        $source | Should -Be @((Join-Path $script:RepoRoot 'LICENSE.md'))
    }

    It 'ships none of the five internal planning documents: <_>' -ForEach @('CHECKLIST.md', 'PLAN.md', 'RESEARCH.md', 'REVIEW.md', 'STATE.md') {
        # STATE.md is the reason this test exists. It is 91 KB of measured detail
        # about the machine this project was developed on -- installed software,
        # service names, publisher strings -- and until P5-C4 the .msi copied it
        # into C:\Program Files\win11-optimizer\docs\ on every machine that
        # installed it. The other four are the chunk board and the research
        # notes, of no use to anybody who did not write them.
        #
        # Asserted by NAME and not just by folder: moving one of them out of
        # docs\ would defeat a path-only check, and putting STATE.md back under
        # any name it is known by is the mistake worth catching.
        $shipped = @(Get-WxsSourceFile | ForEach-Object { Split-Path -Path $_ -Leaf })
        $shipped | Should -Not -Contain $_
    }

    It 'names every file it carries, and each of them exists on disk' {
        # File AND Icon. The .ico is not an installed file -- it is a stream in
        # the .msi -- so it has no File element and a walk of File nodes alone
        # would never notice it had been deleted or renamed.
        $carried = @(Get-WxsSourceFile)
        $carried.Count | Should -BeGreaterThan 0
        foreach ($source in $carried) {
            Test-Path -LiteralPath $source -PathType Leaf | Should -BeTrue -Because "the .wxs points at '$source'"
        }
    }

    It 'installs no file from <_>' -ForEach @('tests', 'docs', 'logs', '.git', 'packaging') {
        # docs\ IN FULL, not just docs\handoff\, since P5-C4: the whole folder is
        # gitignored and nothing in it belongs in Program Files.
        #
        # packaging\ is on this list and packaging\win11-optimizer.ico is in the
        # package -- both are true. The icon is an Icon table stream, not an
        # installed file, so nothing from packaging\ lands on the target machine's
        # disk. That is what this walks File nodes to say.
        $excluded = Join-Path $script:RepoRoot $_
        foreach ($node in (Select-WxsNode -Name 'File')) {
            $source = Resolve-WxsSource -Source $node.Source
            $source.StartsWith($excluded, [System.StringComparison]::OrdinalIgnoreCase) | Should -BeFalse `
                -Because "'$source' is under '$excluded' and must not be installed"
        }
    }

    It 'ships no hidden file and no source-control metadata' {
        foreach ($node in (Select-WxsNode -Name 'File')) {
            $leaf = [string] $node.Name
            $leaf.StartsWith('.') | Should -BeFalse -Because "'$leaf' is a hidden file"
        }
    }

    It 'installs the module where Import-Module can find it by folder name' {
        # C:\Program Files\win11-optimizer\src\Win11Optimizer.Engine, so that the
        # folder name and the manifest name match and Import-Module <folder>
        # works with no PSModulePath change.
        $directory = @(Select-WxsNode -Name 'Directory')
        $byId = @{}
        foreach ($node in $directory) { $byId[[string] $node.Id] = $node }

        $byId.ContainsKey('INSTALLFOLDER') | Should -BeTrue
        $byId['INSTALLFOLDER'].Name        | Should -Be 'win11-optimizer'
        $byId['SrcFolder'].Name            | Should -Be 'src'
        $byId['EngineFolder'].Name         | Should -Be 'Win11Optimizer.Engine'
        $byId['DocsFolder'].Name           | Should -Be 'docs'
        $byId['LedgerFolder'].Name         | Should -Be 'win11-optimizer'
        $byId['INSTALLFOLDER'].ParentNode.Id | Should -Be 'ProgramFiles64Folder'
        $byId['LedgerFolder'].ParentNode.Id  | Should -Be 'CommonAppDataFolder'
    }

    It 'creates one Start Menu shortcut, and it is the one the prompt describes' {
        $shortcut = @(Select-WxsNode -Name 'Shortcut')
        $shortcut.Count | Should -Be 1

        $shortcut[0].Name      | Should -Be 'win11-optimizer'
        $shortcut[0].Target    | Should -Be '[System64Folder]WindowsPowerShell\v1.0\powershell.exe'
        $shortcut[0].Arguments | Should -Be '-NoProfile -File "[#F_App_Bootstrap_ps1]"'
        $shortcut[0].Show      | Should -Be 'normal'

        # "Start In: blank" -- the attribute is absent, not empty.
        @($shortcut[0].Attributes | ForEach-Object { $_.Name }) | Should -Not -Contain 'WorkingDirectory'

        # It lands in the Start Menu itself, not in a folder of its own that an
        # uninstall would then have to clean up.
        $shortcut[0].ParentNode.ParentNode.Id | Should -Be 'ProgramMenuFolder'
    }

    It 'keys the shortcut''s component on HKCU, which is what the ICE checks demand' {
        # NOT a per-user install, and not a slip. A non-advertised shortcut in the
        # Start Menu counts as per-user data to Windows Installer: ICE38, ICE43
        # and ICE57 all fail a component that puts one there with a per-machine
        # key path, and light refuses to produce the .msi at all. The .lnk still
        # lands in the ALL USERS Start Menu because the package is perMachine.
        #
        # This is asserted so that "tidying" it back to HKLM fails here rather
        # than at the next build.
        $registry = @(Select-WxsNode -Name 'RegistryValue' |
            Where-Object { $_.ParentNode.Id -eq 'C_StartMenuShortcut' })
        $registry.Count | Should -Be 1
        $registry[0].Root    | Should -Be 'HKCU'
        $registry[0].KeyPath | Should -Be 'yes'
    }

    It 'points the shortcut at Bootstrap.ps1, which is a file the package installs' {
        $referenced = ([string] (@(Select-WxsNode -Name 'Shortcut')[0].Arguments))
        $referenced | Should -Match '\[#(?<id>[A-Za-z0-9_.]+)\]'
        $id = ([regex]::Match($referenced, '\[#(?<id>[A-Za-z0-9_.]+)\]')).Groups['id'].Value

        $file = @(Select-WxsNode -Name 'File' | Where-Object { $_.Id -eq $id })
        $file.Count | Should -Be 1
        $file[0].Name | Should -Be 'Bootstrap.ps1'
        (Resolve-WxsSource -Source $file[0].Source) | Should -Be $script:BootstrapPath
    }

    It 'asks for no elevation of its own: the menu asks per choice' {
        $text = [System.IO.File]::ReadAllText($script:WxsPath)
        $text | Should -Not -Match 'runas'

        # No shortcut and no custom action asks to be run as administrator. The
        # package elevates once, for the install itself, which is what perMachine
        # means; nothing it leaves behind starts life elevated.
        foreach ($node in (Select-WxsNode -Name 'CustomAction')) {
            [string] $node.Impersonate | Should -Be 'yes' `
                -Because "custom action '$($node.Id)' would otherwise run as SYSTEM"
            [string] $node.Execute | Should -Not -Be 'deferred'
        }
    }

    It 'runs no code of its own during the install' {
        # UNTIL P5-C4 THIS ASSERTED THERE WAS NO CustomAction AT ALL, which was
        # the strongest form of the claim and is no longer available: the finish
        # page's "Launch win11-optimizer" checkbox needs a DoAction, and a
        # DoAction needs a custom action. So the claim is narrowed to the one
        # that was actually load-bearing -- the installer runs no code of its own
        # WHILE INSTALLING -- and it is now checked mechanically rather than by
        # the absence of a word.
        $custom = @(Select-WxsNode -Name 'CustomAction')
        $custom.Count | Should -Be 1
        $custom[0].Id | Should -Be 'CA.LaunchWin11Optimizer'

        # <Custom> is how a custom action gets into a sequence table. There is
        # none, so the action is reachable from exactly one place: the Publish
        # below.
        @(Select-WxsNode -Name 'Custom').Count | Should -Be 0

        $publish = @(Select-WxsNode -Name 'Publish' |
            Where-Object { $_.Event -eq 'DoAction' })
        $publish.Count | Should -Be 1
        $publish[0].Dialog  | Should -Be 'ExitDialog'
        $publish[0].Control | Should -Be 'Finish'
        $publish[0].Value   | Should -Be 'CA.LaunchWin11Optimizer'

        # NOT Installed, so the box is not offered at the end of an uninstall,
        # when the thing it would launch has just been deleted.
        $publish[0].InnerText | Should -Match 'NOT Installed'
    }

    It 'launches exactly what the Start Menu shortcut launches' {
        # Two ways into the same tool. If they ever disagree, one of them is
        # running something nobody tested.
        $shortcut = @(Select-WxsNode -Name 'Shortcut')[0]
        $custom   = @(Select-WxsNode -Name 'CustomAction')[0]

        [string] $custom.ExeCommand | Should -Be ('"{0}" {1}' -f $shortcut.Target, $shortcut.Arguments)

        # asyncNoWait: this starts a console application the person is about to
        # use, and waiting for it would pin the finish page open until they quit.
        [string] $custom.Return | Should -Be 'asyncNoWait'

        # Type 34 -- a directory and a command line. No BinaryKey means no helper
        # DLL and no WixUtilExtension, so the whole action is that one string.
        [string] $custom.Directory | Should -Not -BeNullOrEmpty
        @($custom.Attributes | ForEach-Object { $_.Name }) | Should -Not -Contain 'BinaryKey'
    }

    It 'sets the ledger folder ACL, with inheritance off' {
        $permission = @(Select-WxsNode -Name 'PermissionEx')
        $permission.Count | Should -Be 1

        # The CORE PermissionEx, in the main WiX namespace -- the one that writes
        # the MsiLockPermissionsEx table and takes an SDDL string. There is a
        # second element with the same name in WixUtilExtension that is a custom
        # action, takes a user name, and has no Sddl attribute at all; reaching
        # for it is a compile error, and this is the assertion that says which
        # one this file means.
        $permission[0].NamespaceURI | Should -Be 'http://schemas.microsoft.com/wix/2006/wi'
        $permission[0].Prefix       | Should -BeNullOrEmpty

        $text = [System.IO.File]::ReadAllText($script:WxsPath)
        $sddl = ([regex]::Match($text, '<\?define\s+LedgerSddl\s*=\s*"(?<sddl>[^"]+)"')).Groups['sddl'].Value
        $sddl | Should -Not -BeNullOrEmpty

        # D:P -- protected, i.e. %ProgramData%'s inheritable entries do not apply.
        # Without this the folder is worse than the repo folder it replaces.
        $sddl | Should -Match 'D:P'
        $sddl | Should -Match '\(A;OICI;FA;;;BA\)'
        $sddl | Should -Match '\(A;OICI;FA;;;SY\)'
        $sddl | Should -Match '\(A;OICI;0x1200a9;;;BU\)'
    }

    It 'writes an ACL the running tool then accepts' {
        # The two halves of Q21 asserted against each other: what the installer
        # sets is what Removal\ActionLog.ps1 requires. They are written in
        # different languages in different files, and this is the only place the
        # claim that they agree is actually made.
        $acl = New-TestAcl -Rule @(
            [pscustomobject]@{ Sid = $script:AdministratorSid; Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:SystemSid;        Rights = 'FullControl';    Type = 'Allow' }
            [pscustomobject]@{ Sid = $script:UserSid;          Rights = 'ReadAndExecute'; Type = 'Allow' }
        )
        @(Test-AclProblem -Acl $acl).Count | Should -Be 0
    }

    It 'leaves the ledger folder behind on uninstall' {
        $component = @(Select-WxsNode -Name 'Component' | Where-Object { $_.Id -eq 'C_LedgerFolder' })
        $component.Count | Should -Be 1
        $component[0].Permanent | Should -Be 'yes'

        # Nothing in the package deletes a folder on the way out.
        @(Select-WxsNode -Name 'RemoveFolder').Count | Should -Be 0
        @(Select-WxsNode -Name 'RemoveFile').Count   | Should -Be 0
    }

    It 'is a per-machine 64-bit package that needs Windows Installer 5' {
        $package = @(Select-WxsNode -Name 'Package')[0]
        $package.InstallScope     | Should -Be 'perMachine'
        $package.InstallerVersion | Should -Be '500'
        $package.Compressed       | Should -Be 'yes'
    }

    It 'carries a stable UpgradeCode and upgrades in place' {
        $product = @(Select-WxsNode -Name 'Product')[0]
        $product.UpgradeCode | Should -Match '^\{[0-9A-Fa-f-]{36}\}$'
        @(Select-WxsNode -Name 'MajorUpgrade').Count | Should -Be 1
    }

    It 'gives every component a key path' {
        foreach ($component in (Select-WxsNode -Name 'Component')) {
            $own = [string] $component.KeyPath
            $child = @($component.ChildNodes | Where-Object { $_.KeyPath -eq 'yes' })
            ($own -eq 'yes' -or $child.Count -eq 1) | Should -BeTrue `
                -Because "component '$($component.Id)' has no key path, and Windows Installer needs one"
        }
    }
}

Describe 'P5-C4: what Add/Remove Programs shows' {

    It 'names a publisher, and it is not the product name over again' {
        # It used to say Manufacturer="win11-optimizer", so ARP read
        # "win11-optimizer by win11-optimizer" and the Publisher column carried
        # no information at all.
        $product = @(Select-WxsNode -Name 'Product')[0]
        [string] $product.Manufacturer | Should -Not -BeNullOrEmpty
        [string] $product.Manufacturer | Should -Not -Be ([string] $product.Name)
    }

    It 'has no dead About link' {
        # ARP renders this as a live link. It used to point at
        # https://github.com/win11-optimizer, which is not a repository and not
        # an account: everybody who clicked it got a 404.
        # Dropping the property is a legitimate answer, so the check is
        # conditional on it being there at all -- what is not legitimate is
        # shipping one that goes nowhere.
        $property = Get-WxsProperty
        if ($property.ContainsKey('ARPURLINFOABOUT')) {
            $property['ARPURLINFOABOUT'] | Should -Match '^https://'
            $property['ARPURLINFOABOUT'] | Should -Not -Match 'github\.com/win11-optimizer(/|$)' `
                -Because 'that account does not exist; a missing link beats a dead one'
        }
    }

    It 'declares exactly one icon, from a file that is really there' {
        $icon = @(Select-WxsNode -Name 'Icon')
        $icon.Count | Should -Be 1

        # THE Id MUST END IN .ico. Windows Installer writes the Icon table's key
        # out as a file name when it extracts the icon into the installer cache,
        # and a key with no extension produces a cached file Explorer will not
        # read as an icon -- ARP then shows the generic box this exists to
        # replace, with nothing anywhere saying why.
        [string] $icon[0].Id | Should -BeLike '*.ico'

        (Resolve-WxsSource -Source $icon[0].SourceFile) | Should -Be $script:IcoPath
        Test-Path -LiteralPath $script:IcoPath -PathType Leaf | Should -BeTrue
    }

    It 'points both ARPPRODUCTICON and the shortcut at that one icon' {
        $iconId = [string] (@(Select-WxsNode -Name 'Icon')[0].Id)

        (Get-WxsProperty)['ARPPRODUCTICON'] | Should -Be $iconId

        $shortcut = @(Select-WxsNode -Name 'Shortcut')[0]
        [string] $shortcut.Icon | Should -Be $iconId `
            -Because 'without it the Start Menu entry shows powershell.exe''s icon'
        [string] $shortcut.IconIndex | Should -Be '0'
    }

    It 'ships an icon carrying the sizes Windows actually asks for' {
        # ARP wants a small one, the Start Menu tile wants a large one, and a
        # single-size .ico gets scaled into mush at whichever end it is short of.
        # Read out of the ICONDIR rather than trusted: this file is binary and
        # committed, so nothing else in the suite would notice it being replaced
        # by a 32-pixel placeholder.
        $bytes = [System.IO.File]::ReadAllBytes($script:IcoPath)

        [System.BitConverter]::ToUInt16($bytes, 0) | Should -Be 0    # reserved
        [System.BitConverter]::ToUInt16($bytes, 2) | Should -Be 1    # 1 = icon, 2 = cursor

        $count = [System.BitConverter]::ToUInt16($bytes, 4)
        $size = @(for ($index = 0; $index -lt $count; $index++) {
            $entry = 6 + $index * 16
            # 0 in the width byte means 256: the field is one byte wide.
            if ($bytes[$entry] -eq 0) { 256 } else { [int] $bytes[$entry] }
        })

        foreach ($wanted in @(16, 32, 48, 256)) {
            $size | Should -Contain $wanted -Because "the .ico carries $($size -join ', ')"
        }
    }
}

Describe 'P5-C4: the installer UI' {

    It 'asks for a dialog set at all, and it is WiX''s own' {
        # Before P5-C4 there was no UIRef in the file: the install was a UAC
        # prompt, a progress bar, and then nothing -- no confirmation, and no
        # sign of where the tool had gone.
        #
        # P5-C4 could not use WixUI_Minimal, because its one first-run dialog is
        # WelcomeEulaDlg and LICENSE.md was empty, so it shipped a dialog set of
        # its own -- WixUI_Minimal's dialogs with the licence page taken out.
        # P5-C5 put WixUI_Minimal back. THE ASSERTION IS NOW TWO-SIDED: WiX's set
        # is referenced AND no set of our own is defined, because a leftover
        # <UI Id="..."> fragment would link cleanly and simply never be shown.
        $reference = @(Select-WxsNode -Name 'UIRef' | ForEach-Object { [string] $_.Id })
        $reference | Should -Contain 'WixUI_Minimal'
        $reference | Should -Not -Contain 'WixUI_Win11Optimizer'

        $ownSet = @(Select-WxsNode -Name 'UI' | Where-Object { -not [string]::IsNullOrEmpty([string] $_.Id) })
        $ownSet.Count | Should -Be 0 -Because 'the dialog set is WiX''s, unmodified'
    }

    It 'shows a licence page exactly when there is a licence to show' {
        # WixUI_Minimal's only first-run dialog is WelcomeEulaDlg, which is the
        # welcome page and the licence agreement in one, and with no
        # WixUILicenseRtf of our own it renders WiX's PLACEHOLDER EULA: a licence
        # nobody wrote, displayed as though somebody had, and accepted by
        # everyone who installs this. That is why P5-C4 shipped a dialog set of
        # its own while LICENSE.md was empty.
        #
        # LICENSE.md HAS CONTENT NOW, so this takes its other branch: there is a
        # licence, therefore there is a licence page. NOT ONE LINE OF THIS TEST
        # CHANGED IN P5-C5, which is the whole of what an if-and-only-if is for.
        # THIS TEST IS THE REMINDER AS MUCH AS THE CHECK: emptying LICENSE.md
        # again fails it, here, with the message saying what to take back out. A
        # one-sided assertion in either direction would sit there passing for as
        # long as nobody noticed.
        $licence = Join-Path $script:RepoRoot 'LICENSE.md'
        $haveLicence = (Test-Path -LiteralPath $licence -PathType Leaf) -and
                       -not [string]::IsNullOrWhiteSpace([System.IO.File]::ReadAllText($licence))

        # Read from the parsed XML, not the text: the comment above the dialog
        # set names WixUILicenseRtf in the sentence explaining how to put the
        # licence page back, and a text match cannot tell that from authoring.
        $dialog = @(Select-WxsNode -Name 'DialogRef' | ForEach-Object { [string] $_.Id })
        $variable = @(Select-WxsNode -Name 'WixVariable' | ForEach-Object { [string] $_.Id })
        $shownLicence = ($dialog -contains 'WelcomeEulaDlg') -or
                        ($dialog -contains 'LicenseAgreementDlg') -or
                        ($variable -contains 'WixUILicenseRtf')

        $shownLicence | Should -Be $haveLicence -Because $(if ($haveLicence) {
            'LICENSE.md has content now: put <UIRef Id="WixUI_Minimal" /> back and add <WixVariable Id="WixUILicenseRtf" ... />'
        } else {
            'LICENSE.md is empty, and a placeholder EULA is worse than no licence page'
        })
    }

    It 'offers no feature tree, and lets WixUI_Minimal be the one to say so' {
        # perMachine into Program Files is the only shape this package supports,
        # and a browse page implies otherwise. So does a feature tree, on a
        # Feature marked Absent="disallow".
        #
        # ARPNOMODIFY IS NOT SET IN THIS FILE AT ALL, and that is the assertion.
        # P5-C4's own dialog set set it; WixUI_Minimal sets it too, and setting
        # it here as well is a duplicate-symbol error at link time -- not a
        # warning, and not a package. So the .wxs must be silent about it, and
        # the built package must still have it: the second half is asserted
        # against the .msi's own Property table further down, where it can be
        # read rather than inferred.
        $set = @(Select-WxsNode -Name 'Property' | Where-Object { $_.Id -eq 'ARPNOMODIFY' })
        $set.Count | Should -Be 0 -Because 'WixUI_Minimal supplies it, and a second one will not link'

        # The Feature itself is where "there is nothing to customise" is really
        # said. This does not depend on any dialog set.
        $feature = @(Select-WxsNode -Name 'Feature')
        $feature.Count | Should -Be 1
        $feature[0].Absent | Should -Be 'disallow'
    }

    It 'adds exactly one transition to WiX''s dialog set, and it is the launch' {
        # WixUI_Minimal owns the sequencing now -- welcome-and-licence, progress,
        # finish -- and this file authors none of it. What it does author is one
        # Publish: the finish page's checkbox, wired to the launch.
        #
        # EXACTLY ONE, counted over the whole file. A second Publish appearing
        # here would mean somebody had started rebuilding a dialog set by hand
        # inside the Product, which is the thing P5-C5 deleted; and zero would
        # mean the launch checkbox had quietly become a checkbox that does
        # nothing, which no other test in this file would notice.
        $publish = @(Select-WxsNode -Name 'Publish')
        $publish.Count | Should -Be 1

        $publish[0].Dialog  | Should -Be 'ExitDialog'
        $publish[0].Control | Should -Be 'Finish'
        $publish[0].Event   | Should -Be 'DoAction'
        $publish[0].Value   | Should -Be 'CA.LaunchWin11Optimizer'
        # NOT Installed keeps it off the finish page of an uninstall, where the
        # .lnk it points at is already gone.
        ([string] $publish[0].InnerText) | Should -Match 'NOT Installed'
    }

    It 'ends on a finish page that says where the tool went and offers to start it' {
        $property = Get-WxsProperty
        $property['WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT'] | Should -Be 'Launch win11-optimizer'
        $property['WIXUI_EXITDIALOGOPTIONALCHECKBOX']     | Should -Be '1'
        $property['WIXUI_EXITDIALOGOPTIONALTEXT']         | Should -Match 'Start Menu'

        # A [PROPERTY] reference in that text would print as itself: ExitDlg
        # formats its control text once, and the value the property expands to is
        # not formatted again.
        $property['WIXUI_EXITDIALOGOPTIONALTEXT'] | Should -Not -Match '\['
    }

    It 'says nothing on the finish page that promises a result' {
        # The same promise the rest of the tool keeps: this prints what is on
        # disk now, and never what a change will do to the machine afterwards.
        # A finish page is exactly where that sentence would get written.
        . (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
        $property = Get-WxsProperty
        $visible = @(
            $property['WIXUI_EXITDIALOGOPTIONALTEXT']
            $property['WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT']
            @(Select-WxsNode -Name 'Package')[0].Description
            @(Select-WxsNode -Name 'Shortcut')[0].Description
        ) -join ' '

        foreach ($phrase in (Get-OptimizerForbiddenPhrase)) {
            $visible | Should -Not -BeLike "*$phrase*" -Because "'$phrase' promises a result"
        }
    }
}

Describe 'P5-C2 part B: the build script' {

    It 'is there and parses' {
        Test-Path -LiteralPath $script:BuildPath | Should -BeTrue
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:BuildPath, [ref] $null, [ref] $errors)
        @($errors).Count | Should -Be 0
    }

    It 'runs candle and then light, and nothing else that builds a package' {
        $text = [System.IO.File]::ReadAllText($script:BuildPath)
        $text | Should -Match 'candle\.exe'
        $text | Should -Match 'light\.exe'
        # x64: ProgramFiles64Folder and System64Folder resolve to the 64-bit
        # locations only for an x64 package, and the shortcut's target depends on
        # it -- a 32-bit package would point at SysWOW64's powershell.exe.
        $text | Should -Match "'-arch', 'x64'"
    }

    It 'links with the UI extension, which is where the dialogs come from' {
        # candle needs nothing extra: the .wxs only REFERENCES WiX's dialogs, it
        # does not use any extension's schema. Only the link step does.
        #
        # Dropping the switch is not a silent downgrade to no UI -- light stops
        # with "Unresolved reference to symbol 'WixUI:...'" and produces nothing
        # -- but a build script that has to be remembered is one that gets
        # forgotten, so it is asserted here and documented in packaging\README.md.
        $text = [System.IO.File]::ReadAllText($script:BuildPath)
        $text | Should -Match "'-ext', 'WixUIExtension'"

        $doc = [System.IO.File]::ReadAllText($script:PackagingDoc)
        $doc | Should -Match 'WixUIExtension'
    }

    It 'links with every ICE check on' {
        # -sice: suppresses an internal-consistency check. This package links
        # clean without suppressing any, and the day it stops doing so the answer
        # is to fix the package -- an installer that only validates with its
        # checks switched off has not been validated.
        $text = [System.IO.File]::ReadAllText($script:BuildPath)
        $text | Should -Not -Match '-sice'
        $text | Should -Not -Match '-sval'
    }

    It 'stops when WiX is not installed, rather than working around it' {
        $text = [System.IO.File]::ReadAllText($script:BuildPath)
        $text | Should -Match 'not installed'
        $text | Should -Match 'wixtoolset'
        $text | Should -Match 'no fallback'

        # The refusal is a throw, not a warning followed by a different packager.
        $text | Should -Not -Match 'Compress-Archive'
        $text | Should -Not -Match 'makecab'
        $text | Should -Not -Match 'iexpress'
    }

    It 'takes the version from the module manifest, so the two cannot disagree' {
        $text = [System.IO.File]::ReadAllText($script:BuildPath)
        $text | Should -Match 'Import-PowerShellDataFile'
        $text | Should -Match 'ModuleVersion'
    }
}

Describe 'P5-C2 part C: App\Bootstrap.ps1' {

    It 'is there and parses' {
        Test-Path -LiteralPath $script:BootstrapPath | Should -BeTrue
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:BootstrapPath, [ref] $null, [ref] $errors)
        @($errors).Count | Should -Be 0
    }

    It 'is excluded from the loader, by name, alongside Entry.ps1' {
        $psm1 = [System.IO.File]::ReadAllText($script:ModulePath)
        $psm1 | Should -Match "Get-OptimizerSourceFile[^\r\n]*'App'[^\r\n]*-Exclude\s+'Entry\.ps1',\s*'Bootstrap\.ps1'"

        # Still ONE -Exclude in the whole loader. Two would be two lists to keep
        # true, and the second one is the one nobody looks at.
        @([regex]::Matches($psm1, '-Exclude\s+')).Count | Should -Be 1
    }

    It 'is actually dropped, and Menu.ps1 is actually kept' {
        $files = InModuleScope Win11Optimizer.Engine -Parameters @{ Folder = $script:AppFolder } {
            param($Folder)
            Get-OptimizerSourceFile -Path $Folder -Name 'App' -Exclude 'Entry.ps1', 'Bootstrap.ps1'
        }
        $leaf = @($files | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        $leaf | Should -Contain 'Menu.ps1'
        $leaf | Should -Not -Contain 'Bootstrap.ps1'
        $leaf | Should -Not -Contain 'Entry.ps1'
    }

    It 'defines no function the module exports, so nothing here can be called by accident' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:BootstrapPath, [ref] $null, [ref] $null)
        $defined = @($ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | ForEach-Object { $_.Name })

        $exported = @((Import-PowerShellDataFile -LiteralPath $script:ManifestPath).FunctionsToExport)
        foreach ($name in $defined) {
            $exported | Should -Not -Contain $name -Because "Bootstrap.ps1 is a launcher and '$name' would shadow an export"
        }
    }

    It 'adds no mechanism: it imports, checks the ledger folder, and calls the menu' {
        # The same positive-allowlist idea P5-C1 applied to the menu. A launcher
        # that grows a decision in it is a launcher nothing can test.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:BootstrapPath, [ref] $null, [ref] $null)
        $invoked = @($ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)

        $allowed = @(
            'Get-Location', 'Import-Module', 'Invoke-OptimizerMenu', 'Join-Path',
            'Split-Path', 'Test-OptimizerLedgerFolder', 'Write-BootstrapLine', 'Write-Host'
        )
        foreach ($command in $invoked) {
            $allowed | Should -Contain $command -Because "Bootstrap.ps1 called '$command', which is not on its allowlist"
        }
    }

    It 'starts the menu and writes no log file when there is nothing to say' {
        $ledgerRoot = Join-Path $script:Scratch ('ok-ledger-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $ledgerRoot -ItemType Directory -Force

        $result = Invoke-BootstrapChild -ScriptPath $script:BootstrapPath -Choice 'Quit' -LedgerRoot $ledgerRoot

        $result.ExitCode | Should -Be 0 -Because "the child said: $($result.Output)"
        $result.Output   | Should -Match 'Goodbye'
        $result.LogFile.Count | Should -Be 0 -Because 'a launcher that drops a file in %TEMP% every time teaches people to ignore its files'
    }

    It 'writes one line to %TEMP% and exits 1 when the import fails, rather than vanishing' {
        # A copy of Bootstrap.ps1 with no module beside it. This is what a broken
        # or half-uninstalled install looks like from the shortcut's side.
        $broken = Join-Path $script:Scratch ('broken-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path (Join-Path $broken 'App') -ItemType Directory -Force
        Copy-Item -LiteralPath $script:BootstrapPath -Destination (Join-Path $broken 'App\Bootstrap.ps1')

        $result = Invoke-BootstrapChild -ScriptPath (Join-Path $broken 'App\Bootstrap.ps1')

        $result.ExitCode      | Should -Be 1 -Because "the child said: $($result.Output)"
        $result.LogFile.Count | Should -Be 1

        $log = $result.LogFile[0]
        $log.Name | Should -Match '^win11-optimizer-bootstrap-\d{8}-\d{6}\.log$'

        $text = [System.IO.File]::ReadAllText($log.FullName)
        $text | Should -Match 'could not start'
        $text | Should -Match ([regex]::Escape('Win11Optimizer.Engine.psd1'))
        $text | Should -Match 'process working directory:'
    }

    It 'leaves Entry.ps1 alone' {
        # Entry.ps1 is what a person runs from a shell they already have open,
        # and it is unchanged by this chunk. Two launchers, two jobs.
        $text = [System.IO.File]::ReadAllText($script:EntryPath)
        $text | Should -Match 'Invoke-OptimizerMenu'
        $text | Should -Not -Match 'bootstrap'
    }

    It 'is ASCII only, in every file this chunk touches' {
        foreach ($path in @($script:BootstrapPath, $script:LedgerSource, $script:ModulePath,
                            $script:ManifestPath, $script:WxsPath, $script:BuildPath,
                            $script:PackagingDoc, $PSCommandPath)) {
            $text = [System.IO.File]::ReadAllText($path)
            $bad  = @([regex]::Matches($text, '[^\x20-\x7E\t\r\n]'))
            $bad.Count | Should -Be 0 -Because "$(Split-Path $path -Leaf) must be ASCII only; first offender at offset $(if ($bad.Count -gt 0) { $bad[0].Index } else { -1 })"
        }
    }
}

Describe 'P5-C4: the built package, read from its own tables' -ForEach $MsiUnderTest {

    # Everything below asks the .msi what it contains rather than reading the
    # .wxs and believing it. It is the only level at which "the source produces
    # the rows it means to" can be checked at all: an <Icon> element whose Id
    # never reaches ARPPRODUCTICON, or an ARPNOMODIFY that a dialog set was
    # supposed to supply and did not, both look perfectly correct in the source.
    #
    # $MsiPath comes from -ForEach, resolved at discovery from packaging\dist\.
    # No package there means this whole block generates nothing -- no tests, and
    # no skips either. See the file header.

    It 'is not older than the source it was built from' {
        # A stale package would fail everything below for the wrong reason. This
        # says so once, first, in words.
        $package = Get-Item -LiteralPath $MsiPath
        $source  = Get-Item -LiteralPath (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'packaging\win11-optimizer.wxs')
        $package.LastWriteTime | Should -BeGreaterOrEqual $source.LastWriteTime -Because @"
'$($package.Name)' in packaging\dist is older than win11-optimizer.wxs, so it is
not the package this source describes. Rebuild it with packaging\Build-Msi.ps1,
or delete packaging\dist -- an absent package is fine, a stale one is not.
"@
    }

    It 'carries the publisher and the About link in its Property table' {
        $property = @{}
        foreach ($row in (Get-MsiRow -Path $MsiPath -Query 'SELECT `Property`,`Value` FROM `Property`')) {
            $property[$row[0]] = $row[1]
        }

        $property['Manufacturer'] | Should -Not -BeNullOrEmpty
        $property['Manufacturer'] | Should -Not -Be $property['ProductName']
        $property['ARPNOMODIFY']  | Should -Be '1' -Because 'the dialog set is expected to supply it'
        if ($property.ContainsKey('ARPURLINFOABOUT')) {
            $property['ARPURLINFOABOUT'] | Should -Not -Match 'github\.com/win11-optimizer(/|$)'
        }
    }

    It 'has one icon, and ARPPRODUCTICON and the shortcut both resolve to it' {
        $icon = @(Get-MsiValue -Path $MsiPath -Query 'SELECT `Name` FROM `Icon`')
        $icon.Count | Should -Be 1

        $arp = @(Get-MsiValue -Path $MsiPath -Query 'SELECT `Value` FROM `Property` WHERE `Property`=''ARPPRODUCTICON''')
        $arp | Should -Be @($icon[0])

        $shortcut = @(Get-MsiRow -Path $MsiPath -Query 'SELECT `Icon_`,`IconIndex` FROM `Shortcut`')
        $shortcut.Count | Should -Be 1
        $shortcut[0][0] | Should -Be $icon[0]
        $shortcut[0][1] | Should -Be '0'
    }

    It 'installs LICENSE.md, README.md and USAGE.md into docs\, and nothing else there' {
        # LICENSE.md is the Apache-2.0 4(a) copy, and it is asserted here, in the
        # package's own File table, rather than only in the .wxs: the licence page
        # the installer shows is not a substitute for the file, and only this
        # level can say the file really lands on the target machine.
        $file = Get-MsiFileFolder -Path $MsiPath
        $docs = @($file.Values |
            Where-Object { $_.Folder -eq 'win11-optimizer\docs' } |
            ForEach-Object { $_.Name } | Sort-Object)

        $docs | Should -Be @('LICENSE.md', 'README.md', 'USAGE.md')
    }

    It 'has no <_> anywhere in it' -ForEach @('CHECKLIST.md', 'PLAN.md', 'RESEARCH.md', 'REVIEW.md', 'STATE.md') {
        # By name, over the WHOLE File table, not just the docs\ folder: this is
        # the assertion that STATE.md's 91 KB of detail about the development
        # machine is not on the target machine's disk, and it should not care
        # where somebody might have moved it to.
        $name = @(Get-MsiValue -Path $MsiPath -Query 'SELECT `FileName` FROM `File`' |
            ForEach-Object { ($_ -split '\|')[-1] })
        $name | Should -Not -Contain $_
    }

    It 'has two custom actions, one of them WiX''s, and neither in a sequence table' {
        # P5-C2 AND P5-C4 BOTH SAID "EXACTLY ONE CUSTOM ACTION, NO HELPER DLL".
        # P5-C5 retired that claim, and this is where it is retired rather than
        # quietly loosened: WixUI_Minimal's WelcomeEulaDlg carries a Print button
        # and WiX wires it to WixUIPrintEula, a DLL action in WixUIExtension's own
        # WixUIWixca binary stream. It is not avoidable while showing a licence
        # page -- every WiX licence dialog has the same button -- so the package
        # carries two actions and one helper DLL, and the assertion counts them
        # BY NAME so a third arriving is still a failure.
        $custom = @{}
        foreach ($row in (Get-MsiRow -Path $MsiPath -Query 'SELECT `Action`,`Type` FROM `CustomAction`')) {
            $custom[$row[0]] = [int] $row[1]
        }
        @($custom.Keys | Sort-Object) | Should -Be @('CA.LaunchWin11Optimizer', 'WixUIPrintEula')

        # 226 = 34 (an exe named by a Directory and a command line) + 64
        # (continue on error) + 128 (asynchronous). 2048 -- NoImpersonate, the
        # bit that would run it as SYSTEM -- is NOT set, which is the half of
        # this that matters: the tool starts as the person, not as the machine.
        $custom['CA.LaunchWin11Optimizer'] | Should -Be 226
        ($custom['CA.LaunchWin11Optimizer'] -band 2048) | Should -Be 0 -Because 'it must not run elevated'

        # 65 = 1 (a DLL in the Binary table) + 64 (continue on error). It prints
        # the licence and nothing else, and it too must not run as SYSTEM.
        $custom['WixUIPrintEula'] | Should -Be 65
        ($custom['WixUIPrintEula'] -band 2048) | Should -Be 0 -Because 'nothing in this package runs as the machine'

        # NEITHER is sequenced. Both are reached from a button and from nowhere
        # else, which is what keeps a quiet install (msiexec /qn, no UI) free of
        # both of them.
        foreach ($table in @('InstallExecuteSequence', 'InstallUISequence',
                             'AdminExecuteSequence', 'AdminUISequence', 'AdvtExecuteSequence')) {
            $action = @(Get-MsiValue -Path $MsiPath -Query "SELECT ``Action`` FROM ``$table``")
            foreach ($name in @('CA.LaunchWin11Optimizer', 'WixUIPrintEula')) {
                $action | Should -Not -Contain $name `
                    -Because "$table would run $name during the install, and its only caller is a button"
            }
        }
    }

    It 'reaches the launch only from the finish page, and only on an install' {
        # THE WHOLE DoAction SET, pinned row for row. There are two now -- ours
        # and the licence page's Print button -- and listing both is stronger
        # than the old count of one: a third row wiring a custom action to any
        # other control is still a failure, and so is either of these two moving.
        $event = @(Get-MsiRow -Path $MsiPath -Query 'SELECT `Dialog_`,`Control_`,`Argument`,`Condition` FROM `ControlEvent` WHERE `Event`=''DoAction''')
        @($event | ForEach-Object { '{0}.{1} -> {2}' -f $_[0], $_[1], $_[2] } | Sort-Object) | Should -Be @(
            'ExitDialog.Finish -> CA.LaunchWin11Optimizer'
            'WelcomeEulaDlg.Print -> WixUIPrintEula'
        )

        $launch = @($event | Where-Object { $_[2] -eq 'CA.LaunchWin11Optimizer' })
        $launch.Count | Should -Be 1
        $launch[0][3] | Should -Match 'NOT Installed'
        $launch[0][3] | Should -Match 'WIXUI_EXITDIALOGOPTIONALCHECKBOX'
    }

    It 'opens on the licence page, and the licence on it is ours' {
        # THE INVERSE OF WHAT THIS TEST USED TO SAY. P5-C4 asserted that
        # WelcomeEulaDlg was absent BECAUSE LICENSE.md was empty; the reason has
        # expired, so the assertion turns over rather than being deleted.
        $shown = @{}
        foreach ($row in (Get-MsiRow -Path $MsiPath -Query 'SELECT `Action`,`Condition`,`Sequence` FROM `InstallUISequence`')) {
            $shown[$row[0]] = $row[1]
        }

        $shown.ContainsKey('WelcomeEulaDlg') | Should -BeTrue -Because 'LICENSE.md has content'
        $shown['WelcomeEulaDlg']             | Should -Match 'NOT Installed'
        $shown.ContainsKey('ProgressDlg')    | Should -BeTrue
        $shown.ContainsKey('ExitDialog')     | Should -BeTrue

        # WixUI_Minimal keeps WelcomeDlg for patching only, so a first install
        # sees the licence page and not a second welcome before it.
        $shown['WelcomeDlg'] | Should -Match 'PATCH'

        # VerifyReadyDlg is in the Dialog table without being sequenced.
        @(Get-MsiValue -Path $MsiPath -Query 'SELECT `Dialog` FROM `Dialog`') | Should -Contain 'VerifyReadyDlg'
    }

    It 'renders LICENSE.md itself on that page, and not a placeholder' {
        # THE STRONGEST FORM THIS CLAIM HAS. The licence page's ScrollableText
        # control carries the .rtf inline in the package, so the text a person
        # reads on screen can be read back out of the .msi and compared with the
        # repository's LICENSE.md line by line. A test that only checked
        # WixUILicenseRtf was set would pass on WiX's placeholder EULA, which is
        # exactly the failure P5-C4 built the if-and-only-if to prevent.
        $control = @(Get-MsiValue -Path $MsiPath `
            -Query 'SELECT `Text` FROM `Control` WHERE `Dialog_`=''WelcomeEulaDlg'' AND `Control`=''LicenseText''')
        $control.Count | Should -Be 1
        $rendered = [string] $control[0]

        $rendered | Should -Match '^\{\\rtf1' -Because 'the control holds RTF, not the Markdown source'
        $rendered | Should -Not -Match 'placeholder' -Because 'that is what WiX ships when nobody supplies a licence'

        # Every non-blank line of LICENSE.md, escaped the way Build-Msi.ps1
        # escapes it, is in there. This is what makes the page OURS rather than
        # merely non-empty.
        $licence = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'LICENSE.md'))
        $licence | Should -Not -BeNullOrEmpty
        $missing = New-Object System.Collections.Generic.List[string]
        foreach ($line in ($licence -split "`r`n|`n|`r")) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $escaped = $line.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}')
            if (-not $rendered.Contains($escaped)) { $null = $missing.Add($line) }
        }
        $missing.Count | Should -Be 0 -Because "these lines of LICENSE.md are not on the licence page: $(($missing | Select-Object -First 3) -join ' / ')"

        # And the two lines that say WHOSE licence it is.
        $rendered | Should -Match 'Apache License'
        $rendered | Should -Match 'Nem702'
    }

    It 'offers no feature tree and no install-location browse page' {
        # Moved here from the .wxs Describe in P5-C5 and made real by the move.
        # The old check walked our own DialogRef elements; the dialog set is
        # WiX's now and this file has no DialogRef of its own, so that check
        # would have gone VACUOUS -- passing while asserting nothing. Read from
        # the package's Dialog table it is a stronger claim than it ever was: it
        # covers dialogs WiX might bring in as well as ones we might author.
        $dialog = @(Get-MsiValue -Path $MsiPath -Query 'SELECT `Dialog` FROM `Dialog`')
        foreach ($unwanted in @('InstallDirDlg', 'BrowseDlg', 'CustomizeDlg', 'FeaturesDlg', 'SetupTypeDlg')) {
            $dialog | Should -Not -Contain $unwanted
        }
    }

    It 'shows the launch checkbox and the finish text on the finish page' {
        $property = @{}
        foreach ($row in (Get-MsiRow -Path $MsiPath -Query 'SELECT `Property`,`Value` FROM `Property`')) {
            $property[$row[0]] = $row[1]
        }
        $property['WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT'] | Should -Be 'Launch win11-optimizer'
        $property['WIXUI_EXITDIALOGOPTIONALCHECKBOX']     | Should -Be '1'
        $property['WIXUI_EXITDIALOGOPTIONALTEXT']         | Should -Match 'Start Menu'

        # The controls that read them are real controls on the real dialog.
        $control = @(Get-MsiValue -Path $MsiPath -Query 'SELECT `Control` FROM `Control` WHERE `Dialog_`=''ExitDialog''')
        $control | Should -Contain 'OptionalCheckBox'
        $control | Should -Contain 'OptionalText'
    }

    It 'still leaves the ledger folder behind: no RemoveFile, no RemoveFolder' {
        # P5-C2's claim, re-checked here because the UI added tables and this is
        # the level at which "a table is absent" can be said at all.
        $table = @(Get-MsiTable -Path $MsiPath)
        $table | Should -Not -Contain 'RemoveFile'
        $table | Should -Not -Contain 'RemoveFolder'
        $table | Should -Contain 'MsiLockPermissionsEx'

        $lock = @(Get-MsiRow -Path $MsiPath -Query 'SELECT `LockObject`,`Table`,`SDDLText` FROM `MsiLockPermissionsEx`')
        $lock.Count     | Should -Be 1
        $lock[0][0]     | Should -Be 'LedgerFolder'
        $lock[0][1]     | Should -Be 'CreateFolder'
        $lock[0][2]     | Should -Match 'D:P'
    }

    It 'installs the engine module whole, where Import-Module can find it' {
        $prefix = 'win11-optimizer\src\Win11Optimizer.Engine\'
        $file = Get-MsiFileFolder -Path $MsiPath
        $installed = @($file.Values |
            ForEach-Object { '{0}\{1}' -f $_.Folder, $_.Name } |
            Where-Object { $_.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) } |
            ForEach-Object { $_.Substring($prefix.Length) } |
            Sort-Object)

        $engineRoot = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'src\Win11Optimizer.Engine'
        $onDisk = @(Get-ChildItem -LiteralPath $engineRoot -Recurse -File |
            ForEach-Object { $_.FullName.Substring($engineRoot.Length).TrimStart('\') } | Sort-Object)

        $installed | Should -Be $onDisk
    }
}
