#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for chunk P5-C2 -- packaging: Q21 (where the action ledger lives and
    who may write it), the WiX installer source, and App\Bootstrap.ps1.

    NOTHING IN THIS FILE INSTALLS ANYTHING. No .msi is built, no .msi is run,
    nothing is written to the real %ProgramData%, and no ACL on this machine is
    changed. The three ways the ledger folder is exercised are, in order of how
    much they prove:

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

    Run:  .\tests\Invoke-Tests.ps1        (and -On51, which is not optional)
#>

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

    # A File's Source with the preprocessor variable resolved, as a full path.
    function Resolve-WxsSource {
        param([Parameter(Mandatory)] [string] $Source)
        $expanded = $Source.Replace('$(var.SourceRoot)', $script:RepoRoot)
        try { [System.IO.Path]::GetFullPath($expanded) } catch { $expanded }
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

    It 'installs the five reference documents and no other document' {
        $docs = @(Select-WxsNode -Name 'File' |
            ForEach-Object { Resolve-WxsSource -Source $_.Source } |
            Where-Object { $_.StartsWith((Join-Path $script:RepoRoot 'docs'), [System.StringComparison]::OrdinalIgnoreCase) } |
            ForEach-Object { Split-Path -Path $_ -Leaf } | Sort-Object)

        $docs | Should -Be @('CHECKLIST.md', 'PLAN.md', 'RESEARCH.md', 'REVIEW.md', 'STATE.md')
    }

    It 'names every file it installs, and each of them exists on disk' {
        foreach ($node in (Select-WxsNode -Name 'File')) {
            $source = Resolve-WxsSource -Source $node.Source
            Test-Path -LiteralPath $source -PathType Leaf | Should -BeTrue -Because "the .wxs points at '$source'"
        }
    }

    It 'ships nothing from <_>' -ForEach @('tests', 'docs\handoff', 'logs', '.git', 'packaging') {
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
        $text | Should -Not -Match 'CustomAction'
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
                            $script:ManifestPath, $script:WxsPath, $script:BuildPath, $PSCommandPath)) {
            $text = [System.IO.File]::ReadAllText($path)
            $bad  = @([regex]::Matches($text, '[^\x20-\x7E\t\r\n]'))
            $bad.Count | Should -Be 0 -Because "$(Split-Path $path -Leaf) must be ASCII only; first offender at offset $(if ($bad.Count -gt 0) { $bad[0].Index } else { -1 })"
        }
    }
}
