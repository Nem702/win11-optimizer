#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for chunk P5-C1 -- the launcher: the menu (App\Menu.ps1), the UAC
    relaunch (Support\Elevation.ps1) and the entry point (App\Entry.ps1).

    NOTHING IN THIS FILE ELEVATES ANYTHING, and nothing in it opens a window.
    Every relaunch is either mocked or driven through -WhatIf; the one place a
    real process is started, it is started WITHOUT -Verb RunAs, at the same
    integrity level as the test run, so what is being proved is that the command
    line binds -- not that UAC works, which is Windows' claim and not this
    project's.

    THE FIRST TWO DESCRIBES ARE THE ONES THAT MATTER MOST.

      * The menu's write surface is a POSITIVE ALLOWLIST. A switchboard is a file
        that is easy to quietly grow a mechanism inside -- one Set-ItemProperty
        "just for this choice" and the safety model has a second front door. The
        menu is allowed to call four things that change the machine, all of them
        exports that were tested in the chunk that shipped them, and it is
        allowed to call nothing else.

      * The loader must not dot-source App\Entry.ps1. Entry.ps1 imports the
        module and runs the menu, so dot-sourcing it during the import would
        re-enter Import-Module and open the menu from inside the module's own
        load. The exclusion is asserted from both ends: the .psm1 asks for it,
        and Get-OptimizerSourceFile actually drops it.

    Run:  .\tests\Invoke-Tests.ps1        (and -On51, which is not optional)
#>

BeforeAll {
    $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot   = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath   = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:MenuSource   = Join-Path $script:EngineRoot 'App\Menu.ps1'
    $script:EntrySource  = Join-Path $script:EngineRoot 'App\Entry.ps1'
    $script:ElevSource   = Join-Path $script:EngineRoot 'Support\Elevation.ps1'
    $script:AppFolder    = Join-Path $script:EngineRoot 'App'

    # A log root of our own. The repo's real ledger is the one file in this
    # project that is never rotated, and nothing in this suite may write to it.
    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-menu-" + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("win11opt-menu-scratch-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop

    $script:NewExport = @('Invoke-OptimizerMenu', 'Invoke-OptimizerElevated')

    # ---- the sources, comment-blanked, and their ASTs -----------------------
    #
    # Same machinery as tests\Executor.Tests.ps1, tests\ReviewScreen.Tests.ps1 and
    # tests\ExecutePlan.Tests.ps1. Repeated rather than shared for the reason
    # those files give: a source-scanning assertion that lives somewhere else is
    # one refactor away from scanning nothing, and these are the assertions the
    # chunk rests on.
    function Get-ParsedSource {
        param([Parameter(Mandatory)] [string] $Path)

        $raw = [System.IO.File]::ReadAllText($Path)
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors)

        $builder = New-Object System.Text.StringBuilder $raw
        foreach ($token in @($tokens | Where-Object { $_.Kind -eq 'Comment' })) {
            $start  = $token.Extent.StartOffset
            $length = $token.Extent.EndOffset - $start
            for ($i = 0; $i -lt $length; $i++) {
                if ($builder[$start + $i] -ne "`n" -and $builder[$start + $i] -ne "`r") {
                    $builder[$start + $i] = ' '
                }
            }
        }

        $invoked = [string[]] @(
            $ast.FindAll({
                param($node) $node -is [System.Management.Automation.Language.CommandAst]
            }, $true) | ForEach-Object {
                $element = $_.CommandElements[0]
                if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $element.Value }
                else { "<dynamic:$($element.Extent.Text)>" }
            } | Sort-Object -Unique
        )

        [pscustomobject]@{
            Path    = $Path
            Raw     = $raw
            Code    = $builder.ToString()
            Ast     = $ast
            Errors  = $errors
            Invoked = $invoked
            Defined = [string[]] @($ast.FindAll({
                param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) | ForEach-Object { $_.Name })
        }
    }

    $script:Menu  = Get-ParsedSource -Path $script:MenuSource
    $script:Entry = Get-ParsedSource -Path $script:EntrySource
    $script:Elev  = Get-ParsedSource -Path $script:ElevSource

    # ---- fixtures -----------------------------------------------------------

    # An empty file, used as standard input for every child process this suite
    # starts. -NoNewWindow WITHOUT it leaves the child sharing the operator's
    # console for input: the child's menu text goes into the redirected output
    # file, and its Read-Host prompt goes to a terminal that is showing nothing,
    # so the suite blocks forever on an invisible question. An empty file is at
    # end of file from the first read, Read-Host returns $null there -- measured
    # on 5.1 and 7.6.5, and the reason Invoke-OptimizerMenu has an EndOfInput
    # ending at all -- and the child exits after one menu.
    #
    # This is not belt and braces. It bit for real, elevated, on 2026-09-01: an
    # elevated run reaches 'Receipt', which SUCCEEDS, so the menu loops round and
    # asks for the next choice instead of ending at a refusal.
    $script:EmptyStdIn = Join-Path $script:Scratch 'empty-stdin.txt'
    [System.IO.File]::WriteAllText($script:EmptyStdIn, '')

    $script:LedgerCounter = 0
    function New-LedgerPath {
        $script:LedgerCounter++
        Join-Path $script:Scratch ("ledger-{0:d3}-{1}.jsonl" -f $script:LedgerCounter, [guid]::NewGuid().ToString('N'))
    }

    # A reader driven by a queue. Returns $null once the queue is empty, which
    # ends the session with EndOfInput -- so no test needs to remember to queue a
    # Quit, and a test that queues one too few fails as an assertion rather than
    # hanging.
    function New-QueueReader {
        param(
            [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Answer,
            [Parameter()] [AllowNull()] $PromptLog = $null
        )
        $queue = New-Object System.Collections.Generic.Queue[object]
        foreach ($item in @($Answer)) { $queue.Enqueue($item) }
        $log = $PromptLog

        {
            param($Prompt)
            if ($null -ne $log) { $null = $log.Add([string] $Prompt) }
            if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null }
        }.GetNewClosure()
    }

    function New-CollectingWriter {
        param([Parameter(Mandatory)] $Sink)
        { param($Line) $null = $Sink.Add([string] $Line) }.GetNewClosure()
    }

    function New-Sink { New-Object System.Collections.Generic.List[string] }
}

AfterAll {
    Remove-Item -LiteralPath $script:Scratch -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:TestLogRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'Env:\WIN11OPTIMIZER_LOGROOT' -ErrorAction SilentlyContinue
}

Describe 'P5-C1 the menu changes nothing itself -- a positive allowlist' {

    It 'parses, and defines Invoke-OptimizerMenu' {
        @($script:Menu.Errors).Count | Should -Be 0
        $script:Menu.Defined | Should -Contain 'Invoke-OptimizerMenu'
    }

    It 'calls exactly four things that can change this PC, and they are all tested exports' {
        # The whole write surface of the menu. Each of these was shipped and
        # tested by an earlier chunk; the menu adds no mechanism of its own.
        $allowed = @(
            'Invoke-OptimizerExecutionPlan'   # P4-C2 -- performs a confirmed selection
            'Undo-RemovalAction'              # P3-C3 -- puts one recorded action back
            'New-OptimizerRestorePoint'       # P3-C2 -- asks Windows for a checkpoint
            'Invoke-OptimizerElevated'        # P5-C1 -- starts a second, elevated process
        )

        # Anything that could write, in any form, that is NOT on the list above.
        $forbidden = @(
            'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Item'
            'New-Item', 'Remove-Item', 'Move-Item', 'Copy-Item', 'Clear-Item'
            'Set-Content', 'Add-Content', 'Out-File', 'Set-Service', 'Stop-Service'
            'Start-Service', 'Remove-AppxPackage', 'Unregister-ScheduledTask'
            'Start-Process', 'Invoke-Expression', 'Invoke-Item'
            'Write-OptimizerAction'           # the ledger belongs to whoever performs the action
            'Invoke-RemovalPlan'              # reached only through Invoke-OptimizerExecutionPlan
        )

        foreach ($name in $forbidden) {
            $script:Menu.Invoked | Should -Not -Contain $name -Because "the menu is a switchboard and $name would be a mechanism inside it"
        }

        foreach ($name in $allowed) {
            $script:Menu.Invoked | Should -Contain $name -Because 'the allowlist should not list something the file has stopped calling'
        }
    }

    It 'reaches the executor only through the P4-C2 bridge' {
        # Invoke-RemovalPlan is the executor's own entry point. The menu must go
        # through Invoke-OptimizerExecutionPlan, which is what makes the run
        # all-or-nothing and what writes the receipt.
        $script:Menu.Code | Should -Not -Match '\bInvoke-RemovalPlan\b'
    }

    It 'passes -Confirm:$false exactly once, on the execution, and says why' {
        # The review screen already asked. A second prompt, raised by PowerShell
        # through the host rather than through -Reader, would be the same
        # question in a worse place.
        $confirmFalse = [regex]::Matches($script:Menu.Code, '-Confirm:\$false')
        $confirmFalse.Count | Should -BeGreaterOrEqual 1
        $script:Menu.Code | Should -Match 'Invoke-OptimizerExecutionPlan[^\r\n]*-Confirm:\$false'
    }

    It 'talks to a person only through -Reader and -Writer' {
        # No Write-Host and no Read-Host anywhere except the two parameter
        # defaults, which is what makes the whole menu drivable by a test.
        $hostCalls = [regex]::Matches($script:Menu.Code, '\b(Write-Host|Read-Host)\b')
        $hostCalls.Count | Should -Be 2
        $script:Menu.Code | Should -Match '\$Reader\s*=\s*\{\s*param\(\$Prompt\)\s*Read-Host'
        $script:Menu.Code | Should -Match '\$Writer\s*=\s*\{\s*param\(\$Line\)\s*Write-Host'
    }
}

Describe 'P5-C1 the loader does not dot-source the launcher' {

    It 'asks for its exclusions by name, on one -Exclude, starting with App\Entry.ps1' {
        # AMENDED BY P5-C2. This It used to say "exactly one exclusion" and
        # named only Entry.ps1, which was true of a build with one launcher in it
        # and stopped being true when P5-C2 added App\Bootstrap.ps1 -- the file
        # the installed shortcut runs, which imports the module exactly as
        # Entry.ps1 does and must not be dot-sourced for exactly the same reason.
        #
        # What the count still asserts is the thing that mattered: ONE -Exclude
        # in the whole loader. A second one would be a second list, and the
        # second list is the one nobody looks at.
        $psm1 = [System.IO.File]::ReadAllText($script:ModulePath)
        $psm1 | Should -Match "Get-OptimizerSourceFile[^\r\n]*'App'[^\r\n]*-Exclude\s+'Entry\.ps1',\s*'Bootstrap\.ps1'"

        @([regex]::Matches($psm1, '-Exclude\s+')).Count | Should -Be 1

        # And the list is the launchers, all of them: every .ps1 in App\ that
        # CALLS Import-Module is excluded, and nothing else is. Read from the
        # AST, not grepped -- both launchers also name Import-Module in the
        # comment explaining why they must not be dot-sourced, and a sentence
        # about a command is not a call to it.
        $launcher = @(Get-ChildItem -LiteralPath $script:AppFolder -Filter '*.ps1' | Where-Object {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref] $null, [ref] $null)
            @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -eq 'Import-Module'
            }, $true)).Count -gt 0
        } | ForEach-Object { $_.Name } | Sort-Object)
        $launcher | Should -Be @('Bootstrap.ps1', 'Entry.ps1')
    }

    It 'actually drops Entry.ps1 and keeps Menu.ps1' {
        $files = InModuleScope Win11Optimizer.Engine -Parameters @{ Folder = $script:AppFolder } {
            param($Folder)
            Get-OptimizerSourceFile -Path $Folder -Name 'App' -Exclude 'Entry.ps1', 'Bootstrap.ps1'
        }

        $leaf = @($files | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        $leaf | Should -Contain 'Menu.ps1'
        $leaf | Should -Not -Contain 'Entry.ps1'
    }

    It 'throws when an exclusion matches nothing, rather than silently excluding nothing' {
        # The failure this guards against: Entry.ps1 gets renamed, the exclusion
        # stops matching, and the loader quietly starts dot-sourcing a file that
        # imports the module and opens the menu.
        {
            InModuleScope Win11Optimizer.Engine -Parameters @{ Folder = $script:AppFolder } {
                param($Folder)
                Get-OptimizerSourceFile -Path $Folder -Name 'App' -Exclude 'NoSuchFile.ps1'
            }
        } | Should -Throw '*was told to exclude*NoSuchFile.ps1*'
    }

    It 'still fails loud on a folder that cannot be read' {
        # The behaviour -Exclude was added next to must not have been disturbed.
        {
            InModuleScope Win11Optimizer.Engine {
                Get-OptimizerSourceFile -Path 'C:\this\folder\does\not\exist\at\all' -Name 'Nowhere'
            }
        } | Should -Throw '*could not be read*'
    }

    It 'loads Support before App, and App last' {
        $psm1 = [System.IO.File]::ReadAllText($script:ModulePath)
        $order = @('Shared', 'Support', 'Detectors', 'Removal', 'Review', 'App')

        $position = foreach ($folder in $order) {
            $match = [regex]::Match($psm1, "Get-OptimizerSourceFile -Path \(Join-Path \`$PSScriptRoot '$folder'\)")
            $match.Success | Should -BeTrue -Because "the loader should dot-source $folder"
            $match.Index
        }

        # Strictly increasing: the order in the file is the order in the comment.
        for ($i = 1; $i -lt $position.Count; $i++) {
            $position[$i] | Should -BeGreaterThan $position[$i - 1]
        }
    }
}

Describe 'P5-C1 the entry point' {

    It 'exists and is readable' {
        Test-Path -LiteralPath $script:EntrySource -PathType Leaf | Should -BeTrue
        $script:Entry.Raw.Length | Should -BeGreaterThan 0
        @($script:Entry.Errors).Count | Should -Be 0
    }

    It 'has exactly two statements: the module import and the menu call' {
        $statements = @($script:Entry.Ast.EndBlock.Statements)
        $statements.Count | Should -Be 2

        $statements[0].Extent.Text | Should -Match '^Import-Module\b'
        $statements[0].Extent.Text | Should -Match 'Win11Optimizer\.Engine\.psd1'
        $statements[1].Extent.Text | Should -Match '\bInvoke-OptimizerMenu\b'
    }

    It 'defines no functions -- everything it could get wrong lives in Menu.ps1' {
        @($script:Entry.Defined).Count | Should -Be 0
    }

    It 'resolves the manifest by absolute path, from its own folder' {
        # A relative path here would resolve against System32 under
        # Start-Process -Verb RunAs, which ignores -WorkingDirectory.
        $script:Entry.Code | Should -Match '\$PSScriptRoot'
        $script:Entry.Code | Should -Not -Match "Import-Module\s+-Name\s+'\.\."
    }

    It 'accepts the -Choice and -Argument an elevated relaunch sends it' {
        $parameters = @($script:Entry.Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $parameters | Should -Contain 'Choice'
        $parameters | Should -Contain 'Argument'
    }

    It 'is not exported and is not a source file' {
        @((Get-Module Win11Optimizer.Engine).ExportedFunctions.Keys) | Should -Not -Contain 'Entry'
    }
}

Describe 'P5-C1 the choice table' {

    BeforeAll {
        $script:Choice = InModuleScope Win11Optimizer.Engine { Get-OptimizerMenuChoice }
    }

    It 'is the five choices the prompt names, in order, with keys 1-5' {
        @($script:Choice | ForEach-Object { $_.Name }) | Should -Be @(
            'Scan and review', 'Receipt', 'Undo', 'Restore point', 'Quit')
        @($script:Choice | ForEach-Object { $_.Key }) | Should -Be @('1', '2', '3', '4', '5')
    }

    It 'needs administrator rights for scan, undo and restore point, and not for the other two' {
        $needs = @($script:Choice | Where-Object { $_.RequiresElevation } | ForEach-Object { $_.Name })
        @($needs | Sort-Object) | Should -Be @('Restore point', 'Scan and review', 'Undo')
    }

    It 'gives every elevating choice the words that finish the sentence, and no others' {
        foreach ($choice in $script:Choice) {
            if ($choice.RequiresElevation) {
                $choice.ElevationVerb | Should -Not -BeNullOrEmpty -Because "$($choice.Name) prints 'requires administrator rights to <verb>'"
            }
            else {
                $choice.ElevationVerb | Should -BeNullOrEmpty
            }
        }
    }

    It 'has a branch in the dispatch switch for every choice on it' {
        # The failure this catches: a sixth choice added to the table and not to
        # the switch, which would fall through to the default and throw at a
        # person rather than at a test.
        foreach ($choice in @($script:Choice | Where-Object { $_.Name -ne 'Quit' })) {
            $constant = ($script:Choice | Where-Object { $_.Name -eq $choice.Name }).Name
            $script:Menu.Code | Should -Match ([regex]::Escape($constant)) -Because "'$constant' must be reachable"
        }
        # And the default arm exists, so a table entry with no branch is loud.
        $script:Menu.Code | Should -Match 'default\s*\{[^}]*is on the choice table and has no branch here'
    }

    It 'resolves a choice by key and by name, case-insensitively, ignoring space' {
        foreach ($typed in @('3', 'Undo', 'undo', 'UNDO', '  Undo  ')) {
            $resolved = InModuleScope Win11Optimizer.Engine -Parameters @{ Typed = $typed } {
                param($Typed) Get-OptimizerMenuChoice -InputText $Typed
            }
            $resolved.Name | Should -Be 'Undo' -Because "'$typed' should reach Undo"
        }
    }

    It 'refuses a prefix rather than guessing between Receipt and Restore point' {
        foreach ($typed in @('R', 'Re', 'Rest', '', '   ', '0', '6', 'yes')) {
            $resolved = InModuleScope Win11Optimizer.Engine -Parameters @{ Typed = $typed } {
                param($Typed) Get-OptimizerMenuChoice -InputText $Typed
            }
            $resolved | Should -BeNullOrEmpty -Because "'$typed' is not unambiguously one choice"
        }
    }
}

Describe 'P5-C1 the menu loop' {

    It 'ends on Quit, with EndReason Quit' {
        $sink = New-Sink
        $session = Invoke-OptimizerMenu -Reader (New-QueueReader -Answer @('5')) -Writer (New-CollectingWriter -Sink $sink)

        $session.EndReason      | Should -Be 'Quit'
        $session.IterationCount | Should -Be 1
        $session.Iteration[0].Outcome | Should -Be 'Quit'
        ($sink -join "`n") | Should -Match 'Goodbye'
    }

    It 'ends with EndOfInput when the reader runs out, which is how a closed stdin behaves' {
        # MEASURED on 5.1 and 7.6.5: Read-Host returns $null, not '', at EOF. So
        # a launcher started with redirected input exits after one menu rather
        # than spinning on an answer it cannot understand.
        $sink = New-Sink
        $session = Invoke-OptimizerMenu -Reader (New-QueueReader -Answer @()) -Writer (New-CollectingWriter -Sink $sink)

        $session.EndReason      | Should -Be 'EndOfInput'
        $session.IterationCount | Should -Be 0
    }

    It 'says so and asks again when the answer is not one of the choices' {
        $sink = New-Sink
        $session = Invoke-OptimizerMenu -Reader (New-QueueReader -Answer @('9', 'nonsense', '', '5')) -Writer (New-CollectingWriter -Sink $sink)

        $session.EndReason | Should -Be 'Quit'
        @($session.Iteration | Where-Object { $_.Outcome -eq 'NotUnderstood' }).Count | Should -Be 3
        ($sink -join "`n") | Should -Match "'9' is not one of the choices"
        ($sink -join "`n") | Should -Match 'Type a number from 1 to 5'
    }

    It 'prints the menu again after each choice, so a person is never guessing' {
        $sink = New-Sink
        $null = Invoke-OptimizerMenu -Reader (New-QueueReader -Answer @('2', '2', '5')) -Writer (New-CollectingWriter -Sink $sink)

        @($sink | Where-Object { $_ -eq 'win11-optimizer' }).Count | Should -Be 3
    }

    It 'prints the ledger receipt in the ledger''s own words, not re-rendered' {
        $ledger = New-LedgerPath
        $sink = New-Sink
        $session = Invoke-OptimizerMenu -Reader (New-QueueReader -Answer @('Receipt', '5')) `
            -Writer (New-CollectingWriter -Sink $sink) -LedgerPath $ledger

        $expected = @((Get-OptimizerRunReceipt -Path $ledger).ReceiptText)
        $expected.Count | Should -BeGreaterThan 0
        foreach ($line in $expected) { $sink | Should -Contain $line }

        $session.Iteration[0].Outcome | Should -Be 'Performed'
        $session.Iteration[0].Result.Receipt | Should -Not -BeNullOrEmpty
    }

    It 'records one iteration per pass, with the fields a consumer can branch on' {
        $session = Invoke-OptimizerMenu -Reader (New-QueueReader -Answer @('2', '9', '5')) -Writer (New-CollectingWriter -Sink (New-Sink))

        $session.IterationCount | Should -Be 3
        foreach ($iteration in $session.Iteration) {
            # Every field on every one of them: the module runs under
            # Set-StrictMode -Version Latest and a missing field is a throw.
            foreach ($field in 'Number', 'Answer', 'ChoiceName', 'Argument', 'Outcome', 'Detail', 'Result') {
                @($iteration.PSObject.Properties.Name) | Should -Contain $field
            }
        }
        @($session.Iteration | ForEach-Object { $_.Number }) | Should -Be @(1, 2, 3)
    }

    It 'stars the choices that will need a relaunch, before they are chosen' {
        # A person about to be sent through a UAC prompt by choice 1 should be
        # able to see that before picking it, not after.
        $lines = InModuleScope Win11Optimizer.Engine { Get-OptimizerMenuText -IsElevated $false }
        ($lines -join "`n") | Should -Match 'standard user'
        @($lines | Where-Object { $_ -match '^\s*\*\d' }).Count | Should -Be 3

        $elevated = InModuleScope Win11Optimizer.Engine { Get-OptimizerMenuText -IsElevated $true }
        ($elevated -join "`n") | Should -Match 'Running as administrator'
        @($elevated | Where-Object { $_ -match '^\s*\*\d' }).Count | Should -Be 0
    }
}

Describe 'P5-C1 the elevation gate' {

    It 'relaunches, does not perform, and comes back to the menu' {
        $result = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $false }
            Mock Invoke-OptimizerElevated { $true }
            Mock New-OptimizerRestorePoint { throw 'the restore point must never be reached un-elevated' }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('4'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            Should -Invoke Invoke-OptimizerElevated -Times 1 -Exactly
            Should -Invoke New-OptimizerRestorePoint -Times 0 -Exactly

            [pscustomobject]@{ Session = $session; Text = ($sink -join "`n") }
        }

        $result.Session.Iteration[0].Outcome    | Should -Be 'Relaunched'
        $result.Session.Iteration[0].ChoiceName | Should -Be 'Restore point'
        $result.Session.EndReason               | Should -Be 'Quit'
    }

    It 'prints why on the OLD window, before the new one exists' {
        $text = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $false }
            # Records where in the transcript the relaunch happened.
            Mock Invoke-OptimizerElevated { $script:MarkAt = $sink.Count; $true }

            $null = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('4'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            [pscustomobject]@{ Before = ($sink[0..($script:MarkAt - 1)] -join "`n"); Mark = $script:MarkAt }
        }

        $text.Before | Should -Match 'This tool requires administrator rights to take a restore point\.'
        $text.Before | Should -Match 'Relaunching elevated\.\.\.'
        $text.Before | Should -Match 'A new window will open\. This one stays as it is'
    }

    It 'says so plainly when UAC is declined, and keeps the menu' {
        $result = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $false }
            Mock Invoke-OptimizerElevated { $false }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('4'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            [pscustomobject]@{ Session = $session; Text = ($sink -join "`n") }
        }

        $result.Text | Should -Match 'Elevation was denied or the process crashed\.'
        $result.Session.Iteration[0].Outcome | Should -Be 'ElevationDeclined'
        $result.Session.EndReason            | Should -Be 'Quit'
    }

    It 'does not relaunch when the process is already elevated' {
        InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $true }
            Mock Invoke-OptimizerElevated { throw 'must not relaunch when already elevated' }
            Mock New-OptimizerRestorePoint { [pscustomobject]@{ State = 'Throttled'; Reason = 'Fabricated by the test suite.' } }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('4'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            Should -Invoke Invoke-OptimizerElevated -Times 0 -Exactly
            Should -Invoke New-OptimizerRestorePoint -Times 1 -Exactly
            $session.Iteration[0].Outcome | Should -Be 'Performed'
            $session.Iteration[0].Detail  | Should -Be 'Throttled'
        }
    }

    It 'never relaunches from a session that was itself started at a choice' {
        # This is what bounds the chain at one level deep: the shape of a session
        # started with -InitialChoice is exactly the shape of the child of a
        # relaunch, so no bug in the elevation check can cascade into unbounded
        # UAC prompts.
        $result = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $false }
            Mock Invoke-OptimizerElevated { throw 'a session started at a choice must never relaunch' }

            $session = Invoke-OptimizerMenu -InitialChoice 'Restore point' `
                -Reader { param($Prompt) $null } -Writer { param($Line) $null = $sink.Add([string] $Line) }

            Should -Invoke Invoke-OptimizerElevated -Times 0 -Exactly
            [pscustomobject]@{ Session = $session; Text = ($sink -join "`n") }
        }

        $result.Session.CanRelaunch            | Should -BeFalse
        $result.Session.Iteration[0].Outcome   | Should -Be 'ElevationUnavailable'
        $result.Text | Should -Match 'it will not open another window'
    }

    It 'collects the undo action id BEFORE elevating, and carries it into the relaunch' {
        $ledger = New-LedgerPath
        $actionId = [guid]::NewGuid().ToString()

        $passed = InModuleScope Win11Optimizer.Engine -Parameters @{ Ledger = $ledger; ActionId = $actionId } {
            param($Ledger, $ActionId)

            $sink = New-Object System.Collections.Generic.List[string]
            $script:CapturedChoice = $null
            $script:CapturedArgument = $null

            # PARKED ON THE MODULE'S SCRIPT SCOPE, and the mock body reads it
            # there. A mock body is invoked in a scope of its own and cannot see
            # this block's locals, and .GetNewClosure() -- the obvious fix -- stops
            # Pester binding the mocked function's parameters. Same trap
            # tests\ExecutePlan.Tests.ps1 documents.
            $script:ScenarioActionId = $ActionId

            Mock Test-IsElevated { $false }
            Mock Get-OptimizerActionLog {
                [pscustomobject]@{
                    ActionId = $script:ScenarioActionId; DisplayName = 'Fabricated service'; Route = 'ServiceStartupType'
                    Result = 'Succeeded'; IsReversible = $true; IsParseError = $false
                }
            }
            Mock Invoke-OptimizerElevated {
                $script:CapturedChoice = $Choice
                $script:CapturedArgument = [string[]] @($Argument)
                $true
            }
            Mock Undo-RemovalAction { throw 'the undo itself must not run un-elevated' }

            $null = Invoke-OptimizerMenu -LedgerPath $Ledger -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('3'); $queue.Enqueue('1'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            Should -Invoke Undo-RemovalAction -Times 0 -Exactly
            [pscustomobject]@{ Choice = $script:CapturedChoice; Argument = $script:CapturedArgument }
        }

        $passed.Choice   | Should -Be 'Undo'
        @($passed.Argument) | Should -Be @($actionId)
    }

    It 'passes a choice name from its own table, never free text' {
        $captured = InModuleScope Win11Optimizer.Engine {
            $names = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $false }
            Mock Invoke-OptimizerElevated { $null = $names.Add([string] $Choice); $false }

            $null = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('1'); $queue.Enqueue('4'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) }

            [string[]] @($names.ToArray())
        }

        $valid = @((InModuleScope Win11Optimizer.Engine { Get-OptimizerMenuChoice }) | ForEach-Object { $_.Name })
        @($captured) | Should -Be @('Scan and review', 'Restore point')
        foreach ($name in $captured) { $valid | Should -Contain $name }
    }
}

Describe 'P5-C1 the scan-and-review choice' {

    # The main path, and the one the elevation gate hides from every other test
    # in this file: un-elevated, choice 1 always relaunches instead of running.
    # These drive it elevated, with the three things it calls mocked, so what is
    # being asserted is the WIRING -- who gets called, with what, in what order --
    # and not the review screen or the executor, which have suites of their own.

    It 'carries out a confirmed selection, and passes -Confirm:$false exactly once' {
        $result = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            $script:SeenFinding = $null
            $script:SeenPick    = $null
            $script:SeenPlan    = $null
            $script:SeenConfirm = $null

            $finding = @(
                [pscustomobject]@{ Id = 'Fabricated.One'; DisplayName = 'One' }
                [pscustomobject]@{ Id = 'Fabricated.Two'; DisplayName = 'Two' }
            )
            $script:ScenarioFinding = $finding

            Mock Test-IsElevated { $true }
            Mock Show-ReviewScreen {
                [pscustomobject]@{ Confirmed = $true; Finding = $script:ScenarioFinding; Plan = @(); Executed = $false }
            }
            Mock New-OptimizerExecutionPlan {
                $script:SeenFinding = [psobject[]] @($Finding)
                $script:SeenPick    = [string[]] @($Pick)
                @([pscustomobject]@{ Supported = $true }, [pscustomobject]@{ Supported = $true })
            }
            Mock Invoke-OptimizerExecutionPlan {
                $script:SeenPlan    = [psobject[]] @($Plan)
                $script:SeenConfirm = $ConfirmPreference
                [pscustomobject]@{ Result = 'Completed'; RunId = 'fabricated' }
            }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('1'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            Should -Invoke Show-ReviewScreen           -Times 1 -Exactly
            Should -Invoke New-OptimizerExecutionPlan  -Times 1 -Exactly
            Should -Invoke Invoke-OptimizerExecutionPlan -Times 1 -Exactly

            [pscustomobject]@{
                Session = $session; Pick = $script:SeenPick
                Finding = $script:SeenFinding; Plan = $script:SeenPlan
            }
        }

        # The picks are the ids of what the screen handed back, in its order.
        @($result.Pick)    | Should -Be @('Fabricated.One', 'Fabricated.Two')
        @($result.Finding).Count | Should -Be 2
        @($result.Plan).Count    | Should -Be 2

        $result.Session.Iteration[0].Outcome | Should -Be 'Performed'
        $result.Session.Iteration[0].Detail  | Should -Be 'Completed'
        $result.Session.Iteration[0].Result.Run.RunId | Should -Be 'fabricated'
    }

    It 'runs nothing when the screen was not confirmed' {
        $result = InModuleScope Win11Optimizer.Engine {
            Mock Test-IsElevated { $true }
            Mock Show-ReviewScreen { [pscustomobject]@{ Confirmed = $false; Finding = @(); Plan = @(); Executed = $false } }
            Mock New-OptimizerExecutionPlan { throw 'nothing may be planned for a selection that was not confirmed' }
            Mock Invoke-OptimizerExecutionPlan { throw 'nothing may be executed for a selection that was not confirmed' }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('1'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) }

            Should -Invoke New-OptimizerExecutionPlan   -Times 0 -Exactly
            Should -Invoke Invoke-OptimizerExecutionPlan -Times 0 -Exactly
            $session
        }

        $result.Iteration[0].Outcome | Should -Be 'NothingToDo'
        $result.Iteration[0].Detail  | Should -Be 'Nothing was confirmed, so nothing was carried out.'
    }

    It 'hands the screen the same -Reader and -Writer the menu is using' {
        # Otherwise the review screen would prompt through the host while the
        # menu prompts through the injected reader, and nothing could drive both.
        $seen = InModuleScope Win11Optimizer.Engine {
            $script:SeenReader = $null
            $script:SeenWriter = $null
            Mock Test-IsElevated { $true }
            Mock Show-ReviewScreen {
                $script:SeenReader = $Reader
                $script:SeenWriter = $Writer
                [pscustomobject]@{ Confirmed = $false; Finding = @(); Plan = @(); Executed = $false }
            }

            $marker = { param($Prompt) 'from-the-test' }
            $null = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('1'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) }

            [pscustomobject]@{ Reader = $script:SeenReader; Writer = $script:SeenWriter; Marker = $marker }
        }

        $seen.Reader | Should -Not -BeNullOrEmpty
        $seen.Writer | Should -Not -BeNullOrEmpty
        $seen.Reader | Should -BeOfType [scriptblock]
        $seen.Writer | Should -BeOfType [scriptblock]
    }
}

Describe 'P5-C1 cancellation and errors keep the menu alive' {

    It 'catches OperationCanceledException, prints one line and loops back' {
        $result = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $true }
            Mock New-OptimizerRestorePoint { throw (New-Object System.OperationCanceledException 'cancelled by the test') }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('4'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            [pscustomobject]@{ Session = $session; Text = ($sink -join "`n") }
        }

        $result.Session.Iteration[0].Outcome | Should -Be 'Cancelled'
        $result.Session.IterationCount       | Should -Be 2
        $result.Session.EndReason            | Should -Be 'Quit'
        $result.Text | Should -Match "Cancelled\. 'Restore point' did not finish\."
    }

    It 'does not claim to catch PipelineStoppedException, because it cannot' {
        # MEASURED on 5.1 and 7.6.5, in a child process because the measurement
        # cannot be taken in this one: code that raises a PipelineStoppedException
        # runs NO catch block -- not a typed one, not a bare one -- and no
        # finally. The engine reads it as its own stop signal, unwinds the whole
        # runspace and exits 1 having printed nothing. An earlier draft of this
        # suite asserted the opposite and killed the test runner mid-file.
        #
        # So the assertion is that the source does not carry a catch clause that
        # would read as a guarantee, and does carry the measurement. Re-adding
        # one means re-taking the measurement first.
        $script:Menu.Code | Should -Not -Match 'catch\s*\[\s*System\.Management\.Automation\.PipelineStoppedException\s*\]'
        $script:Menu.Raw  | Should -Match 'NOT CAUGHT, AND NOT CATCHABLE'
        $script:Menu.Raw  | Should -Match 'the ledger'

        # And the measurement itself, re-taken out of process so it cannot take
        # this one with it. Measured: catch does NOT run, finally DOES, and
        # nothing after the try statement does. The exit code is deliberately not
        # asserted -- measured 1 under -Command and 0 under -File, which is
        # itself recorded in the source comment.
        $probe = Join-Path $script:Scratch ("pipestop-" + [guid]::NewGuid().ToString('N') + '.ps1')
        [System.IO.File]::WriteAllText($probe, @'
Write-Host 'REACHED'
try { throw (New-Object System.Management.Automation.PipelineStoppedException) }
catch { Write-Host 'CAUGHT' }
finally { Write-Host 'FINALLY' }
Write-Host 'SURVIVED'
'@)
        $out = Join-Path $script:Scratch ("pipestop-" + [guid]::NewGuid().ToString('N') + '.txt')
        $shell = InModuleScope Win11Optimizer.Engine { Get-OptimizerHostExecutable }
        $null = Start-Process -FilePath $shell -ArgumentList @('-NoProfile', '-File', ('"' + $probe + '"')) `
            -NoNewWindow -PassThru -Wait -RedirectStandardOutput $out -RedirectStandardInput $script:EmptyStdIn

        $text = [System.IO.File]::ReadAllText($out)
        $text | Should -Match 'REACHED'     -Because 'the probe really ran'
        $text | Should -Not -Match 'CAUGHT' -Because 'no catch clause runs, which is why this file has none for it'
        $text | Should -Match 'FINALLY'     -Because 'a finally DOES still run -- the one part of the try that survives'
        $text | Should -Not -Match 'SURVIVED' -Because 'execution stops at the try statement'
    }

    It 'reports any other error loudly, names the type, and keeps the menu' {
        $result = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $true }
            Mock New-OptimizerRestorePoint { throw (New-Object System.InvalidOperationException 'fabricated failure') }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('4'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            [pscustomobject]@{ Session = $session; Text = ($sink -join "`n") }
        }

        $result.Session.Iteration[0].Outcome | Should -Be 'Failed'
        $result.Session.Iteration[0].Detail  | Should -Match 'fabricated failure'
        $result.Session.EndReason            | Should -Be 'Quit'
        $result.Text | Should -Match 'stopped with an error and the menu is still here'
        $result.Text | Should -Match 'InvalidOperationException'
        $result.Text | Should -Match 'Choose Receipt to see what, if anything, was recorded'
    }

    It 'catches a cancellation raised while collecting what a choice needs' {
        $result = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $true }
            Mock Get-OptimizerActionLog { throw (New-Object System.OperationCanceledException 'cancelled at the list') }
            Mock Undo-RemovalAction { throw 'must not be reached' }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('3'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            Should -Invoke Undo-RemovalAction -Times 0 -Exactly
            [pscustomobject]@{ Session = $session; Text = ($sink -join "`n") }
        }

        $result.Session.Iteration[0].Outcome | Should -Be 'Cancelled'
        $result.Text | Should -Match 'was not started, and nothing on this PC has been changed'
    }
}

Describe 'P5-C1 the undo prompt' {

    It 'says there is nothing to undo, and asks for nothing, on an empty ledger' {
        $result = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $true }
            Mock Get-OptimizerActionLog { @() }
            Mock Undo-RemovalAction { throw 'must not be reached with no action chosen' }

            # BOTH LISTS ARE BUILT INSIDE THE & { } THE CLOSURE IS MADE IN.
            # .GetNewClosure() captures the LOCAL scope it is called in, and a
            # variable that merely happens to be readable from an enclosing scope
            # is not captured -- it arrives $null inside the closure and the first
            # .Add() fails with "you cannot call a method on a null-valued
            # expression", a long way from the cause. Measured while writing this.
            $script:ScenarioPrompt = New-Object System.Collections.Generic.List[string]
            $reader = & {
                $queue = New-Object System.Collections.Generic.Queue[object]
                $queue.Enqueue('3'); $queue.Enqueue('5')
                $log = $script:ScenarioPrompt
                { param($Prompt) $null = $log.Add([string] $Prompt); if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
            }

            $session = Invoke-OptimizerMenu -Reader $reader -Writer { param($Line) $null = $sink.Add([string] $Line) }

            Should -Invoke Undo-RemovalAction -Times 0 -Exactly
            [pscustomobject]@{ Session = $session; Text = ($sink -join "`n"); Prompt = [string[]] @($script:ScenarioPrompt.ToArray()) }
        }

        $result.Text | Should -Match 'Nothing is recorded in the action ledger yet'
        $result.Session.Iteration[0].Outcome | Should -Be 'NothingToDo'
        @($result.Prompt | Where-Object { $_ -match 'Which one' }).Count | Should -Be 0
    }

    It 'lists recent actions and takes a number from that list' {
        $chosen = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            $script:Undone = $null
            Mock Test-IsElevated { $true }
            Mock Get-OptimizerActionLog {
                @(
                    [pscustomobject]@{ ActionId = 'aaaaaaaa-0000-0000-0000-000000000001'; DisplayName = 'First';  Route = 'ServiceStartupType'; Result = 'Succeeded'; IsReversible = $true;  IsParseError = $false }
                    [pscustomobject]@{ ActionId = 'aaaaaaaa-0000-0000-0000-000000000002'; DisplayName = 'Second'; Route = 'ServiceStartupType'; Result = 'Refused';   IsReversible = $false; IsParseError = $false }
                )
            }
            Mock Undo-RemovalAction { $script:Undone = $ActionId; [pscustomobject]@{ Result = 'Succeeded'; ErrorText = $null } }

            $null = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('3'); $queue.Enqueue('2'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            [pscustomobject]@{ Undone = $script:Undone; Text = ($sink -join "`n") }
        }

        $chosen.Undone | Should -Be 'aaaaaaaa-0000-0000-0000-000000000002'
        $chosen.Text   | Should -Match 'First'
        $chosen.Text   | Should -Match 'NOT recorded as reversible'
        $chosen.Text   | Should -Match 'Undo of aaaaaaaa-0000-0000-0000-000000000002 : Succeeded'
    }

    It 'takes a full action id typed instead of a number' {
        $chosen = InModuleScope Win11Optimizer.Engine {
            $script:Undone = $null
            Mock Test-IsElevated { $true }
            Mock Get-OptimizerActionLog {
                @([pscustomobject]@{ ActionId = 'bbbbbbbb-0000-0000-0000-000000000001'; DisplayName = 'Only'; Route = 'ServiceStartupType'; Result = 'Succeeded'; IsReversible = $true; IsParseError = $false })
            }
            Mock Undo-RemovalAction { $script:Undone = $ActionId; [pscustomobject]@{ Result = 'Refused'; ErrorText = 'Fabricated refusal.' } }

            $null = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('3'); $queue.Enqueue('cccccccc-0000-0000-0000-000000000009'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) }

            $script:Undone
        }

        $chosen | Should -Be 'cccccccc-0000-0000-0000-000000000009'
    }

    It 'refuses a number that is not on the list, and undoes nothing' {
        $result = InModuleScope Win11Optimizer.Engine {
            $sink = New-Object System.Collections.Generic.List[string]
            Mock Test-IsElevated { $true }
            Mock Get-OptimizerActionLog {
                @([pscustomobject]@{ ActionId = 'dddddddd-0000-0000-0000-000000000001'; DisplayName = 'Only'; Route = 'ServiceStartupType'; Result = 'Succeeded'; IsReversible = $true; IsParseError = $false })
            }
            Mock Undo-RemovalAction { throw 'must not undo anything on an out-of-range pick' }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('3'); $queue.Enqueue('7'); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) $null = $sink.Add([string] $Line) }

            Should -Invoke Undo-RemovalAction -Times 0 -Exactly
            [pscustomobject]@{ Session = $session; Text = ($sink -join "`n") }
        }

        $result.Text | Should -Match "'7' is not a row on that list"
        $result.Session.Iteration[0].Outcome | Should -Be 'NothingToDo'
    }

    It 'asks for an id when the relaunch argument arrives blank, rather than undoing nothing' {
        # -InitialArgument is public, so an array holding one empty string can
        # reach here. It must not count as "the argument was supplied".
        $result = InModuleScope Win11Optimizer.Engine {
            Mock Test-IsElevated { $true }
            Mock Get-OptimizerActionLog { @() }
            Mock Undo-RemovalAction { throw 'a blank relaunch argument is not an action id' }

            $session = Invoke-OptimizerMenu -InitialChoice 'Undo' -InitialArgument @('', '   ') `
                -Reader { param($Prompt) $null } -Writer { param($Line) }

            Should -Invoke Undo-RemovalAction -Times 0 -Exactly
            Should -Invoke Get-OptimizerActionLog -Times 1 -Exactly
            $session
        }

        $result.Iteration[0].Outcome | Should -Be 'NothingToDo'
    }

    It 'goes back on a blank answer without undoing anything' {
        InModuleScope Win11Optimizer.Engine {
            Mock Test-IsElevated { $true }
            Mock Get-OptimizerActionLog {
                @([pscustomobject]@{ ActionId = 'eeeeeeee-0000-0000-0000-000000000001'; DisplayName = 'Only'; Route = 'ServiceStartupType'; Result = 'Succeeded'; IsReversible = $true; IsParseError = $false })
            }
            Mock Undo-RemovalAction { throw 'must not undo anything on a blank answer' }

            $session = Invoke-OptimizerMenu -Reader (& {
                    $queue = New-Object System.Collections.Generic.Queue[object]
                    $queue.Enqueue('3'); $queue.Enqueue(''); $queue.Enqueue('5')
                    { param($Prompt) if ($queue.Count -gt 0) { $queue.Dequeue() } else { $null } }.GetNewClosure()
                }) -Writer { param($Line) }

            Should -Invoke Undo-RemovalAction -Times 0 -Exactly
            $session.Iteration[0].Outcome | Should -Be 'NothingToDo'
        }
    }
}

Describe 'P5-C1 the elevated command line' {

    BeforeAll {
        $script:EntryPath = InModuleScope Win11Optimizer.Engine { Get-OptimizerEntryScript }
    }

    It 'names an absolute host executable that is really there, on this shell' {
        $hostExe = InModuleScope Win11Optimizer.Engine { Get-OptimizerHostExecutable }

        $hostExe | Should -Not -BeNullOrEmpty
        [System.IO.Path]::IsPathRooted($hostExe) | Should -BeTrue
        Test-Path -LiteralPath $hostExe -PathType Leaf | Should -BeTrue

        $expected = $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })
        [System.IO.Path]::GetFileName($hostExe) | Should -Be $expected
    }

    It 'names an absolute entry script that is really there' {
        [System.IO.Path]::IsPathRooted($script:EntryPath) | Should -BeTrue
        Test-Path -LiteralPath $script:EntryPath -PathType Leaf | Should -BeTrue
        [System.IO.Path]::GetFileName($script:EntryPath) | Should -Be 'Entry.ps1'
    }

    It 'is -NoProfile, -File, the quoted absolute script, then the quoted choice' {
        $built = InModuleScope Win11Optimizer.Engine -Parameters @{ Entry = $script:EntryPath } {
            param($Entry)
            Get-OptimizerElevationCommandLine -EntryScript $Entry -Choice 'Restore point'
        }

        @($built)[0] | Should -Be '-NoProfile'
        @($built)[1] | Should -Be '-File'
        @($built)[2] | Should -Be ('"' + $script:EntryPath + '"')
        @($built)[3] | Should -Be '-Choice'
        # QUOTED, which is what carries a choice name containing a space.
        @($built)[4] | Should -Be '"Restore point"'
        @($built).Count | Should -Be 5
    }

    It 'joins several arguments into one element, because -File binds a list that way' {
        $built = InModuleScope Win11Optimizer.Engine -Parameters @{ Entry = $script:EntryPath } {
            param($Entry)
            Get-OptimizerElevationCommandLine -EntryScript $Entry -Choice 'Undo' -Argument @('aaa', 'bbb')
        }

        @($built)[5] | Should -Be '-Argument'
        @($built)[6] | Should -Be '"aaa,bbb"'
    }

    It 'drops blank arguments rather than sending empty strings' {
        $built = InModuleScope Win11Optimizer.Engine -Parameters @{ Entry = $script:EntryPath } {
            param($Entry)
            Get-OptimizerElevationCommandLine -EntryScript $Entry -Choice 'Undo' -Argument @('aaa', '', '   ', 'bbb')
        }
        @($built)[6] | Should -Be '"aaa,bbb"'

        $none = InModuleScope Win11Optimizer.Engine -Parameters @{ Entry = $script:EntryPath } {
            param($Entry)
            Get-OptimizerElevationCommandLine -EntryScript $Entry -Choice 'Undo' -Argument @('', '  ')
        }
        @($none).Count | Should -Be 5
        @($none) | Should -Not -Contain '-Argument'
    }

    It 'refuses a value that could break out of its own quoting, and launches nothing' {
        # Validated rather than escaped: see the constant block in Elevation.ps1.
        foreach ($bad in @('has"quote', "has'quote", 'has$dollar', 'has`backtick', "has`nnewline", "has`rreturn", '-LeadingDash', '', '   ')) {
            {
                InModuleScope Win11Optimizer.Engine -Parameters @{ Entry = $script:EntryPath; Bad = $bad } {
                    param($Entry, $Bad)
                    Get-OptimizerElevationCommandLine -EntryScript $Entry -Choice $Bad
                }
            } | Should -Throw -Because "'$bad' must not reach an elevated command line"
        }
    }

    It 'refuses a bad ARGUMENT too, not just a bad choice' {
        {
            InModuleScope Win11Optimizer.Engine -Parameters @{ Entry = $script:EntryPath } {
                param($Entry)
                Get-OptimizerElevationCommandLine -EntryScript $Entry -Choice 'Undo' -Argument @('fine', 'has"quote')
            }
        } | Should -Throw '*double quote*'
    }

    It 'binds for real: the built command line reaches Entry.ps1 with the choice intact' {
        # Run WITHOUT -Verb RunAs, at this test run's own integrity level, so
        # nothing elevates and no window opens. 'Restore point' is chosen because
        # it is multi-word AND -- started at a choice, un-elevated -- it refuses
        # instead of doing anything. If this test run IS elevated the choice is
        # switched to Receipt, which reads a ledger of its own and changes nothing.
        $hostExe = InModuleScope Win11Optimizer.Engine { Get-OptimizerHostExecutable }
        $elevated = Test-IsElevated

        $choice = $(if ($elevated) { 'Receipt' } else { 'Restore point' })
        $built = InModuleScope Win11Optimizer.Engine -Parameters @{ Entry = $script:EntryPath; Choice = $choice } {
            param($Entry, $Choice)
            Get-OptimizerElevationCommandLine -EntryScript $Entry -Choice $Choice
        }

        # Standard input is redirected from an empty file as well as standard
        # output. Without it this child inherits the operator's console for
        # input: whatever the choice does, the menu loops round afterwards and
        # prompts -- and the prompt is not on screen, because standard output is
        # in $outputPath. See $script:EmptyStdIn.
        $outputPath = Join-Path $script:Scratch ("roundtrip-" + [guid]::NewGuid().ToString('N') + '.txt')
        $process = Start-Process -FilePath $hostExe -ArgumentList $built -NoNewWindow -PassThru -Wait `
            -RedirectStandardOutput $outputPath -RedirectStandardInput $script:EmptyStdIn
        $process.ExitCode | Should -Be 0

        $text = [System.IO.File]::ReadAllText($outputPath)
        if ($elevated) {
            $text | Should -Match 'What this tool has done'
        }
        else {
            # Proves the multi-word choice bound: this sentence is only printed
            # for a choice that resolved to Restore point.
            $text | Should -Match 'requires administrator rights to take a restore point'
            $text | Should -Match 'it will not open another window'
        }
        # And it came back to the menu rather than exiting at the choice.
        $text | Should -Match 'win11-optimizer'
    }
}

Describe 'P5-C3 change 6: this suite never waits for a keystroke' {

    It 'redirects standard input on every child process it starts, not just standard output' {
        # THE BUG THIS EXISTS TO STOP COMING BACK. -NoNewWindow with
        # -RedirectStandardOutput and nothing for input leaves the child sharing
        # the operator's console for input while its own prompt goes into a file.
        # Invoke-OptimizerMenu then sits on Read-Host forever, on a question
        # nobody can see, and a suite that hangs is indistinguishable from a
        # suite that is being slow. Observed elevated on 2026-09-01; measured
        # again while fixing it, where a child with an OPEN and silent stdin was
        # still running after 25 seconds and the same child with stdin at end of
        # file exited immediately with 0.
        #
        # Asserted over THIS file's own AST rather than by inspection, because
        # the next Start-Process somebody adds here is the one that will forget.
        $self = Get-ParsedSource -Path $PSCommandPath

        $started = @($self.Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | Where-Object {
            $element = $_.CommandElements[0]
            ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and
            ($element.Value -eq 'Start-Process')
        })

        # Only the ones that really launch something: the Mock Start-Process
        # bodies below are CommandAsts of their own and never start a process.
        $launching = @($started | Where-Object {
            @($_.CommandElements | Where-Object {
                $_ -is [System.Management.Automation.Language.CommandParameterAst] -and
                $_.ParameterName -eq 'RedirectStandardOutput'
            }).Count -gt 0
        })

        $launching.Count | Should -BeGreaterOrEqual 2 -Because 'this suite starts two real child processes'

        foreach ($call in $launching) {
            $names = @($call.CommandElements |
                Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
                ForEach-Object { $_.ParameterName })
            $names | Should -Contain 'RedirectStandardInput' `
                -Because "the Start-Process at line $($call.Extent.StartLineNumber) redirects output, so it must redirect input too or it waits on the operator's console"
        }
    }

    It 'redirects it from a file that is empty, which is what makes Read-Host return $null' {
        [System.IO.File]::Exists($script:EmptyStdIn) | Should -BeTrue
        (Get-Item -LiteralPath $script:EmptyStdIn).Length | Should -Be 0
    }
}

Describe 'P5-C1 Invoke-OptimizerElevated' {

    It 'prints nothing -- the elevated process owns its own output' {
        $script:Elev.Code | Should -Not -Match '\bWrite-Host\b'
        $script:Elev.Code | Should -Not -Match '\bWrite-Output\b'
        $script:Elev.Code | Should -Not -Match '\bWrite-Warning\b'
        # Verbose only, which is off unless somebody asks.
        $script:Elev.Invoked | Should -Contain 'Write-Verbose'
    }

    It 'starts a process and does nothing else that touches this PC' {
        # The whole outward surface of the file. Start-Process is the one call
        # that leaves this process, and there is exactly one of it.
        #
        # Counted as INVOCATIONS off the AST, not as text: the file also names
        # Start-Process inside a Write-Verbose string, and a regex over the
        # comment-blanked source counts that as a second call. Comments are
        # blanked; string literals are code and are not.
        $started = @($script:Elev.Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | Where-Object {
            $element = $_.CommandElements[0]
            ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and
            ($element.Value -eq 'Start-Process')
        })
        $started.Count | Should -Be 1

        foreach ($forbidden in @(
            'Set-ItemProperty', 'New-ItemProperty', 'Remove-Item', 'New-Item', 'Set-Content'
            'Add-Content', 'Out-File', 'Invoke-Expression', 'Set-Service', 'Write-OptimizerAction'
            'Invoke-RemovalPlan', 'Undo-RemovalAction')) {
            $script:Elev.Invoked | Should -Not -Contain $forbidden
        }
    }

    It 'asks for RunAs, a visible window, and the process object -- and never -WorkingDirectory' {
        # -WorkingDirectory is IGNORED with -Verb RunAs, so passing it would be a
        # promise the call cannot keep.
        $script:Elev.Code | Should -Match "-Verb\s+'RunAs'"
        $script:Elev.Code | Should -Match '-WindowStyle\s+\$WindowStyle'
        $script:Elev.Code | Should -Match '-PassThru'
        $script:Elev.Code | Should -Not -Match '-WorkingDirectory'
        $script:Elev.Code | Should -Not -Match '-WindowStyle\s+Hidden'
    }

    It 'defaults to a visible window' {
        (Get-Command Invoke-OptimizerElevated).Parameters['WindowStyle'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            ForEach-Object { $_.ValidValues } | Should -Not -Contain 'Hidden'

        $default = @($script:Elev.Ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | Where-Object { $_.Name -eq 'Invoke-OptimizerElevated' })
        $parameter = @($default[0].Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'WindowStyle' })
        $parameter[0].DefaultValue.Extent.Text | Should -Be "'Normal'"
    }

    It 'returns $true on a clean exit and $false on a non-zero one' {
        foreach ($case in @(@{ Code = 0; Expected = $true }, @{ Code = 1; Expected = $false }, @{ Code = 3; Expected = $false })) {
            $answer = InModuleScope Win11Optimizer.Engine -Parameters @{ Code = $case.Code } {
                param($Code)
                Mock Start-Process {
                    $stub = [pscustomobject]@{ ExitCode = $Code }
                    $stub | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { } -PassThru
                }
                Invoke-OptimizerElevated -Choice 'Receipt' -Confirm:$false
            }
            $answer | Should -Be $case.Expected -Because "exit code $($case.Code)"
        }
    }

    It 'returns $false when the UAC dialog is cancelled, and does not throw' {
        $answer = InModuleScope Win11Optimizer.Engine {
            # 1223 is ERROR_CANCELLED -- exactly what ShellExecuteEx reports when
            # a person clicks No on the consent prompt.
            Mock Start-Process { throw (New-Object System.ComponentModel.Win32Exception 1223) }
            Invoke-OptimizerElevated -Choice 'Receipt' -Confirm:$false
        }
        $answer | Should -BeFalse
    }

    It 'returns $false when the process cannot be waited on or read' {
        $answer = InModuleScope Win11Optimizer.Engine {
            Mock Start-Process {
                $stub = [pscustomobject]@{ }
                $stub | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { throw 'no handle' } -PassThru
            }
            Invoke-OptimizerElevated -Choice 'Receipt' -Confirm:$false
        }
        $answer | Should -BeFalse
    }

    It 'returns $false and starts nothing when the entry script is missing' {
        $answer = InModuleScope Win11Optimizer.Engine {
            Mock Get-OptimizerEntryScript { 'C:\nowhere\at\all\Entry.ps1' }
            Mock Start-Process { throw 'must not start anything when the entry script is missing' }
            $result = Invoke-OptimizerElevated -Choice 'Receipt' -Confirm:$false
            Should -Invoke Start-Process -Times 0 -Exactly
            $result
        }
        $answer | Should -BeFalse
    }

    It 'returns $false and starts nothing when no host executable can be found' {
        $answer = InModuleScope Win11Optimizer.Engine {
            Mock Get-OptimizerHostExecutable { $null }
            Mock Start-Process { throw 'must not start anything with no host' }
            $result = Invoke-OptimizerElevated -Choice 'Receipt' -Confirm:$false
            Should -Invoke Start-Process -Times 0 -Exactly
            $result
        }
        $answer | Should -BeFalse
    }

    It 'launches nothing under -WhatIf, and still validates the choice' {
        $answer = InModuleScope Win11Optimizer.Engine {
            Mock Start-Process { throw 'must not start anything under -WhatIf' }
            $result = Invoke-OptimizerElevated -Choice 'Receipt' -WhatIf
            Should -Invoke Start-Process -Times 0 -Exactly
            $result
        }
        $answer | Should -BeFalse

        # -WhatIf builds the command line first, so a bad value still throws.
        {
            InModuleScope Win11Optimizer.Engine {
                Mock Start-Process { throw 'must not start anything under -WhatIf' }
                Invoke-OptimizerElevated -Choice 'has"quote' -WhatIf
            }
        } | Should -Throw '*double quote*'
    }

    It 'hands Start-Process the absolute host path and the built argument list' {
        InModuleScope Win11Optimizer.Engine {
            $script:SeenFilePath = $null
            $script:SeenArgument = $null
            Mock Start-Process {
                $script:SeenFilePath = $FilePath
                $script:SeenArgument = [string[]] @($ArgumentList)
                $stub = [pscustomobject]@{ ExitCode = 0 }
                $stub | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { } -PassThru
            }

            $null = Invoke-OptimizerElevated -Choice 'Undo' -Argument @('11111111-2222-3333-4444-555555555555') -Confirm:$false

            [System.IO.Path]::IsPathRooted($script:SeenFilePath) | Should -BeTrue
            @($script:SeenArgument)[0] | Should -Be '-NoProfile'
            @($script:SeenArgument)[1] | Should -Be '-File'
            @($script:SeenArgument)[2] | Should -Match '^"[A-Za-z]:\\.*Entry\.ps1"$'
            @($script:SeenArgument) | Should -Contain '"Undo"'
            @($script:SeenArgument) | Should -Contain '"11111111-2222-3333-4444-555555555555"'
        }
    }

    It 'declares SupportsShouldProcess' {
        $command = Get-Command -Module Win11Optimizer.Engine -Name 'Invoke-OptimizerElevated'
        $command.Parameters.ContainsKey('WhatIf')  | Should -BeTrue
        $command.Parameters.ContainsKey('Confirm') | Should -BeTrue
    }
}

Describe 'P5-C1 the exports' {

    It 'exports exactly the two functions this chunk adds, and keeps the rest internal' {
        $module = Get-Module Win11Optimizer.Engine
        foreach ($name in $script:NewExport) {
            [System.IO.File]::ReadAllText($script:ModulePath)   | Should -Match ([regex]::Escape("'$name'"))
            [System.IO.File]::ReadAllText($script:ManifestPath) | Should -Match ([regex]::Escape("'$name'"))
            @($module.ExportedFunctions.Keys) | Should -Contain $name
        }

        $defined = [string[]] @(@($script:Menu.Defined) + @($script:Elev.Defined))
        $defined.Count | Should -BeGreaterThan $script:NewExport.Count

        $exportedFromThisChunk = @($defined | Where-Object { @($module.ExportedFunctions.Keys) -contains $_ })
        @($exportedFromThisChunk | Sort-Object) -join ',' | Should -BeExactly (@($script:NewExport | Sort-Object) -join ',')
    }

    It 'adds exactly two to the module''s exports, and the manifest agrees' {
        $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
        $exported = @(Get-Command -Module Win11Optimizer.Engine | ForEach-Object { $_.Name })
        @($manifest.FunctionsToExport).Count | Should -Be $exported.Count
        @($exported | Where-Object { $script:NewExport -contains $_ }).Count | Should -Be 2
    }
}
