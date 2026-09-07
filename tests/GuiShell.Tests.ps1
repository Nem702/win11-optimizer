#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The GUI shell -- chunk P6-C2.

    THIS FILE IS WHY "GREEN ON BOTH SHELLS" AND "THE GUI'S LOGIC IS TESTED" ARE
    ONE ANSWER. docs\handoff\21-gui-scaffold.md draws the testing line at the
    C# data layer: parsing, view models, selection, and anything about what is
    refused or held back is tested in C#, and rendering is checked by eye. Those
    C# results do not get to live in a second place with a second command and a
    second count. This suite runs them and turns every one into an It, so
    tests\Invoke-Tests.ps1 reports one number.

    HOW IT IS WIRED. The C# tests are run during Pester's DISCOVERY phase and
    the .trx they produce is turned into a -ForEach list, one entry per C# test.
    That is the same idiom tests\MsiPackaging.Tests.ps1 uses for an artifact
    that may not have been built yet. A failing C# test then appears as a
    failing Pester test, with the C# assertion message as the reason.

    WHAT A FAILURE LOOKS LIKE. Exactly like any other failure from the runner:

        [-] the GUI data layer.<class>.<test> 4ms
          Expected $true, but got $false.
          Assert.True() Failure

    IF THE TOOLCHAIN IS MISSING, THIS FAILS RATHER THAN SKIPS. A skipped test
    would say "the GUI's logic is fine" while proving nothing, and 0 skipped is
    an acceptance criterion for a reason. The one It it emits names the install
    command.

    ASCII only.
#>

# ---- discovery ------------------------------------------------------------
#
# Top level, so it runs during discovery and the results can drive -ForEach.
# Pester runs this file's top level and its BeforeAll in separate scopes, so
# anything both halves need is worked out twice on purpose.

$GuiRepoRoot = Split-Path -Path $PSScriptRoot -Parent
$GuiSourceRoot = Join-Path -Path $GuiRepoRoot -ChildPath 'src\Win11Optimizer.Gui'
$GuiBuildScript = Join-Path -Path $GuiRepoRoot -ChildPath 'packaging\Build-Gui.ps1'

function Get-GuiTestResult {
    <#
        Runs the C# suite and returns one hashtable per test. Never returns an
        empty list quietly: a toolchain that is not there comes back as one
        failing entry, because "no tests ran" and "the tests passed" must not
        look the same.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory)] [string] $BuildScript,
        [Parameter(Mandatory)] [string] $SourceRoot
    )

    . $BuildScript

    $dotnet = Get-OptimizerDotnetPath
    if (-not $dotnet) {
        return @(@{
            Name    = 'the .NET SDK is installed'
            Outcome = 'Failed'
            Message = $script:DotnetMissingMessage
        })
    }

    $project = Join-Path -Path $SourceRoot -ChildPath 'Win11Optimizer.Gui.Core.Tests\Win11Optimizer.Gui.Core.Tests.csproj'
    $resultDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('w11o-gui-trx-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $resultDir -ItemType Directory -Force

    try {
        $output = & $dotnet test $project -c Release --nologo `
            --results-directory $resultDir --logger 'trx;LogFileName=gui.trx' 2>&1
        $exitCode = $LASTEXITCODE

        $trx = Join-Path -Path $resultDir -ChildPath 'gui.trx'
        if (-not [System.IO.File]::Exists($trx)) {
            return @(@{
                Name    = 'the C# suite produced a result file'
                Outcome = 'Failed'
                Message = "dotnet test exited $exitCode and wrote no .trx. Output:`n" + ($output -join "`n")
            })
        }

        [xml] $document = Get-Content -Path $trx -Raw

        $results = @()
        foreach ($entry in @($document.TestRun.Results.UnitTestResult)) {
            if ($null -eq $entry) { continue }

            # A .trx carries an <Output> element only on a test that failed, so
            # reading it straight off a passing one throws. Probed rather than
            # assumed, the same way docs\REVIEW.md says to probe anything whose
            # absence is legal.
            $message = ''
            $outputNode = $entry.SelectSingleNode('*[local-name()="Output"]')
            if ($outputNode) {
                $errorNode = $outputNode.SelectSingleNode('*[local-name()="ErrorInfo"]')
                if ($errorNode) {
                    $message = @(
                        $errorNode.SelectSingleNode('*[local-name()="Message"]').InnerText
                        $errorNode.SelectSingleNode('*[local-name()="StackTrace"]').InnerText
                    ) -join "`n"
                }
            }

            # The class name is on the definition, not the result, so the two
            # are joined here to give a name that says where the test lives.
            $definition = @($document.SelectNodes('//*[local-name()="UnitTest"]') |
                Where-Object { $_.id -eq $entry.testId }) | Select-Object -First 1

            $class = 'Win11Optimizer.Gui.Core.Tests'
            if ($definition) {
                $method = $definition.SelectSingleNode('*[local-name()="TestMethod"]')
                if ($method -and $method.className) {
                    $class = ($method.className -split '\.')[-1]
                }
            }

            $results += @{
                Name    = "$class.$($entry.testName -replace '^.*\.', '')"
                Outcome = [string] $entry.outcome
                Message = $message
            }
        }

        if (@($results).Count -eq 0) {
            return @(@{
                Name    = 'the C# suite contains tests'
                Outcome = 'Failed'
                Message = "The .trx listed no tests. dotnet test exited $exitCode."
            })
        }

        return $results
    }
    finally {
        Remove-Item -Path $resultDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$GuiTestResult = @(Get-GuiTestResult -BuildScript $GuiBuildScript -SourceRoot $GuiSourceRoot |
    ForEach-Object { @{ Name = $_.Name; Outcome = $_.Outcome; Message = $_.Message } })

# ---- the C# suite, as Pester tests ----------------------------------------

Describe 'the GUI data layer' {
    It '<Name>' -ForEach $GuiTestResult {
        if ($Outcome -ne 'Passed') {
            throw ("The C# test '{0}' reported {1}.`n{2}" -f $Name, $Outcome, $Message)
        }

        $Outcome | Should -Be 'Passed'
    }
}

# ---- the engine is unchanged ----------------------------------------------

Describe 'the GUI chunk does not touch the engine' {

    BeforeAll {
        . (Join-Path -Path $PSScriptRoot -ChildPath 'Fixtures\EngineManifest.ps1')
        $script:ManifestPath = Get-OptimizerEngineManifestPath
        $script:Recorded = [System.IO.File]::ReadAllText($script:ManifestPath)
        $script:Current = Get-OptimizerEngineManifest
    }

    It 'has a committed manifest to compare against' {
        [System.IO.File]::Exists($script:ManifestPath) | Should -BeTrue
        $script:Recorded | Should -Not -BeNullOrEmpty
    }

    It 'lists exactly the files that are in the engine folder now' {
        # An ADDED file fails here, which is the half git diff cannot see:
        # docs\REVIEW.md records 'git diff --numstat -- tests/' being blind to
        # four of the five files P6-C1 added.
        $recordedPath = @($script:Recorded -split "`n" | Where-Object { $_ } | ForEach-Object { ($_ -split '  ', 2)[1] })
        $currentPath = @($script:Current -split "`n" | Where-Object { $_ } | ForEach-Object { ($_ -split '  ', 2)[1] })

        ($currentPath | Where-Object { $_ -notin $recordedPath }) | Should -BeNullOrEmpty -Because 'no engine file may be added by this chunk'
        ($recordedPath | Where-Object { $_ -notin $currentPath }) | Should -BeNullOrEmpty -Because 'no engine file may be removed by this chunk'
    }

    It 'has the same bytes in every engine file' {
        # Byte for byte, by SHA-256, and the first difference is named rather
        # than the whole file being dumped.
        $recorded = @($script:Recorded -split "`n" | Where-Object { $_ })
        $current = @($script:Current -split "`n" | Where-Object { $_ })

        $changed = @(Compare-Object -ReferenceObject $recorded -DifferenceObject $current |
            ForEach-Object { ($_.InputObject -split '  ', 2)[1] } | Sort-Object -Unique)

        $changed -join ', ' | Should -BeNullOrEmpty -Because 'src\Win11Optimizer.Engine is not this chunk''s to change'
    }
}

# ---- the shell's own source ------------------------------------------------

Describe 'the shell says nothing about what this PC will do afterwards' {

    BeforeAll {
        . (Join-Path -Path $PSScriptRoot -ChildPath 'ForbiddenPhrase.ps1')
        $script:ForbiddenPhrase = Get-OptimizerForbiddenPhrase

        $script:GuiRoot = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'src\Win11Optimizer.Gui'

        # The reference prototype and the build output are not this chunk's
        # prose: the first is an input, the second is generated.
        $script:GuiSourceFile = @(
            Get-ChildItem -Path $script:GuiRoot -Recurse -File -ErrorAction Stop |
                Where-Object {
                    $_.Extension -in '.cs', '.js', '.css', '.html', '.csproj', '.props', '.manifest' -and
                    $_.FullName -notmatch '\\(bin|obj|reference)\\'
                })
    }

    It 'has source files to check' {
        @($script:GuiSourceFile).Count | Should -BeGreaterThan 10
    }

    It 'never says "<_>"' -ForEach @(
        'free up', 'frees up', 'freed up', 'reclaim ', 'will reclaim',
        'space you will', 'will save', 'you will get back', 'speed up', 'run faster'
    ) {
        $phrase = $_

        # Against the source's own string literals as well as anything it
        # prints, which is the same standard tests\ReviewScreen.Tests.ps1 holds
        # the console screen to.
        $hit = @($script:GuiSourceFile | Where-Object {
            (Get-Content -Path $_.FullName -Raw) -like "*$phrase*"
        } | ForEach-Object { $_.Name })

        $hit -join ', ' | Should -BeNullOrEmpty
    }

    It 'enforces the same list the rest of the suite enforces' {
        # Not a second copy of the phrases: if tests\ForbiddenPhrase.ps1 gains
        # one, this loop is out of date and says so.
        @($script:ForbiddenPhrase).Count | Should -Be 10
    }
}

Describe 'the shell is ASCII and carries nothing about this machine' {

    BeforeAll {
        $script:GuiRoot = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'src\Win11Optimizer.Gui'
        $script:GuiSourceFile = @(
            Get-ChildItem -Path $script:GuiRoot -Recurse -File -ErrorAction Stop |
                Where-Object {
                    $_.Extension -in '.cs', '.js', '.css', '.html', '.csproj', '.props', '.manifest' -and
                    $_.FullName -notmatch '\\(bin|obj|reference)\\'
                })

        $script:BuiltFile = @(
            Get-ChildItem -Path $script:GuiRoot -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'Win11Optimizer.Gui*.dll' -or $_.Name -like 'Win11Optimizer.Gui*.exe' })

        # WHAT COUNTS AS A LEAK, and what is too short to test for.
        #
        # The user profile, the user name as a path segment, and the folder this
        # repository happens to sit in are the things that must never reach a
        # shipped file, and all three are long enough to search for safely.
        #
        # The machine name is only included when it is long enough not to
        # collide with ordinary words. On the machine this was written on it is
        # three characters, and it matches inside the product's own Manufacturer
        # string -- so testing for it there would fail on a name the project
        # chose for itself rather than on anything that leaked. A three-letter
        # substring search is not evidence either way.
        $script:Needle = @(
            $env:USERPROFILE
            (Split-Path -Path $PSScriptRoot -Parent)
            $(if ($env:USERNAME) { '\' + $env:USERNAME + '\' })
            $(if ($env:COMPUTERNAME -and $env:COMPUTERNAME.Length -ge 5) { $env:COMPUTERNAME })
        ) | Where-Object { $_ }
    }

    It 'has no character above 0x7E in <_.Name>' -ForEach @(
        @(Get-ChildItem -Path (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'src\Win11Optimizer.Gui') -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -in '.cs', '.js', '.css', '.html', '.csproj', '.props', '.manifest' -and
                $_.FullName -notmatch '\\(bin|obj|reference)\\'
            })
    ) {
        # One non-ASCII character in a source file takes down 137 unrelated
        # tests on 5.1. docs\REVIEW.md.
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        @($bytes | Where-Object { $_ -gt 126 }).Count | Should -Be 0
    }

    It 'bakes no user profile, user name or repository path into the source' {
        foreach ($file in $script:GuiSourceFile) {
            $text = Get-Content -Path $file.FullName -Raw
            foreach ($value in $script:Needle) {
                $text | Should -Not -BeLike "*$value*" -Because "$($file.Name) must not carry '$value'"
            }
        }
    }

    It 'bakes no user profile, user name or repository path into the built binaries' {
        # THE SOURCE CHECK ABOVE IS NOT ENOUGH, and this is measured rather
        # than assumed: the C# compiler embeds the full path of every source
        # file it compiled, so before src\Win11Optimizer.Gui\Directory.Build.props
        # gained its PathMap line every output here carried the absolute
        # repository path while every source file was clean.
        @($script:BuiltFile).Count | Should -BeGreaterThan 0

        foreach ($file in $script:BuiltFile) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $text = [System.Text.Encoding]::ASCII.GetString($bytes)
            $wide = [System.Text.Encoding]::Unicode.GetString($bytes)

            foreach ($value in $script:Needle) {
                $text | Should -Not -BeLike "*$value*" -Because "$($file.Name) must not carry '$value'"
                $wide | Should -Not -BeLike "*$value*" -Because "$($file.Name) must not carry '$value'"
            }
        }
    }
}

# ---- the shell knows the same vocabulary the engine publishes ---------------

Describe 'the shell and the engine agree about the protocol vocabulary' {

    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'src\Win11Optimizer.Engine\Win11Optimizer.Engine.psd1') -Force
        $script:Contract = Get-OptimizerScanContract

        # The C# restates the protocol vocabulary, because a second process
        # cannot call the function above cheaply. That restatement is checked
        # here rather than left to a comment to keep honest.
        $script:ContractSource = Get-Content -Raw -Path (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'src\Win11Optimizer.Gui\Win11Optimizer.Gui.Core\Contract\ScanContract.cs')
    }

    It 'agrees about the schema version' {
        $script:ContractSource | Should -BeLike "*SchemaVersion = $($script:Contract.SchemaVersion);*"
    }

    It 'knows every record kind the engine publishes' {
        foreach ($kind in $script:Contract.RecordKinds) {
            $script:ContractSource | Should -BeLike "*`"$kind`"*"
        }
    }

    It 'knows every source status the engine publishes, including Refused' {
        foreach ($status in $script:Contract.SourceStatuses) {
            $script:ContractSource | Should -BeLike "*`"$status`"*"
        }
    }

    It 'treats exactly the engine''s two statuses as making a scan incomplete' {
        $incomplete = @($script:Contract.IncompleteStatuses)
        $incomplete.Count | Should -Be 2

        # The list in the C# is one array literal; this pins its contents.
        $literal = 'IncompleteStatusList =' + "`n" + '            { Status' + $incomplete[0] + ', Status' + $incomplete[1] + ' };'
        ($script:ContractSource -replace "`r`n", "`n") | Should -BeLike "*$literal*"
    }

    It 'knows every phase the engine publishes' {
        foreach ($phase in $script:Contract.Phases) {
            $script:ContractSource | Should -BeLike "*`"$phase`"*"
        }
    }

    It 'agrees about the two exit codes' {
        $script:ContractSource | Should -BeLike "*ExitResultWritten = $($script:Contract.ExitCodes.ResultWritten);*"
        $script:ContractSource | Should -BeLike "*ExitNoResult = $($script:Contract.ExitCodes.NoResult);*"
    }

    It 'agrees about the two safety labels' {
        $labels = @((Get-FindingContract).SafetyLabels)
        $labels.Count | Should -Be 2

        foreach ($label in $labels) {
            $script:ContractSource | Should -BeLike "*`"$label`"*"
        }
    }

    It 'runs the launcher the engine actually ships, and not the menu' {
        $source = Get-Content -Raw -Path (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'src\Win11Optimizer.Gui\Win11Optimizer.Gui.Core\Process\EngineLocation.cs')

        # Against the QUOTED literals, not the prose. The file's own comment
        # names Entry.ps1 to say why it is not the one being run, and a check
        # that could not tell those apart would forbid explaining the decision.
        $source | Should -BeLike '*"App", "Scan.ps1"*'
        $source | Should -Not -BeLike '*"Entry.ps1"*'
        $source | Should -Not -BeLike '*"Bootstrap.ps1"*'
    }
}
