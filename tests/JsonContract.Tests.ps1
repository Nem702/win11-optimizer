#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the JSON contract (chunk P6-C1,
    src\Win11Optimizer.Engine\Review\Json.ps1 and
    src\Win11Optimizer.Engine\App\Scan.ps1).

    THE SUITE IS ORGANISED ROUND THE FOUR THINGS THE PROMPT SAID WOULD BITE,
    because every one of them is a way for this contract to be wrong while
    looking right:

      1. SafetyLabelRule is a scriptblock and cannot cross a process boundary.
         No scriptblock and no PSObject-typed remnant may survive serialization
         anywhere in the payload -- and the assertion for that is mechanical,
         not lexical: the writer THROWS on anything it was not told about, so
         the tests here prove the refusal rather than search the output for a
         string.
      2. A [datetime] serializes differently on the two shells (Q29). Every
         timestamp is an explicit ISO-8601 string, and the writer refuses a raw
         [datetime] outright.
      3. Anything that writes to stdout corrupts the stream. Every line of a
         real un-elevated run has to parse as JSON, and nothing else may be
         there.
      4. Refused is a fourth scan-source status, and a consumer that only knows
         three mis-reports a refusal as a failure.

    AND THE CRITERION THAT MATTERS MOST: both shells produce byte-identical
    stdout for the same input. That is proved twice over -- against a committed
    golden file, which runs on each shell in turn and so fails on whichever one
    disagrees, and by spawning the other shell and comparing SHA-256 of the
    bytes. Neither skips: 0 skipped is an acceptance criterion, and a
    cross-shell test that quietly skips is a cross-shell test that never ran.

    NOTHING HERE SCANS THE REAL MACHINE except the two Describes that say so in
    their names, and nothing here writes to the repository's ledger: the log
    root is redirected before the module is imported and the receipt is skipped.

    Run:  .\tests\Invoke-Tests.ps1        (and -On51, which is not optional)
#>

# Discovery-time, for the -ForEach that makes one test per forbidden phrase.
# Pester runs a file's top level during discovery and its BeforeAll during the
# run, in separate scopes, so the list is dot-sourced in both.
. (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
$ForbiddenPhrase = Get-OptimizerForbiddenPhrase

BeforeAll {
    . (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
    $script:ForbiddenPhrase = Get-OptimizerForbiddenPhrase

    $script:RepoRoot     = Split-Path -Path $PSScriptRoot -Parent
    $script:EngineRoot   = Join-Path $script:RepoRoot 'src\Win11Optimizer.Engine'
    $script:ManifestPath = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psd1'
    $script:ModulePath   = Join-Path $script:EngineRoot 'Win11Optimizer.Engine.psm1'
    $script:JsonSource   = Join-Path $script:EngineRoot 'Review\Json.ps1'
    $script:ScanSource   = Join-Path $script:EngineRoot 'App\Scan.ps1'
    $script:FixtureRoot  = Join-Path $PSScriptRoot 'Fixtures'
    $script:FixturePath  = Join-Path $script:FixtureRoot 'JsonContract.Fixture.ps1'
    $script:WriterPath   = Join-Path $script:FixtureRoot 'Write-JsonContractFixture.ps1'
    $script:GoldenPath   = Join-Path $script:FixtureRoot 'json-contract-golden.jsonl'

    # A log root of our own, set BEFORE the import. The repository's ledger is
    # the one file in this project that is never rotated and nothing in this
    # suite may go near it.
    $script:TestLogRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('win11opt-json-' + [guid]::NewGuid().ToString('N'))
    $env:WIN11OPTIMIZER_LOGROOT = $script:TestLogRoot
    $null = New-Item -Path $script:TestLogRoot -ItemType Directory -Force

    $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('win11opt-json-scratch-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $script:Scratch -ItemType Directory -Force

    Import-Module $script:ManifestPath -Force -ErrorAction Stop
    . $script:FixturePath

    $script:Contract = Get-OptimizerScanContract

    $script:NewExport = @(
        'Get-OptimizerScanContract'
        'ConvertTo-OptimizerScanPayload'
        'ConvertTo-OptimizerScanJson'
        'Invoke-OptimizerScanJson'
    )

    # The fixture, projected once. Deterministic by construction -- see the
    # fixture's own header.
    $script:Screen  = Get-JsonContractFixtureScreen
    $script:Payload = ConvertTo-OptimizerScanPayload -Screen $script:Screen -Planner (Get-JsonContractFixturePlanner)
    $script:Line    = ConvertTo-OptimizerScanJson -Kind 'result' -TimestampUtc (Get-JsonContractFixtureTimestamp) -Payload $script:Payload
    $script:Parsed  = ConvertFrom-Json -InputObject $script:Line

    # ---- walking the projection -------------------------------------------
    #
    # The payload is ordered hashtables, arrays and primitives all the way down.
    # This walks it and hands back every leaf value with the path it was found
    # at, so an assertion about "anywhere in the payload" can be exactly that
    # rather than a search of the rendered text.
    function Get-PayloadLeaf {
        param(
            [Parameter(Mandatory)] [AllowNull()] $Value,
            [Parameter()] [string] $Path = '$'
        )

        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($key in $Value.Keys) {
                Get-PayloadLeaf -Value $Value[$key] -Path ("$Path." + [string] $key)
            }
            return
        }

        if ($Value -isnot [string] -and $Value -is [System.Collections.IEnumerable]) {
            $index = 0
            foreach ($item in $Value) {
                Get-PayloadLeaf -Value $item -Path ("$Path[$index]")
                $index++
            }
            return
        }

        [pscustomobject]@{ Path = $Path; Value = $Value }
    }

    $script:Leaf = @(Get-PayloadLeaf -Value $script:Payload)

    # Every key name that appears anywhere in the payload, at any depth.
    function Get-PayloadKey {
        param(
            [Parameter(Mandatory)] [AllowNull()] $Value
        )

        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($key in $Value.Keys) {
                [string] $key
                Get-PayloadKey -Value $Value[$key]
            }
            return
        }

        if ($Value -isnot [string] -and $Value -is [System.Collections.IEnumerable]) {
            foreach ($item in $Value) { Get-PayloadKey -Value $item }
        }
    }

    $script:PayloadKey = @(Get-PayloadKey -Value $script:Payload | Sort-Object -Unique)

    # The rows of the payload, flattened, so a test does not have to walk two
    # levels to reach one.
    $script:Row = @($script:Payload['Section'] | ForEach-Object { $_['Row'] } | Where-Object { $null -ne $_ })

    # ---- the source, comment-blanked ---------------------------------------
    #
    # Same machinery as tests\ReviewScreen.Tests.ps1 and its ancestors, repeated
    # rather than shared for the reason those files give: a source-scanning
    # assertion that lives somewhere else is one refactor away from scanning
    # nothing. Offsets are preserved -- only non-newline characters inside a
    # comment become spaces -- because this file has to be able to NAME the
    # things the source never does.
    $script:Raw = [System.IO.File]::ReadAllText($script:JsonSource)
    $script:Tokens = $null
    $script:Errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:JsonSource, [ref] $script:Tokens, [ref] $script:Errors)

    $blanked = [System.Text.StringBuilder]::new($script:Raw)
    foreach ($token in @($script:Tokens | Where-Object { $_.Kind -eq 'Comment' })) {
        for ($offset = $token.Extent.StartOffset; $offset -lt $token.Extent.EndOffset; $offset++) {
            if ($blanked[$offset] -ne "`r" -and $blanked[$offset] -ne "`n") { $blanked[$offset] = ' ' }
        }
    }
    $script:Code = $blanked.ToString()

    $script:InvokedCommand = @($script:Ast.FindAll({
        param($node) $node -is [System.Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)

    # ---- driving the runner ------------------------------------------------
    #
    # A capturing writer pair, so a test reads the exact transcript instead of
    # the console. The same shape Show-ReviewScreen and Invoke-OptimizerMenu use.
    function New-CapturingRun {
        param(
            [Parameter()] [hashtable] $Argument = @{}
        )

        $out = New-Object System.Collections.Generic.List[string]
        $err = New-Object System.Collections.Generic.List[string]

        $code = Invoke-OptimizerScanJson `
            -Writer      { param($Line) $null = $out.Add([string] $Line) }.GetNewClosure() `
            -ErrorWriter { param($Line) $null = $err.Add([string] $Line) }.GetNewClosure() `
            @Argument

        [pscustomobject]@{
            ExitCode = $code
            Out      = [string[]] @($out.ToArray())
            Err      = [string[]] @($err.ToArray())
        }
    }
}

AfterAll {
    foreach ($path in @($script:TestLogRoot, $script:Scratch)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'P6-C1 the contract publishes its own vocabulary' {

    It 'exports <_> from both the .psm1 and the .psd1' -ForEach @(
        'Get-OptimizerScanContract', 'ConvertTo-OptimizerScanPayload'
        'ConvertTo-OptimizerScanJson', 'Invoke-OptimizerScanJson'
    ) {
        $name = $_
        [System.IO.File]::ReadAllText($script:ModulePath)   | Should -Match ([regex]::Escape("'$name'"))
        [System.IO.File]::ReadAllText($script:ManifestPath) | Should -Match ([regex]::Escape("'$name'"))
        Get-Command -Module Win11Optimizer.Engine -Name $name -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'keeps the manifest and the module in agreement' {
        $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
        $exported = @(Get-Command -Module Win11Optimizer.Engine | ForEach-Object { $_.Name })
        @($manifest.FunctionsToExport).Count | Should -Be $exported.Count
        @($exported | Where-Object { $script:NewExport -contains $_ }).Count | Should -Be 4
    }

    It 'starts at schema version 1' {
        $script:Contract.SchemaVersion | Should -Be 1
    }

    It 'names the three record kinds and no others' {
        @($script:Contract.RecordKinds) | Should -Be @('progress', 'result', 'error')
    }

    It 'carries ALL FOUR scan-source statuses' {
        # THE ONE A SECOND CODEBASE IS MOST LIKELY TO GET WRONG. A consumer that
        # knows only three reports a refusal -- a signal this project declines to
        # use on every machine, forever -- as a failure, which is a different and
        # much worse claim about the same scan.
        @($script:Contract.SourceStatuses) | Should -Be @('Succeeded', 'Skipped', 'Failed', 'Refused')
    }

    It 'says only Skipped and Failed make a scan incomplete' {
        @($script:Contract.IncompleteStatuses) | Should -Be @('Skipped', 'Failed')
        @($script:Contract.IncompleteStatuses) | Should -Not -Contain 'Refused'
    }

    It 'reads the statuses from the shared table rather than restating them' {
        # The four live in Shared\Inventory.ps1 and every detector keys on them.
        # A second copy here is a second copy that can drift.
        $shared = InModuleScope Win11Optimizer.Engine { , $script:ScanSourceStatuses }
        @($script:Contract.SourceStatuses) | Should -Be @($shared)
    }

    It 'publishes the five phases, in the order they run' {
        @($script:Contract.Phases) | Should -Be @('StartupItems', 'InstalledApps', 'JunkFiles', 'Planning', 'Assembling')
    }

    It 'publishes the two exit codes, and only zero means a result was written' {
        $script:Contract.ExitCodes.ResultWritten | Should -Be 0
        $script:Contract.ExitCodes.NoResult      | Should -Not -Be 0
    }

    It 'hands out a COPY of the per-category field table' {
        # The same rule Get-RemovalContract follows for its routes: a consumer
        # that could edit what it was given could change what the next caller is
        # told the contract says.
        $first = Get-OptimizerScanContract
        $first.CategoryRowFields['JunkFile'] = @('tampered')
        (Get-OptimizerScanContract).CategoryRowFields['JunkFile'] | Should -Contain 'EligibleBytes'
    }

    It 'says the line delimiter is LF' {
        $script:Contract.NewLine | Should -BeExactly "`n"
    }
}

Describe 'P6-C1 the writer refuses what cannot cross a process boundary' {

    It 'throws on a scriptblock' {
        # SafetyLabelRule is the one this project has, and the whole point of it
        # is that the rule lives in exactly one place. Serializing it would put a
        # copy in another codebase; serializing a rule-shaped object would put a
        # copy there in pieces. Neither is possible, because the writer stops.
        InModuleScope Win11Optimizer.Engine {
            { ConvertTo-OptimizerJsonText -Value { param($a, $b) 'x' } } |
                Should -Throw '*scriptblock reached the writer*'
        }
    }

    It 'throws on a scriptblock nested deep inside a payload' {
        InModuleScope Win11Optimizer.Engine {
            $payload = [ordered]@{ a = [ordered]@{ b = @([ordered]@{ c = { 1 } }) } }
            { ConvertTo-OptimizerJsonText -Value $payload } | Should -Throw '*scriptblock reached the writer*'
        }
    }

    It 'throws on a raw [datetime], and names Q29 when it does' {
        InModuleScope Win11Optimizer.Engine {
            { ConvertTo-OptimizerJsonText -Value ([datetime]::UtcNow) } | Should -Throw '*Q29*'
        }
    }

    It 'throws on a PSCustomObject rather than serializing it in property order' {
        # THE MECHANICAL VERSION OF "no PSObject-typed remnant survives". An
        # object arriving whole means a field was copied rather than projected,
        # and property order on a PSObject is not something two shells promise.
        InModuleScope Win11Optimizer.Engine {
            { ConvertTo-OptimizerJsonText -Value ([pscustomobject]@{ a = 1 }) } |
                Should -Throw '*nothing here knows how to write*'
        }
    }

    It 'throws on a live Finding, which is the PSObject that would really arrive' {
        InModuleScope Win11Optimizer.Engine {
            $finding = New-Finding -Category JunkFile -Id 'x' -DisplayName 'x' -Evidence 'x' -Confidence Known -RemovalMethod FileDelete
            { ConvertTo-OptimizerJsonText -Value ([ordered]@{ Finding = $finding }) } |
                Should -Throw '*nothing here knows how to write*'
        }
    }

    It 'throws on NaN and on infinity rather than writing them as bare words' {
        InModuleScope Win11Optimizer.Engine {
            { ConvertTo-OptimizerJsonText -Value ([double]::NaN) }               | Should -Throw '*not a number JSON can carry*'
            { ConvertTo-OptimizerJsonText -Value ([double]::PositiveInfinity) }  | Should -Throw '*not a number JSON can carry*'
        }
    }

    It 'stops rather than following a structure round forever' {
        InModuleScope Win11Optimizer.Engine {
            $loop = [ordered]@{ name = 'outer' }
            $loop['self'] = $loop
            { ConvertTo-OptimizerJsonText -Value $loop } | Should -Throw '*deeper than*'
        }
    }
}

Describe 'P6-C1 the writer is deterministic on both shells' {

    It 'escapes the four characters 5.1 and 7 disagree about as themselves' {
        # ConvertTo-Json under 5.1 escapes all four and under 7 does not. This
        # writer picks one behaviour by hand, which is the entire reason it
        # exists, so the choice is pinned here rather than left to be discovered.
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerJsonText -Value "<b>&'" | Should -BeExactly '"<b>&''"'
        }
    }

    It 'escapes the control characters by name and everything above 0x7E as \uXXXX' {
        InModuleScope Win11Optimizer.Engine {
            $text = -join @([char]8, [char]9, [char]10, [char]12, [char]13, [char]31, [char]0x00E9, [char]0x4E2D)
            ConvertTo-OptimizerJsonText -Value $text | Should -BeExactly '"\b\t\n\f\r\u001f\u00e9\u4e2d"'
        }
    }

    It 'escapes a quote and a backslash, and leaves the forward slash alone' {
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerJsonText -Value 'C:\a\"b"/c' | Should -BeExactly '"C:\\a\\\"b\"/c"'
        }
    }

    It 'writes integers invariantly and fractions to a fixed precision' {
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerJsonText -Value ([long] 12345678901) | Should -BeExactly '12345678901'
            ConvertTo-OptimizerJsonText -Value ([long] -42)         | Should -BeExactly '-42'
            ConvertTo-OptimizerJsonText -Value ([double] 2.5)       | Should -BeExactly '2.5'
            ConvertTo-OptimizerJsonText -Value ([double] 0)         | Should -BeExactly '0'
            ConvertTo-OptimizerJsonText -Value ([double] 0.1234567) | Should -BeExactly '0.123457'
        }
    }

    It 'never writes a negative zero' {
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerJsonText -Value ([double] -0.0000001) | Should -BeExactly '0'
        }
    }

    It 'keeps the key order an ordered hashtable was built in' {
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerJsonText -Value ([ordered]@{ z = 1; a = 2; m = 3 }) |
                Should -BeExactly '{"z":1,"a":2,"m":3}'
        }
    }

    It 'writes an empty array and an empty object as themselves, not as null' {
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerJsonText -Value @()          | Should -BeExactly '[]'
            ConvertTo-OptimizerJsonText -Value ([ordered]@{}) | Should -BeExactly '{}'
        }
    }
}

Describe 'P6-C1 both shells produce byte-identical output for the same input' {

    # THE CRITERION THAT MATTERS MOST, proved two ways. The golden file runs on
    # whichever shell the suite is running under, so a divergence fails on one
    # of the two runs; the spawn compares the two directly in one run.

    It 'has a committed golden file' {
        Test-Path -LiteralPath $script:GoldenPath -PathType Leaf | Should -BeTrue
    }

    It 'serializes the fixture to exactly the golden bytes' {
        $produced = [System.Text.Encoding]::ASCII.GetBytes((Get-JsonContractFixtureText))
        $golden   = [System.IO.File]::ReadAllBytes($script:GoldenPath)

        # The length first, because a length mismatch reported as "byte 4,812
        # differs" tells a reader nothing about what happened.
        $produced.Length | Should -Be $golden.Length -Because 'the fixture and the golden file must be the same size'

        $differing = -1
        for ($index = 0; $index -lt $golden.Length; $index++) {
            if ($produced[$index] -ne $golden[$index]) { $differing = $index; break }
        }
        $differing | Should -Be -1 -Because "the first differing byte is at offset $differing"
    }

    It 'produces the same bytes when the OTHER shell serializes the same fixture' {
        # Windows PowerShell is at a fixed path on every Windows install, so this
        # never has to look for a shell and never has to skip. Under -On51 it is
        # a self-comparison and the golden file above carries the cross-shell
        # claim; under 7 it IS the cross-shell claim.
        $otherShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        Test-Path -LiteralPath $otherShell -PathType Leaf | Should -BeTrue

        $mine  = Join-Path $script:Scratch ('mine-'  + [guid]::NewGuid().ToString('N') + '.jsonl')
        $other = Join-Path $script:Scratch ('other-' + [guid]::NewGuid().ToString('N') + '.jsonl')

        [System.IO.File]::WriteAllBytes($mine, [System.Text.Encoding]::ASCII.GetBytes((Get-JsonContractFixtureText)))

        # PSModulePath is removed for the child, exactly as Invoke-Tests.ps1 does
        # it: Windows PowerShell inheriting PowerShell 7's copy loads 7's
        # Microsoft.PowerShell.Utility, which has no Import-PowerShellDataFile.
        $savedModulePath = $env:PSModulePath
        try {
            Remove-Item Env:\PSModulePath -ErrorAction SilentlyContinue
            & $otherShell -NoProfile -File $script:WriterPath -Path $other
            $LASTEXITCODE | Should -Be 0 -Because 'the other shell must be able to serialize the fixture at all'
        }
        finally { $env:PSModulePath = $savedModulePath }

        (Get-FileHash -LiteralPath $other -Algorithm SHA256).Hash |
            Should -Be (Get-FileHash -LiteralPath $mine -Algorithm SHA256).Hash
    }

    It 'writes LF line endings and nothing else' {
        # A line-delimited protocol whose delimiter depends on which shell wrote
        # it is not byte-identical on both shells.
        $bytes = [System.Text.Encoding]::ASCII.GetBytes((Get-JsonContractFixtureText))
        @($bytes | Where-Object { $_ -eq 13 }).Count | Should -Be 0
        @($bytes | Where-Object { $_ -eq 10 }).Count | Should -Be 4
    }

    It 'is pure ASCII, so the bytes do not depend on the console encoding' {
        $text = Get-JsonContractFixtureText
        @($text.ToCharArray() | Where-Object { [int] $_ -gt 126 }).Count | Should -Be 0
        # And the fixture really does contain a character above 0x7E to escape,
        # so this is a statement about the writer and not about a tame fixture.
        (Get-JsonContractFixtureAwkwardText).ToCharArray() |
            Where-Object { [int] $_ -gt 126 } | Should -Not -BeNullOrEmpty
    }
}

Describe 'P6-C1 the envelope' {

    It 'puts kind, schemaVersion and timestamp first, in that order' {
        $script:Line | Should -Match '^\{"kind":"result","schemaVersion":1,"timestamp":"'
    }

    It 'carries schemaVersion on every kind of record, not only on the result' {
        foreach ($kind in @($script:Contract.RecordKinds)) {
            $record = ConvertFrom-Json -InputObject (ConvertTo-OptimizerScanJson -Kind $kind -Payload ([ordered]@{ A = 1 }))
            $record.kind          | Should -Be $kind
            $record.schemaVersion | Should -Be 1
            $record.timestamp     | Should -Not -BeNullOrEmpty
        }
    }

    It 'merges the payload beside the envelope rather than nesting it' {
        $script:Parsed.RowCount | Should -Not -BeNullOrEmpty
        $script:Parsed.PSObject.Properties.Name | Should -Not -Contain 'payload'
    }

    It 'refuses a payload that would overwrite one of the envelope fields' -ForEach @('kind', 'schemaVersion', 'timestamp') {
        { ConvertTo-OptimizerScanJson -Kind 'progress' -Payload ([ordered]@{ $_ = 'hijacked' }) } |
            Should -Throw '*envelope fields*'
    }

    It 'refuses a payload that is an object rather than an ordered hashtable' {
        # Key order is part of this contract's byte-for-byte output, and a
        # PSObject would be serialized in whatever order its properties sit in.
        { ConvertTo-OptimizerScanJson -Kind 'progress' -Payload ([pscustomobject]@{ A = 1 }) } |
            Should -Throw '*ordered hashtable*'
    }

    It 'normalises the timestamp it is given, whatever shape it arrives in' {
        $fromString = ConvertFrom-Json -InputObject (ConvertTo-OptimizerScanJson -Kind 'progress' -TimestampUtc '2026-09-06T12:34:56.7890123Z' -Payload $null)
        (ConvertTo-OptimizerScanJson -Kind 'progress' -TimestampUtc '2026-09-06T12:34:56.7890123Z' -Payload $null) |
            Should -Match '"timestamp":"2026-09-06T12:34:56\.7890123Z"'
        $fromString.kind | Should -Be 'progress'
    }

    It 'refuses a record kind that is not one of the three' {
        { ConvertTo-OptimizerScanJson -Kind 'chatter' -Payload $null } | Should -Throw
    }
}

Describe 'P6-C1 the payload resolves what a second process cannot' {

    It 'carries no scriptblock anywhere' {
        @($script:Leaf | Where-Object { $_.Value -is [scriptblock] }) | Should -BeNullOrEmpty
    }

    It 'carries no PSObject-typed remnant anywhere' {
        $remnants = @($script:Leaf | Where-Object {
            $null -ne $_.Value -and
            $_.Value -isnot [string] -and $_.Value -isnot [bool] -and
            $_.Value -isnot [long] -and $_.Value -isnot [int] -and $_.Value -isnot [double]
        })
        $remnants | Should -BeNullOrEmpty -Because "these leaves are not primitives: $(@($remnants | ForEach-Object { $_.Path }) -join ', ')"
    }

    It 'carries no [datetime] anywhere -- Q29' {
        @($script:Leaf | Where-Object { $_.Value -is [datetime] -or $_.Value -is [datetimeoffset] }) | Should -BeNullOrEmpty
    }

    It 'writes every timestamp as an ISO-8601 string' {
        foreach ($name in @('GeneratedUtc')) {
            $script:Payload[$name] | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$'
        }
        foreach ($scan in $script:Payload['Scan']) {
            $scan['StartedUtc'] | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$'
        }
        foreach ($row in $script:Row) {
            if ($row.Contains('Plan')) { $row['Plan']['VerifiedUtc'] | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$' }
        }
    }

    It 'never writes the shell-specific date literal 5.1 would have produced' {
        # The exact shape Q29 is about. Named here so the assertion is about the
        # defect and not about a regex nobody can read.
        $script:Line | Should -Not -Match '\\/Date\('
        $script:Line | Should -Not -Match '/Date\('
    }

    It 'resolves SafetyLabel to one of the contract''s two strings on every row' {
        $labels = @((Get-FindingContract).SafetyLabels)
        foreach ($row in $script:Row) { $labels | Should -Contain $row['SafetyLabel'] }
    }

    It 'gives a consent-requiring certain match "Review needed", not "Safe to remove"' {
        # The two-axis rule, arriving at a second process as an answer rather
        # than as a rule to re-run.
        $service = @($script:Row | Where-Object { $_['Category'] -eq 'Service' })[0]
        $service['RequiresConsent'] | Should -BeTrue
        $service['Confidence']      | Should -Be 'Known'
        $service['SafetyLabel']     | Should -Be (Get-FindingContract).SafetyLabels[1]
    }

    It 'does not hand a consumer a rule-shaped object to re-derive the label from' {
        $script:PayloadKey | Should -Not -Contain 'SafetyLabelRule'
        $script:PayloadKey | Should -Not -Contain 'SafetyLabels'
        $script:Line | Should -Not -Match 'SafetyLabelRule'
    }

    It 'reports a non-boolean RequiresConsent as null rather than repairing it' {
        # The fail-closed clause exists to catch a consent flag that arrived as
        # something other than a real boolean. Coercing it here would repair the
        # value on the way out and hide exactly that.
        InModuleScope Win11Optimizer.Engine {
            ConvertTo-OptimizerScanBoolean -Value 'false' | Should -BeNullOrEmpty
            ConvertTo-OptimizerScanBoolean -Value 1       | Should -BeNullOrEmpty
            ConvertTo-OptimizerScanBoolean -Value $false  | Should -BeFalse
            ConvertTo-OptimizerScanBoolean -Value $true   | Should -BeTrue
        }
    }
}

Describe 'P6-C1 the payload carries every scan source, with its status and reason' {

    It 'carries one record per detector scan, in the order they ran' {
        @($script:Payload['Scan'] | ForEach-Object { $_['Detector'] }) |
            Should -Be @('StartupItems', 'UnusedApps', 'OemBloatware', 'JunkFiles')
    }

    It 'carries every source of every scan' {
        $expected = 0
        foreach ($scan in @($script:Screen.Scan)) { $expected += @($scan.Source).Count }
        @($script:Payload['Scan'] | ForEach-Object { $_['Source'] }).Count | Should -Be $expected
    }

    It 'keeps Refused distinct from Failed and from Skipped' {
        $statuses = @($script:Payload['Scan'] | ForEach-Object { $_['Source'] } | ForEach-Object { $_['Status'] })
        $statuses | Should -Contain 'Refused'
        $statuses | Should -Contain 'Skipped'
        $statuses | Should -Contain 'Failed'
        $statuses | Should -Contain 'Succeeded'
    }

    It 'keeps the Reason on every source that did not simply succeed' {
        foreach ($scan in $script:Payload['Scan']) {
            foreach ($source in $scan['Source']) {
                if ($source['Status'] -eq 'Succeeded') { continue }
                $source['Reason'] | Should -Not -BeNullOrEmpty -Because "'$($source['Name'])' is $($source['Status'])"
            }
        }
    }

    It 'writes a succeeded source''s Reason as null, not as an empty string' {
        # New-ScanSource forces it back to $null on purpose and callers
        # distinguish the two; a projection that collapsed them would throw that
        # away at the process boundary.
        $succeeded = @($script:Payload['Scan'] | ForEach-Object { $_['Source'] } | Where-Object { $_['Status'] -eq 'Succeeded' })[0]
        $succeeded['Reason'] | Should -BeNullOrEmpty
        $script:Line | Should -Match '"Status":"Succeeded","Reason":null'
    }

    It 'counts only Skipped and Failed as an incompleteness' {
        # The unused-app scan has a Refused source AND a Skipped one, so it is
        # incomplete; a scan whose only non-success is Refused must not be.
        $unused = @($script:Payload['Scan'] | Where-Object { $_['Detector'] -eq 'UnusedApps' })[0]
        $unused['IsComplete']        | Should -BeFalse
        $unused['RefusedSourceName'] | Should -Contain 'FileSystemLastAccess'
        $unused['IncompleteReason']  | Should -Not -Match 'FileSystemLastAccess'
    }

    It 'names the partial sections rather than summarising them' {
        $script:Payload['IsComplete'] | Should -BeFalse
        @($script:Payload['PartialSection']).Count | Should -BeGreaterThan 0
    }
}

Describe 'P6-C1 the payload carries the rows the review screen decided' {

    It 'carries one row per finding, across the four sections' {
        @($script:Row).Count | Should -Be $script:Screen.RowCount
    }

    It 'carries the four sections in screen order' {
        @($script:Payload['Section'] | ForEach-Object { $_['Key'] }) |
            Should -Be @('StartupItems', 'InstalledApps', 'JunkFiles', 'Services')
    }

    It 'carries every common row field on every row' {
        foreach ($row in $script:Row) {
            foreach ($field in @($script:Contract.RowFields)) {
                $row.Contains($field) | Should -BeTrue -Because "row '$($row['DisplayName'])' must carry $field"
            }
        }
    }

    It 'carries a category''s own fields only on that category''s rows' {
        # A row for an Appx package does not have a null age window; it has no
        # age window. A null there would be a placeholder for something that
        # does not exist, which this contract is not allowed to carry.
        foreach ($row in $script:Row) {
            $expected = @($script:Contract.CategoryRowFields[$row['Category']])
            foreach ($field in @('MinimumAgeDays', 'ProfileBreakdown', 'EligibleBytes')) {
                if ($expected -contains $field) { continue }
                $row.Contains($field) | Should -BeFalse -Because "'$($row['DisplayName'])' is a $($row['Category']) row"
            }
        }
    }

    It 'carries the junk row''s own age window, not the scan''s' {
        # The fixture location is measured at 30 days while the scan uses 7. A
        # row that quoted the scan's window would be telling a consumer
        # something untrue about that row in particular.
        $junk = @($script:Row | Where-Object { $_['Category'] -eq 'JunkFile' })[0]
        $junk['MinimumAgeDays'] | Should -Be 30
    }

    It 'carries the profile split as data' {
        $junk = @($script:Row | Where-Object { $_['Category'] -eq 'JunkFile' })[0]
        @($junk['ProfileBreakdown'] | ForEach-Object { $_['Profile'] }) | Should -Be @('Profile 1', 'Profile 2')
        @($junk['ProfileBreakdown'])[0]['EligibleBytes'] | Should -Be 900000000
    }

    It 'NEVER carries the eligible file list' {
        # 773 records for one row on this machine and up to 14,440 across the
        # category. P3-C2 made this call once already, moving junk manifests to
        # sidecars for a 312x smaller ledger line. The fixture Finding really
        # carries the list, so this is a statement about the projection.
        @($script:Screen.Section | ForEach-Object { $_.Row } | ForEach-Object { $_.Finding } |
            Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['EligibleFile'] }) |
            Should -Not -BeNullOrEmpty -Because 'the fixture must actually carry a file list for this to mean anything'

        $script:PayloadKey | Should -Not -Contain 'EligibleFile'
        $script:Line | Should -Not -Match 'EligibleFile"'
    }

    It 'carries the junk row''s counts, which is what replaces the list' {
        $junk = @($script:Row | Where-Object { $_['Category'] -eq 'JunkFile' })[0]
        $junk['EligibleFileCount'] | Should -Be 1234
        $junk['EligibleBytes']     | Should -Be 1220410048
        $junk['IsSizeFloor']       | Should -BeTrue
    }

    It 'carries a section''s TotalLine only where it has rows to derive it from' {
        # docs\STATE.md forbids a bare junk category total: one row on this
        # machine is 92.6% of the bytes. Get-ReviewJunkSection enforces it by
        # never producing a total without the per-row split, and the rule
        # survives the process boundary because the field does.
        foreach ($section in $script:Payload['Section']) {
            if ([string]::IsNullOrWhiteSpace($section['TotalLine'])) { continue }
            @($section['Row']).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'P6-C1 the payload carries the plan, and only the plan''s words' {

    It 'carries a Plan on every row' {
        foreach ($row in $script:Row) { $row.Contains('Plan') | Should -BeTrue }
    }

    It 'carries PreviewText verbatim, as the plan wrote it' {
        # It is already worded, already asserted against the forbidden-phrase
        # list, and P3-C2 keeps it on the ledger so the record and the screen
        # cannot disagree. A second renderer must not re-word it.
        $row = $script:Row[0]
        $plan = (& (Get-JsonContractFixturePlanner) $script:Screen.Section[0].Row[0].Finding)
        @($row['Plan']['PreviewText']) | Should -Be @($plan.PreviewText)
    }

    It 'carries exactly the published plan fields and no others' {
        foreach ($row in $script:Row) {
            @($row['Plan'].Keys) | Should -Be @($script:Contract.PlanFields)
        }
    }

    It 'NEVER carries the plan''s steps or its rollback data' {
        # A FileDeleteSet step carries the whole eligible file list, and
        # RollbackData is a registry export. Neither belongs in a read-only,
        # one-way contract. The fixture plan carries both, so this is a
        # statement about the projection.
        $plan = & (Get-JsonContractFixturePlanner) $script:Screen.Section[0].Row[0].Finding
        $plan.Step         | Should -Not -BeNullOrEmpty
        $plan.RollbackData | Should -Not -BeNullOrEmpty

        $script:PayloadKey | Should -Not -Contain 'Step'
        $script:PayloadKey | Should -Not -Contain 'RollbackData'
        $script:Line | Should -Not -Match 'must not reach the payload'
    }

    It 'leaves Plan off every row when planning is skipped' {
        $bare = ConvertTo-OptimizerScanPayload -Screen $script:Screen -SkipPlan
        foreach ($section in $bare['Section']) {
            foreach ($row in $section['Row']) { $row.Contains('Plan') | Should -BeFalse }
        }
    }
}

Describe 'P6-C1 nothing it emits promises a result' {

    # The same promise the rest of the tool keeps: this prints what is on disk
    # now, and never what a change will do to the machine afterwards.

    It 'does not say "<_>" anywhere in the serialized payload' -ForEach $ForbiddenPhrase {
        $script:Line | Should -Not -BeLike "*$_*"
    }

    It 'does not say "<_>" in its own source, string literals included' -ForEach $ForbiddenPhrase {
        $script:Code | Should -Not -BeLike "*$_*"
    }
}

Describe 'P6-C1 the runner writes protocol lines and nothing else' {

    BeforeAll {
        # ONE REAL SCAN, un-elevated, driven through a capturing writer. Every
        # assertion below reads that transcript rather than scanning again --
        # four scans plus a plan per finding is the most expensive thing in this
        # suite, and running it once is the difference between a suite that gets
        # run and one that does not.
        $script:Run = New-CapturingRun -Argument @{ SkipReceipt = $true }
    }

    It 'exits zero, because a result line was written' {
        $script:Run.ExitCode | Should -Be $script:Contract.ExitCodes.ResultWritten
    }

    It 'writes lines of which EVERY ONE parses as JSON' {
        @($script:Run.Out).Count | Should -BeGreaterThan 0
        foreach ($line in $script:Run.Out) {
            { ConvertFrom-Json -InputObject $line } | Should -Not -Throw -Because "this line is not JSON: $line"
        }
    }

    It 'writes exactly one result line, and it is the last one' {
        $kinds = @($script:Run.Out | ForEach-Object { (ConvertFrom-Json -InputObject $_).kind })
        @($kinds | Where-Object { $_ -eq 'result' }).Count | Should -Be 1
        $kinds[-1] | Should -Be 'result'
    }

    It 'writes no error line when the scan succeeded' {
        @($script:Run.Out | ForEach-Object { (ConvertFrom-Json -InputObject $_).kind } |
            Where-Object { $_ -eq 'error' }) | Should -BeNullOrEmpty
    }

    It 'writes only kinds the contract publishes' {
        foreach ($line in $script:Run.Out) {
            @($script:Contract.RecordKinds) | Should -Contain (ConvertFrom-Json -InputObject $line).kind
        }
    }

    It 'names the phases in the order the contract publishes them' {
        $seen = @($script:Run.Out |
            ForEach-Object { ConvertFrom-Json -InputObject $_ } |
            Where-Object { $_.kind -eq 'progress' } |
            ForEach-Object { $_.Phase })

        # Every phase named must be a published one, and the phase index must
        # never go backwards -- a progress indicator that jumps back is worse
        # than none.
        $lastIndex = 0
        foreach ($line in @($script:Run.Out | ForEach-Object { ConvertFrom-Json -InputObject $_ } | Where-Object { $_.kind -eq 'progress' })) {
            @($script:Contract.Phases) | Should -Contain $line.Phase
            $line.PhaseIndex | Should -BeGreaterOrEqual $lastIndex
            $lastIndex = $line.PhaseIndex
        }
        $seen | Should -Contain 'JunkFiles'
    }

    It 'names the location the junk phase is on, which is why this streams at all' {
        # The longest phase in the tool -- roughly 26,000 files -- and until this
        # chunk it went past in silence. A consumer cannot render progress from a
        # document that only arrives at the end.
        $junk = @($script:Run.Out |
            ForEach-Object { ConvertFrom-Json -InputObject $_ } |
            Where-Object { $_.kind -eq 'progress' -and $_.Phase -eq 'JunkFiles' })

        @($junk).Count | Should -BeGreaterThan 1
        foreach ($line in $junk) {
            $line.Item      | Should -Not -BeNullOrEmpty
            $line.ItemCount | Should -BeGreaterThan 0
            $line.ItemIndex | Should -BeGreaterThan 0
        }
        # One per curated location, and the last one is the last location.
        @($junk).Count | Should -Be $junk[0].ItemCount
        $junk[-1].ItemIndex | Should -Be $junk[0].ItemCount
    }

    It 'puts the incomplete-scan warnings on stderr, never on stdout' {
        # A warning on stdout is a line that does not parse, and the assertion
        # above would already have caught it. This says where they went instead.
        $script:Run.Err | Should -Not -BeNullOrEmpty
        @($script:Run.Err | Where-Object { $_ -like '*INCOMPLETE*' }) | Should -Not -BeNullOrEmpty
    }

    It 'produces a result whose row count matches the rows it carries' {
        $result = ConvertFrom-Json -InputObject $script:Run.Out[-1]
        $rows = @($result.Section | ForEach-Object { $_.Row } | Where-Object { $null -ne $_ })
        @($rows).Count | Should -Be $result.RowCount
    }

    It 'carries no shell-specific date literal in a real run either' {
        $script:Run.Out[-1] | Should -Not -Match '/Date\('
    }

    It 'carries an inventory whose length is the scan''s own InventoryCount, per section' {
        # P6-C3, AND THIS IS THE ONE THAT HAD TO RUN AGAINST THE REAL MACHINE.
        # The fixture can be made to agree with itself; only a real scan can say
        # that the projection and four live detectors agree. Nothing here reads
        # a headline sentence.
        $result = ConvertFrom-Json -InputObject $script:Run.Out[-1]

        $scanByDetector = @{}
        foreach ($scan in $result.Scan) { $scanByDetector[$scan.Detector] = $scan }

        $sectionByKey = @{}
        foreach ($section in $result.Section) { $sectionByKey[$section.Key] = $section }

        # Three of the four sections have a scan whose InventoryCount is exactly
        # the number of objects the section inspected. The services section is
        # the fourth: it is a subset of the startup scan's inventory -- the
        # entries whose Mechanism is Service -- so it is checked against that
        # subset rather than against a count that was never about it.
        $sectionByKey['StartupItems'].InventoryCount |
            Should -Be $scanByDetector['StartupItems'].InventoryCount
        $sectionByKey['InstalledApps'].InventoryCount |
            Should -Be $scanByDetector['UnusedApps'].InventoryCount
        $sectionByKey['JunkFiles'].InventoryCount |
            Should -Be $scanByDetector['JunkFiles'].InventoryCount

        $startupServices = @($sectionByKey['StartupItems'].Inventory | Where-Object { $_.Mechanism -eq 'Service' })
        $sectionByKey['Services'].InventoryCount | Should -Be @($startupServices).Count
    }

    It 'classifies every inventoried object exactly once, on a real machine' {
        $result = ConvertFrom-Json -InputObject $script:Run.Out[-1]

        foreach ($section in $result.Section) {
            $classified = 0
            foreach ($class in @($script:Contract.InventoryClasses)) {
                $classified += @($section.Inventory | Where-Object { $_.Class -eq $class }).Count
            }
            $classified | Should -Be $section.InventoryCount -Because "section '$($section.Key)' must classify every entry once"
        }
    }

    It 'gives every flagged object a row, and every row an object, on a real machine' {
        # The join a category table depends on. A flagged entry with no row
        # would be a finding that is not there; a row with no entry would be an
        # object the inventory forgot.
        #
        # ACROSS THE WHOLE PAYLOAD, not per section, and that is not a weaker
        # claim -- it is the right one. A flagged service appears in the startup
        # section's inventory, because the startup headline counts the services
        # among the things that start with this PC, while its row is in the
        # services section. The class is a judgement about the OBJECT; which
        # table draws the row is the screen's business.
        $result = ConvertFrom-Json -InputObject $script:Run.Out[-1]

        $rowIds     = @($result.Section | ForEach-Object { $_.Row } | Where-Object { $null -ne $_ } | ForEach-Object { $_.FindingId })
        $flaggedIds = @($result.Section | ForEach-Object { $_.Inventory } | Where-Object { $null -ne $_ -and $_.Class -eq 'Flagged' } | ForEach-Object { $_.FindingId })

        @($flaggedIds).Count | Should -BeGreaterThan 0 -Because 'this machine really does flag something'

        foreach ($id in $flaggedIds) {
            $id     | Should -Not -BeNullOrEmpty
            $rowIds | Should -Contain $id -Because "'$id' is flagged in an inventory and has no row anywhere"
        }
        foreach ($id in $rowIds) {
            $flaggedIds | Should -Contain $id -Because "'$id' has a row and is in no section's inventory"
        }
    }
}

Describe 'P6-C3 the inventory agrees with the live scans that produced it' {

    # THE ACCEPTANCE CRITERION, AGAINST THIS MACHINE RATHER THAN A FIXTURE. A
    # fixture can be made to agree with itself; only a real scan says that the
    # screen's inventory and four live detectors agree about how many objects
    # were looked at and how many were held back.
    #
    # ONE SET OF SCANS, and both sides of every assertion come out of it. Two
    # scans a few seconds apart can legitimately disagree -- a service can be
    # installed between them -- and a test that compared one scan's count with
    # another scan's list would be flaky for a reason that is not a defect.
    #
    # NOTHING HERE PARSES A HEADLINE SENTENCE. That is the whole point: until
    # this chunk, ProtectedTaskCount and ProtectedServiceCount reached a
    # consumer only inside prose.

    BeforeAll {
        $script:LiveScreen = InModuleScope Win11Optimizer.Engine {
            $startup = Invoke-StartupItemScan   -WarningAction SilentlyContinue
            $unused  = Invoke-UnusedAppScan     -WarningAction SilentlyContinue
            $oem     = Invoke-OemBloatwareScan  -WarningAction SilentlyContinue
            $junk    = Invoke-JunkFileScan      -WarningAction SilentlyContinue

            [pscustomobject]@{
                Screen  = Get-ReviewScreen -StartupScan $startup -UnusedAppScan $unused -OemScan $oem -JunkScan $junk -SkipReceipt
                Startup = $startup
                Unused  = $unused
                Oem     = $oem
                Junk    = $junk
            }
        }

        $script:LiveSection = @{}
        foreach ($section in $script:LiveScreen.Screen.Section) { $script:LiveSection[$section.Key] = $section }
    }

    It 'gives the startup section one entry per object the startup scan inventoried' {
        @($script:LiveSection['StartupItems'].Inventory).Count |
            Should -Be $script:LiveScreen.Startup.InventoryCount
    }

    It 'gives the installed-apps section one entry per classification the unused-app scan made' {
        # The unused-app scan's inventory, NOT the OEM scan's. Un-elevated the
        # two read the same two sources and match; elevated the OEM scan also
        # reads provisioned packages and its InventoryCount becomes a strict
        # superset, so asserting against it would fail on the first elevated run
        # for a reason that is not a defect.
        @($script:LiveSection['InstalledApps'].Inventory).Count |
            Should -Be $script:LiveScreen.Unused.InventoryCount
        @($script:LiveSection['InstalledApps'].Inventory).Count |
            Should -Be $script:LiveScreen.Unused.ConsideredCount
    }

    It 'gives the junk section one entry per curated location, flagged or not' {
        @($script:LiveSection['JunkFiles'].Inventory).Count |
            Should -Be $script:LiveScreen.Junk.InventoryCount
        @($script:LiveSection['JunkFiles'].Inventory).Count |
            Should -BeGreaterThan @($script:LiveSection['JunkFiles'].Row).Count
    }

    It 'gives the services section one entry per service the startup scan inventoried' {
        @($script:LiveSection['Services'].Inventory).Count |
            Should -Be ([int] $script:LiveScreen.Startup.MechanismCount['Service'])
    }

    It 'holds back exactly ProtectedTaskCount scheduled tasks' {
        @($script:LiveSection['StartupItems'].Inventory |
            Where-Object { $_.Class -eq 'HeldBack' -and $_.Category -eq 'StartupItem' }).Count |
            Should -Be $script:LiveScreen.Startup.ProtectedTaskCount
    }

    It 'holds back exactly ProtectedServiceCount services, in both sections that carry them' {
        @($script:LiveSection['StartupItems'].Inventory |
            Where-Object { $_.Class -eq 'HeldBack' -and $_.Category -eq 'Service' }).Count |
            Should -Be $script:LiveScreen.Startup.ProtectedServiceCount

        @($script:LiveSection['Services'].Inventory | Where-Object { $_.Class -eq 'HeldBack' }).Count |
            Should -Be $script:LiveScreen.Startup.ProtectedServiceCount
    }

    It 'holds back exactly ExcludedCount applications' {
        @($script:LiveSection['InstalledApps'].Inventory | Where-Object { $_.Class -eq 'HeldBack' }).Count |
            Should -Be $script:LiveScreen.Unused.ExcludedCount
    }

    It 'holds back exactly the locations the curated list marks inventory-only' {
        @($script:LiveSection['JunkFiles'].Inventory | Where-Object { $_.Class -eq 'HeldBack' }).Count |
            Should -Be $script:LiveScreen.Junk.InventoryOnlyCount
    }

    It 'never both flags a service and counts it as held back' {
        # The class is decided in one ordered pass with Flagged first, so an
        # overlap would surface as a held-back count that came out SHORT -- and
        # the assertion above would fail without saying why. This says why.
        #
        # The two really are disjoint by construction: a service the exclusion
        # gate holds back never reaches New-Finding, and the count loop applies
        # the same orphan exemption the matcher does so a service flagged in
        # spite of a protected class is not counted as held back. If that ever
        # stops being true, the headline beside it is wrong -- a service that
        # was flagged was not held back by anything.
        $flagged = @($script:LiveScreen.Startup.Findings |
            Where-Object { $_.Category -eq 'Service' } | ForEach-Object { [string] $_.Id })
        $held = @($script:LiveScreen.Startup.InventoryVerdict | ForEach-Object { [string] $_.Id })

        foreach ($id in $held) {
            $flagged | Should -Not -Contain $id -Because "service '$id' is counted as held back and was flagged anyway"
        }
    }

    It 'gives the two sections that share the startup scan the same verdict on one object' {
        # A service appears in the startup section's inventory and in its own.
        # The class is a judgement about the OBJECT, so it cannot differ between
        # the two tables that draw it.
        $startupServices = @{}
        foreach ($entry in @($script:LiveSection['StartupItems'].Inventory | Where-Object { $_.Category -eq 'Service' })) {
            $startupServices[$entry.Id] = $entry.Class
        }

        @($startupServices.Keys).Count | Should -Be @($script:LiveSection['Services'].Inventory).Count

        foreach ($entry in $script:LiveSection['Services'].Inventory) {
            $startupServices.ContainsKey($entry.Id) | Should -BeTrue -Because "'$($entry.Id)' is a service and belongs in both"
            $startupServices[$entry.Id] | Should -Be $entry.Class
        }
    }
}

Describe 'P6-C1 a scan that dies never looks like a scan that found nothing' {

    # This project's signature failure mode, now crossing a process boundary
    # where it is easier to hide.

    BeforeAll {
        $script:Failed = InModuleScope Win11Optimizer.Engine {
            $out = New-Object System.Collections.Generic.List[string]
            $err = New-Object System.Collections.Generic.List[string]

            Mock Invoke-JunkFileScan { throw [System.UnauthorizedAccessException]::new('Access to the path is denied.') }

            $code = Invoke-OptimizerScanJson -SkipReceipt `
                -Writer      { param($Line) $null = $out.Add([string] $Line) }.GetNewClosure() `
                -ErrorWriter { param($Line) $null = $err.Add([string] $Line) }.GetNewClosure()

            [pscustomobject]@{
                ExitCode = $code
                Out      = [string[]] @($out.ToArray())
                Err      = [string[]] @($err.ToArray())
            }
        }
    }

    It 'exits non-zero' {
        $script:Failed.ExitCode | Should -Be $script:Contract.ExitCodes.NoResult
        $script:Failed.ExitCode | Should -Not -Be 0
    }

    It 'writes no result line at all' {
        @($script:Failed.Out | ForEach-Object { (ConvertFrom-Json -InputObject $_).kind } |
            Where-Object { $_ -eq 'result' }) | Should -BeNullOrEmpty
    }

    It 'writes exactly one error line, and it is the last one' {
        $kinds = @($script:Failed.Out | ForEach-Object { (ConvertFrom-Json -InputObject $_).kind })
        @($kinds | Where-Object { $_ -eq 'error' }).Count | Should -Be 1
        $kinds[-1] | Should -Be 'error'
    }

    It 'says which phase failed, and in the words the console would use' {
        $record = ConvertFrom-Json -InputObject $script:Failed.Out[-1]
        $record.Phase         | Should -Be 'JunkFiles'
        $record.ExceptionType | Should -Be 'UnauthorizedAccessException'
        $record.Message       | Should -Be 'Access to the path is denied.'
    }

    It 'also says so on stderr, for whoever is reading a console' {
        @($script:Failed.Err | Where-Object { $_ -like '*no result was produced*' }) | Should -Not -BeNullOrEmpty
        @($script:Failed.Err | Where-Object { $_ -like '*JunkFiles*' })              | Should -Not -BeNullOrEmpty
    }

    It 'still writes every line it did write as parseable JSON' {
        foreach ($line in $script:Failed.Out) {
            { ConvertFrom-Json -InputObject $line } | Should -Not -Throw -Because "this line is not JSON: $line"
        }
    }

    It 'never writes a partial result line' {
        # THE CASE THE CONSUMER HAS TO HANDLE is a process killed mid-run, and
        # it is only detectable if a half-written result line is impossible. The
        # line is serialized whole and handed to the writer in ONE call, so a
        # writer that counts its calls counts complete lines.
        InModuleScope Win11Optimizer.Engine {
            $written = New-Object System.Collections.Generic.List[string]
            $null = Invoke-OptimizerScanJson -SkipReceipt -SkipPlan `
                -Writer      { param($Line) $null = $written.Add([string] $Line) }.GetNewClosure() `
                -ErrorWriter { param($Line) } `

            foreach ($line in $written) {
                $line | Should -Not -Match "`n"
                { ConvertFrom-Json -InputObject $line } | Should -Not -Throw
            }
        }
    }
}

Describe 'P6-C1 the launcher' {

    It 'is there and parses' {
        Test-Path -LiteralPath $script:ScanSource -PathType Leaf | Should -BeTrue
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:ScanSource, [ref] $null, [ref] $errors)
        @($errors).Count | Should -Be 0
    }

    It 'defines no functions -- everything it could get wrong lives in Json.ps1' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScanSource, [ref] $null, [ref] $null)
        @($ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true)) | Should -BeNullOrEmpty
    }

    It 'resolves the manifest by absolute path, from its own folder' {
        # A relative path here would resolve against System32 for a process
        # started with a different working directory.
        $text = [System.IO.File]::ReadAllText($script:ScanSource)
        $text | Should -Match '\$PSScriptRoot'
        $text | Should -Match 'Win11Optimizer\.Engine\.psd1'
    }

    It 'is excluded from the loader, beside the other two launchers' {
        $psm1 = [System.IO.File]::ReadAllText($script:ModulePath)
        $psm1 | Should -Match "-Exclude\s+'Entry\.ps1',\s*'Bootstrap\.ps1',\s*'Scan\.ps1'"
        # Still ONE -Exclude in the whole loader. A second one would be a second
        # list, and the second list is the one nobody looks at.
        @([regex]::Matches($psm1, '-Exclude\s+')).Count | Should -Be 1
    }

    It 'is not dot-sourced and is not exported' {
        @((Get-Module Win11Optimizer.Engine).ExportedFunctions.Keys) | Should -Not -Contain 'Scan'
        $files = InModuleScope Win11Optimizer.Engine -Parameters @{ Folder = (Join-Path $script:EngineRoot 'App') } {
            param($Folder)
            Get-OptimizerSourceFile -Path $Folder -Name 'App' -Exclude 'Entry.ps1', 'Bootstrap.ps1', 'Scan.ps1'
        }
        @($files | ForEach-Object { [System.IO.Path]::GetFileName($_) }) | Should -Not -Contain 'Scan.ps1'
    }

    It 'writes a parseable error line and exits non-zero when the module cannot load' {
        # The one piece of logic the launcher owns, because at that point nothing
        # that could report it exists yet. The line is a CONSTANT -- hand-rolling
        # JSON escaping in a launcher is how an unparseable line gets written on
        # the one run where it matters -- so the detail is on stderr and the line
        # says so.
        $broken = Join-Path $script:Scratch ('broken-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path (Join-Path $broken 'App') -ItemType Directory -Force
        Copy-Item -LiteralPath $script:ScanSource -Destination (Join-Path $broken 'App\Scan.ps1')
        # No .psd1 beside it, so the import fails for a real reason.

        $out = Join-Path $script:Scratch ('broken-out-' + [guid]::NewGuid().ToString('N') + '.txt')
        $err = Join-Path $script:Scratch ('broken-err-' + [guid]::NewGuid().ToString('N') + '.txt')
        $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

        $savedModulePath = $env:PSModulePath
        try {
            Remove-Item Env:\PSModulePath -ErrorAction SilentlyContinue
            $process = Start-Process -FilePath $shell -Wait -PassThru -NoNewWindow `
                -ArgumentList @('-NoProfile', '-File', (Join-Path $broken 'App\Scan.ps1')) `
                -RedirectStandardOutput $out -RedirectStandardError $err
        }
        finally { $env:PSModulePath = $savedModulePath }

        $process.ExitCode | Should -Not -Be 0

        $lines = @([System.IO.File]::ReadAllLines($out) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        @($lines).Count | Should -Be 1
        $record = ConvertFrom-Json -InputObject $lines[0]
        $record.kind          | Should -Be 'error'
        $record.schemaVersion | Should -Be 1
        $record.Phase         | Should -Be 'Import'

        (Get-Item -LiteralPath $err).Length | Should -BeGreaterThan 0
    }
}

Describe 'P6-C1 the junk detector''s progress hook' {

    It 'is optional, and a scan without one is unchanged' {
        $entries = @(Get-JunkLocationList | Select-Object -First 2)
        $without = Get-JunkLocationInventory -LocationEntry $entries -SkipInUseProbe -WarningAction SilentlyContinue
        $with    = Get-JunkLocationInventory -LocationEntry $entries -SkipInUseProbe -WarningAction SilentlyContinue -OnProgress { param($Location) }

        @($without.Locations | ForEach-Object { $_.Id }) | Should -Be @($with.Locations | ForEach-Object { $_.Id })
        @($without.Sources).Count | Should -Be @($with.Sources).Count
    }

    It 'is called once per location, before that location is measured' {
        $entries = @(Get-JunkLocationList | Select-Object -First 3)
        $seen = New-Object System.Collections.Generic.List[psobject]
        $null = Get-JunkLocationInventory -LocationEntry $entries -SkipInUseProbe -WarningAction SilentlyContinue `
            -OnProgress { param($Location) $null = $seen.Add($Location) }.GetNewClosure()

        @($seen).Count | Should -Be $entries.Count
        @($seen | ForEach-Object { $_.Id })    | Should -Be @($entries | ForEach-Object { $_.Id })
        @($seen | ForEach-Object { $_.Index }) | Should -Be @(1, 2, 3)
        foreach ($record in $seen) {
            $record.Count       | Should -Be $entries.Count
            $record.DisplayName | Should -Not -BeNullOrEmpty
        }
    }

    It 'is not named -ProgressAction, which PowerShell 7.4 binds for free' {
        $parameters = @((Get-Command Get-JunkLocationInventory).Parameters.Keys)
        $parameters | Should -Contain 'OnProgress'
        @((Get-Command Invoke-JunkFileScan).Parameters.Keys) | Should -Contain 'OnProgress'
    }

    It 'lets a reporter that throws take the scan down rather than swallowing it' {
        # A reporter that throws is a caller's defect. Swallowing it here would
        # hide a failure inside the scan that was supposed to be reporting its
        # progress -- which is the shape this whole project is built against.
        $entries = @(Get-JunkLocationList | Select-Object -First 1)
        { Get-JunkLocationInventory -LocationEntry $entries -SkipInUseProbe -WarningAction SilentlyContinue `
            -OnProgress { param($Location) throw 'reporter exploded' } } | Should -Throw '*reporter exploded*'
    }
}

Describe 'P6-C1 the screen gained the scans and lost nothing' {

    It 'carries one scan record per detector, with its sources' {
        @($script:Screen.Scan).Count | Should -Be 4
        foreach ($scan in $script:Screen.Scan) {
            $scan.Detector | Should -Not -BeNullOrEmpty
            @($scan.Source).Count | Should -BeGreaterThan 0
        }
    }

    It 'prints nothing new: the rendered screen never mentions the scan records' {
        # The console screen is what P4-C1 shipped. Format-ReviewSection does not
        # read Scan, and this is the assertion that says so from the outside.
        $lines = Format-ReviewScreen -Screen $script:Screen -Width 100
        @($lines | Where-Object { $_ -match 'RefusedSourceName|DurationSeconds|InventoryCount' }) | Should -BeNullOrEmpty
    }

    It 'renders the same lines whether or not the scan records are there' {
        $stripped = $script:Screen | Select-Object -Property * -ExcludeProperty Scan
        @(Format-ReviewScreen -Screen $stripped -Width 100) |
            Should -Be @(Format-ReviewScreen -Screen $script:Screen -Width 100)
    }
}

Describe 'P6-C3 the payload carries the inventory each section inspected' {

    # THE GAP THIS CLOSES. Section[].Row[] carries findings and nothing else,
    # and the prototype's tables have four classes: the two extra ones are
    # objects the engine deliberately did NOT flag. They were counted in the
    # headline sentences and absent from the payload, so the only way to draw
    # them was to parse the prose -- which is the thing this contract exists to
    # avoid.

    BeforeAll {
        $script:Inventory = @($script:Payload['Section'] | ForEach-Object { $_['Inventory'] } |
            Where-Object { $null -ne $_ })

        function Get-PayloadSection {
            param([Parameter(Mandatory)] [string] $Key)
            @($script:Payload['Section'] | Where-Object { $_['Key'] -eq $Key })[0]
        }
    }

    It 'carries an Inventory beside Row on every section' {
        foreach ($section in $script:Payload['Section']) {
            $section.Contains('Inventory')      | Should -BeTrue
            $section.Contains('InventoryCount') | Should -BeTrue
        }
    }

    It 'carries an InventoryCount that is the length of the list beside it' {
        # Both are written from one array by one projection. A consumer that
        # trusted the number over the list would draw a table shorter than the
        # scan, and say nothing about it.
        foreach ($section in $script:Payload['Section']) {
            $section['InventoryCount'] | Should -Be @($section['Inventory']).Count
        }
    }

    It 'inspected more than it flagged, in every section' {
        foreach ($section in $script:Payload['Section']) {
            @($section['Inventory']).Count |
                Should -BeGreaterThan @($section['Row']).Count -Because "section '$($section['Key'])' must carry more than its findings"
        }
    }

    It 'carries every common inventory field on every entry' {
        foreach ($entry in $script:Inventory) {
            foreach ($field in @($script:Contract.InventoryFields)) {
                $entry.Contains($field) | Should -BeTrue -Because "entry '$($entry['Id'])' must carry $field"
                $entry[$field] | Should -Not -BeNullOrEmpty
            }
        }
    }

    It 'gives every entry one of the three published classes' {
        foreach ($entry in $script:Inventory) {
            @($script:Contract.InventoryClasses) | Should -Contain $entry['Class']
        }
    }

    It 'publishes the three classes, and NotFlagged is one of them' {
        # A consumer that knew only Flagged and HeldBack would have nowhere to
        # put the objects nothing was said about, and a consumer that knew only
        # Flagged and NotFlagged would file every held-back object under
        # "nothing was said" -- which is the under-report this project exists to
        # prevent, in the same shape as reading three source statuses instead of
        # four.
        @($script:Contract.InventoryClasses) | Should -Be @('Flagged', 'HeldBack', 'NotFlagged')
    }

    It 'omits an optional field rather than writing it as null' {
        # Absent is not null, here as everywhere. A row nothing flagged has
        # nothing to say and carries no placeholder.
        $quiet = @($script:Inventory | Where-Object { $_['Id'] -eq 'HKCU\Run\Quiet' })[0]
        $quiet | Should -Not -BeNullOrEmpty
        $quiet['Class'] | Should -Be 'NotFlagged'

        foreach ($field in @($script:Contract.OptionalInventoryFields)) {
            $quiet.Contains($field) | Should -BeFalse -Because "nothing was said about this entry, so it has no $field"
        }
    }

    It 'carries a category''s own fields only on that category''s entries' {
        $startup = @($script:Inventory | Where-Object { $_['Category'] -eq 'StartupItem' })[0]
        $app     = @($script:Inventory | Where-Object { $_['Category'] -eq 'UnusedApp' })[0]
        $junk    = @($script:Inventory | Where-Object { $_['Category'] -eq 'JunkFile' })[0]

        foreach ($field in @('Mechanism', 'Scope', 'EnabledState', 'TargetExists')) {
            $startup.Contains($field) | Should -BeTrue
            $junk.Contains($field)    | Should -BeFalse
            $app.Contains($field)     | Should -BeFalse
        }

        foreach ($field in @('Source', 'Detail', 'State')) {
            $app.Contains($field)     | Should -BeTrue
            $startup.Contains($field) | Should -BeFalse
            $junk.Contains($field)    | Should -BeFalse
        }

        foreach ($field in @('Status', 'Exists', 'IsAssessed', 'EligibleBytes', 'IsSizeFloor')) {
            $junk.Contains($field)    | Should -BeTrue
            $startup.Contains($field) | Should -BeFalse
            $app.Contains($field)     | Should -BeFalse
        }
    }

    It 'writes a tri-state that could not be determined as present-and-null' {
        # TargetExists and Exists are the two nullable booleans in this payload.
        # Only $false is "proved absent"; $null is "could not be determined",
        # and collapsing them would manufacture an orphan out of a permission
        # the scan did not have.
        $murky = @($script:Inventory | Where-Object { $_['Id'] -eq 'C:\Fixture\Startup\murky.lnk' })[0]
        $murky.Contains('TargetExists') | Should -BeTrue
        $murky['TargetExists']          | Should -BeNullOrEmpty
        $script:Line | Should -Match '"TargetExists":null'

        $orphan = @($script:Inventory | Where-Object { $_['Id'] -eq 'HKCU\Run\Fixture' })[0]
        $orphan['TargetExists'] | Should -BeOfType [bool]
        $orphan['TargetExists'] | Should -BeFalse

        $temp = @($script:Inventory | Where-Object { $_['Id'] -eq 'windows-temp' })[0]
        $temp.Contains('Exists') | Should -BeTrue
        $temp['Exists']          | Should -BeNullOrEmpty
        $script:Line | Should -Match '"Exists":null'
    }

    It 'names the curated entry that held an object back, structurally' {
        # The prototype's table says "class: security (vpn-clients)". A consumer
        # reads the class off a field, never out of the reason prose.
        $held = @($script:Inventory | Where-Object { $_['Id'] -eq 'FixtureProtectedSvc' })[0]

        $held['Class']     | Should -Be 'HeldBack'
        $held['RuleId']    | Should -Be 'fixture-security-class'
        $held['RuleClass'] | Should -Be 'security'
        $held['Reason']    | Should -Be 'Security software is never offered, whatever a usage heuristic says about it.'
        $held.Contains('FindingId') | Should -BeFalse -Because 'nothing flagged it, so there is no row to point at'
    }

    It 'lets a flagged entry name its row, which is not always its own Id' {
        # Find-UnusedApp keys an Appx Finding on the package family name while
        # the inventory keys on the app's own Id. A consumer joining on Id alone
        # would miss the row and draw the application twice.
        $unused = @($script:Inventory | Where-Object { $_['Id'] -eq 'Fixture.Unused_1.0.0.0_x64__8wekyb3d8bbwe' })[0]

        $unused['Class']     | Should -Be 'Flagged'
        $unused['FindingId'] | Should -Be 'Fixture.Unused_8wekyb3d8bbwe'
        $unused['FindingId'] | Should -Not -Be $unused['Id']

        $rowIds = @($script:Row | ForEach-Object { $_['FindingId'] })
        $rowIds | Should -Contain $unused['FindingId']
    }

    It 'gives every flagged entry a row somewhere in the payload' {
        $rowIds = @($script:Row | ForEach-Object { $_['FindingId'] })
        foreach ($entry in @($script:Inventory | Where-Object { $_['Class'] -eq 'Flagged' })) {
            $entry.Contains('FindingId') | Should -BeTrue -Because "'$($entry['Id'])' says it was flagged"
            $rowIds | Should -Contain $entry['FindingId']
        }
    }

    It 'carries the objects the OEM scan flagged, whose inventory is the OTHER scan''s' {
        # The Installed apps section's inventory is the unused-app scan's
        # classifications; the curated-list scan contributes only its judgement
        # of them. Without that judgement an app flagged by the curated list
        # would read as "looked at, nothing said" and be drawn twice.
        $widget = @($script:Inventory | Where-Object { $_['Id'] -eq 'Fixture.Widget_8wekyb3d8bbwe' })[0]
        $widget['Class']     | Should -Be 'Flagged'
        $widget['FindingId'] | Should -Be 'Fixture.Widget_8wekyb3d8bbwe'
    }

    It 'never carries a whole source object along with an entry' {
        # An inventory of 289 records is the largest thing in this payload and
        # the easiest place for an object to arrive whole. The writer would
        # throw on a PSObject, so this says the projection did not copy one
        # into a hashtable either.
        foreach ($name in @('App', 'InventoryVerdict', 'ResolvedPath', 'DeclaredPath',
                            'MatchedSignals', 'SignalDetail', 'EligibleFile', 'ProfileBreakdown')) {
            foreach ($entry in $script:Inventory) {
                $entry.Contains($name) | Should -BeFalse -Because "entry '$($entry['Id'])' must not carry $name"
            }
        }
    }
}

Describe 'P6-C3 the inventory counts agree with the scan''s own count properties' {

    # THE TEST THAT IS WORTH MORE THAN IT LOOKS. The headline sentences quote
    # InventoryCount, ProtectedTaskCount and ProtectedServiceCount, and until
    # this chunk they were numbers in prose that nothing could check against a
    # list. NOTHING HERE PARSES A HEADLINE SENTENCE.

    BeforeAll {
        function Get-InventorySection {
            param([Parameter(Mandatory)] [string] $Key)
            @($script:Screen.Section | Where-Object { $_.Key -eq $Key })[0]
        }

        function Measure-InventoryClass {
            param(
                [Parameter(Mandatory)] [AllowNull()] $Section,
                [Parameter(Mandatory)] [string] $Class,
                [Parameter()] [AllowNull()] [string] $Category
            )
            $entries = @($Section.Inventory | Where-Object { $_.Class -eq $Class })
            if (-not [string]::IsNullOrWhiteSpace($Category)) {
                $entries = @($entries | Where-Object { $_.Category -eq $Category })
            }
            @($entries).Count
        }

        $script:StartupScan = @($script:Screen.Scan | Where-Object { $_.Detector -eq 'StartupItems' })[0]
    }

    It 'gives the startup section one entry per inventoried startup object' {
        (Get-InventorySection -Key 'StartupItems').Inventory.Count |
            Should -Be $script:StartupScan.InventoryCount
    }

    It 'holds back exactly ProtectedTaskCount scheduled tasks in the startup section' {
        Measure-InventoryClass -Section (Get-InventorySection -Key 'StartupItems') -Class 'HeldBack' -Category 'StartupItem' |
            Should -Be 1
    }

    It 'holds back exactly ProtectedServiceCount services, in both sections that carry them' {
        # The services appear twice: once in the startup section, whose headline
        # counts everything that starts with the PC, and once in their own. The
        # class is a judgement about the OBJECT, so it is the same in both.
        Measure-InventoryClass -Section (Get-InventorySection -Key 'StartupItems') -Class 'HeldBack' -Category 'Service' |
            Should -Be 1
        Measure-InventoryClass -Section (Get-InventorySection -Key 'Services') -Class 'HeldBack' |
            Should -Be 1
    }

    It 'gives the services section one entry per service the startup scan inventoried' {
        (Get-InventorySection -Key 'Services').Inventory.Count |
            Should -Be 2 -Because 'the fixture scan reports MechanismCount.Service = 2'
    }

    It 'holds back exactly ExcludedCount applications' {
        Measure-InventoryClass -Section (Get-InventorySection -Key 'InstalledApps') -Class 'HeldBack' |
            Should -Be 1
    }

    It 'gives the installed-apps section one entry per classification' {
        (Get-InventorySection -Key 'InstalledApps').Inventory.Count | Should -Be 5
    }

    It 'gives the junk section one entry per curated location, flagged or not' {
        $junk = Get-InventorySection -Key 'JunkFiles'
        $junk.Inventory.Count | Should -Be 3
        Measure-InventoryClass -Section $junk -Class 'Flagged'    | Should -Be 1
        Measure-InventoryClass -Section $junk -Class 'HeldBack'   | Should -Be 1
        Measure-InventoryClass -Section $junk -Class 'NotFlagged' | Should -Be 1
    }

    It 'accounts for every inventoried object exactly once' {
        foreach ($section in $script:Screen.Section) {
            $total = 0
            foreach ($class in @($script:Contract.InventoryClasses)) {
                $total += Measure-InventoryClass -Section $section -Class $class
            }
            $total | Should -Be @($section.Inventory).Count -Because "section '$($section.Key)' must classify every entry once"
        }
    }
}

Describe 'P6-C3 the console screen did not change' {

    # Format-ReviewSection and Format-ReviewScreen do not read Inventory, so the
    # console screen is byte for byte what P4-C1 shipped. The same arrangement
    # P6-C1 made for the Scan records, asserted the same way.

    BeforeAll {
        $script:Rendered = @(Format-ReviewScreen -Screen $script:Screen -Width 100)

        $script:Stripped = Get-JsonContractFixtureScreen
        foreach ($section in $script:Stripped.Section) { $section.Inventory = [psobject[]] @() }
        $script:StrippedLines = @(Format-ReviewScreen -Screen $script:Stripped -Width 100)
    }

    It 'renders the same lines whether or not the inventory is there' {
        $script:Rendered.Count | Should -Be $script:StrippedLines.Count
        for ($index = 0; $index -lt $script:Rendered.Count; $index++) {
            $script:Rendered[$index] | Should -Be $script:StrippedLines[$index]
        }
    }

    It 'never prints one of the inventory class names' {
        # CASE-SENSITIVELY, and the reason is a real near-miss: the startup
        # table's own column heading is "Why flagged", which a case-insensitive
        # match on 'Flagged' hits. The class names are capitalised machine
        # vocabulary and the screen's prose is not, so the case IS the test.
        foreach ($line in $script:Rendered) {
            foreach ($class in @($script:Contract.InventoryClasses)) {
                $line | Should -Not -CMatch ([regex]::Escape($class))
            }
        }
    }
}

Describe 'P6-C3 the detectors publish what their exclusion gate held back' {

    # The change that made the rest of this chunk possible, and the property
    # that matters most about it: the rule is evaluated ONCE. Before this,
    # Invoke-UnusedAppScan ran Get-UnusedAppExclusionMatch a second time over
    # the same classifications purely to arrive at ExcludedCount.

    BeforeAll {
        $script:ExclusionEntry = InModuleScope Win11Optimizer.Engine {
            @([pscustomobject]@{
                Id                    = 'fixture-security'
                DisplayName           = 'Fixture security software'
                Class                 = 'security'
                Reason                = 'Security software is never flagged as unused, full stop.'
                AppxPackageName       = [string[]] @()
                AppxPackageFamilyName = [string[]] @()
                RegistryDisplayName   = [string[]] @('Fixture Guard*')
                RegistryPublisher     = [string[]] @()
            })
        }

        $script:Classification = InModuleScope Win11Optimizer.Engine {
            $held = New-InstalledApp -Source 'RegistryUninstall' -Id 'HKLM\Fixture\Guard' `
                -Name 'Fixture Guard' -DisplayName 'Fixture Guard' -Publisher 'Fixture Security Inc'
            $free = New-InstalledApp -Source 'RegistryUninstall' -Id 'HKLM\Fixture\Toy' `
                -Name 'Fixture Toy' -DisplayName 'Fixture Toy' -Publisher 'Fixture Ltd'

            # MatchedSignals IS NOT EMPTY, and that is not padding. Only the
            # branch of Get-AppUsageClassification that found at least one
            # signal can produce State 'Unused', so an Unused classification
            # with no matched signal is a shape the classifier cannot make --
            # and a fabricated one walks into a real 5.1 divergence at
            # Detectors\UnusedApps.ps1:1108. See the report: @([string[]] $null)
            # is $null on 5.1 and a one-element array on 7, so `.Count` on it
            # throws under Set-StrictMode -Version Latest on one shell only.
            # A fixture that cannot occur is not worth a red test on 5.1.
            @(
                [pscustomobject]@{ App = $held; DisplayName = 'Fixture Guard'; State = 'Unused'
                                   Reason = 'No launch recorded.'; UnusedWindowDays = 180; MinimumAgeDays = 30
                                   MatchedSignals = [string[]] @('UserAssist')
                                   SignalDetail = [string[]] @('UserAssist recorded 2026-01-02 (fixture)')
                                   LastUsedUtc = ([datetime]::new(2026, 1, 2, 0, 0, 0, [System.DateTimeKind]::Utc))
                                   LastUsedAgeDays = 247.0; InstallDate = $null; InstallAgeDays = $null }
                [pscustomobject]@{ App = $free; DisplayName = 'Fixture Toy'; State = 'Unused'
                                   Reason = 'No launch recorded.'; UnusedWindowDays = 180; MinimumAgeDays = 30
                                   MatchedSignals = [string[]] @('UserAssist')
                                   SignalDetail = [string[]] @('UserAssist recorded 2026-01-02 (fixture)')
                                   LastUsedUtc = ([datetime]::new(2026, 1, 2, 0, 0, 0, [System.DateTimeKind]::Utc))
                                   LastUsedAgeDays = 247.0; InstallDate = $null; InstallAgeDays = $null }
            )
        }
    }

    It 'records a verdict for what it flagged and for what it held back' {
        $verdicts = New-Object System.Collections.Generic.List[psobject]
        $findings = @(Find-UnusedApp -Classification $script:Classification -ExclusionEntry $script:ExclusionEntry -Verdict $verdicts)

        @($findings).Count | Should -Be 1
        @($verdicts).Count | Should -Be 2

        $held = @($verdicts | Where-Object { $_.Class -eq 'HeldBack' })
        @($held).Count      | Should -Be 1
        $held[0].Id         | Should -Be 'HKLM\Fixture\Guard'
        $held[0].RuleId     | Should -Be 'fixture-security'
        $held[0].RuleClass  | Should -Be 'security'
        $held[0].Reason     | Should -Be 'Security software is never flagged as unused, full stop.'
        $held[0].FindingId  | Should -BeNullOrEmpty

        $flagged = @($verdicts | Where-Object { $_.Class -eq 'Flagged' })
        @($flagged).Count   | Should -Be 1
        $flagged[0].Id        | Should -Be 'HKLM\Fixture\Toy'
        $flagged[0].FindingId | Should -Be 'HKLM\Fixture\Toy'
        $flagged[0].RuleId    | Should -BeNullOrEmpty
    }

    It 'still returns the same findings when no list is handed in' {
        # The out-collection is optional and additive: four existing call sites
        # pass nothing and must be unaffected.
        $with    = @(Find-UnusedApp -Classification $script:Classification -ExclusionEntry $script:ExclusionEntry -Verdict (New-Object System.Collections.Generic.List[psobject]))
        $without = @(Find-UnusedApp -Classification $script:Classification -ExclusionEntry $script:ExclusionEntry)

        @($without).Count | Should -Be @($with).Count
        @($without | ForEach-Object { $_.Id }) | Should -Be @($with | ForEach-Object { $_.Id })
    }

    It 'never puts a verdict on the Finding stream' {
        # The verdicts go into the caller's list, not onto the pipeline. A
        # second record type mixed into a Finding stream would break every
        # existing consumer of it.
        $verdicts = New-Object System.Collections.Generic.List[psobject]
        $findings = @(Find-UnusedApp -Classification $script:Classification -ExclusionEntry $script:ExclusionEntry -Verdict $verdicts)

        foreach ($finding in $findings) {
            $finding.PSObject.TypeNames | Should -Contain 'Win11Optimizer.Finding'
        }
    }

    It 'records one verdict per inventory record inside a grouped curated finding' {
        # Find-KnownBloatware deduplicates per (whitelist entry, RemovalMethod),
        # so one Finding can cover a per-user Appx package AND its provisioned
        # twin. Recording one verdict per FINDING would leave the second record
        # looking like something nothing was said about.
        $whitelist = InModuleScope Win11Optimizer.Engine {
            @([pscustomobject]@{
                Id                    = 'fixture-widget'
                DisplayName           = 'Fixture Widget'
                Vendor                = 'Fixture'
                Reason                = 'Preinstalled and unused.'
                EvidenceSource        = 'curated'
                RequiresConsent       = $false
                AppxPackageName       = [string[]] @('Fixture.Widget')
                AppxPackageFamilyName = [string[]] @()
                RegistryDisplayName   = [string[]] @()
                RegistryPublisher     = [string[]] @()
            })
        }

        $apps = InModuleScope Win11Optimizer.Engine {
            @(
                (New-InstalledApp -Source 'AppxPackage' -Id 'Fixture.Widget_8wekyb3d8bbwe' `
                    -Name 'Fixture.Widget' -DisplayName 'Fixture Widget' -PackageFamilyName 'Fixture.Widget_8wekyb3d8bbwe')
                (New-InstalledApp -Source 'AppxProvisionedPackage' -Id 'Fixture.Widget_1.0.0.0_neutral_8wekyb3d8bbwe' `
                    -Name 'Fixture.Widget' -DisplayName 'Fixture Widget' -PackageFamilyName 'Fixture.Widget_8wekyb3d8bbwe')
            )
        }

        $verdicts = New-Object System.Collections.Generic.List[psobject]
        $findings = @(Find-KnownBloatware -InstalledApp $apps -KnownBloatwareEntry $whitelist -Verdict $verdicts)

        @($findings).Count | Should -Be 1
        @($verdicts).Count | Should -Be 2
        @($verdicts | ForEach-Object { $_.Class } | Sort-Object -Unique) | Should -Be @('Flagged')
        @($verdicts | ForEach-Object { $_.FindingId } | Sort-Object -Unique) | Should -Be @($findings[0].Id)
        @($verdicts | ForEach-Object { $_.Id }) | Should -Be @($apps | ForEach-Object { $_.Id })
    }

    It 'evaluates the exclusion rule once, not once per count' {
        # THE REGRESSION THIS CHANGE EXISTS TO PREVENT COMING BACK.
        # Invoke-UnusedAppScan used to loop over the classifications a second
        # time, calling Get-UnusedAppExclusionMatch again purely to arrive at
        # ExcludedCount. One safety rule evaluated in two places is two places
        # for it to be wrong, and the two really can disagree -- the second loop
        # had no null-App guard and the gate does.
        #
        # AST, not a string count: the file also DEFINES that function, and a
        # text search cannot tell a definition from a call.
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $script:EngineRoot 'Detectors\UnusedApps.ps1'), [ref] $tokens, [ref] $errors)

        $calls = @($ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | Where-Object { $_.GetCommandName() -eq 'Get-UnusedAppExclusionMatch' })

        @($calls).Count | Should -Be 1 -Because 'the exclusion gate is invoked in exactly one place, inside Find-UnusedApp'

        # And it is inside the matcher, not beside it in the scan function.
        $enclosing = $calls[0].Parent
        while ($null -ne $enclosing -and $enclosing -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
            $enclosing = $enclosing.Parent
        }
        $enclosing.Name | Should -Be 'Find-UnusedApp'
    }

    It 'derives ProtectedServiceCount from the records it kept' {
        $source = [System.IO.File]::ReadAllText((Join-Path $script:EngineRoot 'Detectors\StartupItems.ps1'))
        $source | Should -Match '\$protectedServiceCount\s*=\s*\$protectedService\.Count'
        $source | Should -Not -Match '\$protectedServiceCount\+\+'
    }
}
