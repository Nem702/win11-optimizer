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
