<#
    THE ENGINE MANIFEST -- chunk P6-C2, the GUI shell.

    This is a test fixture, not a test file: it has no .Tests.ps1 suffix, so
    Invoke-Tests.ps1 does not discover it as a suite. Dot-source it instead,
    the way tests\ForbiddenPhrase.ps1 is dot-sourced.

    WHAT IT IS FOR
    --------------
    P6-C2 adds the first code in this project that is not PowerShell, and its
    one hard rule is that the engine folder is not touched. The acceptance
    criterion in docs\handoff\21-gui-scaffold.md asks for a test that
    src\Win11Optimizer.Engine\ is byte-identical to HEAD.

    IT IS NOT COMPARED AGAINST HEAD, AND THAT IS DELIBERATE.

      1. It could not be. P6-C1 is in the working tree and not committed:
         App\Scan.ps1 and Review\Json.ps1 are untracked and four more engine
         files are modified. A test that diffed against HEAD would fail on its
         first run for reasons that have nothing to do with this chunk.

      2. git diff DOES NOT SEE UNTRACKED FILES. docs\REVIEW.md records this as
         a measured trap -- 'git diff --numstat -- tests/' was blind to four of
         the five test files P6-C1 added. A guard against "the engine changed"
         that cannot see a NEW engine file is the same shape as every other bug
         this project has hit: it returns less than the truth without erroring.

    So the manifest records every file under the engine folder with its
    SHA-256, and the test recomputes and compares BOTH THE FILE LIST AND EVERY
    HASH. A modified file fails on its hash. An added or deleted one fails on
    the list. Neither depends on what git happens to know about.

    FORMAT. One line per file, sorted ordinally by path, LF, pure ASCII:

        <SHA-256, uppercase hex>  <path relative to the engine folder, / separated>

    Two spaces between them, so the file is also readable by sha256sum. Paths
    use / rather than \ so the text does not depend on which shell wrote it.

    THE FILES ARE ENUMERATED WITH [System.IO.Directory]::GetFiles, NOT
    Get-ChildItem. docs\REVIEW.md, measured against C:\Windows\Prefetch:
    Get-ChildItem on a folder the current user cannot list returns zero items
    and raises no error EVEN WITH -ErrorAction Stop, while the .NET call
    throws. A manifest generator that silently enumerated nothing would write
    an empty manifest and every later run would agree with it.

    REGENERATING IT. Only when the engine really changed, and then the diff on
    this file is the review:

        . tests\Fixtures\EngineManifest.ps1
        Write-OptimizerEngineManifest

    ASCII only -- see docs\REVIEW.md for what one non-ASCII character in a
    comment does to a whole container under 5.1.
#>

function Get-OptimizerEngineRoot {
    <#
        The engine folder, as an absolute path. Resolved from this file rather
        than from the current directory, which is not ours to depend on.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $repoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Join-Path -Path $repoRoot -ChildPath 'src\Win11Optimizer.Engine'
}

function Get-OptimizerEngineManifestPath {
    # The committed manifest, beside this file.
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Join-Path -Path $PSScriptRoot -ChildPath 'engine-manifest.txt'
}

function Get-OptimizerEngineManifest {
    <#
    .SYNOPSIS
        The engine folder as one manifest string: SHA-256 and path, one file
        per line, LF, ASCII. Reads; changes nothing.

    .PARAMETER Path
        The folder to describe. Defaults to the engine folder.

    .OUTPUTS
        [string] -- LF-delimited, with a trailing LF, or '' for no files.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [ValidateNotNullOrEmpty()] [string] $Path = (Get-OptimizerEngineRoot)
    )

    if (-not [System.IO.Directory]::Exists($Path)) {
        throw "Get-OptimizerEngineManifest: '$Path' is not a folder that exists."
    }

    # GetFiles, not Get-ChildItem: a folder that cannot be listed must throw
    # here rather than contribute zero files to a manifest that then looks
    # complete. docs\REVIEW.md.
    $files = [System.IO.Directory]::GetFiles($Path, '*', [System.IO.SearchOption]::AllDirectories)

    $root = [System.IO.Path]::GetFullPath($Path)
    if (-not $root.EndsWith('\')) { $root = $root + '\' }

    $relativePath = New-Object System.Collections.Generic.List[string]
    $hashByPath   = @{}

    foreach ($file in @($files)) {
        $full = [System.IO.Path]::GetFullPath($file)
        if (-not $full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Get-OptimizerEngineManifest: '$full' is not under '$root'."
        }

        $relative = $full.Substring($root.Length).Replace('\', '/')
        if ($hashByPath.ContainsKey($relative)) {
            throw "Get-OptimizerEngineManifest: '$relative' was enumerated twice."
        }

        $relativePath.Add($relative)
        $hashByPath[$relative] = (Get-FileHash -Path $full -Algorithm SHA256).Hash.ToUpperInvariant()
    }

    # SORTED BY PATH, NOT BY LINE. Sorting the assembled line would sort by the
    # hash, and a file whose contents changed would then move somewhere else in
    # the manifest -- turning a one-line diff into a two-line one that does not
    # say which file it was about. This file is reviewed by its diff.
    #
    # Ordinal, so the order does not depend on the culture the shell happens to
    # be running under. Sort-Object without -CaseSensitive is culture-aware and
    # would not be stable across machines.
    $sorted = [string[]] @($relativePath)
    [array]::Sort($sorted, [System.StringComparer]::Ordinal)

    if (@($sorted).Count -eq 0) { return '' }

    $lines = foreach ($relative in $sorted) { $hashByPath[$relative] + '  ' + $relative }
    ((@($lines) -join "`n") + "`n")
}

function Write-OptimizerEngineManifest {
    <#
    .SYNOPSIS
        Writes the manifest to tests\Fixtures\engine-manifest.txt.

    .DESCRIPTION
        WriteAllBytes over ASCII bytes rather than Set-Content, for the reason
        tests\Fixtures\Write-JsonContractFixture.ps1 gives: nothing between the
        string and the file is then free to add a BOM, or to translate an LF
        into a CRLF on one shell and not the other.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter()] [ValidateNotNullOrEmpty()] [string] $Path = (Get-OptimizerEngineManifestPath)
    )

    $text = Get-OptimizerEngineManifest

    if ($PSCmdlet.ShouldProcess($Path, 'Write the engine manifest')) {
        [System.IO.File]::WriteAllBytes($Path, [System.Text.Encoding]::ASCII.GetBytes($text))
    }

    $Path
}
