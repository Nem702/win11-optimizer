<#
    THE forbidden-benefit-phrase list. One file, read by every suite that
    enforces it. Chunk P5-C3, change 5.

    This is a test fixture, not a test file: it has no .Tests.ps1 suffix, so
    Invoke-Tests.ps1 does not discover it as a suite. Dot-source it instead.

    WHAT IT IS FOR
    --------------
    This project prints what is on disk now. It never says what a change will do
    to the machine afterwards -- no space freed, no seconds saved, no "runs
    faster". docs\PLAN.md fixes the run receipt as derived from what was actually
    deleted, and a sentence that promises a number turns the tool into the
    benchmark claim it exists not to make. These are the phrases that would break
    that promise, and five suites assert that nothing they print contains any of
    them: the junk list file, every Finding's evidence, every removal preview,
    the review screen (source literals included), the execution transcript and
    the run receipt.

    'reclaim ' CARRIES A TRAILING SPACE ON PURPOSE. Every junk Finding ends with
    "not a promise of space reclaimed", which is the opposite claim and must
    survive. Forbidding the bare word would ban the sentence that exists to make
    the promise explicit.

    WHY IT IS HERE RATHER THAN IN A SUITE
    -------------------------------------
    It used to live in two: tests\DispatcherJunkAmendment.Tests.ps1 held five
    phrases and tests\RemovalDispatcher.Tests.ps1 held nine, they DIFFERED, and
    neither was a superset of the other. Three more suites needed the union, so
    each of them lifted both lists out by AST at run time rather than write a
    third copy -- the same 20-line extractor pasted three times, keyed on finding
    an array literal that happens to contain 'free up'.

    Nothing was unenforced under that arrangement, and it had one property worth
    keeping: a phrase added to either list was picked up everywhere without an
    edit. THIS FILE KEEPS THAT PROPERTY AND MAKES IT THE OBVIOUS ONE -- add a
    phrase below and all five suites enforce it on the next run, with no AST, no
    extractor, and no way for two lists to disagree because there is only one.

    The list below is the exact union of what those two suites enforced before
    P5-C3, so nothing enforces fewer phrases than it did.

    USE
    ---
    Pester 5 runs a file's top level during DISCOVERY and its BeforeAll during
    RUN, in separate scopes, so a suite that needs the list in both places
    dot-sources it in both places:

        . (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')   # top level, for -ForEach
        $ForbiddenPhrase = Get-OptimizerForbiddenPhrase

        BeforeAll {
            . (Join-Path $PSScriptRoot 'ForbiddenPhrase.ps1')
            $script:ForbiddenPhrase = Get-OptimizerForbiddenPhrase
        }

    ASCII only -- see docs\REVIEW.md for what one non-ASCII character in a
    comment does to a whole container under 5.1.
#>

function Get-OptimizerForbiddenPhrase {
    <#
        The phrases, sorted and de-duplicated so two suites comparing counts see
        the same list in the same order. Matched case-insensitively by every
        caller, as a SUBSTRING -- these are not regexes, and a caller that needs
        one escapes it.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    [string[]] @(@(
        'free up'
        'frees up'
        'freed up'
        'reclaim '
        'will reclaim'
        'space you will'
        'will save'
        'you will get back'
        'speed up'
        'run faster'
    ) | Sort-Object -Unique)
}
