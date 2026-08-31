<#
    The review screen -- chunk P4-C1.

    ONE CONSOLE SCREEN. It shows what the four detectors found, lets a person
    pick what to act on, prints the plan for each pick, and asks yes or no once.
    It stops there. Wiring a confirmed selection to Invoke-RemovalPlan is P4-C2,
    and NOTHING IN THIS FILE CALLS IT -- not behind a switch, not behind a
    -Force, not at all. A test asserts that against the AST rather than against
    this comment.

    PRINTING ONLY. No window, no event loop, no background thread, no browser,
    no spinner, no progress bar, no TUI framework. Everything this file produces
    is a string, which is what makes it testable the same way as the rest of the
    project: Format-ReviewScreen hands back [string[]] and a test reads it.

    THE STRUCTURE IS DECIDE-THEN-PRINT, and it is two functions per section:
    Get-Review*Section works out what the section should SAY (counts, wording,
    which rows exist, what is held back), and Format-ReviewSection turns that
    into lines. The first is where the tests are; the second is spot-checked.
    There is no view-model layer beyond the section object itself.

    WHAT IT DOES NOT DO, and each of these is a decision made elsewhere:

      * It never re-words a plan. Plan.PreviewText is what a person reads before
        approving, and Get-OptimizerRunReceipt's ReceiptText is what they read
        afterwards. Both are already written. This file PRINTS them.
      * It never re-derives a safety label. Get-FindingContract().SafetyLabelRule
        is run; the two-axis rule is not restated here in any form.
      * It never prints a benefit claim -- no space freed, no time saved, no
        "faster". The forbidden-phrase tests the junk detector's evidence is held
        to apply to every line this file emits.
      * It never prints a bare category total for junk files. On this machine ONE
        row is 92.6% of the bytes (docs\STATE.md, after P3-C1a), so a category
        figure without the per-row split beside it is a number that misleads by
        construction. The total is derived from the rows and rendered only after
        them.

    COLOUR is built from [char]27 by hand. $PSStyle is PowerShell 7 only and the
    `e escape shorthand does not exist in 5.1, and 5.1 is this project's floor.
    Every escape sequence is added AFTER padding, so it costs no display width
    and the columns line up whether colour is on or off.

    ASCII only, framing included -- '+', '-' and '|'. Box-drawing characters are
    non-ASCII and one of those in a source file takes down 137 unrelated tests on
    5.1 (docs\REVIEW.md, after P3-C1a).
#>

#region Constants

$script:ReviewScreenTypeName    = 'Win11Optimizer.ReviewScreen'
$script:ReviewSectionTypeName   = 'Win11Optimizer.ReviewSection'
$script:ReviewRowTypeName       = 'Win11Optimizer.ReviewRow'
$script:ReviewSelectionTypeName = 'Win11Optimizer.ReviewSelection'

# The four sections, IN SCREEN ORDER. Each one opens differently because each
# category's honest first sentence is a different sentence -- the order and the
# reasons are docs\STATE.md's, not this file's invention.
$script:ReviewSectionStartup   = 'StartupItems'
$script:ReviewSectionInstalled = 'InstalledApps'
$script:ReviewSectionJunk      = 'JunkFiles'
$script:ReviewSectionService   = 'Services'

$script:ReviewSectionKeys = @(
    $script:ReviewSectionStartup
    $script:ReviewSectionInstalled
    $script:ReviewSectionJunk
    $script:ReviewSectionService
)

$script:ReviewDefaultWidth = 100
$script:ReviewMinimumWidth = 60
$script:ReviewMaximumWidth = 140

# The narrowest a column may be squeezed to before the layout gives up and lets
# the line run long. Below this a truncated cell is all ellipsis and no content.
$script:ReviewMinimumColumnWidth = 8
$script:ReviewColumnGap = 2

# ANSI, from [char]27. Held as one table so nothing else in this file spells an
# escape sequence out, and so Format-ReviewScreen -Colour:$false can simply hand
# back the empty string for every key.
$script:ReviewEscape = [string][char]27

$script:ReviewStyle = [ordered]@{
    Reset   = "$([char]27)[0m"
    Frame   = "$([char]27)[38;5;244m"
    Title   = "$([char]27)[1;36m"
    Lead    = "$([char]27)[1m"
    Muted   = "$([char]27)[38;5;244m"
    Number  = "$([char]27)[36m"
    Safe    = "$([char]27)[32m"
    Review  = "$([char]27)[33m"
    Partial = "$([char]27)[1;33m"
    Prompt  = "$([char]27)[1;37m"
}

# What a startup mechanism is called on screen. The detector's vocabulary is
# machine-facing; this is the same fact in the words a person uses.
$script:ReviewMechanismText = @{
    'RunKey'        = 'Registry Run key'
    'StartupFolder' = 'Startup folder'
    'ScheduledTask' = 'Scheduled task'
    'Service'       = 'Windows service'
}

# The same four in the plural, written out rather than derived by adding an 's'.
# 'Registry Run keys' is not what an 's' produces from a phrase whose last word
# is already the noun, and a headline sentence is the wrong place to be clever.
$script:ReviewMechanismPluralText = @{
    'RunKey'        = 'registry Run keys'
    'StartupFolder' = 'Startup-folder shortcuts'
    'ScheduledTask' = 'scheduled tasks'
    'Service'       = 'Windows services'
}

# Why a startup item was flagged, in a column's worth of words. An unmapped
# reason falls through to its own name rather than to a blank -- a row with no
# stated reason would violate the one rule the Finding contract enforces at
# construction, and printing an empty cell would hide that rather than show it.
$script:ReviewReasonText = @{
    'Orphan'  = 'Target file is missing'
    'Curated' = 'On the curated list'
}

#endregion

#region Internal: text helpers

function Get-ReviewStyleText {
    # One style, or '' when colour is off. Every caller goes through this so the
    # no-colour path is one branch rather than one per call site.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Name,
        [Parameter(Mandatory)] [bool] $Colour
    )

    if (-not $Colour) { return '' }
    if ([string]::IsNullOrEmpty($Name)) { return '' }
    if (-not $script:ReviewStyle.Contains($Name)) { return '' }
    [string] $script:ReviewStyle[$Name]
}

function Add-ReviewStyle {
    # Wraps already-padded text. AFTER padding on purpose: an escape sequence has
    # no display width, so colouring a padded cell keeps every column aligned and
    # a plain render and a coloured render differ by escapes alone.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Name,
        [Parameter(Mandatory)] [bool] $Colour
    )

    $style = Get-ReviewStyleText -Name $Name -Colour $Colour
    if ([string]::IsNullOrEmpty($style)) { return $Text }
    $style + $Text + $script:ReviewStyle['Reset']
}

function Get-ReviewTruncatedText {
    # Fits text to a width, ending in '...' when it does not fit. ASCII ellipsis,
    # three characters, never the single non-ASCII one.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] $Text,
        [Parameter(Mandatory)] [int] $Width
    )

    $value = [string] $Text
    if ($Width -le 0) { return '' }
    if ($value.Length -le $Width) { return $value }
    if ($Width -le 3) { return $value.Substring(0, $Width) }
    $value.Substring(0, $Width - 3) + '...'
}

function Split-ReviewText {
    <#
        Word-wraps one paragraph to a width and returns the lines, each already
        carrying its indent.

        A word longer than the width is broken rather than allowed to run off the
        edge: the junk detector's incompleteness reasons quote absolute paths,
        and one of those is 120 characters with no space in it.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] $Text,
        [Parameter(Mandatory)] [int] $Width,
        [Parameter()] [string] $Indent = ''
    )

    $value = ([string] $Text).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { return [string[]] @() }

    $available = $Width - $Indent.Length
    if ($available -lt 12) { $available = 12 }

    $lines   = New-Object System.Collections.Generic.List[string]
    $current = ''

    foreach ($word in @($value -split '\s+')) {
        if ([string]::IsNullOrEmpty($word)) { continue }

        $piece = $word
        while ($piece.Length -gt $available) {
            if ($current.Length -gt 0) {
                $null = $lines.Add($Indent + $current)
                $current = ''
            }
            $null = $lines.Add($Indent + $piece.Substring(0, $available))
            $piece = $piece.Substring($available)
        }

        if ($current.Length -eq 0) { $current = $piece }
        elseif (($current.Length + 1 + $piece.Length) -le $available) { $current = "$current $piece" }
        else {
            $null = $lines.Add($Indent + $current)
            $current = $piece
        }
    }

    if ($current.Length -gt 0) { $null = $lines.Add($Indent + $current) }
    [string[]] @($lines.ToArray())
}

function Get-ReviewColumnWidth {
    <#
        Column widths for one table: the natural width of each column, squeezed
        from the widest end until the row fits.

        Returns the widths, and never returns one below the floor -- a table that
        genuinely cannot fit runs long rather than becoming a column of ellipses.
    #>
    [CmdletBinding()]
    [OutputType([int[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Header,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Row,
        [Parameter(Mandatory)] [int] $Width
    )

    $count = @($Header).Count
    if ($count -lt 1) { return [int[]] @() }

    $widths = New-Object 'System.Collections.Generic.List[int]'
    for ($index = 0; $index -lt $count; $index++) {
        $widest = ([string] $Header[$index]).Length
        # $entry, NOT $row. A foreach variable that differs from a parameter of
        # the enclosing function only by case IS that parameter, and re-applies
        # its type constraint on every iteration -- so 'foreach ($row in @($Row))'
        # hands each pass a ONE-ELEMENT ARRAY wrapping the row, it type-checks,
        # nothing is raised, and every property read inside returns $null. It cost
        # this chunk a render of five blank rows. docs\REVIEW.md, after P3-C2.
        foreach ($entry in @($Row)) {
            $cells = [string[]] @(Get-OptimizerProperty -InputObject $entry -Name 'Cell' -Default @())
            if ($index -ge $cells.Count) { continue }
            $length = ([string] $cells[$index]).Length
            if ($length -gt $widest) { $widest = $length }
        }
        $null = $widths.Add($widest)
    }

    $gaps = $script:ReviewColumnGap * ($count - 1)
    # Shrink the widest column one character at a time. Slower than solving it,
    # and it keeps the narrow columns intact -- which is what a reader needs,
    # because the wide column is the prose one and the narrow ones are the facts.
    while ((($widths | Measure-Object -Sum).Sum + $gaps) -gt $Width) {
        $largest = 0
        for ($index = 1; $index -lt $count; $index++) {
            if ($widths[$index] -gt $widths[$largest]) { $largest = $index }
        }
        if ($widths[$largest] -le $script:ReviewMinimumColumnWidth) { break }
        $widths[$largest] = $widths[$largest] - 1
    }

    [int[]] @($widths.ToArray())
}

function Format-ReviewTable {
    <#
        Header, rule and rows, aligned. Purely mechanical: it reads Cell and
        Style off each row and knows nothing about what any of them mean.

        Style is a parallel array of style names, one per cell, '' for none. It
        exists so that "the safety column is coloured" is a decision the SECTION
        makes, in the function that decides what the section says, rather than a
        column index hard-coded into the printer.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Header,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Row,
        [Parameter(Mandatory)] [int] $Width,
        [Parameter(Mandatory)] [bool] $Colour,
        [Parameter()] [string] $Indent = '  '
    )

    $rows = @($Row)
    if ($rows.Count -lt 1) { return [string[]] @() }

    $available = $Width - $Indent.Length
    $widths = Get-ReviewColumnWidth -Header $Header -Row $rows -Width $available
    $count  = @($Header).Count

    $lines = New-Object System.Collections.Generic.List[string]

    $headerCells = New-Object System.Collections.Generic.List[string]
    $ruleCells   = New-Object System.Collections.Generic.List[string]
    for ($index = 0; $index -lt $count; $index++) {
        $null = $headerCells.Add((Get-ReviewTruncatedText -Text $Header[$index] -Width $widths[$index]).PadRight($widths[$index]))
        $null = $ruleCells.Add(('-' * $widths[$index]))
    }

    $null = $lines.Add($Indent + (Add-ReviewStyle -Text (($headerCells -join (' ' * $script:ReviewColumnGap)).TrimEnd()) -Name 'Muted' -Colour $Colour))
    $null = $lines.Add($Indent + (Add-ReviewStyle -Text ($ruleCells -join (' ' * $script:ReviewColumnGap)) -Name 'Frame' -Colour $Colour))

    # $entry, not $row -- see the note in Get-ReviewColumnWidth above.
    foreach ($entry in $rows) {
        $cells  = [string[]] @(Get-OptimizerProperty -InputObject $entry -Name 'Cell' -Default @())
        $styles = [string[]] @(Get-OptimizerProperty -InputObject $entry -Name 'Style' -Default @())

        $rendered = New-Object System.Collections.Generic.List[string]
        for ($index = 0; $index -lt $count; $index++) {
            $text  = $(if ($index -lt $cells.Count) { [string] $cells[$index] } else { '' })
            $style = $(if ($index -lt $styles.Count) { [string] $styles[$index] } else { '' })
            $padded = (Get-ReviewTruncatedText -Text $text -Width $widths[$index]).PadRight($widths[$index])
            $null = $rendered.Add((Add-ReviewStyle -Text $padded -Name $style -Colour $Colour))
        }
        $null = $lines.Add($Indent + ($rendered -join (' ' * $script:ReviewColumnGap)))
    }

    [string[]] @($lines.ToArray())
}

function Get-ReviewMapValue {
    <#
        One value out of something that may be a DICTIONARY or an OBJECT.

        MechanismCount arrives on the startup scan result as an [ordered]
        hashtable, and PSObject.Properties does not see dictionary keys at all --
        so Get-OptimizerProperty answers $null for a key that is right there.
        That is the same shape of gap docs\REVIEW.md already records for
        Get-ItemProperty, and it renders as "0 Windows services were looked at"
        on a machine with 90 of them.

        Both readings have to work, not just the dictionary one: the very same
        field comes back as a PSCustomObject after a JSON round trip, and a
        screen that rendered differently depending on whether the scan was fresh
        or read out of a log would be worse than one that rendered wrong.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Name,
        [Parameter()] $Default = $null
    )

    if ($null -eq $InputObject) { return $Default }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if (-not $InputObject.Contains($Name)) { return $Default }
        $value = $InputObject[$Name]
        if ($null -eq $value) { return $Default }
        return $value
    }

    Get-OptimizerProperty -InputObject $InputObject -Name $Name -Default $Default
}

function Get-ReviewSafetyLabel {
    <#
        The safety label for one Finding, obtained by RUNNING the Finding
        contract's own rule.

        The two-axis rule and its fail-closed behaviour are not restated here in
        any form, and the label is not read off the object either: a Finding that
        arrived deserialized has SafetyLabel as a plain string that nothing
        re-checked, and a Finding that arrived from a future detector may not
        have the property at all. Running the rule gives the same answer for a
        live Finding and the fail-closed answer for anything else.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Finding
    )

    $contract = Get-FindingContract
    [string](& $contract.SafetyLabelRule `
        (Get-OptimizerProperty -InputObject $Finding -Name 'Confidence') `
        (Get-OptimizerProperty -InputObject $Finding -Name 'RequiresConsent'))
}

function Get-ReviewSafetyStyle {
    # Which style a safety label is drawn in. Keyed off the contract's own two
    # strings so a renamed label cannot silently lose its colour, and colour is
    # never the only carrier -- the words are printed either way.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Label
    )

    $labels = @((Get-FindingContract).SafetyLabels)
    if ($labels.Count -ge 1 -and $Label -eq $labels[0]) { return 'Safe' }
    'Review'
}

function Get-ReviewShortReason {
    # The 'why flagged' cell. FindingReason where the detector states one, the
    # first sentence of the first evidence line otherwise. Evidence is mandatory
    # on every Finding, so this cell can only be empty for an object that is not
    # a Finding at all.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Finding
    )

    $reason = [string](Get-OptimizerProperty -InputObject $Finding -Name 'FindingReason' -Default '')
    if (-not [string]::IsNullOrWhiteSpace($reason)) {
        if ($script:ReviewReasonText.ContainsKey($reason)) { return [string] $script:ReviewReasonText[$reason] }
        return $reason
    }

    # An OEM match names the list entry it matched. That is the whole reason, in
    # a column's worth of characters, and it is the string a person would search
    # the curated list for -- where the first sentence of the evidence truncates
    # to "Matches curated known-bloa..." and says nothing at all.
    $entryId = [string](Get-OptimizerProperty -InputObject $Finding -Name 'WhitelistEntryId' -Default '')
    if (-not [string]::IsNullOrWhiteSpace($entryId)) { return "List entry '$entryId'" }

    $evidence = @(Get-OptimizerProperty -InputObject $Finding -Name 'Evidence' -Default @())
    if ($evidence.Count -lt 1) { return '(no reason stated)' }

    $first = [string] $evidence[0]
    $stop  = $first.IndexOf('. ')
    if ($stop -gt 0) { return $first.Substring(0, $stop) }
    $first
}

function New-ReviewRow {
    # One numbered row. Cell and Style are parallel; the Finding is carried whole
    # so a selection can hand back the object itself rather than a row index that
    # something later has to resolve.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [int] $Number,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $SectionKey,
        [Parameter(Mandatory)] [AllowNull()] $Finding,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Cell,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Style,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $SafetyLabel
    )

    [pscustomobject][ordered]@{
        PSTypeName  = $script:ReviewRowTypeName
        Number      = $Number
        SectionKey  = $SectionKey
        DisplayName = [string](Get-OptimizerProperty -InputObject $Finding -Name 'DisplayName' -Default '(unnamed)')
        Category    = [string](Get-OptimizerProperty -InputObject $Finding -Name 'Category' -Default '')
        SafetyLabel = $SafetyLabel
        Cell        = [string[]] @($Cell)
        Style       = [string[]] @($Style)
        Finding     = $Finding
    }
}

function New-ReviewSection {
    # Every field on every section, whatever the category -- Set-StrictMode
    # -Version Latest is on for everything that reads this.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Key,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Title,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Headline,
        [Parameter()] [AllowEmptyCollection()] [string[]] $Note = @(),
        [Parameter()] [AllowEmptyCollection()] [string[]] $ColumnHeader = @(),
        [Parameter()] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Row = @(),
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $TotalLine,
        [Parameter()] [bool] $IsComplete = $true,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $IncompleteReason,
        [Parameter()] [AllowEmptyCollection()] [string[]] $RefusedSourceName = @(),
        [Parameter()] [AllowEmptyString()] [string] $EmptyText = 'Nothing here is flagged.'
    )

    [pscustomobject][ordered]@{
        PSTypeName        = $script:ReviewSectionTypeName
        Key               = $Key
        Title             = $Title
        Headline          = [string[]] @($Headline)
        Note              = [string[]] @($Note)
        ColumnHeader      = [string[]] @($ColumnHeader)
        Row               = [psobject[]] @($Row)
        # Only ever non-null where Row is non-empty. See Get-ReviewJunkSection:
        # the rule that a category total may not be printed without the per-row
        # split is enforced by never producing one without rows, not by a
        # convention the renderer is trusted to follow.
        TotalLine         = $(if ([string]::IsNullOrWhiteSpace($TotalLine)) { $null } else { $TotalLine })
        IsComplete        = [bool] $IsComplete
        IncompleteReason  = $(if ([string]::IsNullOrWhiteSpace($IncompleteReason)) { $null } else { $IncompleteReason })
        RefusedSourceName = [string[]] @($RefusedSourceName)
        EmptyText         = $EmptyText
    }
}

function Get-ReviewScanFacts {
    # The three things every section needs off a scan result and must not guess
    # at: whether it finished, why not, and which signals this project refuses to
    # use at all. Read through Get-OptimizerProperty so a fabricated or
    # deserialized scan result cannot throw under strict mode.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Scan
    )

    [pscustomobject]@{
        IsComplete        = [bool](Get-OptimizerProperty -InputObject $Scan -Name 'IsComplete' -Default $true)
        IncompleteReason  = [string](Get-OptimizerProperty -InputObject $Scan -Name 'IncompleteReason' -Default '')
        RefusedSourceName = [string[]] @(Get-OptimizerProperty -InputObject $Scan -Name 'RefusedSourceName' -Default @())
    }
}

function Get-ReviewFinding {
    # The findings of one category out of a scan result, in the order the
    # detector produced them.
    [CmdletBinding()]
    [OutputType([psobject[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Scan,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Category
    )

    $findings = @(Get-OptimizerProperty -InputObject $Scan -Name 'Findings' -Default @())
    if ([string]::IsNullOrWhiteSpace($Category)) { return [psobject[]] @($findings) }

    # The category is captured into a local first. $_ inside a Where-Object is
    # the pipeline element, and a filter that reads a parameter of the enclosing
    # function by the same name would be filtering on itself -- docs\REVIEW.md,
    # after P3-C1a.
    $wanted = $Category
    [psobject[]] @($findings | Where-Object { [string](Get-OptimizerProperty -InputObject $_ -Name 'Category') -eq $wanted })
}

#endregion

#region Sections: what each one says

function Get-ReviewStartupSection {
    <#
        LEADS WITH THE INVENTORY, not with the findings.

        "148 things start with your PC. 28 of them are already off." is the
        sentence a person came for; the Finding list is an annotation on it. A
        section that opened with "1 item flagged" would be answering a question
        nobody asked and hiding the one they did.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Scan
    )

    $facts     = Get-ReviewScanFacts -Scan $Scan
    $inventory = [int](Get-OptimizerProperty -InputObject $Scan -Name 'InventoryCount' -Default 0)
    $disabled  = [int](Get-OptimizerProperty -InputObject $Scan -Name 'DisabledCount' -Default 0)
    $enabled   = [int](Get-OptimizerProperty -InputObject $Scan -Name 'EnabledCount' -Default 0)
    $unknown   = [int](Get-OptimizerProperty -InputObject $Scan -Name 'UnknownStateCount' -Default 0)
    $protTask  = [int](Get-OptimizerProperty -InputObject $Scan -Name 'ProtectedTaskCount' -Default 0)

    $headline = New-Object System.Collections.Generic.List[string]
    $null = $headline.Add(("{0} things start with your PC, {1} already off." -f `
        (Format-JunkCount -Count $inventory), (Format-JunkCount -Count $disabled)))

    $mechanism = Get-OptimizerProperty -InputObject $Scan -Name 'MechanismCount'
    if ($null -ne $mechanism) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($name in 'RunKey', 'StartupFolder', 'ScheduledTask', 'Service') {
            $value = Get-ReviewMapValue -InputObject $mechanism -Name $name
            if ($null -eq $value) { continue }
            $null = $parts.Add(("{0} {1}" -f (Format-JunkCount -Count ([int] $value)), $script:ReviewMechanismPluralText[$name]))
        }
        if ($parts.Count -gt 0) { $null = $headline.Add("That is " + ($parts -join ', ') + ".") }
    }

    if ($unknown -gt 0) {
        $null = $headline.Add(("{0} of them would not say whether they are on or off, and are counted as neither." -f (Format-JunkCount -Count $unknown)))
    }

    $startupFindings = @(Get-ReviewFinding -Scan $Scan -Category 'StartupItem')

    $note = New-Object System.Collections.Generic.List[string]
    if ($protTask -gt 0) {
        $null = $note.Add(("{0} scheduled tasks in protected Windows namespaces were never considered." -f (Format-JunkCount -Count $protTask)))
    }
    if ($startupFindings.Count -gt 0) {
        $null = $note.Add(("Of the {0} that are still on, the rows above are the ones this tool has something to say about." -f (Format-JunkCount -Count $enabled)))
    }
    else {
        $null = $note.Add(("All {0} that are still on were looked at and none of them is flagged." -f (Format-JunkCount -Count $enabled)))
    }

    $rows = New-Object System.Collections.Generic.List[psobject]
    $number = 0
    foreach ($finding in $startupFindings) {
        $number++
        $label = Get-ReviewSafetyLabel -Finding $finding
        $mechanismName = [string](Get-OptimizerProperty -InputObject $finding -Name 'Mechanism' -Default '')
        $mechanismText = $(if ($script:ReviewMechanismText.ContainsKey($mechanismName)) { $script:ReviewMechanismText[$mechanismName] } else { $mechanismName })

        $null = $rows.Add((New-ReviewRow -Number $number -SectionKey $script:ReviewSectionStartup -Finding $finding -SafetyLabel $label `
            -Cell ([string[]] @(
                [string] $number
                [string](Get-OptimizerProperty -InputObject $finding -Name 'DisplayName' -Default '(unnamed)')
                $mechanismText
                (Get-ReviewShortReason -Finding $finding)
                $label
            )) `
            -Style ([string[]] @('Number', '', 'Muted', 'Muted', (Get-ReviewSafetyStyle -Label $label)))))
    }

    New-ReviewSection -Key $script:ReviewSectionStartup -Title 'Startup items' `
        -Headline ([string[]] $headline.ToArray()) -Note ([string[]] $note.ToArray()) `
        -ColumnHeader ([string[]] @('#', 'What', 'Starts via', 'Why flagged', 'Safety')) `
        -Row ([psobject[]] @($rows.ToArray())) `
        -IsComplete $facts.IsComplete -IncompleteReason $facts.IncompleteReason `
        -RefusedSourceName $facts.RefusedSourceName `
        -EmptyText 'Nothing that starts with this PC is flagged. The inventory above is the answer, not an empty list.'
}

function Get-ReviewInstalledAppSection {
    <#
        LEADS WITH WHAT IT COULD NOT JUDGE.

        docs\STATE.md, confirmed against an elevated run: this category is 82%
        Unknown with 0 Findings on a machine like this one, WITH full elevation
        and prefetch working. A tab that rendered the Finding list would be an
        empty list on most machines and actively misleading on the rest. So the
        first sentence is "234 of 286 could not be judged", and the findings are
        the small remainder.

        The Used/Unknown split is also NOT a stable fact about the PC: two
        elevated runs a day apart moved it 52/234 -> 46/240 with nothing the user
        did in between, because Windows ages the prefetch folder on its own
        schedule. The note below says so, because a number presented without that
        reads as a property of the machine.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $UnusedScan,
        [Parameter(Mandatory)] [AllowNull()] $OemScan
    )

    $unusedFacts = Get-ReviewScanFacts -Scan $UnusedScan
    $oemFacts    = Get-ReviewScanFacts -Scan $OemScan

    $considered = [int](Get-OptimizerProperty -InputObject $UnusedScan -Name 'ConsideredCount' -Default 0)
    $unknown    = [int](Get-OptimizerProperty -InputObject $UnusedScan -Name 'UnknownCount' -Default 0)
    $used       = [int](Get-OptimizerProperty -InputObject $UnusedScan -Name 'UsedCount' -Default 0)
    $unused     = [int](Get-OptimizerProperty -InputObject $UnusedScan -Name 'UnusedCount' -Default 0)
    $excluded   = [int](Get-OptimizerProperty -InputObject $UnusedScan -Name 'ExcludedCount' -Default 0)

    $headline = New-Object System.Collections.Generic.List[string]
    $null = $headline.Add(("Could not judge {0} of {1} installed applications." -f `
        (Format-JunkCount -Count $unknown), (Format-JunkCount -Count $considered)))
    $null = $headline.Add(("{0} were used recently, {1} look unused, {2} are on the exclusion list and were never considered." -f `
        (Format-JunkCount -Count $used), (Format-JunkCount -Count $unused), (Format-JunkCount -Count $excluded)))

    $note = New-Object System.Collections.Generic.List[string]
    $null = $note.Add('Used and unknown are not stable facts about this PC. Windows ages its own launch history on its own schedule, and two runs a day apart have given different splits with nothing done in between. The rows are the list; the counts above are not.')
    if ($unusedFacts.RefusedSourceName.Count -gt 0) {
        $refusedCount = $unusedFacts.RefusedSourceName.Count
        $null = $note.Add(("{0} usage {1} refused by design and never read at all ({2}). The scan result's Sources list says why." -f `
            (Format-JunkCount -Count $refusedCount),
            $(if ($refusedCount -eq 1) { 'signal is' } else { 'signals are' }),
            ($unusedFacts.RefusedSourceName -join ', ')))
    }

    $rows = New-Object System.Collections.Generic.List[psobject]
    $number = 0
    foreach ($finding in @(@(Get-ReviewFinding -Scan $OemScan -Category 'OemBloatware') + @(Get-ReviewFinding -Scan $UnusedScan -Category 'UnusedApp'))) {
        if ($null -eq $finding) { continue }
        $number++
        $label = Get-ReviewSafetyLabel -Finding $finding
        $foundBy = $(if ([string](Get-OptimizerProperty -InputObject $finding -Name 'Category') -eq 'OemBloatware') { 'Curated list' } else { 'Usage signal' })

        $null = $rows.Add((New-ReviewRow -Number $number -SectionKey $script:ReviewSectionInstalled -Finding $finding -SafetyLabel $label `
            -Cell ([string[]] @(
                [string] $number
                [string](Get-OptimizerProperty -InputObject $finding -Name 'DisplayName' -Default '(unnamed)')
                $foundBy
                (Get-ReviewShortReason -Finding $finding)
                $label
            )) `
            -Style ([string[]] @('Number', '', 'Muted', 'Muted', (Get-ReviewSafetyStyle -Label $label)))))
    }

    # TWO SCANS FEED THIS SECTION, so completeness is the AND of both and the
    # reasons are joined. Reporting only the unused-app scan's state would let an
    # un-elevated OEM scan -- which cannot read provisioned Appx packages at all
    # -- present itself as complete.
    $reasons = @(@($unusedFacts.IncompleteReason, $oemFacts.IncompleteReason) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    New-ReviewSection -Key $script:ReviewSectionInstalled -Title 'Installed apps' `
        -Headline ([string[]] $headline.ToArray()) -Note ([string[]] $note.ToArray()) `
        -ColumnHeader ([string[]] @('#', 'Application', 'Found by', 'Why flagged', 'Safety')) `
        -Row ([psobject[]] @($rows.ToArray())) `
        -IsComplete ($unusedFacts.IsComplete -and $oemFacts.IsComplete) `
        -IncompleteReason ($reasons -join ' ') `
        -RefusedSourceName ([string[]] @(@($unusedFacts.RefusedSourceName) + @($oemFacts.RefusedSourceName) | Sort-Object -Unique)) `
        -EmptyText 'No installed application is flagged. Given how many could not be judged, that is a statement about the signals available, not a clean bill of health.'
}

function Get-ReviewJunkSection {
    <#
        A ROW PER LOCATION, WITH ITS OWN SIZE. NEVER A BARE CATEGORY TOTAL.

        Measured on this machine after P3-C1a: 27.51 of 29.71 GiB eligible is one
        row, the NVIDIA shader cache -- 92.6%. A category figure on its own is
        therefore a number about one folder wearing the name of five, and
        docs\STATE.md makes not printing it a requirement of this screen.

        The total below is DERIVED FROM THE ROWS and is produced only where there
        are rows to derive it from. That is the enforcement: there is no code
        path that can compute a category figure without the split, because the
        figure is the split summed. It is not the scan's TotalEligibleBytes,
        which also counts locations that produced no Finding.

        Each row also carries ITS OWN age window. A curated entry may set a floor
        of its own -- the shader cache is measured at 30 days while the rest of
        the scan uses 7 -- and a row that quoted the scan's window would be
        telling the user something untrue about that row in particular.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Scan
    )

    $facts     = Get-ReviewScanFacts -Scan $Scan
    $locations = [int](Get-OptimizerProperty -InputObject $Scan -Name 'InventoryCount' -Default 0)
    $scanDays  = [int](Get-OptimizerProperty -InputObject $Scan -Name 'MinimumAgeDays' -Default 0)
    $isFloor   = [bool](Get-OptimizerProperty -InputObject $Scan -Name 'SizeIsFloor' -Default $false)

    $findings = @(Get-ReviewFinding -Scan $Scan -Category 'JunkFile')

    $rows = New-Object System.Collections.Generic.List[psobject]
    $rowBytes = New-Object 'System.Collections.Generic.List[long]'
    $rowFiles = New-Object 'System.Collections.Generic.List[long]'
    $windowDiffers = $false
    $number = 0

    foreach ($finding in $findings) {
        $number++
        $label = Get-ReviewSafetyLabel -Finding $finding
        $bytes = [long](Get-OptimizerProperty -InputObject $finding -Name 'EligibleBytes' -Default 0)
        $files = [long](Get-OptimizerProperty -InputObject $finding -Name 'EligibleFileCount' -Default 0)
        $days  = [int](Get-OptimizerProperty -InputObject $finding -Name 'MinimumAgeDays' -Default $scanDays)
        $floor = [bool](Get-OptimizerProperty -InputObject $finding -Name 'IsSizeFloor' -Default $false)

        if ($days -ne $scanDays) { $windowDiffers = $true }

        $null = $rowBytes.Add($bytes)
        $null = $rowFiles.Add($files)

        $sizeText = Format-JunkSize -Bytes $bytes
        if ($floor) { $sizeText = "$sizeText or more" }

        $null = $rows.Add((New-ReviewRow -Number $number -SectionKey $script:ReviewSectionJunk -Finding $finding -SafetyLabel $label `
            -Cell ([string[]] @(
                [string] $number
                [string](Get-OptimizerProperty -InputObject $finding -Name 'DisplayName' -Default '(unnamed)')
                $sizeText
                (Format-JunkCount -Count $files)
                ("{0} days" -f $days)
                $label
            )) `
            -Style ([string[]] @('Number', '', '', 'Muted', 'Muted', (Get-ReviewSafetyStyle -Label $label)))))
    }

    $headline = New-Object System.Collections.Generic.List[string]
    $null = $headline.Add(("{0} locations were measured; {1} of them hold something this tool would offer to delete." -f `
        (Format-JunkCount -Count $locations), (Format-JunkCount -Count $rows.Count)))
    $null = $headline.Add(("Each row is sized on its own. What is below is what is on disk now, not a promise about what this PC will do afterwards."))

    # THE TOTAL, AND THE ONLY PLACE ONE IS BUILT. Inside the branch that has
    # rows, summed from the rows, with the largest row's share stated beside it
    # because that share is the entire reason this rule exists.
    $totalLine = $null
    if ($rows.Count -ge 1) {
        $totalBytes = [long] 0
        foreach ($value in $rowBytes) { $totalBytes += $value }
        $totalFiles = [long] 0
        foreach ($value in $rowFiles) { $totalFiles += $value }

        $largest = [long] 0
        foreach ($value in $rowBytes) { if ($value -gt $largest) { $largest = $value } }

        $shareText = ''
        if ($totalBytes -gt 0 -and $rows.Count -gt 1) {
            $share = [math]::Round((100.0 * $largest / $totalBytes), 1)
            $shareText = " The largest single row is {0}% of that, so read the rows and not this line." -f `
                $share.ToString('0.#', [System.Globalization.CultureInfo]::InvariantCulture)
        }

        $totalLine = "The {0} rows above come to {1} across {2} files on disk now.{3}" -f `
            (Format-JunkCount -Count $rows.Count), (Format-JunkSize -Bytes $totalBytes), (Format-JunkCount -Count $totalFiles), $shareText
    }

    $note = New-Object System.Collections.Generic.List[string]
    if ($windowDiffers) {
        $null = $note.Add(("The scan used a {0}-day age window; a row whose window differs says so in its own column, because what is in it is worth keeping for longer." -f $scanDays))
    }
    if ($isFloor) {
        $null = $note.Add('A size marked "or more" is a floor and not a total: folders inside that location could not be listed at this privilege level, so what is in them is neither counted nor listed.')
    }
    $null = $note.Add('Every row here needs an explicit OK. Each file is re-checked before anything is deleted.')

    New-ReviewSection -Key $script:ReviewSectionJunk -Title 'Junk files' `
        -Headline ([string[]] $headline.ToArray()) -Note ([string[]] $note.ToArray()) `
        -ColumnHeader ([string[]] @('#', 'Location', 'On disk now', 'Files', 'Older than', 'Safety')) `
        -Row ([psobject[]] @($rows.ToArray())) -TotalLine $totalLine `
        -IsComplete $facts.IsComplete -IncompleteReason $facts.IncompleteReason `
        -RefusedSourceName $facts.RefusedSourceName `
        -EmptyText 'No location holds anything this tool would offer to delete.'
}

function Get-ReviewServiceSection {
    <#
        THE COUNT HELD BACK AS PROTECTED SITS BESIDE THE FINDINGS.

        ProtectedServiceCount is the number of enabled services the shared
        exclusion list held back -- services actually held back, not services
        that merely matched a class (docs\STATE.md, changed in P2-C2a for exactly
        this reason). Without it a zero-Finding section and an exclusion list
        that swallowed everything look identical, and the whole point of this
        project is that they must not.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Scan
    )

    $facts     = Get-ReviewScanFacts -Scan $Scan
    $protected = [int](Get-OptimizerProperty -InputObject $Scan -Name 'ProtectedServiceCount' -Default 0)

    $serviceTotal = 0
    $mechanism = Get-OptimizerProperty -InputObject $Scan -Name 'MechanismCount'
    if ($null -ne $mechanism) {
        $serviceTotal = [int](Get-ReviewMapValue -InputObject $mechanism -Name 'Service' -Default 0)
    }

    # The live state of each flagged service, joined out of the inventory the
    # scan already carries rather than read again from the registry: a second
    # read here could disagree with the one the Finding was made from, and the
    # screen would then be showing two different moments as one.
    $items = @(Get-OptimizerProperty -InputObject $Scan -Name 'StartupItems' -Default @())

    $findings = @(Get-ReviewFinding -Scan $Scan -Category 'Service')

    $headline = New-Object System.Collections.Generic.List[string]
    $null = $headline.Add(("{0} Windows services were looked at; {1} {2} flagged below." -f `
        (Format-JunkCount -Count $serviceTotal), (Format-JunkCount -Count $findings.Count),
        $(if ($findings.Count -eq 1) { 'is' } else { 'are' })))
    $null = $headline.Add(("{0} more {1} held back as protected and {2} not offered, whatever else is true about {3}." -f `
        (Format-JunkCount -Count $protected),
        $(if ($protected -eq 1) { 'was' } else { 'were' }),
        $(if ($protected -eq 1) { 'is' } else { 'are' }),
        $(if ($protected -eq 1) { 'it' } else { 'them' })))

    $note = New-Object System.Collections.Generic.List[string]
    $null = $note.Add('This tool only ever changes a service startup type. It does not delete a service and it does not stop one that is running.')

    $rows = New-Object System.Collections.Generic.List[psobject]
    $number = 0
    foreach ($finding in $findings) {
        $number++
        $label = Get-ReviewSafetyLabel -Finding $finding
        $id = [string](Get-OptimizerProperty -InputObject $finding -Name 'Id' -Default '')

        # The id is captured first: $_ inside the filter is the pipeline element.
        $wanted = $id
        $item = @($items | Where-Object {
            [string](Get-OptimizerProperty -InputObject $_ -Name 'Mechanism') -eq 'Service' -and
            [string](Get-OptimizerProperty -InputObject $_ -Name 'Id') -eq $wanted
        } | Select-Object -First 1)

        $state = 'Unknown'
        if ($item.Count -gt 0) { $state = [string](Get-OptimizerProperty -InputObject $item[0] -Name 'EnabledState' -Default 'Unknown') }

        $null = $rows.Add((New-ReviewRow -Number $number -SectionKey $script:ReviewSectionService -Finding $finding -SafetyLabel $label `
            -Cell ([string[]] @(
                [string] $number
                [string](Get-OptimizerProperty -InputObject $finding -Name 'DisplayName' -Default '(unnamed)')
                $state
                (Get-ReviewShortReason -Finding $finding)
                $label
            )) `
            -Style ([string[]] @('Number', '', 'Muted', 'Muted', (Get-ReviewSafetyStyle -Label $label)))))
    }

    New-ReviewSection -Key $script:ReviewSectionService -Title 'Services' `
        -Headline ([string[]] $headline.ToArray()) -Note ([string[]] $note.ToArray()) `
        -ColumnHeader ([string[]] @('#', 'Service', 'State', 'Why flagged', 'Safety')) `
        -Row ([psobject[]] @($rows.ToArray())) `
        -IsComplete $facts.IsComplete -IncompleteReason $facts.IncompleteReason `
        -RefusedSourceName $facts.RefusedSourceName `
        -EmptyText 'No service is flagged.'
}

#endregion

#region Sections: how each one prints

function Format-ReviewSection {
    <#
        One section as lines. The printing half of the pair: it reads the section
        object and knows nothing about detectors, categories or scan results.

        The ORDER is the contract, and one part of it is load-bearing: TotalLine
        is emitted INSIDE the branch that has already emitted the rows. There is
        no path through this function that prints a total without the per-row
        split above it.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [psobject] $Section,
        [Parameter()] [int] $Width = $script:ReviewDefaultWidth,
        [Parameter()] [bool] $Colour = $false
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $title = [string](Get-OptimizerProperty -InputObject $Section -Name 'Title' -Default '')
    $rule  = "+-- $title "
    if ($rule.Length -lt $Width) { $rule = $rule + ('-' * ($Width - $rule.Length)) }
    $null = $lines.Add((Add-ReviewStyle -Text $rule -Name 'Title' -Colour $Colour))
    $null = $lines.Add('')

    foreach ($text in @(Get-OptimizerProperty -InputObject $Section -Name 'Headline' -Default @())) {
        foreach ($line in @(Split-ReviewText -Text $text -Width $Width -Indent '  ')) {
            $null = $lines.Add((Add-ReviewStyle -Text $line -Name 'Lead' -Colour $Colour))
        }
    }

    if (-not [bool](Get-OptimizerProperty -InputObject $Section -Name 'IsComplete' -Default $true)) {
        $null = $lines.Add('')
        $null = $lines.Add((Add-ReviewStyle -Text '  PARTIAL -- this list is not the whole picture.' -Name 'Partial' -Colour $Colour))
        foreach ($line in @(Split-ReviewText -Text (Get-OptimizerProperty -InputObject $Section -Name 'IncompleteReason') -Width $Width -Indent '    ')) {
            $null = $lines.Add((Add-ReviewStyle -Text $line -Name 'Muted' -Colour $Colour))
        }
    }

    $rows = @(Get-OptimizerProperty -InputObject $Section -Name 'Row' -Default @())
    $null = $lines.Add('')

    if ($rows.Count -lt 1) {
        foreach ($line in @(Split-ReviewText -Text (Get-OptimizerProperty -InputObject $Section -Name 'EmptyText') -Width $Width -Indent '  ')) {
            $null = $lines.Add($line)
        }
    }
    else {
        foreach ($line in @(Format-ReviewTable `
            -Header ([string[]] @(Get-OptimizerProperty -InputObject $Section -Name 'ColumnHeader' -Default @())) `
            -Row ([psobject[]] $rows) -Width $Width -Colour $Colour)) {
            $null = $lines.Add($line)
        }

        # AND ONLY HERE. A total belongs to the rows it was summed from, and this
        # is the only statement in this file that prints one.
        $total = Get-OptimizerProperty -InputObject $Section -Name 'TotalLine'
        if (-not [string]::IsNullOrWhiteSpace($total)) {
            $null = $lines.Add('')
            foreach ($line in @(Split-ReviewText -Text $total -Width $Width -Indent '  ')) {
                $null = $lines.Add((Add-ReviewStyle -Text $line -Name 'Lead' -Colour $Colour))
            }
        }
    }

    $notes = @(Get-OptimizerProperty -InputObject $Section -Name 'Note' -Default @())
    if ($notes.Count -gt 0) {
        $null = $lines.Add('')
        foreach ($text in $notes) {
            foreach ($line in @(Split-ReviewText -Text $text -Width $Width -Indent '  ')) {
                $null = $lines.Add((Add-ReviewStyle -Text $line -Name 'Muted' -Colour $Colour))
            }
        }
    }

    $null = $lines.Add('')
    [string[]] @($lines.ToArray())
}

#endregion

#region Public: the screen

function Get-ReviewScreen {
    <#
    .SYNOPSIS
        Works out everything the review screen should say. Decides; prints
        nothing; changes nothing.

    .DESCRIPTION
        Builds the four sections -- startup items, installed apps, junk files,
        services, in that order -- from the four detectors' scan results, plus
        the screen-level completeness banner and the run receipt derived from the
        action ledger.

        Each section is built by its own Get-Review*Section function, which is
        where the wording and the counting live. This function only assembles
        them, so a change to what a category says is a change in one place.

        A scan result not supplied is RUN HERE. That is a read-only sweep and can
        take tens of seconds; a caller that wants to say what it is doing while
        that happens should run the scans itself and pass them in, which is what
        Show-ReviewScreen does.

        ReceiptText is Get-OptimizerRunReceipt's own lines, carried unchanged --
        what this tool has already done, in the words it was already given. It is
        $null when there is no ledger yet.

    .PARAMETER StartupScan
        The result of Invoke-StartupItemScan. Feeds both the startup and the
        service section.

    .PARAMETER UnusedAppScan
        The result of Invoke-UnusedAppScan.

    .PARAMETER OemScan
        The result of Invoke-OemBloatwareScan.

    .PARAMETER JunkScan
        The result of Invoke-JunkFileScan.

    .PARAMETER LedgerPath
        The action ledger the receipt is derived from. Defaults to
        Get-OptimizerActionLogPath.

    .PARAMETER SkipReceipt
        Do not read the ledger at all.

    .EXAMPLE
        Format-ReviewScreen -Screen (Get-ReviewScreen)
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()] [AllowNull()] $StartupScan,
        [Parameter()] [AllowNull()] $UnusedAppScan,
        [Parameter()] [AllowNull()] $OemScan,
        [Parameter()] [AllowNull()] $JunkScan,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $LedgerPath,
        [switch] $SkipReceipt
    )

    if ($null -eq $StartupScan)   { $StartupScan   = Invoke-StartupItemScan }
    if ($null -eq $UnusedAppScan) { $UnusedAppScan = Invoke-UnusedAppScan }
    if ($null -eq $OemScan)       { $OemScan       = Invoke-OemBloatwareScan }
    if ($null -eq $JunkScan)      { $JunkScan      = Invoke-JunkFileScan }

    $sections = [psobject[]] @(
        (Get-ReviewStartupSection -Scan $StartupScan)
        (Get-ReviewInstalledAppSection -UnusedScan $UnusedAppScan -OemScan $OemScan)
        (Get-ReviewJunkSection -Scan $JunkScan)
        (Get-ReviewServiceSection -Scan $StartupScan)
    )

    $incomplete = @($sections | Where-Object { -not $_.IsComplete })

    # The receipt, printed and never re-rendered. A ledger that is not there yet
    # is the ordinary case on a first run and is not an error.
    $receiptText = $null
    if (-not $SkipReceipt) {
        $path = $(if ([string]::IsNullOrWhiteSpace($LedgerPath)) { Get-OptimizerActionLogPath } else { $LedgerPath })
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            try { $receiptText = [string[]] @((Get-OptimizerRunReceipt -Path $path).ReceiptText) }
            catch {
                Write-Verbose "The action ledger at '$path' could not be read for the receipt: $($_.Exception.Message)"
                $receiptText = $null
            }
        }
    }

    [pscustomobject][ordered]@{
        PSTypeName    = $script:ReviewScreenTypeName
        GeneratedUtc  = [datetime]::UtcNow.ToString('o')
        MachineName   = [Environment]::MachineName
        UserName      = [Environment]::UserName
        IsElevated    = [bool](Test-IsElevated)
        Section       = $sections
        IsComplete    = ($incomplete.Count -eq 0)
        # Named, not summarised. A banner that said "some scans were partial"
        # without saying which would be the under-report this project exists to
        # prevent, wearing a warning.
        PartialSection = [string[]] @($incomplete | ForEach-Object { $_.Title })
        RowCount      = [int](@($sections | ForEach-Object { @($_.Row).Count } | Measure-Object -Sum).Sum)
        ReceiptText   = $receiptText
    }
}

function Format-ReviewScreen {
    <#
    .SYNOPSIS
        The review screen as lines of text. Prints nothing itself -- it returns
        the strings, and something else decides where they go.

    .DESCRIPTION
        Everything this screen is, is a [string[]]. That is what makes it
        testable the same way as the rest of this project: no window, no event
        loop, no host dependency, and a test can assert on the exact bytes a
        person would see.

        Colour is ANSI built from [char]27 and is applied AFTER padding, so a
        coloured render and a plain one differ by escape sequences alone and the
        columns line up either way. Colour is off by default: a caller that is
        writing to a file or a pipe must not have to strip anything.

    .PARAMETER Screen
        A screen from Get-ReviewScreen.

    .PARAMETER Width
        Line width. Clamped to a sane range.

    .PARAMETER Colour
        Emit ANSI colour.

    .PARAMETER SkipReceipt
        Leave the "what this tool has done" block off the end.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [psobject] $Screen,
        [Parameter()] [int] $Width = $script:ReviewDefaultWidth,
        [switch] $Colour,
        [switch] $SkipReceipt
    )

    process {
        $useColour = [bool] $Colour
        $useWidth = $Width
        if ($useWidth -lt $script:ReviewMinimumWidth) { $useWidth = $script:ReviewMinimumWidth }
        if ($useWidth -gt $script:ReviewMaximumWidth) { $useWidth = $script:ReviewMaximumWidth }

        $lines = New-Object System.Collections.Generic.List[string]

        $bar = '+' + ('-' * ($useWidth - 2)) + '+'
        $null = $lines.Add((Add-ReviewStyle -Text $bar -Name 'Frame' -Colour $useColour))
        foreach ($text in @(
            'win11-optimizer -- what is on this PC right now',
            ("Looked at {0} as {1}\{2}, {3}." -f `
                (ConvertTo-RemovalUtcText -Value (Get-OptimizerProperty -InputObject $Screen -Name 'GeneratedUtc')),
                [string](Get-OptimizerProperty -InputObject $Screen -Name 'MachineName'),
                [string](Get-OptimizerProperty -InputObject $Screen -Name 'UserName'),
                $(if ([bool](Get-OptimizerProperty -InputObject $Screen -Name 'IsElevated' -Default $false)) { 'as administrator' } else { 'not as administrator' })),
            'Nothing on this PC has been changed. This screen reads; it does not act.'
        )) {
            foreach ($line in @(Split-ReviewText -Text $text -Width ($useWidth - 4) -Indent '')) {
                $body = '| ' + $line.PadRight($useWidth - 4) + ' |'
                $null = $lines.Add((Add-ReviewStyle -Text $body -Name 'Frame' -Colour $useColour))
            }
        }
        $null = $lines.Add((Add-ReviewStyle -Text $bar -Name 'Frame' -Colour $useColour))
        $null = $lines.Add('')

        if (-not [bool](Get-OptimizerProperty -InputObject $Screen -Name 'IsComplete' -Default $true)) {
            $partial = [string[]] @(Get-OptimizerProperty -InputObject $Screen -Name 'PartialSection' -Default @())
            foreach ($line in @(Split-ReviewText -Width $useWidth -Indent '  ' -Text (
                "PARTIAL: {0} of the four lists below {1} incomplete ({2}). Each one says why where it appears. Nothing here is presented as a full picture when it is not." -f `
                    $partial.Count, $(if ($partial.Count -eq 1) { 'is' } else { 'are' }), ($partial -join ', ')))) {
                $null = $lines.Add((Add-ReviewStyle -Text $line -Name 'Partial' -Colour $useColour))
            }
            $null = $lines.Add('')
        }

        foreach ($section in @(Get-OptimizerProperty -InputObject $Screen -Name 'Section' -Default @())) {
            foreach ($line in @(Format-ReviewSection -Section $section -Width $useWidth -Colour $useColour)) {
                $null = $lines.Add($line)
            }
        }

        if (-not $SkipReceipt) {
            $receipt = @(Get-OptimizerProperty -InputObject $Screen -Name 'ReceiptText' -Default @())
            if ($receipt.Count -gt 0) {
                $null = $lines.Add((Add-ReviewStyle -Text ('+' + ('-' * ($useWidth - 2)) + '+') -Name 'Frame' -Colour $useColour))
                $null = $lines.Add('')
                # VERBATIM. These lines were written by Get-OptimizerRunReceipt
                # and are already worded; re-wrapping or re-styling them here
                # would make this file a second renderer of the same thing.
                foreach ($line in $receipt) { $null = $lines.Add('  ' + $line) }
                $null = $lines.Add('')
            }
        }

        [string[]] @($lines.ToArray())
    }
}

#endregion

#region Public: the selection

function Get-ReviewSelection {
    <#
    .SYNOPSIS
        Parses what someone typed at a section prompt into row numbers. Pure:
        it reads a string and returns an answer.

    .DESCRIPTION
        The whole input language, and it is deliberately this small:

          (blank)      nothing from this section
          a  /  all    every row in it
          1 3 7        those rows
          2-5          that range
          1, 3-5, 9    any mixture, separated by commas or spaces

        No nested menus, no modes, no negation, no wildcards. Anything else is
        rejected WITH THE OFFENDING TOKEN NAMED, rather than silently ignored:
        a selection screen that quietly drops what it did not understand is one
        that acts on a list the person did not choose.

        Out of range is rejected too, for the same reason. Typing 9 where there
        are 4 rows is far more likely to be a mistake about which section is on
        screen than a wish to select nothing.

    .PARAMETER InputText
        What was typed.

    .PARAMETER RowCount
        How many rows the section has.

    .EXAMPLE
        Get-ReviewSelection -InputText '1, 3-5' -RowCount 8
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory, Position = 0)] [AllowNull()] [AllowEmptyString()] [string] $InputText,
        [Parameter(Mandatory, Position = 1)] [int] $RowCount
    )

    $text = ([string] $InputText).Trim()

    $result = [pscustomobject][ordered]@{
        InputText = $text
        IsValid   = $true
        IsAll     = $false
        IsNone    = $false
        Number    = [int[]] @()
        Error     = $null
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
        $result.IsNone = $true
        return $result
    }

    if ($text -match '^(a|all)$') {
        $result.IsAll  = $true
        $result.IsNone = ($RowCount -lt 1)
        $result.Number = [int[]] @($(if ($RowCount -ge 1) { 1..$RowCount } else { @() }))
        return $result
    }

    $picked = New-Object 'System.Collections.Generic.List[int]'
    foreach ($token in @($text -split '[,\s]+')) {
        if ([string]::IsNullOrWhiteSpace($token)) { continue }

        if ($token -match '^(?<from>\d+)-(?<to>\d+)$') {
            $from = [int] $Matches['from']
            $to   = [int] $Matches['to']
            if ($from -lt 1 -or $to -lt 1 -or $from -gt $RowCount -or $to -gt $RowCount) {
                $result.IsValid = $false
                $result.Error   = "'$token' is not a row on this list. There $(if ($RowCount -eq 1) { 'is 1 row' } else { "are $RowCount rows" })."
                return $result
            }
            if ($from -gt $to) {
                $result.IsValid = $false
                $result.Error   = "'$token' runs backwards. Write it the other way round."
                return $result
            }
            for ($number = $from; $number -le $to; $number++) { $null = $picked.Add($number) }
            continue
        }

        if ($token -match '^\d+$') {
            $number = [int] $token
            if ($number -lt 1 -or $number -gt $RowCount) {
                $result.IsValid = $false
                $result.Error   = "'$token' is not a row on this list. There $(if ($RowCount -eq 1) { 'is 1 row' } else { "are $RowCount rows" })."
                return $result
            }
            $null = $picked.Add($number)
            continue
        }

        $result.IsValid = $false
        $result.Error   = "'$token' is not a number, a range like 2-5, 'a' for all, or blank for none."
        return $result
    }

    $result.Number = [int[]] @($picked.ToArray() | Sort-Object -Unique)
    $result.IsNone = ($result.Number.Count -lt 1)
    $result
}

function Get-ReviewConfirmation {
    <#
    .SYNOPSIS
        Reads a yes-or-no answer. Yes is 'y' or 'yes'; EVERYTHING ELSE IS NO.

    .DESCRIPTION
        Asked once, plainly, and it fails safe. An unrecognised answer is not a
        re-prompt and not an error: it is no. The prompt says so, so a person who
        types anything at all gets the outcome they were told they would get, and
        nothing can be started by a stray keystroke.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)] [AllowNull()] [AllowEmptyString()] [string] $InputText
    )

    [bool](([string] $InputText).Trim() -match '^(y|yes)$')
}

function New-ReviewSelectionResult {
    # What Show-ReviewScreen hands back. Executed is present, is $false, and is
    # not settable from anywhere in this file: the chunk that runs a plan is
    # P4-C2, and until it exists this field is how a caller can tell that what it
    # is holding is a decision and not a result.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [bool] $Confirmed,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Answer,
        [Parameter()] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Finding = @(),
        [Parameter()] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Plan = @(),
        [Parameter()] [AllowEmptyCollection()] [AllowNull()] [psobject[]] $Pick = @()
    )

    [pscustomobject][ordered]@{
        PSTypeName    = $script:ReviewSelectionTypeName
        DecidedUtc    = [datetime]::UtcNow.ToString('o')
        Confirmed     = $Confirmed
        Answer        = $Answer
        SelectedCount = @($Finding).Count
        Pick          = [psobject[]] @($Pick)
        Finding       = [psobject[]] @($Finding)
        Plan          = [psobject[]] @($Plan)
        Executed      = $false
        Note          = 'A selection only. Nothing on this PC has been changed by this screen, whatever Confirmed says.'
    }
}

#endregion

#region Public: the interactive screen

function Show-ReviewScreen {
    <#
    .SYNOPSIS
        Prints the review screen, collects a selection, shows the plan for each
        pick and asks yes or no once. Returns the selection. RUNS NOTHING.

    .DESCRIPTION
        The one function in this file that talks to a person, and it does it
        through two scriptblocks so that "talks to a person" is a parameter
        rather than a dependency: -Writer takes one line, -Reader takes a prompt
        and returns a string. The defaults are Write-Host and Read-Host; a test
        passes a queue and asserts on the exact transcript.

        THE SEQUENCE:
          1. the screen;
          2. one prompt per section, in screen order -- numbers, 'a', or blank;
          3. the plan for every pick, as Plan.PreviewText, unaltered;
          4. one yes-or-no question.

        No nested menus and no modes. Step 4 is asked once and fails safe:
        anything that is not yes is no.

        WHAT IT DOES NOT DO. It does not call Invoke-RemovalPlan, it has no
        switch that would, and it does not write to the action ledger. Wiring a
        confirmed selection to the executor is chunk P4-C2. The object handed
        back carries Executed = $false to say so in the data as well as here.

    .PARAMETER Screen
        A screen from Get-ReviewScreen. Built here if not supplied, with a line
        saying what is being read while each scan runs -- a line, not a progress
        bar and not a spinner.

    .PARAMETER Reader
        Scriptblock taking one prompt string and returning what was typed.

    .PARAMETER Writer
        Scriptblock taking one line to display.

    .PARAMETER Width
        Line width. Defaults to the console window's, clamped.

    .PARAMETER NoColour
        Print without ANSI colour.

    .EXAMPLE
        $selection = Show-ReviewScreen
        $selection.Confirmed
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()] [AllowNull()] $Screen,
        [Parameter()] [ValidateNotNull()] [scriptblock] $Reader = { param($Prompt) Read-Host -Prompt $Prompt },
        [Parameter()] [ValidateNotNull()] [scriptblock] $Writer = { param($Line) Write-Host $Line },
        [Parameter()] [int] $Width = 0,
        [switch] $NoColour
    )

    $write = { param($Line) $null = & $Writer ([string] $Line) }

    if ($Width -lt 1) { $Width = Get-ReviewConsoleWidth }
    # Clamped here as well as in Format-ReviewScreen, because this function draws
    # one rule of its own and a caller who passes a silly width must not get a
    # screen whose body fits and whose heading does not.
    if ($Width -lt $script:ReviewMinimumWidth) { $Width = $script:ReviewMinimumWidth }
    if ($Width -gt $script:ReviewMaximumWidth) { $Width = $script:ReviewMaximumWidth }

    $colour = (-not $NoColour) -and (Test-ReviewColourSupport)

    if ($null -eq $Screen) {
        # A line saying what is happening, per scan. Three seconds of work earns
        # a sentence; it does not earn an animation.
        & $write 'Reading what starts with this PC...'
        $startupScan = Invoke-StartupItemScan
        & $write 'Reading installed applications and how recently they were used...'
        $unusedScan = Invoke-UnusedAppScan
        & $write 'Checking installed applications against the curated list...'
        $oemScan = Invoke-OemBloatwareScan
        & $write 'Measuring the junk-file locations...'
        $junkScan = Invoke-JunkFileScan
        & $write ''
        $Screen = Get-ReviewScreen -StartupScan $startupScan -UnusedAppScan $unusedScan -OemScan $oemScan -JunkScan $junkScan
    }

    foreach ($line in @(Format-ReviewScreen -Screen $Screen -Width $Width -Colour:$colour)) { & $write $line }

    $picks     = New-Object System.Collections.Generic.List[psobject]
    $selected  = New-Object System.Collections.Generic.List[psobject]

    foreach ($section in @(Get-OptimizerProperty -InputObject $Screen -Name 'Section' -Default @())) {
        $rows = @(Get-OptimizerProperty -InputObject $section -Name 'Row' -Default @())
        $title = [string](Get-OptimizerProperty -InputObject $section -Name 'Title')
        if ($rows.Count -lt 1) { continue }

        $prompt = $(if ($rows.Count -eq 1) {
            "$title -- type 1 to pick the one row, or press Enter for none"
        } else {
            "$title -- type numbers to pick (1-$($rows.Count)), 'a' for all $($rows.Count), or press Enter for none"
        })

        # BOUNDED. A prompt that re-asks forever on bad input is a prompt that
        # cannot be driven by a script and cannot be got out of by a person who
        # has stopped understanding it. After the third try the section is
        # skipped, which is the safe direction.
        $answer = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            $typed = [string](& $Reader $prompt)
            $answer = Get-ReviewSelection -InputText $typed -RowCount $rows.Count
            if ($answer.IsValid) { break }
            & $write ("  " + (Add-ReviewStyle -Text $answer.Error -Name 'Partial' -Colour $colour))
            if ($attempt -eq 3) {
                & $write '  Nothing taken from this section.'
                $answer = Get-ReviewSelection -InputText '' -RowCount $rows.Count
            }
        }

        $numbers = [int[]] @($answer.Number)
        $null = $picks.Add([pscustomobject][ordered]@{
            SectionKey = [string](Get-OptimizerProperty -InputObject $section -Name 'Key')
            Title      = $title
            RowCount   = $rows.Count
            Number     = $numbers
        })

        foreach ($number in $numbers) {
            $row = $rows[$number - 1]
            $null = $selected.Add($row)
        }

        & $write ("  " + (Add-ReviewStyle -Colour $colour -Name 'Muted' -Text $(
            if ($numbers.Count -lt 1) { 'Nothing taken from this section.' }
            else { "Taken: $($numbers -join ', ')." })))
        & $write ''
    }

    if ($selected.Count -lt 1) {
        & $write 'Nothing was selected, so there is nothing to show a plan for and nothing to confirm.'
        return (New-ReviewSelectionResult -Confirmed $false -Answer $null)
    }

    # The plan for each pick, re-verified now. Get-RemovalPlan reads; it removes,
    # disables and writes nothing, which is what makes it safe to call from a
    # screen whose job is to show a person what would happen.
    $plans = New-Object System.Collections.Generic.List[psobject]
    foreach ($row in $selected) { $null = $plans.Add((Get-RemovalPlan -Finding $row.Finding)) }

    & $write (Add-ReviewStyle -Colour $colour -Name 'Title' -Text ("+-- What would happen " + ('-' * [math]::Max(0, $Width - 22))))
    & $write ''

    foreach ($plan in $plans) {
        # PRINTED, NOT RE-RENDERED. PreviewText is the text a person read before
        # approving, and P3-C2 keeps it on the ledger for exactly that reason. A
        # second renderer here would eventually disagree with the record.
        foreach ($line in @(Get-OptimizerProperty -InputObject $plan -Name 'PreviewText' -Default @())) {
            & $write ('  ' + $line)
        }
        & $write ''
    }

    $supported = @($plans | Where-Object { [bool](Get-OptimizerProperty -InputObject $_ -Name 'Supported' -Default $false) })
    if ($supported.Count -lt $plans.Count) {
        & $write (Add-ReviewStyle -Colour $colour -Name 'Partial' -Text (
            "  {0} of the {1} selected have nothing planned for them, for the reasons above. They stay as they are." -f `
                ($plans.Count - $supported.Count), $plans.Count))
        & $write ''
    }

    $typed = [string](& $Reader ("Go ahead with these $($plans.Count)? Type 'yes' to say so -- anything else stops"))
    $confirmed = Get-ReviewConfirmation -InputText $typed

    if ($confirmed) {
        & $write ''
        & $write 'Recorded as a yes. Nothing has been done: this build collects the decision and stops there.'
    }
    else {
        & $write ''
        & $write 'Stopped. Nothing on this PC has been changed.'
    }

    New-ReviewSelectionResult -Confirmed $confirmed -Answer $typed `
        -Finding ([psobject[]] @($selected | ForEach-Object { $_.Finding })) `
        -Plan ([psobject[]] @($plans.ToArray())) `
        -Pick ([psobject[]] @($picks.ToArray()))
}

#endregion

#region Internal: the console it is being printed on

function Get-ReviewConsoleWidth {
    # The window's width, or the default. Never throws: this runs in a remote
    # session, a redirected pipe and an ISE-like host as well as a console, and
    # in some of those RawUI is absent or answers with nonsense.
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $width = 0
    try {
        $rawUi = $Host.UI.RawUI
        if ($null -ne $rawUi -and $null -ne $rawUi.WindowSize) { $width = [int] $rawUi.WindowSize.Width - 1 }
    }
    catch { $width = 0 }

    if ($width -lt $script:ReviewMinimumWidth) { return $script:ReviewDefaultWidth }
    if ($width -gt $script:ReviewMaximumWidth) { return $script:ReviewMaximumWidth }
    $width
}

function Test-ReviewColourSupport {
    <#
        Should ANSI be emitted?

        NO_COLOR is honoured -- it is the one cross-tool convention for this and
        costs nothing to respect. Output that is redirected gets none either,
        because escape sequences in a file are noise.

        Everything else gets colour, INCLUDING the old console host. Windows 11's
        conhost turns virtual-terminal processing on for new sessions, and this
        was measured on both hosts for this chunk rather than assumed; where it
        is off -- an old machine, or the per-user
        HKCU:\Console\VirtualTerminalLevel set to 0 -- the escapes print as
        visible garbage, so -NoColour exists and is one switch away. This
        function deliberately does not P/Invoke SetConsoleMode: changing the
        console's mode is a change to something this tool did not create.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable('NO_COLOR'))) { return $false }

    try { if ([Console]::IsOutputRedirected) { return $false } }
    catch { return $false }

    $true
}

#endregion
