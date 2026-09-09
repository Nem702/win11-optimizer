<#
    The JSON contract -- chunk P6-C1.

    ONE SCAN, AS JSON LINES ON STDOUT. One complete JSON object per line, and
    nothing else on stdout ever. Not one document at the end.

    THAT IS THE WHOLE DESIGN DECISION AND IT HAS ONE REASON: P3, the silent
    scan. The junk phase measures ~26,000 files with nothing to show for it
    until it finishes, and a document written when the scan ends cannot drive a
    progress indicator. A consumer has to be able to render progress from the
    stream as it arrives.

    THIS IS THE SECOND RENDERER OF Get-ReviewScreen, and the seam it uses was
    cut on purpose. P4-C1 split deciding (Get-ReviewScreen) from printing
    (Format-ReviewScreen) so that exactly this could exist. Nothing in this file
    decides anything the screen has not already decided: it projects, it
    serializes, it writes.

    FOUR THINGS THAT WILL BITE, ALL MEASURED BEFORE THIS FILE WAS WRITTEN.

      1. SafetyLabelRule IS A SCRIPTBLOCK AND CANNOT CROSS A PROCESS BOUNDARY.
         Every consumer to date RUNS it. A second process cannot. So the label
         is resolved here, before serializing, and the payload carries the
         resolved string. The rule is not serialized, no rule-shaped object is
         emitted, and the payload deliberately does not hand a consumer enough
         pieces to re-derive it -- the whole point of the scriptblock was that
         the rule lives in exactly one place.

      2. [datetime] SERIALIZES DIFFERENTLY ON THE TWO SHELLS. Q29, closed
         inside P4-C1: a [datetime] nested in a payload comes out /Date(ms)/ on
         5.1 and ISO-8601 on 7. Every timestamp here is an explicit ISO-8601
         string on both shells, normalised through ConvertTo-RemovalUtcText,
         and the writer below REFUSES a raw [datetime] outright rather than
         guessing what to do with one.

      3. ANYTHING THAT WRITES TO STDOUT CORRUPTS THE STREAM.
         logs\Invoke-P4C2Survey.ps1's header records this being measured the
         hard way: a writer that puts lines on the pipeline has them captured
         by the assignment that was meant to receive something else. So the
         default writer is [Console]::Out -- not Write-Output, which the host
         would format, and not Write-Host. Every diagnostic goes to stderr or
         to the run log. Warnings are captured and re-emitted on stderr rather
         than left to the host to place.

      4. Refused IS A FOURTH SCAN-SOURCE STATUS. Succeeded / Skipped / Failed /
         Refused, Reason mandatory on all three non-success ones, and only
         Skipped and Failed making a scan incomplete. Get-OptimizerScanContract
         publishes all four, because a consumer that only knows three will
         silently mis-report a refusal as a failure.

    WHY THE JSON IS WRITTEN BY HAND rather than by ConvertTo-Json. The
    acceptance criterion that matters most is that both shells produce
    byte-identical stdout for the same input, and ConvertTo-Json cannot deliver
    it: 5.1 serializes through JavaScriptSerializer, which escapes the angle
    brackets, the ampersand and the apostrophe as \u escapes, and PowerShell 7
    does not. Number formatting, key order for a plain hashtable and newline
    handling all differ as well. The writer below fixes every one of those by
    construction, and it has a second property worth more than the first: IT
    THROWS ON ANY TYPE IT DOES NOT KNOW. That is the mechanical enforcement of
    "no scriptblock and no PSObject remnant survives serialization anywhere in
    the payload" -- a check that cannot be passed by accident, rather than a
    search for a string.

    EVERY NON-ASCII CHARACTER IS ESCAPED \uXXXX. stdout is then pure ASCII
    whatever the console's encoding happens to be, which removes the last way
    the two shells could disagree about bytes.

    ASCII only, this file included -- one non-ASCII character in a source file
    takes down 137 unrelated tests on 5.1 (docs\REVIEW.md).
#>

#region Constants

# The schema version. It changes when a field is REMOVED or RENAMED, when a
# field's type or meaning changes, when a record kind is added or removed, or
# when one of the published value sets changes. Adding an optional field does
# not change it. A second codebase depends on this shape, and the moment it
# does, changing a field silently is a defect.
$script:ScanJsonSchemaVersion = 1

$script:ScanJsonKindProgress = 'progress'
$script:ScanJsonKindResult   = 'result'
$script:ScanJsonKindError    = 'error'

$script:ScanJsonKinds = @(
    $script:ScanJsonKindProgress
    $script:ScanJsonKindResult
    $script:ScanJsonKindError
)

# The envelope. Lowercase, unlike everything in the payload, and that is the
# split the contract keeps: the envelope is this protocol's own vocabulary, and
# the payload carries the engine's field names UNCHANGED. Renaming SafetyLabel
# to safetyLabel on the way out would be a translation layer between two
# codebases that have to agree, and a translation layer is a place for them to
# stop agreeing.
$script:ScanJsonEnvelopeField = @('kind', 'schemaVersion', 'timestamp')

# A consumer must be able to tell a scan that found nothing from a scan that
# died. This project's signature failure mode, now crossing a process boundary
# where it is easier to hide.
$script:ScanJsonExitResultWritten = 0
$script:ScanJsonExitNoResult      = 1

$script:ScanJsonPhaseStartup    = 'StartupItems'
$script:ScanJsonPhaseInstalled  = 'InstalledApps'
$script:ScanJsonPhaseJunk       = 'JunkFiles'
$script:ScanJsonPhasePlanning   = 'Planning'
$script:ScanJsonPhaseAssembling = 'Assembling'

$script:ScanJsonPhases = @(
    $script:ScanJsonPhaseStartup
    $script:ScanJsonPhaseInstalled
    $script:ScanJsonPhaseJunk
    $script:ScanJsonPhasePlanning
    $script:ScanJsonPhaseAssembling
)

# LF, not CRLF, and stated once. A line-delimited protocol whose delimiter
# depends on which shell wrote it is not byte-identical on both shells.
$script:ScanJsonNewLine = "`n"

# How deep the writer will follow a structure before it decides something has
# gone wrong. The real payload is six levels at its deepest.
$script:ScanJsonMaximumDepth = 32

# The fields every row carries, whatever category it came from.
$script:ScanJsonRowField = @(
    'Number', 'SectionKey', 'DisplayName', 'Category', 'SafetyLabel', 'Cell'
    'FindingId', 'Confidence', 'RequiresConsent', 'RemovalMethod', 'Evidence'
)

# The fields a row carries ONLY where the detector that made the Finding put
# them there. Absent rather than null: a row for an Appx package does not have
# a null age window, it has no age window, and a null would be a placeholder
# for something that does not exist.
$script:ScanJsonCategoryRowField = [ordered]@{
    'OemBloatware' = @('WhitelistEntryId')
    'StartupItem'  = @('Mechanism', 'FindingReason', 'StartupEntryId')
    'Service'      = @('Mechanism', 'FindingReason', 'StartupEntryId')
    'UnusedApp'    = @()
    'JunkFile'     = @('LocationId', 'LocationPath', 'EligibleBytes', 'EligibleFileCount',
                       'IsSizeFloor', 'MinimumAgeDays', 'ProfileBreakdown')
}

# The junk row fields that are numbers rather than text, named once so the
# projection below reads a list instead of repeating a condition.
$script:ScanJsonNumericRowField = @('EligibleBytes', 'EligibleFileCount', 'MinimumAgeDays')

# ---- the inventory, chunk P6-C3 -----------------------------------------
#
# WHAT EACH SECTION LOOKED AT, beside what it flagged. Row[] carries findings
# and nothing else, and a table with four classes needs the other two: the
# objects a rule held back, and the objects nothing was flagged about. Both
# were counted in the headline sentences and neither was in the payload, so
# the only way to draw them was to parse the prose -- which is the thing this
# contract exists to avoid.
#
# DEFINED BY THE SCAN, NOT BY THE SCREEN. The obvious alternative was to carry
# only the two classes the prototype's tables draw today. Rejected: that
# couples the contract to one screen's present design and has to be
# renegotiated the first time a table changes. Inventory[] is what the section
# looked at; which of it a screen draws is the screen's business.
$script:ScanJsonInventoryField = @('Id', 'DisplayName', 'Category', 'Class')

# Present only where the engine had one, and ABSENT otherwise rather than
# null: an object nothing held back has no reason, and a null there would be a
# placeholder for something that does not exist. FindingId is the join back
# into Row[] and is on flagged entries only; RuleId and RuleClass name the
# curated entry that held an object back, so a consumer reads 'security'
# structurally instead of string-matching the reason prose.
$script:ScanJsonOptionalInventoryField = @('Reason', 'FindingId', 'RuleId', 'RuleClass')

# The fields an inventory entry carries only where its category has them. Same
# rule as $script:ScanJsonCategoryRowField, and the same rule the screen's own
# $script:ReviewInventoryCategoryField keeps -- these are read by PRESENCE on
# the entry rather than by restating that table here, so the two cannot
# disagree.
#
# A listed field is present even when its value is null, and on two of them
# that is load-bearing: TargetExists and Exists are TRI-STATES whose null means
# "could not be determined", which is not the same claim as false.
$script:ScanJsonInventoryNumericField = @(
    'FileCount', 'TotalBytes', 'EligibleFileCount', 'EligibleBytes', 'MinimumAgeDays'
)

$script:ScanJsonInventoryBooleanField = @('TargetExists', 'Exists', 'IsAssessed', 'IsSizeFloor')

# What a row's Plan carries, and it is a closed list for a reason. Step is NOT
# on it and neither is RollbackData: a FileDeleteSet step carries the whole
# eligible file list, which on this machine is 773 records for one row and up
# to 14,440 across the category. P3-C2 made this call once already, moving junk
# manifests to sidecars for a 312x smaller ledger line. The payload carries the
# counts; the list stays where it is.
$script:ScanJsonPlanField = @(
    'Route', 'Supported', 'UnsupportedReason', 'CurrentState', 'VerifiedUtc'
    'RequiresElevation', 'RequiresConsent', 'SafetyLabel', 'IsReversible', 'Note', 'PreviewText'
)

#endregion

#region Internal: the JSON writer

function ConvertTo-OptimizerJsonString {
    <#
        One string as one JSON string literal, quotes included.

        Escaping is spelled out here rather than delegated, because the two
        shells' own serializers disagree about it and this is the file where
        that stops mattering. The angle brackets, the ampersand and the
        apostrophe are left as themselves -- they are ordinary characters in
        JSON, 5.1's serializer escapes them and 7's does not, and picking one of
        those two behaviours by hand is the entire point.

        EVERYTHING ABOVE 0x7E BECOMES \uXXXX, in lowercase hex, four digits.
        A surrogate pair comes out as two escapes, which is valid JSON and is
        what every reader expects. The output is then pure ASCII, so the bytes
        on the wire do not depend on the console's encoding.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Value
    )

    $builder = New-Object System.Text.StringBuilder
    $null = $builder.Append('"')

    foreach ($character in $Value.ToCharArray()) {
        $code = [int] $character
        if     ($character -ceq '"')  { $null = $builder.Append('\"') }
        elseif ($character -ceq '\')  { $null = $builder.Append('\\') }
        elseif ($code -eq 8)          { $null = $builder.Append('\b') }
        elseif ($code -eq 9)          { $null = $builder.Append('\t') }
        elseif ($code -eq 10)         { $null = $builder.Append('\n') }
        elseif ($code -eq 12)         { $null = $builder.Append('\f') }
        elseif ($code -eq 13)         { $null = $builder.Append('\r') }
        elseif ($code -lt 32 -or $code -gt 126) { $null = $builder.Append(('\u{0:x4}' -f $code)) }
        else                          { $null = $builder.Append($character) }
    }

    $null = $builder.Append('"')
    $builder.ToString()
}

function ConvertTo-OptimizerJsonText {
    <#
        One value as JSON text. Recursive, deterministic, and DELIBERATELY
        NARROW.

        WHAT IT ACCEPTS: $null, [string], [bool], the integer types, the
        floating types, an IDictionary (which is where key order comes from --
        the projection builds [ordered] hashtables and nothing else), and any
        other IEnumerable, as an array.

        WHAT IT REFUSES, LOUDLY: a scriptblock, a [datetime], and any object it
        was not told about -- a PSCustomObject included. That refusal is the
        contract's enforcement, not a convenience: "no scriptblock and no
        PSObject-typed remnant survives serialization anywhere in the payload"
        is a property this function makes impossible to violate, rather than
        one a test has to go looking for. docs\CHECKLIST.md records four
        occasions on which a lexical ban broke and the fix was always the same
        -- replace the string check with a mechanical one. This is that, built
        in from the start.

        NUMBERS ARE FORMATTED INVARIANTLY. Integers go through
        InvariantCulture; a double is rounded to six places and written with a
        fixed pattern, because .NET Framework and .NET Core disagree about
        round-trip formatting and a duration written one way on one shell and
        another way on the other is not byte-identical output. NaN and infinity
        throw: neither is JSON.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Value,
        [Parameter()] [int] $Depth = 0
    )

    if ($Depth -gt $script:ScanJsonMaximumDepth) {
        throw "ConvertTo-OptimizerJsonText: the structure is deeper than $($script:ScanJsonMaximumDepth) levels. The payload this contract describes is six at its deepest, so this is a loop or an object that should never have been handed to the writer."
    }

    if ($null -eq $Value) { return 'null' }

    # Before anything else, because both are the failures this writer exists to
    # make impossible and either would otherwise be caught by a later branch
    # that would say something less useful.
    if ($Value -is [scriptblock]) {
        throw 'ConvertTo-OptimizerJsonText: a scriptblock reached the writer. A scriptblock cannot cross a process boundary, and the one this project has -- Get-FindingContract().SafetyLabelRule -- must be RUN and its answer serialized, never serialized itself. Resolve it in the projection.'
    }

    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) {
        throw 'ConvertTo-OptimizerJsonText: a [datetime] reached the writer. Q29: a [datetime] nested in a payload comes out as a /Date()/ literal on 5.1 and as ISO-8601 on 7, so this contract carries every timestamp as an explicit ISO-8601 string. Normalise it with ConvertTo-RemovalUtcText first.'
    }

    if ($Value -is [string]) { return (ConvertTo-OptimizerJsonString -Value $Value) }
    if ($Value -is [bool])   { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [char])   { return (ConvertTo-OptimizerJsonString -Value ([string] $Value)) }

    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or
        $Value -is [sbyte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        $number = [double] $Value
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) {
            throw "ConvertTo-OptimizerJsonText: '$number' is not a number JSON can carry. A count or a duration that came out NaN or infinite is a defect upstream, not something to write as a string."
        }
        $text = ([math]::Round($number, 6)).ToString('0.######', [System.Globalization.CultureInfo]::InvariantCulture)
        # The pattern renders a negative zero as '-0', which is legal JSON and
        # is also a difference nobody wants to explain.
        if ($text -eq '-0') { $text = '0' }
        return $text
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($key in $Value.Keys) {
            $null = $parts.Add((ConvertTo-OptimizerJsonString -Value ([string] $key)) + ':' +
                (ConvertTo-OptimizerJsonText -Value $Value[$key] -Depth ($Depth + 1)))
        }
        return '{' + ($parts -join ',') + '}'
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            $null = $parts.Add((ConvertTo-OptimizerJsonText -Value $item -Depth ($Depth + 1)))
        }
        return '[' + ($parts -join ',') + ']'
    }

    $typeName = $Value.GetType().FullName
    throw "ConvertTo-OptimizerJsonText: nothing here knows how to write a [$typeName]. The projection hands this writer ordered hashtables, arrays and primitives, and nothing else -- an object arriving whole means a field was copied rather than projected, and a PSObject that reached a second codebase is a shape nobody agreed to."
}

#endregion

#region Internal: strict-mode-safe reads for the projection

function ConvertTo-OptimizerScanString {
    # A string, or $null. NULL AND EMPTY ARE KEPT APART: New-ScanSource forces a
    # Succeeded source's Reason back to $null rather than '' precisely because
    # callers distinguish "there was no reason" from "the reason was blank",
    # and a projection that collapsed them would throw that away on the way out.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Value
    )

    if ($null -eq $Value) { return $null }
    [string] $Value
}

function ConvertTo-OptimizerScanStringArray {
    # An array of strings, always an array, never $null. A null element is
    # dropped rather than written as JSON null: every one of these lists is a
    # list of lines or of names, and a null line is not one.
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Value
    )

    [string[]] @(@($Value) | Where-Object { $null -ne $_ } | ForEach-Object { [string] $_ })
}

function ConvertTo-OptimizerScanBoolean {
    # A real [bool], or $null when what arrived was not one.
    #
    # NEVER COERCED. RequiresConsent is the motivating field: the safety rule
    # fails closed on anything that is not a real boolean, and coercing the
    # string 'false' to $false here would repair the value on the way out and
    # hide the very thing the fail-closed clause exists to catch. SafetyLabel is
    # resolved separately and already carries the honest answer.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Value
    )

    if ($Value -is [bool]) { return [bool] $Value }
    $null
}

function ConvertTo-OptimizerScanNumber {
    # A number, or $null. Whole values come out as [long] and fractional ones as
    # [double], so a count never acquires a decimal point on its way through.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $null }

    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or
        $Value -is [sbyte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        return [long] $Value
    }

    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        return [double] $Value
    }

    $null
}

function Get-OptimizerScanFindingField {
    <#
        Reads one field off a Finding and returns it wrapped, or $null when the
        Finding does not carry that field at all.

        The distinction matters: $script:ScanJsonCategoryRowField lists the
        fields a category's detector attaches, and a field that is listed but
        genuinely absent must be LEFT OUT of the payload rather than written as
        null. A null there would be a placeholder for something that does not
        exist, which is the one thing the contract is not allowed to carry.

        Wrapped, because the value itself may legitimately be $null and the
        caller has to be able to tell that from "no such field".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Finding,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Name
    )

    if ($null -eq $Finding) { return $null }
    $property = $Finding.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }

    [pscustomobject]@{ Value = $property.Value }
}

#endregion

#region Public: the contract itself

function Get-OptimizerScanContract {
    <#
    .SYNOPSIS
        The JSON contract's own vocabulary: the schema version, the record
        kinds, the statuses, the phases and the exit codes.

    .DESCRIPTION
        The sibling of Get-FindingContract and Get-RemovalContract, and it
        exists for the same reason: a consumer -- including a consumer written
        in another language, in another repository -- reads the permitted values
        from one place instead of restating them.

        SourceStatuses carries ALL FOUR, and IncompleteStatuses carries the two
        that make a scan incomplete. That pair is the one a second codebase is
        most likely to get wrong: a consumer that knows only Succeeded, Skipped
        and Failed will silently report a refusal -- a signal this project
        declines to use on every machine, forever -- as a failure, which is a
        different and much worse claim.

        SchemaVersion is 1. It changes when a field is removed or renamed, when
        a field's type or meaning changes, when a record kind is added or
        removed, or when one of the value sets below changes. Adding an optional
        field does not change it.

        P6-C3 ADDED Inventory[] AND InventoryCount TO EVERY SECTION AND LEFT THE
        VERSION AT 1, deliberately. Nothing was removed, renamed or retyped; no
        record kind moved; none of the value sets that existed changed -- two
        new ones were published beside them. The C# binds by key presence rather
        than by shape, so a consumer built against the old payload reads the new
        one and simply does not see the new field. That is what additive means
        here, and it is why the version holds.

    .EXAMPLE
        (Get-OptimizerScanContract).SourceStatuses
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    # A copy of the per-category table, not the table. A consumer that could
    # edit what it was handed could change what the next caller is told the
    # contract says -- the same rule Get-RemovalContract follows for its routes.
    $categoryField = [ordered]@{}
    foreach ($key in $script:ScanJsonCategoryRowField.Keys) {
        $categoryField[[string] $key] = [string[]] @($script:ScanJsonCategoryRowField[$key])
    }

    [pscustomobject][ordered]@{
        SchemaVersion           = [int] $script:ScanJsonSchemaVersion
        RecordKinds             = [string[]] $script:ScanJsonKinds
        EnvelopeFields          = [string[]] $script:ScanJsonEnvelopeField
        Phases                  = [string[]] $script:ScanJsonPhases
        SourceStatuses          = [string[]] $script:ScanSourceStatuses
        IncompleteStatuses      = [string[]] $script:ScanSourceIncompleteStatuses
        RowFields               = [string[]] $script:ScanJsonRowField
        CategoryRowFields       = $categoryField
        # The inventory's own vocabulary, chunk P6-C3. InventoryClasses is the
        # one a second codebase is most likely to get wrong, and it is the same
        # shape of mistake as reading three source statuses instead of four: a
        # consumer that knew only 'Flagged' and 'NotFlagged' would file every
        # held-back object under "nothing was said about it", which is the
        # under-report this project exists to prevent.
        InventoryFields         = [string[]] $script:ScanJsonInventoryField
        OptionalInventoryFields = [string[]] $script:ScanJsonOptionalInventoryField
        InventoryClasses        = [string[]] $script:ReviewInventoryClasses
        PlanFields              = [string[]] $script:ScanJsonPlanField
        ExitCodes               = [pscustomobject][ordered]@{
            ResultWritten = [int] $script:ScanJsonExitResultWritten
            NoResult      = [int] $script:ScanJsonExitNoResult
        }
        NewLine                 = [string] $script:ScanJsonNewLine
    }
}

#endregion

#region Internal: the projection

function ConvertTo-OptimizerScanSourceRecord {
    # One ScanSource, whole: status and Reason both, because a source that did
    # not simply succeed and carries no reason is the silent under-report this
    # project exists to prevent, and it must survive the process boundary.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Source
    )

    [ordered]@{
        Name            = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Source -Name 'Name')
        Status          = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Source -Name 'Status')
        Reason          = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Source -Name 'Reason')
        ItemCount       = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $Source -Name 'ItemCount' -Default 0)
        DurationSeconds = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $Source -Name 'DurationSeconds' -Default 0)
    }
}

function ConvertTo-OptimizerScanScanRecord {
    # One detector's scan, as the screen now carries it.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Scan
    )

    $sources = New-Object System.Collections.Generic.List[psobject]
    foreach ($source in @(Get-OptimizerProperty -InputObject $Scan -Name 'Source' -Default @())) {
        if ($null -eq $source) { continue }
        $null = $sources.Add((ConvertTo-OptimizerScanSourceRecord -Source $source))
    }

    [ordered]@{
        Detector          = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Scan -Name 'Detector')
        Category          = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Scan -Name 'Category')
        # ISO-8601, on both shells. New-ScanResult holds StartedUtc as a real
        # [datetime]; this is where it stops being one.
        StartedUtc        = ConvertTo-RemovalUtcText -Value (Get-OptimizerProperty -InputObject $Scan -Name 'StartedUtc')
        DurationSeconds   = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $Scan -Name 'DurationSeconds' -Default 0)
        IsElevated        = [bool](Get-OptimizerProperty -InputObject $Scan -Name 'IsElevated' -Default $false)
        InventoryCount    = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $Scan -Name 'InventoryCount' -Default 0)
        FindingCount      = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $Scan -Name 'FindingCount' -Default 0)
        IsComplete        = [bool](Get-OptimizerProperty -InputObject $Scan -Name 'IsComplete' -Default $true)
        IncompleteReason  = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Scan -Name 'IncompleteReason')
        RefusedSourceName = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $Scan -Name 'RefusedSourceName' -Default @())
        Source            = [psobject[]] @($sources.ToArray())
    }
}

function ConvertTo-OptimizerScanProfileRecord {
    # One entry of a junk row's ProfileBreakdown. Q14's split, as data.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $ProfileRecord
    )

    [ordered]@{
        Profile           = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $ProfileRecord -Name 'Profile')
        FileCount         = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $ProfileRecord -Name 'FileCount' -Default 0)
        TotalBytes        = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $ProfileRecord -Name 'TotalBytes' -Default 0)
        EligibleFileCount = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $ProfileRecord -Name 'EligibleFileCount' -Default 0)
        EligibleBytes     = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $ProfileRecord -Name 'EligibleBytes' -Default 0)
    }
}

function ConvertTo-OptimizerScanPlanRecord {
    <#
        A plan, reduced to $script:ScanJsonPlanField and nothing else.

        PreviewText IS CARRIED VERBATIM. It is already worded, it is already
        asserted against the forbidden-benefit-phrase list, P3-C2 keeps it on
        the ledger so the record and the screen cannot disagree, and a second
        renderer must not re-word it. This function copies the lines; it does
        not touch them.

        Step and RollbackData are absent by construction -- see the note on
        $script:ScanJsonPlanField.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Plan
    )

    if ($null -eq $Plan) { return $null }

    [ordered]@{
        Route             = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Plan -Name 'Route')
        Supported         = [bool](Get-OptimizerProperty -InputObject $Plan -Name 'Supported' -Default $false)
        UnsupportedReason = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Plan -Name 'UnsupportedReason')
        CurrentState      = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Plan -Name 'CurrentState')
        VerifiedUtc       = ConvertTo-RemovalUtcText -Value (Get-OptimizerProperty -InputObject $Plan -Name 'VerifiedUtc')
        RequiresElevation = [bool](Get-OptimizerProperty -InputObject $Plan -Name 'RequiresElevation' -Default $false)
        RequiresConsent   = ConvertTo-OptimizerScanBoolean -Value (Get-OptimizerProperty -InputObject $Plan -Name 'RequiresConsent')
        SafetyLabel       = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Plan -Name 'SafetyLabel')
        IsReversible      = [bool](Get-OptimizerProperty -InputObject $Plan -Name 'IsReversible' -Default $false)
        Note              = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $Plan -Name 'Note' -Default @())
        PreviewText       = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $Plan -Name 'PreviewText' -Default @())
    }
}

function ConvertTo-OptimizerScanRowRecord {
    <#
        One review row, plus the Finding fields the screen relies on, plus its
        plan where one could be made.

        SafetyLabel IS THE ROW'S, which the screen produced by RUNNING
        Get-FindingContract().SafetyLabelRule (Get-ReviewSafetyLabel). It is
        read here rather than re-derived, and the rule itself never leaves the
        process. A row that somehow arrived without one has the rule run for it
        -- never the two-axis AND restated, which exists in exactly one place
        and is going to stay there.

        EligibleFile is deliberately not projected. It is 773 records for one
        row on this machine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Row,
        [Parameter(Mandatory)] [AllowNull()] $Planner
    )

    $finding  = Get-OptimizerProperty -InputObject $Row -Name 'Finding'
    $category = [string](Get-OptimizerProperty -InputObject $Row -Name 'Category' -Default '')

    $label = [string](Get-OptimizerProperty -InputObject $Row -Name 'SafetyLabel' -Default '')
    if ([string]::IsNullOrWhiteSpace($label)) { $label = Get-ReviewSafetyLabel -Finding $finding }

    $record = [ordered]@{
        Number          = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $Row -Name 'Number' -Default 0)
        SectionKey      = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Row -Name 'SectionKey')
        DisplayName     = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Row -Name 'DisplayName')
        Category        = ConvertTo-OptimizerScanString -Value $category
        SafetyLabel     = ConvertTo-OptimizerScanString -Value $label
        Cell            = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $Row -Name 'Cell' -Default @())
        FindingId       = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $finding -Name 'Id')
        Confidence      = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $finding -Name 'Confidence')
        RequiresConsent = ConvertTo-OptimizerScanBoolean -Value (Get-OptimizerProperty -InputObject $finding -Name 'RequiresConsent')
        RemovalMethod   = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $finding -Name 'RemovalMethod')
        Evidence        = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $finding -Name 'Evidence' -Default @())
    }

    # The category's own fields, and only where the Finding really carries them.
    $extra = @()
    if ($script:ScanJsonCategoryRowField.Contains($category)) { $extra = @($script:ScanJsonCategoryRowField[$category]) }

    foreach ($name in $extra) {
        $held = Get-OptimizerScanFindingField -Finding $finding -Name $name
        if ($null -eq $held) { continue }

        $value = $held.Value

        if ($name -eq 'ProfileBreakdown') {
            $profiles = New-Object System.Collections.Generic.List[psobject]
            foreach ($entry in @($value)) {
                if ($null -eq $entry) { continue }
                $null = $profiles.Add((ConvertTo-OptimizerScanProfileRecord -ProfileRecord $entry))
            }
            $record[$name] = [psobject[]] @($profiles.ToArray())
        }
        elseif ($name -eq 'LocationPath') {
            $record[$name] = ConvertTo-OptimizerScanStringArray -Value $value
        }
        elseif ($script:ScanJsonNumericRowField -contains $name) {
            $record[$name] = ConvertTo-OptimizerScanNumber -Value $value
        }
        elseif ($name -eq 'IsSizeFloor') {
            $record[$name] = [bool] $value
        }
        else {
            $record[$name] = ConvertTo-OptimizerScanString -Value $value
        }
    }

    if ($null -ne $Planner) {
        $record['Plan'] = ConvertTo-OptimizerScanPlanRecord -Plan (& $Planner $finding)
    }

    $record
}

function ConvertTo-OptimizerScanInventoryRecord {
    <#
        One inventory entry: an object the section inspected, and what the
        engine did with it.

        THE KEYS ARE THE ENTRY'S OWN, IN THE ENTRY'S OWN ORDER. The screen built
        it as an ordered hashtable and added a key only where the field applies,
        so walking the properties here reproduces exactly that -- one table of
        which category carries which field, in Review\Screen.ps1, rather than a
        second copy of it here that could disagree with the first. Property
        order off a [pscustomobject] built from an [ordered] hashtable is
        construction order on both shells, which is what keeps the bytes
        identical.

        ABSENT IS NOT NULL, and it comes out of that walk for free: a field the
        entry does not carry produces no key. A field it DOES carry is written
        even when its value is null, which on the two tri-states -- TargetExists
        and Exists -- is the engine saying it looked and could not tell. A
        consumer must not read either of those nulls as false.

        The type of each value is decided by name against the two lists above,
        so a count never acquires a decimal point and a tri-state is never
        coerced to a bare bool.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Entry
    )

    $record = [ordered]@{}
    if ($null -eq $Entry) { return $record }

    foreach ($property in $Entry.PSObject.Properties) {
        $name  = [string] $property.Name
        $value = $property.Value

        if ($script:ScanJsonInventoryNumericField -contains $name) {
            $record[$name] = ConvertTo-OptimizerScanNumber -Value $value
        }
        elseif ($script:ScanJsonInventoryBooleanField -contains $name) {
            $record[$name] = ConvertTo-OptimizerScanBoolean -Value $value
        }
        else {
            $record[$name] = ConvertTo-OptimizerScanString -Value $value
        }
    }

    $record
}

function ConvertTo-OptimizerScanSectionRecord {
    # One section's decided content. The wording is the screen's; this copies it.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Section,
        [Parameter(Mandatory)] [AllowNull()] $Planner
    )

    $rows = New-Object System.Collections.Generic.List[psobject]
    foreach ($row in @(Get-OptimizerProperty -InputObject $Section -Name 'Row' -Default @())) {
        if ($null -eq $row) { continue }
        $null = $rows.Add((ConvertTo-OptimizerScanRowRecord -Row $row -Planner $Planner))
    }

    $inventory = New-Object System.Collections.Generic.List[psobject]
    foreach ($entry in @(Get-OptimizerProperty -InputObject $Section -Name 'Inventory' -Default @())) {
        if ($null -eq $entry) { continue }
        $null = $inventory.Add((ConvertTo-OptimizerScanInventoryRecord -Entry $entry))
    }

    [ordered]@{
        Key               = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Section -Name 'Key')
        Title             = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Section -Name 'Title')
        Headline          = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $Section -Name 'Headline' -Default @())
        Note              = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $Section -Name 'Note' -Default @())
        ColumnHeader      = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $Section -Name 'ColumnHeader' -Default @())
        # Null where there are no rows, and that is load-bearing rather than
        # incidental: docs\STATE.md forbids a bare junk category total, and
        # Get-ReviewJunkSection enforces it by never producing one without the
        # per-row split. The rule survives the process boundary because the
        # field does.
        TotalLine         = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Section -Name 'TotalLine')
        IsComplete        = [bool](Get-OptimizerProperty -InputObject $Section -Name 'IsComplete' -Default $true)
        IncompleteReason  = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Section -Name 'IncompleteReason')
        RefusedSourceName = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $Section -Name 'RefusedSourceName' -Default @())
        EmptyText         = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Section -Name 'EmptyText')
        RowCount          = [long] $rows.Count
        Row               = [psobject[]] @($rows.ToArray())
        # BESIDE Row[], NOT INSTEAD OF IT. Row[] is what this section flagged;
        # Inventory[] is everything it looked at, the flagged objects included,
        # so InventoryCount here is the scan's own inventory count and a test
        # asserts exactly that per section. Assembled by the screen -- see
        # New-ReviewStartupInventory and its two siblings -- because deciding
        # which rule held an object back is a judgement, and this file makes
        # none.
        InventoryCount    = [long] $inventory.Count
        Inventory         = [psobject[]] @($inventory.ToArray())
    }
}

#endregion

#region Public: the payload

function ConvertTo-OptimizerScanPayload {
    <#
    .SYNOPSIS
        Turns a review screen into the plain-data payload of a 'result' record.
        Decides nothing; emits no text.

    .DESCRIPTION
        The projection, and it is an ALLOW LIST rather than a copy. Every field
        that reaches the payload is named in this file, which is what makes the
        payload's size and shape predictable and what stops a future detector's
        extra field arriving unannounced in a contract a second codebase
        depends on.

        What comes back is ordered hashtables, arrays, strings, numbers,
        booleans and nulls -- nothing else. No scriptblock, no PSObject, no
        [datetime]. ConvertTo-OptimizerJsonText refuses all three, so this is a
        property the writer enforces rather than one this function is trusted
        to maintain.

    .PARAMETER Screen
        A screen from Get-ReviewScreen.

    .PARAMETER Planner
        How to get a removal plan for one Finding. Defaults to Get-RemovalPlan,
        which reads and changes nothing.

        It is a parameter rather than a call for two reasons: the runner wraps
        it to emit a progress line per finding, and a test injects a
        deterministic one. Passing -SkipPlan leaves Plan off every row.

    .PARAMETER SkipPlan
        Do not plan anything. Every row comes back without a Plan field.

    .EXAMPLE
        ConvertTo-OptimizerScanPayload -Screen (Get-ReviewScreen)
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Screen,
        [Parameter()] [AllowNull()] [scriptblock] $Planner,
        [switch] $SkipPlan
    )

    $usePlanner = $null
    if (-not $SkipPlan) {
        $usePlanner = $(if ($null -ne $Planner) { $Planner } else { { param($Finding) Get-RemovalPlan -Finding $Finding } })
    }

    $scans = New-Object System.Collections.Generic.List[psobject]
    foreach ($scan in @(Get-OptimizerProperty -InputObject $Screen -Name 'Scan' -Default @())) {
        if ($null -eq $scan) { continue }
        $null = $scans.Add((ConvertTo-OptimizerScanScanRecord -Scan $scan))
    }

    $sections = New-Object System.Collections.Generic.List[psobject]
    foreach ($section in @(Get-OptimizerProperty -InputObject $Screen -Name 'Section' -Default @())) {
        if ($null -eq $section) { continue }
        $null = $sections.Add((ConvertTo-OptimizerScanSectionRecord -Section $section -Planner $usePlanner))
    }

    # Get-OptimizerRunReceipt's own lines, carried unchanged. $null when there
    # is no ledger yet, which is the ordinary case on a first run and is not an
    # error -- and $null rather than an empty array, so a consumer can tell "no
    # ledger" from "a ledger with nothing in it".
    $receipt = Get-OptimizerProperty -InputObject $Screen -Name 'ReceiptText'
    $receiptText = $(if ($null -eq $receipt) { $null } else { ConvertTo-OptimizerScanStringArray -Value $receipt })

    [ordered]@{
        GeneratedUtc   = ConvertTo-RemovalUtcText -Value (Get-OptimizerProperty -InputObject $Screen -Name 'GeneratedUtc')
        MachineName    = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Screen -Name 'MachineName')
        UserName       = ConvertTo-OptimizerScanString -Value (Get-OptimizerProperty -InputObject $Screen -Name 'UserName')
        IsElevated     = [bool](Get-OptimizerProperty -InputObject $Screen -Name 'IsElevated' -Default $false)
        IsComplete     = [bool](Get-OptimizerProperty -InputObject $Screen -Name 'IsComplete' -Default $true)
        # Named, not summarised -- the same rule Format-ReviewScreen follows. A
        # banner that says "some scans were partial" without saying which is the
        # under-report this project exists to prevent, wearing a warning.
        PartialSection = ConvertTo-OptimizerScanStringArray -Value (Get-OptimizerProperty -InputObject $Screen -Name 'PartialSection' -Default @())
        RowCount       = ConvertTo-OptimizerScanNumber -Value (Get-OptimizerProperty -InputObject $Screen -Name 'RowCount' -Default 0)
        ReceiptText    = $receiptText
        Scan           = [psobject[]] @($scans.ToArray())
        Section        = [psobject[]] @($sections.ToArray())
    }
}

#endregion

#region Public: one record as one line

function ConvertTo-OptimizerScanJson {
    <#
    .SYNOPSIS
        One protocol record as one line of JSON text. Prints; decides nothing.

    .DESCRIPTION
        Wraps a payload in the envelope -- kind, schemaVersion, timestamp -- and
        serializes the whole thing with this file's own writer.

        THE ENVELOPE IS BUILT IN EXACTLY ONE PLACE, here, and the payload's keys
        are merged in beside it rather than nested under a wrapper: a consumer
        reading a 'result' line should not have to open a box to find the
        screen. A payload that carries one of the envelope's own key names
        THROWS rather than overwriting it.

        schemaVersion goes on EVERY record, not only the result. A consumer
        holding one line has to be able to tell what it is reading.

    .PARAMETER Kind
        'progress', 'result' or 'error'.

    .PARAMETER Payload
        An ordered hashtable of the record's own fields.

    .PARAMETER TimestampUtc
        The record's timestamp. Defaults to now. Supplied explicitly by the
        tests, so that a fixture serializes to the same bytes every time.

    .EXAMPLE
        ConvertTo-OptimizerScanJson -Kind result -Payload (ConvertTo-OptimizerScanPayload -Screen $screen)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)] [ValidateSet('progress', 'result', 'error')] [string] $Kind,
        [Parameter(Mandatory, Position = 1)] [AllowNull()] $Payload,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $TimestampUtc
    )

    $stamp = $(
        if ([string]::IsNullOrWhiteSpace($TimestampUtc)) { [datetime]::UtcNow.ToString('o') }
        else { ConvertTo-RemovalUtcText -Value $TimestampUtc }
    )

    $record = [ordered]@{
        kind          = $Kind
        schemaVersion = [int] $script:ScanJsonSchemaVersion
        timestamp     = $stamp
    }

    if ($null -ne $Payload) {
        if ($Payload -isnot [System.Collections.IDictionary]) {
            throw "ConvertTo-OptimizerScanJson: the payload is a [$($Payload.GetType().FullName)]. It has to be an ordered hashtable -- key order is part of this contract's byte-for-byte output, and an object would be serialized in whatever order its properties happen to sit in."
        }
        foreach ($key in $Payload.Keys) {
            $name = [string] $key
            if ($script:ScanJsonEnvelopeField -contains $name) {
                throw "ConvertTo-OptimizerScanJson: the payload carries '$name', which is one of this protocol's own envelope fields ($($script:ScanJsonEnvelopeField -join ', ')). Merging it would overwrite the envelope, and a line whose 'kind' came from a detector is a line nobody can route."
            }
            $record[$name] = $Payload[$key]
        }
    }

    ConvertTo-OptimizerJsonText -Value $record
}

#endregion

#region Internal: the progress record

function New-OptimizerScanProgress {
    # One progress payload. Every field on every one of them, whatever the
    # phase: Set-StrictMode -Version Latest is on for everything that reads
    # these, and a consumer branching on a field that is sometimes absent is a
    # consumer that throws on the interesting run.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Phase,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Message,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Item,
        [Parameter()] [long] $ItemIndex = 0,
        [Parameter()] [long] $ItemCount = 0,
        [Parameter()] [long] $FindingCount = 0,
        [Parameter()] [long] $InventoryCount = 0
    )

    $index = [array]::IndexOf([string[]] $script:ScanJsonPhases, $Phase)
    if ($index -lt 0) {
        throw "New-OptimizerScanProgress: '$Phase' is not one of Get-OptimizerScanContract().Phases ($($script:ScanJsonPhases -join ', '))."
    }

    # Held untyped and only ever assigned a string: $x = $null on a
    # [string]-constrained variable becomes '', and '' reads as "there was an
    # item and it was blank" rather than as "there was none". docs\REVIEW.md.
    $itemValue = $null
    if (-not [string]::IsNullOrWhiteSpace($Item)) { $itemValue = [string] $Item }

    [ordered]@{
        Phase          = $Phase
        PhaseIndex     = [long] ($index + 1)
        PhaseCount     = [long] @($script:ScanJsonPhases).Count
        Message        = $Message
        # What it is on now. The junk phase names its location, which is the
        # only phase where the work is a list a person can watch go by.
        Item           = $itemValue
        ItemIndex      = [long] $ItemIndex
        ItemCount      = [long] $ItemCount
        # The counts SO FAR, which is what they are and what they must not be
        # read as: a total.
        FindingCount   = [long] $FindingCount
        InventoryCount = [long] $InventoryCount
    }
}

#endregion

#region Public: the runner

function Invoke-OptimizerScanJson {
    <#
    .SYNOPSIS
        Runs a scan and writes it to stdout as JSON Lines. Returns the exit
        code. Changes nothing on this PC.

    .DESCRIPTION
        The runner. It scans, it emits 'progress' lines as it goes, it plans
        each finding, and it emits exactly one 'result' line at the end -- or,
        if something failed, one 'error' line and nothing else.

        STDOUT CARRIES PROTOCOL LINES AND NOTHING ELSE. The default writer is
        [Console]::Out, deliberately: Write-Output puts objects on the pipeline
        for the host to format, and a line put on the pipeline is a line the
        assignment that was meant to receive something else will capture.
        logs\Invoke-P4C2Survey.ps1's header records that being measured the hard
        way. Every scan is run with its warnings CAPTURED and re-emitted on
        stderr, rather than left to the host to place.

        THE RESULT LINE IS BUILT WHOLE AND WRITTEN ONCE. A consumer has to be
        able to tell a scan that found nothing from a scan that died, and the
        case it cannot be protected from -- a process killed mid-run -- is only
        detectable if a half-written 'result' line is impossible. So the line is
        serialized into a string first and handed to the writer in a single
        call.

        IT RUNS NOTHING AND CHANGES NOTHING. Four read-only scans, the review
        screen, and Get-RemovalPlan -- which reads, and which P3-C1 ships
        without any Invoke-* at all. The write path is a different chunk.

    .PARAMETER Writer
        Scriptblock taking one line, for stdout. Defaults to [Console]::Out.

    .PARAMETER ErrorWriter
        Scriptblock taking one line, for stderr. Defaults to [Console]::Error.

    .PARAMETER LedgerPath
        The action ledger the receipt is read from. Defaults to
        Get-OptimizerActionLogPath. Read-only.

    .PARAMETER SkipReceipt
        Do not read the ledger at all.

    .PARAMETER SkipPlan
        Do not plan the findings. Every row comes back without a Plan.

    .EXAMPLE
        exit (Invoke-OptimizerScanJson)

    .OUTPUTS
        [int] -- 0 when a result line was written, non-zero when none was.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter()] [ValidateNotNull()] [scriptblock] $Writer = {
            param($Line)
            [Console]::Out.Write([string] $Line + "`n")
            [Console]::Out.Flush()
        },
        [Parameter()] [ValidateNotNull()] [scriptblock] $ErrorWriter = {
            param($Line)
            [Console]::Error.WriteLine([string] $Line)
            [Console]::Error.Flush()
        },
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $LedgerPath,
        [switch] $SkipReceipt,
        [switch] $SkipPlan
    )

    $scanJsonWrite      = { param($Line) $null = & $Writer ([string] $Line) }
    $scanJsonWriteError = { param($Line) $null = & $ErrorWriter ([string] $Line) }

    # Which phase we were in when it went wrong. Set before each phase so the
    # error record can say where, which is the first thing a consumer showing a
    # failure needs.
    $phase = $script:ScanJsonPhaseStartup

    # Counted as the scans return, and carried into the progress lines. They are
    # counts SO FAR and the record says so by its field names; nothing here may
    # present them as a total, because the scan that would make them one has not
    # finished yet.
    $scanJsonFindingCount   = [long] 0
    $scanJsonInventoryCount = [long] 0

    try {
        # ---- startup items --------------------------------------------------
        $null = & $scanJsonWrite (ConvertTo-OptimizerScanJson -Kind $script:ScanJsonKindProgress -Payload (
            New-OptimizerScanProgress -Phase $script:ScanJsonPhaseStartup `
                -Message 'Reading what starts with this PC.'))

        $scanWarning = @()
        $startupScan = Invoke-StartupItemScan -WarningAction SilentlyContinue -WarningVariable scanWarning
        foreach ($line in @($scanWarning)) { $null = & $scanJsonWriteError ("win11-optimizer: $line") }

        $scanJsonInventoryCount += [long](Get-OptimizerProperty -InputObject $startupScan -Name 'InventoryCount' -Default 0)
        $scanJsonFindingCount   += [long]@(Get-OptimizerProperty -InputObject $startupScan -Name 'Findings' -Default @()).Count

        # ---- installed apps, which is two scans ----------------------------
        $phase = $script:ScanJsonPhaseInstalled
        $null = & $scanJsonWrite (ConvertTo-OptimizerScanJson -Kind $script:ScanJsonKindProgress -Payload (
            New-OptimizerScanProgress -Phase $script:ScanJsonPhaseInstalled -Item 'Usage signals' `
                -ItemIndex 1 -ItemCount 2 -FindingCount $scanJsonFindingCount -InventoryCount $scanJsonInventoryCount `
                -Message 'Reading installed applications and how recently they were used.'))

        $scanWarning = @()
        $unusedScan = Invoke-UnusedAppScan -WarningAction SilentlyContinue -WarningVariable scanWarning
        foreach ($line in @($scanWarning)) { $null = & $scanJsonWriteError ("win11-optimizer: $line") }

        $scanJsonInventoryCount += [long](Get-OptimizerProperty -InputObject $unusedScan -Name 'InventoryCount' -Default 0)
        $scanJsonFindingCount   += [long]@(Get-OptimizerProperty -InputObject $unusedScan -Name 'Findings' -Default @()).Count

        $null = & $scanJsonWrite (ConvertTo-OptimizerScanJson -Kind $script:ScanJsonKindProgress -Payload (
            New-OptimizerScanProgress -Phase $script:ScanJsonPhaseInstalled -Item 'Curated list' `
                -ItemIndex 2 -ItemCount 2 -FindingCount $scanJsonFindingCount -InventoryCount $scanJsonInventoryCount `
                -Message 'Checking installed applications against the curated list.'))

        $scanWarning = @()
        $oemScan = Invoke-OemBloatwareScan -WarningAction SilentlyContinue -WarningVariable scanWarning
        foreach ($line in @($scanWarning)) { $null = & $scanJsonWriteError ("win11-optimizer: $line") }

        $scanJsonInventoryCount += [long](Get-OptimizerProperty -InputObject $oemScan -Name 'InventoryCount' -Default 0)
        $scanJsonFindingCount   += [long]@(Get-OptimizerProperty -InputObject $oemScan -Name 'Findings' -Default @()).Count

        # ---- the junk phase, which is the one this protocol exists for ------
        #
        # ~26,000 files, measured in silence until now. -OnProgress names each
        # curated location as it is reached, which is the only handle a progress
        # indicator has on the longest phase in the tool.
        #
        # NO .GetNewClosure() ON THIS OR ON THE PLANNER BELOW, and the reason is
        # measured rather than stylistic: GetNewClosure rebinds a scriptblock to
        # a NEW dynamic module, and the rebound block can no longer see this
        # module's own private functions. The first run of this file died with
        # "The term 'Get-OptimizerProperty' is not recognized" from inside the
        # junk reporter for exactly that reason.
        #
        # It does not need one. PowerShell resolves a variable dynamically, up
        # the call stack, and this reporter is invoked from inside
        # Get-JunkLocationInventory, whose caller is Invoke-JunkFileScan, whose
        # caller is this function -- so $scanJsonWrite and the two counts below
        # are in scope where it runs. That is why every local these two blocks
        # read carries the scanJson prefix: the name is the contract, and a
        # prefixed name cannot be shadowed by a local in a function in between.
        #
        # The two counts do not move while the junk scan runs -- the findings it
        # produces are counted after it returns -- so this is the honest reading
        # of "so far".
        $phase = $script:ScanJsonPhaseJunk
        $scanJsonJunkFindingCount   = $scanJsonFindingCount
        $scanJsonJunkInventoryCount = $scanJsonInventoryCount

        $onJunkProgress = {
            param($Location)
            $name = [string](Get-OptimizerProperty -InputObject $Location -Name 'DisplayName')
            $null = & $scanJsonWrite (ConvertTo-OptimizerScanJson -Kind $script:ScanJsonKindProgress -Payload (
                New-OptimizerScanProgress -Phase $script:ScanJsonPhaseJunk -Item $name `
                    -ItemIndex ([long](Get-OptimizerProperty -InputObject $Location -Name 'Index' -Default 0)) `
                    -ItemCount ([long](Get-OptimizerProperty -InputObject $Location -Name 'Count' -Default 0)) `
                    -FindingCount $scanJsonJunkFindingCount -InventoryCount $scanJsonJunkInventoryCount `
                    -Message ('Measuring {0}.' -f $name)))
        }

        $scanWarning = @()
        $junkScan = Invoke-JunkFileScan -OnProgress $onJunkProgress -WarningAction SilentlyContinue -WarningVariable scanWarning
        foreach ($line in @($scanWarning)) { $null = & $scanJsonWriteError ("win11-optimizer: $line") }

        $scanJsonInventoryCount += [long](Get-OptimizerProperty -InputObject $junkScan -Name 'InventoryCount' -Default 0)
        $scanJsonFindingCount   += [long]@(Get-OptimizerProperty -InputObject $junkScan -Name 'Findings' -Default @()).Count

        # ---- the screen ----------------------------------------------------
        $phase = $script:ScanJsonPhaseAssembling
        $screenArguments = @{
            StartupScan   = $startupScan
            UnusedAppScan = $unusedScan
            OemScan       = $oemScan
            JunkScan      = $junkScan
        }
        if (-not [string]::IsNullOrWhiteSpace($LedgerPath)) { $screenArguments['LedgerPath'] = $LedgerPath }
        if ($SkipReceipt) { $screenArguments['SkipReceipt'] = $true }

        $screen = Get-ReviewScreen @screenArguments

        # ---- the plans -----------------------------------------------------
        #
        # Get-RemovalPlan re-probes, so this is what the machine says now rather
        # than what the detector said a minute ago -- and it reads, which is
        # what makes it safe to call from something whose whole job is to
        # describe what would happen.
        $phase = $script:ScanJsonPhasePlanning
        $scanJsonRowCount = [long](Get-OptimizerProperty -InputObject $screen -Name 'RowCount' -Default 0)
        # A [ref] rather than a plain local, because dynamic scoping lets the
        # planner READ this function's variables and not assign to them: a bare
        # assignment inside the scriptblock would create a local of its own and
        # every plan would be announced as number 1.
        $scanJsonPlanned = [ref] ([long] 0)

        $payloadArguments = @{ Screen = $screen }
        if ($SkipPlan) {
            $payloadArguments['SkipPlan'] = $true
        }
        else {
            $payloadArguments['Planner'] = {
                param($Finding)
                $scanJsonPlanned.Value = $scanJsonPlanned.Value + 1
                $name = [string](Get-OptimizerProperty -InputObject $Finding -Name 'DisplayName')
                $null = & $scanJsonWrite (ConvertTo-OptimizerScanJson -Kind $script:ScanJsonKindProgress -Payload (
                    New-OptimizerScanProgress -Phase $script:ScanJsonPhasePlanning -Item $name `
                        -ItemIndex $scanJsonPlanned.Value -ItemCount $scanJsonRowCount `
                        -FindingCount $scanJsonFindingCount -InventoryCount $scanJsonInventoryCount `
                        -Message ('Working out what would happen to {0}.' -f $name)))
                Get-RemovalPlan -Finding $Finding
            }
        }

        $payload = ConvertTo-OptimizerScanPayload @payloadArguments

        $phase = $script:ScanJsonPhaseAssembling
        $null = & $scanJsonWrite (ConvertTo-OptimizerScanJson -Kind $script:ScanJsonKindProgress -Payload (
            New-OptimizerScanProgress -Phase $script:ScanJsonPhaseAssembling `
                -FindingCount $scanJsonFindingCount -InventoryCount $scanJsonInventoryCount `
                -Message 'Assembling the result.'))

        # SERIALIZED WHOLE, THEN WRITTEN ONCE. A partial result line must be
        # impossible, so that a consumer seeing no result line at all knows the
        # process died rather than that the scan found nothing.
        $line = ConvertTo-OptimizerScanJson -Kind $script:ScanJsonKindResult -Payload $payload
        $null = & $scanJsonWrite $line

        return [int] $script:ScanJsonExitResultWritten
    }
    catch {
        # PowerShell wraps an exception thrown by a .NET method in a
        # MethodInvocationException, so the useful type and message are one
        # level down. Get-OptimizerInnerException does that properly.
        $exception = Get-OptimizerInnerException -Exception $_.Exception
        $message = [string] $exception.Message

        # The error line first, then the sentence on stderr. Both, always: the
        # line is for the consumer and the sentence is for the person reading a
        # console, and a failure only one of them can see is a failure the other
        # one reports as an empty scan.
        try {
            $null = & $scanJsonWrite (ConvertTo-OptimizerScanJson -Kind $script:ScanJsonKindError -Payload ([ordered]@{
                Phase         = $phase
                ExceptionType = [string] $exception.GetType().Name
                Message       = $message
            }))
        }
        catch {
            # stdout is gone -- a closed pipe is the ordinary reason. There is
            # nowhere left to put the protocol line, and the stderr sentence
            # below is the whole of what can still be said.
            $null = & $scanJsonWriteError ("win11-optimizer: the failure below could not be written to stdout either: $($_.Exception.Message)")
        }

        $null = & $scanJsonWriteError ("win11-optimizer: the scan failed during the $phase phase and no result was produced. $message")
        return [int] $script:ScanJsonExitNoResult
    }
}

#endregion
