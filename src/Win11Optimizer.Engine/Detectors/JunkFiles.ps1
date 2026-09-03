<#
    JunkFiles detector -- chunk P2-C4.

    Reports the disk locations on this machine that hold genuinely reclaimable
    junk, how much is in each one, and returns Findings for the subset that is
    defensibly safe to delete.

    THE RULE THIS FILE EXISTS TO OBEY
    ---------------------------------
    "A file is not junk because of where it sits."

    Every earlier detector points at software -- something with an installer, an
    uninstall path and a vendor. This one points at FILES, and a false positive
    here costs data that has no undo. So a file becomes deletable only when ALL
    of the following hold, and every one of them is a gate in code below:

      1. it is inside a location on the curated list (Data\junk-locations.json),
         which is a reviewed claim this project ships -- there is NO heuristic
         tier, no "this folder looks like a cache", no size threshold that
         promotes a folder into scope;
      2. nothing has modified it inside the age window (-MinimumAgeDays, or
         the curated entry own longer window where it declares one);
      3. no other process holds it open, where "cannot tell" counts as open;
      4. it was not reached by following a reparse point;
      5. the location is not marked inventory-only, and is not one of the
         locations this file protects IN CODE regardless of what the list says.

    THE UNIT OF JUDGEMENT IS THE LOCATION, NOT THE FILE
    ---------------------------------------------------
    One Finding per curated location, never one per file. A developer's %TEMP%
    holds thousands of files (1,964 when this was written); a Finding each is
    unreviewable in P4-C1 and unactionable by a human. So a Finding is
    "Windows Update download cache -- N files, X MiB", its Id is the location's
    curated id, and the enumerated file list hangs off it.

    CONSEQUENCE FOR P3-C1: RemovalMethod 'FileDelete' on a JunkFile Finding means
    "delete this SET of files", not "delete this path". The set is enumerated once,
    here, at scan time; P3-C1 must re-check the in-use gate per file at removal
    time, because a file that was free ten minutes ago may not be now.

    WHAT IS NOT HERE, AND WILL NOT BE
    ---------------------------------
    Downloads, Documents, Desktop, Pictures, Videos, Music and any other folder
    the user saves into are out of scope entirely -- not enumerated, not sized,
    not reported. WinSxS belongs to DISM alone. Prefetch is evidence P2-C3 reads
    and may never be a Finding. Shadow copies are P3-C2's rollback assumption.
    The page file, the hibernation file and crash dumps are reclaimed by
    configuration rather than deletion. The first three are enforced in code by
    Get-JunkProtectedPath and Get-JunkForcedInventoryPath, not by a list entry, so
    no future list edit can reach them.

    This file DETECTS ONLY. It never deletes, moves, truncates or writes anything;
    every filesystem call in it is a read or a read-only open probe.

    Public surface (registered in the .psm1 export list and the .psd1 manifest):
      Get-JunkLocationList       load + validate the curated location list
      Get-JunkLocationInventory  read this machine -> locations + per-location status
      Find-JunkFileLocation      pure: locations -> Findings
      Invoke-JunkFileScan        scan this machine -> scan result

    ASCII only -- see Detectors\README.md for what a UTF-8 em dash does to 5.1.
#>

#region Constants

$script:JunkCategory      = 'JunkFile'
$script:JunkRemovalMethod = 'FileDelete'

# The age window. A file written five minutes ago in %TEMP% probably belongs to a
# running installer, so nothing modified inside the window is ever eligible.
#
# Seven days, matching the window Windows' own Disk Cleanup applies to the temp
# folder -- a published precedent rather than a number this project invented, and
# long enough that a multi-stage installer, a reboot-and-continue update or a
# weekend-long download can finish. It is a named parameter on every public
# function here; nothing compares against a literal.
$script:JunkDefaultMinimumAgeDays = 7

# The upper bound on a curated entry's own age window, and the same number
# -MinimumAgeDays is range-validated against. An entry may declare a window of its
# own (Data\junk-locations.json 'minimumAgeDays') where one scan-wide number cannot
# express what the location is worth: the NVIDIA shader cache is set to 30, because
# a game played ten days ago should not have its compiled shaders thrown away.
#
# The entry's value is a FLOOR under the scan's, never a replacement -- see
# Get-JunkLocationInventory -- and a value outside 1..this fails the whole list
# load rather than being ignored.
$script:JunkMaximumAgeDays = 3650

# The age anchor is the NEWER of LastWriteTimeUtc and CreationTimeUtc. Two
# timestamps because either alone can lie in the dangerous direction: a file
# copied into place preserving its write time is new but reads old, and a file
# created long ago is old but may have been written to a second ago.
#
# LastAccessTime is deliberately not consulted. docs\STATE.md 2026-08-25 measured
# it saturated on this machine -- every file on the volume reads as accessed
# within ~1.2 days because something scans them all -- so an access-time age gate
# would hold back the entire disk and this detector would find nothing, which is
# this project's signature failure mode wearing a safety label.

$script:JunkProvenanceValues    = @('measured', 'published')
$script:JunkPublishedProvenance = 'published'
$script:JunkPublishedEvidence   = 'Provenance: this location comes from a published source. It has never been observed holding anything on real hardware by this project, so the claim is only as good as that source.'

# Location resolvers. A closed set: 'path' expands the entry's own paths, and
# 'recycleBin' is code, because the Recycle Bin lives at one folder per fixed
# drive named after the current user's SID and no environment variable spells it.
$script:JunkResolverPath       = 'path'
$script:JunkResolverRecycleBin = 'recycleBin'
$script:JunkResolverValues     = @($script:JunkResolverPath, $script:JunkResolverRecycleBin)

# Sample caps on the diagnostic detail carried per location, so one pathological
# folder cannot put 100k paths on a scan result.
$script:JunkMaxReparseSample    = 25
$script:JunkMaxUnreadableSample = 10

$script:JunkLocationTypeName   = 'Win11Optimizer.JunkLocation'
$script:JunkFileTypeName       = 'Win11Optimizer.JunkFile'
$script:JunkEntryTypeName      = 'Win11Optimizer.JunkLocationEntry'
$script:JunkInventoryTypeName  = 'Win11Optimizer.JunkInventory'
$script:JunkScanResultTypeName = 'Win11Optimizer.JunkScanResult'
$script:JunkScanSourceTypeName = 'Win11Optimizer.JunkScanSource'
# One per browser profile inside a profile-expanded location. Q14: a browser is
# still ONE Finding, and this is how the row says it is four profiles.
$script:JunkProfileTypeName    = 'Win11Optimizer.JunkLocationProfile'

# The in-use verdicts. 'Undetermined' exists because a probe that cannot answer
# must not be read as "free" -- it is counted separately and treated as in use.
# Taken from the shared constants rather than restated, so the detector and the
# removal dispatcher cannot drift apart on spelling (chunk P3-C1).
$script:JunkInUseFree         = $script:OptimizerInUseFree
$script:JunkInUseHeld         = $script:OptimizerInUseHeld
$script:JunkInUseUndetermined = $script:OptimizerInUseUndetermined

#endregion

#region Internal: the paths this file protects in code

function Get-JunkKnownUserFolderPath {
    <#
        The folders a person saves things into, resolved from the shell rather
        than spelled out. A junk detector that enumerates any of these is a junk
        detector that offers to delete someone's tax return.

        Promoted to Shared\Inventory.ps1 as Get-OptimizerKnownUserFolderPath by
        chunk P3-C1, on its second consumer. This name stays as a delegation.

        -ProfileRoot is deliberately NOT passed. The shared default is
        [Environment]::GetFolderPath('UserProfile') -- the same value this file used
        to spell out -- and P3-C1 only passed it to keep a source-scanning
        assertion in tests\JunkFiles.Tests.ps1 matching after the promotion. P3-C1a
        moved that assertion to tests\SharedInventory.Tests.ps1, where the code it
        is about now lives, so the delegation is a delegation again.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    Get-OptimizerKnownUserFolderPath
}

function Get-JunkProtectedPath {
    <#
        Every path this detector may not enumerate, with the reason it may not,
        and HOW the check applies.

        The universal half -- the known user folders (Subtree), the profile root,
        the Windows folder and the fixed drive roots (Root) -- was promoted to
        Shared\Inventory.ps1 as Get-OptimizerProtectedPath by chunk P3-C1, because
        the removal dispatcher is the last gate before anything is acted on and
        needs exactly the same list. See that function for why the two match modes
        exist and why conflating them rejects %TEMP%.

        What is left here is the one entry that belongs to this detector alone:
        the component store. It is not on the shared list because it is not a
        universal rule about acting on paths -- it is a statement about who owns
        WinSxS, and the answer is DISM.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    Get-OptimizerProtectedPath

    $windowsRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
    if (-not [string]::IsNullOrWhiteSpace($windowsRoot)) {
        [pscustomobject]@{
            Path   = (Join-Path -Path $windowsRoot -ChildPath 'WinSxS')
            Match  = 'Subtree'
            Reason = 'the component store belongs to DISM alone, and getting it wrong breaks Windows servicing'
        }
    }
}

function Get-JunkForcedInventoryPath {
    <#
        Locations that may be SIZED and reported but may never become a Finding,
        whatever the curated list says. Enforced here rather than by the entry's
        own inventoryOnly flag, so a future list edit cannot flip one.

        Prefetch is the whole reason this function exists: P2-C3's elevated scan
        reads .pf files as a usage signal, and docs\STATE.md Q11 measured the cost
        directly -- the folder losing 244 files took six applications' 'Used'
        verdict with it. A junk detector must never offer to delete evidence
        another detector relies on.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    $windowsRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
    if (-not [string]::IsNullOrWhiteSpace($windowsRoot)) {
        [pscustomobject]@{
            Path   = (Join-Path -Path $windowsRoot -ChildPath 'Prefetch')
            Reason = 'the unused-application detector reads this folder as evidence of which programs you actually use, so this tool will not offer to delete it'
        }
    }
}

function Get-JunkFixedDriveRoot {
    # Promoted to Shared\Inventory.ps1 as Get-OptimizerFixedDriveRoot by chunk
    # P3-C1 with the rest of the protected-path cluster. Delegation only.
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    Get-OptimizerFixedDriveRoot
}

function ConvertTo-JunkComparablePath {
    # Promoted to Shared\Inventory.ps1 as ConvertTo-OptimizerComparablePath by
    # chunk P3-C1 with the rest of the protected-path cluster. Delegation only.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    ConvertTo-OptimizerComparablePath -Path $Path
}

function Test-JunkPathWithin {
    # Promoted to Shared\Inventory.ps1 as Test-OptimizerPathWithin by chunk P3-C1
    # with the rest of the protected-path cluster. Delegation only.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Container
    )

    Test-OptimizerPathWithin -Path $Path -Container $Container
}

function Get-JunkProtectedPathConflict {
    # Promoted to Shared\Inventory.ps1 as Get-OptimizerProtectedPathConflict by
    # chunk P3-C1, on its second consumer: the removal dispatcher runs the same
    # directional check as the LAST gate before anything is acted on. This name
    # stays as a delegation so the call sites in this file are untouched.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ProtectedPath
    )

    Get-OptimizerProtectedPathConflict -Path $Path -ProtectedPath $ProtectedPath
}

#endregion

#region Internal: formatting

function Format-JunkSize {
    # Human-readable size for evidence lines. Invariant culture on purpose: the
    # evidence string ends up in a JSON run log and must not change shape with the
    # machine's locale.
    #
    # THE UNITS ARE BINARY AND THE LABELS SAY SO. The divisors below are 1024,
    # 1024^2 and 1024^3, so the labels are KiB / MiB / GiB, not KB / MB / GB.
    # Explorer divides by the same 1024 and labels it 'GB', so on its own this was
    # a label that agreed with the number beside it in the only place a user could
    # compare them. It stops agreeing the moment anything else does -- a drive
    # maker's GB, a download size, a Storage Settings figure -- and this project's
    # whole pitch is that the number and the sentence never disagree. KiB is the
    # unambiguous name for what is actually being counted.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Bytes
    )

    $value = [double] 0
    if ($null -ne $Bytes) { $value = [double] $Bytes }
    if ($value -lt 0) { $value = 0 }

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    if ($value -lt 1024) { return ([long] $value).ToString('N0', $culture) + ' bytes' }
    if ($value -lt 1048576) { return ($value / 1024).ToString('N1', $culture) + ' KiB' }
    if ($value -lt 1073741824) { return ($value / 1048576).ToString('N1', $culture) + ' MiB' }
    ($value / 1073741824).ToString('N2', $culture) + ' GiB'
}

function Format-JunkCount {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Count
    )

    $value = [long] 0
    if ($null -ne $Count) { $value = [long] $Count }
    $value.ToString('N0', [System.Globalization.CultureInfo]::InvariantCulture)
}

#endregion

#region Internal: records

function New-JunkScanSource {
    # Thin wrapper over the shared New-ScanSource so every source this detector
    # reports carries the detector's own type tag as well as the shared one.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('Succeeded', 'Skipped', 'Failed', 'Refused')] [string] $Status,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Reason,
        [Parameter()] [int] $ItemCount = 0,
        [Parameter()] [double] $DurationSeconds = 0
    )

    $arguments = @{
        AdditionalTypeName = $script:JunkScanSourceTypeName
        Name               = $Name
        Status             = $Status
        ItemCount          = $ItemCount
        DurationSeconds    = $DurationSeconds
    }
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $arguments['Reason'] = $Reason }

    New-ScanSource @arguments
}

function New-JunkFileRecord {
    # One record per file that passed every gate. This is what P3-C1 deletes and
    # what P3-C2 needs a size for, so the size travels with the path rather than
    # being re-read later from a file that may already be gone.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [long] $SizeBytes,
        [Parameter(Mandatory)] [datetime] $LastWriteUtc,
        [Parameter(Mandatory)] [string] $LocationId
    )

    [pscustomobject]@{
        PSTypeName   = $script:JunkFileTypeName
        Path         = $Path
        SizeBytes    = $SizeBytes
        LastWriteUtc = $LastWriteUtc
        LocationId   = $LocationId
    }
}

function New-JunkLocation {
    <#
        One record per curated location: what it is, what was found in it, and
        what was held back. Every property is always present (even when null) so
        the matcher, the tests and P4-C1 can rely on the shape.

        This record is reported for EVERY location, including ones that produce no
        Finding and ones that could not be read. "Recycle Bin: 2.3 MiB, not
        flagged" is inventory the user wants; "Recycle Bin" silently absent is the
        failure mode this project is built against.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $DisplayName,
        [Parameter(Mandatory)] [string] $Reason,
        [Parameter(Mandatory)] [string] $Provenance,
        [Parameter()] [AllowNull()] [string] $Owner,
        [Parameter()] [bool] $InventoryOnly = $false,
        [Parameter()] [AllowNull()] [string] $InventoryOnlyReason,
        # The age window this location was ACTUALLY measured against, which is not
        # always the scan's: an entry may carry a floor of its own. Carried on the
        # record so the matcher can name the real window in the evidence rather
        # than repeating the scan-wide one.
        [Parameter()] [int] $MinimumAgeDays = $script:JunkDefaultMinimumAgeDays,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [string[]] $ResolvedPath,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [string[]] $DeclaredPath,
        [Parameter(Mandatory)] [ValidateSet('Succeeded', 'Skipped', 'Failed', 'Refused')] [string] $Status,
        [Parameter()] [AllowNull()] [string] $StatusReason,
        [Parameter()] [AllowNull()] [Nullable[bool]] $Exists,
        [Parameter()] [bool] $IsAssessed = $false,
        [Parameter()] [long] $FileCount = 0,
        [Parameter()] [long] $TotalBytes = 0,
        [Parameter()] [bool] $IsSizeFloor = $false,
        [Parameter()] [long] $UnreadableDirectoryCount = 0,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [string[]] $UnreadableDirectorySample,
        [Parameter()] [long] $ReparsePointCount = 0,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [string[]] $ReparsePointSample,
        [Parameter()] [long] $DuplicatePathCount = 0,
        [Parameter()] [long] $AgeHeldBackCount = 0,
        [Parameter()] [long] $AgeHeldBackBytes = 0,
        [Parameter()] [long] $InUseCount = 0,
        [Parameter()] [long] $UndeterminedCount = 0,
        [Parameter()] [long] $EligibleFileCount = 0,
        [Parameter()] [long] $EligibleBytes = 0,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $EligibleFile,
        # Q14. One record per browser profile for a location whose paths came out
        # of the profileChildPath expansion; empty for every other location, which
        # is most of them. Always present, so the matcher and the tests can read
        # it without asking whether it is there.
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ProfileBreakdown,
        [Parameter()] [double] $DurationSeconds = 0,
        [Parameter()] [AllowNull()] [string] $Detail
    )

    # @($null) is an array of one null, not an empty array, so every collection
    # here is filtered rather than wrapped. A ResolvedPath of @($null) would reach
    # an evidence line as an empty path and a test as a count of one.
    $declared = @()
    if ($null -ne $DeclaredPath) { $declared = @($DeclaredPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }

    $resolved = @()
    if ($null -ne $ResolvedPath) { $resolved = @($ResolvedPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }

    $reparse = @()
    if ($null -ne $ReparsePointSample) { $reparse = @($ReparsePointSample | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }

    $unreadable = @()
    if ($null -ne $UnreadableDirectorySample) { $unreadable = @($UnreadableDirectorySample | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }

    $files = @()
    if ($null -ne $EligibleFile) { $files = @($EligibleFile | Where-Object { $null -ne $_ }) }

    $profile = @()
    if ($null -ne $ProfileBreakdown) { $profile = @($ProfileBreakdown | Where-Object { $null -ne $_ }) }

    [pscustomobject]@{
        PSTypeName                = $script:JunkLocationTypeName
        Id                        = $Id
        DisplayName               = $DisplayName
        Reason                    = $Reason
        Provenance                = $Provenance
        Owner                     = $Owner
        InventoryOnly             = $InventoryOnly
        InventoryOnlyReason       = $InventoryOnlyReason
        MinimumAgeDays            = $MinimumAgeDays
        DeclaredPath              = [string[]] $declared
        ResolvedPath              = [string[]] $resolved
        Status                    = $Status
        StatusReason              = $StatusReason
        Exists                    = $Exists
        IsAssessed                = $IsAssessed
        FileCount                 = $FileCount
        TotalBytes                = $TotalBytes
        IsSizeFloor               = $IsSizeFloor
        UnreadableDirectoryCount  = $UnreadableDirectoryCount
        UnreadableDirectorySample = [string[]] $unreadable
        ReparsePointCount         = $ReparsePointCount
        ReparsePointSample        = [string[]] $reparse
        DuplicatePathCount        = $DuplicatePathCount
        AgeHeldBackCount          = $AgeHeldBackCount
        AgeHeldBackBytes          = $AgeHeldBackBytes
        InUseCount                = $InUseCount
        UndeterminedCount         = $UndeterminedCount
        EligibleFileCount         = $EligibleFileCount
        EligibleBytes             = $EligibleBytes
        EligibleFile              = [psobject[]] $files
        ProfileBreakdown          = [psobject[]] $profile
        DurationSeconds           = $DurationSeconds
        Detail                    = $Detail
    }
}

#endregion

#region Internal: the gates

function Test-JunkFileInUse {
    <#
        Is another process holding this file open? Returns one of Free / InUse /
        Undetermined, and the caller treats the last two identically.

        The probe itself lives in Shared\Inventory.ps1 as Test-OptimizerFileInUse,
        promoted there by chunk P3-C1 on its second consumer -- the removal
        dispatcher re-checks the same gate at plan time -- exactly as
        Test-StartupTargetPresent was promoted by P2-C4. This name stays as a
        delegation so the call sites in this file and their tests are untouched.

        -Access is deliberately NOT passed. The shared default is
        [System.IO.FileAccess]::Read and the shared function ENFORCES it, throwing
        for anything else; P3-C1 only passed it to keep a source-scanning
        assertion in tests\JunkFiles.Tests.ps1 matching after the promotion. P3-C1a
        moved that assertion to tests\SharedInventory.Tests.ps1, where the code it
        is about now lives, so the delegation is a delegation again.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Path
    )

    Test-OptimizerFileInUse -Path $Path
}

function Get-JunkDirectoryContent {
    <#
        Walks one directory tree and returns what is in it, without ever following
        a reparse point and without ever silently under-reporting.

        Three deliberate choices, each of which the alternative gets wrong:

        1. EVERY read is [System.IO.Directory]::, never Get-ChildItem. REVIEW.md:
           Get-ChildItem returns zero items and raises no error on a folder the
           current user cannot list, even with -ErrorAction Stop.

        2. The walk is an explicit stack, one directory at a time, never
           SearchOption.AllDirectories. Measured here on
           %ProgramData%\Microsoft\Windows\WER\ReportArchive un-elevated:
           GetFiles(path, '*', AllDirectories) THREW UnauthorizedAccessException
           and returned NOTHING, while the per-directory walk returned the 3 files
           it could see and counted the 296 directories it could not. A recursive
           call aborts the whole enumeration on the first denied subtree; this
           walk records it and keeps going.

        3. A directory whose listing failed increments UnreadableDirectoryCount,
           which makes the location's size a FLOOR rather than a total. It must not
           silently shrink.

        Files are deduplicated against $SeenPath across the whole scan, so two
        curated locations that overlap cannot count the same file twice.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [datetime] $CutoffUtc,
        [Parameter(Mandatory)] [AllowNull()] $SeenPath,
        [Parameter(Mandatory)] [string] $LocationId,
        [Parameter()] [switch] $CollectFiles
    )

    $result = [pscustomobject]@{
        FileCount                 = [long] 0
        TotalBytes                = [long] 0
        AgeHeldBackCount          = [long] 0
        AgeHeldBackBytes          = [long] 0
        AgePassCount              = [long] 0
        AgePassBytes              = [long] 0
        DuplicatePathCount        = [long] 0
        ReparsePointCount         = [long] 0
        ReparsePointSample        = (New-Object System.Collections.Generic.List[string])
        UnreadableDirectoryCount  = [long] 0
        UnreadableDirectorySample = (New-Object System.Collections.Generic.List[string])
        Candidate                 = (New-Object System.Collections.Generic.List[psobject])
    }

    $reparse = [int][System.IO.FileAttributes]::ReparsePoint

    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Path)

    while ($stack.Count -gt 0) {
        $directory = $stack.Pop()

        # A directory counts as unreadable ONCE, however many of the two reads
        # below fail on it. Counting the subdirectory listing and the file listing
        # separately would report two unreadable folders where there is one, and
        # that number reaches the user as the reason their size is a floor.
        $directoryUnreadable = $false

        $subdirectories = $null
        try { $subdirectories = [System.IO.Directory]::GetDirectories($directory) }
        catch {
            $directoryUnreadable = $true
            $subdirectories = @()
        }

        foreach ($subdirectory in $subdirectories) {
            $attributes = $null
            try { $attributes = [System.IO.File]::GetAttributes($subdirectory) }
            catch {
                # Cannot even read the attributes, so whether it is a junction
                # cannot be established. Not traversed, and counted as unreadable
                # so the size stays a floor.
                $result.UnreadableDirectoryCount++
                if ($result.UnreadableDirectorySample.Count -lt $script:JunkMaxUnreadableSample) {
                    $result.UnreadableDirectorySample.Add($subdirectory)
                }
                continue
            }

            if (([int] $attributes -band $reparse) -ne 0) {
                # A junction, symlink or mount point can point anywhere on the
                # system, including at a real user folder. Recursing through one
                # would size and offer to delete something outside this
                # detector's scope, under an evidence line naming an in-scope
                # path. So: not traversed, not sized, not listed -- counted.
                $result.ReparsePointCount++
                if ($result.ReparsePointSample.Count -lt $script:JunkMaxReparseSample) {
                    $result.ReparsePointSample.Add($subdirectory)
                }
                continue
            }

            $stack.Push($subdirectory)
        }

        $files = $null
        try { $files = [System.IO.Directory]::GetFiles($directory) }
        catch {
            $directoryUnreadable = $true
            $files = @()
        }

        if ($directoryUnreadable) {
            $result.UnreadableDirectoryCount++
            if ($result.UnreadableDirectorySample.Count -lt $script:JunkMaxUnreadableSample) {
                $result.UnreadableDirectorySample.Add($directory)
            }
        }

        foreach ($file in $files) {
            $info = $null
            try { $info = New-Object System.IO.FileInfo $file }
            catch {
                $result.UnreadableDirectoryCount++
                continue
            }

            $attributes = $null
            $length     = [long] 0
            $lastWrite  = [datetime]::MinValue
            $created    = [datetime]::MinValue
            try {
                $attributes = $info.Attributes
                $length     = $info.Length
                $lastWrite  = $info.LastWriteTimeUtc
                $created    = $info.CreationTimeUtc
            }
            catch {
                # The file was there a moment ago and cannot be stat'ed now.
                # Counted as unreadable rather than skipped silently.
                $result.UnreadableDirectoryCount++
                continue
            }

            if (([int] $attributes -band $reparse) -ne 0) {
                $result.ReparsePointCount++
                if ($result.ReparsePointSample.Count -lt $script:JunkMaxReparseSample) {
                    $result.ReparsePointSample.Add($file)
                }
                continue
            }

            if ($null -ne $SeenPath) {
                $key = ConvertTo-JunkComparablePath -Path $file
                if ([string]::IsNullOrWhiteSpace($key)) {
                    $result.UnreadableDirectoryCount++
                    continue
                }
                $key = $key.ToLowerInvariant()
                if ($SeenPath.Contains($key)) {
                    # Already counted under another curated location. Counting it
                    # twice would claim space that only exists once.
                    $result.DuplicatePathCount++
                    continue
                }
                $null = $SeenPath.Add($key)
            }

            $result.FileCount++
            $result.TotalBytes += $length

            $anchor = $lastWrite
            if ($created -gt $anchor) { $anchor = $created }

            if ($anchor -ge $CutoffUtc) {
                $result.AgeHeldBackCount++
                $result.AgeHeldBackBytes += $length
                continue
            }

            $result.AgePassCount++
            $result.AgePassBytes += $length

            if ($CollectFiles) {
                $result.Candidate.Add((New-JunkFileRecord -Path $file -SizeBytes $length -LastWriteUtc $lastWrite -LocationId $LocationId))
            }
        }
    }

    $result
}

#endregion

#region Public: the curated list

function Get-JunkLocationList {
    <#
    .SYNOPSIS
        Loads and validates the curated junk-location list.

    .DESCRIPTION
        Reads Data\junk-locations.json and returns one normalized entry per list
        entry, with every field guaranteed present.

        Every rule is enforced here and violations THROW, the same treatment
        Get-KnownBloatwareList, Get-UnusedAppExclusionList and
        Get-KnownStartupItemList get, and for the same reason with more at stake:
        a list that silently fails to load yields zero locations, and a junk
        detector that silently finds nothing looks exactly like a clean disk.

        The rules that are about safety rather than shape:

          * A declared path that resolves inside -- or that contains -- a known
            user folder, the component store, the profile root or a drive root is
            REJECTED, by name, with the reason. This is the rule that keeps
            Downloads out, and it lives here rather than on the list.
          * A path may not contain '..'.
          * Prefetch is forced to inventory-only whatever the entry says.
          * An entry's optional 'minimumAgeDays' must be a whole number between 1
            and $script:JunkMaximumAgeDays, and a bad one fails the load. It is
            REJECTED rather than ignored on purpose: skipping the entry would drop
            a location from a junk list, and a junk detector that reports one
            location fewer looks exactly like a slightly cleaner disk.

        Note the strict-mode trap the other loaders hit: $entry.PSObject.Properties.Name
        throws on an EMPTY property collection under Set-StrictMode -Version
        Latest, so properties are enumerated one at a time.

    .PARAMETER Path
        List file to load. Defaults to Data\junk-locations.json next to the module.

    .EXAMPLE
        Get-JunkLocationList | Select-Object Id, DisplayName, Provenance, InventoryOnly
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if (-not $Path) {
        $Path = Join-Path -Path $script:OptimizerDataRoot -ChildPath 'junk-locations.json'
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Junk-location list not found at '$Path'. The JunkFiles detector will not run without it -- with no list there are no locations, and a scan that reported nothing would be indistinguishable from a clean disk."
    }

    $raw = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Junk-location list '$Path' is empty."
    }

    try {
        $document = ConvertFrom-Json -InputObject $raw
    }
    catch {
        throw "Junk-location list '$Path' is not valid JSON: $($_.Exception.Message)"
    }

    # Read the property directly rather than through Get-OptimizerProperty: an
    # empty JSON array would unroll to nothing on the way out of a function and be
    # indistinguishable from a missing 'entries' key.
    $entriesProperty = $document.PSObject.Properties['entries']
    if ($null -eq $entriesProperty -or $null -eq $entriesProperty.Value) {
        throw "Junk-location list '$Path' has no 'entries' array."
    }

    $entries = @($entriesProperty.Value)
    if ($entries.Count -lt 1) {
        throw "Junk-location list '$Path' contains no entries."
    }

    $protected      = @(Get-JunkProtectedPath)
    $forcedInventory = @(Get-JunkForcedInventoryPath)

    $seenIds = @{}
    $index   = -1

    foreach ($entry in $entries) {
        $index++
        $id = [string](Get-OptimizerProperty -InputObject $entry -Name 'id')
        $where = if ([string]::IsNullOrWhiteSpace($id)) { "entry #$index" } else { "entry '$id'" }

        foreach ($required in 'id', 'displayName', 'reason', 'provenance') {
            $value = [string](Get-OptimizerProperty -InputObject $entry -Name $required)
            if ([string]::IsNullOrWhiteSpace($value)) {
                throw "Junk-location list '$Path': $where is missing a non-empty '$required'. Every entry is a claim that a folder on a user's machine holds nothing worth keeping; it has to say what it is, why, and whether this project has ever seen it on real hardware."
            }
        }

        if ($seenIds.ContainsKey($id.ToLowerInvariant())) {
            throw "Junk-location list '$Path': duplicate entry id '$id'."
        }
        $seenIds[$id.ToLowerInvariant()] = $true

        $provenance = [string](Get-OptimizerProperty -InputObject $entry -Name 'provenance')
        if ($script:JunkProvenanceValues -notcontains $provenance) {
            throw "Junk-location list '$Path': $where declares unknown 'provenance' '$provenance'. Allowed: $($script:JunkProvenanceValues -join ', ')."
        }

        $resolver = [string](Get-OptimizerProperty -InputObject $entry -Name 'resolver' -Default $script:JunkResolverPath)
        if ($script:JunkResolverValues -notcontains $resolver) {
            throw "Junk-location list '$Path': $where declares unknown 'resolver' '$resolver'. Allowed: $($script:JunkResolverValues -join ', '). A resolver is code in the detector, not something a list entry can invent."
        }

        # Same rule and same reasoning as the other three lists: the string "true"
        # is truthy in PowerShell and would leave an entry looking enforced while
        # the code that reads it disagreed.
        $inventoryOnly = $false
        $inventoryProperty = $entry.PSObject.Properties['inventoryOnly']
        if ($null -ne $inventoryProperty -and $null -ne $inventoryProperty.Value) {
            if ($inventoryProperty.Value -isnot [bool]) {
                throw "Junk-location list '$Path': $where declares 'inventoryOnly' as [$($inventoryProperty.Value.GetType().Name)] '$($inventoryProperty.Value)'. It must be a JSON boolean (true / false), not a string."
            }
            $inventoryOnly = [bool] $inventoryProperty.Value
        }

        # An optional per-entry age window. ABSENT means "use the scan's
        # -MinimumAgeDays", which is what every other entry on the shipped list
        # does and must keep doing.
        #
        # A bad value fails the WHOLE load rather than skipping the entry, the
        # same treatment a bad path gets a few lines below: a malformed curated
        # entry is a bug in a file this project ships, not a condition of the
        # machine, and an entry quietly dropped from a junk list is one more
        # location that reports nothing on a disk that is not clean.
        #
        # Not read through Get-OptimizerProperty: the type has to be checked
        # before any coercion happens, and reading the raw property is the only
        # way to see what the JSON actually said.
        $minimumAge = $null
        $ageProperty = $entry.PSObject.Properties['minimumAgeDays']
        if ($null -ne $ageProperty -and $null -ne $ageProperty.Value) {
            $ageValue = $ageProperty.Value

            # A JSON integer arrives as [int] under Windows PowerShell 5.1 and as
            # [long] under PowerShell 7, so the test is on the integral types
            # rather than on one of them. A string, a boolean or a fractional
            # number is rejected by name for the same reason "true" is rejected
            # above: '30' is silently coercible in PowerShell and would leave an
            # entry looking configured while nothing had checked it.
            $isWholeNumber = ($ageValue -is [int]) -or ($ageValue -is [long]) -or ($ageValue -is [int16]) -or ($ageValue -is [byte])
            if (-not $isWholeNumber) {
                throw "Junk-location list '$Path': $where declares 'minimumAgeDays' as [$($ageValue.GetType().Name)] '$ageValue'. It must be a whole JSON number (30, not `"30`", not 30.5, not true)."
            }

            $ageDays = [long] $ageValue
            if ($ageDays -lt 1 -or $ageDays -gt $script:JunkMaximumAgeDays) {
                throw "Junk-location list '$Path': $where declares 'minimumAgeDays' as $ageDays. It must be between 1 and $($script:JunkMaximumAgeDays). A location's own window is a floor under the scan's, so 0 or less would say nothing at all, and a number beyond this bound would hold the location back forever without saying so."
            }

            $minimumAge = [int] $ageDays
        }

        $declaredPaths = @()
        if ($resolver -eq $script:JunkResolverPath) {
            $pathsProperty = $entry.PSObject.Properties['paths']
            if ($null -eq $pathsProperty -or $null -eq $pathsProperty.Value) {
                throw "Junk-location list '$Path': $where has no 'paths' array. Every entry either names its paths or declares a resolver."
            }

            $declaredPaths = @(@($pathsProperty.Value) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ })

            if ($declaredPaths.Count -lt 1) {
                throw "Junk-location list '$Path': $where declares 'paths' with no usable path."
            }

            foreach ($declared in $declaredPaths) {
                if ($declared.Contains('..')) {
                    throw "Junk-location list '$Path': $where declares path '$declared', which contains '..'. A junk location is named outright, never reached by walking upwards out of one."
                }

                # Expanded and checked HERE, at load, against the folders this
                # detector may never enumerate. An entry that resolves into the
                # user's own files is a bug in the list, and it fails the whole
                # load rather than quietly becoming one more row.
                $expanded = $null
                try { $expanded = [System.Environment]::ExpandEnvironmentVariables($declared) } catch { $expanded = $null }
                if ([string]::IsNullOrWhiteSpace($expanded)) { continue }

                # An environment variable that does not exist on this machine
                # leaves its own name behind ('%NOPE%\x'); that is a resolution
                # miss, handled at scan time, not a safety violation.
                if ($expanded.Contains('%')) { continue }

                $conflict = Get-JunkProtectedPathConflict -Path $expanded -ProtectedPath $protected
                if ($null -ne $conflict) {
                    throw "Junk-location list '$Path': $where declares path '$declared', which resolves to '$expanded' and collides with '$($conflict.Path)' -- $($conflict.Reason). This detector never enumerates it, and an entry that names it is a bug in the list, not a row to be skipped."
                }
            }
        }

        $profileChildPaths = @()
        $childProperty = $entry.PSObject.Properties['profileChildPath']
        if ($null -ne $childProperty -and $null -ne $childProperty.Value) {
            $profileChildPaths = @(@($childProperty.Value) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ })

            if ($profileChildPaths.Count -lt 1) {
                throw "Junk-location list '$Path': $where declares 'profileChildPath' with no usable path."
            }

            foreach ($child in $profileChildPaths) {
                if ($child.Contains('..')) {
                    throw "Junk-location list '$Path': $where declares profile child path '$child', which contains '..'."
                }
                if ([System.IO.Path]::IsPathRooted($child)) {
                    throw "Junk-location list '$Path': $where declares profile child path '$child', which is an absolute path. A profile child path is relative to one profile folder, and naming it absolutely would reach outside the browser folder it is scoped to."
                }
            }
        }

        # Prefetch and anything else this file protects is inventory-only whatever
        # the entry says. Decided in code so no list edit can flip it.
        $forcedReason = $null
        foreach ($declared in $declaredPaths) {
            $expanded = $null
            try { $expanded = [System.Environment]::ExpandEnvironmentVariables($declared) } catch { $expanded = $null }
            if ([string]::IsNullOrWhiteSpace($expanded)) { continue }

            foreach ($forced in $forcedInventory) {
                $forcedPath = [string](Get-OptimizerProperty -InputObject $forced -Name 'Path')
                if ([string]::IsNullOrWhiteSpace($forcedPath)) { continue }
                if ((Test-JunkPathWithin -Path $expanded -Container $forcedPath) -or
                    (Test-JunkPathWithin -Path $forcedPath -Container $expanded)) {
                    $inventoryOnly = $true
                    $forcedReason  = [string](Get-OptimizerProperty -InputObject $forced -Name 'Reason')
                    break
                }
            }
            if ($null -ne $forcedReason) { break }
        }

        $inventoryReason = $forcedReason
        if ($inventoryOnly -and [string]::IsNullOrWhiteSpace($inventoryReason)) {
            $inventoryReason = 'This location is reported for size only. The curated list marks it as never offered for removal.'
        }

        [pscustomobject]@{
            PSTypeName          = $script:JunkEntryTypeName
            Id                  = $id
            DisplayName         = [string](Get-OptimizerProperty -InputObject $entry -Name 'displayName')
            Owner               = [string](Get-OptimizerProperty -InputObject $entry -Name 'owner')
            Reason              = [string](Get-OptimizerProperty -InputObject $entry -Name 'reason')
            Provenance          = $provenance
            Resolver            = $resolver
            InventoryOnly       = [bool] $inventoryOnly
            InventoryOnlyReason = $inventoryReason
            IsForcedInventory   = ($null -ne $forcedReason)
            MinimumAgeDays      = $minimumAge
            Path                = [string[]] $declaredPaths
            ProfileChildPath    = [string[]] $profileChildPaths
            Note                = [string](Get-OptimizerProperty -InputObject $entry -Name 'note')
        }
    }
}

#endregion

#region Internal: resolution

function Resolve-JunkLocationPath {
    <#
        Turns one curated entry into the list of real directories to walk on this
        machine, plus a note about anything that did not resolve.

        Three shapes:

          * a plain path, environment variables expanded;
          * a path plus profileChildPath, which expands to <base>\<profile>\<child>
            for every immediate subdirectory of the base that actually has that
            child. Enumerating the profile folders is why this is not a
            hard-coded 'Default': Chrome has three profiles on this machine and
            hard-coding one would have missed 660 MiB of the 1.3 GiB in its cache
            WITHOUT SAYING SO, which is the failure mode this project is built
            against. The child path itself is still named precisely -- the
            enumeration finds profiles, never cache folders;
          * the recycleBin resolver, which is <fixed drive>\$Recycle.Bin\<SID>.

        Every resolved path is re-checked against the protected list. The load-time
        check catches a bad list; this catches a machine whose %TEMP% has been
        redirected somewhere it must not follow.

        RETURNS Path AND Profile AS PARALLEL ARRAYS, same length, same order.
        Profile is the profile folder's own name for a path that came out of the
        profileChildPath expansion, and the empty string for every other shape.
        It is captured HERE because here is the only place that knows it: by the
        time a caller has '<base>\Profile 1\Cache\Cache_Data' the only way back to
        'Profile 1' is to re-expand the environment variable and count segments,
        and re-deriving machine state in the pure half of the detector is exactly
        what Find-JunkFileLocation is written not to do. See Q14.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Entry,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ProtectedPath
    )

    $paths    = New-Object System.Collections.Generic.List[string]
    $profiles = New-Object System.Collections.Generic.List[string]
    $notes    = New-Object System.Collections.Generic.List[string]
    $refused  = $false

    $resolver = [string](Get-OptimizerProperty -InputObject $Entry -Name 'Resolver' -Default $script:JunkResolverPath)

    # Candidate paths and the profile each one belongs to, kept side by side so
    # the protected-path filter below drops both halves together.
    $candidates       = New-Object System.Collections.Generic.List[string]
    $candidateProfile = New-Object System.Collections.Generic.List[string]

    if ($resolver -eq $script:JunkResolverRecycleBin) {
        $sid = $null
        try { $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { $sid = $null }

        if ([string]::IsNullOrWhiteSpace($sid)) {
            $notes.Add('The current user SID could not be read, so the Recycle Bin folder could not be located.')
        }
        else {
            foreach ($root in @(Get-JunkFixedDriveRoot)) {
                $candidates.Add((Join-Path -Path (Join-Path -Path $root -ChildPath '$Recycle.Bin') -ChildPath $sid))
                $candidateProfile.Add('')
            }
            if ($candidates.Count -lt 1) {
                $notes.Add('No fixed drive was readable, so no Recycle Bin folder could be located.')
            }
        }
    }
    else {
        $childPaths = @(Get-OptimizerProperty -InputObject $Entry -Name 'ProfileChildPath' -Default @())

        foreach ($declared in @(Get-OptimizerProperty -InputObject $Entry -Name 'Path' -Default @())) {
            $expanded = $null
            try { $expanded = [System.Environment]::ExpandEnvironmentVariables([string] $declared) } catch { $expanded = $null }

            if ([string]::IsNullOrWhiteSpace($expanded) -or $expanded.Contains('%')) {
                $notes.Add("'$declared' does not resolve on this machine: an environment variable in it is not set.")
                continue
            }
            if (-not [System.IO.Path]::IsPathRooted($expanded)) {
                $notes.Add("'$declared' resolves to '$expanded', which is not an absolute path.")
                continue
            }

            if ($childPaths.Count -lt 1) {
                $candidates.Add($expanded)
                $candidateProfile.Add('')
                continue
            }

            # Profile expansion. Only the immediate subdirectories of the base are
            # enumerated, and only to test for the named child folder; nothing
            # else in the browser folder is read.
            #
            # The base is probed first, tri-state. A browser that is not installed
            # must resolve to "nothing to read, and that is the whole truth" --
            # NOT to a note, because a note makes the location Skipped and the
            # scan PARTIAL, and every machine without Firefox would then warn that
            # its scan was incomplete forever. That is the trap docs\STATE.md
            # records under the PARTIAL-forever design fork.
            $basePresent = Test-OptimizerPathPresent -Path $expanded -PathType Directory
            if ($basePresent -eq $false) { continue }
            if ($null -eq $basePresent) {
                $notes.Add("'$expanded' could not be reached at this privilege level, so its profile folders were not enumerated.")
                continue
            }

            $profileRoots = $null
            try { $profileRoots = [System.IO.Directory]::GetDirectories($expanded) }
            catch {
                $inner = Get-OptimizerInnerException -Exception $_.Exception
                $notes.Add("'$expanded' could not be listed to find profile folders: $($inner.Message)")
                continue
            }

            foreach ($profileRoot in $profileRoots) {
                # The profile folder's own name, taken here rather than parsed
                # back out of the joined path later. GetFileName is used rather
                # than a substring of $expanded so a base path that arrived with
                # or without a trailing separator gives the same answer.
                $profileName = ''
                try { $profileName = [string][System.IO.Path]::GetFileName($profileRoot.TrimEnd('\', '/')) } catch { $profileName = '' }

                foreach ($child in $childPaths) {
                    $candidate = Join-Path -Path $profileRoot -ChildPath ([string] $child)
                    if ((Test-OptimizerPathPresent -Path $candidate -PathType Directory) -eq $true) {
                        $candidates.Add($candidate)
                        $candidateProfile.Add($profileName)
                    }
                }
            }
        }
    }

    for ($index = 0; $index -lt $candidates.Count; $index++) {
        $candidate = $candidates[$index]
        $conflict = Get-JunkProtectedPathConflict -Path $candidate -ProtectedPath $ProtectedPath
        if ($null -ne $conflict) {
            $refused = $true
            $notes.Add("'$candidate' was NOT read: it collides with '$($conflict.Path)' -- $($conflict.Reason).")
            continue
        }
        $paths.Add($candidate)
        $profiles.Add($candidateProfile[$index])
    }

    [pscustomobject]@{
        Path      = [string[]] $paths.ToArray()
        Profile   = [string[]] $profiles.ToArray()
        Note      = [string[]] $notes.ToArray()
        IsRefused = $refused
    }
}

#endregion

#region Public: inventory

function Get-JunkLocationInventory {
    <#
    .SYNOPSIS
        Measures every curated junk location on this machine.

    .DESCRIPTION
        Returns one object carrying Locations (one record per curated location,
        whether or not it produced anything) and Sources (one status record per
        location). Read-only.

        The two halves are returned together on purpose. A caller that received
        only the locations with something in them could not tell "the Windows
        Update cache is empty" from "the Windows Update cache could not be read",
        and those mean opposite things.

        ELEVATION. Unlike the other three detectors, this one genuinely loses
        coverage without administrator rights: %SystemRoot%\Temp, Prefetch and
        parts of the Windows Error Reporting queues are simply not readable as a
        normal user. A location that cannot be read at this privilege level is a
        SKIPPED source naming it -- never Refused, which would mean "this project
        will never use this signal on any machine", and re-running as
        administrator would change this answer.

    .PARAMETER LocationEntry
        Curated entries to measure. Defaults to Get-JunkLocationList.

    .PARAMETER MinimumAgeDays
        Nothing modified inside this many days is eligible for removal. Default 7.

        A curated entry may declare a longer window of its own. Where it does, the
        window used for that location is the GREATER of the two, and the location
        record says which one it was (MinimumAgeDays on the record) so the evidence
        can name the window it actually measured against.

    .PARAMETER SkipInUseProbe
        Do not probe candidate files for open handles. The affected locations
        report themselves Skipped, and no file that was not probed can ever reach
        a Finding.

    .EXAMPLE
        $inventory = Get-JunkLocationInventory
        $inventory.Locations | Format-Table Id, Status, FileCount, TotalBytes, EligibleFileCount

    .OUTPUTS
        Win11Optimizer.JunkInventory
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()]
        [AllowNull()]
        [psobject[]] $LocationEntry,

        [Parameter()]
        [ValidateRange(0, 3650)]
        [int] $MinimumAgeDays = $script:JunkDefaultMinimumAgeDays,

        [Parameter()]
        [switch] $SkipInUseProbe
    )

    if ($null -eq $LocationEntry) { $LocationEntry = @(Get-JunkLocationList) }

    $locations = New-Object System.Collections.Generic.List[psobject]
    $sources   = New-Object System.Collections.Generic.List[psobject]
    $statistic = @{}

    # One set for the whole scan: a file counted under one location is never
    # counted again under another, so two locations that overlap cannot claim the
    # same bytes twice.
    $seenPath  = New-Object 'System.Collections.Generic.HashSet[string]'
    $protected = @(Get-JunkProtectedPath)

    # ONE clock reading for the whole scan. Every cutoff below is derived from it
    # rather than from a fresh [datetime]::UtcNow, so two locations measured
    # seconds apart are measured against the same instant and a file cannot land
    # on opposite sides of the window depending on where it sits in the list.
    $nowUtc    = [datetime]::UtcNow
    $cutoffUtc = $nowUtc.AddDays(-$MinimumAgeDays)

    $statistic['ProtectedPathCount']     = $protected.Count
    $statistic['CutoffUtc']              = $cutoffUtc
    $statistic['InUseProbeSeconds']      = [double] 0
    $statistic['InUseProbeCount']        = [long] 0
    $statistic['AgeWindowOverrideCount'] = [long] 0

    foreach ($entry in @($LocationEntry)) {
        $timer = [System.Diagnostics.Stopwatch]::StartNew()

        $id            = [string](Get-OptimizerProperty -InputObject $entry -Name 'Id')
        $displayName   = [string](Get-OptimizerProperty -InputObject $entry -Name 'DisplayName')
        $reason        = [string](Get-OptimizerProperty -InputObject $entry -Name 'Reason')
        $provenance    = [string](Get-OptimizerProperty -InputObject $entry -Name 'Provenance' -Default $script:JunkPublishedProvenance)
        $owner         = [string](Get-OptimizerProperty -InputObject $entry -Name 'Owner')
        $inventoryOnly = [bool](Get-OptimizerProperty -InputObject $entry -Name 'InventoryOnly' -Default $false)
        $inventoryWhy  = [string](Get-OptimizerProperty -InputObject $entry -Name 'InventoryOnlyReason')
        $declaredPath  = [string[]] @(Get-OptimizerProperty -InputObject $entry -Name 'Path' -Default @())

        # THE EFFECTIVE AGE WINDOW for this location: the GREATER of the scan's
        # window and the entry's own.
        #
        # Greater, not "the entry's if it has one". -MinimumAgeDays 90 is a caller
        # asking to be MORE conservative than the default, and an entry that then
        # computed at 30 would be less conservative than what was asked for --
        # this way round the override can only ever hold more back, never less.
        #
        # Not named $minimumAgeDays: PowerShell variable names are case-insensitive,
        # so that local WOULD BE the [int] $MinimumAgeDays parameter and every
        # location after the first would inherit the previous one's window.
        $entryAgeDays  = Get-OptimizerProperty -InputObject $entry -Name 'MinimumAgeDays'
        $effectiveDays = [int] $MinimumAgeDays
        if ($null -ne $entryAgeDays -and ([int] $entryAgeDays) -gt $effectiveDays) {
            $effectiveDays = [int] $entryAgeDays
            $statistic['AgeWindowOverrideCount'] = [long] $statistic['AgeWindowOverrideCount'] + 1
        }
        $entryCutoffUtc = $nowUtc.AddDays(-$effectiveDays)

        $common = @{
            Id                  = $id
            DisplayName         = $displayName
            Reason              = $reason
            Provenance          = $provenance
            Owner               = $owner
            InventoryOnly       = $inventoryOnly
            InventoryOnlyReason = $inventoryWhy
            MinimumAgeDays      = $effectiveDays
            DeclaredPath        = $declaredPath
        }

        $resolution = Resolve-JunkLocationPath -Entry $entry -ProtectedPath $protected
        $resolved   = @($resolution.Path)
        # Aligned with $resolved, one entry each, '' for anything that did not
        # come out of a profileChildPath expansion. Read by index below rather
        # than parsed back out of the path -- see Resolve-JunkLocationPath.
        $resolvedProfile = @($resolution.Profile)
        $detail     = $null
        if (@($resolution.Note).Count -gt 0) { $detail = ($resolution.Note -join ' ') }

        if ($resolved.Count -lt 1) {
            $timer.Stop()
            $seconds = [math]::Round($timer.Elapsed.TotalSeconds, 3)

            # Nothing to read. Two very different reasons, and they get different
            # statuses: a path this detector REFUSED to follow is a gap in what
            # was measured, while a path that simply does not exist on this
            # machine is a complete answer -- so the second must not spend the
            # incompleteness warning, or every machine without a Delivery
            # Optimization cache reports a partial scan forever.
            if ($resolution.IsRefused -or @($resolution.Note).Count -gt 0) {
                $why = "Location '$id' ($displayName) was not read. $detail"
                $sources.Add((New-JunkScanSource -Name $id -Status 'Skipped' -Reason $why -DurationSeconds $seconds))
                $locations.Add((New-JunkLocation @common -Status 'Skipped' -StatusReason $why -Exists $null -DurationSeconds $seconds -Detail $detail))
            }
            else {
                $sources.Add((New-JunkScanSource -Name $id -Status 'Succeeded' -ItemCount 0 -DurationSeconds $seconds))
                $locations.Add((New-JunkLocation @common -Status 'Succeeded' -Exists ([Nullable[bool]] $false) -IsAssessed $true -DurationSeconds $seconds `
                    -Detail 'This location does not exist on this machine.'))
            }
            continue
        }

        # Presence, tri-state. [System.IO.Directory]::Exists returns $false for a
        # folder the caller may not look at, so "not there" is only believed once
        # a parent has been listed successfully -- otherwise the location would be
        # reported as absent when it is merely locked down.
        $present   = $null
        $anyExists = $false
        $anyUnknown = $false
        foreach ($path in $resolved) {
            $probe = Test-OptimizerPathPresent -Path $path -PathType Directory
            if ($probe -eq $true) { $anyExists = $true }
            elseif ($null -eq $probe) { $anyUnknown = $true }
        }
        if ($anyExists) { $present = [Nullable[bool]] $true }
        elseif ($anyUnknown) { $present = $null }
        else { $present = [Nullable[bool]] $false }

        if ($present -eq $false) {
            $timer.Stop()
            $seconds = [math]::Round($timer.Elapsed.TotalSeconds, 3)
            $sources.Add((New-JunkScanSource -Name $id -Status 'Succeeded' -ItemCount 0 -DurationSeconds $seconds))
            $locations.Add((New-JunkLocation @common -Status 'Succeeded' -ResolvedPath $resolved -Exists ([Nullable[bool]] $false) -IsAssessed $true `
                -DurationSeconds $seconds -Detail 'This location does not exist on this machine.'))
            continue
        }

        if ($null -eq $present) {
            $timer.Stop()
            $seconds = [math]::Round($timer.Elapsed.TotalSeconds, 3)
            $why = "Location '$id' ($displayName) could not be reached at this privilege level, so whether it exists and what is in it are both unknown. Paths: $($resolved -join '; '). Re-running this scan as administrator would change this answer."
            $sources.Add((New-JunkScanSource -Name $id -Status 'Skipped' -Reason $why -DurationSeconds $seconds))
            $locations.Add((New-JunkLocation @common -Status 'Skipped' -StatusReason $why -ResolvedPath $resolved -Exists $null -DurationSeconds $seconds -Detail $detail))
            continue
        }

        # It is there. Walk it.
        $fileCount        = [long] 0
        $totalBytes       = [long] 0
        $ageHeldCount     = [long] 0
        $ageHeldBytes     = [long] 0
        $duplicateCount   = [long] 0
        $reparseCount     = [long] 0
        $unreadableCount  = [long] 0
        $reparseSample    = New-Object System.Collections.Generic.List[string]
        $unreadableSample = New-Object System.Collections.Generic.List[string]
        $candidates       = New-Object System.Collections.Generic.List[psobject]
        $walkFailure      = $null

        # Q14: the per-profile split, for a location whose paths came out of the
        # profileChildPath expansion. A browser is ONE row -- P4-C1 already has
        # 149 startup rows and one Finding per profile would multiply the junk
        # section by four -- so the split lives in the evidence instead, and this
        # is where the numbers for it are collected. Nothing is re-walked: the
        # per-path figures the walk already produces are added up per profile, and
        # each candidate file is tagged with the profile whose folder it was found
        # under so the eligible half can be attributed without a second pass.
        #
        # Ordered, so the evidence line comes out in profile-enumeration order
        # before it is sorted by size, and so a machine with no profile-expanded
        # location pays for an empty dictionary and nothing else.
        $profileTotals    = [ordered]@{}
        $candidateProfile = New-Object System.Collections.Generic.List[string]

        for ($pathIndex = 0; $pathIndex -lt $resolved.Count; $pathIndex++) {
            $path = $resolved[$pathIndex]
            $pathProfile = ''
            if ($pathIndex -lt $resolvedProfile.Count) { $pathProfile = [string] $resolvedProfile[$pathIndex] }

            if ((Test-OptimizerPathPresent -Path $path -PathType Directory) -ne $true) { continue }

            $content = $null
            try {
                $content = Get-JunkDirectoryContent -Path $path -CutoffUtc $entryCutoffUtc -SeenPath $seenPath -LocationId $id -CollectFiles:(-not $inventoryOnly)
            }
            catch {
                $inner = Get-OptimizerInnerException -Exception $_.Exception
                $walkFailure = "$($inner.GetType().Name): $($inner.Message)"
                continue
            }

            $fileCount      += $content.FileCount
            $totalBytes     += $content.TotalBytes
            $ageHeldCount   += $content.AgeHeldBackCount
            $ageHeldBytes   += $content.AgeHeldBackBytes
            $duplicateCount += $content.DuplicatePathCount
            $reparseCount   += $content.ReparsePointCount
            $unreadableCount += $content.UnreadableDirectoryCount

            foreach ($sample in $content.ReparsePointSample) {
                if ($reparseSample.Count -lt $script:JunkMaxReparseSample) { $reparseSample.Add($sample) }
            }
            foreach ($sample in $content.UnreadableDirectorySample) {
                if ($unreadableSample.Count -lt $script:JunkMaxUnreadableSample) { $unreadableSample.Add($sample) }
            }
            foreach ($candidate in $content.Candidate) {
                $candidates.Add($candidate)
                $candidateProfile.Add($pathProfile)
            }

            if (-not [string]::IsNullOrWhiteSpace($pathProfile)) {
                if (-not $profileTotals.Contains($pathProfile)) {
                    $profileTotals[$pathProfile] = [ordered]@{
                        FileCount         = [long] 0
                        TotalBytes        = [long] 0
                        EligibleFileCount = [long] 0
                        EligibleBytes     = [long] 0
                    }
                }
                $profileTotals[$pathProfile]['FileCount']  = [long] $profileTotals[$pathProfile]['FileCount'] + $content.FileCount
                $profileTotals[$pathProfile]['TotalBytes'] = [long] $profileTotals[$pathProfile]['TotalBytes'] + $content.TotalBytes
            }
        }

        if ($null -ne $walkFailure) {
            $timer.Stop()
            $seconds = [math]::Round($timer.Elapsed.TotalSeconds, 3)
            $why = "Location '$id' ($displayName) could not be measured: $walkFailure Anything in it is missing from this scan."
            $sources.Add((New-JunkScanSource -Name $id -Status 'Failed' -Reason $why -DurationSeconds $seconds))
            $locations.Add((New-JunkLocation @common -Status 'Failed' -StatusReason $why -ResolvedPath $resolved -Exists $present -DurationSeconds $seconds -Detail $detail))
            continue
        }

        # The in-use gate, over the files that passed the age gate. Skipped
        # entirely for an inventory-only location, which can never produce a
        # Finding and therefore never needs a file list.
        $inUseCount       = [long] 0
        $undeterminedCount = [long] 0
        $eligible         = New-Object System.Collections.Generic.List[psobject]
        $probeSkipped     = $false

        if (-not $inventoryOnly) {
            if ($SkipInUseProbe) {
                $probeSkipped = $true
            }
            else {
                $probeTimer = [System.Diagnostics.Stopwatch]::StartNew()
                for ($candidateIndex = 0; $candidateIndex -lt $candidates.Count; $candidateIndex++) {
                    $candidate = $candidates[$candidateIndex]
                    $verdict = Test-JunkFileInUse -Path $candidate.Path
                    if ($verdict -eq $script:JunkInUseFree) {
                        $eligible.Add($candidate)

                        # Attributed by the index the candidate was collected at,
                        # not by matching its path against the resolved list --
                        # the tag is exact and costs nothing, and a prefix test
                        # over 17,841 Chrome files times twelve cache folders is
                        # a measurable amount of nothing to be exact about.
                        $owner = $candidateProfile[$candidateIndex]
                        if (-not [string]::IsNullOrWhiteSpace($owner) -and $profileTotals.Contains($owner)) {
                            $profileTotals[$owner]['EligibleFileCount'] = [long] $profileTotals[$owner]['EligibleFileCount'] + 1
                            $profileTotals[$owner]['EligibleBytes']     = [long] $profileTotals[$owner]['EligibleBytes'] + [long] $candidate.SizeBytes
                        }
                    }
                    elseif ($verdict -eq $script:JunkInUseHeld) { $inUseCount++ }
                    else { $undeterminedCount++ }
                }
                $probeTimer.Stop()
                $statistic['InUseProbeSeconds'] = [double] $statistic['InUseProbeSeconds'] + $probeTimer.Elapsed.TotalSeconds
                $statistic['InUseProbeCount']   = [long] $statistic['InUseProbeCount'] + $candidates.Count
            }
        }

        $eligibleBytes = [long] 0
        foreach ($file in $eligible) { $eligibleBytes += $file.SizeBytes }

        # One record per profile, largest first. Largest first because the whole
        # point of the split is that one profile is usually most of the row, and
        # a reader who stops after the first name should have read the one that
        # matters. A profile that resolved and holds nothing eligible is still
        # listed, at the bottom, with its zero: "four profiles, three of them
        # empty" is the answer, and a silently absent profile is not.
        $profileBreakdown = New-Object System.Collections.Generic.List[psobject]
        foreach ($profileName in @($profileTotals.Keys)) {
            $bucket = $profileTotals[$profileName]
            $profileBreakdown.Add([pscustomobject]@{
                PSTypeName        = $script:JunkProfileTypeName
                Profile           = [string] $profileName
                FileCount         = [long] $bucket['FileCount']
                TotalBytes        = [long] $bucket['TotalBytes']
                EligibleFileCount = [long] $bucket['EligibleFileCount']
                EligibleBytes     = [long] $bucket['EligibleBytes']
            })
        }
        $sortedProfile = [psobject[]] @($profileBreakdown |
            Sort-Object -Property @{ Expression = 'EligibleBytes'; Descending = $true },
                                  @{ Expression = 'TotalBytes'; Descending = $true },
                                  @{ Expression = 'Profile'; Descending = $false })

        $isFloor = ($unreadableCount -gt 0)
        $timer.Stop()
        $seconds = [math]::Round($timer.Elapsed.TotalSeconds, 3)

        $status       = 'Succeeded'
        $statusReason = $null

        if ($isFloor) {
            # One example path, not the whole sample. This string is concatenated
            # into the scan result's IncompleteReason and into the PARTIAL warning
            # a user reads; ten paths from each of three locations makes that
            # unreadable. The full sample stays on the location record.
            $firstUnreadable = ''
            if ($unreadableSample.Count -gt 0) { $firstUnreadable = " For example: $($unreadableSample[0])." }

            $status = 'Skipped'
            $statusReason = "Location '$id' ($displayName): $unreadableCount folder$(if ($unreadableCount -eq 1) { '' } else { 's' }) under it could not be listed at this privilege level, so its reported size is a FLOOR and not a total. Re-running this scan as administrator would change this answer.$firstUnreadable"
        }
        elseif ($probeSkipped) {
            $status = 'Skipped'
            $statusReason = "Location '$id' ($displayName) was measured but its files were not checked for open handles, because the caller asked for the in-use probe to be skipped. Nothing here can become a Finding without that check."
        }

        if ($status -eq 'Succeeded') {
            $sources.Add((New-JunkScanSource -Name $id -Status 'Succeeded' -ItemCount ([int][math]::Min($fileCount, [int]::MaxValue)) -DurationSeconds $seconds))
        }
        else {
            $sources.Add((New-JunkScanSource -Name $id -Status $status -Reason $statusReason -ItemCount ([int][math]::Min($fileCount, [int]::MaxValue)) -DurationSeconds $seconds))
        }

        $locations.Add((New-JunkLocation @common `
            -ResolvedPath $resolved `
            -Status $status `
            -StatusReason $statusReason `
            -Exists $present `
            -IsAssessed (-not ($inventoryOnly -or $probeSkipped)) `
            -FileCount $fileCount `
            -TotalBytes $totalBytes `
            -IsSizeFloor $isFloor `
            -UnreadableDirectoryCount $unreadableCount `
            -UnreadableDirectorySample ([string[]] $unreadableSample.ToArray()) `
            -ReparsePointCount $reparseCount `
            -ReparsePointSample ([string[]] $reparseSample.ToArray()) `
            -DuplicatePathCount $duplicateCount `
            -AgeHeldBackCount $ageHeldCount `
            -AgeHeldBackBytes $ageHeldBytes `
            -InUseCount $inUseCount `
            -UndeterminedCount $undeterminedCount `
            -EligibleFileCount $eligible.Count `
            -EligibleBytes $eligibleBytes `
            -EligibleFile ([psobject[]] $eligible.ToArray()) `
            -ProfileBreakdown $sortedProfile `
            -DurationSeconds $seconds `
            -Detail $detail))
    }

    [pscustomobject]@{
        PSTypeName     = $script:JunkInventoryTypeName
        Locations      = [psobject[]] $locations.ToArray()
        Sources        = [psobject[]] $sources.ToArray()
        Statistic      = $statistic
        MinimumAgeDays = $MinimumAgeDays
        CutoffUtc      = $cutoffUtc
    }
}

#endregion

#region Public: the matcher

function Find-JunkFileLocation {
    <#
    .SYNOPSIS
        Turns measured junk locations into Findings -- one per location, never one
        per file.

    .DESCRIPTION
        The pure half of the detector: it reads location records and returns
        Findings, and touches no filesystem of its own. Everything it needs was
        measured by Get-JunkLocationInventory.

        A location becomes a Finding when ALL of these hold:

          * it is not inventory-only (the Recycle Bin, Prefetch and the
            servicing logs are reported with their sizes and never flagged);
          * it was assessed -- read, and its files checked for open handles;
          * at least one file passed every gate.

        Every Finding is Confidence 'Known' -- a curated location is a reviewed
        claim, and there is no heuristic tier here -- and RequiresConsent, so it
        surfaces as "Review needed". Unconditionally, no exceptions for
        "obviously safe" caches, exactly as every Service Finding does. The label
        itself is derived by the contract; nothing here re-derives it.

        THE ID IS THE LOCATION'S CURATED ID, not a path. RemovalMethod
        'FileDelete' therefore means "delete this set of files", and the set is on
        the Finding as EligibleFile.

    .PARAMETER Location
        Location records from Get-JunkLocationInventory.

    .PARAMETER MinimumAgeDays
        The SCAN-WIDE age window the locations were measured against; used to say
        so in the evidence, and as the fallback for a record that does not carry a
        window of its own.

        A location record measured by Get-JunkLocationInventory carries the window
        it was ACTUALLY measured against, which is the greater of this value and
        the curated entry own floor. That is the number the evidence quotes, and
        where the two differ the evidence says so in a line of its own.

    .EXAMPLE
        Find-JunkFileLocation -Location $inventory.Locations -MinimumAgeDays 7

    .OUTPUTS
        Win11Optimizer.Finding
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [psobject[]] $Location,

        [Parameter()]
        [ValidateRange(0, 3650)]
        [int] $MinimumAgeDays = $script:JunkDefaultMinimumAgeDays
    )

    if ($null -eq $Location) { return }

    foreach ($record in $Location) {
        if ($null -eq $record) { continue }

        if ([bool](Get-OptimizerProperty -InputObject $record -Name 'InventoryOnly' -Default $false)) { continue }
        if (-not [bool](Get-OptimizerProperty -InputObject $record -Name 'IsAssessed' -Default $false)) { continue }

        $eligibleCount = [long](Get-OptimizerProperty -InputObject $record -Name 'EligibleFileCount' -Default 0)
        if ($eligibleCount -lt 1) { continue }

        $id          = [string](Get-OptimizerProperty -InputObject $record -Name 'Id')
        $displayName = [string](Get-OptimizerProperty -InputObject $record -Name 'DisplayName')
        if ([string]::IsNullOrWhiteSpace($id) -or [string]::IsNullOrWhiteSpace($displayName)) { continue }

        $eligibleBytes = [long](Get-OptimizerProperty -InputObject $record -Name 'EligibleBytes' -Default 0)
        $fileCount     = [long](Get-OptimizerProperty -InputObject $record -Name 'FileCount' -Default 0)
        $totalBytes    = [long](Get-OptimizerProperty -InputObject $record -Name 'TotalBytes' -Default 0)
        $resolvedPath  = [string[]] @(Get-OptimizerProperty -InputObject $record -Name 'ResolvedPath' -Default @())

        # The window this location was ACTUALLY measured against, which is not
        # always the scan's: a curated entry may carry a floor of its own. A row
        # computed at 30 days whose evidence says 7 is a lie in the user's own
        # words, and the evidence being true is this project's whole pitch. A
        # record with no such field -- one built by hand, or read back from an
        # older run -- falls back to the scan's window, which is what it meant.
        $windowDays = [int](Get-OptimizerProperty -InputObject $record -Name 'MinimumAgeDays' -Default $MinimumAgeDays)
        if ($windowDays -lt 1) { $windowDays = $MinimumAgeDays }

        $evidence = New-Object System.Collections.Generic.List[string]

        # The headline line. Phrased as what is on disk, never as space that will
        # be freed: docs\PLAN.md fixes the run receipt as derived from what P3-C2
        # actually deleted, and a detector that promises a number becomes the
        # benchmark claim this project does not make.
        $evidence.Add(("{0}: {1} files, {2}, older than {3} days and not open in any process. The location holds {4} files and {5} in total." -f `
            $displayName,
            (Format-JunkCount -Count $eligibleCount),
            (Format-JunkSize -Bytes $eligibleBytes),
            $windowDays,
            (Format-JunkCount -Count $fileCount),
            (Format-JunkSize -Bytes $totalBytes)))

        if ($windowDays -ne $MinimumAgeDays) {
            $evidence.Add("Age window: this location was measured against its own $windowDays-day window rather than the $MinimumAgeDays days the rest of this scan used, because what is in it is worth keeping for longer.")
        }

        # Q14: the profile split, before the paths. A browser stays ONE row --
        # P4-C1 already has 149 startup rows and per-profile Findings would
        # multiply the junk section by the number of people who use the machine --
        # so the thing a bare "Brave web cache, 364.2 MiB" hides is said here
        # instead, in the same terms the headline uses. This is P3-C1a's per-row
        # split rule applied one level down: the total is not wrong, it is
        # unreadable, and the fix is to show what it is made of rather than to
        # break it into rows nobody can review.
        #
        # The list is already largest-first and already includes profiles holding
        # nothing eligible. Nothing here re-derives a profile name from a path --
        # see Resolve-JunkLocationPath.
        $profileBreakdown = @(Get-OptimizerProperty -InputObject $record -Name 'ProfileBreakdown' -Default @())
        if ($profileBreakdown.Count -gt 0) {
            $profileText = New-Object System.Collections.Generic.List[string]
            foreach ($profile in $profileBreakdown) {
                $profileText.Add(("{0} -- {1} files, {2}" -f `
                    [string](Get-OptimizerProperty -InputObject $profile -Name 'Profile' -Default '(unnamed)'),
                    (Format-JunkCount -Count ([long](Get-OptimizerProperty -InputObject $profile -Name 'EligibleFileCount' -Default 0))),
                    (Format-JunkSize -Bytes ([long](Get-OptimizerProperty -InputObject $profile -Name 'EligibleBytes' -Default 0)))))
            }
            if ($profileBreakdown.Count -eq 1) {
                # Said even when there is nothing to split, because "one profile"
                # and "we only looked at one profile" are different claims and
                # the reader cannot tell them apart from silence.
                $evidence.Add("Profiles: one browser profile, and this is all of it -- $($profileText[0]). Every profile folder was enumerated; there is no second one.")
            }
            else {
                $evidence.Add(("Profiles: the figure above is {0} separate browser profiles, largest first -- {1}. This row covers all of them together; a single profile cannot be selected on its own." -f `
                    (Format-JunkCount -Count $profileBreakdown.Count),
                    ($profileText -join '; ')))
            }
        }

        if ($resolvedPath.Count -gt 0) {
            $evidence.Add("Location: $($resolvedPath -join '; ')")
        }

        $reason = [string](Get-OptimizerProperty -InputObject $record -Name 'Reason')
        if (-not [string]::IsNullOrWhiteSpace($reason)) { $evidence.Add($reason) }

        # What was held back, and why. A gate that never says it fired is a gate
        # nobody can audit.
        $ageHeld     = [long](Get-OptimizerProperty -InputObject $record -Name 'AgeHeldBackCount' -Default 0)
        $ageBytes    = [long](Get-OptimizerProperty -InputObject $record -Name 'AgeHeldBackBytes' -Default 0)
        $inUse       = [long](Get-OptimizerProperty -InputObject $record -Name 'InUseCount' -Default 0)
        $undetermined = [long](Get-OptimizerProperty -InputObject $record -Name 'UndeterminedCount' -Default 0)
        $reparse     = [long](Get-OptimizerProperty -InputObject $record -Name 'ReparsePointCount' -Default 0)
        $duplicates  = [long](Get-OptimizerProperty -InputObject $record -Name 'DuplicatePathCount' -Default 0)

        $heldBack = New-Object System.Collections.Generic.List[string]
        if ($ageHeld -gt 0) { $heldBack.Add("$(Format-JunkCount -Count $ageHeld) modified in the last $windowDays days ($(Format-JunkSize -Bytes $ageBytes))") }
        if ($inUse -gt 0) { $heldBack.Add("$(Format-JunkCount -Count $inUse) open in another process") }
        if ($undetermined -gt 0) { $heldBack.Add("$(Format-JunkCount -Count $undetermined) that could not be checked, which counts as in use") }
        if ($reparse -gt 0) { $heldBack.Add("$(Format-JunkCount -Count $reparse) junction$(if ($reparse -eq 1) { '' } else { 's' }) or link$(if ($reparse -eq 1) { '' } else { 's' }), which this tool never follows") }
        if ($duplicates -gt 0) { $heldBack.Add("$(Format-JunkCount -Count $duplicates) already counted under another location") }

        if ($heldBack.Count -gt 0) {
            $evidence.Add("Held back: $($heldBack -join '; ').")
        }

        if ([bool](Get-OptimizerProperty -InputObject $record -Name 'IsSizeFloor' -Default $false)) {
            $unreadable = [long](Get-OptimizerProperty -InputObject $record -Name 'UnreadableDirectoryCount' -Default 0)
            $evidence.Add("The size above is a FLOOR, not a total: $(Format-JunkCount -Count $unreadable) folder$(if ($unreadable -eq 1) { '' } else { 's' }) inside this location could not be listed at this privilege level, so whatever is in them is not counted and not listed.")
        }

        if ([string]::Equals([string](Get-OptimizerProperty -InputObject $record -Name 'Provenance'), $script:JunkPublishedProvenance, [System.StringComparison]::OrdinalIgnoreCase)) {
            $evidence.Add($script:JunkPublishedEvidence)
        }

        $evidence.Add('This is what is on disk now, not a promise of space reclaimed. Each file is re-checked before anything is deleted.')

        $finding = New-Finding -Category $script:JunkCategory `
            -Id $id `
            -DisplayName $displayName `
            -Evidence ([string[]] $evidence.ToArray()) `
            -Confidence 'Known' `
            -RequiresConsent `
            -RemovalMethod $script:JunkRemovalMethod

        # Detector-specific fields go on the Finding after the fact, the way
        # OemBloatware.ps1 attaches WhitelistEntryId -- the Finding contract gains
        # nothing from a file list that means nothing to the other three
        # detectors. EligibleFile is the SET that RemovalMethod 'FileDelete'
        # refers to; P3-C1 deletes these paths, not the location.
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationId'        -Value $id
        $finding | Add-Member -MemberType NoteProperty -Name 'LocationPath'      -Value $resolvedPath
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFileCount' -Value $eligibleCount
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleBytes'     -Value $eligibleBytes
        $finding | Add-Member -MemberType NoteProperty -Name 'EligibleFile'      -Value ([psobject[]] @(Get-OptimizerProperty -InputObject $record -Name 'EligibleFile' -Default @()))
        $finding | Add-Member -MemberType NoteProperty -Name 'IsSizeFloor'       -Value ([bool](Get-OptimizerProperty -InputObject $record -Name 'IsSizeFloor' -Default $false))
        # Q14. The same split the evidence sentence states, as data, so P4-C1 can
        # render it without parsing English back out of a sentence. Empty for
        # every location that is not profile-expanded.
        $finding | Add-Member -MemberType NoteProperty -Name 'ProfileBreakdown'  -Value ([psobject[]] $profileBreakdown)
        # The window this row was measured against, not the scan's -- the same
        # number the evidence line above quotes, so a consumer reading the field
        # and a user reading the sentence never disagree.
        $finding | Add-Member -MemberType NoteProperty -Name 'MinimumAgeDays'    -Value $windowDays

        $finding
    }
}

#endregion

#region Public: scan

function Invoke-JunkFileScan {
    <#
    .SYNOPSIS
        Scans this machine for reclaimable junk files and disk caches.

    .DESCRIPTION
        Measures every curated location, returns one Finding per location that has
        something safely deletable in it, and hands back the FULL per-location
        inventory alongside them -- including the locations that produced no
        Finding, which is the number a user actually wants for the Recycle Bin.

        Read-only. Nothing is deleted, moved or written; -WhatIf and -Confirm are
        deliberately not implemented because there is no state change for them to
        guard. Deleting belongs to the dispatcher (chunk P3-C1), which ships
        dry-run only.

        WHAT THE COUNTS MEAN. TotalEligibleBytes is a PREVIEW of what is on disk
        right now, not a receipt and not a promise. The run receipt is derived
        from P3-C2's action log -- what was actually deleted -- and this number
        must never become that number.

        ELEVATION. This detector genuinely loses coverage without it. Un-elevated
        on the development machine, %SystemRoot%\Temp and Prefetch are unreadable
        outright and 296 folders under the Windows Error Reporting archive cannot
        be listed, so those locations report Skipped and the scan reports itself
        PARTIAL. That is the honest answer, not a broken scan.

    .PARAMETER LocationListPath
        Curated location list. Defaults to Data\junk-locations.json.

    .PARAMETER MinimumAgeDays
        Nothing modified inside this many days is eligible. Default 7 -- the
        window Windows' own Disk Cleanup applies to the temp folder.

        A curated location may declare a longer window of its own, in which case
        that location is measured against the greater of the two. Raising this
        value therefore always holds more back and never less; AgeWindowOverrideCount
        on the result says how many locations used a window of their own.

    .PARAMETER SkipInUseProbe
        Measure sizes but do not check files for open handles. Affected locations
        report Skipped and can produce no Findings.

    .EXAMPLE
        $scan = Invoke-JunkFileScan
        $scan.SummaryText
        $scan.Locations | Format-Table Id, Status, FileCount, TotalBytes, EligibleFileCount
        $scan.Findings | Format-Table DisplayName, EligibleFileCount, SafetyLabel

    .OUTPUTS
        Win11Optimizer.JunkScanResult
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $LocationListPath,

        [Parameter()]
        [ValidateRange(0, 3650)]
        [int] $MinimumAgeDays = $script:JunkDefaultMinimumAgeDays,

        [Parameter()]
        [switch] $SkipInUseProbe
    )

    $startedUtc = [datetime]::UtcNow
    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

    Write-OptimizerLog -EventName 'JunkScanStarted' -Message 'Junk-file scan started.'

    # The list loads first and a failure propagates. There is no second rule here
    # that could carry the scan on its own: with no list there are no locations,
    # and a junk detector that silently finds nothing looks exactly like a clean
    # disk.
    try {
        $listArguments = @{}
        if ($LocationListPath) { $listArguments['Path'] = $LocationListPath }
        $entries = @(Get-JunkLocationList @listArguments)
    }
    catch {
        Write-OptimizerLog -EventName 'JunkScanFailed' -Level 'Error' `
            -Message "Junk-location list could not be loaded: $($_.Exception.Message)"
        throw
    }

    Write-OptimizerLog -EventName 'JunkListLoaded' `
        -Message "Loaded $($entries.Count) curated junk locations."

    $isElevated = Test-IsElevated

    $inventoryArguments = @{
        LocationEntry  = $entries
        MinimumAgeDays = $MinimumAgeDays
    }
    if ($SkipInUseProbe) { $inventoryArguments['SkipInUseProbe'] = $true }

    $inventory = Get-JunkLocationInventory @inventoryArguments
    $locations = @($inventory.Locations)
    $sources   = @($inventory.Sources)

    foreach ($source in $sources) {
        $level = if ($script:ScanSourceIncompleteStatuses -contains $source.Status) { 'Warning' } else { 'Info' }
        Write-OptimizerLog -EventName 'JunkScanSource' -Level $level `
            -Message "Location $($source.Name): $($source.Status)." `
            -Data ([ordered]@{
                Location        = $source.Name
                Status          = $source.Status
                ItemCount       = $source.ItemCount
                DurationSeconds = $source.DurationSeconds
                Reason          = $source.Reason
            })
    }

    $findings = @(Find-JunkFileLocation -Location $locations -MinimumAgeDays $MinimumAgeDays |
        Sort-Object -Property @{ Expression = 'EligibleBytes'; Descending = $true }, 'DisplayName')

    $totalBytesSeen    = [long] 0
    $totalEligible     = [long] 0
    $totalEligibleFile = [long] 0
    $totalFiles        = [long] 0
    $reparseTotal      = [long] 0
    $inUseTotal        = [long] 0
    $undeterminedTotal = [long] 0
    $duplicateTotal    = [long] 0
    $floorCount        = 0

    foreach ($location in $locations) {
        $totalFiles        += [long] $location.FileCount
        $totalBytesSeen    += [long] $location.TotalBytes
        $totalEligible     += [long] $location.EligibleBytes
        $totalEligibleFile += [long] $location.EligibleFileCount
        $reparseTotal      += [long] $location.ReparsePointCount
        $inUseTotal        += [long] $location.InUseCount
        $undeterminedTotal += [long] $location.UndeterminedCount
        $duplicateTotal    += [long] $location.DuplicatePathCount
        if ($location.IsSizeFloor) { $floorCount++ }
    }

    $inventoryOnlyCount = @($locations | Where-Object { $_.InventoryOnly }).Count
    $absentCount        = @($locations | Where-Object { $_.Exists -is [bool] -and -not $_.Exists }).Count

    $totalTimer.Stop()

    $defaultListPath = Join-Path -Path $script:OptimizerDataRoot -ChildPath 'junk-locations.json'

    $result = New-ScanResult -Detector 'JunkFiles' -Category $script:JunkCategory `
        -StartedUtc $startedUtc `
        -DurationSeconds ([math]::Round($totalTimer.Elapsed.TotalSeconds, 3)) `
        -IsElevated $isElevated `
        -InventoryCount $locations.Count `
        -Source $sources `
        -Finding $findings `
        -ItemNoun 'junk locations' `
        -FindingNoun 'junk-file findings' `
        -ScanLabel 'Junk-file scan' `
        -TypeName $script:JunkScanResultTypeName `
        -AdditionalProperty ([ordered]@{
            LocationListPath     = $(if ($LocationListPath) { $LocationListPath } else { $defaultListPath })
            LocationListCount    = $entries.Count
            MinimumAgeDays       = $MinimumAgeDays
            CutoffUtc            = $inventory.CutoffUtc
            Locations            = [psobject[]] $locations
            TotalFileCount       = $totalFiles
            TotalBytesSeen       = $totalBytesSeen
            TotalEligibleFiles   = $totalEligibleFile
            TotalEligibleBytes   = $totalEligible
            SizeIsFloor          = ($floorCount -gt 0)
            FloorLocationCount   = $floorCount
            ReparsePointCount    = $reparseTotal
            InUseCount           = $inUseTotal
            UndeterminedCount    = $undeterminedTotal
            DuplicatePathCount   = $duplicateTotal
            InventoryOnlyCount   = $inventoryOnlyCount
            AbsentLocationCount  = $absentCount
            AgeWindowOverrideCount = [long] $inventory.Statistic['AgeWindowOverrideCount']
            ReadStatistic        = $inventory.Statistic
        })

    Write-OptimizerLog -EventName 'JunkScanCompleted' `
        -Level $(if ($result.IsComplete) { 'Info' } else { 'Warning' }) `
        -Message $result.SummaryText `
        -Data ([ordered]@{
            IsComplete         = $result.IsComplete
            IsElevated         = $isElevated
            LocationCount      = $locations.Count
            FindingCount       = @($result.Findings).Count
            TotalFileCount     = $totalFiles
            TotalBytesSeen     = $totalBytesSeen
            TotalEligibleBytes = $totalEligible
            SizeIsFloor        = ($floorCount -gt 0)
            ReparsePointCount  = $reparseTotal
            InUseCount         = $inUseTotal
            MinimumAgeDays     = $MinimumAgeDays
            DurationSeconds    = $result.DurationSeconds
        })

    $result
}

#endregion
