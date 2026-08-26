<#
    UnusedApps detector -- chunk P2-C3.

    Finds installed applications the user appears never or rarely to launch, and
    returns them as Findings with Confidence = Heuristic. ALWAYS Heuristic: nothing
    this file produces is ever Confidence = Known, no matter how clean a signal
    looks. P2-C1 owns 'Known'.

    THE RULE THIS FILE EXISTS TO OBEY
    ---------------------------------
    "I found no evidence this was used" and "this was not used" are different
    statements. Windows keeps no general last-run record: UserAssist only ever sees
    shell launches, prefetch needs elevation and can be off, and filesystem
    last-access times are either disabled or -- as measured on the development
    machine -- so saturated by background scanners that every file reads as touched
    yesterday. Conflating the two would flag every application on the machine.

    So every app lands in exactly one of three states:

      Used     positive evidence of a launch inside the window     -> no Finding
      Unused   a usable signal names this app AND says no launch   -> Finding
               inside the window
      Unknown  no usable signal names this app                     -> no Finding,
                                                                      but counted

    Unknown is a first-class outcome, not a default that quietly becomes Unused.
    On a machine where no signal is readable, EVERY app is Unknown, the scan
    reports itself incomplete, and the detector returns zero Findings. That is a
    correct result, and it must not look like a clean machine.

    This file DETECTS ONLY. It never uninstalls, deletes, disables or writes
    anything; every registry, prefetch and filesystem call in it is a read.
    Win32_Product / WMI is deliberately not used anywhere: it triggers an MSI
    reconfiguration pass across every other installed MSI application.

    Public surface (registered in the .psm1 export list and the .psd1 manifest):
      Get-UnusedAppExclusionList  load + validate the curated exclusion list
      Get-AppUsageClassification  pure: apps + signals + thresholds -> three states
      Find-UnusedApp              pure: classifications + exclusions -> Findings
      Invoke-UnusedAppScan        scan this machine -> scan result

    ASCII only -- see Detectors\README.md for what a UTF-8 em dash does to 5.1.
#>

# Thresholds. Both are parameters on the public functions; these are the documented
# defaults, in one place, so no magic number can hide in a second one.
$script:UnusedAppDefaultWindowDays     = 180
$script:UnusedAppDefaultMinimumAgeDays = 30

# The three states. Unknown is not a failure -- see the header.
$script:UnusedAppStateUsed    = 'Used'
$script:UnusedAppStateUnused  = 'Unused'
$script:UnusedAppStateUnknown = 'Unknown'

# Exclusion-list classes. A closed set, so a typo fails the load rather than
# quietly demoting an entry to a class with no meaning.
$script:UnusedAppExclusionClasses = @(
    'runtime'         # redistributables, frameworks, interpreters
    'driver'          # drivers and driver components
    'driver-utility'  # firmware/driver update and device-control utilities
    'security'        # antivirus, endpoint security, anti-cheat, VPN clients
    'os-component'    # shell, sign-in, settings, Store
    'background'      # services, agents, sync clients -- no UI to launch
)

# Same match fields and same dialect as the OEM whitelist (Shared\Inventory.ps1
# owns the primitives). One difference, deliberate and documented in
# Data\README.md: registryPublisher may stand alone here. On the whitelist,
# matching a whole vendor would be a safety claim about software the tool offers
# to delete; on the exclusion list it only ever means "never flag this", and
# over-matching costs a missed finding rather than a broken machine.
$script:UnusedAppMatchFields = @('appxPackageName', 'appxPackageFamilyName', 'registryDisplayName', 'registryPublisher')

# Usage-signal names, as they appear in the scan result's per-source list and in
# every Finding's Evidence.
$script:UnusedAppSignalUserAssist = 'UserAssist'
$script:UnusedAppSignalPrefetch   = 'Prefetch'
$script:UnusedAppSignalLastAccess = 'FileSystemLastAccess'

# How a signal record says which app it is about.
$script:UnusedAppMatchPackageFamilyName = 'PackageFamilyName'
$script:UnusedAppMatchExecutablePath    = 'ExecutablePath'
$script:UnusedAppMatchExecutableName    = 'ExecutableName'
$script:UnusedAppMatchDisplayName       = 'DisplayName'

$script:UnusedAppScanResultTypeName    = 'Win11Optimizer.UnusedAppScanResult'
$script:UnusedAppScanSourceTypeName    = 'Win11Optimizer.UnusedAppScanSource'
$script:UsageSignalTypeName            = 'Win11Optimizer.UsageSignal'
$script:UsageClassificationTypeName    = 'Win11Optimizer.AppUsageClassification'
$script:UnusedAppExclusionTypeName     = 'Win11Optimizer.UnusedAppExclusionEntry'

$script:UnusedAppPrefetchPath = Join-Path -Path ([Environment]::GetFolderPath('Windows')) -ChildPath 'Prefetch'

# UserAssist keeps its Count values ROT13-encoded, and every value that is not a
# path or an AppUserModelID is one of Explorer's own session counters. Those carry
# a run count in the same field but a nonsense FILETIME (this machine reports the
# year 1641), so they are dropped by name before anything is decoded.
$script:UnusedAppUserAssistRoot   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
$script:UnusedAppUserAssistPrefix = 'UEME_'

# UserAssist stores paths with the containing known folder replaced by its GUID.
# Only GUIDs in this table are resolvable; an entry under any other one is skipped
# rather than guessed at. Every GUID here was observed in the UserAssist hive of
# the development machine or is a documented KNOWNFOLDERID.
$script:UnusedAppKnownFolder = @{
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = 'System'          # System32
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' = 'SystemX86'
    '{6D809377-6AF0-444B-8957-A3773F02200E}' = 'ProgramFiles'
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = 'ProgramFilesX86'
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = 'Windows'
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' = 'Programs'        # per-user Start menu
    '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' = 'CommonPrograms'  # all-users Start menu
    '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}' = 'UserPinned'      # taskbar / Start pins
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}' = 'Desktop'
    '{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}' = 'PublicDesktop'
    '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' = 'LocalAppData'
    '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' = 'AppData'         # Roaming
    '{374DE290-123F-4565-9164-39C4925E467B}' = 'Downloads'
    '{FDD39AD0-238F-46AF-ADB4-6C85480369C7}' = 'Documents'
}

#region Internal: known-folder resolution

function Get-UnusedAppKnownFolderPath {
    # Resolves the small set of KNOWNFOLDERIDs UserAssist actually uses. Anything
    # not in the table returns null, and the caller drops the entry -- a guessed
    # path would join a usage record to the wrong application.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Guid
    )

    if (-not $script:UnusedAppKnownFolder.ContainsKey($Guid)) { return $null }
    $token = $script:UnusedAppKnownFolder[$Guid]

    try {
        switch ($token) {
            'System'          { return [Environment]::GetFolderPath('System') }
            'SystemX86'       { return [Environment]::GetFolderPath('SystemX86') }
            'ProgramFiles'    { return [Environment]::GetFolderPath('ProgramFiles') }
            'ProgramFilesX86' { return [Environment]::GetFolderPath('ProgramFilesX86') }
            'Windows'         { return [Environment]::GetFolderPath('Windows') }
            'Programs'        { return [Environment]::GetFolderPath('Programs') }
            'CommonPrograms'  { return [Environment]::GetFolderPath('CommonPrograms') }
            'Desktop'         { return [Environment]::GetFolderPath('DesktopDirectory') }
            'PublicDesktop'   { return [Environment]::GetFolderPath('CommonDesktopDirectory') }
            'LocalAppData'    { return [Environment]::GetFolderPath('LocalApplicationData') }
            'AppData'         { return [Environment]::GetFolderPath('ApplicationData') }
            'Downloads'       { return (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads') }
            'Documents'       { return [Environment]::GetFolderPath('MyDocuments') }
            'UserPinned'      {
                $appData = [Environment]::GetFolderPath('ApplicationData')
                if ([string]::IsNullOrWhiteSpace($appData)) { return $null }
                return (Join-Path $appData 'Microsoft\Internet Explorer\Quick Launch\User Pinned')
            }
        }
    }
    catch {
        Write-Verbose "Known folder '$token' could not be resolved: $($_.Exception.Message)"
        return $null
    }

    $null
}

function ConvertFrom-UnusedAppRot13 {
    # UserAssist value names are ROT13-encoded. Letters only; digits, braces,
    # separators and dots pass through untouched.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Value
    )

    $builder = New-Object System.Text.StringBuilder
    foreach ($character in $Value.ToCharArray()) {
        $code = [int] $character
        if ($code -ge 97 -and $code -le 122)   { $code = ((($code - 97) + 13) % 26) + 97 }
        elseif ($code -ge 65 -and $code -le 90) { $code = ((($code - 65) + 13) % 26) + 65 }
        $null = $builder.Append([char] $code)
    }
    $builder.ToString()
}

#endregion

function New-UnusedAppScanSource {
    # Thin wrapper over the shared New-ScanSource so every source this detector
    # reports carries the detector's own type tag as well as the shared one, and so
    # a Succeeded source ends up with Reason $null rather than an empty string.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('Succeeded', 'Skipped', 'Failed', 'Refused')] [string] $Status,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Reason,
        [Parameter()] [int] $ItemCount = 0,
        [Parameter()] [double] $DurationSeconds = 0
    )

    $arguments = @{
        AdditionalTypeName = $script:UnusedAppScanSourceTypeName
        Name               = $Name
        Status             = $Status
        ItemCount          = $ItemCount
        DurationSeconds    = $DurationSeconds
    }
    if (-not [string]::IsNullOrWhiteSpace($Reason)) { $arguments['Reason'] = $Reason }

    New-ScanSource @arguments
}

#region Internal: the usage-signal record

function New-UsageSignal {
    # One recorded last-use time plus the handle that says which app it is about.
    #
    # LastUsedUtc is deliberately allowed to be null, and a null one is dropped by
    # the readers before it ever reaches a classification: a UserAssist entry with
    # a zero FILETIME means "this app has an entry but Windows recorded no launch
    # time", which is exactly the absence-of-evidence case, not a launch at the
    # start of the epoch.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Signal,
        [Parameter(Mandatory)]
        [ValidateSet('PackageFamilyName', 'ExecutablePath', 'ExecutableName', 'DisplayName')]
        [string] $MatchType,
        [Parameter(Mandatory)] [string] $Value,
        [Parameter()] [AllowNull()] [Nullable[datetime]] $LastUsedUtc,
        [Parameter()] [AllowNull()] [string] $Detail
    )

    [pscustomobject]@{
        PSTypeName  = $script:UsageSignalTypeName
        Signal      = $Signal
        MatchType   = $MatchType
        Value       = $Value
        LastUsedUtc = $LastUsedUtc
        Detail      = $Detail
    }
}

#endregion

#region Internal: signal readers (all read-only)

function Get-UserAssistUsageSignal {
    <#
        Reads HKCU UserAssist and yields one usage signal per resolvable entry.

        What this signal can and cannot see, measured on the development machine
        2026-08-25: 258 values across 9 GUID subkeys, 248 once Explorer's own
        UEME_ session counters are dropped, 163 of those carrying a real timestamp,
        oldest 2025-12-03. It records SHELL launches only -- never a background
        service, never a command-line tool, never a game started from inside its
        own launcher.

        Three joins come out of it, in descending order of how much they are worth:

          AUMID           'Family_hash!AppId' -> PackageFamilyName. Exact, and the
                          only fully reliable join available. 25 of 146 installed
                          Appx packages had one; 18 carried a timestamp.
          Executable path a resolved {KNOWNFOLDERID}\...\x.exe, matched against an
                          app's InstallLocation.
          Shortcut name   the basename of a .lnk, matched against an uninstall
                          key's DisplayName, plus the shortcut's target path where
                          the .lnk still resolves. A name join is weaker than a
                          path join, so the shortcut it came from is named in the
                          Evidence for a human to check.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [ValidateNotNullOrEmpty()] [string] $Path = $script:UnusedAppUserAssistRoot
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "UserAssist key not found at '$Path'."
    }

    $shell = $null

    foreach ($guidKey in @(Get-ChildItem -LiteralPath $Path -ErrorAction Stop)) {
        $countPath = Join-Path -Path $guidKey.PSPath -ChildPath 'Count'
        if (-not (Test-Path -LiteralPath $countPath)) { continue }

        $countKey = Get-Item -LiteralPath $countPath -ErrorAction SilentlyContinue
        if ($null -eq $countKey) { continue }

        foreach ($valueName in @($countKey.GetValueNames())) {
            $blob = $countKey.GetValue($valueName)
            if ($blob -isnot [byte[]]) { continue }

            # Windows 7 and later write a 72-byte record; the last-executed
            # FILETIME lives at offset 60. A shorter blob is an older or unknown
            # layout and is skipped rather than read at a guessed offset.
            if ($blob.Length -lt 68) { continue }

            $decoded = ConvertFrom-UnusedAppRot13 -Value $valueName
            if ([string]::IsNullOrWhiteSpace($decoded)) { continue }
            if ($decoded.StartsWith($script:UnusedAppUserAssistPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }

            $lastUsed = $null
            try {
                $fileTime = [System.BitConverter]::ToInt64($blob, 60)
                if ($fileTime -gt 0) {
                    $candidate = [datetime]::FromFileTimeUtc($fileTime)
                    # Sanity band. Explorer writes nonsense here for some records;
                    # a launch dated 1641 or 2400 is not evidence of anything.
                    if ($candidate.Year -ge 2000 -and $candidate -le [datetime]::UtcNow.AddDays(1)) {
                        $lastUsed = [Nullable[datetime]] $candidate
                    }
                }
            }
            catch {
                Write-Verbose "Unreadable UserAssist timestamp for '$decoded': $($_.Exception.Message)"
                $lastUsed = $null
            }

            # No timestamp is no signal. Emitting it would turn "Windows kept no
            # launch time for this" into "this was never launched".
            if ($null -eq $lastUsed) { continue }

            # 1. AppUserModelID -> package family name.
            $bangIndex = $decoded.IndexOf('!')
            if ($bangIndex -gt 0) {
                $familyName = $decoded.Substring(0, $bangIndex)
                if ($familyName.Contains('_')) {
                    New-UsageSignal -Signal $script:UnusedAppSignalUserAssist `
                        -MatchType $script:UnusedAppMatchPackageFamilyName `
                        -Value $familyName `
                        -LastUsedUtc $lastUsed `
                        -Detail "AppUserModelID $decoded"
                }
                continue
            }

            $resolved = $null
            if ($decoded.StartsWith('{')) {
                $closing = $decoded.IndexOf('}')
                if ($closing -gt 0 -and $decoded.Length -gt ($closing + 2)) {
                    $folder = Get-UnusedAppKnownFolderPath -Guid $decoded.Substring(0, $closing + 1)
                    if (-not [string]::IsNullOrWhiteSpace($folder)) {
                        $resolved = $folder + $decoded.Substring($closing + 1)
                    }
                }
            }
            elseif ($decoded.Length -gt 3 -and $decoded[1] -eq ':' -and $decoded[2] -eq [char] 92) {
                $resolved = $decoded
            }

            # A bare AppID with no path and no '!' -- 'Chrome', 'Valve.Steam.Client',
            # 'com.nvidia.nvapp'. There is no defensible way to join those to an
            # uninstall key, so they are dropped: 150 of 248 on this machine. That
            # is a large part of why the Unknown count is what it is.
            if ([string]::IsNullOrWhiteSpace($resolved)) { continue }

            if ($resolved.EndsWith('.lnk', [System.StringComparison]::OrdinalIgnoreCase)) {
                $shortcutName = [System.IO.Path]::GetFileNameWithoutExtension($resolved)
                if (-not [string]::IsNullOrWhiteSpace($shortcutName)) {
                    New-UsageSignal -Signal $script:UnusedAppSignalUserAssist `
                        -MatchType $script:UnusedAppMatchDisplayName `
                        -Value $shortcutName `
                        -LastUsedUtc $lastUsed `
                        -Detail "Start-menu or taskbar shortcut '$shortcutName'"
                }

                # The shortcut's target is a much stronger join than its name, so
                # take it too where the .lnk is still on disk.
                $target = $null
                try {
                    if ([System.IO.File]::Exists($resolved)) {
                        if ($null -eq $shell) { $shell = New-Object -ComObject WScript.Shell }
                        $target = [string] $shell.CreateShortcut($resolved).TargetPath
                    }
                }
                catch {
                    Write-Verbose "Shortcut '$resolved' could not be resolved: $($_.Exception.Message)"
                    $target = $null
                }

                if (-not [string]::IsNullOrWhiteSpace($target)) {
                    New-UsageSignal -Signal $script:UnusedAppSignalUserAssist `
                        -MatchType $script:UnusedAppMatchExecutablePath `
                        -Value $target `
                        -LastUsedUtc $lastUsed `
                        -Detail "Shortcut '$shortcutName' targeting $target"
                }
                continue
            }

            if ($resolved.EndsWith('.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
                New-UsageSignal -Signal $script:UnusedAppSignalUserAssist `
                    -MatchType $script:UnusedAppMatchExecutablePath `
                    -Value $resolved `
                    -LastUsedUtc $lastUsed `
                    -Detail "Executable $resolved"
            }
        }
    }

    if ($null -ne $shell) {
        try { $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) } catch { }
        $shell = $null
    }
}

function Test-UnusedAppPrefetchAvailable {
    <#
        Answers "can this machine's prefetch folder be used as a signal", and if
        not, why not -- in words a user can act on.

        This probe exists because of a trap measured on the development machine:
        'Get-ChildItem C:\Windows\Prefetch -Filter *.pf -ErrorAction Stop' run
        un-elevated returns ZERO items and throws NOTHING. A detector built on it
        would report "no prefetch data" on a machine full of prefetch data, which
        is the exact "silently returned nothing" failure this project keeps
        hitting. [System.IO.Directory]::GetFiles throws UnauthorizedAccessException
        for the same folder, so the probe uses .NET directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [ValidateNotNullOrEmpty()] [string] $Path = $script:UnusedAppPrefetchPath
    )

    $enableValue = $null
    try {
        $parameters = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -ErrorAction Stop
        $enableValue = Get-OptimizerProperty -InputObject $parameters -Name 'EnablePrefetcher'
    }
    catch {
        $enableValue = $null
    }

    if ($null -ne $enableValue -and 0 -eq [int] $enableValue) {
        return [pscustomobject]@{
            Available = $false
            Reason    = "Prefetch is turned off on this machine (EnablePrefetcher = 0). Application launch times are not being recorded, so no app can be shown to be unused from this signal. Turn prefetching on (EnablePrefetcher = 3) if you want this scan to see launch history."
        }
    }

    if (-not [System.IO.Directory]::Exists($Path)) {
        return [pscustomobject]@{
            Available = $false
            Reason    = "The prefetch folder '$Path' does not exist, so there is no launch history to read."
        }
    }

    try {
        $null = [System.IO.Directory]::GetFiles($Path, '*.pf')
    }
    catch {
        # One catch, then look at what came out. A .NET method call raises a
        # MethodInvocationException wrapping the real exception, so a typed
        # 'catch [UnauthorizedAccessException]' is not something to rely on here.
        $exception = $_.Exception
        while ($null -ne $exception -and $exception -isnot [System.UnauthorizedAccessException] -and $null -ne $exception.InnerException) {
            $exception = $exception.InnerException
        }

        if ($exception -is [System.UnauthorizedAccessException]) {
            return [pscustomobject]@{
                Available = $false
                Reason    = "The prefetch folder '$Path' cannot be read without administrator rights. Re-run this scan as administrator to include application launch history; without it, apps that only this signal could speak for are reported as unknown rather than unused."
            }
        }

        return [pscustomobject]@{
            Available = $false
            Reason    = "The prefetch folder '$Path' could not be read: $($_.Exception.Message)"
        }
    }

    [pscustomobject]@{ Available = $true; Reason = $null }
}

function Get-PrefetchUsageSignal {
    <#
        Yields one usage signal per .pf file: the executable's name, and the .pf
        file's LastWriteTime as a last-run proxy. The binary format is deliberately
        not parsed -- the write time is what Windows updates on each run, and
        parsing an undocumented structure to get the same answer is not worth the
        risk of getting it wrong.

        A .pf gives an executable NAME, never a path, so the join is by name
        against the executables sitting in an app's InstallLocation. Names collide
        ('Update.exe', 'setup.exe', 'crashpad_handler.exe' all appear in several
        install folders on the development machine). A collision can only make an
        app look MORE recently used, because a classification takes the most recent
        matching signal -- so it fails towards "no Finding", which is the safe
        direction. The matched executable name is named in the Evidence so a human
        reviewing a Finding can see which one it was.

        Absence of a .pf is NOT evidence of non-use: Windows caps the folder at
        1024 entries and prunes the oldest.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [ValidateNotNullOrEmpty()] [string] $Path = $script:UnusedAppPrefetchPath
    )

    # .NET rather than Get-ChildItem: see Test-UnusedAppPrefetchAvailable.
    foreach ($file in [System.IO.Directory]::GetFiles($Path, '*.pf')) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($file)
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        # 'CHROME.EXE-A1B2C3D4' -> 'CHROME.EXE'
        $dashIndex = $name.LastIndexOf('-')
        if ($dashIndex -gt 0) { $name = $name.Substring(0, $dashIndex) }
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $lastUsed = $null
        try { $lastUsed = [Nullable[datetime]] ([System.IO.File]::GetLastWriteTimeUtc($file)) }
        catch { continue }

        # PowerShell unwraps a Nullable[datetime] to a plain datetime, so this
        # reads .Year directly rather than through .Value.
        if ($null -eq $lastUsed -or ([datetime]$lastUsed).Year -lt 2000) { continue }

        New-UsageSignal -Signal $script:UnusedAppSignalPrefetch `
            -MatchType $script:UnusedAppMatchExecutableName `
            -Value $name `
            -LastUsedUtc $lastUsed `
            -Detail "Prefetch record $([System.IO.Path]::GetFileName($file))"
    }
}

function Get-UnusedAppLastAccessStatus {
    <#
        Filesystem LastAccessTime is NOT used as a usage signal, and this function
        exists to say so with the machine's actual setting in the reason rather
        than leaving the signal out in silence.

        Measured on the development machine 2026-08-25:
          * fsutil reports "DisableLastAccess = 2 (System Managed, Last Access Time
            Updates ENABLED)", and a controlled probe confirmed a read does update
            the timestamp -- so the signal is live, contrary to the usual advice
            that Windows disables it;
          * and it is still worthless. All 67 install locations with a readable
            InstallLocation came back with a last-access age under 1.2 days, the
            oldest of them software last written to 542 days ago. A background
            reader (a scheduled antimalware scan, the search indexer, a backup
            agent) touches every file, so the signal is saturated: everything reads
            as used yesterday.

        Both ways it fails are disqualifying. Saturated, it says "used" about
        everything and can never produce a Finding. Disabled -- the pre-1803
        default, and what NtfsDisableLastAccessUpdate = 1 still means -- a stale
        timestamp equal to the install date reads as "never used" for every
        application on the machine, which is the failure this chunk exists to
        avoid.
    #>
    [CmdletBinding()]
    param()

    $setting = $null
    try {
        $fileSystem = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -ErrorAction Stop
        $setting = Get-OptimizerProperty -InputObject $fileSystem -Name 'NtfsDisableLastAccessUpdate'
    }
    catch {
        $setting = $null
    }

    $settingText = if ($null -eq $setting) { 'not set' } else { "NtfsDisableLastAccessUpdate = $setting" }

    [pscustomobject]@{
        Available = $false
        Reason    = "Not used as a usage signal, by measurement rather than by assumption ($settingText). Where last-access updates are ON, a background reader -- a scheduled antimalware scan, the search indexer, a backup agent -- touches every file, and every install location reads as accessed within a day; the signal is saturated and says nothing about the user. Where they are OFF, which is the Windows default on older builds, a stale timestamp equal to the install date would read as 'never used' for every application on the machine. Neither state can honestly support an unused verdict."
    }
}

#endregion

#region Public: the exclusion list

function Get-UnusedAppExclusionList {
    <#
    .SYNOPSIS
        Loads and validates the curated unused-app exclusion list.

    .DESCRIPTION
        Reads Data\unused-app-exclusions.json and returns one normalized entry per
        exclusion, with every field guaranteed present.

        The list is data, not code, and it is the reason this detector is usable at
        all: runtimes, drivers, driver/firmware-update utilities, security and
        anti-cheat software, OS and shell components and background services are
        never launched by a user, so any usage heuristic reads all of them as
        unused. Flagging a Visual C++ redistributable as "you never open this" is
        the exact failure that discredits tools in this category.

        Every rule is enforced here and violations throw -- the same treatment
        Get-KnownBloatwareList gets, for the same reason: a list that fails to load
        yields zero exclusions, which looks like a machine with nothing to exclude
        and would let the detector flag every runtime on it.

    .PARAMETER Path
        Exclusion file to load. Defaults to Data\unused-app-exclusions.json next to
        the module.

    .EXAMPLE
        Get-UnusedAppExclusionList | Select-Object Id, Class, Reason
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if (-not $Path) {
        $Path = Join-Path -Path $script:OptimizerDataRoot -ChildPath 'unused-app-exclusions.json'
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Unused-app exclusion list not found at '$Path'. The UnusedApps detector will not run without it -- with no exclusions it would flag every runtime, driver and background service on the machine."
    }

    $raw = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Unused-app exclusion list '$Path' is empty."
    }

    try {
        $document = ConvertFrom-Json -InputObject $raw
    }
    catch {
        throw "Unused-app exclusion list '$Path' is not valid JSON: $($_.Exception.Message)"
    }

    # Read the property directly rather than through Get-OptimizerProperty: an empty
    # JSON array would unroll to nothing on the way out of a function and be
    # indistinguishable from a missing 'entries' key.
    $entriesProperty = $document.PSObject.Properties['entries']
    if ($null -eq $entriesProperty -or $null -eq $entriesProperty.Value) {
        throw "Unused-app exclusion list '$Path' has no 'entries' array."
    }

    $entries = @($entriesProperty.Value)
    if ($entries.Count -lt 1) {
        throw "Unused-app exclusion list '$Path' contains no entries."
    }

    $seenIds = @{}
    $index = -1

    foreach ($entry in $entries) {
        $index++
        $id = [string](Get-OptimizerProperty -InputObject $entry -Name 'id')
        $where = if ([string]::IsNullOrWhiteSpace($id)) { "entry #$index" } else { "entry '$id'" }

        foreach ($required in 'id', 'displayName', 'class', 'reason') {
            $value = [string](Get-OptimizerProperty -InputObject $entry -Name $required)
            if ([string]::IsNullOrWhiteSpace($value)) {
                throw "Unused-app exclusion list '$Path': $where is missing a non-empty '$required'. Every entry has to say what it covers and why software of that kind can never be judged by a usage heuristic."
            }
        }

        if ($seenIds.ContainsKey($id.ToLowerInvariant())) {
            throw "Unused-app exclusion list '$Path': duplicate entry id '$id'."
        }
        $seenIds[$id.ToLowerInvariant()] = $true

        $class = [string](Get-OptimizerProperty -InputObject $entry -Name 'class')
        if ($script:UnusedAppExclusionClasses -notcontains $class) {
            throw "Unused-app exclusion list '$Path': $where declares unknown 'class' '$class'. Allowed: $($script:UnusedAppExclusionClasses -join ', ')."
        }

        $match = Get-OptimizerProperty -InputObject $entry -Name 'match'
        if ($null -eq $match) {
            throw "Unused-app exclusion list '$Path': $where has no 'match' block."
        }

        $rules = @{}
        foreach ($field in $script:UnusedAppMatchFields) { $rules[$field] = @() }

        # Enumerated one property at a time rather than as $match.PSObject.Properties.Name:
        # under Set-StrictMode -Version Latest, member enumeration of .Name over an
        # EMPTY property collection throws "the property 'Name' cannot be found",
        # so an entry declaring "match": {} would fail with a parser-level message
        # instead of the one that says what is actually wrong.
        $declaredFields = @($match.PSObject.Properties | ForEach-Object { $_.Name })

        foreach ($field in $declaredFields) {
            if ($script:UnusedAppMatchFields -notcontains $field) {
                throw "Unused-app exclusion list '$Path': $where declares unknown match field '$field'. Allowed: $($script:UnusedAppMatchFields -join ', ')."
            }

            $patterns = @(@(Get-OptimizerProperty -InputObject $match -Name $field -Default @()) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ })

            if ($patterns.Count -lt 1) {
                throw "Unused-app exclusion list '$Path': $where declares match field '$field' with no patterns."
            }

            foreach ($pattern in $patterns) {
                Assert-OptimizerPattern -Pattern $pattern -Context "Unused-app exclusion list '$Path', $where, field '$field'"
            }

            $rules[$field] = $patterns
        }

        $ruleCount = 0
        foreach ($field in $script:UnusedAppMatchFields) { $ruleCount += $rules[$field].Count }
        if ($ruleCount -lt 1) {
            throw "Unused-app exclusion list '$Path': $where has an empty 'match' block."
        }

        [pscustomobject]@{
            PSTypeName            = $script:UnusedAppExclusionTypeName
            Id                    = $id
            DisplayName           = [string](Get-OptimizerProperty -InputObject $entry -Name 'displayName')
            Class                 = $class
            Reason                = [string](Get-OptimizerProperty -InputObject $entry -Name 'reason')
            Note                  = [string](Get-OptimizerProperty -InputObject $entry -Name 'note')
            AppxPackageName       = [string[]] $rules['appxPackageName']
            AppxPackageFamilyName = [string[]] $rules['appxPackageFamilyName']
            RegistryDisplayName   = [string[]] $rules['registryDisplayName']
            RegistryPublisher     = [string[]] $rules['registryPublisher']
        }
    }
}

function Get-UnusedAppExclusionMatch {
    # This detector's name for the shared matcher. The body moved to
    # Shared\Inventory.ps1 as Get-OptimizerExclusionMatch when chunk P2-C2 became
    # its second caller (it matches services against the same list); the name stays
    # here so P2-C3's call sites read the way they always did. Unlike the OEM
    # whitelist, registryPublisher stands alone on an exclusion list -- see the note
    # on $script:UnusedAppMatchFields.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $InstalledApp,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [psobject[]] $ExclusionEntry
    )

    Get-OptimizerExclusionMatch -InstalledApp $InstalledApp -ExclusionEntry $ExclusionEntry
}

#endregion

#region Public: the three-state classifier

function Get-AppUsageClassification {
    <#
    .SYNOPSIS
        Classifies each installed app as Used, Unused or Unknown against a supplied
        set of usage signals.

    .DESCRIPTION
        The pure half of the detector: no machine access, no elevation, no I/O, so
        the three states can be tested against fabricated input rather than against
        whatever happens to be installed on the test machine.

        The three states, and why the third one exists:

          Used     a signal names this app and records a launch no more than
                   -UnusedWindowDays ago.
          Unused   a signal names this app and the most recent launch it records is
                   older than -UnusedWindowDays. POSITIVE evidence of absence.
          Unknown  no signal names this app at all, or the only signals that do
                   carry no launch time. ABSENCE of evidence. Never a Finding.

        No app is ever classified Unused because nothing was found about it. On a
        machine where no signal is readable, every app comes back Unknown.

        Signal disagreement is resolved by taking the MOST RECENT launch any
        matching signal records, and the disagreement is kept on the record so it
        reaches the Finding's Evidence. Taking the most recent is the safe
        direction: it can only move an app towards Used and away from a Finding.

        The minimum-age rule is the second guard. A UserAssist entry outlives the
        software it describes, so an app uninstalled and reinstalled last week can
        still carry a launch time from last year -- which would otherwise read as
        "not used in 180 days" the day after it was installed. An app whose
        recorded install date is younger than -MinimumAgeDays is therefore
        classified Unknown, not Unused: it has no signal that can be trusted about
        THIS install.

    .PARAMETER InstalledApp
        Inventory records, as returned by Get-RegistryInstalledApp or built by the
        Appx source. Missing properties are tolerated.

    .PARAMETER UsageSignal
        Usage signals to match against. An empty set is legal and yields all
        Unknown -- that is the "no signal on this machine" case.

    .PARAMETER UnusedWindowDays
        An app with no recorded launch inside this many days is a candidate.
        Default 180.

    .PARAMETER MinimumAgeDays
        An app installed more recently than this is new, not unused, and is
        classified Unknown however old its signals are. Default 30.

    .PARAMETER ReferenceUtc
        The "now" the ages are measured from. Defaults to the current UTC time;
        the tests pin it so a fixture does not age.

    .EXAMPLE
        Get-AppUsageClassification -InstalledApp $apps -UsageSignal $signals | Group-Object State
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [psobject[]] $InstalledApp,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [psobject[]] $UsageSignal,

        [Parameter()]
        [ValidateRange(1, 36500)]
        [int] $UnusedWindowDays = $script:UnusedAppDefaultWindowDays,

        [Parameter()]
        [ValidateRange(0, 36500)]
        [int] $MinimumAgeDays = $script:UnusedAppDefaultMinimumAgeDays,

        [Parameter()]
        [datetime] $ReferenceUtc = [datetime]::UtcNow
    )

    $signals = @($UsageSignal | Where-Object { $null -ne $_ -and $null -ne (Get-OptimizerProperty -InputObject $_ -Name 'LastUsedUtc') })

    foreach ($app in @($InstalledApp)) {
        if ($null -eq $app) { continue }

        $displayName = [string](Get-OptimizerProperty -InputObject $app -Name 'DisplayName')
        $name        = [string](Get-OptimizerProperty -InputObject $app -Name 'Name')
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $name }

        $familyName      = [string](Get-OptimizerProperty -InputObject $app -Name 'PackageFamilyName')
        $installLocation = [string](Get-OptimizerProperty -InputObject $app -Name 'InstallLocation')
        $executableNames = @([string[]](Get-OptimizerProperty -InputObject $app -Name 'ExecutableName' -Default @()))
        $installDate     = Get-OptimizerProperty -InputObject $app -Name 'InstallDate'

        $locationPrefix = $null
        if (-not [string]::IsNullOrWhiteSpace($installLocation)) {
            $locationPrefix = $installLocation.TrimEnd([char] 92) + [char] 92
        }

        # Deliberately not $matches: that is an automatic variable.
        $matched = New-Object System.Collections.Generic.List[psobject]

        foreach ($signal in $signals) {
            $matchType = [string](Get-OptimizerProperty -InputObject $signal -Name 'MatchType')
            $value     = [string](Get-OptimizerProperty -InputObject $signal -Name 'Value')
            if ([string]::IsNullOrWhiteSpace($value)) { continue }

            $hit = $false
            switch ($matchType) {
                $script:UnusedAppMatchPackageFamilyName {
                    $hit = (-not [string]::IsNullOrWhiteSpace($familyName)) -and
                           [string]::Equals($familyName, $value, [System.StringComparison]::OrdinalIgnoreCase)
                }
                $script:UnusedAppMatchExecutablePath {
                    $hit = (-not [string]::IsNullOrWhiteSpace($locationPrefix)) -and
                           $value.StartsWith($locationPrefix, [System.StringComparison]::OrdinalIgnoreCase)
                }
                $script:UnusedAppMatchExecutableName {
                    foreach ($executable in $executableNames) {
                        if ([string]::IsNullOrWhiteSpace($executable)) { continue }
                        if ([string]::Equals($executable, $value, [System.StringComparison]::OrdinalIgnoreCase)) { $hit = $true; break }
                    }
                }
                $script:UnusedAppMatchDisplayName {
                    $hit = (-not [string]::IsNullOrWhiteSpace($displayName)) -and
                           [string]::Equals($displayName, $value, [System.StringComparison]::OrdinalIgnoreCase)
                }
                default { $hit = $false }
            }

            if ($hit) { $matched.Add($signal) }
        }

        $installAgeDays = $null
        if ($installDate -is [datetime]) {
            $installAgeDays = [math]::Round(($ReferenceUtc - $installDate).TotalDays, 1)
        }

        $state    = $script:UnusedAppStateUnknown
        $reason   = $null
        $lastUsed = $null
        $ageDays  = $null

        if ($matched.Count -lt 1) {
            $reason = 'No usage signal on this machine names this application. That is absence of evidence, not evidence of absence -- it is never reported as unused.'
        }
        else {
            $best = $null
            foreach ($candidate in $matched) {
                $candidateTime = Get-OptimizerProperty -InputObject $candidate -Name 'LastUsedUtc'
                if ($null -eq $best -or $candidateTime -gt (Get-OptimizerProperty -InputObject $best -Name 'LastUsedUtc')) {
                    $best = $candidate
                }
            }

            $lastUsed = [datetime](Get-OptimizerProperty -InputObject $best -Name 'LastUsedUtc')
            $ageDays  = [math]::Round(($ReferenceUtc - $lastUsed).TotalDays, 1)

            if ($ageDays -le $UnusedWindowDays) {
                $state  = $script:UnusedAppStateUsed
                $reason = "Launched $ageDays days ago, inside the $UnusedWindowDays-day window."
            }
            elseif ($null -ne $installAgeDays -and $installAgeDays -lt $MinimumAgeDays) {
                # The signal is older than the install it supposedly describes, so
                # it is about a previous install of the same software.
                $state  = $script:UnusedAppStateUnknown
                $reason = "Installed $installAgeDays days ago, under the $MinimumAgeDays-day minimum age. The launch record found for it is $ageDays days old and therefore predates this install, so it says nothing about it. Reported as unknown, not unused."
            }
            else {
                $state  = $script:UnusedAppStateUnused
                $reason = "No launch recorded in the last $UnusedWindowDays days; the most recent one is $ageDays days old."
            }
        }

        $signalNames = @($matched | ForEach-Object { [string](Get-OptimizerProperty -InputObject $_ -Name 'Signal') } | Select-Object -Unique)
        $details = @($matched | ForEach-Object {
            $signalName = [string](Get-OptimizerProperty -InputObject $_ -Name 'Signal')
            $detail     = [string](Get-OptimizerProperty -InputObject $_ -Name 'Detail')
            $when       = Get-OptimizerProperty -InputObject $_ -Name 'LastUsedUtc'
            $stamp      = if ($null -eq $when) { 'no recorded time' } else { ([datetime]$when).ToString('yyyy-MM-dd') }
            "$signalName recorded $stamp ($detail)"
        })

        [pscustomobject]@{
            PSTypeName       = $script:UsageClassificationTypeName
            App              = $app
            DisplayName      = $displayName
            Source           = [string](Get-OptimizerProperty -InputObject $app -Name 'Source')
            State            = $state
            Reason           = $reason
            LastUsedUtc      = $lastUsed
            LastUsedAgeDays  = $ageDays
            InstallDate      = $(if ($installDate -is [datetime]) { $installDate } else { $null })
            InstallAgeDays   = $installAgeDays
            MatchedSignals   = [string[]] $signalNames
            SignalDetail     = [string[]] $details
            UnusedWindowDays = $UnusedWindowDays
            MinimumAgeDays   = $MinimumAgeDays
        }
    }
}

#endregion

#region Public: the matcher

function Find-UnusedApp {
    <#
    .SYNOPSIS
        Turns Unused classifications into Findings, minus anything the exclusion
        list covers.

    .DESCRIPTION
        The second pure half of the detector. Only classifications whose State is
        'Unused' can become a Finding -- 'Unknown' never does, which is the whole
        point of the three states -- and an app matching the curated exclusion list
        never does either, regardless of what its signals say.

        Every Finding is Confidence 'Heuristic', so its SafetyLabel is always
        "Review needed". It never sets RequiresConsent: a heuristic finding already
        requires review, and consent is a second axis for curated-but-sensitive
        matches (P2-C1a), not a synonym for uncertainty.

        Each Finding's Evidence names the signal that produced the judgement, what
        it said, the install date where one is recorded, and BOTH threshold values
        as the actual numbers used -- a user reading "not used in 180 days (last
        launch 2026-02-19, 187 days ago, via UserAssist)" can judge it; "appears
        unused" is not evidence.

        Overlap with P2-C1 is expected and left alone: an app can be both known
        bloatware and unused, and grouping the two Findings is P4-C1's job.

    .PARAMETER Classification
        Records from Get-AppUsageClassification.

    .PARAMETER ExclusionEntry
        Entries from Get-UnusedAppExclusionList.

    .EXAMPLE
        Find-UnusedApp -Classification $classifications -ExclusionEntry (Get-UnusedAppExclusionList)
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [psobject[]] $Classification,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject[]] $ExclusionEntry
    )

    $emitted = @{}

    foreach ($record in @($Classification)) {
        if ($null -eq $record) { continue }

        $state = [string](Get-OptimizerProperty -InputObject $record -Name 'State')
        if ($state -ne $script:UnusedAppStateUnused) { continue }

        $app = Get-OptimizerProperty -InputObject $record -Name 'App'
        if ($null -eq $app) { continue }

        # The exclusion gate. Checked here, in the one place a Finding is built, so
        # it cannot be bypassed by handing in a classification built elsewhere.
        $exclusion = Get-UnusedAppExclusionMatch -InstalledApp $app -ExclusionEntry $ExclusionEntry
        if ($null -ne $exclusion) {
            Write-Verbose "Excluded '$(Get-OptimizerProperty -InputObject $record -Name 'DisplayName')' via exclusion entry '$(Get-OptimizerProperty -InputObject $exclusion -Name 'Id')'."
            continue
        }

        $source      = [string](Get-OptimizerProperty -InputObject $app -Name 'Source')
        $displayName = [string](Get-OptimizerProperty -InputObject $record -Name 'DisplayName')
        $familyName  = [string](Get-OptimizerProperty -InputObject $app -Name 'PackageFamilyName')
        $identifier  = [string](Get-OptimizerProperty -InputObject $app -Name 'Id')
        $publisher   = [string](Get-OptimizerProperty -InputObject $app -Name 'Publisher')
        $version     = [string](Get-OptimizerProperty -InputObject $app -Name 'Version')
        $location    = [string](Get-OptimizerProperty -InputObject $app -Name 'InstallLocation')
        $sizeKb      = Get-OptimizerProperty -InputObject $app -Name 'EstimatedSizeKb'

        # Same rule as P2-C1: Appx packages take the Appx path, registry uninstall
        # entries take their uninstall string. PackageManagement is never assigned
        # -- whether it is a removal path at all is still P3-C1's question.
        $removalMethod = $null
        if ($source -eq $script:SourceAppx -or $source -eq $script:SourceProvisioned) {
            $removalMethod = 'Appx'
            if (-not [string]::IsNullOrWhiteSpace($familyName)) { $identifier = $familyName }
        }
        elseif ($source -eq $script:SourceRegistry) {
            $removalMethod = 'RegistryUninstallString'
        }
        else {
            Write-Verbose "Ignoring classification with unrecognized Source '$source'."
            continue
        }

        if ([string]::IsNullOrWhiteSpace($identifier)) { $identifier = $displayName }
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $identifier }

        $key = '{0}|{1}' -f $identifier.ToLowerInvariant(), $removalMethod
        if ($emitted.ContainsKey($key)) { continue }
        $emitted[$key] = $true

        $windowDays    = [int](Get-OptimizerProperty -InputObject $record -Name 'UnusedWindowDays' -Default $script:UnusedAppDefaultWindowDays)
        $minimumAge    = [int](Get-OptimizerProperty -InputObject $record -Name 'MinimumAgeDays' -Default $script:UnusedAppDefaultMinimumAgeDays)
        $lastUsed      = Get-OptimizerProperty -InputObject $record -Name 'LastUsedUtc'
        $ageDays       = Get-OptimizerProperty -InputObject $record -Name 'LastUsedAgeDays'
        $installDate   = Get-OptimizerProperty -InputObject $record -Name 'InstallDate'
        $signalNames   = @([string[]](Get-OptimizerProperty -InputObject $record -Name 'MatchedSignals' -Default @()))
        $signalDetails = @([string[]](Get-OptimizerProperty -InputObject $record -Name 'SignalDetail' -Default @()))

        $evidence = New-Object System.Collections.Generic.List[string]

        $lastUsedText = if ($null -eq $lastUsed) { 'unknown' } else { ([datetime]$lastUsed).ToString('yyyy-MM-dd') }
        $evidence.Add("Not used in the last $windowDays days: the most recent launch recorded for it is $lastUsedText, $ageDays days ago.")

        # Every signal that named this app, with what it said. If two disagreed the
        # more recent one won and both are here, so the disagreement is visible.
        foreach ($detail in $signalDetails) { $evidence.Add("Signal: $detail.") }
        if ($signalNames.Count -gt 1) {
            $evidence.Add("Signals disagreed ($($signalNames -join ', ')); the most recent launch of the two was used, which is the reading that favours keeping the application.")
        }

        if ($installDate -is [datetime]) {
            $installAge = Get-OptimizerProperty -InputObject $record -Name 'InstallAgeDays'
            $evidence.Add("Installed $(([datetime]$installDate).ToString('yyyy-MM-dd')), $installAge days ago.")
        }
        else {
            $evidence.Add('The uninstall key records no usable install date, so the age of the install could not be confirmed.')
        }

        $evidence.Add("Thresholds used: unused window $windowDays days, minimum age $minimumAge days.")

        $identityLine = "Installed as $displayName"
        if (-not [string]::IsNullOrWhiteSpace($publisher)) { $identityLine += " by $publisher" }
        if (-not [string]::IsNullOrWhiteSpace($version))   { $identityLine += ", version $version" }
        $identityLine += " ($identifier)"
        $evidence.Add("$identityLine.")

        if (-not [string]::IsNullOrWhiteSpace($location)) {
            $evidence.Add("Installed at $location.")
        }
        if ($null -ne $sizeKb -and [long]$sizeKb -gt 0) {
            $evidence.Add("The uninstall key reports about $([math]::Round([long]$sizeKb / 1024.0, 1)) MB on disk.")
        }

        $evidence.Add('This is a heuristic finding. Windows records launches only patchily, so "no launch recorded" is weaker than "never launched" -- check whether you still want this before removing it.')

        New-Finding -Category 'UnusedApp' `
            -Id $identifier `
            -DisplayName $displayName `
            -Evidence ([string[]] $evidence.ToArray()) `
            -Confidence 'Heuristic' `
            -RemovalMethod $removalMethod
    }
}

#endregion

#region Public: scan

function Invoke-UnusedAppScan {
    <#
    .SYNOPSIS
        Scans this machine for installed applications that appear unused.

    .DESCRIPTION
        Enumerates what is installed (per-user Appx packages and the three registry
        uninstall views), reads whatever usage signals this machine actually
        exposes, classifies every app as Used / Unused / Unknown, and returns a
        single scan-result object carrying the Findings, the three-state counts and
        which signals were available.

        Read-only. Nothing is uninstalled, disabled or written.

        WHAT THE COUNTS MEAN. UnknownCount is the headline number, not a footnote:
        it is how many installed applications this machine can say nothing about.
        A scan where everything is Unknown is a scan that could not see usage, and
        it reports itself incomplete rather than looking like a clean machine.
        ExcludedCount is how many apps classified Unused were held back by the
        curated exclusion list, so a Finding count of zero can be told apart from
        an exclusion list that swallowed everything.

        SIGNALS. Each is reported in Sources with the shared Succeeded / Skipped /
        Failed / Refused vocabulary, and a signal being off is a Skipped with a
        reason a human can act on, never silence:

          UserAssist            per-user shell launch history. No elevation needed.
          Prefetch              per-machine launch history. Needs administrator
                                rights to read, and can be turned off. Skipped when
                                unreadable -- that is environmental, so it does make
                                the scan incomplete.
          FileSystemLastAccess  always Refused: this project will not use the signal
                                on any machine at any privilege level. It stays in
                                Sources with the measurement behind the decision (see
                                Get-UnusedAppLastAccessStatus) and does NOT make the
                                scan incomplete.

        Provisioned (all-users) Appx packages are deliberately NOT inventoried
        here. A provisioned package that is not registered for this user has no
        per-user launch history by construction, so including it would add nothing
        but Unknown rows -- and would make this scan need elevation it otherwise
        does not. P2-C1 owns the provisioned view.

    .PARAMETER ExclusionPath
        Exclusion list to use. Defaults to Data\unused-app-exclusions.json.

    .PARAMETER RegistryPath
        Uninstall views to read. Defaults to the HKLM, HKLM\WOW6432Node and HKCU
        views -- all three, because omitting WOW6432Node hides most 32-bit software.

    .PARAMETER PrefetchPath
        Prefetch folder to read. Defaults to %WINDIR%\Prefetch.

    .PARAMETER UnusedWindowDays
        An app with no recorded launch in this many days is a candidate. Default
        180. The value used is written into every Finding's Evidence.

    .PARAMETER MinimumAgeDays
        An app installed more recently than this is new, not unused. Default 30.
        The value used is written into every Finding's Evidence.

    .EXAMPLE
        $scan = Invoke-UnusedAppScan
        "$($scan.UnknownCount) of $($scan.ConsideredCount) apps could not be judged"
        $scan.Findings | Format-Table DisplayName, SafetyLabel

    .OUTPUTS
        Win11Optimizer.UnusedAppScanResult
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ExclusionPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]] $RegistryPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $PrefetchPath = $script:UnusedAppPrefetchPath,

        [Parameter()]
        [ValidateRange(1, 36500)]
        [int] $UnusedWindowDays = $script:UnusedAppDefaultWindowDays,

        [Parameter()]
        [ValidateRange(0, 36500)]
        [int] $MinimumAgeDays = $script:UnusedAppDefaultMinimumAgeDays
    )

    $startedUtc = [datetime]::UtcNow
    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

    Write-OptimizerLog -EventName 'UnusedAppScanStarted' -Message 'Unused-app scan started.'

    # Load the exclusion list first and let a failure propagate: with no exclusions
    # this detector would flag every runtime, driver and background service on the
    # machine, which is worse than not running at all.
    try {
        $exclusionArguments = @{}
        if ($ExclusionPath) { $exclusionArguments['Path'] = $ExclusionPath }
        $exclusions = @(Get-UnusedAppExclusionList @exclusionArguments)
    }
    catch {
        Write-OptimizerLog -EventName 'UnusedAppScanFailed' -Level 'Error' `
            -Message "Unused-app exclusion list could not be loaded: $($_.Exception.Message)"
        throw
    }

    Write-OptimizerLog -EventName 'UnusedAppExclusionsLoaded' -Message "Loaded $($exclusions.Count) unused-app exclusion entries."

    $isElevated = Test-IsElevated
    $inventory  = New-Object System.Collections.Generic.List[psobject]
    $signals    = New-Object System.Collections.Generic.List[psobject]
    $sources    = New-Object System.Collections.Generic.List[psobject]

    # --- Inventory 1: per-user Appx packages ----------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $items = @(Get-OemAppxPackageItem)
        $timer.Stop()
        foreach ($item in $items) { $inventory.Add($item) }
        $sources.Add((New-UnusedAppScanSource -Name $script:SourceAppx -Status 'Succeeded' `
            -ItemCount $items.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    catch {
        $timer.Stop()
        $sources.Add((New-UnusedAppScanSource -Name $script:SourceAppx -Status 'Failed' `
            -Reason "Enumerating per-user Appx packages failed: $($_.Exception.Message)" `
            -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }

    # --- Inventory 2: registry uninstall views ---------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $registryArguments = @{}
        if ($RegistryPath) { $registryArguments['Path'] = $RegistryPath }
        $items = @(Get-RegistryInstalledApp @registryArguments)
        $timer.Stop()
        foreach ($item in $items) { $inventory.Add($item) }
        $sources.Add((New-UnusedAppScanSource -Name $script:SourceRegistry -Status 'Succeeded' `
            -ItemCount $items.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    catch {
        $timer.Stop()
        $sources.Add((New-UnusedAppScanSource -Name $script:SourceRegistry -Status 'Failed' `
            -Reason "Reading the registry uninstall views failed: $($_.Exception.Message)" `
            -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }

    # --- Signal 1: UserAssist --------------------------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $items = @(Get-UserAssistUsageSignal)
        $timer.Stop()
        foreach ($item in $items) { $signals.Add($item) }
        $sources.Add((New-UnusedAppScanSource -Name $script:UnusedAppSignalUserAssist -Status 'Succeeded' `
            -ItemCount $items.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    catch {
        $timer.Stop()
        $sources.Add((New-UnusedAppScanSource -Name $script:UnusedAppSignalUserAssist -Status 'Failed' `
            -Reason "Reading the UserAssist shell-launch history failed: $($_.Exception.Message) Without it, apps with no other signal are reported as unknown rather than unused." `
            -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }

    # --- Signal 2: prefetch ----------------------------------------------------
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $prefetchStatus = Test-UnusedAppPrefetchAvailable -Path $PrefetchPath
    if (-not $prefetchStatus.Available) {
        $timer.Stop()
        $sources.Add((New-UnusedAppScanSource -Name $script:UnusedAppSignalPrefetch -Status 'Skipped' `
            -Reason $prefetchStatus.Reason -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
    }
    else {
        try {
            $items = @(Get-PrefetchUsageSignal -Path $PrefetchPath)
            foreach ($item in $items) { $signals.Add($item) }

            # A .pf names an executable, not a path, so the join needs to know which
            # executables belong to which app. Done only when prefetch is actually
            # readable, so a scan that cannot use the signal does not pay for it.
            Add-UnusedAppExecutableName -InstalledApp $inventory

            $timer.Stop()
            $sources.Add((New-UnusedAppScanSource -Name $script:UnusedAppSignalPrefetch -Status 'Succeeded' `
                -ItemCount $items.Count -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
        }
        catch {
            $timer.Stop()
            $sources.Add((New-UnusedAppScanSource -Name $script:UnusedAppSignalPrefetch -Status 'Failed' `
                -Reason "Reading the prefetch launch history failed: $($_.Exception.Message)" `
                -DurationSeconds ([math]::Round($timer.Elapsed.TotalSeconds, 3))))
        }
    }

    # --- Signal 3: filesystem last-access (never used; see the reason) ---------
    # 'Refused', not 'Skipped': this project has decided never to use this signal,
    # on any machine, at any privilege level. It was 'Skipped' until chunk P2-C2,
    # which meant a fully-elevated scan with every real signal succeeding still
    # reported itself PARTIAL -- forever, on every machine. The measurement stays
    # in Sources with its full reason; it just stops being called an
    # incompleteness. See docs\STATE.md 2026-08-25.
    $lastAccess = Get-UnusedAppLastAccessStatus
    $sources.Add((New-UnusedAppScanSource -Name $script:UnusedAppSignalLastAccess -Status 'Refused' `
        -Reason $lastAccess.Reason))

    foreach ($source in $sources) {
        $level = if ($script:ScanSourceIncompleteStatuses -contains $source.Status) { 'Warning' } else { 'Info' }
        Write-OptimizerLog -EventName 'UnusedAppScanSource' -Level $level `
            -Message "Source $($source.Name): $($source.Status)." `
            -Data ([ordered]@{
                Source          = $source.Name
                Status          = $source.Status
                ItemCount       = $source.ItemCount
                DurationSeconds = $source.DurationSeconds
                Reason          = $source.Reason
            })
    }

    $classifications = @(Get-AppUsageClassification -InstalledApp $inventory.ToArray() `
        -UsageSignal $signals.ToArray() `
        -UnusedWindowDays $UnusedWindowDays `
        -MinimumAgeDays $MinimumAgeDays)

    $findings = @(Find-UnusedApp -Classification $classifications -ExclusionEntry $exclusions |
        Sort-Object DisplayName)

    $usedCount    = @($classifications | Where-Object { $_.State -eq $script:UnusedAppStateUsed }).Count
    $unusedCount  = @($classifications | Where-Object { $_.State -eq $script:UnusedAppStateUnused }).Count
    $unknownCount = @($classifications | Where-Object { $_.State -eq $script:UnusedAppStateUnknown }).Count

    # How many Unused classifications the exclusion list held back. Reported so a
    # zero-Finding scan can be told apart from an exclusion list that ate the lot.
    $excludedCount = 0
    foreach ($record in $classifications) {
        if ($record.State -ne $script:UnusedAppStateUnused) { continue }
        if ($null -ne (Get-UnusedAppExclusionMatch -InstalledApp $record.App -ExclusionEntry $exclusions)) { $excludedCount++ }
    }

    $totalTimer.Stop()

    $defaultExclusionPath = Join-Path -Path $script:OptimizerDataRoot -ChildPath 'unused-app-exclusions.json'

    $result = New-ScanResult -Detector 'UnusedApps' -Category 'UnusedApp' `
        -StartedUtc $startedUtc `
        -DurationSeconds ([math]::Round($totalTimer.Elapsed.TotalSeconds, 3)) `
        -IsElevated $isElevated `
        -InventoryCount $inventory.Count `
        -Source $sources.ToArray() `
        -Finding $findings `
        -ItemNoun 'installed items' `
        -FindingNoun 'unused-app findings' `
        -ScanLabel 'Unused-app scan' `
        -TypeName $script:UnusedAppScanResultTypeName `
        -AdditionalProperty ([ordered]@{
            ExclusionPath    = $(if ($ExclusionPath) { $ExclusionPath } else { $defaultExclusionPath })
            ExclusionCount   = $exclusions.Count
            UnusedWindowDays = $UnusedWindowDays
            MinimumAgeDays   = $MinimumAgeDays
            SignalCount      = $signals.Count
            ConsideredCount  = $classifications.Count
            UsedCount        = $usedCount
            UnusedCount      = $unusedCount
            UnknownCount     = $unknownCount
            ExcludedCount    = $excludedCount
            Classifications  = [psobject[]] $classifications
        })

    Write-OptimizerLog -EventName 'UnusedAppScanCompleted' `
        -Level $(if ($result.IsComplete) { 'Info' } else { 'Warning' }) `
        -Message $result.SummaryText `
        -Data ([ordered]@{
            IsComplete      = $result.IsComplete
            IsElevated      = $isElevated
            FindingCount    = @($result.Findings).Count
            ConsideredCount = $classifications.Count
            UsedCount       = $usedCount
            UnusedCount     = $unusedCount
            UnknownCount    = $unknownCount
            ExcludedCount   = $excludedCount
            DurationSeconds = $result.DurationSeconds
        })

    $result
}

function Add-UnusedAppExecutableName {
    # Attaches the top-level executable names of each app's InstallLocation, which
    # is what a prefetch record can be joined against. Added with Add-Member rather
    # than baked into the shared installed-app record: it costs a directory read
    # per app, and P2-C1 has no use for it.
    #
    # Top level only, and capped. Walking an install tree recursively would drag in
    # every bundled helper and updater in the product and make a name collision
    # far more likely than it already is.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $InstalledApp,
        [Parameter()] [int] $MaximumPerApp = 40
    )

    foreach ($app in @($InstalledApp)) {
        if ($null -eq $app) { continue }
        if ($null -ne $app.PSObject.Properties['ExecutableName']) { continue }

        $location = [string](Get-OptimizerProperty -InputObject $app -Name 'InstallLocation')
        $names = @()

        if (-not [string]::IsNullOrWhiteSpace($location)) {
            try {
                $names = @([System.IO.Directory]::GetFiles($location, '*.exe') |
                    ForEach-Object { [System.IO.Path]::GetFileName($_) } |
                    Select-Object -First $MaximumPerApp)
            }
            catch {
                Write-Verbose "Could not list executables under '$location': $($_.Exception.Message)"
                $names = @()
            }
        }

        $app | Add-Member -MemberType NoteProperty -Name 'ExecutableName' -Value ([string[]] $names) -Force
    }
}

#endregion
