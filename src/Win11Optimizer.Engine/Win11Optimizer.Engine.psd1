@{
    RootModule            = 'Win11Optimizer.Engine.psm1'
    ModuleVersion         = '0.1.0'
    GUID                  = '639a63df-7755-4bad-b311-71ffa157edb1'
    Author                = 'Nems'
    CompanyName           = 'win11-optimizer'
    Copyright             = '(c) 2026 Nems.'
    Description           = 'Core engine for win11-optimizer: the shared Finding contract, elevation check and JSON-lines run log that the sweep detectors, removal dispatcher and WPF shell build on.'

    # Windows PowerShell 5.1 is the floor: the tool must run on a stock Windows 11
    # box with nothing installed. Nothing here needs PowerShell 7+.
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')

    RequiredModules       = @()
    RequiredAssemblies    = @()

    # Detector chunks (P2-C1..C4) add their public function names here and to the
    # Export-ModuleMember list in Win11Optimizer.Engine.psm1.
    FunctionsToExport     = @(
        'New-Finding'
        'Test-Finding'
        'Get-FindingContract'
        'Test-IsElevated'
        'Start-OptimizerLog'
        'Write-OptimizerLog'
        'Stop-OptimizerLog'
        'Get-OptimizerLog'
        'Get-OptimizerLogPath'
        'Get-OptimizerLogRoot'

        # P2-C1 -- OemBloatware detector
        'Get-KnownBloatwareList'
        'Find-KnownBloatware'
        'Invoke-OemBloatwareScan'

        # P2-C3 -- shared inventory
        'Get-RegistryInstalledApp'

        # P2-C3 -- UnusedApp detector
        'Get-UnusedAppExclusionList'
        'Get-AppUsageClassification'
        'Find-UnusedApp'
        'Invoke-UnusedAppScan'

        # P2-C2 -- StartupItem / Service detector
        'Get-KnownStartupItemList'
        'Get-StartupItemInventory'
        'Find-UnwantedStartupItem'
        'Invoke-StartupItemScan'

        # P2-C4 - JunkFile detector
        'Get-JunkLocationList'
        'Get-JunkLocationInventory'
        'Find-JunkFileLocation'
        'Invoke-JunkFileScan'

        # P3-C1 - removal dispatcher (plans only; removes nothing)
        'Get-RemovalContract'
        'Get-RemovalPlan'
        'Get-RemovalPreview'

        # P3-C2 - the append-only action ledger (Removal/ActionLog.ps1) and the
        # best-effort restore point (Removal/RestorePoint.ps1).
        'Get-OptimizerActionLogPath'
        'Write-OptimizerAction'
        'Get-OptimizerActionLog'
        'Get-OptimizerRunReceipt'
        'New-OptimizerRestorePoint'

        # P5-C2 - Q21: the ledger's per-machine home and the ACL check that
        # guards it (Removal/ActionLog.ps1).
        'Get-OptimizerActionLogRoot'
        'Test-OptimizerLedgerFolder'
        'Assert-OptimizerLedgerFolder'

        # P3-C3 - the executor (Removal/Executor.ps1). The first code here that
        # changes the machine on purpose, and it changes one thing: the startup
        # type of one service. Every other route is refused, with a reason.
        'Invoke-RemovalPlan'
        'Undo-RemovalAction'

        # P4-C1 - the console review screen (Review/Screen.ps1). Deciding and
        # printing kept apart: Get-ReviewScreen works out what the four sections
        # say, Format-ReviewScreen turns that into lines, and Show-ReviewScreen
        # drives the prompts. It collects a selection and runs nothing.
        'Get-ReviewScreen'
        'Format-ReviewScreen'
        'Get-ReviewSelection'
        'Get-ReviewConfirmation'
        'Show-ReviewScreen'

        # P4-C2 - picks to plans, and a confirmed set of plans to the executor
        # (Review/Execute.ps1). The two joins between the screen and the machine.
        # New-OptimizerExecutionPlan reads and plans; Invoke-OptimizerExecutionPlan
        # is the only thing outside Removal/ that can change anything, and it does
        # it by calling Invoke-RemovalPlan and nothing else.
        'New-OptimizerExecutionPlan'
        'Invoke-OptimizerExecutionPlan'

        # P5-C1 - the entry point (App/Menu.ps1) and the UAC relaunch
        # (Support/Elevation.ps1). Invoke-OptimizerMenu is a switchboard over
        # every export above it and adds no mechanism of its own;
        # Invoke-OptimizerElevated starts a second, elevated process running
        # App/Entry.ps1, which is the launcher and is not part of this surface.
        'Invoke-OptimizerMenu'
        'Invoke-OptimizerElevated'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()

    PrivateData           = @{
        PSData = @{
            Tags       = @('Windows11', 'Debloat', 'Optimization')
            LicenseUri = ''
            ProjectUri = ''
        }
    }
}
