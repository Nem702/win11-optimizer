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

        # P2-C1 — OemBloatware detector
        'Get-KnownBloatwareList'
        'Find-KnownBloatware'
        'Invoke-OemBloatwareScan'
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
