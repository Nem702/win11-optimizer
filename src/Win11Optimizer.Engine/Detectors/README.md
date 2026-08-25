# Detectors

One file per sweep category, added by the Phase 2 chunks in `docs/PLAN.md`:

| file (planned)        | chunk | category       |
| --------------------- | ----- | -------------- |
| `OemBloatware.ps1`    | P2-C1 | `OemBloatware` |
| `StartupItems.ps1`    | P2-C2 | `StartupItem`, `Service` |
| `UnusedApps.ps1`      | P2-C3 | `UnusedApp`    |
| `JunkFiles.ps1`       | P2-C4 | `JunkFile`     |

Every `.ps1` in this folder is dot-sourced by `Win11Optimizer.Engine.psm1` at
import time. A detector must:

- return only objects built by `New-Finding` (never a bare hashtable), and
- add its public function names to the `Export-ModuleMember` list in the `.psm1`
  **and** to `FunctionsToExport` in the `.psd1` — the manifest gates what callers see.

Empty as of chunk P1-C1.
