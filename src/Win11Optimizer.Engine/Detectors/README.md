# Detectors

One file per sweep category, added by the Phase 2 chunks in `docs/PLAN.md`:

| file                  | chunk | category       | status      |
| --------------------- | ----- | -------------- | ----------- |
| `OemBloatware.ps1`    | P2-C1, P2-C1a | `OemBloatware` | done |
| `StartupItems.ps1`    | P2-C2 | `StartupItem`, `Service` | planned |
| `UnusedApps.ps1`      | P2-C3 | `UnusedApp`    | planned     |
| `JunkFiles.ps1`       | P2-C4 | `JunkFile`     | planned     |

Every `.ps1` in this folder is dot-sourced by `Win11Optimizer.Engine.psm1` at
import time. A detector must:

- return only objects built by `New-Finding` (never a bare hashtable), and
- add its public function names to the `Export-ModuleMember` list in the `.psm1`
  **and** to `FunctionsToExport` in the `.psd1` — the manifest gates what callers see.

Two more things `OemBloatware.ps1` established that later detectors should copy:

- **Keep detector source ASCII-only, or give the file a UTF-8 BOM.** Windows
  PowerShell 5.1 reads a BOM-less `.ps1` as ANSI. A UTF-8 em dash then decodes to
  `â€"`, whose last character 5.1 accepts as a *string delimiter* — so a comment or
  message containing one produces a wall of unrelated parser errors. The repo's files
  are all BOM-less, so stick to ASCII in `.ps1` files.
- **A scan returns a result object, not a bare array of Findings.** Detection sources
  can be unavailable (elevation, a busy servicing session), and a caller must not be
  able to receive a partial list and mistake it for a complete one. See
  `Invoke-OemBloatwareScan` and `docs/handoff/02-oem-detector.report.md`.
- **`Confidence` is not the safety label.** `New-Finding` takes a second, orthogonal
  `-RequiresConsent` switch, and `SafetyLabel` is the AND of both — "Safe to remove"
  only for a `Known` match that needs no explicit human OK. A detector that has a
  certain match it still would not want acted on unattended sets the switch; it must
  not reach for `Heuristic`, which belongs to P2-C3. See
  `docs/handoff/03-whitelist-amendment.report.md`.
- **Detector-specific fields go on the Finding, not in the contract.** `OemBloatware.ps1`
  attaches `WhitelistEntryId` with `Add-Member` after `New-Finding`, because a join key
  into the curated whitelist means nothing to the other three detectors. Add to the
  shared contract only what every category needs.
