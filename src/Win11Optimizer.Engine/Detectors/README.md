# Detectors

One file per sweep category, added by the Phase 2 chunks in `docs/PLAN.md`:

| file                  | chunk | category       | status      |
| --------------------- | ----- | -------------- | ----------- |
| `OemBloatware.ps1`    | P2-C1, P2-C1a | `OemBloatware` | done |
| `StartupItems.ps1`    | P2-C2 | `StartupItem`, `Service` | done |
| `UnusedApps.ps1`      | P2-C3 | `UnusedApp`    | done        |
| `JunkFiles.ps1`       | P2-C4 | `JunkFile`     | planned     |

Every `.ps1` in this folder is dot-sourced by `Win11Optimizer.Engine.psm1` at
import time, **after** everything in `..\Shared\`. A detector must:

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

Two more, added by chunk P2-C3:

- **Do not write a second inventory walk.** `..\Shared\Inventory.ps1` owns the
  registry uninstall walk (`Get-RegistryInstalledApp`, all three views), the
  normalised installed-app record (`New-InstalledApp`), the match-pattern dialect
  and the scan-result wrapper (`New-ScanResult` / `New-ScanSource`). Detectors
  compose those. P2-C3 promoted them out of `OemBloatware.ps1` on their second use;
  a detector that needs a per-detector field on an inventory record attaches it with
  `Add-Member` in its own file, the way `Add-UnusedAppExecutableName` does.
- **"No evidence of X" is never "not X".** A heuristic detector must distinguish
  positive evidence of absence from absence of evidence, and report the second as a
  counted, first-class outcome rather than acting on it. `UnusedApps.ps1` puts every
  app in exactly one of `Used` / `Unused` / `Unknown` and the scan result reports all
  three counts, so a scan that could not see usage is obviously distinguishable from
  a scan that found nothing to flag. See `docs/handoff/04-unused-apps.report.md`.

Three more, added by chunk P2-C2:

- **A scan source has four statuses, and `Refused` is not `Skipped`.** `Skipped`
  means "not read this time, for a reason that could have gone the other way
  somewhere else" — not elevated, feature off on this machine, path absent.
  `Refused` means "this project will never use this signal, on any machine, at any
  privilege level". Only `Skipped` and `Failed` make a scan incomplete. Getting
  this wrong is not cosmetic: `FileSystemLastAccess` was `Skipped`, so
  `Invoke-UnusedAppScan` reported itself `PARTIAL` on every run of every machine
  forever, and a warning that always fires is a warning nobody reads. **`Refused`
  must never absorb an environmental failure** — if the answer could differ
  elsewhere, it is `Skipped`. `Reason` is mandatory for all three non-success
  statuses.
- **"Autostarting is not evidence of being unwanted."** The same shape as
  P2-C3's rule, in a category where the raw inventory is much bigger. Almost
  everything a person installs deliberately adds a startup entry, so
  `StartupItems.ps1` flags exactly two things — a curated-list match, and an
  *orphan* whose target is proved absent — and inventories the other ~148 entries
  without flagging any of them. A publisher tier ("flag what is not Microsoft")
  was considered and rejected: it would produce 22 Findings on the development
  machine, every one of them software the user chose.
- **Prove absence before acting on it.** `Test-StartupTargetPresent` is a
  tri-state (`$true` / `$false` / `$null`), because `[System.IO.File]::Exists`
  returns `$false` for a path the caller may not look at, exactly as
  `Get-ChildItem` does on an unreadable folder. A missing file is only believed
  once the containing directory has been *listed successfully*; otherwise the
  answer is `$null` and the entry is inventory, never a Finding.
