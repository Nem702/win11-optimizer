# win11-optimizer

A Windows 11 tool that sweeps a machine, shows you what it found, and changes only
what you explicitly confirm. Never a silent auto-clean, and never a benefit claim it
did not measure.

**Using it?** Read [`USAGE.md`](USAGE.md). This file is about how it is built.

## What it does

Four detectors, all read-only:

| category | what it finds |
| --- | --- |
| OEM bloatware | preinstalled and vendor software, against a curated list |
| Startup items & services | Run keys, Startup folders, logon/boot scheduled tasks, automatic services |
| Unused apps | installed software with no sign of recent use -- heuristics only |
| Junk files | caches and temporary files, per curated location |

Findings become **plans**, plans are shown to you in full, and only a confirmed
selection is carried out. Everything performed is written to an append-only ledger
that survives uninstalling the tool.

## Status: 0.1.0

Complete and packaged. Detection, planning, the review screen, execution, the ledger,
undo, the launcher and an `.msi` installer all exist, with 1,598 tests green on both
Windows PowerShell 5.1 and PowerShell 7.

**It performs one removal route of seven.** Setting a service's startup type is
carried out; the other six are planned, described, and refused. That is a deliberate
staging decision -- the service route is the only one whose ledger record is provably
enough to reverse it. See `USAGE.md`.

**The `.msi` has been built but never installed.** Three things stay unverified until
it is run on a clean machine: that it installs and starts, that the ledger folder
lands with the right permissions, and that uninstalling leaves that folder behind.

## The two rules that shape everything

- **A curated list decides what is "safe".** Only a match against a curated list is
  ever described as safe to remove. Usage heuristics raise candidates for review and
  never flag anything on their own. No publisher heuristic -- measured at 22 wrong
  findings on one machine. Security software, drivers, runtimes and updaters are
  never flagged, and an updater that stops running is a machine that stops getting
  security fixes.
- **Silent under-reporting is the enemy.** "Found nothing" must never be
  indistinguishable from "broke". A scan that could not read something reports itself
  incomplete and says which source and why. Most of the engineering in this repo is
  about that one property.

## Layout

```
src/Win11Optimizer.Engine/     the engine module
            App/               launcher, entry point, menu
            Detectors/         one file per category
            Removal/           dispatcher, executor, action ledger, restore point
            Review/            the console review screen and execution wiring
            Data/              the curated lists, as JSON
tests/                         Pester 5 suite
packaging/                     WiX source and the .msi build script
docs/                          plan, state, review notes, per-chunk handoffs (untracked)
```

## Requirements

Windows 11 or 10. **Windows PowerShell 5.1 is the target runtime, not PowerShell 7** --
the `msi` and `Programs` package providers the inventory needs exist only under 5.1,
and returning one result instead of a thousand is exactly the silent under-reporting
this project refuses. The suite runs green on both.

Pester 5 is needed only to run the tests. Building the `.msi` needs the WiX Toolset v3
-- see [`packaging/README.md`](packaging/README.md).

## Developing

```powershell
Import-Module .\src\Win11Optimizer.Engine\Win11Optimizer.Engine.psd1
Get-Command -Module Win11Optimizer.Engine

.\tests\Invoke-Tests.ps1          # current shell
.\tests\Invoke-Tests.ps1 -On51    # re-run under Windows PowerShell 5.1
```

Run the suite from a **non-elevated** shell. Elevated, the launcher tests drive real
child processes and the run is far slower; elevated PowerShell 7 in particular has
been measured at ~18x the un-elevated time, for reasons not yet understood.

Roadmap, decisions and per-chunk handoffs live under `docs/` -- present on disk,
untracked by design. `docs/CHECKLIST.md` is the board.
