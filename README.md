# win11-optimizer

A Windows 11 desktop tool that sweeps a system, flags software and startup clutter
that can safely be removed — OEM bloatware, dead startup items, unused installed
applications, junk/temp disk bloat — and removes **only** what the user explicitly
confirms. Never a silent auto-clean.

Two rules shape everything here:

- **Curated whitelist decides what is "safe".** Only a match against the curated
  known-bloatware list is ever described to the user as safe to remove. Usage
  heuristics surface additional candidates, always labelled "review needed".
- **The tool keeps its own rollback record.** System Restore is a best-effort extra
  layer, not the safety net — it has a hard 24-hour interval between checkpoints and
  is frequently disabled outright.

## Status

**Early scaffold.** The engine core exists — the shared `Finding` contract, the
elevation check and the JSON-lines run log. There is no detection, no removal and no
GUI yet; nothing in the repo currently changes anything on your machine.

## Layout

```
src/Win11Optimizer.Engine/   PowerShell engine module (contract, elevation, run log)
src/Win11Optimizer.Engine/Detectors/   one file per sweep category (empty for now)
tests/                       Pester 5 suite
logs/                        per-run JSON-lines logs, created at runtime (untracked)
```

## Requirements

Windows 11, Windows PowerShell 5.1 or PowerShell 7+. No third-party modules — Pester 5
is needed only to run the tests.

## Usage

```powershell
Import-Module .\src\Win11Optimizer.Engine\Win11Optimizer.Engine.psd1
Get-Command -Module Win11Optimizer.Engine
```

Run the tests:

```powershell
.\tests\Invoke-Tests.ps1          # current shell
.\tests\Invoke-Tests.ps1 -On51    # re-run under Windows PowerShell 5.1
```

## Plan

Roadmap, decisions and research live in [`docs/PLAN.md`](docs/PLAN.md) (local, untracked).
