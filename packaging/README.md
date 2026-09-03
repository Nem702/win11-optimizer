# packaging

The installer. Chunk P5-C2.

| file | what it is |
| --- | --- |
| `win11-optimizer.wxs` | The WiX v3 source. Hand-maintained, and `tests\MsiPackaging.Tests.ps1` asserts its file list is exactly the engine folder plus the five reference documents, in both directions. |
| `Build-Msi.ps1` | Finds the WiX toolset, runs `candle` and then `light`. Stops with an explanation if WiX is not installed. |

## Building

```powershell
.\packaging\Build-Msi.ps1 -VerifyOnly   # is the toolset here at all?
.\packaging\Build-Msi.ps1               # -> packaging\dist\win11-optimizer-<version>-x64.msi
```

Needs the **WiX Toolset v3** (v3.11 or newer). Two ways to get it:

```powershell
# 1. the installer. Needs administrator and the .NET Framework 3.5 feature.
winget install --id WiXToolset.WiXToolset

# 2. the portable binaries. Needs neither. This is how 0.1.0 was built.
#    Download wix314-binaries.zip from https://github.com/wixtoolset/wix3/releases
$env:WIX = 'C:\wherever\you\unpacked\it'
```

WiX v4 and v5 replace `candle` and `light` with a single `wix.exe` and a
different schema. This source targets v3 and will not compile under either.

It links with **no ICE check suppressed** — no `-sice`, no `-sval`. One warning
is expected and is benign: `ICE69` observes that the shortcut's `Arguments`
name a file belonging to another component, and then says itself that both are
in the same feature.

## What the .msi does

- Installs the engine module to `C:\Program Files\win11-optimizer\src\Win11Optimizer.Engine\`,
  so `Import-Module 'C:\Program Files\win11-optimizer\src\Win11Optimizer.Engine'` works
  as-is.
- Installs five reference documents to `C:\Program Files\win11-optimizer\docs\`.
- Creates one Start Menu shortcut, `win11-optimizer`, running Windows PowerShell 5.1
  against `App\Bootstrap.ps1`. It does **not** ask for elevation; the menu asks per
  choice, when a choice needs it.
- Creates `%ProgramData%\win11-optimizer\` with an explicit ACL: Administrators and
  SYSTEM full control, Users read, inheritance off. This is the action ledger's home
  (docs/STATE.md, Q21) and the reason this chunk is an installer rather than a zip:
  nothing but an installer can set that ACL, and the tool refuses to write a ledger
  into a folder that does not have it.

Uninstall removes the tool and the shortcut. It leaves
`%ProgramData%\win11-optimizer\` exactly where it is — the record of what the tool
did to the machine outlives the tool, which is the point of having one.

## Not here

Code signing (P5-C3), deferred until there is a build worth signing. An unsigned
`.msi` shows an unknown-publisher UAC prompt; that is expected.
