# packaging

The installer. Chunk P5-C2, polished in P5-C4.

| file | what it is |
| --- | --- |
| `win11-optimizer.wxs` | The WiX v3 source. Hand-maintained, and `tests\MsiPackaging.Tests.ps1` asserts its file list is exactly the engine folder plus `LICENSE.md`, `README.md` and `USAGE.md`, in both directions. |
| `win11-optimizer.ico` | The product icon: one `.ico` carrying 16, 24, 32, 48, 64, 128 and 256 px. Used twice - `ARPPRODUCTICON` and the Start Menu shortcut - from one `<Icon>` row. It is a stream in the `.msi`, not an installed file. |
| `Build-Msi.ps1` | Finds the WiX toolset, generates `obj\License.rtf` from `LICENSE.md`, then runs `candle` and `light`. Stops with an explanation if WiX is not installed. |

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

`light` is run with **`-ext WixUIExtension`**, which is where the dialog set
comes from. `candle` needs no extension - the `.wxs` only *references* WiX's
dialogs, it does not use any extension's schema. Dropping the switch is not a
silent downgrade to no UI: light stops with `LGHT0094 : Unresolved reference to
symbol 'Dialog:ErrorDlg'`, one per dialog, and produces nothing.

It links with **no ICE check suppressed** - no `-sice`, no `-sval`. One warning
is expected and is benign: `ICE69` observes that the shortcut's `Arguments`
name a file belonging to another component, and then says itself that both are
in the same feature.

## What the .msi does

- Installs the engine module to `C:\Program Files\win11-optimizer\src\Win11Optimizer.Engine\`,
  so `Import-Module 'C:\Program Files\win11-optimizer\src\Win11Optimizer.Engine'` works
  as-is.
- Installs `LICENSE.md`, `README.md` and `USAGE.md` to
  `C:\Program Files\win11-optimizer\docs\`. `LICENSE.md` is not optional and the
  installer's licence page is not a substitute for it: Apache-2.0 4(a) requires
  giving every recipient of the Work a copy of the licence, and shipping the
  `.msi` is distributing the Work.
- Creates one Start Menu shortcut, `win11-optimizer`, running Windows PowerShell 5.1
  against `App\Bootstrap.ps1`, carrying the product icon. It does **not** ask for
  elevation; the menu asks per choice, when a choice needs it.
- Creates `%ProgramData%\win11-optimizer\` with an explicit ACL: Administrators and
  SYSTEM full control, Users read, inheritance off. This is the action ledger's home
  (docs/STATE.md, Q21) and the reason this chunk is an installer rather than a zip:
  nothing but an installer can set that ACL, and the tool refuses to write a ledger
  into a folder that does not have it.

Uninstall removes the tool and the shortcut. It leaves
`%ProgramData%\win11-optimizer\` exactly where it is - the record of what the tool
did to the machine outlives the tool, which is the point of having one.

## The UI

```
first install    WelcomeEulaDlg -> ProgressDlg -> ExitDialog
maintenance      MaintenanceWelcomeDlg -> MaintenanceTypeDlg -> VerifyReadyDlg -> ...
```

It is **`WixUI_Minimal`, WiX's own, unmodified**. The `.wxs` adds one thing to it:
the finish page's launch checkbox, published from a `<UI>` in the `Product`.

`WixUI_Minimal`'s single first-run dialog is `WelcomeEulaDlg` - the welcome page and
the licence agreement in one - and it renders whatever `WixUILicenseRtf` points at.
P5-C4 could not use it: `LICENSE.md` was empty, so the page would have shown WiX's
placeholder EULA, a licence nobody wrote and everybody accepts. P5-C4 shipped a
dialog set of its own instead, `WixUI_Win11Optimizer`, and said in writing that it
could go the day `LICENSE.md` was filled in. P5-C5 filled it in and deleted it.

**The licence text is generated, not committed.** `Build-Msi.ps1` converts
`LICENSE.md` to `obj\License.rtf` on every build and hands `candle` the absolute
path. A checked-in `.rtf` would be a second copy of the licence that could drift
from the first, invisibly - the installer showing one licence and the file installed
beside it saying another.

No feature tree and no install-location browse page: `perMachine` into
`Program Files` is the only shape this package supports, and offering a choice
implies there is one.

The finish page offers **Launch win11-optimizer**, ticked by default. That is the
WiX convention for this checkbox and it is a decision, not an inheritance:
somebody who has just run an installer meant to run the tool, and the alternative
is a finish page whose one offer is switched off. `CA.LaunchWin11Optimizer` is
**in no sequence table** - its only caller is the checkbox, so a quiet install
(`msiexec /qn`, which has no UI) never reaches it. It is a type 34 action (a
directory and a command line) and it runs **unelevated**: an immediate custom
action published from a dialog runs in the UI process, which for a `perMachine`
package is the person's own session.

**The package now carries a second custom action, and it is WiX's.**
`WelcomeEulaDlg` has a Print button, wired to `WixUIPrintEula`, a DLL action in
`WixUIExtension`'s own `WixUIWixca` binary stream. P5-C2 and P5-C4 both claimed
"one custom action, no helper DLL"; that claim retired with the licence page,
because every WiX licence dialog has the same button. It is not sequenced either.

## Third-party

The `.msi` links `WixUIExtension` and therefore embeds WiX v3's own dialogs,
bitmaps and `WixUIWixca`. WiX v3 is under the **Microsoft Reciprocal License
(MS-RL)**. No NOTICE file and no third-party folder: the reciprocal obligation is
on modified WiX source, and none of WiX's source is modified here.

## Not here

Code signing, deferred until there is a GUI binary worth signing. An unsigned
`.msi` shows an unknown-publisher UAC prompt; that is expected.
