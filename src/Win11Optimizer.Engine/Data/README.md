# Data

Runtime data files loaded by the engine. Nothing here is code; nothing here is
generated. Everything in this folder is hand-curated and reviewed.

## `known-bloatware.json`

The curated whitelist behind the `OemBloatware` detector (chunk P2-C1). Per
`docs/PLAN.md` this list is the **only** thing the tool ever labels "Safe to remove"
— a `Confidence = Known` Finding exists if and only if something on the machine
matched an entry here. Adding an entry is a safety claim, not a convenience.

Loaded by `Get-KnownBloatwareList`, which validates every rule below at load time and
**throws** on any violation. A whitelist that fails to load stops the scan; it never
degrades into "found nothing".

### Entry shape

```jsonc
{
  "id": "vendor-app-slug",        // required, unique, stable — used as the dedupe key
  "displayName": "App name",      // required — what the review UI shows
  "vendor": "Publisher / OEM",    // required — who it comes from
  "reason": "Why this is bloat.", // required, non-empty — surfaced to the user as evidence
  "evidenceSource": "measured",   // optional: "measured" (seen on a real machine) or "public-list"
  "note": "…",                    // optional, for maintainers; not shown to the user
  "match": { … }                  // required, at least one rule
}
```

`reason` is not documentation. It is copied into the Finding's `Evidence`, so it is
what the user reads when deciding whether to confirm a removal. An entry without a
stated reason is rejected at load.

### Match rules

| field                   | matched against                                  | removal method            |
| ----------------------- | ------------------------------------------------ | ------------------------- |
| `appxPackageName`       | Appx `Name` (e.g. `Microsoft.Copilot`)           | `Appx`                    |
| `appxPackageFamilyName` | Appx `PackageFamilyName` (`Name_publisherhash`)  | `Appx`                    |
| `registryDisplayName`   | uninstall key `DisplayName`                      | `RegistryUninstallString` |
| `registryPublisher`     | uninstall key `Publisher` — **guard only**       | —                         |

Each field holds an array of patterns. An entry matches an installed item if **any**
pattern in an applicable field matches. Rules that don't apply to an item's source are
ignored, so one entry can cover both an Appx install and a Win32 install of the same
product (see `microsoft-copilot`).

`registryPublisher` is an **AND-guard**, never a match on its own: when present, the
`DisplayName` must match *and* the `Publisher` must match. It exists so a generic
display name can be pinned to one vendor. An entry carrying `registryPublisher` with
no `registryDisplayName` is rejected at load — publisher alone is far too broad to be
a safety claim.

Any `match` field not in the table above is rejected at load. A typo must fail loudly
rather than silently disabling an entry.

### Pattern syntax — deliberately tiny

OEM package and Win32 display names carry version suffixes (`AIDA64 Extreme v7.50`,
`NVIDIA App 11.0.8.299`), so some wildcarding is unavoidable. The syntax is kept as
small as it can be while still covering that:

- Matching is **case-insensitive ordinal**.
- A pattern is either an **exact string**, or a **prefix followed by exactly one `*`
  as the final character**.
- `*` anywhere other than the last character is rejected at load. So is a pattern that
  is only `*`.
- The literal prefix before a trailing `*` must be at least **6 characters**. `A*` is
  rejected.
- **No other character is special.** `?`, `[`, `]` and `.` are literals. Matching does
  not use `-like` or regex precisely so those cannot leak in.

Wildcards match a *prefix*, never a substring: `WildTangent*` matches
`WildTangent Games` but not `Games by WildTangent`.

### What must never go on this list

Getting one of these wrong breaks a machine, so they are out of scope regardless of
how much they look like bloat:

- Anything Microsoft ships as an **OS component** (shell, search, store, runtime hosts).
- **Microsoft Store** itself.
- **Security software** — including OEM-preinstalled antivirus trials.
- **Drivers** and driver control panels (NVIDIA/Realtek/AMD/Intel).
- **Runtimes** — Visual C++ redistributables, .NET, WebView2, GameInput.
- **OEM firmware/driver-update utilities** — MSI Center, Lenovo Vantage, Dell
  SupportAssist, HP Support Assistant, ASUS Armoury Crate. These update firmware and
  drivers; treating them as bloat is how a machine loses its fan curve or its BIOS
  update path.

`tests/OemBloatware.Tests.ps1` asserts a sample of these never appear in the file.
