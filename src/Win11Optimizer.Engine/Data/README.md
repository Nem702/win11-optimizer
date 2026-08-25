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
  "requiresConsent": true,        // optional, JSON boolean — see "Consent" below. Absent = false
  "sensitiveClass": "security-trial", // optional — the only accepted value; see "The carve-out"
  "note": "…",                    // optional, for maintainers; not shown to the user
  "match": { … }                  // required, at least one rule
}
```

`schemaVersion` is **2** as of chunk P2-C1a, which added `requiresConsent` and
`sensitiveClass`. Entries written against version 1 load unchanged: both fields are
optional and both default to "no".

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

### Consent — the second axis

`requiresConsent` says **"matched for certain, but a human still has to approve it"**.
It is deliberately *not* the same question as confidence:

| question                                          | field             |
| ------------------------------------------------- | ----------------- |
| how sure are we this is the thing we think it is?  | `Confidence`      |
| must a human explicitly approve this one anyway?   | `RequiresConsent` |

A matched entry always produces a `Confidence = Known` Finding. If the entry sets
`requiresConsent`, that Finding's `SafetyLabel` reads **"Review needed"** rather than
"Safe to remove" — the match is certain and it still needs a person. Downgrading such
an entry to `Heuristic` instead was considered and rejected: `Heuristic` is chunk
P2-C3's entire identity and the word cannot mean two things.

It must be a real JSON boolean. The string `"true"` is rejected at load, by name,
because it is truthy in PowerShell and would leave an entry looking enforced while the
Finding contract — which fails closed on a non-boolean — disagreed about what it meant.

### The security carve-out — `sensitiveClass: "security-trial"`

"Never whitelist security software" still stands, with exactly one exception, locked in
`docs/STATE.md` (2026-08-25): **OEM trial/nagware editions** may be listed. `Get-KnownBloatwareList`
enforces what that costs, so the rules are structural rather than a review convention.
An entry declaring `sensitiveClass: "security-trial"` must satisfy **all** of:

- `requiresConsent` is `true` — it can never surface as "Safe to remove";
- **no `*` in any pattern, in any match field.** Exact identifiers only, no exceptions.
  A prefix match on a security product is precisely how a list that meant to catch the
  OEM trial catches the suite the user chose and paid for;
- `reason` is non-empty and says it is the trial/nagware edition — it is checked for the
  word `trial` or `nagware`, because prose is what the user reads before approving a
  removal and for security software it has to name the edition being flagged.

Any other `sensitiveClass` value is rejected at load, so a typo cannot quietly demote an
entry to an ordinary one and shed these rules with it.

The practical cost of the no-wildcard rule is that a security-trial entry **misses** if
the vendor version-stamps its display name. That is the accepted trade: a miss is a
safe failure, and the wildcard that would fix it is the thing that makes the entry
dangerous.

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
- **Security software** — with the single narrow exception of OEM trial/nagware
  editions listed under `sensitiveClass: "security-trial"`, above. Anything a user
  could have chosen and paid for stays off the list, and so does anything whose
  display name is shared between the trial and the retail product.
- **Drivers** and driver control panels (NVIDIA/Realtek/AMD/Intel).
- **Runtimes** — Visual C++ redistributables, .NET, WebView2, GameInput.
- **OEM firmware/driver-update utilities** — MSI Center, Lenovo Vantage, Dell
  SupportAssist, HP Support Assistant, ASUS Armoury Crate. These update firmware and
  drivers; treating them as bloat is how a machine loses its fan curve or its BIOS
  update path.

`tests/OemBloatware.Tests.ps1` asserts a sample of these never appear in the file,
including the retail editions of the two vendors the carve-out entries come from.

### Provenance reaches the user two ways

`evidenceSource` distinguishes an identifier observed on real hardware (`measured`) from
one taken from a published list (`public-list`) and never verified here. Both routes out
of the detector exist so nothing has to string-match prose to learn this:

- **Structurally**, for the GUI: every Finding carries `WhitelistEntryId`, the id of the
  entry it matched. Call `Get-KnownBloatwareList`, look the id up, and read
  `evidenceSource`, `sensitiveClass` and `requiresConsent` off the entry.
- **In plain words**, for a human reading the evidence: a Finding from a `public-list`
  entry gains an Evidence line saying the identifier has never been observed on real
  hardware. A `measured` entry gains no corresponding line — **silence means measured.**
