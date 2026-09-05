# Using win11-optimizer

Version 0.1.0. This is the guide for someone who has been handed the installer.

---

## Before you start: what this tool actually does in 0.1.0

It **inspects** four things thoroughly, and it **changes** exactly one kind of thing.

It will find and describe, in full detail: OEM bloatware and preinstalled apps,
startup items and background services, applications that look unused, and junk and
temporary files. For every one of them it will tell you what it would do and why.

**It will only carry out one kind of change: setting a background service's startup
type.** Uninstalling an app, deleting junk files, disabling a startup entry -- it
plans all of these, shows you the plan, and then refuses to perform them. That is
deliberate, not a bug. The service route is the only one whose record is enough to
put your machine back exactly as it was, and the others were not offered behind a
flag or a switch.

**It is also all-or-nothing.** If you tick an app and a service in the same pass,
the whole run stops before it does anything at all. On most machines that is the
normal outcome, not an edge case. You will see a refusal that explains which pick
it stopped on.

So today this is an excellent tool for finding out what is on a Windows machine,
plus one narrow, fully reversible change. Treat it that way and it will not
surprise you.

---

## Installing

Double-click `win11-optimizer-0.1.0-x64.msi`.

Windows will warn you about an **unknown publisher**. That is expected -- this build
is not code-signed. Installing needs administrator rights.

It puts four things on the machine:

| what | where |
| --- | --- |
| The tool | `C:\Program Files\win11-optimizer\` |
| A Start Menu shortcut | `win11-optimizer` |
| The action ledger | `C:\ProgramData\win11-optimizer\actions.jsonl` |
| Run logs (created as you use it) | `%LOCALAPPDATA%\win11-optimizer\logs\` |

The `ProgramData` folder is created with locked permissions: administrators and
SYSTEM can write to it, everyone else can only read. That folder is the record of
everything this tool has changed, and it is deliberately harder to edit than the
tool itself. **If those permissions are wrong, the tool refuses to run rather than
writing its record somewhere less safe.**

**Requirements:** Windows 11 or 10, with Windows PowerShell 5.1 -- which every
Windows installation already has. Nothing else to install.

---

## Running it

Launch **win11-optimizer** from the Start Menu. You get a console window and five
choices:

```
1  Scan and review    look at what is on this PC and choose what to change
2  Receipt            what this tool has already done, from the action ledger
3  Undo               put back one change, by action id
4  Restore point      ask Windows for a System Restore checkpoint
5  Quit               leave
```

The shortcut does **not** ask for administrator up front. Choices 1, 3 and 4 need
it and will ask when you pick them, which opens a second window. Choices 2 and 5
do not.

### 1 -- Scan and review

The main event. It scans, then prints one screen in four sections:

- **Startup items** -- what starts with your PC, what is already switched off
- **Installed apps** -- what is installed, and what it can and cannot judge
- **Junk files** -- caches and temporary files, per location
- **Services** -- background services set to start automatically

Rows are numbered. You type the numbers you want. It then prints the **plan** for
each pick -- exactly what it would do to that specific thing -- and asks you yes or
no, **once**. Nothing on your machine changes before that yes.

Two things you will notice, and both are intentional:

- **A lot of "Review needed".** The tool separates "I am sure what this is" from
  "a human must approve this regardless". Anything touching security software,
  drivers or things it cannot identify is held back on purpose.
- **"Unknown" in the installed apps section, a lot of it.** Windows does not record
  when most software was last used. Rather than guess, the tool says it does not
  know. An app it cannot judge is never flagged for removal.

### 2 -- Receipt

Reads the ledger and tells you what this tool has done to this machine, ever. It
reports only what was actually changed and how much disk was actually reclaimed.
It will never tell you your PC is faster, or estimate a benefit -- if it did not
measure it, it does not claim it.

### 3 -- Undo

Every change is recorded with an action id, which the receipt shows you. Undo takes
one id and puts that one change back.

It refuses to undo when it cannot be certain: if something else has altered the same
setting since, if the record does not say what the value was before, or if the
ledger says the change was attempted but never recorded an outcome. In each case it
tells you why and does nothing.

### 4 -- Restore point

Asks Windows for a System Restore checkpoint. This is a **best-effort extra layer,
not the safety net**. Windows allows at most one checkpoint per 24 hours and System
Restore is switched off entirely on many machines -- so it may decline, and it will
say so. The tool's own ledger is the real record.

---

## Where things live afterwards

- **`C:\ProgramData\win11-optimizer\actions.jsonl`** -- the ledger. One line per
  action, append-only, never rewritten. An undo is recorded as a new action that
  points at the one it reversed, so the history shows what happened *and* that it
  was put back.
- **`%LOCALAPPDATA%\win11-optimizer\logs\`** -- per-run logs. Disposable.

**Uninstalling removes the tool and the shortcut, and leaves
`C:\ProgramData\win11-optimizer\` exactly where it is.** The record of what was done
to a machine outlives the thing that did it -- that is the point of keeping one.

**A note before you share a log:** run logs and the ledger contain your machine name,
your user name and a list of your installed software. Read one before you attach it
to a bug report.

---

## If something goes wrong

- **The window closed instantly.** The launcher writes one line to
  `%TEMP%\win11-optimizer-bootstrap-<date>-<time>.log` when it cannot start, with
  the error in it.
- **It refuses to start, mentioning the ledger folder.** The permissions on
  `C:\ProgramData\win11-optimizer\` are not what the installer set. The error prints
  an `icacls` command you can paste from an administrator prompt to repair it.
  Repairing or reinstalling the `.msi` also fixes it.
- **It refused to do what you picked.** Read the reason it printed. In 0.1.0 the
  usual reason is the one at the top of this page: only the service startup-type
  route is carried out, and one refusal stops the whole run.
