# Changelog

## [1.1] — 2026-09-25

Status: parser check (PowerShell 7.4) and unit tests of the changed functions passed; **a full run on Windows / PS 5.1 is still pending**.

### Added
- Pre-launch environment check, before anything is written to disk: `#Requires -Version 5.1` plus a runtime check
  (PS < 5.1, pwsh on non-Windows, non-`FullLanguage` mode → clear message and exit code `2`;
  32-bit PowerShell on 64-bit OS and old WMF 5.1 builds → warning, recorded in collection notes).
- SQLite sidecar files (`-wal`, `-journal`, `-shm`) are copied next to browser / Windows Timeline databases with the same
  prefix and verified hashes; `-wal`/`-journal` are also searched for hints.

### Changed
- Order of volatility (NIST SP 800-86 5.1.2): new step 1.1 takes a fast raw snapshot (TCP/UDP → processes);
  owner/hash/signature enrichment runs afterwards on that snapshot. Steps 1.x renumbered (1.1–1.6).
- Scheduled tasks under `\Microsoft\*` are no longer skipped wholesale: a task is kept when its action is in a
  user/non-standard path, has IOC/suspicious arguments, or runs an interpreter (powershell, cmd, mshta, rundll32…)
  with a non-Microsoft author. TaskScheduler events under `\Microsoft\*` are kept when registered/changed by a
  real user account or when the action is suspicious. Flagged as "Маскування під \Microsoft\" (High).
- Event log sampling cut by `-MaxEvents` now states from which time events were kept, and the flag is Medium (was Info).
- `Get-StringHints` reads databases in 4 MB chunks with overlap instead of loading the whole file into memory.

### Fixed
- IOC IPs were matched as substrings (`10.9.0.20` matched `110.9.0.201` and `10.9.0.200`). Text search now respects
  address boundaries; exact comparisons normalise brackets and IPv6 zone ids.
- `-ExcludeDirs 'a,b'` via `-File` was not split, because `OutRoot` was appended before `Split-ListParam`.
- `-OutRoot E:\` added `\` to exclusions and silently disabled the wide search; now only the case folder is excluded.
- PowerShell 4104: script blocks that are the collector's own code (same path or a fragment of its text) are skipped
  and counted in collection notes, instead of raising false "suspicious script block" flags.
- `.gitattributes` restored (it was committed as `gitattributes.txt` and had no effect).
- Duplicate `$Keywords` computation removed.

## [1.0]
- Initial version: tested on Windows 11 / PowerShell 5.1.26100, 34/34 steps OK.
