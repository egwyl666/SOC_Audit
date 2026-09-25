# Changelog

## [1.4.1] — 2026-09-25

Fixes from the v1.4 run on a domain controller. Status: parser check and unit tests passed; **Windows run pending**.

### Fixed
- Step 2.10 failed with "Specified method is not supported": a helper function was named `FT`, which is the built-in
  alias of `Format-Table` (aliases take precedence over functions). Renamed to `ConvertFrom-AdFileTime` / `Get-AdProp`;
  all function names are now checked against built-in aliases.
- `auditpol /r` was parsed by English column headers. On a localized OS (RU/UA) the headers are translated, so every
  subcategory was read as "no auditing" — in step 3.10 and in the existing step 2.8. Columns are now read by position;
  anything unrecognised is reported as "unknown", not as "no auditing". Shared helper `Get-AuditSubcategory`.

### Changed
- README (EN/UK) rewritten in a plain style: no emoji, badges, HTML blocks or diagrams; content updated to v1.4.

## [1.4] — 2026-09-25

Active Directory — two new, independent steps that run **only on a domain controller** (elsewhere: one line in notes).
Status: parser check and unit tests passed (22 synthetic events for the AD event parser); **Windows run pending**.

### Added
- **Step 2.10 — AD configuration** (LDAP via System.DirectoryServices, read-only, no RSAT): kerberoastable users
  (SPN, RC4 allowed, privileged), AS-REP-roastable users (DONT_REQ_PREAUTH), unconstrained delegation on non-DCs,
  krbtgt password age, privileged accounts with PASSWD_NOTREQD / non-expiring password, all users with PASSWD_NOTREQD,
  ms-DS-MachineAccountQuota, minimum password length, lockout threshold, direct members of Domain/Enterprise/Schema
  Admins and Administrators (found by SID — independent of OS language).
  Output: `02_system\ad_config.csv`, `02_system\ad_risky_accounts.csv`.
- **Step 3.10 — AD attack signs in the Security log** (filtered in XPath so the `-MaxEvents` budget is spent on
  suspicious events only): Kerberoasting (4769 with RC4/DES, grouped by requester+IP, ≥5 SPNs → High), AS-REP roasting
  (4768 without preauth), Kerberos password spraying / brute-force (4771 0x18 by source / by account), DCSync (4662 with
  replication GUIDs from a non-machine account → Critical; MSOL_/AAD_ → High), privileged group changes
  (4728/4732/4756 and removals, by group SID + DnsAdmins), dangerous userAccountControl changes (4738/4742:
  no preauth, unconstrained / protocol-transition delegation, PASSWD_NOTREQD, DES), 5136 on msDS-KeyCredentialLink
  (Shadow Credentials), RBCD, gPCFileSysPath, user SPNs and ACL changes of AdminSDHolder / domain root.
  Audit coverage is checked first (7 subcategories); a subcategory that is not audited is reported —
  "no events" then proves nothing. Output: `03_eventlogs\ad_attack_findings.csv`, `ad_attack_events.csv`,
  `ad_audit_coverage.csv`; flags, timeline, report section **5.1 Active Directory**.

### Changed
- Step 2.9: on a DC `LmCompatibilityLevel` < 5 is now a Medium risk (the DC accepts NTLMv1 from clients).
- Step 2.9: firewall `DefaultInbound = NotConfigured` is shown as "NotConfigured (= Block by default)".

## [1.3] — 2026-09-25

New, independent steps only — existing steps are unchanged (except the order inside the 1.1 snapshot).
Status: parser check and unit tests passed; **Windows run pending**.

### Added
- **Step 2.9 — security configuration audit** (`02_system\security_config_audit.csv`, report section 4.1): SMBv1 and
  SMB signing, LLMNR, NetBIOS over TCP/IP, WDigest `UseLogonCredential`, LSA protection (RunAsPPL), Credential Guard,
  LM hash storage, LmCompatibilityLevel, anonymous SAM enumeration, UAC (`EnableLUA`, admin prompt,
  `LocalAccountTokenFilterPolicy`), RDP NLA, PowerShell v2, BitLocker on the system drive, Defender ASR rules, LAPS,
  Guest account, Print Spooler on a DC, firewall profiles, age of the last installed update.
  Each row: current / recommended / status / fix / why. Risks rated High or Medium become flags (area "Конфігурація").
  DC-aware: Credential Guard and LAPS are N/A on a domain controller; Spooler is checked as a DC risk.
- **Step 3.9 — full export of original event logs** (`wevtutil epl`) to `03_eventlogs\evtx\` with SHA256 in
  `integrity_copies.csv`, custody and `evtx_export.csv`: every log from the event-log health check plus WMI-Activity,
  BITS, WinRM, RDPClient, SMBServer/Security, NTLM/Operational, Directory Service and DNS Server when present.
  Switch `-NoEvtx` skips it.

### Changed
- Step 1.1 snapshot order: netstat → TCP → processes → UDP (on a DC/DNS server UDP enumeration takes ~8 s;
  UDP is already captured by netstat).

## [1.2] — 2026-09-25

Driven by the v1.1 test run on a domain controller (64- and 32-bit). Status: parser check and unit tests passed;
**Windows re-run pending**.

### Fixed
- `pfirewall.log` was parsed and copied twice when firewall profiles spelled the path with different case
  (`system32` / `System32`) — ALLOW/DROP counters and per-source totals were doubled. Paths are now de-duplicated
  case-insensitively.
- Bare executable names in task actions and command lines (`sc.exe`, `powershell.exe`, `BthUdTask.exe`) were
  classified as "non-standard path" → false High flags on built-in `\Microsoft\` tasks (regression from 1.1) and on
  third-party tasks. New `Resolve-BareExe` resolves them via System32 / Windows / wbem / WindowsPowerShell / SysWOW64.
- Firewall rules whose program is `System` (kernel) were flagged "program in non-standard path" (69 false flags on DC).
- Microsoft-signed binaries in `C:\Windows\<subfolder>` (ADWS, AzureArcSetup…) are no longer flagged for location;
  unsigned files there (e.g. `C:\Windows\KMSAutoS`) still are.
- Locked sources (active `pfirewall.log`, History of a running browser) got `COPY-ONLY`: the hash before/after is now
  computed via a shared-read stream, so copies are verified or reported as `SOURCE_CHANGED`.

### Changed
- 4624 is queried in two parts with separate limits — interactive/RDP (2/7/10/11) and network (3) — and service SIDs
  (S-1-5-18/19/20/7) are excluded in XPath, so network logons on a DC no longer push RDP/interactive logons out of the sample.
- 32-bit PowerShell on 64-bit Windows: when started with `-File`, the script re-launches itself in 64-bit PowerShell
  (`Sysnative`) with the same parameters (the test showed WOW64 distortions: empty `Winlogon\Userinit`,
  "missing" `lsass.exe`). Otherwise it warns as before.
- Step 1.1 captures `netstat -ano` first (`01_volatile\netstat_ano.txt`) and records the time of each source in custody.
- Host role (workstation / DC / server) is recorded; on a DC, SMB/RPC from internal addresses without drops is no longer
  a pfirewall.log heuristic hit. RDP/WinRM/SSH and SMB/RPC are now separate heuristics.

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
