# Changelog

## [1.9.1] — 2026-09-28

Fixes after the DC01 run of 1.9.0.

### Fixed
- Step 2.12: Active Setup entries whose StubPath is not a file path (`U`, `/UserInstall` — known Windows leftovers,
  shown by Autoruns as "File not found") were flagged "Середньо — Файл відсутній". They are now listed as
  "Інфо — Не шлях до файлу (штатний залишок Windows)".
- Report, 4624 table: the `Elevated` column showed raw `%%1842` / `%%1843`; now "Так" / "Ні".
- Unit tests: two IPv6 checks still used the old test address after the IOC addresses were changed on `main`.

## [1.9.0] — 2026-09-25

Extended persistence.

### Added
- Step **2.12 "Розширена персистентність"** (`02_system\persistence_extended.csv`, report section 9), read-only:
  LSA Authentication / Notification / Security Packages (T1547.002, T1547.005, T1556.002), AppInit_DLLs with
  LoadAppInit_DLLs (T1546.010), AppCertDlls (T1546.009), Winlogon Notify / GinaDLL / Taskman and per-user Shell /
  Userinit (T1547.004), screensaver (T1546.002), Session Manager BootExecute / SetupExecute / Execute, Active Setup
  StubPath (T1547.014), COM hijack — a user CLSID overriding a system one (T1546.015), netsh helpers (T1546.007),
  Print Monitors (T1547.010), Time Providers (T1547.003), SilentProcessExit MonitorProcess (T1546.012), running
  drivers without a valid signature or outside System32\drivers.
- Verdict per DLL/EXE by presence and signature: Microsoft signature = normal; another valid signature = Інфо
  (Середньо if in a user folder); no valid signature = Високо; missing file = Середньо; IOC hash = Критично.
  Високо / Середньо rows become flags.
- Tests for the verdict logic; the smoke run checks `persistence_extended.csv`.

### Fixed
- **Event-log steps 3.1–3.10 lost their results for the report.** Inside these steps the per-event variable `$d`
  shadowed the global data store `$D` (PowerShell variable names are case-insensitive). After the first parsed event,
  every `$D.X = …` in that step went into the local variable: the CSV files were written correctly, but the report,
  brute-force summary, correlation and flags saw empty data. Present since the original version; renamed to `$evd`.
- New unit test: no `Invoke-Step` block may assign or loop over a variable named `$d` / `$D`.

## [1.8.0] — 2026-09-25

Safe defaults.

### Changed
- **No built-in IOCs.** `-NamePatterns`, `-KnownPaths`, `-IocSha256`, `-IocIPs` are empty by default. Without any IOC
  parameter the run is a host audit: configuration, logs and artifacts are collected in full; the disk search by
  masks (5.2) and the USN extract (5.9) are skipped with a note; the report shows a banner.
- The KMSAuto test IOCs moved behind a new switch `-TestIoc` (same behaviour as before: mask-only flags lowered to
  "Інфо" and marked "[тестова маска]").

### Added
- Warning (console, collection notes, report banner) when `-OutRoot` is on the system drive of the examined host:
  writing evidence there can overwrite free space that still holds deleted files.
- `-EncryptZip`: password-protected ZIP (AES-256) via 7-Zip if installed. 7-Zip asks for the password in the console,
  so it never appears on the command line, in 4688 or in PowerShell history. Without 7-Zip a plain ZIP is created and
  a warning is shown.

## [1.7.2] — 2026-09-25

### Fixed
- Step 5.6 (Zone.Identifier) failed with "The parameter is incorrect" when `Get-Item -Stream` hit a file it cannot
  query (non-NTFS volume, unusual path): that error is terminating and ignored `-ErrorAction SilentlyContinue`.
  Each file is now checked separately; unreadable files are skipped and counted in the collection notes.

## [1.7.1] — 2026-09-25

Event visibility by category — the analyst's manual "what can we see" table, built automatically.
Status: parser check and unit tests pass; Windows validation in CI; runs on DC01 / Pro to follow.

### Added
- Step **2.11 "Видимість за категоріями подій"** (`02_system\event_visibility.csv`). For each category — logons
  (4624/4625/4648/4672/4634/4647/4776), RDP (21/24/25/1149), process creation (4688, Sysmon 1), Sysmon 3, PowerShell
  (4104, 4103, transcription), services (4697/7045), tasks (4698-4702, TaskScheduler 106/140/141), network (5156,
  5152/5157), firewall rule changes (4946-4948, 2004-2006/2097), user and group management, audit policy change (4719),
  log clearing (1102/104), file shares (5140/5145), file access (4663), Defender (1116/1117), WMI-Activity, WinRM, and on
  a DC Kerberos (4768/4771, 4769), DS Access (4662) and DS Changes (5136):
  - the state of the source: auditpol subcategory by GUID (no locale dependence), channel, or registry policy;
  - the actual number of events in the last 24 h by Event ID (EventLogReader, per-ID breakdown, limit 100 000);
  - status Бачимо / Частково / НЕ бачимо / Невідомо and a generated comment; alternative sources are taken into
    account (7045 in System, TaskScheduler channel, pfirewall.log, Firewall channel) as "Частково".
- Report: subsection **1.2 "Перевірка видимості за категоріями подій"** under the log stability table, with a
  summary line and colour by status.
- One new flag (Середньо): an audit subcategory is off now, but its events exist in the last 24 h — the audit policy
  may have been changed recently. Disabled audit itself is already flagged by step 2.8, so it is not duplicated.
- Tests: status logic, XPath, step 2.11 on stub data (workstation and DC), per-ID counts compared with `Get-WinEvent`
  on Windows; smoke run checks `event_visibility.csv`.

## [1.7.0] — 2026-09-25

Complete source data and a clearer report. Flags and highlighting still work on the same subsets, so there is no extra noise.
Status: parser check and unit tests pass; Windows validation in CI; runs on DC01 / Pro to follow.

### Changed — source CSVs are no longer pre-filtered
- **Firewall rules:** all rules, including disabled ones (`04_firewall\fw_rules_all.csv`, column `Enabled`);
  `fw_rules_enabled.csv` is kept.
- **Scheduled tasks:** every task, including the built-in `\Microsoft\` ones (`02_system\scheduled_tasks_all.csv`,
  column `Suspicious`); `scheduled_tasks_nonms_or_suspicious.csv` is kept.
- **Prefetch:** every `.pf` file (`05_artifacts\prefetch_all.csv`, column `Match`), not only mask matches.
- **ARP/NDP:** all neighbour states (Unreachable / Permanent were dropped before).
- **Defender:** all properties of `Get-MpComputerStatus` and `Get-MpPreference` (`02_system\defender_full.csv`).
- **Event logs:** inventory of every channel on the host (`02_system\eventlog_inventory.csv`); the health check also
  covers WMI-Activity, WinRM, BITS, SMBServer/Security, NTLM/Operational, RDPClient, Directory Service and DNS Server
  (for reference only, no flags); new column `Events24h`.

### Added
- Report section **1.1 "Стабільність надходження логів"**, opened by default:
  - table: channel, events in the last 24 h (exact count by event time via EventLogReader; for channels with more
    than 100 000 events a day — an estimate from the RecordId difference, marked "≈"), total records,
    max size, fill %, history days, mode, state;
  - disabled channels and channels that do not cover the window are highlighted;
  - numbers use thousands separators;
  - below it a "Показник / Значення" table: snapshot time, Security history depth and window coverage, Sysmon, 4104,
    command line in 4688, disabled / absent channels, channel totals.
- Full tables in the report: all firewall rules (disabled ones greyed), all scheduled tasks, all log channels, all
  Prefetch files, full Defender state.
- Table sorting treats "33 744" and "15,1" as numbers.

### Fixed (found by CI on v1.6.0)
- Amcache working copy stayed mounted: keys opened through the PowerShell registry provider kept handles, so
  `reg unload` failed. Amcache is now read with .NET `RegistryKey` and every key is closed explicitly.
- Smoke test counted 0 rows for every CSV in Windows PowerShell 5.1 (`PSObject.Properties` has no `.Count` there).
- Duplicate lines in collection notes.
- Events per 24 h: the first version used only the RecordId difference; CI showed it can overcount (354 vs 329 on a
  freshly booted VM whose clock was corrected, record order ≠ time order). Now counted exactly.

## [1.6.0] — 2026-09-25

Execution traces — "was the file run, by whom and when" where Prefetch is off (servers) and 4688/Sysmon are not set up.
One new, independent step; existing steps unchanged. Status: parser check, 157 unit tests (incl. synthetic
UserAssist/ShimCache blobs); Windows validation in CI (smoke run now uses `-CollectHives`).

### Added
- **Step 5.10 — execution traces**, report section **13.1**, CSVs in `05_artifacts\`:
  - **UserAssist** for loaded user hives: decoded (ROT13) program path with KNOWNFOLDER GUIDs resolved, run count,
    focus count/time, last run time (Win7+ 72-byte and XP 16-byte formats).
  - **RunMRU** (Win+R history) in MRU order, each command checked with the existing LOLBin / suspicious-argument /
    IOC logic.
  - **ShimCache / AppCompatCache** (Windows 10/11, Server 2016+): path, file modification time, order. Clearly
    labelled as "seen by the system", not proof of execution.
  - **Amcache** (with `-CollectHives`): `reg load` of a *working copy* of the verified copy → InventoryApplicationFile
    (path, SHA1, publisher, version, link date) → `reg unload`, recorded in custody; the working copy is deleted.
- Parameter **`-IocSha1`** — matched against Amcache SHA1; hits go to IOC matches and are Critical flags.
- Flags (area "Виконання") for mask/IOC matches; RunMRU flagged only for suspicious arguments or IOC matches.
  Timeline entries for UserAssist last runs and ShimCache file dates of matches.

### Changed
- CI runs on push only for `main` (pull requests are still checked), no more duplicate runs.
- Smoke test runs with `-CollectHives`, prints execution-trace row counts and fails if an Amcache hive is left mounted.

## [1.5.0] — 2026-09-25

First step of the road to 2.0: automated checks on real Windows. The collector's behaviour is unchanged.

### Added
- `tests/run-tests.ps1` — 139 unit tests without external modules (functions are taken from the script via AST, the
  script itself is not run): IOC IP boundaries, `\Microsoft\` task heuristics, bare-exe resolution, hashing of files open
  for writing, chunked string search, `auditpol` parsing (EN/RU/UA, 6 and 7 columns), FILETIME, AD attack signs,
  default-IOC flag lowering, function names vs built-in aliases, step 2.9 run for a workstation and a DC.
- `tests/check-encoding.ps1` — all `*.ps1` must be UTF-8 with BOM and CRLF.
- `tests/smoke.ps1` — full collection in a separate process; fails on a non-zero exit code, missing report/manifest
  or any step with status `ПОМИЛКА`.
- `.github/workflows/ci.yml` — on every push / PR on `windows-latest`: encoding, PSScriptAnalyzer (errors + PS 5.1
  syntax), unit tests in Windows PowerShell 5.1 and PowerShell 7, smoke run, report uploaded as an artifact.

### Fixed
- Default-IOC detection copies `$PSBoundParameters` into a variable before `Where-Object`, so it does not depend on
  how the script block scope resolves automatic variables.

## [1.4.4] — 2026-09-25

### Changed
- When none of `-NamePatterns` / `-IocSha256` / `-IocIPs` / `-KnownPaths` is passed, the test KMSAuto IOCs are used:
  a yellow console warning, a collection note and a report banner say so, and flags whose only basis is a file-name
  mask match are lowered from Medium to Info and marked "[тестова маска]". IOC hash / IOC IP flags are not affected;
  with case IOCs everything works as before. (On the DC run 29 of 55 Medium flags were such mask noise.)
- Wording of the note about a disabled AD audit subcategory.

## [1.4.3] — 2026-09-25

### Added
- Step 2.10: new check "Non-standard direct members of Administrators on a DC". The built-in Administrators group on
  a domain controller equals domain admin rights; expected direct members are only Administrator (RID 500), Domain
  Admins (512) and Enterprise Admins (519). Anyone else is reported as a Medium risk with object class.

## [1.4.2] — 2026-09-25

### Fixed
- `auditpol`: the Russian "Без аудита" (no auditing) was not recognised and was shown as "not recognised". Matching now
  uses word stems (`без аудит`, `нет аудит`, `немає аудит`, `no auditing`). Confirmed on the DC: localized `auditpol /r`
  has 6 columns (no "Setting Value"), so the text column is used.

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
