# soc-collect.ps1 — command reference

English | [Українська](README.uk.md)

**SOC Live Response Collector v1.4.3** — a single script for evidence collection and first-pass analysis of a Windows host
(replaces the old main audit + `fwlog.ps1` + `filesinter.ps1`). Aligned with **NIST SP 800-86**.

The script collects volatile data, persistence, event logs, `pfirewall.log` and file artifacts, checks security
settings and, on a domain controller, the AD configuration and signs of attacks on it. Output: a self-contained HTML
report, CSV files, a UTC timeline, chain of custody and a SHA256 manifest. Change history: [CHANGELOG](CHANGELOG.md).

The script's console output and report are in Ukrainian.

---

## 1. Requirements

| What | Requirement |
|---|---|
| PowerShell | **Windows PowerShell 5.1** (built into Windows 10/11, Server 2016+) or PowerShell 7.x on Windows |
| Privileges | **Administrator** (without it there is no Security log, BAM and some other data; the script warns you) |
| OS | Windows 10 / 11, Windows Server 2016 / 2019 / 2022 / 2025 |
| File encoding | UTF-8 **with BOM** — don't re-save it without BOM, or Cyrillic breaks in 5.1 |
| Third-party tools | None (for AD as well: no RSAT, no ActiveDirectory module) |

Before anything is written to disk the script checks the environment: PowerShell version (`#Requires -Version 5.1`),
Windows, `FullLanguage` mode. If something is wrong it prints a clear message and exits with code `2`.
32-bit PowerShell on a 64-bit OS started via `-File` re-launches itself in 64-bit automatically.

> Tested: v1.0 — Windows 11 / PS 5.1.26100, 34/34 steps; v1.1–v1.3 — domain controller (Windows Server, PS 5.1),
> 64- and 32-bit, all steps OK. v1.4.1 — DC OK (AD steps and localized auditpol parsing). v1.4.2 — one fix for recognising "Без аудита".

Get the script via **Download raw file** or `git clone` — the repository stores it byte-for-byte (BOM + CRLF,
see `.gitattributes`). Copy-pasting from the GitHub page may drop the BOM.

---

## 2. How to run

### 2.1 Via `-File` — recommended

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\1\soc-collect.ps1 -CaseId INC-0922
```

- SHA256 is computed from the script file itself (best option for chain of custody).
- **Lists are passed as one comma-separated string** — the script splits them:
  ```powershell
  -IocIPs '192.168.77.51,10.9.0.20' -NamePatterns '*KMS*,*SECOPatcher*'
  ```

### 2.2 Via scriptblock

```powershell
powershell.exe -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Get-Content -Raw -Encoding UTF8 'C:\1\soc-collect.ps1'))) -CaseId INC-0922 -IocIPs @('192.168.77.51','10.9.0.20')"
```

- Arrays work natively via `@(...)`.
- The hash is taken from the script text (may differ from the file hash because of BOM/line endings — the report says so).
- The 32→64-bit re-launch does not work in this mode — run the 64-bit `powershell.exe`.

### 2.3 From an already open elevated console

```powershell
Set-ExecutionPolicy -Scope Process Bypass
cd C:\1
.\soc-collect.ps1 -CaseId INC-0922 -Hours 72
```

### 2.4 Remotely (WinRM)

```powershell
Invoke-Command -ComputerName PC-17 -FilePath C:\1\soc-collect.ps1 -ArgumentList 'HUNT-PC17'
```

- `-ArgumentList` passes parameters **by position only** (the first one is `CaseId`).
- Results stay on the remote host in `C:\SOC_Evidence` — retrieve them after collection.

---

## 3. Parameters

### Case and time window

| Parameter | Default | Description |
|---|---|---|
| `-CaseId` | `INC-testPC_1-KMSAuto` | Case identifier (used in folder and report names) |
| `-Analyst` | — | Analyst name for chain of custody |
| `-Hours` | `48` | Log window: last N hours (if `-Since` is not set) |
| `-Since` | now − `Hours` | Window start, **ISO format**: `'2026-09-22 00:00'` |
| `-Until` | start of run | Window end |

> Note: dates must be `yyyy-MM-dd HH:mm`. PowerShell will not parse `22.09.2026`.

### IOCs and search

| Parameter | Default | Description |
|---|---|---|
| `-NamePatterns` | `*KMS*`, `*activ*`, `*SECOPatcher*` | File name masks (disk search, LNK, BAM, Prefetch, Recycle Bin, browser history) |
| `-KnownPaths` | KMSAuto paths | Specific files/folders: hash, signature, MAC before/after, Zone.Identifier |
| `-IocSha256` | KMSAuto++ and archive hashes | Matched against files, processes, services, Sysmon |
| `-IocIPs` | `192.168.77.51`, `fe80::1a2b:…`, `10.9.0.20` | Matched against connections, ARP/NDP, pfirewall.log, RDP, 4625, KMS registry. Whole-address match only (`10.9.0.20` does not match `110.9.0.201`) |
| `-SearchRoots` | all local and removable drives | Where to search for files |
| `-ExcludeDirs` | WinSxS, DriverStore, servicing… | Path fragments to skip |

> Note: **for a new case you must change the masks and IOCs.** The defaults belong to the KMSAuto test case —
> elsewhere `*activ*` gives many false positives (Active Directory, ActiveX, Wazuh `active-response`).

### Output location

| Parameter | Default | Description |
|---|---|---|
| `-OutRoot` | `C:\SOC_Evidence` | Root folder for results |

> **NIST:** don't write evidence to the disk under investigation — writes overwrite free space that may still hold
> deleted files. For serious cases use `-OutRoot E:\Evidence` (USB / external drive).

### Limits

| Parameter | Default | Description |
|---|---|---|
| `-MaxEvents` | `5000` | Max events per log query. If the report says "limit reached" — raise it |
| `-MaxHashMB` | `300` | Files larger than this are not hashed |
| `-HtmlMaxRows` | `400` | Rows per table in HTML (CSV always has full data) |

### Switches

| Switch | What it does | When to use |
|---|---|---|
| `-SkipWideSearch` | No search across all drives | Quick triage (this is the longest step) |
| `-SkipEvidenceCopy` | No copies of browser history / Timeline / PS history / pfirewall.log | Hunting across many hosts |
| `-NoEvtx` | No export of original `.evtx` logs (step 3.9) | Hunting / little disk space. On a DC the Security log can be 1+ GB |
| `-CollectHives` | `reg save` SYSTEM/SOFTWARE + Amcache via `esentutl /vss` | Deep forensics. Note: creates a shadow copy — modifies the system (recorded in custody) |
| `-UsnJournal` | USN journal extract by masks | When you need to know when files were created/deleted. Slow |
| `-NoZip` | No ZIP archive | When you don't need the archive |

---

## 4. Typical scenarios

### Full incident investigation

```powershell
.\soc-collect.ps1 -CaseId INC-0922 -Analyst "Surname" `
  -Since '2026-09-22 00:00' -Until '2026-09-23 00:00' -OutRoot E:\Evidence
```

### Quick triage (~2–5 min)

```powershell
.\soc-collect.ps1 -CaseId TRIAGE-PC17 -Hours 24 -SkipWideSearch -SkipEvidenceCopy -NoEvtx -NoZip
```

### Threat hunting on other hosts (same IOCs)

```powershell
.\soc-collect.ps1 -CaseId HUNT-PC17 -Since '2026-09-15 00:00' -SkipEvidenceCopy -NoEvtx `
  -IocIPs '192.168.77.51,10.9.0.20' -NamePatterns '*KMS*,*SECOPatcher*'
```

Check the **IOC matches** and **Authentication / brute-force** sections.

### Domain controller

```powershell
.\soc-collect.ps1 -CaseId AUDIT-DC01 -Hours 72 -SkipWideSearch -OutRoot E:\Evidence
```

The AD steps (2.10, 3.10) turn on automatically when the host is a domain controller. See report sections
**4.1 Security settings** and **5.1 Active Directory**.

### Deep forensics

```powershell
.\soc-collect.ps1 -CaseId INC-0922-DEEP -CollectHives -UsnJournal -MaxEvents 50000 -OutRoot E:\Evidence
```

### Checking a "clean" system / new case

```powershell
.\soc-collect.ps1 -CaseId CHECK-HOME -Hours 168 -NamePatterns '*anydesk*,*rat*' -IocIPs '0.0.0.0' -KnownPaths 'C:\nonexistent'
```

---

## 5. Collection stages (NIST order: volatile data first)

| Stage | What is collected |
|---|---|
| **0. Pre-flight** | Script SHA256, time/timezone/NTP, NTFS last-access, Prefetch, user profiles, host role (workstation / server / DC) |
| **1. Volatile** | Fast snapshot first: `netstat -ano`, TCP, processes, UDP. Then ARP/NDP, DNS cache, IP/routes, SMB. Only after that — process owner/hash/signature and sessions |
| **2. System** | Accounts, admins, policies, services, scheduled tasks (author from XML), autoruns, WMI, Defender, licensing/KMS, firewall, event logs (size/depth/coverage) and audit policy |
| **2.9 Security settings** | SMBv1 and SMB signing, LLMNR/NetBIOS, WDigest, LSA protection (RunAsPPL), Credential Guard, LM/NTLM, UAC, RDP NLA, PowerShell v2, BitLocker, ASR rules, LAPS, Guest account, Print Spooler on a DC, firewall profiles, age of the last update |
| **2.10 AD configuration** (DC only) | Kerberoastable and AS-REP-roastable accounts, unconstrained delegation, krbtgt password age, privileged account flags, MachineAccountQuota, password and lockout policy, privileged group members |
| **3. Logs for the window** | 4625/4624/4648/4740/4776, account changes, log clearing, RDP (1149, 21–25, 131, 140), services (7045/4697/7040), tasks (4698–4702, TaskScheduler), firewall changes (2004–2006, 2033, 2052, 2097, 2099, 4946–4950), Defender, LOLBin/IOC executions (Sysmon 1 / 4688), Sysmon 11/13/3, PowerShell 4104 |
| **3.9 Original logs** | Full `.evtx` export (`wevtutil epl`) with SHA256 — for re-analysis with Hayabusa / Chainsaw / EvtxECmd |
| **3.10 AD attack signs** (DC only) | Kerberoasting (4769 RC4), AS-REP roasting (4768), Kerberos spraying (4771), DCSync (4662), privileged group changes, dangerous userAccountControl changes, 5136 (Shadow Credentials, RBCD, GPO, AdminSDHolder and domain-root ACL). First checks whether these events are audited at all |
| **4. pfirewall.log** | Summary by port and source, ALLOW/DROP, first/last, heuristics (ICMP recon, RDP/WinRM/SSH, SMB/RPC, scanning), IOC IPs |
| **5. File artifacts** | Known paths, mask search, LNK (with target), BAM/DAM, Prefetch, Recycle Bin ($I), Zone.Identifier, copies of browser history / Windows Timeline (with `-wal`/`-journal`) / PS history with hint search |
| **6. Analysis** | Brute-force summary, 4625 ↔ firewall ↔ RDP correlation, IOC matches, automatic flags |
| **7–9. Report** | Timeline (UTC), HTML, chain of custody, SHA256 manifest, ZIP + hash |

---

## 6. Output

```
C:\SOC_Evidence\<CaseId>_<HOST>_<yyyyMMdd_HHmmss>Z\
├── report.html                  ← main report (open in a browser)
├── findings_auto.csv            ← automatic flags
├── timeline_full.csv            ← full timeline (UTC + local time)
├── ioc_hits.csv                 ← all IOC matches
├── integrity_copies.csv         ← hash before / copy / after for every copy and export
├── chain_of_custody.log / .csv  ← every action: seq, UTC, operator, object, result
├── collection_steps.csv         ← collection steps, status, errors with line number
├── collection_notes.txt         ← collection limitations (truncated logs, disabled auditing, etc.)
├── manifest.csv                 ← SHA256 of every case file
├── manifest.csv.sha256          ← manifest hash
├── 00_tool\                     ← copy of the script used for collection
├── 01_volatile\                 ← processes, network, netstat_ano.txt, sessions
├── 02_system\                   ← system; security_config_audit.csv; on a DC — ad_config.csv, ad_risky_accounts.csv
├── 03_eventlogs\                ← log extracts; on a DC — ad_attack_findings.csv, ad_attack_events.csv, ad_audit_coverage.csv
│   └── evtx\                    ← original .evtx logs + evtx_export.csv
├── 04_firewall\  05_artifacts\
└── 06_evidence_copies\          ← verified copies (browsers, pfirewall.log, hives)
<CaseDir>.zip  +  <CaseDir>.zip.sha256
```

**For the ticket:** record the SHA256 of the manifest and the archive (printed at the end) — this is your integrity checkpoint.

### HTML report

- Sidebar navigation — 19 sections, incl. "4.1 Security settings" and "5.1 Active Directory" (on a DC)
- Counter cards and a flag table with severity (Critical / High / Medium / Info)
- Every table has a **filter** (search box) and **sorting** (click a header)
- Row highlighting: red — IOC / critical, orange — suspicious, green — VERIFIED / OK
- Settings tables show current value, recommended value, fix command and why it matters
- Fully self-contained (no external resources) — opens on an isolated machine

> Flags are **hints**, not conclusions. The analyst draws conclusions after checking several independent sources (NIST 8.3).

---

## 7. PowerShell 5.1 compatibility

| Topic | Status |
|---|---|
| Syntax | No PS7-only constructs (`??`, `?:`, `&&`, `-Parallel`) |
| Encoding | UTF-8 with BOM — 5.1 reads Cyrillic correctly |
| Modules | Built-in only: NetSecurity, NetTCPIP, ScheduledTasks, Defender, LocalAccounts, CimCmdlets, SmbShare; for AD — System.DirectoryServices |
| OS localization | Event data is read from XML (not localized text); `auditpol` is parsed by column position (headers are translated on RU/UA systems); AD groups are found by SID |

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ПОМИЛКА: потрібен PowerShell 5.1+` or a `#requires` error | Install WMF 5.1 or run via `powershell.exe` (5.1) / `pwsh.exe` (7.x) |
| `ПОМИЛКА: LanguageMode = ConstrainedLanguage` | AppLocker/WDAC restricts PowerShell; run from an allowed admin context or whitelist the script |
| Warning about 32-bit PowerShell | With `-File` the script re-launches itself in 64-bit. Otherwise run `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `cannot be loaded because running scripts is disabled` | Add `-ExecutionPolicy Bypass` or run `Set-ExecutionPolicy -Scope Process Bypass` |
| Garbled Cyrillic | The file was re-saved without BOM. Save as **UTF-8 with BOM** or run via scriptblock with `-Encoding UTF8` |
| `Cannot convert value … to type System.DateTime` | Date isn't ISO. Use `'2026-09-22 00:00'` |
| IOC list recognized as a single item | With `-File`, pass it comma-separated in one string: `'a,b,c'` |
| Empty Security log, BAM | Not running as Administrator |
| Report says "limit of N events reached" | Raise `-MaxEvents` |
| `COPY-ONLY` in copy verification | The source could not be hashed even with shared read. The copy hash is recorded |
| `SOURCE_CHANGED` for pfirewall.log | The active log is appended during copy — expected; the copy is the evidence |
| `EXPORT` in verification for `.evtx` | A live log cannot be hashed before/after — the exported file hash is recorded |
| A step has status `ПОМИЛКА` (error) | See `collection_steps.csv`: error text and **line number**. Other steps are unaffected |
| AD: "audit subcategory not enabled" | Those events won't exist even during an attack. The enable command is in the Fix column (`ad_audit_coverage.csv`) |
| Empty Prefetch | Prefetch is disabled by default on Windows Server — not proof that nothing ran |
| "Investigation window not covered" | The log is too small and has already rolled over. The command to enlarge it is in the Advice column |
| Many "IOC mask match" flags | Masks/IOCs from another case. Adjust `-NamePatterns` to the case |

---

## 9. Limitations (honestly)

- **Live response** — no write blocker and no bit-stream image. For court-grade evidence, take a VM snapshot/image first.
- No memory dump.
- `.evtx` logs are exported in full (`wevtutil epl`) — an export, not a byte copy of the log file.
- Browser history / Timeline are analyzed by string search (no SQLite) — no exact timestamps; for timing, open the copies in DB Browser for SQLite.
- Privileged AD group membership — direct members only; check nested groups separately.
- AD attack signs are visible only when the corresponding audit subcategories are enabled (the script checks this and reports it).
- Recommended log sizes are approximate (for busy servers / DCs, Security ≥ 4 GB).
- An IP address in correlation is a **candidate**, not proof of identity (NIST 6.4.4).
