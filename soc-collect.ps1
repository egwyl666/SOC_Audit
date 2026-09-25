<#
.SYNOPSIS
    SOC Live Response Collector v1.4.2 — єдиний скрипт збору доказів і первинного аналізу Windows-хоста.
    Об'єднує: основний аудит (служби / задачі / firewall / журнали), fwlog (pfirewall.log) і filesinter (файлові артефакти).
    Узгоджено з NIST SP 800-86: Collection -> Examination -> Analysis -> Reporting,
    "спочатку волатильні дані", hash ДО і ПІСЛЯ копіювання, chain of custody, фіксація версії інструмента.

.DESCRIPTION
    Етапи:
      0. Pre-flight — права, SHA256 самого скрипта, час/таймзона/NTP, NTFS last-access, Prefetch, профілі.
      1. Волатильні дані — процеси (+hash/підпис), TCP/UDP, сесії, ARP/NDP, DNS-кеш, IP/маршрути, SMB.
      2. Система та персистентність — облікові записи, політики, служби, задачі (автор з XML), Run/Startup/WMI,
         Defender (стан + винятки), ліцензування/KMS, firewall (профілі, логування, правила).
      3. Журнали подій за вікно — 4625/4624/4648/4740/4776, RDP (1149, 21-25, 131, 140), служби (7045/4697/7040),
         задачі (4698-4702 + TaskScheduler), зміни firewall (2004-2006/2033/2052/2097/2099, 4946-4950),
         Defender, очищення журналів, LOLBin/IOC-запуски (Sysmon 1 / 4688), Sysmon 11/13/3 за IOC, PowerShell 4104.
      4. pfirewall.log — зведення по портах і джерелах (allow/drop, first/last), IOC IP.
      5. Файлові артефакти — відомі шляхи, пошук за масками по всіх дисках, Zone.Identifier, LNK (з ціллю),
         BAM, Prefetch, кошик ($I), історія браузерів / Windows Timeline / PowerShell history (копії з hash до/після).
      6. Аналіз — зведення brute-force, кореляція 4625 <-> firewall <-> RDP, IOC-матчі, автоматичні прапорці.
      7. Звіт — єдиний timeline (UTC), HTML, CSV, chain of custody, маніфест SHA256, ZIP + hash.

    ЧЕСНО ПРО ОБМЕЖЕННЯ (NIST SP 800-86, 3.1.3 / 4.2.3):
      * Це LIVE RESPONSE на працюючій системі — без write blocker і без bit-stream образу.
        Скрипт нічого не змінює й не видаляє, але читання файлу може оновити LastAccessTime,
        якщо NTFS last-access увімкнено. Тому MAC-часи фіксуються ДО читання, перевіряються ПІСЛЯ,
        а файли зі зміненим Accessed позначаються у звіті.
      * Копії доказів верифікуються: hash джерела ДО -> hash копії -> hash джерела ПІСЛЯ.
      * Для доказів юридичного рівня: спочатку снапшот/образ VM, скрипт — на копії.

.EXAMPLE
    # Рекомендовано (файл у UTF-8 з BOM — кирилиця не ламається):
    powershell.exe -ExecutionPolicy Bypass -File C:\1\soc-collect.ps1 -CaseId INC-0922 -Since '2026-09-22 00:00' -Until '2026-09-23 00:00'

.EXAMPLE
    # Через scriptblock (як fwlog):
    powershell.exe -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Get-Content -Raw -Encoding UTF8 'C:\1\soc-collect.ps1'))) -CaseId INC-0922 -Hours 48"

.NOTES
    Для іншої справи змінюйте лише параметри нижче (або передавайте їх при запуску).
    Мінімальні вимоги: Windows PowerShell 5.1 або PowerShell 7.x на Windows, FullLanguage mode.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    # ─── Ідентифікація справи ───────────────────────────────────────────────
    [string]$CaseId  = "INC-testPC_1-KMSAuto",
    [string]$Analyst = "",

    # ─── Часове вікно для журналів подій і firewall-логу ────────────────────
    [int]$Hours = 48,              # використовується, якщо не задано -Since
    [datetime]$Since,              # напр. '2026-09-22 00:00' (локальний час)
    [datetime]$Until,              # за замовчуванням — момент запуску

    # ─── Куди складати докази ───────────────────────────────────────────────
    [string]$OutRoot = "C:\SOC_Evidence",

    # ─── IOC та критерії пошуку (редагуйте під нову справу) ─────────────────
    [string[]]$NamePatterns = @("*KMS*", "*activ*", "*SECOPatcher*"),
    [string[]]$KnownPaths = @(
        "C:\Windows\KMSAutoS",
        "C:\Windows\KMSAutoS\KMSAuto++ x64.exe",
        "C:\Windows\KMSAutoS\KMSAuto_Files\bin\KMSSS.exe",
        "C:\Windows\KMSAutoS\KMSAuto_Files\bin\driver\x64WDV\SECOPatcher.dll",
        "C:\kmsauto_windows_11.rar",
        "C:\kmsauto_windows_11"
    ),
    [string[]]$IocSha256 = @(
        "ABAA1B89DCA9655410F61D64DE25990972DB95D28738FC93BB7A8A69B347A6A6",
        "397E90D1E6E5CA717186A12011220AD18092F10DB85101CB994DC0567D9F568E"
    ),
    [string[]]$IocIPs = @("192.168.77.51", "fe80::1a2b:3c4d:5e6f:7a8b", "10.9.0.20"),

    # ─── Де шукати файли (порожньо = всі локальні диски) ────────────────────
    [string[]]$SearchRoots = @(),
    [string[]]$ExcludeDirs = @('\Windows\WinSxS', '\Windows\System32\DriverStore', '\Windows\servicing',
                               '\Windows\Installer', '\Windows\assembly', '\Windows\Microsoft.NET',
                               '\ProgramData\Microsoft\Windows\AppRepository', '\System Volume Information',
                               '\SOC_Evidence', '\SOC_Audit'),

    # ─── Ліміти та перемикачі ───────────────────────────────────────────────
    [int]$MaxEvents   = 5000,      # максимум подій на один запит до журналу
    [int]$MaxHashMB   = 300,       # файли більші за це — без hash
    [int]$HtmlMaxRows = 400,       # рядків на таблицю в HTML (повні дані — у CSV)
    [switch]$SkipWideSearch,       # не шукати по всіх дисках (швидше)
    [switch]$SkipEvidenceCopy,     # не копіювати браузерні БД / логи
    [switch]$CollectHives,         # reg save SYSTEM/SOFTWARE + Amcache через esentutl /vss (створює тимчасову тіньову копію!)
    [switch]$UsnJournal,           # вибірка з USN-журналу за масками (довго)
    [switch]$NoEvtx,               # не експортувати оригінальні .evtx (лише CSV-вибірки)
    [switch]$NoZip
)

# ════════════════════════════════════ ІНІЦІАЛІЗАЦІЯ ════════════════════════════════════
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ─── Перевірка середовища ДО будь-яких змін на диску (NIST: не змінювати систему даремно) ───
# #Requires вище спрацьовує при запуску файлу; ця перевірка дублює її для scriptblock / Invoke-Command
# і дає зрозуміле повідомлення замість помилки парсера.
$MinPsVersion = [version]'5.1'
$EnvWarnings  = @()
$psv = $PSVersionTable.PSVersion
if ($psv -lt $MinPsVersion) {
    Write-Host ("ПОМИЛКА: потрібен PowerShell {0}+, запущено {1}. Оновіть WMF 5.1 або запустіть через powershell.exe (5.1) / pwsh.exe (7.x)." -f $MinPsVersion, $psv) -ForegroundColor Red
    exit 2
}
if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    Write-Host "ПОМИЛКА: скрипт збирає артефакти Windows і працює лише на Windows." -ForegroundColor Red
    exit 2
}
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host ("ПОМИЛКА: LanguageMode = {0}. Потрібен FullLanguage (обмеження AppLocker/WDAC/__PSLockdownPolicy) — .NET-виклики скрипта заблоковані." -f $ExecutionContext.SessionState.LanguageMode) -ForegroundColor Red
    exit 2
}
$Relaunched = ($env:SOC_COLLECT_RELAUNCHED -eq '1')
if ($Relaunched) { Remove-Item Env:SOC_COLLECT_RELAUNCHED -ErrorAction SilentlyContinue; $EnvWarnings += 'Скрипт автоматично перезапущено з 32-бітного PowerShell у 64-бітний (Sysnative), щоб уникнути перенаправлення WOW64.' }
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    # WOW64 підміняє System32 і HKLM\SOFTWARE — на тесті це дало порожній Winlogon\Userinit і «відсутній» lsass.exe.
    # При запуску з файлу перезапускаємось у 64-бітному powershell.exe з тими самими параметрами.
    $native = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not $Relaunched -and $PSCommandPath -and $PSVersionTable.PSEdition -ne 'Core' -and (Test-Path -LiteralPath $native)) {
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        foreach ($kv in $PSBoundParameters.GetEnumerator()) {
            $v = $kv.Value
            if ($null -eq $v -or ($v -is [string] -and -not $v) -or ($v -is [array] -and -not @($v).Count)) { continue }   # порожні аргументи PS 5.1 не передає нативним exe
            if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $argList += "-$($kv.Key)" }; continue }
            $argList += "-$($kv.Key)"
            if ($v -is [datetime]) { $argList += $v.ToString('yyyy-MM-dd HH:mm:ss') }
            elseif ($v -is [array]) { $argList += (@($v) -join ',') }   # -File: списки через кому розбирає Split-ListParam
            else { $argList += [string]$v }
        }
        Write-Host "32-бітний PowerShell на 64-бітній ОС — перезапуск у 64-бітному: $native" -ForegroundColor Yellow
        $env:SOC_COLLECT_RELAUNCHED = '1'
        & $native @argList
        exit $LASTEXITCODE
    }
    $EnvWarnings += 'Запущено 32-бітний PowerShell на 64-бітній ОС: WOW64 перенаправляє System32 і частину реєстру — дані можуть бути неповними (напр. Winlogon, «відсутні» бінарники служб). Запускайте %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe.'
}
if ($psv.Major -eq 5 -and $psv.Minor -eq 1 -and $psv.Build -lt 14393) {
    $EnvWarnings += ("PowerShell {0} (WMF 5.1 на старій ОС): частина модулів (LocalAccounts, NetTCPIP) може бути відсутня — кроки позначаться як ПОМИЛКА." -f $psv)
}
foreach ($w in $EnvWarnings) { Write-Host "УВАГА: $w" -ForegroundColor Yellow }

$ToolPathTop = $PSCommandPath
$ToolTextTop = $null
try { if ($MyInvocation.MyCommand.ScriptBlock) { $ToolTextTop = $MyInvocation.MyCommand.ScriptBlock.ToString() } } catch {}
# Текст самого інструмента (без CR) — щоб відрізнити власні script blocks у 4104 від дій зловмисника
$OwnTextNorm = ''
try {
    if ($ToolPathTop -and (Test-Path -LiteralPath $ToolPathTop)) { $OwnTextNorm = [IO.File]::ReadAllText($ToolPathTop) }
    elseif ($ToolTextTop) { $OwnTextNorm = $ToolTextTop }
} catch {}
$OwnTextNorm = ([string]$OwnTextNorm).Replace("`r", '')

$ToolName    = 'SOC Live Response Collector'
$ToolVersion = '1.4.2'
$RunStart    = Get-Date
if (-not $PSBoundParameters.ContainsKey('Since')) { $Since = $RunStart.AddHours(-$Hours) }
if (-not $PSBoundParameters.ContainsKey('Until')) { $Until = $RunStart }

$IsAdmin  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$HostName = $env:COMPUTERNAME
$Stamp    = $RunStart.ToUniversalTime().ToString('yyyyMMdd_HHmmss') + 'Z'
$CaseSafe = $CaseId -replace '[^\w\.\-]', '_'
$CaseDir  = Join-Path $OutRoot ("{0}_{1}_{2}" -f $CaseSafe, $HostName, $Stamp)
foreach ($sub in '00_tool', '01_volatile', '02_system', '03_eventlogs', '04_firewall', '05_artifacts', '06_evidence_copies') {
    New-Item -ItemType Directory -Force -Path (Join-Path $CaseDir $sub) | Out-Null
}
$Operator = "$env:USERDOMAIN\$env:USERNAME"
if ($Analyst) { $Operator = "$Analyst ($Operator)" }

# Сховища даних (reference-типи — безпечні між областями видимості)
$D          = @{}
$Ctx        = @{ Seq = 0 }
$Custody    = New-Object System.Collections.Generic.List[object]
$Notes      = New-Object System.Collections.Generic.List[string]
$StepLog    = New-Object System.Collections.Generic.List[object]
$Integrity  = New-Object System.Collections.Generic.List[object]
$Timeline   = New-Object System.Collections.Generic.List[object]
$Flags      = New-Object System.Collections.Generic.List[object]
$BinCache   = @{}
$CustodyLive = Join-Path $CaseDir 'chain_of_custody.log'

# При запуску через -File списки "a,b,c" приходять одним рядком — розбиваємо
function Split-ListParam { param([string[]]$v) if ($v -and $v.Count -eq 1 -and $v[0] -match ',') { return @($v[0] -split '\s*,\s*' | Where-Object { $_ }) }; return @($v) }
$NamePatterns = Split-ListParam $NamePatterns; $KnownPaths = Split-ListParam $KnownPaths; $IocSha256 = Split-ListParam $IocSha256
$IocIPs = Split-ListParam $IocIPs; $SearchRoots = Split-ListParam $SearchRoots; $ExcludeDirs = Split-ListParam $ExcludeDirs
# Папку з доказами виключаємо з пошуку ПІСЛЯ розбиття списку. Якщо OutRoot — корінь диска (E:\),
# виключаємо лише папку поточної справи, інакше '\' виключив би взагалі все.
$OutRel = ($OutRoot -replace '^[A-Za-z]:', '').TrimEnd('\')
if (-not $OutRel) { $OutRel = ($CaseDir -replace '^[A-Za-z]:', '').TrimEnd('\') }
$ExcludeDirs = @(@($ExcludeDirs) + @($OutRel) | Where-Object { $_ -and $_ -ne '\' })

# IOC IP: множина для точного порівняння + regex з межами адреси для пошуку в тексті
$IocIpSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$ipParts  = @()
foreach ($ip in @($IocIPs)) {
    $n = ($ip.Trim().Trim('[', ']') -replace '%.*$', '').ToLowerInvariant()
    if (-not $n) { continue }
    [void]$IocIpSet.Add($n)
    if ($n.Contains(':')) { $ipParts += ('(?<![0-9a-f:])' + [regex]::Escape($n) + '(?![0-9a-f:])') }   # IPv6
    else { $ipParts += ('(?<![\d.])' + [regex]::Escape($n) + '(?!\d|\.\d)') }                          # IPv4 (порт після ':' — допустимо)
}
$IocIpRx = $null
if ($ipParts.Count) { $IocIpRx = New-Object Text.RegularExpressions.Regex (($ipParts -join '|'), ([Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::Compiled)) }

$Keywords = @($NamePatterns | ForEach-Object { $_.Replace('*', '').Replace('?', '').Trim() } | Where-Object { $_.Length -ge 3 } | Select-Object -Unique)
if (-not $env:SystemRoot)  { $env:SystemRoot  = 'C:\Windows' }
if (-not $env:ProgramData) { $env:ProgramData = 'C:\ProgramData' }
# Диски для пошуку файлів: вказані вручну або всі локальні/знімні (fallback — Get-PSDrive)
$SearchRootsFinal = @($SearchRoots | Where-Object { $_ })
if ($SearchRootsFinal.Count -eq 0) {
    try { $SearchRootsFinal = @(Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DriveType -in 2, 3 } | ForEach-Object { $_.DeviceID + '\' }) }
    catch { $SearchRootsFinal = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Root -match '^[A-Za-z]:\\$' } | ForEach-Object { $_.Root }) }
}

$DataKeys = 'TcpRaw','UdpRaw','ProcRaw','Procs','Tcp','Udp','Arp','Dns','IpAddr','Routes','SmbSess','SmbOpen','SmbShares','Profiles','ProfileRoots',
            'LocalUsers','LocalAdmins','Services','Tasks','Autoruns','WmiPersist','MpExclusions','MpStatusRows','Licensing','KmsReg',
            'FwProfiles','FwRules','Ev4625','Ev4624','OtherAuth','LogCleared','Rdp','RdpSummary','SvcEvents','TaskEvents',
            'FwEvents','MpEvents','Exec','SysmonMisc','Ps4104','FwByPort','FwBySource','FwIocRaw','FwSvcHits','KnownFiles',
            'WideHigh','WideLow','WideDirs','LogHealth','Hardening','EvtxExport','AdConfig','AdObjects','AdAudit','AdEvents','AdFindings','AuditSettings','Lnk','Bam','Prefetch','Recycle','Zone','Hints','PsHist','BruteForce','Correlation','IocHits'
foreach ($k in $DataKeys) { $D[$k] = @() }

$Lolbins = @('netsh.exe','wmic.exe','reg.exe','sc.exe','schtasks.exe','cscript.exe','wscript.exe','mshta.exe','rundll32.exe',
             'regsvr32.exe','certutil.exe','bitsadmin.exe','esentutl.exe','vssadmin.exe','wevtutil.exe','bcdedit.exe','net.exe',
             'net1.exe','powershell.exe','pwsh.exe','whoami.exe','nltest.exe','icacls.exe','takeown.exe','attrib.exe','fsutil.exe',
             'curl.exe','installutil.exe','regasm.exe','msbuild.exe','psexec.exe','psexesvc.exe','auditpol.exe','cmdkey.exe',
             'sdbinst.exe','forfiles.exe','cmstp.exe','odbcconf.exe','diskshadow.exe','ntdsutil.exe','quser.exe','qwinsta.exe',
             'tasklist.exe','systeminfo.exe','arp.exe','nslookup.exe','ping.exe')

$NtStatus = @{
    '0xc000006d' = "невірне ім'я або пароль";   '0xc000006a' = 'невірний пароль';          '0xc0000064' = 'користувач не існує'
    '0xc0000234' = 'обліковий запис заблоковано'; '0xc0000072' = 'обліковий запис вимкнено'; '0xc000006f' = 'вхід поза дозволеним часом'
    '0xc0000070' = 'обмеження робочої станції';   '0xc0000071' = 'пароль прострочено';       '0xc0000193' = 'обліковий запис прострочено'
    '0xc0000133' = 'розсинхронізація часу';       '0xc0000224' = 'потрібна зміна пароля';    '0xc000015b' = 'тип входу не дозволено'
    '0xc0000413' = 'authentication firewall';     '0x0' = '—'
}
$LogonTypes = @{ '2' = 'Interactive'; '3' = 'Network'; '4' = 'Batch'; '5' = 'Service'; '7' = 'Unlock'; '8' = 'NetworkCleartext'; '9' = 'NewCredentials'; '10' = 'RemoteInteractive (RDP)'; '11' = 'CachedInteractive' }

# ════════════════════════════════════ ДОПОМІЖНІ ФУНКЦІЇ ════════════════════════════════════
function Arr {   # безпечне перетворення на масив (обхід бага PS7 з @(List[object])), без $null
    param($x)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -ne $x) {
        if ($x -is [System.Collections.IEnumerable] -and $x -isnot [string] -and $x -isnot [System.Collections.IDictionary]) { foreach ($i in $x) { if ($null -ne $i) { $out.Add($i) } } }
        else { $out.Add($x) }
    }
    return ,$out.ToArray()
}
function E   { param($s) if ($null -eq $s) { return '' }; return [System.Net.WebUtility]::HtmlEncode([string]$s) }

function U {   # -> 'yyyy-MM-dd HH:mm:ssZ' (UTC)
    param($d)
    if ($null -eq $d) { return '' }
    if ($d -is [string]) { if (-not $d.Trim()) { return '' }; try { $d = [datetime]$d } catch { return $d } }
    try { $dt = [datetime]$d; if ($dt.Year -lt 1990) { return '' }; return $dt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z' } catch { return [string]$d }
}
function L {   # -> 'yyyy-MM-dd HH:mm:ss' (локальний час хоста)
    param($d)
    if ($null -eq $d) { return '' }
    if ($d -is [string]) { if (-not $d.Trim()) { return '' }; try { $d = [datetime]$d } catch { return $d } }
    try { $dt = [datetime]$d; if ($dt.Year -lt 1990) { return '' }; return $dt.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') } catch { return [string]$d }
}
function PU {  # 'yyyy-MM-dd HH:mm:ssZ' -> DateTime (UTC)
    param([string]$s)
    if (-not $s) { return $null }
    try {
        return [datetime]::ParseExact($s.TrimEnd('Z'), 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
    } catch { return $null }
}

function Add-Custody {
    param([string]$Action, [string]$Target, [string]$Result = 'OK', [string]$Details = '')
    $Ctx.Seq = $Ctx.Seq + 1
    $o = [pscustomobject]@{
        Seq      = $Ctx.Seq
        TimeUtc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff') + 'Z'
        Operator = $Operator; Action = $Action; Target = $Target; Result = $Result; Details = $Details
    }
    $Custody.Add($o)
    $line = "{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}" -f $o.Seq, $o.TimeUtc, $o.Operator, $o.Action, $o.Target, $o.Result, $o.Details
    try { [IO.File]::AppendAllText($CustodyLive, $line + [Environment]::NewLine, (New-Object Text.UTF8Encoding($true))) } catch {}
}
function Add-Note { param([string]$t) $Notes.Add($t) }
function Add-Flag {
    param([string]$Sev, [string]$Area, [string]$Title, [string]$Evidence, [string]$Anchor = 'summary')
    $Flags.Add([pscustomobject]@{ Severity = $Sev; Area = $Area; Finding = $Title; Evidence = $Evidence; Anchor = $Anchor })
}
function Add-TL {
    param($Time, [string]$Source, [string]$EventLabel, [string]$Summary, [string]$Actor = '', [string]$Mark = '')
    $dt = $null
    if ($Time -is [datetime]) { $dt = $Time.ToUniversalTime() }
    elseif ($Time -is [string] -and $Time) { $dt = PU $Time; if ($null -eq $dt) { try { $dt = ([datetime]$Time).ToUniversalTime() } catch {} } }
    if ($null -eq $dt -or $dt.Year -lt 1990) { return }
    $Timeline.Add([pscustomobject]@{
        TimeUtc = $dt.ToString('yyyy-MM-dd HH:mm:ss') + 'Z'; TimeLocal = $dt.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Source = $Source; Event = $EventLabel; Summary = $Summary; Actor = $Actor; Mark = $Mark })
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Name) -ForegroundColor Cyan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'; $err = ''
    try { & $Body } catch { $status = 'ПОМИЛКА'; $err = ("{0} [рядок {1}]" -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber); Write-Host "    ! $err" -ForegroundColor Yellow }
    $sw.Stop()
    $StepLog.Add([pscustomobject]@{ Step = $Name; Status = $status; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Error = $err })
    Add-Custody 'STEP' $Name $status ("{0:N1}s {1}" -f $sw.Elapsed.TotalSeconds, $err)
}

function Save-Csv {
    param($Rows, [string]$Rel)
    $path = Join-Path $CaseDir $Rel
    $dir = Split-Path $path -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $arr = Arr $Rows
    if ($arr.Count -gt 0) { $arr | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 }
    else { Set-Content -LiteralPath $path -Value '# немає даних за заданими критеріями' -Encoding UTF8 }
    Add-Custody 'WRITE_OUTPUT' $Rel 'OK' ("{0} рядків" -f $arr.Count)
}
function Save-Text {
    param([string]$Text, [string]$Rel)
    $path = Join-Path $CaseDir $Rel
    [IO.File]::WriteAllText($path, [string]$Text, (New-Object Text.UTF8Encoding($true)))
    Add-Custody 'WRITE_OUTPUT' $Rel 'OK' ''
}

function Test-KwMatch {
    param([string]$s)
    if (-not $s) { return $false }
    foreach ($k in $Keywords) { if ($s.IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
    return $false
}
function Get-NormIP {   # '[fe80::1%12]' -> 'fe80::1'; регістр не важливий
    param([string]$ip)
    if (-not $ip) { return '' }
    return ($ip.Trim().Trim('[', ']') -replace '%.*$', '').ToLowerInvariant()
}
function Test-IocIP {   # IOC IP у довільному тексті — лише по межах адреси (10.9.0.20 ≠ 110.9.0.201 / 10.9.0.200)
    param([string]$s)
    if (-not $s -or -not $IocIpRx) { return $false }
    return $IocIpRx.IsMatch($s)
}
function Test-IocIPEq {   # точне порівняння одного значення-адреси з IOC
    param([string]$ip)
    if (-not $ip) { return $false }
    return $IocIpSet.Contains((Get-NormIP $ip))
}
function Test-PrivateIP {
    param([string]$ip)
    if (-not $ip -or $ip -in @('-', '::', '0.0.0.0', '*')) { return $true }
    $ip = ($ip.Trim('[', ']') -replace '%.*$', '')
    if ($ip -match '^(10\.|127\.|169\.254\.|192\.168\.|0\.)') { return $true }
    if ($ip -match '^172\.(1[6-9]|2\d|3[01])\.') { return $true }
    if ($ip -match '^(22[4-9]|23\d|255)\.') { return $true }
    if ($ip -match '^(?i)(::1$|fe80:|f[cd][0-9a-f]{2}:|ff[0-9a-f]{2}:)') { return $true }
    return $false
}
function Get-FirstIP {
    param([string[]]$Values)
    foreach ($v in $Values) {
        if (-not $v) { continue }
        $m = [regex]::Match($v, '(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])')
        if ($m.Success) { return $m.Groups[1].Value }
        $t = $v.Trim().Trim('[', ']')
        if ($t -match '^(?i)[0-9a-f:]+(%\d+)?$' -and $t.Contains(':') -and ($t.Contains('::') -or $t.Split(':').Count -ge 8)) { return $t }
    }
    return ''
}
function Get-StatusText { param([string]$s) if (-not $s) { return '' }; $k = $s.ToLower(); if ($NtStatus.ContainsKey($k)) { return "$s ($($NtStatus[$k]))" }; return $s }
function Get-LogonTypeText { param([string]$t) if ($LogonTypes.ContainsKey([string]$t)) { return "$t $($LogonTypes[[string]$t])" }; return $t }
function Resolve-Sid {
    param([string]$sid)
    if (-not $sid -or $sid -notmatch '^S-1-') { return $sid }
    try { return (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { return $sid }
}

function Get-PathClass {
    param([string]$p)
    if (-not $p) { return '' }
    $w = $env:SystemRoot.TrimEnd('\')
    foreach ($s in @("$w\System32\", "$w\SysWOW64\", "$w\WinSxS\", "$w\servicing\", "$w\Microsoft.NET\", "$w\SystemApps\", "$w\ImmersiveControlPanel\", "$w\assembly\", "$w\Sysnative\")) {
        if ($p.StartsWith($s, [StringComparison]::OrdinalIgnoreCase)) { return 'Системний' }
    }
    if ($p -match '^(?i)[a-z]:\\Windows\\[^\\]+\.exe$') { return 'Системний' }
    if ($p -match '(?i)\\Program Files( \(x86\))?\\' -or $p -match '(?i)\\ProgramData\\Microsoft\\Windows Defender\\') { return 'Program Files' }
    foreach ($r in @($D.ProfileRoots)) { if ($r -and $p.StartsWith($r.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return 'Користувацький/тимчасовий' } }
    if ($p -match '(?i)\\(Users|AppData|Temp|Tmp|ProgramData|Downloads|PerfLogs|Public)\\' -or $p -match '(?i)\\\$Recycle\.Bin\\') { return 'Користувацький/тимчасовий' }
    return 'Нестандартний'
}

function Resolve-BareExe {   # 'sc.exe' / 'powershell.exe' без шляху -> повний шлях (як його знайде Windows), інакше без змін
    param([string]$exe)
    if (-not $exe -or $exe.Contains('\') -or $exe.Contains('/')) { return $exe }
    $w = $env:SystemRoot
    foreach ($d in @("$w\System32", "$w", "$w\System32\wbem", "$w\System32\WindowsPowerShell\v1.0", "$w\SysWOW64")) {
        foreach ($cand in @((Join-Path $d $exe), (Join-Path $d "$exe.exe"))) {
            if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
        }
    }
    return $exe
}
function Get-ExeFromCmd {
    param([string]$cmd)
    if (-not $cmd) { return '' }
    return (Resolve-BareExe (Get-ExeFromCmdRaw $cmd))
}
function Get-ExeFromCmdRaw {
    param([string]$cmd)
    if (-not $cmd) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    $c = $c -replace '^(?i)\\SystemRoot\\', ($env:SystemRoot + '\') -replace '^\\\?\?\\', ''
    if ($c -match '^(?i)system32\\') { $c = Join-Path $env:SystemRoot $c }
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { return $c.Substring(1, $e - 1) } }
    $m = [regex]::Match($c, '^(?i)(.+?\.(exe|sys|dll|com|bat|cmd|ps1|vbs))(\s|"|$)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s')[0]
}

function Get-BinInfo {   # hash + підпис виконуваного файлу (кешується)
    param([string]$Path)
    if (-not $Path) { return $null }
    $k = $Path.ToLowerInvariant()
    if ($BinCache.ContainsKey($k)) { return $BinCache[$k] }
    $o = [pscustomobject]@{ Exists = $false; SHA256 = ''; Sig = ''; Signer = ''; Class = (Get-PathClass $Path) }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $o.Exists = $true
        try { $o.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $o.Sig = [string]$s.Status
            if ($s.SignerCertificate) { $o.Signer = ($s.SignerCertificate.Subject -replace '^CN="?([^,"]+).*$', '$1') }
        } catch { $o.Sig = 'Error' }
    }
    $BinCache[$k] = $o
    return $o
}

function Get-EffPathClass {   # як Get-PathClass, але підпапки C:\Windows з валідним підписом Microsoft (ADWS, AzureArcSetup…) — не «Нестандартний»
    param([string]$Path)
    $cls = Get-PathClass $Path
    if ($cls -ne 'Нестандартний' -or -not $Path) { return $cls }
    if (-not $Path.StartsWith($env:SystemRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return $cls }
    $bi = Get-BinInfo $Path
    if ($bi -and $bi.Exists -and $bi.Sig -eq 'Valid' -and $bi.Signer -match '^Microsoft ') { return 'Windows (підпис Microsoft)' }
    return $cls   # непідписане в C:\Windows\<папка> (як KMSAutoS) лишається підозрілим
}

function Get-FileEvidence {   # MAC ДО читання -> hash/підпис/Zone.Identifier -> MAC ПІСЛЯ
    param([string]$Path, [string]$Origin = '')
    $o = [ordered]@{ Origin = $Origin; Path = $Path; Exists = $false; SizeBytes = ''; CreatedUtc = ''; ModifiedUtc = ''
                     AccessedUtc_Before = ''; AccessedUtc_After = ''; AtimeChanged = ''; SHA256 = ''; MD5 = ''
                     Signature = ''; Signer = ''; ZoneId = ''; HostUrl = ''; ReferrerUrl = ''; PathClass = ''; IocHash = $false; Note = '' }
    $fi = $null
    try { $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { $o.Note = 'Не знайдено / немає доступу'; return [pscustomobject]$o }
    $o.Exists = $true
    $o.SizeBytes = $fi.Length
    $o.CreatedUtc = U $fi.CreationTimeUtc
    $o.ModifiedUtc = U $fi.LastWriteTimeUtc
    $aBefore = $fi.LastAccessTimeUtc
    $o.AccessedUtc_Before = U $aBefore
    $o.PathClass = Get-PathClass $Path
    if ($fi.Length -le ($MaxHashMB * 1MB)) {
        try {
            $o.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
            $o.MD5    = (Get-FileHash -LiteralPath $Path -Algorithm MD5 -ErrorAction Stop).Hash
        } catch { $o.Note = "Hash: $($_.Exception.Message)" }
    } else { $o.Note = "Файл > $MaxHashMB MB — hash не рахувався" }
    if ($fi.Extension -match '^(?i)\.(exe|dll|sys|scr|com|msi|ps1|psm1|cat|ocx|cpl|drv)$') {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $o.Signature = [string]$s.Status
            if ($s.SignerCertificate) { $o.Signer = $s.SignerCertificate.Subject }
        } catch { $o.Signature = 'Помилка перевірки' }
    }
    try {
        $z = Get-Content -LiteralPath $Path -Stream 'Zone.Identifier' -ErrorAction Stop
        foreach ($l in @($z)) {
            if ($l -match '^ZoneId=(\d+)') { $o.ZoneId = $Matches[1] }
            elseif ($l -match '^HostUrl=(.+)$') { $o.HostUrl = $Matches[1] }
            elseif ($l -match '^ReferrerUrl=(.+)$') { $o.ReferrerUrl = $Matches[1] }
        }
    } catch {}
    try { $fi.Refresh(); $o.AccessedUtc_After = U $fi.LastAccessTimeUtc; $o.AtimeChanged = ($fi.LastAccessTimeUtc -ne $aBefore) } catch {}
    if ($o.SHA256 -and ($IocSha256 -contains $o.SHA256)) { $o.IocHash = $true }
    Add-Custody 'EXAMINE_FILE' $Path 'OK' ("sha256={0}; atimeChanged={1}" -f $o.SHA256, $o.AtimeChanged)
    return [pscustomobject]$o
}

function Get-SharedHash {   # SHA256 файлу, який інший процес тримає відкритим на запис (pfirewall.log, History відкритого браузера)
    param([string]$Path)
    $fs = $null; $sha = $null
    try {
        $fs  = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $sha = [Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '')
    } catch { return '' } finally { if ($fs) { $fs.Close() }; if ($sha) { $sha.Dispose() } }
}
function Get-SourceHash {   # спершу звичайний Get-FileHash, для заблокованих — спільне читання
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return (Get-SharedHash $Path) }
}

function Copy-Evidence {   # NIST: hash джерела ДО -> копія -> hash копії -> hash джерела ПІСЛЯ
    param([string]$Source, [string]$RelDir, [switch]$ActiveFile, [string]$Prefix = '')
    $destDir = Join-Path $CaseDir $RelDir
    if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Force -Path $destDir | Out-Null }
    $name = (($Prefix + (Split-Path $Source -Leaf)) -replace '[\\/:*?"<>|]', '_')
    $dest = Join-Path $destDir $name
    $k = 1
    while (Test-Path -LiteralPath $dest) { $dest = Join-Path $destDir ("{0}_{1}" -f $k, $name); $k++ }
    $pre = ''; $post = ''; $dst = ''; $method = 'Copy-Item'; $err = ''; $copied = $false
    $pre = Get-SourceHash $Source
    try { Copy-Item -LiteralPath $Source -Destination $dest -Force -ErrorAction Stop; $copied = $true }
    catch {
        try {
            $in  = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $out = [IO.File]::Create($dest)
            try { $in.CopyTo($out) } finally { $out.Close(); $in.Close() }
            $copied = $true; $method = 'Stream (FileShare.ReadWrite)'
        } catch { $err = $_.Exception.Message }
    }
    if ($copied) {
        try { $dst  = (Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
        $post = Get-SourceHash $Source
    }
    $status = 'CHECK'
    if (-not $copied) { $status = 'НЕ СКОПІЙОВАНО' }
    elseif ($pre -and $pre -eq $dst -and $pre -eq $post) { $status = 'VERIFIED (до = копія = після)' }
    elseif ($pre -and $post -and $pre -ne $post) {
        if ($ActiveFile) { $status = 'SOURCE_CHANGED — активний файл, зміна очікувана; доказ = копія (hash зафіксовано)' }
        else { $status = 'УВАГА: джерело змінилося під час копіювання' }
    }
    elseif ($pre -and $pre -ne $dst) { $status = 'УВАГА: hash копії ≠ hash джерела' }
    elseif (-not $pre) { $status = 'COPY-ONLY: джерело заблоковане для hash, зафіксовано hash копії' }
    $Integrity.Add([pscustomobject]@{ Source = $Source; Copy = $dest.Substring($CaseDir.Length + 1); Method = $method
        SHA256_Source_Before = $pre; SHA256_Copy = $dst; SHA256_Source_After = $post; Status = $status; Error = $err })
    $res = 'FAIL'; if ($copied) { $res = 'OK' }
    Add-Custody 'COPY_EVIDENCE' $Source $res $status
    if ($copied) { return $dest } else { return $null }
}

function Read-SharedLines {
    param([string]$Path)
    $list = New-Object System.Collections.Generic.List[string]
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $sr = New-Object IO.StreamReader($fs)
    try { while ($null -ne ($l = $sr.ReadLine())) { $list.Add($l) } } finally { $sr.Close(); $fs.Close() }
    return ,$list.ToArray()
}

function Get-StringHints {   # URL/шляхи з ключовими словами у бінарних БД (History, ActivitiesCache) — без SQLite
    # Читання блоками по 4 МБ з перекриттям: пам'ять не залежить від розміру БД (раніше — ReadAllBytes на весь файл)
    param([string]$Path, [int]$Max = 300)
    $out = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if (-not $Keywords -or -not (Test-Path -LiteralPath $Path)) { return @() }
    $rx = New-Object Text.RegularExpressions.Regex('(?i)(https?://[^\s"''<>\x00-\x1f]{4,400}|\b[a-z]:\\(?:[^\x00-\x1f"<>|*?\\/:]{1,120}\\){0,15}[^\x00-\x1f"<>|*?\\/:]{1,120}?\.(?:exe|dll|sys|rar|zip|7z|ini|cfg|ps1|bat|cmd|vbs|js|lnk|msi|iso|img|txt|log|reg)\b)')
    $chunk = 4MB; $overlap = 8KB   # обидва парні — UTF-16 декодується з вирівняної позиції
    $buf = New-Object byte[] ($chunk + $overlap + 2)
    $fs = $null
    try { $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite) } catch { return @() }
    try {
        $carry = 0; $pos = [int64]0   # $pos — зміщення buf[0] у файлі
        while ($out.Count -lt $Max) {
            $n = $fs.Read($buf, $carry, $chunk)
            if ($n -le 0) { break }
            $len = $carry + $n
            foreach ($enc in @([Text.Encoding]::UTF8, [Text.Encoding]::Unicode)) {
                $txt = $enc.GetString($buf, 0, $len)
                foreach ($m in $rx.Matches($txt)) {
                    if ($out.Count -ge $Max) { break }
                    if (Test-KwMatch $m.Value) { [void]$out.Add($m.Value.Trim()) }
                }
            }
            # хвіст блоку переносимо на початок — рядок на межі блоків не загубиться
            $carry = [Math]::Min($overlap, $len)
            if ((($pos + $len - $carry) % 2) -ne 0 -and $carry -lt $len) { $carry++ }   # зберегти парне вирівнювання
            $pos += ($len - $carry)
            [Array]::Copy($buf, $len - $carry, $buf, 0, $carry)
        }
    } catch {} finally { $fs.Close() }
    return @($out)
}

function Find-Pattern {   # обхід дисків без рекурсивних junction-петель, з виключеннями
    param([string[]]$Roots, [string[]]$Patterns, [string[]]$Exclude)
    $files = New-Object System.Collections.Generic.List[object]
    $dirs  = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Generic.Stack[string]
    foreach ($r in $Roots) { if ($r -and (Test-Path -LiteralPath $r)) { $stack.Push($r) } }
    $scanned = 0
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $skip = $false
        foreach ($ex in $Exclude) { if ($ex -and $dir.IndexOf($ex, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $skip = $true; break } }
        if ($skip) { continue }
        $di = $null
        try { $di = New-Object IO.DirectoryInfo($dir) } catch { continue }
        $subs = @(); try { $subs = $di.GetDirectories() } catch {}
        foreach ($s in $subs) {
            if (($s.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            foreach ($p in $Patterns) { if ($s.Name -like $p) { $dirs.Add($s); break } }
            $stack.Push($s.FullName)
        }
        $fl = @(); try { $fl = $di.GetFiles() } catch {}
        foreach ($f in $fl) { $scanned++; foreach ($p in $Patterns) { if ($f.Name -like $p) { $files.Add($f); break } } }
    }
    return [pscustomobject]@{ Files = $files; Dirs = $dirs; Scanned = $scanned }
}

function Get-LogAdvice {   # рекомендації щодо журналу: розмір, заповненість, режим, глибина, покриття вікна
    param([string]$Name, [bool]$Enabled, [string]$Mode, [int64]$MaxBytes, [int64]$SizeBytes, $Oldest, [int64]$RecBytes, [datetime]$WindowStart)
    $adv = @(); $sev = 'OK'
    if (-not $Enabled) { $adv += ('Журнал вимкнено — увімкнути: wevtutil sl "{0}" /e:true' -f $Name); $sev = 'Високо' }
    if ($RecBytes -gt 0 -and $MaxBytes -lt $RecBytes) {
        $adv += ('Макс. розмір {0} MB < рекомендованих {1} MB: wevtutil sl "{2}" /ms:{3}' -f [math]::Round($MaxBytes / 1MB), [math]::Round($RecBytes / 1MB), $Name, $RecBytes)
        if ($sev -eq 'OK') { $sev = 'Середньо' }
    }
    if ($MaxBytes -gt 0 -and $SizeBytes -ge (0.9 * $MaxBytes) -and $Mode -eq 'Circular') { $adv += 'Заповнений на ≥90% і пише по колу — старі події вже перезаписуються' }
    if ($Mode -eq 'Retain') { $adv += 'Режим Retain: після заповнення НОВІ події не пишуться — краще Circular або AutoBackup'; if ($sev -eq 'OK') { $sev = 'Середньо' } }
    $days = $null
    if ($Oldest) {
        $days = [math]::Round(((Get-Date) - [datetime]$Oldest).TotalDays, 1)
        if ($Mode -eq 'Circular' -and $days -lt 30) { $adv += ('Історія лише {0} дн. — для розслідувань бажано 30–90 днів' -f $days); if ($sev -eq 'OK') { $sev = 'Середньо' } }
        if ([datetime]$Oldest -gt $WindowStart) {
            $adv += ('ВІКНО РОЗСЛІДУВАННЯ НЕ ПОКРИТЕ: найстаріша подія {0}, аналіз з {1} — частину подій уже втрачено, "не знайдено" ≠ "не було"' -f ([datetime]$Oldest).ToString('yyyy-MM-dd HH:mm'), $WindowStart.ToString('yyyy-MM-dd HH:mm'))
            $sev = 'Високо'
        }
    }
    if (-not $adv.Count) { $adv += 'OK' }
    return [pscustomobject]@{ Severity = $sev; HistoryDays = $days; Advice = ($adv -join ' | ') }
}

# ─── Журнали подій ───
function Get-Ev {
    param([string]$Log, [int[]]$Id)
    $fh = @{ LogName = $Log; StartTime = $Since; EndTime = $Until }
    if ($Id) { $fh['Id'] = $Id }
    $res = @()
    try { $res = @(Get-WinEvent -FilterHashtable $fh -MaxEvents $MaxEvents -ErrorAction Stop) }
    catch {
        $fq = [string]$_.FullyQualifiedErrorId
        if ($fq -like 'NoMatchingEventsFound*') { $res = @() }
        elseif ($fq -like 'NoMatchingLogsFound*') { Add-Note "Журнал відсутній або вимкнений: $Log"; $res = @() }
        else { Add-Note ("Не вдалося прочитати {0} [{1}]: {2}" -f $Log, ($Id -join ','), $_.Exception.Message); $res = @() }
    }
    if ($res.Count -ge $MaxEvents) {
        # Get-WinEvent віддає від найновіших: усе, що старше за останній елемент, у вибірку не потрапило
        $keptFrom = ''; try { $keptFrom = U $res[$res.Count - 1].TimeCreated } catch {}
        Add-Note ("УВАГА: {0} [{1}] — досягнуто ліміту {2} подій: збережено лише події з {3}, раніші за вікно {4} ВТРАЧЕНО з вибірки (збільште -MaxEvents)." -f $Log, ($Id -join ','), $MaxEvents, $keptFrom, (U $Since))
    }
    Add-Custody 'READ_EVENTLOG' ("{0} [{1}]" -f $Log, ($Id -join ',')) 'OK' ("{0} подій" -f $res.Count)
    return $res
}
function Get-EvXPath {
    param([string]$Log, [string]$XPath, [string]$Label)
    $res = @()
    try { $res = @(Get-WinEvent -LogName $Log -FilterXPath $XPath -MaxEvents $MaxEvents -ErrorAction Stop) }
    catch { if ([string]$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { Add-Note ("Не вдалося прочитати {0} ({1}): {2}" -f $Log, $Label, $_.Exception.Message) } }
    if ($res.Count -ge $MaxEvents) {
        $keptFrom = ''; try { $keptFrom = U $res[$res.Count - 1].TimeCreated } catch {}
        Add-Note ("УВАГА: {0} ({1}) — досягнуто ліміту {2} подій: збережено лише події з {3}, раніші ВТРАЧЕНО з вибірки (збільште -MaxEvents)." -f $Log, $Label, $MaxEvents, $keptFrom)
    }
    Add-Custody 'READ_EVENTLOG' ("{0} ({1})" -f $Log, $Label) 'OK' ("{0} подій" -f $res.Count)
    return $res
}
function Get-EvData {
    param($e)
    $d = [ordered]@{}
    try {
        $x = [xml]$e.ToXml()
        $i = 0
        if ($x.Event.EventData -is [System.Xml.XmlElement]) {
            foreach ($n in @($x.Event.EventData.ChildNodes)) {
                if ($n -is [System.Xml.XmlElement]) {
                    $k = $n.GetAttribute('Name'); if (-not $k) { $k = "Data$i" }
                    $d[$k] = $n.InnerText; $i++
                }
            }
        }
        if ($x.Event.UserData -is [System.Xml.XmlElement]) {
            foreach ($c in @($x.Event.UserData.ChildNodes)) {
                if ($c -is [System.Xml.XmlElement]) { foreach ($cc in @($c.ChildNodes)) { if ($cc -is [System.Xml.XmlElement]) { $d[$cc.LocalName] = $cc.InnerText } } }
            }
        }
    } catch {}
    return $d
}
function Format-EvData {
    param($d, [string[]]$Skip = @())
    $parts = foreach ($k in @($d.Keys)) { $v = [string]$d[$k]; if ($Skip -notcontains $k -and $v -and $v -ne '-') { "{0}={1}" -f $k, $v } }
    $s = (@($parts) -join '; ')
    if ($s.Length -gt 700) { $s = $s.Substring(0, 700) + '…' }
    return $s
}
function Get-ExecReason {
    param([string]$Img, [string]$Cmd, [string]$Hashes)
    $r = @()
    $leaf = ''; if ($Img) { $leaf = [IO.Path]::GetFileName($Img).ToLowerInvariant() }
    if ($Lolbins -contains $leaf) { $r += "LOLBin: $leaf" }
    if (Test-KwMatch "$Img $Cmd") { $r += 'Збіг з маскою IOC' }
    if (Test-IocIP $Cmd) { $r += 'IOC IP у командному рядку' }
    if ($Hashes) { foreach ($h in $IocSha256) { if ($Hashes.IndexOf($h, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $r += 'IOC HASH'; break } } }
    if ($Cmd -match '(?i)(-enc(odedcommand)?\s|frombase64string|downloadstring|downloadfile|invoke-webrequest|add-mppreference|set-mppreference|msft_mppreference|advfirewall|/skms|/ato|/ipk|delete\s+shadows|clear-eventlog|wevtutil(\.exe)?\s+cl)') { $r += 'Підозрілі аргументи' }
    return ($r -join '; ')
}
function ConvertFrom-AuditpolCsv {   # рядки 'auditpol /get /subcategory:{GUID} /r' -> @{ Value = 0..3 або $null; Text }
    # Заголовки CSV у локалізованій ОС перекладені (RU/UA), тому колонки беремо за ПОЗИЦІЄЮ:
    # 0 Machine Name, 1 Policy Target, 2 Subcategory, 3 Subcategory GUID, 4 Inclusion Setting, 5 Exclusion Setting, 6 Setting Value
    param([string[]]$Lines)
    $res = [pscustomobject]@{ Value = $null; Text = '' }
    $rows = @(@($Lines | Where-Object { $_ -and $_.Trim() }) | ConvertFrom-Csv)
    if (-not $rows.Count) { return $res }
    $props = @($rows[0].PSObject.Properties)
    if ($props.Count -ge 5) { $res.Text = [string]$props[4].Value }
    $last = ([string]$props[$props.Count - 1].Value).Trim()
    if ($props.Count -ge 7 -and $last -match '^[0-3]$') { $res.Value = [int]$last; return $res }
    # запасний шлях — текст Inclusion Setting (EN/RU/UA)
    $t = $res.Text
    if ($t -match '(?i)no auditing|без аудит|нет аудит|немає аудит') { $res.Value = 0; return $res }   # «Без аудита» (RU), «Без аудиту» / «Немає аудиту» (UA)
    $v = 0
    if ($t -match '(?i)success|успех|успіх') { $v = $v -bor 1 }
    if ($t -match '(?i)failure|сбой|збій|отказ|відмов|невдач') { $v = $v -bor 2 }
    if ($v) { $res.Value = $v }   # нічого не розпізнали -> $null («невідомо»), а не 0 («немає аудиту»)
    return $res
}
function Get-AuditSubcategory { param([string]$Guid) try { return (ConvertFrom-AuditpolCsv @(& auditpol /get /subcategory:"$Guid" /r 2>$null)) } catch { return [pscustomobject]@{ Value = $null; Text = '' } } }

function Get-Sha256FromHashes { param([string]$h) if ($h -match '(?i)SHA256=([0-9a-f]{64})') { return $Matches[1].ToUpper() }; return '' }

# Інтерпретатори/проксі-запуску, якими маскують задачі під \Microsoft\ (бінарник системний, шкідливе — в аргументах)
$TaskInterpreters = @('powershell.exe','pwsh.exe','cmd.exe','mshta.exe','wscript.exe','cscript.exe','rundll32.exe','regsvr32.exe',
                      'certutil.exe','bitsadmin.exe','msbuild.exe','installutil.exe','regasm.exe','forfiles.exe','conhost.exe')
function Get-MsTaskSuspicion {   # чому задача під \Microsoft\ НЕ схожа на штатну ('' = штатна)
    param([string]$Exe, [string]$Actions, [string]$Author, [string]$Actor = '')
    $r = @()
    $cls = Get-EffPathClass $Exe
    if ($Exe -and $cls -in @('Нестандартний', 'Користувацький/тимчасовий')) { $r += "дія: $cls" }
    $why = Get-ExecReason $Exe $Actions ''
    if ($why -match 'IOC|Підозрілі') { $r += $why }
    $leaf = ''; if ($Exe) { $leaf = [IO.Path]::GetFileName($Exe).ToLowerInvariant() }
    $msAuthor = (-not $Author) -or $Author -match '^(?i)(\$\(@|Microsoft|Корпорация Майкрософт|Корпорація Майкрософт)'
    if ($TaskInterpreters -contains $leaf -and -not $msAuthor) { $r += "інтерпретатор $leaf, автор '$Author'" }
    # службові облікові записи (SYSTEM, LOCAL/NETWORK SERVICE, комп'ютерні акаунти NAME$) — штатне оновлення задач
    $svcActor = '(?i)^(S-1-5-(18|19|20)|NT AUTHORITY\\.*|.*\\?(SYSTEM|СИСТЕМА|LOCAL SERVICE|NETWORK SERVICE)|.*\$)$'
    if ($Actor -and $Actor -notmatch $svcActor) { $r += "зареєстровано/змінено користувачем $Actor" }
    return ($r -join '; ')
}

Write-Host ""
Write-Host "═══ $ToolName v$ToolVersion ═══" -ForegroundColor White
Write-Host ("Справа: {0} | Хост: {1} | Оператор: {2}" -f $CaseId, $HostName, $Operator)
Write-Host ("Вікно подій: {0} → {1} (локальний час)" -f $Since.ToString('yyyy-MM-dd HH:mm:ss'), $Until.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ("Результати: {0}" -f $CaseDir)
if (-not $IsAdmin) { Write-Host "УВАГА: запуск БЕЗ прав адміністратора — Security-журнал, BAM, частина даних будуть недоступні." -ForegroundColor Red; Add-Note "Скрипт запущено без прав адміністратора — частина джерел недоступна." }
foreach ($w in $EnvWarnings) { Add-Note $w }
Add-Custody 'START' $HostName 'OK' ("Case={0}; Window={1}..{2}; Admin={3}" -f $CaseId, (U $Since), (U $Until), $IsAdmin)

# ════════════════════════════════════ 0. PRE-FLIGHT ════════════════════════════════════
Invoke-Step "0. Pre-flight: версія інструмента, час, профілі, налаштування, що впливають на докази" {
    $toolDir = Join-Path $CaseDir '00_tool'
    if ($ToolPathTop -and (Test-Path -LiteralPath $ToolPathTop)) {
        $D.ToolPath   = $ToolPathTop
        $D.ToolSHA256 = (Get-FileHash -LiteralPath $ToolPathTop -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $ToolPathTop -Destination $toolDir -Force
        $D.ToolMode   = 'Запуск з файлу (-File): hash обчислено для самого файлу скрипта'
    } elseif ($ToolTextTop) {
        $tp = Join-Path $toolDir 'soc-collect.from-scriptblock.ps1'
        [IO.File]::WriteAllText($tp, $ToolTextTop, (New-Object Text.UTF8Encoding($true)))
        $D.ToolPath   = "(scriptblock) $tp"
        $D.ToolSHA256 = (Get-FileHash -LiteralPath $tp -Algorithm SHA256).Hash
        $D.ToolMode   = 'Запуск через scriptblock: зафіксовано hash збереженого тексту скрипта (може відрізнятися від hash файлу через BOM/переноси)'
    } else { $D.ToolPath = 'невідомо'; $D.ToolSHA256 = ''; $D.ToolMode = 'Не вдалося зафіксувати версію інструмента' }
    Add-Custody 'TOOL_HASH' $D.ToolPath 'OK' $D.ToolSHA256

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $tz = $null; try { $tz = Get-TimeZone } catch {}
    $ntp = ''; try { $ntp = ((& w32tm /query /source 2>&1) | Out-String).Trim() } catch {}

    # NTFS last-access (NIST 4.2.3): чи змінює читання файлу мітку Accessed
    $laText = 'невідомо'
    try {
        $la = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name NtfsDisableLastAccessUpdate -ErrorAction Stop).NtfsDisableLastAccessUpdate
        $v = ([int64]$la) -band 0xFFFFFFFF
        if (($v -band 1) -eq 1) { $laText = 'ВИМКНЕНО — читання файлів НЕ змінює LastAccessTime' }
        else { $laText = 'УВІМКНЕНО — читання може оновити LastAccessTime (скрипт фіксує Accessed до/після)' }
        if (($v -band 2) -eq 2) { $laText += ' [system managed]' } else { $laText += ' [user managed]' }
        $laText += (" (0x{0:X8})" -f $v)
    } catch {}
    $D.LastAccess = $laText

    $pf = $null
    try { $pf = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -ErrorAction Stop).EnablePrefetcher } catch {}
    $pfText = 'невідомо / ключ відсутній'
    if ($null -ne $pf) {
        switch ([int]$pf) {
            0 { $pfText = '0 — Prefetch вимкнено (типово для Windows Server) → .pf-артефактів не буде' }
            1 { $pfText = '1 — лише запуск застосунків' }
            2 { $pfText = '2 — лише завантаження ОС' }
            3 { $pfText = '3 — застосунки + завантаження' }
            default { $pfText = [string]$pf }
        }
    }
    $D.PrefetchState = $pfText

    # Профілі користувачів з ProfileList (охоплює нестандартні диски, напр. E:\пользователи)
    $profiles = @()
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue)) {
        $pp = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if (-not $pp) { continue }
        $pp = [Environment]::ExpandEnvironmentVariables($pp)
        $sid = $k.PSChildName
        if ($sid -notmatch '^S-1-5-21-|^S-1-12-') { continue }
        $profiles += [pscustomobject]@{ SID = $sid; User = (Resolve-Sid $sid); Path = $pp; Exists = (Test-Path -LiteralPath $pp) }
    }
    $D.Profiles = Arr $profiles
    $D.ProfileRoots = Arr ($profiles | Where-Object { $_.Exists } | ForEach-Object { $_.Path })
    Save-Csv $D.Profiles '02_system\user_profiles.csv'


    # Роль хоста: 1 = робоча станція, 2 = контролер домену, 3 = сервер (впливає на евристики мережевого трафіку)
    $D.ProductType = 0; if ($os) { $D.ProductType = [int]$os.ProductType }
    $D.IsDC = ($D.ProductType -eq 2)
    $isVm = $false
    if ($cs -and ("$($cs.Manufacturer) $($cs.Model)" -match '(?i)vmware|virtual|kvm|qemu|hyper-v|xen|virtualbox|parallels')) { $isVm = $true }
    $D.SysInfo = [pscustomobject][ordered]@{
        'Хост'                       = $HostName
        'Домен / робоча група'       = $(if ($cs) { $cs.Domain } else { '' })
        'ОС'                         = $(if ($os) { "$($os.Caption) ($($os.Version), build $($os.BuildNumber))" } else { '' })
        'Встановлено (UTC)'          = $(if ($os) { U $os.InstallDate } else { '' })
        'Останнє завантаження (UTC)' = $(if ($os) { U $os.LastBootUpTime } else { '' })
        'Виробник / модель'          = $(if ($cs) { "$($cs.Manufacturer) / $($cs.Model)" } else { '' })
        'Віртуальна машина'          = $isVm
        'Роль хоста'                 = $(switch ($D.ProductType) { 1 { 'Робоча станція' } 2 { 'Контролер домену' } 3 { 'Сервер' } default { 'невідомо' } })
        'Часовий пояс'               = $(if ($tz) { "$($tz.Id) (UTC$($tz.BaseUtcOffset))" } else { '' })
        'Джерело часу (w32tm)'       = $ntp
        'Час старту збору (локальний)' = $RunStart.ToString('yyyy-MM-dd HH:mm:ss')
        'Час старту збору (UTC)'     = U $RunStart
        'Вікно журналів (UTC)'       = ("{0} → {1}" -f (U $Since), (U $Until))
        'PowerShell'                 = $PSVersionTable.PSVersion.ToString()
        'Права адміністратора'       = $IsAdmin
        'Оператор'                   = $Operator
        'NTFS last-access'           = $laText
        'Prefetch'                   = $pfText
        'Інструмент'                 = "$ToolName v$ToolVersion"
        'Інструмент: шлях'           = $D.ToolPath
        'Інструмент: SHA256'         = $D.ToolSHA256
        'Інструмент: режим'          = $D.ToolMode
        'Диски для пошуку'           = ($SearchRootsFinal -join ', ')
    }
    Save-Csv $D.SysInfo '02_system\system_info.csv'
}

# ════════════════════════════════════ 1. ВОЛАТИЛЬНІ ДАНІ (NIST 5.1.2 — першими) ════════════════════════════════════
Invoke-Step "1.1 Швидкий знімок: netstat, TCP, процеси, UDP (без hash — щоб не втратити летючі дані)" {
    # NIST 5.1.2: спочатку найлетючіше. Збагачення (власник, hash, підпис) — окремими кроками нижче, по знімку.
    $t0 = (Get-Date).ToUniversalTime()
    $errs = @(); $tm = @()   # збій одного джерела не повинен зірвати знімок інших; час кожного — у custody
    $sw = [Diagnostics.Stopwatch]::StartNew()
    # netstat -ano — найшвидше джерело (нативний, без завантаження модулів): фіксує з'єднання за частки секунди
    $ns = ''; try { $ns = ((& netstat.exe -ano 2>&1) | Out-String) } catch { $errs += "netstat: $($_.Exception.Message)" }
    $tm += ('netstat {0:N1}s' -f $sw.Elapsed.TotalSeconds); $sw.Restart()
    try { $D.TcpRaw  = Arr (Get-NetTCPConnection -ErrorAction Stop) } catch { $errs += "TCP: $($_.Exception.Message)" }
    $tm += ('TCP {0:N1}s' -f $sw.Elapsed.TotalSeconds); $sw.Restart()
    try { $D.ProcRaw = Arr (Get-CimInstance Win32_Process -ErrorAction Stop) } catch { $errs += "Процеси: $($_.Exception.Message)" }
    $tm += ('процеси {0:N1}s' -f $sw.Elapsed.TotalSeconds); $sw.Restart()
    # UDP останнім: на DC/DNS-сервері тисячі сокетів (~8 с), а UDP вже зафіксовано в netstat вище
    try { $D.UdpRaw  = Arr (Get-NetUDPEndpoint -ErrorAction Stop) } catch { $errs += "UDP: $($_.Exception.Message)" }
    $tm += ('UDP {0:N1}s' -f $sw.Elapsed.TotalSeconds)
    $D.SnapshotUtc = $t0.ToString('yyyy-MM-dd HH:mm:ss.fff') + 'Z'
    Save-Text ("# netstat -ano, знято {0}`r`n{1}" -f $D.SnapshotUtc, $ns) '01_volatile\netstat_ano.txt'
    Add-Custody 'VOLATILE_SNAPSHOT' 'netstat/TCP/UDP/процеси' $(if ($errs) { 'PARTIAL' } else { 'OK' }) ("TCP {0}, UDP {1}, процесів {2}; {3}" -f @($D.TcpRaw).Count, @($D.UdpRaw).Count, @($D.ProcRaw).Count, ($tm -join ', '))
    if ($errs) { throw ($errs -join ' | ') }
}

Invoke-Step "1.2 ARP/NDP-сусіди, DNS-кеш, IP-конфігурація, маршрути" {
    $arp = foreach ($n in @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -notin @('Unreachable', 'Permanent') })) {
        [pscustomobject]@{ IPAddress = $n.IPAddress; MAC = $n.LinkLayerAddress; State = [string]$n.State; Family = [string]$n.AddressFamily; Interface = $n.InterfaceAlias; IocIP = (Test-IocIPEq $n.IPAddress) }
    }
    $D.Arp = Arr ($arp | Sort-Object @{ Expression = { -not $_.IocIP } }, Family, IPAddress)
    Save-Csv $D.Arp '01_volatile\arp_ndp_neighbors.csv'
    $dns = foreach ($c in @(Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{ Entry = $c.Entry; Name = $c.Name; Data = $c.Data; Type = $c.Type; TTL = $c.TimeToLive; Match = ((Test-KwMatch "$($c.Entry) $($c.Data)") -or (Test-IocIP $c.Data)) }
    }
    $D.Dns = Arr $dns
    Save-Csv $D.Dns '01_volatile\dns_cache.csv'
    $D.IpAddr = Arr (Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ IPAddress = $_.IPAddress; Prefix = $_.PrefixLength; Family = [string]$_.AddressFamily; Interface = $_.InterfaceAlias; Origin = [string]$_.PrefixOrigin } })
    Save-Csv $D.IpAddr '01_volatile\ip_addresses.csv'
    $D.Routes = Arr (Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Destination = $_.DestinationPrefix; NextHop = $_.NextHop; Interface = $_.InterfaceAlias; Metric = $_.RouteMetric } })
    Save-Csv $D.Routes '01_volatile\routes_ipv4.csv'
    $D.OwnIPs = @(@($D.IpAddr | ForEach-Object { $_.IPAddress }) + @('127.0.0.1', '::1'))
}

Invoke-Step "1.3 SMB: сесії, відкриті файли, шари" {
    $D.SmbSess   = Arr (Get-SmbSession -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Client = $_.ClientComputerName; User = $_.ClientUserName; Opens = $_.NumOpens; Seconds = $_.SecondsExists; Dialect = $_.Dialect } })
    $D.SmbOpen   = Arr (Get-SmbOpenFile -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Client = $_.ClientComputerName; User = $_.ClientUserName; Path = $_.Path } })
    $D.SmbShares = Arr (Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Path = $_.Path; Description = $_.Description } })
    Save-Csv $D.SmbSess '01_volatile\smb_sessions.csv'
    Save-Csv $D.SmbOpen '01_volatile\smb_open_files.csv'
    Save-Csv $D.SmbShares '01_volatile\smb_shares.csv'
}

Invoke-Step "1.4 Процеси зі знімка: власник, батьківський процес, hash, підпис" {
    $procs = @($D.ProcRaw)
    $byPid = @{}; foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p.Name }
    $rows = foreach ($p in $procs) {
        $owner = ''
        try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop; if ($o.User) { $owner = "$($o.Domain)\$($o.User)" } } catch {}
        $bi = $null; if ($p.ExecutablePath) { $bi = Get-BinInfo $p.ExecutablePath }
        $sha = ''; $sig = ''; $signer = ''; $cls = ''
        if ($bi) { $sha = $bi.SHA256; $sig = $bi.Sig; $signer = $bi.Signer; $cls = Get-EffPathClass $p.ExecutablePath }
        $flag = @()
        if ($sha -and $IocSha256 -contains $sha) { $flag += 'IOC HASH' }
        if ($sig -and $sig -ne 'Valid' -and $cls -ne 'Системний') { $flag += "Підпис: $sig" }
        if ($cls -in @('Нестандартний', 'Користувацький/тимчасовий')) { $flag += "Розташування: $cls" }
        if (Test-KwMatch "$($p.ExecutablePath) $($p.CommandLine)") { $flag += 'Збіг з маскою IOC' }
        [pscustomobject]@{
            PID = $p.ProcessId; PPID = $p.ParentProcessId; ParentName = $byPid[[int]$p.ParentProcessId]; Name = $p.Name
            Owner = $owner; StartUtc = (U $p.CreationDate); Path = $p.ExecutablePath; CommandLine = $p.CommandLine
            SHA256 = $sha; Signature = $sig; Signer = $signer; Location = $cls; Flags = ($flag -join '; ')
        }
    }
    $D.Procs = Arr $rows
    Save-Csv $D.Procs '01_volatile\processes.csv'
}

Invoke-Step "1.5 Мережеві з'єднання TCP/UDP зі знімка (з процесом-власником)" {
    $pn = @{}; foreach ($p in @($D.Procs)) { $pn[[int]$p.PID] = $p }
    $tcp = foreach ($c in @($D.TcpRaw)) {
        $pr = $pn[[int]$c.OwningProcess]
        [pscustomobject]@{
            State = [string]$c.State; LocalAddress = $c.LocalAddress; LocalPort = $c.LocalPort
            RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort; PID = $c.OwningProcess
            Process = $(if ($pr) { $pr.Name } else { '' }); ProcessPath = $(if ($pr) { $pr.Path } else { '' })
            Signature = $(if ($pr) { $pr.Signature } else { '' }); CreatedLocal = (L $c.CreationTime)
            RemoteIsPublic = (-not (Test-PrivateIP $c.RemoteAddress)); IocIP = (Test-IocIPEq $c.RemoteAddress)
        }
    }
    $D.Tcp = Arr ($tcp | Sort-Object @{ Expression = { if ($_.State -eq 'Established') { 0 } elseif ($_.State -eq 'Listen') { 1 } else { 2 } } }, RemoteAddress)
    Save-Csv $D.Tcp '01_volatile\tcp_connections.csv'
    $udp = foreach ($u in @($D.UdpRaw)) {
        $pr = $pn[[int]$u.OwningProcess]
        [pscustomobject]@{ LocalAddress = $u.LocalAddress; LocalPort = $u.LocalPort; PID = $u.OwningProcess; Process = $(if ($pr) { $pr.Name } else { '' }); ProcessPath = $(if ($pr) { $pr.Path } else { '' }) }
    }
    $D.Udp = Arr $udp
    Save-Csv $D.Udp '01_volatile\udp_endpoints.csv'
}

Invoke-Step "1.6 Сесії користувачів (quser + власники explorer.exe)" {
    $q = ''
    try { $q = ((& quser 2>&1) | Out-String) } catch { $q = "quser недоступний: $($_.Exception.Message)" }
    $expl = @($D.Procs | Where-Object { $_.Name -eq 'explorer.exe' } | ForEach-Object { "explorer.exe PID {0} — {1} — старт {2}" -f $_.PID, $_.Owner, $_.StartUtc })
    $D.SessionsText = ($q.Trim() + [Environment]::NewLine + [Environment]::NewLine + 'Інтерактивні оболонки:' + [Environment]::NewLine + ($expl -join [Environment]::NewLine))
    Save-Text $D.SessionsText '01_volatile\sessions.txt'
}

# ════════════════════════════════════ 2. СИСТЕМА ТА ПЕРСИСТЕНТНІСТЬ ════════════════════════════════════
Invoke-Step "2.1 Локальні облікові записи, адміністратори, політика блокування, audit policy" {
    $D.LocalUsers = Arr (Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Enabled = $_.Enabled; LastLogonUtc = (U $_.LastLogon); PasswordLastSetUtc = (U $_.PasswordLastSet); SID = $_.SID.Value; Description = $_.Description } })
    Save-Csv $D.LocalUsers '02_system\local_users.csv'
    $adm = @()
    try { $adm = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Class = $_.ObjectClass; Source = [string]$_.PrincipalSource; SID = [string]$_.SID } }) }
    catch {
        try {
            $gname = (Resolve-Sid 'S-1-5-32-544').Split('\')[-1]
            $g = [ADSI]("WinNT://$env:COMPUTERNAME/$gname,group")
            $adm = @($g.psbase.Invoke('Members') | ForEach-Object { [pscustomobject]@{ Name = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null); Class = ''; Source = 'ADSI'; SID = '' } })
        } catch { Add-Note "Не вдалося отримати склад групи адміністраторів: $($_.Exception.Message)" }
    }
    $D.LocalAdmins = Arr $adm
    Save-Csv $D.LocalAdmins '02_system\local_admins.csv'
    $D.NetAccounts = ((& net accounts 2>&1) | Out-String).Trim()
    Save-Text $D.NetAccounts '02_system\net_accounts.txt'
    $D.AuditPol = ((& auditpol /get /category:* 2>&1) | Out-String).Trim()
    Save-Text $D.AuditPol '02_system\auditpol.txt'
}

Invoke-Step "2.2 Служби (усі) + hash/підпис бінарників, нестандартні шляхи" {
    $rows = foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
        $exe = Get-ExeFromCmd $s.PathName
        $bi = Get-BinInfo $exe
        $cls = Get-EffPathClass $exe
        $flag = @()
        if ($bi -and $exe -and -not $bi.Exists) { $flag += 'Бінарник відсутній на диску' }
        if ($bi -and $bi.Exists -and $bi.Sig -ne 'Valid') { $flag += "Підпис: $($bi.Sig)" }
        if ($cls -in @('Нестандартний', 'Користувацький/тимчасовий')) { $flag += "Розташування: $cls" }
        if (Test-KwMatch "$($s.Name) $($s.DisplayName) $($s.PathName)") { $flag += 'Збіг з маскою IOC' }
        if ($bi -and $bi.SHA256 -and $IocSha256 -contains $bi.SHA256) { $flag += 'IOC HASH' }
        [pscustomobject]@{
            Name = $s.Name; DisplayName = $s.DisplayName; State = $s.State; StartMode = $s.StartMode; Account = $s.StartName; PID = $s.ProcessId
            CommandLine = $s.PathName; Binary = $exe; BinaryExists = $(if ($bi) { $bi.Exists } else { '' })
            SHA256 = $(if ($bi) { $bi.SHA256 } else { '' }); Signature = $(if ($bi) { $bi.Sig } else { '' }); Signer = $(if ($bi) { $bi.Signer } else { '' })
            Location = $cls; AutoNotRunning = ($s.StartMode -eq 'Auto' -and $s.State -ne 'Running'); Flags = ($flag -join '; ')
        }
    }
    $D.Services = Arr $rows
    Save-Csv $D.Services '02_system\services_all.csv'
    Save-Csv ($D.Services | Where-Object { $_.Flags }) '02_system\services_flagged.csv'
    Save-Csv ($D.Services | Where-Object { $_.AutoNotRunning }) '02_system\services_auto_not_running.csv'
}

Invoke-Step "2.3 Задачі планувальника: автор (з XML задачі), дії, тригери, останній/наступний запуск" {
    $rows = foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        $isMs = $t.TaskPath -like '\Microsoft\*'
        $acts = @($t.Actions | ForEach-Object { if ($_.Execute) { ("{0} {1}" -f $_.Execute, $_.Arguments).Trim() } elseif ($_.ClassId) { "COM:$($_.ClassId)" } })
        $firstExe = ''
        foreach ($a in @($t.Actions)) { if ($a.Execute) { $firstExe = Resolve-BareExe ([Environment]::ExpandEnvironmentVariables(([string]$a.Execute).Trim('"'))); break } }
        $cls = Get-EffPathClass $firstExe
        # \Microsoft\* пропускаємо лише якщо задача виглядає штатною (маскування під системну — класичний прийом)
        $msWhy = ''
        if ($isMs) { $msWhy = Get-MsTaskSuspicion $firstExe ($acts -join ' ') ([string]$t.Author); if (-not $msWhy) { continue } }
        $info = $null; try { $info = Get-ScheduledTaskInfo -InputObject $t -ErrorAction Stop } catch {}
        $trig = @($t.Triggers | ForEach-Object {
            $n = ([string]$_.CimClass.CimClassName) -replace '^MSFT_Task', '' -replace 'Trigger$', ''
            if ($_.StartBoundary) { "$n від $($_.StartBoundary)" } else { $n } }) -join ' | '
        $bi = $null; if ($firstExe) { $bi = Get-BinInfo $firstExe }
        $flag = @()
        if (-not $isMs) { $flag += 'Стороння задача' } else { $flag += "Маскування під \Microsoft\: $msWhy" }
        if ($cls -in @('Нестандартний', 'Користувацький/тимчасовий')) { $flag += "Дія: $cls" }
        if (Test-KwMatch "$($t.TaskName) $($t.Author) $($acts -join ' ')") { $flag += 'Збіг з маскою IOC' }
        if ($bi -and $bi.SHA256 -and $IocSha256 -contains $bi.SHA256) { $flag += 'IOC HASH' }
        if ($t.Settings -and $t.Settings.Hidden) { $flag += 'Прихована' }
        $last = ''; $next = ''; $res = ''
        if ($info) {
            $last = U $info.LastRunTime; $next = U $info.NextRunTime
            if ($null -ne $info.LastTaskResult) { $res = ('0x{0:X}' -f [int64]$info.LastTaskResult) }
        }
        $reg = ''; if ($t.Date) { $reg = U $t.Date }
        [pscustomobject]@{
            TaskName = $t.TaskName; TaskPath = $t.TaskPath; State = [string]$t.State; Author = $t.Author
            RegisteredUtc = $reg; RunAs = $t.Principal.UserId; RunLevel = [string]$t.Principal.RunLevel
            Actions = ($acts -join ' | '); ActionBinary = $firstExe; ActionSHA256 = $(if ($bi) { $bi.SHA256 } else { '' })
            ActionSignature = $(if ($bi) { $bi.Sig } else { '' }); Triggers = $trig
            LastRunUtc = $last; NextRunUtc = $next; LastResult = $res; Flags = ($flag -join '; ')
        }
    }
    $D.Tasks = Arr $rows
    Save-Csv $D.Tasks '02_system\scheduled_tasks_nonms_or_suspicious.csv'
}

Invoke-Step "2.4 Автозапуск: Run/RunOnce, Winlogon, IFEO, Startup, WMI-підписки" {
    $rows = New-Object System.Collections.Generic.List[object]
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $keys += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
        $keys += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    foreach ($k in $keys) {
        $item = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $exe = Get-ExeFromCmd ([string]$p.Value); $bi = Get-BinInfo $exe
            $rows.Add([pscustomobject]@{ Type = 'Run-ключ'; Location = $k; Name = $p.Name; Command = [string]$p.Value; Binary = $exe
                Signature = $(if ($bi) { $bi.Sig } else { '' }); PathClass = (Get-EffPathClass $exe); Match = (Test-KwMatch ("{0} {1}" -f $p.Name, $p.Value)) })
        }
    }
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($wl) {
        foreach ($n in 'Shell', 'Userinit') {
            $v = [string]$wl.$n
            $ok = ($n -eq 'Shell' -and $v -match '^(?i)explorer\.exe$') -or ($n -eq 'Userinit' -and $v -match '^(?i)C:\\Windows\\system32\\userinit\.exe,?$')
            $rows.Add([pscustomobject]@{ Type = 'Winlogon'; Location = 'HKLM\...\Winlogon'; Name = $n; Command = $v; Binary = ''; Signature = ''; PathClass = $(if ($ok) { 'стандарт' } else { 'НЕСТАНДАРТНЕ значення' }); Match = (-not $ok) })
        }
    }
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue)) {
        $dbg = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($dbg) { $rows.Add([pscustomobject]@{ Type = 'IFEO Debugger'; Location = $k.PSChildName; Name = 'Debugger'; Command = $dbg; Binary = (Get-ExeFromCmd $dbg); Signature = ''; PathClass = (Get-PathClass (Get-ExeFromCmd $dbg)); Match = $true }) }
    }
    $startDirs = @(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
    foreach ($p in @($D.Profiles | Where-Object { $_.Exists })) { $startDirs += (Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') }
    foreach ($sd in $startDirs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $sd -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $rows.Add([pscustomobject]@{ Type = 'Startup-папка'; Location = $sd; Name = $f.Name; Command = $f.FullName; Binary = $f.FullName; Signature = ''; PathClass = (Get-PathClass $f.FullName); Match = (Test-KwMatch $f.Name) })
        }
    }
    $D.Autoruns = Arr $rows
    Save-Csv $D.Autoruns '02_system\autoruns.csv'

    $wmi = New-Object System.Collections.Generic.List[object]
    foreach ($cls in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
        foreach ($o in @(Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction SilentlyContinue)) {
            $name = [string]$o.Name
            $det = ''
            if ($cls -eq '__EventFilter') { $det = [string]$o.Query }
            elseif ($cls -eq '__EventConsumer') { $det = ("{0} {1} {2}" -f $o.CimClass.CimClassName, $o.CommandLineTemplate, $o.ScriptText).Trim() }
            else { $det = ("{0} → {1}" -f $o.Filter, $o.Consumer); $name = 'binding' }
            $benign = ($det -match 'SCM Event Log|BVTFilter|BVTConsumer' -or $name -match '^(SCM Event Log|BVTFilter|BVTConsumer)')
            $wmi.Add([pscustomobject]@{ Class = $cls; Name = $name; Details = $det; LikelyBenign = $benign })
        }
    }
    $D.WmiPersist = Arr $wmi
    Save-Csv $D.WmiPersist '02_system\wmi_subscriptions.csv'
}

Invoke-Step "2.5 Microsoft Defender: стан захисту та винятки" {
    $st = $null; $pref = $null
    try { $st = Get-MpComputerStatus -ErrorAction Stop } catch { Add-Note "Get-MpComputerStatus недоступний: $($_.Exception.Message)" }
    try { $pref = Get-MpPreference -ErrorAction Stop } catch { Add-Note "Get-MpPreference недоступний: $($_.Exception.Message)" }
    $rows = @()
    if ($st) {
        foreach ($n in 'AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'OnAccessProtectionEnabled', 'IsTamperProtected', 'AMRunningMode', 'AMProductVersion', 'AntivirusSignatureLastUpdated') {
            $rows += [pscustomobject]@{ Setting = $n; Value = [string]$st.$n }
        }
    }
    if ($pref) { foreach ($n in 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning', 'MAPSReporting', 'SubmitSamplesConsent') { $rows += [pscustomobject]@{ Setting = "Pref.$n"; Value = [string]$pref.$n } } }
    $D.MpStatusRows = Arr $rows
    Save-Csv $D.MpStatusRows '02_system\defender_status.csv'
    $ex = @()
    if ($pref) {
        foreach ($t in @(@{ N = 'Path'; P = 'ExclusionPath' }, @{ N = 'Process'; P = 'ExclusionProcess' }, @{ N = 'Extension'; P = 'ExclusionExtension' }, @{ N = 'IpAddress'; P = 'ExclusionIpAddress' })) {
            foreach ($v in @($pref.($t.P))) {
                if (-not $v) { continue }
                if ([string]$v -like 'N/A*') { Add-Note "Винятки Defender приховані: $v"; continue }
                $ex += [pscustomobject]@{ Type = $t.N; Value = [string]$v; PathClass = (Get-PathClass ([string]$v)); Match = (Test-KwMatch ([string]$v)) }
            }
        }
    }
    $D.MpExclusions = Arr $ex
    Save-Csv $D.MpExclusions '02_system\defender_exclusions.csv'
}

Invoke-Step "2.6 Ліцензування / KMS: статус активації, KMS-хост, оцінка часу останньої активації" {
    $lsMap = @{ 0 = 'Unlicensed'; 1 = 'Licensed'; 2 = 'OOB Grace'; 3 = 'OOT Grace'; 4 = 'Non-Genuine Grace'; 5 = 'Notification'; 6 = 'Extended Grace' }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($cls in 'SoftwareLicensingProduct', 'OfficeSoftwareProtectionProduct') {
        $items = @()
        try { $items = @(Get-CimInstance -ClassName $cls -Filter 'PartialProductKey IS NOT NULL' -ErrorAction Stop) } catch { continue }
        foreach ($p in $items) {
            $grace = [int64]$p.GracePeriodRemaining
            $isKms = ([string]$p.Description -match '(?i)KMSCLIENT|KMS_?Client|VOLUME_KMS')
            $est = ''
            if ($isKms -and [int]$p.LicenseStatus -eq 1 -and $grace -gt 0 -and $grace -le 259200) {
                $est = U ((Get-Date).AddMinutes(-(259200 - $grace)))   # KMS-активація дійсна 180 діб (259200 хв)
            }
            $rows.Add([pscustomobject]@{
                Class = $cls; Name = $p.Name; Description = $p.Description; PartialKey = $p.PartialProductKey
                LicenseStatus = ("{0} ({1})" -f $p.LicenseStatus, $lsMap[[int]$p.LicenseStatus]); GraceDaysLeft = [math]::Round($grace / 1440, 1)
                KmsChannel = $isKms; KmsMachine = $p.KeyManagementServiceMachine; KmsPort = $p.KeyManagementServicePort
                DiscoveredKms = $p.DiscoveredKeyManagementServiceMachineName; DiscoveredKmsIp = $p.DiscoveredKeyManagementServiceMachineIpAddress
                EstLastKmsActivationUtc = $est
            })
        }
    }
    $D.Licensing = Arr $rows
    Save-Csv $D.Licensing '02_system\licensing_products.csv'
    $kr = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
                   'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OfficeSoftwareProtectionPlatform',
                   'Registry::HKEY_USERS\S-1-5-20\Software\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform') {
        $it = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $it) { continue }
        foreach ($p in $it.PSObject.Properties) { if ($p.Name -match '(?i)KeyManagementService|DiscoveredKeyManagement') { $kr += [pscustomobject]@{ Key = $k; Name = $p.Name; Value = [string]$p.Value; IocIP = (Test-IocIP ([string]$p.Value)) } } }
    }
    $D.KmsReg = Arr $kr
    Save-Csv $D.KmsReg '02_system\kms_registry.csv'
}

Invoke-Step "2.7 Firewall: профілі, налаштування логування, активні правила" {
    $D.FwProfiles = Arr (Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Profile = $_.Name; Enabled = [string]$_.Enabled; DefaultInbound = [string]$_.DefaultInboundAction; DefaultOutbound = [string]$_.DefaultOutboundAction
            LogAllowed = [string]$_.LogAllowed; LogBlocked = [string]$_.LogBlocked; LogFile = [Environment]::ExpandEnvironmentVariables([string]$_.LogFileName); LogMaxKB = $_.LogMaxSizeKilobytes } })
    Save-Csv $D.FwProfiles '04_firewall\fw_profiles.csv'
    foreach ($p in @($D.FwProfiles)) { if ($p.LogAllowed -ne 'True') { Add-Note ("Firewall-профіль {0}: LogAllowed={1} — дозволені з'єднання можуть не потрапляти в pfirewall.log." -f $p.Profile, $p.LogAllowed) } }
    $pfIdx = @{}; foreach ($f in @(Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) { $pfIdx[$f.InstanceID] = $f }
    $afIdx = @{}; foreach ($f in @(Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue)) { $afIdx[$f.InstanceID] = $f }
    $adIdx = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -All -ErrorAction SilentlyContinue)) { $adIdx[$f.InstanceID] = $f }
    $rows = foreach ($r in @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { [string]$_.Enabled -eq 'True' })) {
        $pf = $pfIdx[$r.Name]; $af = $afIdx[$r.Name]; $ad = $adIdx[$r.Name]
        $prog = ''; if ($af) { $prog = [Environment]::ExpandEnvironmentVariables([string]$af.Program) }
        $lp = ''; $rp = ''; $proto = ''
        if ($pf) { $lp = (@($pf.LocalPort) -join ','); $rp = (@($pf.RemotePort) -join ','); $proto = [string]$pf.Protocol }
        $ra = ''; if ($ad) { $ra = (@($ad.RemoteAddress) -join ',') }
        $flag = @()
        if (Test-KwMatch "$($r.Name) $($r.DisplayName) $prog") { $flag += 'Збіг з маскою IOC' }
        if ("$lp,$rp" -match '(^|,)1688(,|$)') { $flag += 'Порт 1688 (KMS)' }
        if ($prog -and $prog -notin @('Any', 'System') -and (Get-EffPathClass $prog) -in @('Нестандартний', 'Користувацький/тимчасовий')) { $flag += 'Програма в нестандартному шляху' }
        [pscustomobject]@{ Name = $r.Name; DisplayName = $r.DisplayName; Direction = [string]$r.Direction; Action = [string]$r.Action; Profile = [string]$r.Profile
            Protocol = $proto; LocalPort = $lp; RemotePort = $rp; RemoteAddress = $ra; Program = $prog; Group = $r.Group; Flags = ($flag -join '; ') }
    }
    $D.FwRules = Arr $rows
    Save-Csv $D.FwRules '04_firewall\fw_rules_enabled.csv'
}

Invoke-Step "2.8 Журнали подій: розмір, заповненість, глибина історії, покриття вікна + налаштування аудиту" {
    $recMB = [ordered]@{
        'Security' = 1024; 'System' = 256; 'Application' = 256; 'Windows PowerShell' = 256
        'Microsoft-Windows-Sysmon/Operational' = 1024; 'Microsoft-Windows-PowerShell/Operational' = 512
        'Microsoft-Windows-TaskScheduler/Operational' = 128; 'Microsoft-Windows-Windows Defender/Operational' = 128
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' = 128
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 128
        'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational' = 128
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' = 128
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($name in $recMB.Keys) {
        $l = $null
        try { $l = Get-WinEvent -ListLog $name -ErrorAction Stop } catch {
            $rows.Add([pscustomobject]@{ Log = $name; Exists = $false; Enabled = ''; Mode = ''; MaxMB = ''; SizeMB = ''; FillPct = ''; Records = ''; OldestLocal = ''; HistoryDays = ''
                RecommendedMB = $recMB[$name]; Severity = $(if ($name -like '*Sysmon*') { 'Середньо' } else { 'Інфо' })
                Advice = $(if ($name -like '*Sysmon*') { 'Sysmon не встановлено — немає деталізації процесів/мережі/файлів (рекомендовано Sysmon + конфіг SwiftOnSecurity/Olaf Hartong)' } else { 'Журнал відсутній на цій системі' }) })
            continue
        }
        $oldest = $null
        if ($l.RecordCount -gt 0) { try { $oldest = (Get-WinEvent -LogName $name -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch {} }
        $size = [int64]$l.FileSize; $max = [int64]$l.MaximumSizeInBytes
        $a = Get-LogAdvice -Name $name -Enabled ([bool]$l.IsEnabled) -Mode ([string]$l.LogMode) -MaxBytes $max -SizeBytes $size -Oldest $oldest -RecBytes ([int64]$recMB[$name] * 1MB) -WindowStart $Since
        $rows.Add([pscustomobject]@{ Log = $name; Exists = $true; Enabled = $l.IsEnabled; Mode = [string]$l.LogMode
            MaxMB = [math]::Round($max / 1MB, 1); SizeMB = [math]::Round($size / 1MB, 1); FillPct = $(if ($max) { [math]::Round(100 * $size / $max) } else { '' })
            Records = $l.RecordCount; OldestLocal = (L $oldest); HistoryDays = $a.HistoryDays; RecommendedMB = $recMB[$name]; Severity = $a.Severity; Advice = $a.Advice })
    }
    $D.LogHealth = Arr $rows
    Save-Csv $D.LogHealth '02_system\eventlog_health.csv'

    # Налаштування аудиту (auditpol /r дає CSV; Setting Value: 1=успіх, 2=відмова, 3=обидва)
    $aud = New-Object System.Collections.Generic.List[object]
    $subs = @(
        @{ N = 'Logon (4624/4625)'; G = '{0CCE9215-69AE-11D9-BED3-505054503030}'; R = 3 },
        @{ N = 'Account Lockout (4625 з lockout)'; G = '{0CCE9217-69AE-11D9-BED3-505054503030}'; R = 2 },
        @{ N = 'Process Creation (4688)'; G = '{0CCE922B-69AE-11D9-BED3-505054503030}'; R = 1 },
        @{ N = 'Security System Extension (4697)'; G = '{0CCE9211-69AE-11D9-BED3-505054503030}'; R = 1 },
        @{ N = 'Other Object Access (4698-4702, задачі)'; G = '{0CCE9227-69AE-11D9-BED3-505054503030}'; R = 3 },
        @{ N = 'User Account Management (4720/4722/4724)'; G = '{0CCE9235-69AE-11D9-BED3-505054503030}'; R = 3 },
        @{ N = 'Security Group Management (4732)'; G = '{0CCE9237-69AE-11D9-BED3-505054503030}'; R = 1 },
        @{ N = 'MPSSVC Rule-Level Policy Change (4946-4948)'; G = '{0CCE9232-69AE-11D9-BED3-505054503030}'; R = 1 }
    )
    $bits = @{ 0 = 'Немає аудиту'; 1 = 'Успіх'; 2 = 'Відмова'; 3 = 'Успіх і відмова' }
    foreach ($sb in $subs) {
        $cur = ''; $ok = $null
        $ap = Get-AuditSubcategory $sb.G
        if ($null -ne $ap.Value) { $v = [int]$ap.Value; $cur = $bits[$v]; if ($ap.Text) { $cur += " ($($ap.Text))" }; $ok = (($v -band $sb.R) -eq $sb.R) }
        else { $cur = $(if ($ap.Text) { "не розпізнано: $($ap.Text)" } else { 'не вдалося прочитати' }) }
        $fix = ''
        if ($ok -eq $false) {
            $fix = 'auditpol /set /subcategory:"{0}"' -f $sb.G
            if ($sb.R -band 1) { $fix += ' /success:enable' }; if ($sb.R -band 2) { $fix += ' /failure:enable' }
        }
        $aud.Add([pscustomobject]@{ Setting = "Audit: $($sb.N)"; Current = $cur; Recommended = $bits[$sb.R]; OK = $ok; Fix = $fix })
    }
    $pol = @(
        @{ N = 'PowerShell Script Block Logging (4104)'; K = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; V = 'EnableScriptBlockLogging'; Fix = 'GPO: Administrative Templates → Windows PowerShell → Turn on PowerShell Script Block Logging' },
        @{ N = 'Командний рядок у 4688'; K = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; V = 'ProcessCreationIncludeCmdLine_Enabled'; Fix = 'GPO: System → Audit Process Creation → Include command line in process creation events' }
    )
    foreach ($p in $pol) {
        $v = $null; try { $v = (Get-ItemProperty -LiteralPath $p.K -Name $p.V -ErrorAction Stop).($p.V) } catch {}
        $aud.Add([pscustomobject]@{ Setting = $p.N; Current = $(if ($v -eq 1) { 'Увімкнено' } else { 'Вимкнено / не задано' }); Recommended = 'Увімкнено'; OK = ($v -eq 1); Fix = $(if ($v -eq 1) { '' } else { $p.Fix }) })
    }
    $sysmon = @($D.Services | Where-Object { $_.Name -like 'Sysmon*' })
    $aud.Add([pscustomobject]@{ Setting = 'Sysmon'; Current = $(if ($sysmon.Count) { "Встановлено ($($sysmon[0].Name), $($sysmon[0].State))" } else { 'Не встановлено' }); Recommended = 'Встановлено'; OK = ($sysmon.Count -gt 0); Fix = $(if ($sysmon.Count) { '' } else { 'Встановити Sysmon з конфігом (SwiftOnSecurity / Olaf Hartong sysmon-modular)' }) })
    foreach ($fp in @($D.FwProfiles)) {
        $okLog = ($fp.LogBlocked -eq 'True' -and $fp.LogAllowed -eq 'True' -and [int64]$fp.LogMaxKB -ge 16384)
        $aud.Add([pscustomobject]@{ Setting = "Firewall-лог ($($fp.Profile))"; Current = ("Allowed={0}, Blocked={1}, {2} KB" -f $fp.LogAllowed, $fp.LogBlocked, $fp.LogMaxKB); Recommended = 'Allowed+Blocked, ≥16 MB'; OK = $okLog
            Fix = $(if ($okLog) { '' } else { "Set-NetFirewallProfile -Name $($fp.Profile) -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767" }) })
    }
    $D.AuditSettings = Arr $aud
    Save-Csv $D.AuditSettings '02_system\audit_settings_check.csv'
}

# ════════════════════════════════════ 2.9 АУДИТ КОНФІГУРАЦІЇ БЕЗПЕКИ ════════════════════════════════════
# Лише читання реєстру/CIM. Не «що сталося», а «наскільки хост вразливий»: кожен рядок — поточне значення,
# рекомендоване, команда виправлення і чому це важливо. Ризики рівня Високо/Середньо потрапляють у прапорці (6.4).
Invoke-Step "2.9 Налаштування безпеки: SMB, LLMNR/NetBIOS, WDigest, LSA, UAC, RDP, NTLM, PowerShell v2, BitLocker, ASR, LAPS, оновлення" {
    $rows = New-Object System.Collections.Generic.List[object]
    function Get-RegValue { param([string]$Key, [string]$Name) try { return (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction Stop).$Name } catch { return $null } }
    function Add-Chk {   # State: ok / risk / na / unknown
        param([string]$Area, [string]$Check, $Current, [string]$Recommended, [string]$State, [string]$Sev = '', [string]$Fix = '', [string]$Why = '')
        $st = switch ($State) { 'ok' { 'OK' } 'risk' { 'Ризик' } 'na' { 'Н/д' } default { 'Невідомо' } }
        if ($State -ne 'risk') { $Sev = '' }
        if ($State -eq 'ok') { $Fix = '' }
        $rows.Add([pscustomobject]@{ Area = $Area; Check = $Check; Current = [string]$Current; Recommended = $Recommended; Status = $st; Severity = $Sev; Fix = $Fix; Why = $Why })
    }
    $isWs = ($D.ProductType -eq 1)
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    # ── SMB ──
    $smb = $null; try { $smb = Get-SmbServerConfiguration -ErrorAction Stop } catch {}
    if ($smb) {
        $on = [bool]$smb.EnableSMB1Protocol
        Add-Chk 'Мережа' 'SMBv1 (сервер)' $(if ($on) { 'Увімкнено' } else { 'Вимкнено' }) 'Вимкнено' $(if ($on) { 'risk' } else { 'ok' }) 'Високо' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' 'EternalBlue/WannaCry; застарілий протокол без захисту від relay'
        $sg = [bool]$smb.RequireSecuritySignature
        Add-Chk 'Мережа' 'SMB signing обовʼязковий (сервер)' $(if ($sg) { 'Так' } else { 'Ні' }) 'Так' $(if ($sg) { 'ok' } else { 'risk' }) $(if ($D.IsDC) { 'Високо' } else { 'Середньо' }) 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force' 'NTLM relay на SMB (ntlmrelayx)'
    } else { Add-Chk 'Мережа' 'SMB (сервер)' 'Get-SmbServerConfiguration недоступний' 'SMBv1 вимкнено, signing обовʼязковий' 'unknown' }

    # ── Отруєння імен (Responder) ──
    $mc = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    Add-Chk 'Мережа' 'LLMNR' $(if ($mc -eq 0) { 'Вимкнено політикою' } else { 'Увімкнено (політику не задано)' }) 'Вимкнено' $(if ($mc -eq 0) { 'ok' } else { 'risk' }) 'Середньо' 'GPO: Network → DNS Client → Turn off multicast name resolution = Enabled' 'Отруєння LLMNR (Responder) → перехоплення NTLM-хешів'
    $nb = @()
    try { $nb = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop) } catch {}
    if ($nb.Count) {
        $bad = @($nb | Where-Object { [int]$_.TcpipNetbiosOptions -ne 2 })
        $cur = (@($nb | ForEach-Object { "{0}: {1}" -f $_.Description, $(switch ([int]$_.TcpipNetbiosOptions) { 0 { 'за DHCP (зазвичай увімкнено)' } 1 { 'увімкнено' } 2 { 'вимкнено' } default { '?' } }) }) -join '; ')
        Add-Chk 'Мережа' 'NetBIOS over TCP/IP' $cur 'Вимкнено на всіх адаптерах' $(if ($bad.Count) { 'risk' } else { 'ok' }) 'Середньо' 'Адаптер → IPv4 → Додатково → WINS → Вимкнути NetBIOS (або DHCP option 001 = 2)' 'Отруєння NBT-NS (Responder)'
    }

    # ── Облікові дані в памʼяті / LSA ──
    $wd = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    Add-Chk 'Облікові дані' 'WDigest UseLogonCredential' $(if ($null -eq $wd) { 'не задано (0 за замовчуванням)' } else { $wd }) '0' $(if ($wd -eq 1) { 'risk' } else { 'ok' }) 'Високо' 'reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f' 'Паролі у відкритому вигляді в LSASS (Mimikatz). Значення 1 зловмисники ставлять навмисно — перевірте, хто змінив'
    $ppl = Get-RegValue $lsa 'RunAsPPL'
    Add-Chk 'Облікові дані' 'LSA Protection (RunAsPPL)' $(if ($null -eq $ppl) { 'не задано' } else { $ppl }) '1 або 2' $(if ($ppl -in 1, 2) { 'ok' } else { 'risk' }) 'Середньо' 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f (+ перезавантаження; перевірте сумісність драйверів/AV)' 'Захист LSASS від дампу памʼяті'
    if ($D.IsDC) { Add-Chk 'Облікові дані' 'Credential Guard' 'контролер домену' 'н/д' 'na' '' '' 'На DC Credential Guard не захищає базу AD і не рекомендований' }
    else {
        $cg = $null; try { $cg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop } catch {}
        if ($cg) { $run = (@($cg.SecurityServicesRunning) -contains 1); Add-Chk 'Облікові дані' 'Credential Guard' $(if ($run) { 'Працює' } else { 'Не працює' }) 'Працює' $(if ($run) { 'ok' } else { 'risk' }) 'Інфо' 'GPO: System → Device Guard → Turn On Virtualization Based Security (Credential Guard)' 'Ізоляція NTLM-хешів і Kerberos-квитків від LSASS' }
        else { Add-Chk 'Облікові дані' 'Credential Guard' 'Win32_DeviceGuard недоступний' 'Працює' 'unknown' }
    }
    $nolm = Get-RegValue $lsa 'NoLMHash'
    Add-Chk 'NTLM' 'Зберігання LM-хешів (NoLMHash)' $(if ($null -eq $nolm) { 'не задано (1 за замовчуванням)' } else { $nolm }) '1' $(if ($nolm -eq 0) { 'risk' } else { 'ok' }) 'Високо' 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NoLMHash /t REG_DWORD /d 1 /f' 'LM-хеш зламується за хвилини'
    $lmc = Get-RegValue $lsa 'LmCompatibilityLevel'
    $lmv = 3; if ($null -ne $lmc) { $lmv = [int]$lmc }
    # На DC рівень визначає, що контролер ПРИЙМАЄ від клієнтів: < 5 — приймає NTLMv1 (і LM при < 4)
    if ($D.IsDC) { $lmState = $(if ($lmv -ge 5) { 'ok' } else { 'risk' }); $lmSev = $(if ($lmv -lt 3) { 'Високо' } else { 'Середньо' }); $lmRec = '5 (DC відхиляє LM і NTLMv1)' }
    else { $lmState = $(if ($lmv -lt 3) { 'risk' } else { 'ok' }); $lmSev = 'Високо'; $lmRec = '5 (лише NTLMv2), мінімум 3' }
    Add-Chk 'NTLM' 'LmCompatibilityLevel' $(if ($null -eq $lmc) { 'не задано (3 за замовчуванням)' } else { $lmc }) $lmRec $lmState $lmSev 'GPO: Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM' 'LM/NTLMv1 дозволяють відновити хеш з перехопленого трафіку'
    $ras = Get-RegValue $lsa 'RestrictAnonymousSAM'
    Add-Chk 'NTLM' 'Анонімний перелік SAM (RestrictAnonymousSAM)' $(if ($null -eq $ras) { 'не задано (1 за замовчуванням)' } else { $ras }) '1' $(if ($ras -eq 0) { 'risk' } else { 'ok' }) 'Середньо' 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f' 'Анонімна розвідка облікових записів'

    # ── UAC / віддалене адміністрування ──
    $lua = Get-RegValue $sysPol 'EnableLUA'
    Add-Chk 'UAC' 'UAC (EnableLUA)' $(if ($null -eq $lua) { 'не задано (1)' } else { $lua }) '1' $(if ($lua -eq 0) { 'risk' } else { 'ok' }) 'Високо' 'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f' 'Без UAC будь-який процес адміністратора працює з повними правами'
    $cpa = Get-RegValue $sysPol 'ConsentPromptBehaviorAdmin'
    Add-Chk 'UAC' 'Запит підвищення для адмінів (ConsentPromptBehaviorAdmin)' $(if ($null -eq $cpa) { 'не задано (5)' } else { $cpa }) '2 або 5' $(if ($cpa -eq 0) { 'risk' } else { 'ok' }) 'Середньо' 'GPO: User Account Control: Behavior of the elevation prompt for administrators ≠ Elevate without prompting' '0 = тихе підвищення прав'
    $latfp = Get-RegValue $sysPol 'LocalAccountTokenFilterPolicy'
    Add-Chk 'UAC' 'LocalAccountTokenFilterPolicy' $(if ($null -eq $latfp) { 'не задано (0)' } else { $latfp }) '0' $(if ($latfp -eq 1) { 'risk' } else { 'ok' }) 'Середньо' 'reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /f' '1 = повні права локальних адмінів по мережі (pass-the-hash, lateral movement)'

    # ── RDP ──
    $deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($deny -eq 1) { Add-Chk 'RDP' 'RDP NLA' 'RDP вимкнено' 'NLA увімкнено' 'na' }
    else {
        $nla = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
        $src = 'політика'
        if ($null -eq $nla) { $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'; $src = 'RDP-Tcp' }
        Add-Chk 'RDP' 'RDP NLA (UserAuthentication)' ("RDP увімкнено; NLA={0} ({1})" -f $nla, $src) '1' $(if ($nla -eq 1) { 'ok' } else { 'risk' }) 'Високо' 'GPO: Remote Desktop Session Host → Security → Require user authentication … by using NLA = Enabled' 'Без NLA логін-екран доступний до автентифікації (brute-force, BlueKeep-клас вразливостей)'
    }

    # ── PowerShell v2 (обхід AMSI і Script Block Logging) ──
    $eng = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion'
    $gac = Test-Path -LiteralPath (Join-Path $env:SystemRoot 'assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll')
    $n35 = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' 'Install'
    $v2 = (([string]$eng -like '2*') -or $gac)
    $v2run = ($v2 -and $n35 -eq 1)
    Add-Chk 'PowerShell' 'PowerShell v2 (ознаки)' ("рушій v2: {0}; збірка v1.0 у GAC: {1}; .NET 3.5: {2}" -f $(if ($v2) { 'так' } else { 'ні' }), $(if ($gac) { 'так' } else { 'ні' }), $(if ($n35 -eq 1) { 'так' } else { 'ні' })) 'Видалено' $(if ($v2run) { 'risk' } elseif ($v2) { 'risk' } else { 'ok' }) $(if ($v2run) { 'Середньо' } else { 'Інфо' }) $(if ($isWs) { 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' } else { 'Uninstall-WindowsFeature PowerShell-V2' }) 'powershell -version 2 обходить AMSI і Script Block Logging (4104). Без .NET 3.5 не запускається'

    # ── Шифрування диска ──
    $bl = $null; $blErr = ''
    try { $bl = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter ("DriveLetter='{0}'" -f $env:SystemDrive) -ErrorAction Stop } catch { $blErr = $_.Exception.Message }
    if ($bl) { $prot = ([int]$bl.ProtectionStatus -eq 1); Add-Chk 'Дані' ("BitLocker ({0})" -f $env:SystemDrive) $(if ($prot) { 'Захист увімкнено' } else { 'Захист вимкнено' }) 'Увімкнено' $(if ($prot) { 'ok' } else { 'risk' }) $(if ($isWs) { 'Середньо' } else { 'Інфо' }) 'manage-bde -on C: (або через Intune/GPO)' 'Викрадення диска / офлайн-доступ до даних' }
    else { Add-Chk 'Дані' ("BitLocker ({0})" -f $env:SystemDrive) 'компонент BitLocker не встановлено / недоступний' 'Увімкнено' $(if ($isWs) { 'unknown' } else { 'na' }) }

    # ── Defender ASR ──
    $mp = $null; try { $mp = Get-MpPreference -ErrorAction Stop } catch {}
    if ($mp) {
        $act = @($mp.AttackSurfaceReductionRules_Actions)
        $blk = @($act | Where-Object { [int]$_ -in 1, 6 }).Count; $aud = @($act | Where-Object { [int]$_ -eq 2 }).Count
        Add-Chk 'Defender' 'Правила ASR' ("блок/попередження: {0}; аудит: {1}" -f $blk, $aud) 'Ключові правила в режимі Block' $(if ($blk -gt 0) { 'ok' } else { 'risk' }) $(if ($isWs) { 'Середньо' } else { 'Інфо' }) 'Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled (напр. 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 — крадіжка з LSASS)' 'ASR блокує типові ланцюжки: макроси Office, дамп LSASS, запуск з пошти/USB'
    } else { Add-Chk 'Defender' 'Правила ASR' 'Get-MpPreference недоступний (інший AV?)' 'Ключові правила в режимі Block' 'unknown' }

    # ── LAPS ──
    $cs = $null; try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch {}
    if ($D.IsDC) { Add-Chk 'Облікові дані' 'LAPS' 'контролер домену' 'н/д (на DC — DSRM-пароль)' 'na' }
    elseif ($cs -and -not $cs.PartOfDomain) { Add-Chk 'Облікові дані' 'LAPS' 'хост не в домені' 'н/д' 'na' }
    else {
        $legacy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
        $wl = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' 'BackupDirectory'
        if ($null -eq $wl) { $wl = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory' }
        $ok = ($legacy -eq 1 -or $wl -in 1, 2)
        Add-Chk 'Облікові дані' 'LAPS (пароль локального адміна)' ("legacy LAPS: {0}; Windows LAPS BackupDirectory: {1}" -f $(if ($legacy -eq 1) { 'так' } else { 'ні' }), $(if ($null -eq $wl) { 'не задано' } else { $wl })) 'Увімкнено' $(if ($ok) { 'ok' } else { 'risk' }) 'Середньо' 'GPO: System → LAPS → Configure password backup directory = Active Directory' 'Однаковий пароль локального адміна на всіх хостах = lateral movement з одного хешу'
    }

    # ── Облікові записи / служби / firewall ──
    $guest = @($D.LocalUsers | Where-Object { ([string]$_.SID) -match '-501$' })
    if ($guest.Count) { $ge = ([string]$guest[0].Enabled -eq 'True'); Add-Chk 'Облікові записи' 'Гість (RID 501)' $(if ($ge) { 'Увімкнено' } else { 'Вимкнено' }) 'Вимкнено' $(if ($ge) { 'risk' } else { 'ok' }) 'Високо' ("Disable-LocalUser -SID {0}" -f $guest[0].SID) 'Анонімний/гостьовий доступ до ресурсів' }
    $sp = @($D.Services | Where-Object { $_.Name -eq 'Spooler' })
    if ($sp.Count) {
        $spRun = ($sp[0].State -eq 'Running')
        if ($D.IsDC) { Add-Chk 'Служби' 'Print Spooler на контролері домену' $sp[0].State 'Зупинено і вимкнено' $(if ($spRun) { 'risk' } else { 'ok' }) 'Високо' 'Stop-Service Spooler; Set-Service Spooler -StartupType Disabled' 'PrintNightmare; примусова автентифікація DC (PrinterBug) → relay/делегування' }
        else { Add-Chk 'Служби' 'Print Spooler' $sp[0].State 'Вимкнено, якщо друк не потрібен' 'na' }
    }
    foreach ($fp in @($D.FwProfiles)) {
        $en = ($fp.Enabled -eq 'True')
        $inb = [string]$fp.DefaultInbound; if ($inb -eq 'NotConfigured') { $inb = 'NotConfigured (= Block за замовчуванням)' }
        Add-Chk 'Firewall' ("Профіль {0}" -f $fp.Profile) $(if ($en) { "Увімкнено, вхідні: $inb" } else { 'ВИМКНЕНО' }) 'Увімкнено, вхідні: Block' $(if ($en) { 'ok' } else { 'risk' }) 'Високо' ("Set-NetFirewallProfile -Name {0} -Enabled True" -f $fp.Profile) 'Без firewall усі служби хоста доступні з мережі'
    }

    # ── Оновлення ──
    $hf = @(); try { $hf = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn }) } catch {}
    if ($hf.Count) {
        $last = $hf | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $days = [math]::Round(((Get-Date) - [datetime]$last.InstalledOn).TotalDays)
        $st = 'ok'; $sev = ''
        if ($days -gt 60) { $st = 'risk'; $sev = 'Високо' } elseif ($days -gt 35) { $st = 'risk'; $sev = 'Середньо' }
        Add-Chk 'Оновлення' 'Останнє встановлене оновлення' ("{0}, {1} ({2} дн. тому)" -f $last.HotFixID, ([datetime]$last.InstalledOn).ToString('yyyy-MM-dd'), $days) '≤ 35 днів (щомісячний цикл)' $st $sev 'Встановіть накопичувальні оновлення (Windows Update / WSUS)' 'Відомі вразливості без патчів. Джерело — Win32_QuickFixEngineering (не всі типи оновлень)'
    } else { Add-Chk 'Оновлення' 'Останнє встановлене оновлення' 'Get-HotFix не повернув дат' '≤ 35 днів' 'unknown' }

    $D.Hardening = Arr $rows
    Save-Csv $D.Hardening '02_system\security_config_audit.csv'
}

# ════════════════════════════════════ 2.10 ACTIVE DIRECTORY: КОНФІГУРАЦІЯ ДОМЕНУ ════════════════════════════════════
# Лише на контролері домену. Тільки читання LDAP через System.DirectoryServices (без RSAT / модуля ActiveDirectory).
# Шукаємо те, що атакують найчастіше: цілі Kerberoasting / AS-REP roasting, неконтрольоване делегування, старий krbtgt,
# слабкі прапорці привілейованих облікових записів, MachineAccountQuota, парольну політику, склад привілейованих груп.
if ($D.IsDC) {
    Invoke-Step "2.10 Active Directory: конфігурація домену (цілі Kerberoasting/AS-REP, делегування, krbtgt, привілейовані групи)" {
        $rows = New-Object System.Collections.Generic.List[object]
        $objs = New-Object System.Collections.Generic.List[object]
        function Add-AdChk {   # той самий формат, що й у 2.9; State: ok / risk / info / unknown
            param([string]$Check, $Current, [string]$Recommended, [string]$State, [string]$Sev = '', [string]$Fix = '', [string]$Why = '')
            $st = switch ($State) { 'ok' { 'OK' } 'risk' { 'Ризик' } 'info' { 'Інфо' } default { 'Невідомо' } }
            if ($State -ne 'risk') { $Sev = '' }
            if ($State -eq 'ok') { $Fix = '' }
            $rows.Add([pscustomobject]@{ Area = 'Active Directory'; Check = $Check; Current = [string]$Current; Recommended = $Recommended; Status = $st; Severity = $Sev; Fix = $Fix; Why = $Why })
        }
        $rootDse = [ADSI]'LDAP://RootDSE'
        $dn = [string]$rootDse.defaultNamingContext
        if (-not $dn) { throw 'RootDSE недоступний — LDAP-запити неможливі' }
        $D.AdDomainDN = $dn
        $domain = [ADSI]"LDAP://$dn"
        $domSid = ([Security.Principal.SecurityIdentifier]::new([byte[]]$domain.objectSid[0], 0)).Value
        function Find-Ad {
            param([string]$Filter, [string[]]$Props)
            $srch = New-Object DirectoryServices.DirectorySearcher($domain)
            $srch.Filter = $Filter; $srch.PageSize = 1000; $srch.SizeLimit = 0
            foreach ($pp in $Props) { [void]$srch.PropertiesToLoad.Add($pp) }
            $res = $srch.FindAll()
            try { return @(foreach ($r in $res) { $r }) } finally { $res.Dispose(); $srch.Dispose() }
        }
        function Get-AdProp { param($r, [string]$n) $v = $r.Properties[$n.ToLowerInvariant()]; if ($v -and $v.Count) { return $v[0] }; return $null }
        # Увага: не називати допоміжні функції 'FT' / 'FL' тощо — це вбудовані алиаси (Format-Table), вони мають пріоритет над функціями
        function ConvertFrom-AdFileTime { param($v) if ($null -eq $v -or [int64]$v -le 0 -or [int64]$v -eq [int64]::MaxValue) { return $null }; return [DateTime]::FromFileTimeUtc([int64]$v) }
        $enabledUser = '(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        $now = (Get-Date).ToUniversalTime()
        Add-Custody 'LDAP_QUERY' $dn 'OK' 'Початок LDAP-запитів (лише читання)'

        # ── Kerberoasting: користувачі (не компʼютери) з SPN ──
        $spnU = @(Find-Ad "(&$enabledUser(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))" @('sAMAccountName', 'servicePrincipalName', 'adminCount', 'pwdLastSet', 'msDS-SupportedEncryptionTypes'))
        $spnAdm = 0
        foreach ($r in $spnU) {
            $enc = Get-AdProp $r 'msDS-SupportedEncryptionTypes'; $aesOnly = ($null -ne $enc -and ([int]$enc -band 0x18) -and -not ([int]$enc -band 0x4))
            $pls = ConvertFrom-AdFileTime (Get-AdProp $r 'pwdLastSet'); $age = ''; if ($pls) { $age = [math]::Round(($now - $pls).TotalDays) }
            $adm = ((Get-AdProp $r 'adminCount') -eq 1); if ($adm) { $spnAdm++ }
            $objs.Add([pscustomobject]@{ Category = 'Kerberoastable (користувач із SPN)'; Account = (Get-AdProp $r 'sAMAccountName'); Privileged = $adm; PwdAgeDays = $age
                Details = ("SPN: {0}; шифрування: {1}" -f ((@($r.Properties['serviceprincipalname']) | Select-Object -First 3) -join ', '), $(if ($aesOnly) { 'лише AES' } else { 'RC4 дозволено' })) })
        }
        Add-AdChk 'Kerberoastable: користувачі з SPN' ("{0} (з них привілейованих: {1})" -f $spnU.Count, $spnAdm) '0 або gMSA / паролі 25+ символів, лише AES' $(if ($spnU.Count) { 'risk' } else { 'ok' }) $(if ($spnAdm) { 'Високо' } else { 'Середньо' }) 'Перевести сервіси на gMSA; довгі випадкові паролі; msDS-SupportedEncryptionTypes = 0x18 (AES)' 'Будь-який користувач домену може запросити квиток і підібрати пароль офлайн (Kerberoasting)'

        # ── AS-REP roasting: без Kerberos preauth ──
        $asrep = @(Find-Ad "(&$enabledUser(userAccountControl:1.2.840.113556.1.4.803:=4194304))" @('sAMAccountName', 'adminCount'))
        foreach ($r in $asrep) { $objs.Add([pscustomobject]@{ Category = 'AS-REP roastable (без preauth)'; Account = (Get-AdProp $r 'sAMAccountName'); Privileged = ((Get-AdProp $r 'adminCount') -eq 1); PwdAgeDays = ''; Details = 'DONT_REQ_PREAUTH' }) }
        Add-AdChk 'AS-REP roastable: без Kerberos preauth' $asrep.Count '0' $(if ($asrep.Count) { 'risk' } else { 'ok' }) 'Високо' 'Set-ADAccountControl <user> -DoesNotRequirePreAuth $false (або зняти прапорець у властивостях облікового запису)' 'Хеш пароля можна отримати без жодних облікових даних (AS-REP roasting)'

        # ── Неконтрольоване делегування (крім DC) ──
        $unc = @(Find-Ad '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName', 'objectClass'))
        foreach ($r in $unc) { $objs.Add([pscustomobject]@{ Category = 'Неконтрольоване делегування'; Account = (Get-AdProp $r 'sAMAccountName'); Privileged = ''; PwdAgeDays = ''; Details = 'TRUSTED_FOR_DELEGATION' }) }
        Add-AdChk 'Неконтрольоване делегування (не DC)' $unc.Count '0' $(if ($unc.Count) { 'risk' } else { 'ok' }) 'Високо' 'Замінити на constrained / resource-based delegation; критичні облікові записи — у Protected Users або "Account is sensitive and cannot be delegated"' 'Хост кешує TGT усіх, хто до нього підключається: компрометація = квитки адміністраторів (PrinterBug + unconstrained)'

        # ── krbtgt ──
        $kt = @(Find-Ad '(sAMAccountName=krbtgt)' @('pwdLastSet'))
        if ($kt.Count) {
            $kp = ConvertFrom-AdFileTime (Get-AdProp $kt[0] 'pwdLastSet'); $kd = $(if ($kp) { [math]::Round(($now - $kp).TotalDays) } else { $null })
            Add-AdChk 'Вік пароля krbtgt' $(if ($null -ne $kd) { "{0} дн. (змінено {1})" -f $kd, $kp.ToString('yyyy-MM-dd') } else { 'невідомо' }) '≤ 180 днів; після інциденту — двічі з інтервалом' $(if ($null -eq $kd) { 'unknown' } elseif ($kd -gt 180) { 'risk' } else { 'ok' }) 'Середньо' 'Скидання krbtgt двічі з паузою ≥ часу життя квитка (скрипт Microsoft New-KrbtgtKeys.ps1)' 'Старий ключ krbtgt продовжує життя Golden Ticket'
        }

        # ── Привілейовані облікові записи (adminCount=1) і прапорці паролів ──
        $adm = @(Find-Ad "(&$enabledUser(adminCount=1))" @('sAMAccountName', 'userAccountControl', 'pwdLastSet', 'lastLogonTimestamp'))
        $admNoExp = 0; $admNoReq = 0
        foreach ($r in $adm) {
            $uac = [int](Get-AdProp $r 'userAccountControl'); $f = @()
            if ($uac -band 0x10000) { $f += 'пароль без терміну дії'; $admNoExp++ }
            if ($uac -band 0x20) { $f += 'PASSWD_NOTREQD'; $admNoReq++ }
            $pls = ConvertFrom-AdFileTime (Get-AdProp $r 'pwdLastSet'); $ll = ConvertFrom-AdFileTime (Get-AdProp $r 'lastLogonTimestamp')
            $objs.Add([pscustomobject]@{ Category = 'Привілейований (adminCount=1)'; Account = (Get-AdProp $r 'sAMAccountName'); Privileged = $true
                PwdAgeDays = $(if ($pls) { [math]::Round(($now - $pls).TotalDays) } else { '' })
                Details = ("{0}; останній вхід ≈ {1}" -f $(if ($f) { $f -join ', ' } else { 'прапорці OK' }), $(if ($ll) { $ll.ToString('yyyy-MM-dd') } else { 'ніколи/невідомо' })) })
        }
        Add-AdChk 'Привілейовані з PASSWD_NOTREQD' $admNoReq '0' $(if ($admNoReq) { 'risk' } else { 'ok' }) 'Високо' 'Зняти прапорець PASSWD_NOTREQD, задати пароль' 'Обліковий запис може мати порожній пароль'
        Add-AdChk 'Привілейовані з паролем без терміну дії' ("{0} з {1}" -f $admNoExp, $adm.Count) '0 (крім break-glass із контролем)' $(if ($admNoExp) { 'risk' } else { 'ok' }) 'Середньо' 'Зняти "Password never expires" або керувати паролем через PAM/LAPS' 'Роками незмінні паролі адміністраторів'
        $noReq = @(Find-Ad "(&$enabledUser(userAccountControl:1.2.840.113556.1.4.803:=32))" @('sAMAccountName'))
        Add-AdChk 'Усі користувачі з PASSWD_NOTREQD' $noReq.Count '0' $(if ($noReq.Count) { 'risk' } else { 'ok' }) 'Середньо' 'Get-ADUser -Filter {PasswordNotRequired -eq $true} | Set-ADUser -PasswordNotRequired $false' 'Можливі облікові записи з порожнім паролем'

        # ── Домен: MachineAccountQuota, парольна політика ──
        $maq = $domain.'ms-DS-MachineAccountQuota'; $maqV = $(if ($maq -and $maq.Count) { [int]$maq[0] } else { $null })
        Add-AdChk 'ms-DS-MachineAccountQuota' $(if ($null -eq $maqV) { 'невідомо' } else { $maqV }) '0' $(if ($null -eq $maqV) { 'unknown' } elseif ($maqV -gt 0) { 'risk' } else { 'ok' }) 'Середньо' 'Set-ADDomain -Identity <domain> -Replace @{"ms-DS-MachineAccountQuota"="0"}' 'Будь-який користувач може створити обʼєкт компʼютера — основа атак RBCD / noPac'
        $mpl = $domain.minPwdLength; $mplV = $(if ($mpl -and $mpl.Count) { [int]$mpl[0] } else { $null })
        Add-AdChk 'Мінімальна довжина пароля (Default Domain Policy)' $(if ($null -eq $mplV) { 'невідомо' } else { $mplV }) '≥ 14 (або FGPP для адмінів)' $(if ($null -eq $mplV) { 'unknown' } elseif ($mplV -lt 12) { 'risk' } else { 'ok' }) 'Середньо' 'GPO Default Domain Policy → Password Policy → Minimum password length' 'Короткі паролі — password spraying і офлайн-підбір'
        $lt = $domain.lockoutThreshold; $ltV = $(if ($lt -and $lt.Count) { [int]$lt[0] } else { $null })
        Add-AdChk 'Поріг блокування облікових записів' $(if ($null -eq $ltV) { 'невідомо' } elseif ($ltV -eq 0) { '0 (блокування вимкнено)' } else { $ltV }) '5–10 спроб' $(if ($null -eq $ltV) { 'unknown' } elseif ($ltV -eq 0) { 'risk' } else { 'ok' }) 'Середньо' 'GPO Default Domain Policy → Account Lockout Policy' 'Без блокування підбір паролів необмежений'

        # ── Склад привілейованих груп (за SID — не залежить від мови ОС; лише прямі члени) ──
        foreach ($g in @(@{ Sid = "$domSid-512"; N = 'Domain Admins' }, @{ Sid = "$domSid-519"; N = 'Enterprise Admins' }, @{ Sid = "$domSid-518"; N = 'Schema Admins' }, @{ Sid = 'S-1-5-32-544'; N = 'Administrators' })) {
            $gr = @(Find-Ad ("(objectSid={0})" -f $g.Sid) @('member', 'sAMAccountName'))
            if (-not $gr.Count) { continue }   # Enterprise/Schema Admins існують лише в кореневому домені лісу
            $mem = @($gr[0].Properties['member'] | ForEach-Object { ([string]$_ -split ',')[0] -replace '^CN=', '' })
            foreach ($m in $mem) { $objs.Add([pscustomobject]@{ Category = "Член групи $($g.N)"; Account = $m; Privileged = $true; PwdAgeDays = ''; Details = "прямий член $(Get-AdProp $gr[0] 'sAMAccountName')" }) }
            $st = 'info'; if ($g.N -eq 'Schema Admins' -and $mem.Count) { $st = 'risk' }
            Add-AdChk ("Склад групи {0} ({1})" -f $g.N, (Get-AdProp $gr[0] 'sAMAccountName')) ("{0} прямих членів: {1}" -f $mem.Count, (($mem | Select-Object -First 10) -join ', ')) $(if ($g.N -eq 'Schema Admins') { '0 (додавати лише на час змін схеми)' } else { 'мінімум, лише іменовані адмін-облікові записи' }) $st 'Середньо' 'Прибрати зайвих членів; вкладені групи перевірити окремо' 'Кожен член — повний контроль над доменом/лісом'
        }

        $D.AdConfig = Arr $rows
        $D.AdObjects = Arr $objs
        Save-Csv $D.AdConfig '02_system\ad_config.csv'
        Save-Csv $D.AdObjects '02_system\ad_risky_accounts.csv'
    }
} else { Add-Note 'Хост не є контролером домену — кроки аудиту Active Directory (2.10, 3.10) пропущено.' }

# ════════════════════════════════════ 3. ЖУРНАЛИ ПОДІЙ ЗА ВІКНО ════════════════════════════════════
Invoke-Step "3.1 Автентифікація: 4625 / 4624 / 4648 / 4740 / 4776, зміни облікових записів, очищення журналів" {
    $rows = foreach ($e in (Get-Ev 'Security' @(4625))) {
        $d = Get-EvData $e
        [pscustomobject]@{
            TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = 4625
            TargetUser = $d['TargetUserName']; TargetDomain = $d['TargetDomainName']
            LogonType = $d['LogonType']; LogonTypeText = (Get-LogonTypeText $d['LogonType'])
            Status = (Get-StatusText $d['Status']); SubStatus = (Get-StatusText $d['SubStatus'])
            SourceIP = $d['IpAddress']; SourcePort = $d['IpPort']; Workstation = $d['WorkstationName']
            CallerProcess = $d['ProcessName']; LogonProcess = ([string]$d['LogonProcessName']).Trim(); AuthPackage = $d['AuthenticationPackageName']
            Subject = ("{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']); RecordId = $e.RecordId
        }
    }
    $D.Ev4625 = Arr ($rows | Sort-Object TimeUtc)
    Save-Csv $D.Ev4625 '03_eventlogs\security_4625_failed_logons.csv'

    $sU = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z'); $uU = $Until.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
    # Два окремі запити зі своїм лімітом: на DC/файл-сервері мережеві входи (тип 3) інакше витісняють з вибірки
    # інтерактивні та RDP-входи. Службові SID (SYSTEM, LOCAL/NETWORK SERVICE, ANONYMOUS) відсікаються вже в XPath.
    $xpBase = "*[System[(EventID=4624) and TimeCreated[@SystemTime>='$sU' and @SystemTime<='$uU']]] and *[EventData[Data[@Name='TargetUserSid']!='S-1-5-18' and Data[@Name='TargetUserSid']!='S-1-5-19' and Data[@Name='TargetUserSid']!='S-1-5-20' and Data[@Name='TargetUserSid']!='S-1-5-7']]"
    $xpInter = $xpBase + " and *[EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']]"
    $xpNet   = $xpBase + " and *[EventData[Data[@Name='LogonType']='3']]"
    $ev4624 = @(Get-EvXPath 'Security' $xpInter '4624 типи 2/7/10/11 — інтерактивні/RDP') + @(Get-EvXPath 'Security' $xpNet '4624 тип 3 — мережеві')
    $rows = foreach ($e in $ev4624) {
        $d = Get-EvData $e
        $sid = [string]$d['TargetUserSid']
        if ($sid -notmatch '^S-1-5-21-|^S-1-12-' -or ([string]$d['TargetUserName']).EndsWith('$')) { continue }
        [pscustomobject]@{
            TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = 4624
            TargetUser = ("{0}\{1}" -f $d['TargetDomainName'], $d['TargetUserName']); LogonType = (Get-LogonTypeText $d['LogonType'])
            SourceIP = $d['IpAddress']; Workstation = $d['WorkstationName']; LogonProcess = ([string]$d['LogonProcessName']).Trim()
            AuthPackage = $d['AuthenticationPackageName']; LogonId = $d['TargetLogonId']; Elevated = $d['ElevatedToken']; CallerProcess = $d['ProcessName']
        }
    }
    $D.Ev4624 = Arr ($rows | Sort-Object TimeUtc)
    Save-Csv $D.Ev4624 '03_eventlogs\security_4624_user_logons.csv'

    $meaning = @{ 4648 = 'Вхід з явними обліковими даними'; 4740 = 'Обліковий запис ЗАБЛОКОВАНО'; 4776 = 'NTLM-перевірка облікових даних'
                  4720 = 'Створено обліковий запис'; 4722 = 'Обліковий запис увімкнено'; 4724 = 'Скидання пароля'; 4725 = 'Обліковий запис вимкнено'
                  4726 = 'Обліковий запис видалено'; 4732 = 'Додано до локальної групи'; 4733 = 'Видалено з локальної групи'; 4738 = 'Змінено обліковий запис' }
    $rows = foreach ($e in (Get-Ev 'Security' @(4648, 4740, 4776, 4720, 4722, 4724, 4725, 4726, 4732, 4733, 4738))) {
        $d = Get-EvData $e
        $target = $d['TargetUserName']; if (-not $target -and $d['MemberName']) { $target = $d['MemberName'] }; if (-not $target -and $d['MemberSid']) { $target = Resolve-Sid $d['MemberSid'] }
        [pscustomobject]@{
            TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = $e.Id; Meaning = $meaning[[int]$e.Id]
            Target = $target; Actor = ("{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']).Trim('\')
            SourceIP = (Get-FirstIP @($d['IpAddress'])); Workstation = $(if ($d['Workstation']) { $d['Workstation'] } else { $d['TargetDomainName'] })
            Status = (Get-StatusText $d['Status']); Details = (Format-EvData $d @('SubjectUserSid', 'SubjectLogonId', 'TargetUserSid', 'PrivilegeList'))
        }
    }
    $D.OtherAuth = Arr ($rows | Sort-Object TimeUtc)
    Save-Csv $D.OtherAuth '03_eventlogs\security_auth_other.csv'

    $rows = @()
    foreach ($e in (Get-Ev 'Security' @(1102, 1100))) { $d = Get-EvData $e; $rows += [pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = $e.Id; Log = 'Security'; Details = $(if ($e.Id -eq 1102) { 'Журнал Security ОЧИЩЕНО. ' } else { 'Служба журналювання зупинена. ' }) + (Format-EvData $d) } }
    foreach ($e in (Get-Ev 'System' @(104))) { $d = Get-EvData $e; $rows += [pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = 104; Log = 'System'; Details = 'Журнал ОЧИЩЕНО. ' + (Format-EvData $d) } }
    $D.LogCleared = Arr $rows
    Save-Csv $D.LogCleared '03_eventlogs\log_cleared.csv'
}

Invoke-Step "3.2 RDP: 1149 (NLA), 21-25/39/40 (сесії), 131/140 (RdpCoreTS — IP джерела)" {
    $defs = @(
        @{ Log = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149); Short = 'RCM' },
        @{ Log = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Ids = @(21, 22, 23, 24, 25, 39, 40); Short = 'LSM' },
        @{ Log = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Ids = @(131, 140); Short = 'RdpCoreTS' }
    )
    $mean = @{ 1149 = 'RDP: облікові дані прийнято (NLA)'; 21 = 'Сесія: вхід'; 22 = 'Сесія: shell запущено'; 23 = 'Сесія: вихід'; 24 = 'Сесія: відключено'
               25 = 'Сесія: перепідключення'; 39 = 'Сесію відключено іншою сесією'; 40 = 'Сесію відключено (код причини)'
               131 = "Прийнято TCP-з'єднання RDP"; 140 = "Невдале RDP-з'єднання: невірні облікові дані" }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($df in $defs) {
        foreach ($e in (Get-Ev $df.Log $df.Ids)) {
            $d = Get-EvData $e
            $user = ''
            if ($e.Id -eq 1149) { $user = ("{0}\{1}" -f $d['Param2'], $d['Param1']).Trim('\') } elseif ($d['User']) { $user = $d['User'] }
            $ip = Get-FirstIP @($d['Param3'], $d['Address'], $d['ClientIP'], $d['IPString'])
            $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = $e.Id; Log = $df.Short; Meaning = $mean[[int]$e.Id]; User = $user; SourceIP = $ip; Details = (Format-EvData $d) })
        }
    }
    $D.Rdp = Arr ($rows | Sort-Object TimeUtc)
    Save-Csv $D.Rdp '03_eventlogs\rdp_events.csv'
    $sum = @($D.Rdp | Where-Object { $_.SourceIP } | Group-Object SourceIP | ForEach-Object {
        $g = @($_.Group | Sort-Object TimeUtc)
        [pscustomobject]@{ SourceIP = $_.Name; IocIP = (Test-IocIPEq $_.Name)
            'TCP-зєднання (131)' = @($g | Where-Object { $_.EventId -eq 131 }).Count; 'Невдалі креденшали (140)' = @($g | Where-Object { $_.EventId -eq 140 }).Count
            'NLA успішно (1149)' = @($g | Where-Object { $_.EventId -eq 1149 }).Count; 'Входи/перепідкл. (21/25)' = @($g | Where-Object { $_.EventId -in 21, 25 }).Count
            Users = ((@($g | Where-Object { $_.User } | ForEach-Object { $_.User }) | Select-Object -Unique) -join ', ')
            FirstUtc = $g[0].TimeUtc; LastUtc = $g[$g.Count - 1].TimeUtc; FirstLocal = $g[0].TimeLocal; LastLocal = $g[$g.Count - 1].TimeLocal }
    } | Sort-Object 'Невдалі креденшали (140)' -Descending)
    $D.RdpSummary = Arr $sum
    Save-Csv $D.RdpSummary '03_eventlogs\rdp_by_source.csv'
}

Invoke-Step "3.3 Служби: встановлення (7045 / 4697) і зміна типу запуску (7040)" {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-Ev 'System' @(7045, 7040))) {
        $d = Get-EvData $e
        if ($e.Id -eq 7045) {
            $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = 7045; Source = 'System / SCM'; Service = $d['ServiceName']; Binary = $d['ImagePath']; StartType = $d['StartType']; Account = $d['AccountName']; InstalledBy = ''; LogonId = '' })
        } else {
            $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = 7040; Source = 'System / SCM'; Service = $d['param1']; Binary = ''; StartType = ("{0} → {1}" -f $d['param2'], $d['param3']); Account = ''; InstalledBy = ''; LogonId = '' })
        }
    }
    foreach ($e in (Get-Ev 'Security' @(4697))) {
        $d = Get-EvData $e
        $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = 4697; Source = 'Security'; Service = $d['ServiceName']; Binary = $d['ServiceFileName']; StartType = $d['ServiceStartType']; Account = $d['ServiceAccount']
            InstalledBy = ("{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']); LogonId = $d['SubjectLogonId'] })
    }
    foreach ($r in $rows) {
        $now = @($D.Services | Where-Object { $_.Name -eq $r.Service })
        $r | Add-Member -NotePropertyName ExistsNow -NotePropertyValue ($now.Count -gt 0)
        $r | Add-Member -NotePropertyName StateNow -NotePropertyValue $(if ($now.Count) { $now[0].State } else { 'видалена' })
        $r | Add-Member -NotePropertyName Match -NotePropertyValue (Test-KwMatch "$($r.Service) $($r.Binary)")
    }
    $D.SvcEvents = Arr ($rows | Sort-Object TimeUtc)
    Save-Csv $D.SvcEvents '03_eventlogs\service_install_events.csv'
}

Invoke-Step "3.4 Задачі: 4698-4702 (Security) + TaskScheduler/Operational (106/140/141/200/201)" {
    $rows = New-Object System.Collections.Generic.List[object]
    $mean = @{ 4698 = 'Задачу СТВОРЕНО'; 4699 = 'Задачу видалено'; 4700 = 'Задачу увімкнено'; 4701 = 'Задачу вимкнено'; 4702 = 'Задачу змінено'
               106 = 'Задачу зареєстровано'; 140 = 'Задачу оновлено'; 141 = 'Задачу видалено'; 200 = 'Запущено дію задачі'; 201 = 'Дію задачі завершено' }
    foreach ($e in (Get-Ev 'Security' @(4698, 4699, 4700, 4701, 4702))) {
        $d = Get-EvData $e
        $xml = [string]$d['TaskContent']; if (-not $xml) { $xml = [string]$d['TaskContentNew'] }
        $cmd = ''; $args2 = ''; $auth = ''
        if ($xml -match '(?s)<Command>(.*?)</Command>') { $cmd = $Matches[1] }
        if ($xml -match '(?s)<Arguments>(.*?)</Arguments>') { $args2 = $Matches[1] }
        if ($xml -match '(?s)<Author>(.*?)</Author>') { $auth = $Matches[1] }
        $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = $e.Id; Meaning = $mean[[int]$e.Id]; TaskName = $d['TaskName']
            Actor = ("{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']); Author = $auth; Command = ("{0} {1}" -f $cmd, $args2).Trim(); Result = '' })
    }
    foreach ($e in (Get-Ev 'Microsoft-Windows-TaskScheduler/Operational' @(106, 140, 141, 200, 201))) {
        $d = Get-EvData $e
        if ([string]$d['TaskName'] -like '\Microsoft\*') {
            # штатні задачі Windows — шум; лишаємо ті, що зареєстровані/змінені користувачем або запускають інтерпретатор/нестандартний шлях
            $actor = [string]$(if ($d['UserContext']) { $d['UserContext'] } else { $d['UserName'] })
            if ($e.Id -in 200, 201) { $actor = '' }
            $exe = Get-ExeFromCmd ([string]$d['ActionName'])
            if (-not (Get-MsTaskSuspicion $exe ([string]$d['ActionName']) 'Microsoft' $actor)) { continue }
        }
        $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = $e.Id; Meaning = $mean[[int]$e.Id]; TaskName = $d['TaskName']
            Actor = $(if ($d['UserContext']) { $d['UserContext'] } else { $d['UserName'] }); Author = ''; Command = $d['ActionName']; Result = $d['ResultCode'] })
    }
    foreach ($r in $rows) { $r | Add-Member -NotePropertyName Match -NotePropertyValue (Test-KwMatch "$($r.TaskName) $($r.Command) $($r.Author)") }
    $D.TaskEvents = Arr ($rows | Sort-Object TimeUtc)
    Save-Csv $D.TaskEvents '03_eventlogs\task_events.csv'
}

Invoke-Step "3.5 Зміни правил firewall: 2004/2005/2006/2033/2052/2097/2099 + Security 4946-4950" {
    $mean = @{ 2004 = 'Правило ДОДАНО'; 2097 = 'Правило ДОДАНО'; 2005 = 'Правило змінено'; 2099 = 'Правило змінено'; 2006 = 'Правило ВИДАЛЕНО'; 2052 = 'Правило ВИДАЛЕНО'
               2033 = 'Усі правила видалено'; 4946 = 'Правило додано (Security)'; 4947 = 'Правило змінено (Security)'; 4948 = 'Правило видалено (Security)'; 4950 = 'Змінено налаштування firewall' }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-Ev 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' @(2004, 2005, 2006, 2033, 2052, 2097, 2099))) {
        $d = Get-EvData $e
        $modUser = Resolve-Sid ([string]$d['ModifyingUser'])
        $modApp  = [string]$d['ModifyingApplication']
        $auto = ($modApp -match '(?i)\\Windows\\System32\\svchost\.exe$' -or $modUser -match '(?i)mpssvc|SYSTEM|СИСТЕМА')
        $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = $e.Id; Meaning = $mean[[int]$e.Id]
            RuleName = $d['RuleName']; RuleId = $d['RuleId']; Direction = $d['Direction']; Action = $d['Action']; Protocol = $d['Protocol']
            LocalPorts = $d['LocalPorts']; RemotePorts = $d['RemotePorts']; App = $d['ApplicationPath']; ModifiedBy = $modUser; ModifyingApp = $modApp
            Category = $(if ($auto) { 'Windows / служба (автоматично)' } else { 'Стороннє / ручне' }); Initiator = '' })
    }
    foreach ($e in (Get-Ev 'Security' @(4946, 4947, 4948, 4950))) {
        $d = Get-EvData $e
        $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = $e.Id; Meaning = $mean[[int]$e.Id]
            RuleName = $d['RuleName']; RuleId = $d['RuleId']; Direction = ''; Action = ''; Protocol = ''; LocalPorts = ''; RemotePorts = ''; App = ''
            ModifiedBy = ''; ModifyingApp = ''; Category = 'Security audit'; Initiator = (Format-EvData $d @('RuleName', 'RuleId')) })
    }
    foreach ($r in $rows) { $r | Add-Member -NotePropertyName Match -NotePropertyValue ((Test-KwMatch "$($r.RuleName) $($r.App)") -or ("$($r.LocalPorts),$($r.RemotePorts)" -match '(^|,)1688(,|$)')) }
    $D.FwEvents = Arr ($rows | Sort-Object TimeUtc)
    Save-Csv $D.FwEvents '03_eventlogs\firewall_rule_change_events.csv'
}

Invoke-Step "3.6 Defender: виявлення, вимкнення захисту, зміни конфігурації" {
    $mean = @{ 1006 = 'Виявлено шкідливе/небажане ПЗ'; 1116 = 'Виявлено загрозу'; 1117 = 'Вжито дій щодо загрози'; 1118 = 'Помилка дії щодо загрози'
               1119 = 'Критична помилка дії'; 5001 = 'Real-time protection ВИМКНЕНО'; 5004 = 'Змінено real-time protection'; 5007 = 'Змінено конфігурацію Defender'
               5010 = 'Сканування spyware вимкнено'; 5012 = 'Сканування вірусів вимкнено'; 5013 = 'Tamper protection заблокував зміну' }
    $rows = foreach ($e in (Get-Ev 'Microsoft-Windows-Windows Defender/Operational' @(1006, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012, 5013))) {
        $d = Get-EvData $e
        $det = ''
        if ($e.Id -eq 5007) { $det = ("{0}  →  {1}" -f $d['Old Value'], $d['New Value']) }
        elseif ($e.Id -in 1006, 1116, 1117, 1118, 1119) { $det = ("{0} | {1} | {2}" -f $d['Threat Name'], $d['Path'], $d['Action Name']) }
        else { $det = Format-EvData $d @('Product Name', 'Product Version') }
        [pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = $e.Id; Meaning = $mean[[int]$e.Id]; Details = $det
            Exclusion = ($det -match '(?i)\\Exclusions\\'); Match = (Test-KwMatch $det) }
    }
    $D.MpEvents = Arr ($rows | Sort-Object TimeUtc)
    Save-Csv $D.MpEvents '03_eventlogs\defender_events.csv'
}

Invoke-Step "3.7 Запуск процесів за LOLBin/IOC (Sysmon 1, Security 4688) + Sysmon 11/13/3 за IOC" {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-Ev 'Microsoft-Windows-Sysmon/Operational' @(1))) {
        $d = Get-EvData $e
        $why = Get-ExecReason $d['Image'] $d['CommandLine'] $d['Hashes']
        if (-not $why) { continue }
        $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); Source = 'Sysmon 1'; Image = $d['Image']; CommandLine = $d['CommandLine']
            Parent = $d['ParentImage']; ParentCommandLine = $d['ParentCommandLine']; User = $d['User']; LogonId = $d['LogonId']; SHA256 = (Get-Sha256FromHashes $d['Hashes']); Reason = $why })
    }
    foreach ($e in (Get-Ev 'Security' @(4688))) {
        $d = Get-EvData $e
        $why = Get-ExecReason $d['NewProcessName'] $d['CommandLine'] ''
        if (-not $why) { continue }
        $rows.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); Source = 'Security 4688'; Image = $d['NewProcessName']; CommandLine = $d['CommandLine']
            Parent = $d['ParentProcessName']; ParentCommandLine = ''; User = ("{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']); LogonId = $d['SubjectLogonId']; SHA256 = ''; Reason = $why })
    }
    $D.Exec = Arr ($rows | Sort-Object TimeUtc)
    Save-Csv $D.Exec '03_eventlogs\process_exec_lolbin_ioc.csv'

    $misc = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-Ev 'Microsoft-Windows-Sysmon/Operational' @(11, 13, 3))) {
        $d = Get-EvData $e
        $keep = ''; $target = ''
        if ($e.Id -eq 11) {
            $target = [string]$d['TargetFilename']
            if (Test-KwMatch $target) { $keep = 'Файл за маскою IOC' }
            elseif ($target -match '(?i)\.(exe|dll|sys|scr|ps1|bat|cmd|vbs|js|hta|lnk)$' -and (Get-PathClass $target) -in @('Нестандартний', 'Користувацький/тимчасовий')) { $keep = 'Виконуваний файл у нестандартному місці' }
        } elseif ($e.Id -eq 13) {
            $target = ("{0} = {1}" -f $d['TargetObject'], $d['Details'])
            if ($target -match '(?i)Windows Defender\\Exclusions|KeyManagementService|\\CurrentVersion\\Run|Image File Execution Options|\\Services\\[^\\]+\\ImagePath' -or (Test-KwMatch $target)) { $keep = 'Реєстр: персистентність/Defender/KMS' }
        } else {
            $target = ("{0}:{1} → {2}:{3} ({4})" -f $d['SourceIp'], $d['SourcePort'], $d['DestinationIp'], $d['DestinationPort'], $d['Protocol'])
            if ((Test-IocIP $target) -or (Test-KwMatch $d['Image'])) { $keep = 'Мережа: IOC IP / процес за маскою' }
        }
        if (-not $keep) { continue }
        $misc.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = ("Sysmon {0}" -f $e.Id); Image = $d['Image']; Target = $target; User = $d['User']; Reason = $keep })
    }
    $D.SysmonMisc = Arr ($misc | Sort-Object TimeUtc)
    Save-Csv $D.SysmonMisc '03_eventlogs\sysmon_file_reg_net_ioc.csv'
}

Invoke-Step "3.8 PowerShell 4104 (Script Block Logging) — підозрілі блоки" {
    $rx = '(?i)(add-mppreference|set-mppreference|msft_mppreference|downloadstring|downloadfile|invoke-webrequest|\biex\b|invoke-expression|frombase64string|net\.webclient|bitsadmin|certutil|slmgr|advfirewall|new-netfirewallrule|clear-eventlog|wevtutil|reg\s+add|schtasks|new-service|sc\.exe\s+create)'
    $selfSkipped = 0
    $rows = foreach ($e in (Get-Ev 'Microsoft-Windows-PowerShell/Operational' @(4104))) {
        $d = Get-EvData $e
        $txt = [string]$d['ScriptBlockText']
        if (-not ($txt -match $rx -or (Test-KwMatch $txt) -or (Test-IocIP $txt))) { continue }
        # Власний код коллектора: той самий файл або фрагмент його тексту (4104 ділить великі скрипти на частини)
        $txtN = $txt.Replace("`r", '').Trim()
        if (($ToolPathTop -and [string]$d['Path'] -eq $ToolPathTop) -or ($OwnTextNorm -and $txtN.Length -ge 40 -and $OwnTextNorm.Contains($txtN))) { $selfSkipped++; continue }
        $snip = $txt; if ($snip.Length -gt 600) { $snip = $snip.Substring(0, 600) + '…' }
        [pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); ScriptBlockId = $d['ScriptBlockId']; Path = $d['Path']; Part = ("{0}/{1}" -f $d['MessageNumber'], $d['MessageTotal']); Snippet = $snip }
    }
    $D.Ps4104 = Arr ($rows | Sort-Object TimeUtc)
    if ($selfSkipped) { Add-Note ("4104: пропущено {0} script block(ів), що є текстом самого коллектора (збіг шляху або вмісту) — щоб не давати хибних прапорців." -f $selfSkipped) }
    Save-Csv $D.Ps4104 '03_eventlogs\powershell_4104_suspicious.csv'
}

# ════════════════════════════════════ 3.10 ACTIVE DIRECTORY: ОЗНАКИ АТАК У ЖУРНАЛАХ ════════════════════════════════════
# Лише на DC. Фільтрація в XPath (тип шифрування, preauth, AccessMask, атрибут) — щоб у ліміт -MaxEvents потрапляли
# саме підозрілі події, а не мільйони штатних квитків. Спершу перевіряємо, чи потрібні підкатегорії взагалі аудитуються:
# якщо ні — «подій немає» нічого не доводить (NIST: відсутність даних ≠ відсутність події).
$AdReplGuids = @{ '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'; '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
                  '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set' }
$AdUacCodes = @{ '%%2096' = @('Високо', "Вимкнено Kerberos preauth (DONT_REQ_PREAUTH) — підготовка AS-REP roasting")
                 '%%2093' = @('Високо', 'Увімкнено неконтрольоване делегування (TRUSTED_FOR_DELEGATION)')
                 '%%2098' = @('Середньо', 'Увімкнено делегування з протокольним переходом (TRUSTED_TO_AUTH_FOR_DELEGATION)')
                 '%%2082' = @('Середньо', 'Встановлено PASSWD_NOTREQD (пароль не обовʼязковий)')
                 '%%2095' = @('Середньо', 'Увімкнено USE_DES_KEY_ONLY') }
$AdPrivGroupRx = '(-512|-518|-519|-520)$|^S-1-5-32-(544|548|549|551)$'   # DA, Schema, EA, GPO Creators; Administrators, Account/Server/Backup Operators

function Get-AdAttackRow {   # одна подія (Id + словник EventData) -> рядок з технікою і рівнем, або $null якщо штатна
    param([int]$Id, $d, [string]$DomainDN = '')
    $ip = ([string]$d['IpAddress']) -replace '^::ffff:', ''
    $row = $null
    switch ($Id) {
        4769 {
            $svc = [string]$d['ServiceName']
            if ($svc -match '\$$' -or $svc -match '^(?i)krbtgt') { return $null }
            $row = @{ Technique = 'Kerberoasting (слабке шифрування квитка)'; Severity = 'Середньо'; Actor = [string]$d['TargetUserName']; Target = $svc
                      Details = ("шифрування {0}" -f $d['TicketEncryptionType']) }
        }
        4768 {
            $row = @{ Technique = 'AS-REP roasting (квиток без preauth)'; Severity = 'Високо'; Actor = ''; Target = [string]$d['TargetUserName']
                      Details = ("PreAuthType={0}; шифрування {1}" -f $d['PreAuthType'], $d['TicketEncryptionType']) }
        }
        4771 {
            $row = @{ Technique = 'Невдала Kerberos preauth (підбір / spraying)'; Severity = 'Інфо'; Actor = ''; Target = [string]$d['TargetUserName']; Details = ("Status={0}" -f $d['Status']) }
        }
        4662 {
            $props = ([string]$d['Properties']).ToLowerInvariant()
            $hit = @($AdReplGuids.Keys | Where-Object { $props.Contains($_) } | ForEach-Object { $AdReplGuids[$_] })
            if (-not $hit.Count) { return $null }
            $actor = [string]$d['SubjectUserName']
            if ($actor -match '\$$') { return $null }   # реплікація між DC (компʼютерні облікові записи) — штатна
            $sev = 'Критично'; $note = ''
            if ($actor -match '^(?i)(MSOL_|AAD_|Sync_)') { $sev = 'Високо'; $note = ' — ймовірно Azure AD Connect / Entra Connect, перевірте' }
            $row = @{ Technique = 'DCSync (права реплікації від не-DC)'; Severity = $sev; Actor = ("{0}\{1}" -f $d['SubjectDomainName'], $actor); Target = [string]$d['ObjectName']
                      Details = (($hit -join ', ') + $note) }
        }
        { $_ -in 4728, 4732, 4756, 4729, 4733, 4757 } {
            $gs = [string]$d['TargetSid']
            if ($gs -notmatch $AdPrivGroupRx -and [string]$d['TargetUserName'] -ne 'DnsAdmins') { return $null }
            $add = ($Id -in 4728, 4732, 4756)
            $member = [string]$d['MemberName']; if (-not $member -or $member -eq '-') { $member = [string]$d['MemberSid'] }
            $row = @{ Technique = $(if ($add) { 'Додано до привілейованої групи' } else { 'Видалено з привілейованої групи' }); Severity = $(if ($add) { 'Високо' } else { 'Середньо' })
                      Actor = ("{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']); Target = ("{0} → {1}" -f $member, $d['TargetUserName']); Details = "SID групи $gs" }
        }
        { $_ -in 4738, 4742 } {
            $uac = [string]$d['UserAccountControl']
            $hits = @($AdUacCodes.Keys | Where-Object { $uac.Contains($_) })
            if (-not $hits.Count) { return $null }
            $sev = 'Середньо'; if (@($hits | Where-Object { $AdUacCodes[$_][0] -eq 'Високо' }).Count) { $sev = 'Високо' }
            $row = @{ Technique = 'Небезпечна зміна userAccountControl'; Severity = $sev; Actor = ("{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']); Target = [string]$d['TargetUserName']
                      Details = ((@($hits | ForEach-Object { $AdUacCodes[$_][1] })) -join '; ') }
        }
        5136 {
            $attr = [string]$d['AttributeLDAPDisplayName']; $obj = [string]$d['ObjectDN']; $cls = [string]$d['ObjectClass']
            if ([string]$d['OperationType'] -ne '%%14674') { return $null }   # цікавить лише додане значення
            $t = ''; $sev = 'Високо'
            switch ($attr) {
                'msDS-KeyCredentialLink' { $t = 'Shadow Credentials (msDS-KeyCredentialLink)' }
                'msDS-AllowedToActOnBehalfOfOtherIdentity' { $t = 'Resource-based constrained delegation (RBCD)' }
                'gPCFileSysPath' { $t = 'Зміна шляху файлів GPO (перехоплення GPO)' }
                'servicePrincipalName' { if ($cls -eq 'user') { $t = 'SPN додано користувачу (targeted Kerberoasting)'; $sev = 'Середньо' } }
                'nTSecurityDescriptor' {
                    if ($obj -match '^(?i)CN=AdminSDHolder,') { $t = 'Змінено ACL AdminSDHolder (персистентність)' }
                    elseif ($DomainDN -and $obj -eq $DomainDN) { $t = 'Змінено ACL кореня домену (можлива видача прав DCSync)' }
                }
            }
            if (-not $t) { return $null }
            $val = [string]$d['AttributeValue']; if ($val.Length -gt 200) { $val = $val.Substring(0, 200) + '…' }
            $row = @{ Technique = $t; Severity = $sev; Actor = ("{0}\{1}" -f $d['SubjectDomainName'], $d['SubjectUserName']); Target = $obj; Details = ("{0} = {1}" -f $attr, $val) }
        }
        default { return $null }
    }
    if (-not $row) { return $null }
    $row['SourceIP'] = $(if ($ip -and $ip -ne '-') { $ip } else { '' })
    return $row
}

if ($D.IsDC) {
    Invoke-Step "3.10 Active Directory: ознаки атак (Kerberoasting, AS-REP, spraying, DCSync, привілейовані групи, ACL/делегування)" {
        # ── Покриття аудиту ──
        $need = @(
            @{ N = 'Kerberos Service Ticket Operations'; G = '{0CCE9240-69AE-11D9-BED3-505054503030}'; R = 3; For = '4769 (Kerberoasting)' },
            @{ N = 'Kerberos Authentication Service'; G = '{0CCE9242-69AE-11D9-BED3-505054503030}'; R = 3; For = '4768 / 4771 (AS-REP, spraying)' },
            @{ N = 'Directory Service Access'; G = '{0CCE923B-69AE-11D9-BED3-505054503030}'; R = 1; For = '4662 (DCSync) — також потрібен SACL на корені домену' },
            @{ N = 'Directory Service Changes'; G = '{0CCE923C-69AE-11D9-BED3-505054503030}'; R = 1; For = '5136 (ACL, RBCD, Shadow Credentials, GPO)' },
            @{ N = 'Security Group Management'; G = '{0CCE9237-69AE-11D9-BED3-505054503030}'; R = 1; For = '4728 / 4732 / 4756' },
            @{ N = 'User Account Management'; G = '{0CCE9235-69AE-11D9-BED3-505054503030}'; R = 1; For = '4738 (userAccountControl)' },
            @{ N = 'Computer Account Management'; G = '{0CCE9236-69AE-11D9-BED3-505054503030}'; R = 1; For = '4742 (делегування компʼютерів)' }
        )
        $bits = @{ 0 = 'Немає аудиту'; 1 = 'Успіх'; 2 = 'Відмова'; 3 = 'Успіх і відмова' }
        $aud = New-Object System.Collections.Generic.List[object]
        foreach ($sb in $need) {
            $ap = Get-AuditSubcategory $sb.G
            $v = $ap.Value; $cur = 'не вдалося прочитати'
            if ($null -ne $v) { $cur = $bits[[int]$v]; if ($ap.Text) { $cur += " ($($ap.Text))" } } elseif ($ap.Text) { $cur = "не розпізнано: $($ap.Text)" }
            $ok = $(if ($null -eq $v) { $null } else { (($v -band $sb.R) -eq $sb.R) })
            $aud.Add([pscustomobject]@{ Subcategory = $sb.N; Current = $cur; Needed = $bits[$sb.R]; OK = $ok; Detects = $sb.For
                Consequence = $(if ($ok -eq $false) { 'НЕ аудитується → відсутність подій нічого не доводить' } else { '' })
                Fix = $(if ($ok -eq $false) { ('auditpol /set /subcategory:"{0}"{1}{2}' -f $sb.G, $(if ($sb.R -band 1) { ' /success:enable' } else { '' }), $(if ($sb.R -band 2) { ' /failure:enable' } else { '' })) } else { '' }) })
        }
        $D.AdAudit = Arr $aud
        foreach ($a in @($aud | Where-Object { $_.OK -eq $false })) { Add-Note ("AD: підкатегорія аудиту «{0}» не ввімкнена — {1} не фіксуються, їх відсутність не доводить відсутність атаки." -f $a.Subcategory, $a.Detects) }

        # ── Події (XPath-фільтри) ──
        $sU = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z'); $uU = $Until.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        $T = "TimeCreated[@SystemTime>='$sU' and @SystemTime<='$uU']"
        $queries = @(
            @{ L = '4769 RC4/DES-квитки'; X = "*[System[(EventID=4769) and $T]] and *[EventData[(Data[@Name='TicketEncryptionType']='0x17' or Data[@Name='TicketEncryptionType']='0x18' or Data[@Name='TicketEncryptionType']='0x1' or Data[@Name='TicketEncryptionType']='0x3') and Data[@Name='Status']='0x0']]" },
            @{ L = '4768 без preauth'; X = "*[System[(EventID=4768) and $T]] and *[EventData[Data[@Name='PreAuthType']='0' and Data[@Name='Status']='0x0']]" },
            @{ L = '4771 невдала preauth'; X = "*[System[(EventID=4771) and $T]] and *[EventData[Data[@Name='Status']='0x18']]" },
            @{ L = '4662 Control Access'; X = "*[System[(EventID=4662) and $T]] and *[EventData[Data[@Name='AccessMask']='0x100']]" },
            @{ L = 'зміни груп'; X = "*[System[(EventID=4728 or EventID=4732 or EventID=4756 or EventID=4729 or EventID=4733 or EventID=4757) and $T]]" },
            @{ L = '4738/4742 userAccountControl'; X = "*[System[(EventID=4738 or EventID=4742) and $T]]" },
            @{ L = '5136 чутливі атрибути'; X = "*[System[(EventID=5136) and $T]] and *[EventData[Data[@Name='AttributeLDAPDisplayName']='msDS-KeyCredentialLink' or Data[@Name='AttributeLDAPDisplayName']='msDS-AllowedToActOnBehalfOfOtherIdentity' or Data[@Name='AttributeLDAPDisplayName']='gPCFileSysPath' or Data[@Name='AttributeLDAPDisplayName']='servicePrincipalName' or Data[@Name='AttributeLDAPDisplayName']='nTSecurityDescriptor']]" }
        )
        $domDN = [string]$D.AdDomainDN
        if (-not $domDN -and $env:USERDNSDOMAIN) { $domDN = ((@($env:USERDNSDOMAIN.Split('.') | ForEach-Object { "DC=$_" })) -join ',') }
        $ev = New-Object System.Collections.Generic.List[object]
        foreach ($q in $queries) {
            foreach ($e in (Get-EvXPath 'Security' $q.X $q.L)) {
                $r = Get-AdAttackRow ([int]$e.Id) (Get-EvData $e) $domDN
                if (-not $r) { continue }
                $ev.Add([pscustomobject]@{ TimeUtc = (U $e.TimeCreated); TimeLocal = (L $e.TimeCreated); EventId = $e.Id; Technique = $r.Technique; Severity = $r.Severity
                    Actor = $r.Actor; Target = $r.Target; SourceIP = $r.SourceIP; Details = $r.Details })
            }
        }
        $D.AdEvents = Arr ($ev | Sort-Object TimeUtc)
        Save-Csv $D.AdEvents '03_eventlogs\ad_attack_events.csv'

        # ── Зведення (підказки для аналітика) ──
        $fnd = New-Object System.Collections.Generic.List[object]
        foreach ($g in @($D.AdEvents | Where-Object { $_.EventId -eq 4769 } | Group-Object Actor, SourceIP)) {
            $svcs = @($g.Group | ForEach-Object { $_.Target } | Select-Object -Unique)
            $first = $g.Group[0]; $last = $g.Group[$g.Count - 1]
            $sev = $(if ($svcs.Count -ge 5) { 'Високо' } else { 'Середньо' })
            $fnd.Add([pscustomobject]@{ Severity = $sev; Technique = $(if ($svcs.Count -ge 5) { 'Ймовірний Kerberoasting' } else { 'RC4/DES-квитки на сервісні облікові записи' })
                Who = ("{0} з {1}" -f $first.Actor, $first.SourceIP); Count = $g.Count
                Evidence = ("{0} різних SPN: {1}; {2} → {3}" -f $svcs.Count, (($svcs | Select-Object -First 8) -join ', '), $first.TimeLocal, $last.TimeLocal) })
        }
        foreach ($g in @($D.AdEvents | Where-Object { $_.EventId -eq 4768 } | Group-Object Target, SourceIP)) {
            $fnd.Add([pscustomobject]@{ Severity = 'Високо'; Technique = 'AS-REP roasting'; Who = ("{0} (запит з {1})" -f $g.Group[0].Target, $g.Group[0].SourceIP); Count = $g.Count
                Evidence = ("{0} → {1}" -f $g.Group[0].TimeLocal, $g.Group[$g.Count - 1].TimeLocal) })
        }
        foreach ($g in @($D.AdEvents | Where-Object { $_.EventId -eq 4771 -and $_.SourceIP } | Group-Object SourceIP)) {
            $accs = @($g.Group | ForEach-Object { $_.Target } | Select-Object -Unique)
            if ($accs.Count -ge 10) { $fnd.Add([pscustomobject]@{ Severity = 'Високо'; Technique = 'Password spraying (Kerberos)'; Who = $g.Name; Count = $g.Count
                Evidence = ("{0} різних облікових записів: {1}…; {2} → {3}" -f $accs.Count, (($accs | Select-Object -First 8) -join ', '), $g.Group[0].TimeLocal, $g.Group[$g.Count - 1].TimeLocal) }) }
        }
        foreach ($g in @($D.AdEvents | Where-Object { $_.EventId -eq 4771 } | Group-Object Target)) {
            if ($g.Count -ge 10) { $fnd.Add([pscustomobject]@{ Severity = 'Середньо'; Technique = 'Підбір пароля (Kerberos)'; Who = $g.Name; Count = $g.Count
                Evidence = ("джерела: {0}; {1} → {2}" -f ((@($g.Group | ForEach-Object { $_.SourceIP } | Select-Object -Unique) | Select-Object -First 8) -join ', '), $g.Group[0].TimeLocal, $g.Group[$g.Count - 1].TimeLocal) }) }
        }
        foreach ($e in @($D.AdEvents | Where-Object { $_.EventId -notin 4769, 4768, 4771 })) {
            $fnd.Add([pscustomobject]@{ Severity = $e.Severity; Technique = $e.Technique; Who = $e.Actor; Count = 1; Evidence = ("{0}; {1}; {2}" -f $e.TimeLocal, $e.Target, $e.Details) })
        }
        $D.AdFindings = Arr $fnd
        Save-Csv $D.AdFindings '03_eventlogs\ad_attack_findings.csv'
        Save-Csv $D.AdAudit '03_eventlogs\ad_audit_coverage.csv'
    }
}

# ════════════════════════════════════ 3.9 ОРИГІНАЛЬНІ ЖУРНАЛИ (.evtx) ════════════════════════════════════
# NIST SP 800-86: зберігати оригінальні дані, а не лише вибірки. Повний експорт журналу (wevtutil epl) — для
# переаналізу іншими інструментами (Hayabusa, Chainsaw, EvtxECmd, Event Viewer) і перевірки висновків звіту.
if (-not $NoEvtx) {
    Invoke-Step "3.9 Експорт оригінальних журналів (.evtx) з hash — для переаналізу (Hayabusa, Chainsaw, EvtxECmd)" {
        $dir = Join-Path $CaseDir '03_eventlogs\evtx'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($l in @($D.LogHealth | Where-Object { $_.Exists -eq $true })) { if (-not $names.Contains($l.Log)) { $names.Add($l.Log) } }
        foreach ($x in 'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-WinRM/Operational',
                       'Microsoft-Windows-TerminalServices-RDPClient/Operational', 'Microsoft-Windows-SMBServer/Security', 'Microsoft-Windows-NTLM/Operational',
                       'Directory Service', 'DNS Server') {
            if (-not $names.Contains($x)) { $names.Add($x) }
        }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($n in $names) {
            $li = $null
            try { $li = Get-WinEvent -ListLog $n -ErrorAction Stop } catch { continue }   # журналу немає на цій системі (напр. Directory Service не на DC)
            if (-not $li.RecordCount) {
                $rows.Add([pscustomobject]@{ Log = $n; Records = 0; SizeMB = ''; File = ''; SHA256 = ''; Seconds = ''; Status = 'Порожній — не експортувався' })
                continue
            }
            $file = Join-Path $dir (($n -replace '[\\/:*?"<>| ]', '_') + '.evtx')
            $rel = $file.Substring($CaseDir.Length + 1)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $out = ((& wevtutil.exe epl $n $file /ow:true 2>&1) | Out-String).Trim()
            $code = $LASTEXITCODE
            $sw.Stop()
            if ($code -eq 0 -and (Test-Path -LiteralPath $file)) {
                $h = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
                $mb = [math]::Round((Get-Item -LiteralPath $file).Length / 1MB, 1)
                $Integrity.Add([pscustomobject]@{ Source = "Журнал: $n"; Copy = $rel; Method = 'wevtutil epl (повний експорт)'; SHA256_Source_Before = 'н/д (живий журнал)'
                    SHA256_Copy = $h; SHA256_Source_After = 'н/д'; Status = 'EXPORT: hash копії зафіксовано'; Error = '' })
                Add-Custody 'EXPORT_EVTX' $n 'OK' ("{0} подій, {1} MB, {2:N1} с, sha256={3}" -f $li.RecordCount, $mb, $sw.Elapsed.TotalSeconds, $h)
                $rows.Add([pscustomobject]@{ Log = $n; Records = $li.RecordCount; SizeMB = $mb; File = $rel; SHA256 = $h; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Status = 'OK' })
            } else {
                Add-Custody 'EXPORT_EVTX' $n 'FAIL' ("код {0}: {1}" -f $code, $out)
                $rows.Add([pscustomobject]@{ Log = $n; Records = $li.RecordCount; SizeMB = ''; File = ''; SHA256 = ''; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Status = ("ПОМИЛКА (код {0}): {1}" -f $code, $out) })
            }
        }
        $D.EvtxExport = Arr $rows
        Save-Csv $D.EvtxExport '03_eventlogs\evtx_export.csv'
        $fail = @($rows | Where-Object { $_.Status -like 'ПОМИЛКА*' })
        if ($fail.Count) { Add-Note ("Експорт .evtx: {0} журнал(ів) не експортовано — див. 03_eventlogs\evtx_export.csv." -f $fail.Count) }
    }
} else { Add-Note 'Експорт оригінальних .evtx пропущено (-NoEvtx) — у справі лише CSV-вибірки журналів.' }

# ════════════════════════════════════ 4. FIREWALL-ЛОГ (pfirewall.log) ════════════════════════════════════
Invoke-Step "4. pfirewall.log: зведення по портах і джерелах, allow/drop, first/last, IOC IP" {
    # Шляхи з профілів різняться регістром (system32 / System32) — без дедупу той самий лог читався двічі і лічильники подвоювались
    $files = New-Object System.Collections.Generic.List[string]
    $seenFw = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $cands = @(@($D.FwProfiles) | ForEach-Object { $_.LogFile }) + @(Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log')
    foreach ($c in $cands) {
        if (-not $c) { continue }
        $full = $c; try { $full = [IO.Path]::GetFullPath($c) } catch {}
        if ($seenFw.Add($full)) { $files.Add($full) }
    }
    $all = @(); foreach ($f in $files) { $all += $f; $all += ($f + '.old') }
    $own = @($D.OwnIPs)
    $byPort = @{}; $bySrc = @{}
    $iocRaw = New-Object System.Collections.Generic.List[object]
    $svcHits = New-Object System.Collections.Generic.List[object]
    $svcPorts = @('3389', '445', '139', '135', '22', '5985', '5986', '1688')
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $read = 0; $inWin = 0
    foreach ($f in $all) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        if (-not $SkipEvidenceCopy) { [void](Copy-Evidence $f '06_evidence_copies\firewall' -ActiveFile) }
        $fields = @('date', 'time', 'action', 'protocol', 'src-ip', 'dst-ip', 'src-port', 'dst-port', 'size', 'tcpflags', 'tcpsyn', 'tcpack', 'tcpwin', 'icmptype', 'icmpcode', 'info', 'path', 'pid')
        $ix = @{}; for ($i = 0; $i -lt $fields.Count; $i++) { $ix[$fields[$i]] = $i }
        $lines = Read-SharedLines $f
        Add-Custody 'READ_FILE' $f 'OK' ("{0} рядків" -f $lines.Count)
        foreach ($line in $lines) {
            if (-not $line) { continue }
            if ($line.StartsWith('#')) {
                if ($line -like '#Fields:*') { $fields = @($line.Substring(8).Trim() -split '\s+'); $ix = @{}; for ($i = 0; $i -lt $fields.Count; $i++) { $ix[$fields[$i]] = $i } }
                continue
            }
            $read++
            $c = $line -split ' '
            if ($c.Count -lt 8) { continue }
            $t = [datetime]::MinValue
            if (-not [datetime]::TryParseExact(("{0} {1}" -f $c[$ix['date']], $c[$ix['time']]), 'yyyy-MM-dd HH:mm:ss', $inv, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$t)) { continue }
            if ($t -lt $Since -or $t -gt $Until) { continue }
            $inWin++
            $act = $c[$ix['action']]; $proto = $c[$ix['protocol']]; $src = $c[$ix['src-ip']]; $dst = $c[$ix['dst-ip']]; $dport = $c[$ix['dst-port']]
            $dir = ''; if ($ix.ContainsKey('path') -and $ix['path'] -lt $c.Count) { $dir = $c[$ix['path']] }
            $pk = "$proto,$dport"
            if (-not $byPort.ContainsKey($pk)) { $byPort[$pk] = @{ Allow = 0; Drop = 0; Srcs = (New-Object 'System.Collections.Generic.HashSet[string]') } }
            if ($act -eq 'ALLOW') { $byPort[$pk].Allow++ } elseif ($act -eq 'DROP') { $byPort[$pk].Drop++ }
            [void]$byPort[$pk].Srcs.Add($src)
            if (-not $bySrc.ContainsKey($src)) { $bySrc[$src] = @{ Total = 0; Allow = 0; Drop = 0; Icmp = 0; Ports = (New-Object 'System.Collections.Generic.HashSet[string]'); Protos = (New-Object 'System.Collections.Generic.HashSet[string]'); Dsts = (New-Object 'System.Collections.Generic.HashSet[string]'); First = $t; Last = $t; Dirs = (New-Object 'System.Collections.Generic.HashSet[string]') } }
            $s = $bySrc[$src]
            $s.Total++
            if ($act -eq 'ALLOW') { $s.Allow++ } elseif ($act -eq 'DROP') { $s.Drop++ }
            if ($proto -like 'ICMP*') { $s.Icmp++ }
            [void]$s.Ports.Add($dport); [void]$s.Protos.Add($proto); [void]$s.Dsts.Add($dst); if ($dir) { [void]$s.Dirs.Add($dir) }
            if ($t -lt $s.First) { $s.First = $t }; if ($t -gt $s.Last) { $s.Last = $t }
            if (($IocIpSet.Contains($src) -or $IocIpSet.Contains($dst)) -and $iocRaw.Count -lt 5000) {
                $iocRaw.Add([pscustomobject]@{ TimeLocal = $t.ToString('yyyy-MM-dd HH:mm:ss'); TimeUtc = (U $t); Action = $act; Protocol = $proto; Src = $src; SrcPort = $c[$ix['src-port']]; Dst = $dst; DstPort = $dport; Direction = $dir; Raw = $line })
            }
            if ($svcPorts -contains $dport -and $own -notcontains $src -and $svcHits.Count -lt 50000) {
                $svcHits.Add([pscustomobject]@{ TimeUtcDt = $t.ToUniversalTime(); Src = $src; DstPort = $dport; Action = $act })
            }
        }
    }
    Add-Custody 'PARSE_FIREWALL_LOG' ($all -join '; ') 'OK' ("прочитано {0} записів, у вікні {1}" -f $read, $inWin)
    if ($read -eq 0) { Add-Note 'pfirewall.log не знайдено або порожній — перевірте, чи ввімкнено логування firewall (LogBlocked/LogAllowed).' }

    $D.FwByPort = Arr ($byPort.GetEnumerator() | ForEach-Object {
        $parts = $_.Key.Split(',')
        [pscustomobject]@{ Protocol = $parts[0]; DstPort = $parts[1]; Allow = $_.Value.Allow; Drop = $_.Value.Drop; Total = ($_.Value.Allow + $_.Value.Drop); UniqueSources = $_.Value.Srcs.Count
            Sources = ((@($_.Value.Srcs) | Select-Object -First 15) -join ', ') }
    } | Sort-Object Total -Descending)
    $D.FwBySource = Arr ($bySrc.GetEnumerator() | ForEach-Object {
        $v = $_.Value; $ip = $_.Key; $isOwn = ($own -contains $ip)
        $h = @()
        if (-not $isOwn) {
            if (Test-IocIPEq $ip) { $h += 'IOC IP' }
            if ($v.Icmp -ge 20) { $h += ("ICMP ×{0} — можлива розвідка (ping sweep)" -f $v.Icmp) }
            if (@($v.Ports | Where-Object { $_ -in '3389', '5985', '5986', '22' }).Count -gt 0) { $h += 'Звернення до RDP/WinRM/SSH' }
            # На контролері домену SMB/RPC з внутрішніх адрес без DROP — штатний трафік клієнтів домену (GPO, SYSVOL, реплікація)
            if (@($v.Ports | Where-Object { $_ -in '445', '139', '135' }).Count -gt 0 -and -not ($D.IsDC -and (Test-PrivateIP $ip) -and $v.Drop -eq 0)) { $h += 'Звернення до SMB/RPC' }
            if ($v.Drop -ge 20) { $h += ("Багато DROP ({0})" -f $v.Drop) }
            if ($v.Ports.Count -ge 15) { $h += ("Багато портів ({0}) — схоже на сканування" -f $v.Ports.Count) }
        }
        [pscustomobject]@{ SourceIP = $ip; Own = $isOwn; Total = $v.Total; Allow = $v.Allow; Drop = $v.Drop; ICMP = $v.Icmp
            DstPorts = ((@($v.Ports) | Sort-Object { $n = 0; if ([int]::TryParse($_, [ref]$n)) { $n } else { 99999 } } | Select-Object -First 25) -join ',')
            Protocols = (@($v.Protos) -join ','); Destinations = ((@($v.Dsts) | Select-Object -First 10) -join ', '); Direction = (@($v.Dirs) -join ',')
            FirstLocal = $v.First.ToString('yyyy-MM-dd HH:mm:ss'); LastLocal = $v.Last.ToString('yyyy-MM-dd HH:mm:ss'); FirstUtc = (U $v.First); LastUtc = (U $v.Last)
            Heuristic = ($h -join '; ') }
    } | Sort-Object @{ Expression = { if ($_.Heuristic) { 0 } else { 1 } } }, @{ Expression = { $_.Total }; Descending = $true })
    $D.FwIocRaw = Arr $iocRaw
    $D.FwSvcHits = Arr $svcHits
    $D.FwLinesInWindow = $inWin
    Save-Csv $D.FwByPort '04_firewall\fw_log_by_port.csv'
    Save-Csv $D.FwBySource '04_firewall\fw_log_by_source.csv'
    Save-Csv $D.FwIocRaw '04_firewall\fw_log_ioc_raw.csv'
}

# ════════════════════════════════════ 5. ФАЙЛОВІ АРТЕФАКТИ ════════════════════════════════════
Invoke-Step "5.1 Відомі шляхи IOC: MAC до/після, hash, підпис, Zone.Identifier" {
    $rows = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $KnownPaths) { if (Test-Path -LiteralPath $p -PathType Leaf) { [void]$seen.Add((Get-Item -LiteralPath $p -Force).FullName) } }
    foreach ($p in $KnownPaths) {
        if (Test-Path -LiteralPath $p -PathType Leaf) { $rows.Add((Get-FileEvidence $p 'Відомий шлях')) }
        elseif (Test-Path -LiteralPath $p -PathType Container) {
            $di = Get-Item -LiteralPath $p -Force
            $rows.Add([pscustomobject]@{ Origin = 'Відомий шлях (папка)'; Path = $p; Exists = $true; SizeBytes = ''; CreatedUtc = (U $di.CreationTimeUtc); ModifiedUtc = (U $di.LastWriteTimeUtc)
                AccessedUtc_Before = (U $di.LastAccessTimeUtc); AccessedUtc_After = ''; AtimeChanged = ''; SHA256 = ''; MD5 = ''; Signature = ''; Signer = ''; ZoneId = ''; HostUrl = ''; ReferrerUrl = ''
                PathClass = (Get-PathClass ($p + '\x')); IocHash = $false; Note = 'Директорія' })
            $n = 0
            foreach ($f in @(Get-ChildItem -LiteralPath $p -Recurse -File -Force -ErrorAction SilentlyContinue)) {
                if ($n -ge 300) { Add-Note "Відомий шлях $p містить >300 файлів — оброблено перші 300."; break }
                if (-not $seen.Add($f.FullName)) { continue }
                $rows.Add((Get-FileEvidence $f.FullName "Вміст $p")); $n++
            }
        } else {
            $rows.Add([pscustomobject]@{ Origin = 'Відомий шлях'; Path = $p; Exists = $false; SizeBytes = ''; CreatedUtc = ''; ModifiedUtc = ''; AccessedUtc_Before = ''; AccessedUtc_After = ''; AtimeChanged = ''
                SHA256 = ''; MD5 = ''; Signature = ''; Signer = ''; ZoneId = ''; HostUrl = ''; ReferrerUrl = ''; PathClass = ''; IocHash = $false; Note = 'Відсутній' })
        }
    }
    $D.KnownFiles = Arr $rows
    Save-Csv $D.KnownFiles '05_artifacts\known_paths.csv'
}

if (-not $SkipWideSearch) {
    Invoke-Step "5.2 Широкий пошук за масками по всіх дисках (класифікація: цікаві / ймовірний шум)" {
        $hiExt = '^(?i)\.(exe|dll|sys|scr|com|msi|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|rar|zip|7z|cab|iso|img|ini|cfg|txt|reg|xml|json|log)$'
        $res = Find-Pattern -Roots $SearchRootsFinal -Patterns $NamePatterns -Exclude $ExcludeDirs
        Add-Custody 'WIDE_SEARCH' ($SearchRootsFinal -join ', ') 'OK' ("переглянуто файлів: {0}; збігів: {1}; папок: {2}" -f $res.Scanned, $res.Files.Count, $res.Dirs.Count)
        $known = @($D.KnownFiles | ForEach-Object { $_.Path.ToLowerInvariant() })
        $hi = New-Object System.Collections.Generic.List[object]; $lo = New-Object System.Collections.Generic.List[object]
        foreach ($f in $res.Files) {
            if ($known -contains $f.FullName.ToLowerInvariant()) { continue }
            $cls = Get-PathClass $f.FullName
            if ($f.Extension -match $hiExt -and $cls -notin @('Системний', 'Program Files')) { $hi.Add((Get-FileEvidence $f.FullName 'Пошук за маскою')) }
            else {
                $lo.Add([pscustomobject]@{ Path = $f.FullName; SizeBytes = $f.Length; CreatedUtc = (U $f.CreationTimeUtc); ModifiedUtc = (U $f.LastWriteTimeUtc); PathClass = $cls
                    Note = 'Лише метадані (файл не читався — Accessed не змінюється)' })
            }
        }
        $D.WideHigh = Arr $hi; $D.WideLow = Arr $lo
        $D.WideDirs = Arr ($res.Dirs | ForEach-Object { [pscustomobject]@{ Path = $_.FullName; CreatedUtc = (U $_.CreationTimeUtc); ModifiedUtc = (U $_.LastWriteTimeUtc); PathClass = (Get-PathClass ($_.FullName + '\x')) } })
        $D.WideScanned = $res.Scanned
        Save-Csv $D.WideHigh '05_artifacts\pattern_hits_interesting.csv'
        Save-Csv $D.WideLow '05_artifacts\pattern_hits_low_interest.csv'
        Save-Csv $D.WideDirs '05_artifacts\pattern_dirs.csv'
    }
} else { Add-Note 'Широкий пошук по дисках пропущено (-SkipWideSearch).' }

Invoke-Step "5.3 LNK-ярлики (Recent, Desktop) з розбором цілі" {
    $wsh = $null; try { $wsh = New-Object -ComObject WScript.Shell } catch { Add-Note 'WScript.Shell недоступний — ціль LNK не розбирається.' }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($D.Profiles | Where-Object { $_.Exists })) {
        foreach ($sub in 'AppData\Roaming\Microsoft\Windows\Recent', 'Desktop') {
            $dir = Join-Path $p.Path $sub
            foreach ($l in @(Get-ChildItem -LiteralPath $dir -Filter '*.lnk' -File -Force -ErrorAction SilentlyContinue)) {
                $tgt = ''; $args2 = ''
                if ($wsh) { try { $sc = $wsh.CreateShortcut($l.FullName); $tgt = $sc.TargetPath; $args2 = $sc.Arguments } catch {} }
                $rows.Add([pscustomobject]@{ Profile = $p.User; Lnk = $l.FullName; LnkCreatedUtc = (U $l.CreationTimeUtc); LnkModifiedUtc = (U $l.LastWriteTimeUtc)
                    Target = $tgt; Arguments = $args2; Match = ((Test-KwMatch "$($l.Name) $tgt $args2") -or (Test-IocIP $args2)) })
            }
        }
    }
    $D.Lnk = Arr ($rows | Sort-Object @{ Expression = { -not $_.Match } }, LnkCreatedUtc)
    Save-Csv $D.Lnk '05_artifacts\lnk_recent_desktop.csv'
}

Invoke-Step "5.4 BAM/DAM (останній запуск виконуваних файлів) та Prefetch" {
    $rows = New-Object System.Collections.Generic.List[object]
    $found = $false
    foreach ($root in 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings') {
        if (-not (Test-Path $root)) { continue }
        $found = $true
        foreach ($sk in @(Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $key = Get-Item -LiteralPath $sk.PSPath -ErrorAction SilentlyContinue
            if (-not $key) { continue }
            $user = Resolve-Sid $sk.PSChildName
            foreach ($vn in $key.GetValueNames()) {
                if ($vn -in 'Version', 'SequenceNumber') { continue }
                $b = $key.GetValue($vn)
                $t = ''
                if ($b -is [byte[]] -and $b.Length -ge 8) { try { $t = U ([DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b, 0))) } catch {} }
                $rows.Add([pscustomobject]@{ Source = ($root -replace '^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\', ''); User = $user; Executable = $vn; LastRunUtc = $t; Match = (Test-KwMatch $vn) })
            }
        }
    }
    if (-not $found) { Add-Note 'Ключі BAM/DAM відсутні на цій системі — джерело "останній запуск" недоступне.' }
    elseif ($rows.Count -eq 0) { Add-Note 'Ключі BAM/DAM присутні, але записів немає.' }
    $D.Bam = Arr ($rows | Sort-Object @{ Expression = { -not $_.Match } }, @{ Expression = { $_.LastRunUtc }; Descending = $true })
    Save-Csv $D.Bam '05_artifacts\bam_dam.csv'

    $pdir = Join-Path $env:SystemRoot 'Prefetch'
    $pfAll = @(Get-ChildItem -LiteralPath $pdir -Filter '*.pf' -File -Force -ErrorAction SilentlyContinue)
    $D.PrefetchTotal = $pfAll.Count
    $D.Prefetch = Arr ($pfAll | Where-Object { (Test-KwMatch $_.Name) } | ForEach-Object {
        [pscustomobject]@{ File = $_.Name; CreatedUtc = (U $_.CreationTimeUtc); ModifiedUtc = (U $_.LastWriteTimeUtc); Note = 'Created ≈ перший запуск, Modified ≈ останній запуск' } })
    Save-Csv $D.Prefetch '05_artifacts\prefetch_matches.csv'
}

Invoke-Step '5.5 Кошик ($I-записи): що видалено, коли, звідки' {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $SearchRootsFinal) {
        $rb = Join-Path $r '$Recycle.Bin'
        foreach ($f in @(Get-ChildItem -LiteralPath $rb -Recurse -Force -File -Filter '$I*' -ErrorAction SilentlyContinue)) {
            try {
                $b = [IO.File]::ReadAllBytes($f.FullName)
                if ($b.Length -lt 24) { continue }
                $ver = [BitConverter]::ToInt64($b, 0); $size = [BitConverter]::ToInt64($b, 8); $del = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b, 16))
                if ($ver -eq 2 -and $b.Length -ge 28) { $len = [BitConverter]::ToInt32($b, 24); $name = [Text.Encoding]::Unicode.GetString($b, 28, [Math]::Min(($len - 1) * 2, $b.Length - 28)) }
                else { $name = [Text.Encoding]::Unicode.GetString($b, 24, [Math]::Min(520, $b.Length - 24)).TrimEnd([char]0) }
                $rows.Add([pscustomobject]@{ DeletedUtc = (U $del); OriginalPath = $name; SizeBytes = $size; Owner = (Resolve-Sid $f.Directory.Name); InfoFile = $f.FullName; Match = (Test-KwMatch $name) })
            } catch {}
        }
    }
    $D.Recycle = Arr ($rows | Sort-Object DeletedUtc -Descending)
    Save-Csv $D.Recycle '05_artifacts\recycle_bin.csv'
}

Invoke-Step "5.6 Zone.Identifier (Mark of the Web) у Downloads/Desktop і корені дисків" {
    $rows = New-Object System.Collections.Generic.List[object]
    $cand = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($D.Profiles | Where-Object { $_.Exists })) {
        foreach ($sub in 'Downloads', 'Desktop') { foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $p.Path $sub) -Recurse -File -Force -ErrorAction SilentlyContinue)) { $cand.Add($f) } }
    }
    foreach ($r in $SearchRootsFinal) { foreach ($f in @(Get-ChildItem -LiteralPath $r -File -Force -ErrorAction SilentlyContinue)) { $cand.Add($f) } }
    foreach ($f in $cand) {
        $zs = Get-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
        if (-not $zs) { continue }
        $z = @(Get-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue)
        $zid = ''; $hu = ''; $ru = ''
        foreach ($l in $z) { if ($l -match '^ZoneId=(\d+)') { $zid = $Matches[1] } elseif ($l -match '^HostUrl=(.+)$') { $hu = $Matches[1] } elseif ($l -match '^ReferrerUrl=(.+)$') { $ru = $Matches[1] } }
        $rows.Add([pscustomobject]@{ File = $f.FullName; CreatedUtc = (U $f.CreationTimeUtc); ModifiedUtc = (U $f.LastWriteTimeUtc); ZoneId = $zid; HostUrl = $hu; ReferrerUrl = $ru; Match = (Test-KwMatch "$($f.Name) $hu $ru") })
    }
    $D.Zone = Arr ($rows | Sort-Object @{ Expression = { -not $_.Match } }, CreatedUtc)
    Save-Csv $D.Zone '05_artifacts\zone_identifier.csv'
}

if (-not $SkipEvidenceCopy) {
    Invoke-Step "5.7 Копії доказів (hash до/після): історія браузерів, Windows Timeline, PowerShell history + пошук підказок" {
        $hints = New-Object System.Collections.Generic.List[object]
        $psh = New-Object System.Collections.Generic.List[object]
        $psRx = '(?i)(slmgr|kms|netsh|advfirewall|add-mppreference|set-mppreference|wmic|schtasks|sc(\.exe)?\s+(create|config|delete)|reg(\.exe)?\s+add|invoke-webrequest|downloadstring|certutil|bitsadmin|remove-item|clear-eventlog|wevtutil|new-netfirewallrule)'
        foreach ($p in @($D.Profiles | Where-Object { $_.Exists })) {
            $userTag = ($p.User -replace '[\\/:*?"<>| ]', '_') + '__'
            $targets = New-Object System.Collections.Generic.List[object]
            foreach ($b in @(@{ N = 'Chrome'; P = 'AppData\Local\Google\Chrome\User Data' }, @{ N = 'Edge'; P = 'AppData\Local\Microsoft\Edge\User Data' })) {
                $root = Join-Path $p.Path $b.P
                foreach ($prof in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
                    $h = Join-Path $prof.FullName 'History'
                    if (Test-Path -LiteralPath $h) { $targets.Add(@{ Kind = "$($b.N) History ($($prof.Name))"; Path = $h; Prefix = "$userTag$($b.N)_$($prof.Name -replace ' ','')_"; Sqlite = $true }) }
                }
            }
            foreach ($ff in @(Get-ChildItem -LiteralPath (Join-Path $p.Path 'AppData\Roaming\Mozilla\Firefox\Profiles') -Directory -Force -ErrorAction SilentlyContinue)) {
                $pl = Join-Path $ff.FullName 'places.sqlite'
                if (Test-Path -LiteralPath $pl) { $targets.Add(@{ Kind = "Firefox places ($($ff.Name))"; Path = $pl; Prefix = "${userTag}Firefox_$($ff.Name)_"; Sqlite = $true }) }
            }
            foreach ($cd in @(Get-ChildItem -LiteralPath (Join-Path $p.Path 'AppData\Local\ConnectedDevicesPlatform') -Directory -Force -ErrorAction SilentlyContinue)) {
                $ac = Join-Path $cd.FullName 'ActivitiesCache.db'
                if (Test-Path -LiteralPath $ac) { $targets.Add(@{ Kind = 'Windows Timeline (ActivitiesCache.db)'; Path = $ac; Prefix = "${userTag}Timeline_$($cd.Name)_"; Sqlite = $true }) }
            }
            $ph = Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if (Test-Path -LiteralPath $ph) { $targets.Add(@{ Kind = 'PowerShell history'; Path = $ph; Prefix = "${userTag}PS_" }) }

            foreach ($t in $targets) {
                $copy = Copy-Evidence $t.Path '06_evidence_copies\user_artifacts' -Prefix $t.Prefix
                if (-not $copy) { continue }
                # SQLite: найсвіжіші записи часто ще у -wal / -journal, а не в основному файлі — копіюємо поруч з тим самим префіксом
                $hintFiles = @($copy)
                if ($t.Sqlite) {
                    foreach ($sfx in '-wal', '-journal', '-shm') {
                        $side = $t.Path + $sfx
                        if (-not (Test-Path -LiteralPath $side -PathType Leaf)) { continue }
                        $sc = Copy-Evidence $side '06_evidence_copies\user_artifacts' -Prefix $t.Prefix -ActiveFile
                        if ($sc -and $sfx -ne '-shm') { $hintFiles += $sc }
                    }
                }
                if ($t.Kind -eq 'PowerShell history') {
                    $ln = 0
                    foreach ($line in [IO.File]::ReadAllLines($copy)) {
                        $ln++
                        if ($line -match $psRx -or (Test-KwMatch $line) -or (Test-IocIP $line)) { $psh.Add([pscustomobject]@{ Profile = $p.User; Line = $ln; Command = $line }) }
                    }
                } else {
                    foreach ($hf in $hintFiles) {
                        $src = $t.Kind; if ($hf -ne $copy) { $src = "$($t.Kind) [$(Split-Path $hf -Leaf)]" }
                        foreach ($v in @(Get-StringHints $hf)) { $hints.Add([pscustomobject]@{ Profile = $p.User; Source = $src; Hint = $v }) }
                    }
                }
            }
        }
        $D.Hints = Arr $hints; $D.PsHist = Arr $psh
        Save-Csv $D.Hints '05_artifacts\evidence_string_hints.csv'
        Save-Csv $D.PsHist '05_artifacts\powershell_history_hits.csv'
        Add-Note 'Підказки з браузерних БД/Timeline отримані пошуком рядків у КОПІЯХ (без SQLite) — без точних часових міток. Для таймінгу відкрийте копії у DB Browser for SQLite (таблиці urls, downloads; ActivityOperation/Activity). Файли -wal/-journal скопійовано поруч з тим самим префіксом — тримайте їх у одній папці з БД, інакше SQLite не побачить найсвіжіших записів. Копії БД і WAL знято не атомарно.'
    }
} else { Add-Note 'Копіювання браузерних БД/логів пропущено (-SkipEvidenceCopy).' }

if ($CollectHives) {
    Invoke-Step "5.8 Кущі реєстру (reg save) та Amcache (esentutl /vss)" {
        $hd = Join-Path $CaseDir '06_evidence_copies\hives'
        New-Item -ItemType Directory -Force -Path $hd | Out-Null
        foreach ($h in 'SYSTEM', 'SOFTWARE') {
            $dest = Join-Path $hd "$h.hiv"
            $out = ((& reg.exe save "HKLM\$h" $dest /y 2>&1) | Out-String).Trim()
            if (Test-Path -LiteralPath $dest) {
                $Integrity.Add([pscustomobject]@{ Source = "HKLM\$h (живий кущ)"; Copy = $dest.Substring($CaseDir.Length + 1); Method = 'reg save'; SHA256_Source_Before = 'н/д (живий кущ)'
                    SHA256_Copy = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash; SHA256_Source_After = 'н/д'; Status = 'EXPORT: hash копії зафіксовано'; Error = '' })
                Add-Custody 'REG_SAVE' "HKLM\$h" 'OK' $out
            } else { Add-Custody 'REG_SAVE' "HKLM\$h" 'FAIL' $out }
        }
        $am = Join-Path $env:SystemRoot 'AppCompat\Programs\Amcache.hve'
        if (Test-Path -LiteralPath $am) {
            $dest = Join-Path $hd 'Amcache.hve'
            Add-Custody 'VSS_COPY_DECISION' $am 'OK' 'esentutl /vss створює тимчасову тіньову копію тому — зміна стану системи задокументована (NIST 3.1.1)'
            $out = ((& esentutl.exe /y $am /vss /d $dest 2>&1) | Out-String).Trim()
            if (Test-Path -LiteralPath $dest) {
                $Integrity.Add([pscustomobject]@{ Source = $am; Copy = $dest.Substring($CaseDir.Length + 1); Method = 'esentutl /y /vss'; SHA256_Source_Before = 'н/д (заблокований)'
                    SHA256_Copy = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash; SHA256_Source_After = 'н/д'; Status = 'VSS-COPY: hash копії зафіксовано'; Error = '' })
                Add-Custody 'COPY_EVIDENCE' $am 'OK' 'esentutl /vss'
            } else { Add-Custody 'COPY_EVIDENCE' $am 'FAIL' $out }
        }
        Add-Note 'Кущі/Amcache зібрані для офлайн-аналізу (Registry Explorer, AmcacheParser — Eric Zimmerman).'
    }
}

if ($UsnJournal) {
    Invoke-Step "5.9 USN-журнал: записи за масками (створення/видалення/перейменування)" {
        $sb = New-Object System.Text.StringBuilder
        foreach ($r in $SearchRootsFinal) {
            $drv = $r.Substring(0, 2)
            [void]$sb.AppendLine("##### $drv")
            $hdr = $false; $cnt = 0
            & fsutil usn readjournal $drv csv 2>$null | ForEach-Object {
                if (-not $hdr -and $_ -match '(?i)usn|file name|имя|ім') { [void]$sb.AppendLine($_); $hdr = $true; return }
                if (Test-KwMatch $_) { [void]$sb.AppendLine($_); $cnt++ }
            }
            Add-Custody 'READ_USN' $drv 'OK' ("{0} збігів" -f $cnt)
        }
        Save-Text $sb.ToString() '05_artifacts\usn_journal_hits.csv'
    }
}

# ════════════════════════════════════ 6. АНАЛІЗ ════════════════════════════════════
Invoke-Step "6.1 Brute-force: зведення 4625 (ціль, джерело, кількість, перша/остання спроба)" {
    $bf = @($D.Ev4625) | Group-Object -Property TargetUser, SourceIP, Workstation, LogonType, CallerProcess | ForEach-Object {
        $g = @($_.Group | Sort-Object TimeUtc)
        $first = $g[0]; $last = $g[$g.Count - 1]
        $dur = ''; $a = PU $first.TimeUtc; $b = PU $last.TimeUtc
        if ($a -and $b) { $dur = [math]::Round(($b - $a).TotalMinutes, 1) }
        $st = (@($_.Group | Group-Object Status | Sort-Object Count -Descending | ForEach-Object { "{0} ×{1}" -f $_.Name, $_.Count }) -join '; ')
        [pscustomobject]@{ TargetUser = $first.TargetUser; SourceIP = $first.SourceIP; Workstation = $first.Workstation; LogonType = $first.LogonTypeText
            CallerProcess = $first.CallerProcess; Attempts = $_.Count; FirstUtc = $first.TimeUtc; LastUtc = $last.TimeUtc; FirstLocal = $first.TimeLocal; LastLocal = $last.TimeLocal
            DurationMin = $dur; Statuses = $st }
    }
    $D.BruteForce = Arr ($bf | Sort-Object Attempts -Descending)
    Save-Csv $D.BruteForce '03_eventlogs\bruteforce_summary.csv'
}

Invoke-Step "6.2 Кореляція джерела: 4625 ↔ firewall-лог ↔ RDP (NIST 6.4.4 — IP ≠ ідентичність)" {
    $corr = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($D.BruteForce | Where-Object { $_.Attempts -ge 5 })) {
        $ws = PU $g.FirstUtc; $we = PU $g.LastUtc
        if (-not $ws -or -not $we) { continue }
        $ws = $ws.AddMinutes(-15); $we = $we.AddMinutes(15)
        $agg = @{}
        foreach ($h in @($D.FwSvcHits)) {
            if ($h.TimeUtcDt -lt $ws -or $h.TimeUtcDt -gt $we) { continue }
            if (-not $agg.ContainsKey($h.Src)) { $agg[$h.Src] = @{} }
            $pk = ("firewall {0}/{1}" -f $h.DstPort, $h.Action)
            if ($agg[$h.Src].ContainsKey($pk)) { $agg[$h.Src][$pk] = $agg[$h.Src][$pk] + 1 } else { $agg[$h.Src][$pk] = 1 }
        }
        foreach ($r in @($D.Rdp | Where-Object { $_.SourceIP })) {
            $t = PU $r.TimeUtc
            if (-not $t -or $t -lt $ws -or $t -gt $we) { continue }
            if (-not $agg.ContainsKey($r.SourceIP)) { $agg[$r.SourceIP] = @{} }
            $pk = ("RDP {0}" -f $r.EventId)
            if ($agg[$r.SourceIP].ContainsKey($pk)) { $agg[$r.SourceIP][$pk] = $agg[$r.SourceIP][$pk] + 1 } else { $agg[$r.SourceIP][$pk] = 1 }
        }
        if ($g.SourceIP -and $g.SourceIP -ne '-') {
            if (-not $agg.ContainsKey($g.SourceIP)) { $agg[$g.SourceIP] = @{} }
            $agg[$g.SourceIP]['4625 IpAddress'] = $g.Attempts
        }
        if ($agg.Count -eq 0) {
            $corr.Add([pscustomobject]@{ TargetUser = $g.TargetUser; Attempts = $g.Attempts; WindowUtc = ("{0} … {1}" -f $g.FirstUtc, $g.LastUtc); Candidate = '(не знайдено)'; IocIP = $false
                Evidence = 'У вікні ±15 хв немає звернень до RDP/SMB/RPC/WinRM у pfirewall.log і RDP-подій з IP'; Caveat = 'Перевірте логи периметрального firewall / EDR / сусідніх хостів' })
        }
        foreach ($src in $agg.Keys) {
            $ev = (@($agg[$src].GetEnumerator() | Sort-Object Name | ForEach-Object { "{0} ×{1}" -f $_.Name, $_.Value }) -join '; ')
            $corr.Add([pscustomobject]@{ TargetUser = $g.TargetUser; Attempts = $g.Attempts; WindowUtc = ("{0} … {1}" -f $g.FirstUtc, $g.LastUtc); Candidate = $src; IocIP = (Test-IocIPEq $src)
                Evidence = $ev; Caveat = 'Кандидат, не доказ ідентичності: підтвердити DHCP/CMDB/ARP/EDR (NIST SP 800-86, 6.4.4)' })
        }
    }
    $D.Correlation = Arr $corr
    Save-Csv $D.Correlation '03_eventlogs\bruteforce_source_correlation.csv'
}

Invoke-Step "6.3 IOC-матчі по всіх джерелах" {
    $h = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($D.KnownFiles + $D.WideHigh | Where-Object { $_.IocHash })) { $h.Add([pscustomobject]@{ Type = 'SHA256'; Where = 'Файл'; Value = $r.SHA256; Details = $r.Path }) }
    foreach ($r in @($D.Procs | Where-Object { $_.SHA256 -and $IocSha256 -contains $_.SHA256 })) { $h.Add([pscustomobject]@{ Type = 'SHA256'; Where = 'Запущений процес'; Value = $r.SHA256; Details = "$($r.PID) $($r.Path)" }) }
    foreach ($r in @($D.Services | Where-Object { $_.SHA256 -and $IocSha256 -contains $_.SHA256 })) { $h.Add([pscustomobject]@{ Type = 'SHA256'; Where = 'Служба'; Value = $r.SHA256; Details = $r.Name }) }
    foreach ($r in @($D.Exec | Where-Object { $_.SHA256 -and $IocSha256 -contains $_.SHA256 })) { $h.Add([pscustomobject]@{ Type = 'SHA256'; Where = 'Запуск (Sysmon)'; Value = $r.SHA256; Details = "$($r.TimeLocal) $($r.Image)" }) }
    foreach ($r in @($D.Tcp | Where-Object { $_.IocIP })) { $h.Add([pscustomobject]@{ Type = 'IP'; Where = "TCP-з'єднання"; Value = $r.RemoteAddress; Details = "$($r.State) $($r.Process)" }) }
    foreach ($r in @($D.Arp | Where-Object { $_.IocIP })) { $h.Add([pscustomobject]@{ Type = 'IP'; Where = 'ARP/NDP-сусід'; Value = $r.IPAddress; Details = "MAC $($r.MAC) ($($r.State))" }) }
    foreach ($r in @($D.FwBySource | Where-Object { Test-IocIPEq $_.SourceIP })) { $h.Add([pscustomobject]@{ Type = 'IP'; Where = 'pfirewall.log'; Value = $r.SourceIP; Details = ("{0} записів (ALLOW {1} / DROP {2}, ICMP {3}), порти {4}, {5} → {6}" -f $r.Total, $r.Allow, $r.Drop, $r.ICMP, $r.DstPorts, $r.FirstLocal, $r.LastLocal) }) }
    foreach ($r in @($D.RdpSummary | Where-Object { $_.IocIP })) { $h.Add([pscustomobject]@{ Type = 'IP'; Where = 'RDP-журнали'; Value = $r.SourceIP; Details = ("{0} → {1}" -f $r.FirstLocal, $r.LastLocal) }) }
    foreach ($r in @($D.KmsReg | Where-Object { $_.IocIP })) { $h.Add([pscustomobject]@{ Type = 'IP'; Where = 'Реєстр KMS'; Value = $r.Value; Details = "$($r.Key)\$($r.Name)" }) }
    foreach ($r in @($D.Ev4625 | Where-Object { Test-IocIPEq $_.SourceIP } | Select-Object -First 1)) { $h.Add([pscustomobject]@{ Type = 'IP'; Where = '4625 IpAddress'; Value = $r.SourceIP; Details = 'є невдалі входи з цієї адреси' }) }
    $D.IocHits = Arr $h
    Save-Csv $D.IocHits 'ioc_hits.csv'
}

Invoke-Step "6.4 Автоматичні прапорці (підказки для аналітика, не висновки)" {
    foreach ($r in @($D.LogCleared)) { Add-Flag 'Критично' 'Журнали' 'Очищення / зупинка журналу подій' ("{0} ({1}) {2}" -f $r.TimeLocal, $r.EventId, $r.Details) 'auth' }
    foreach ($r in @($D.IocHits | Where-Object { $_.Type -eq 'SHA256' })) { Add-Flag 'Критично' 'IOC' ("Збіг IOC-hash: {0}" -f $r.Where) ("{0} — {1}" -f $r.Value, $r.Details) 'ioc' }
    foreach ($r in @($D.IocHits | Where-Object { $_.Type -eq 'IP' })) { Add-Flag 'Високо' 'IOC' ("IOC IP {0} — {1}" -f $r.Value, $r.Where) $r.Details 'ioc' }
    foreach ($g in @($D.BruteForce | Where-Object { $_.Attempts -ge 10 })) {
        Add-Flag 'Високо' 'Автентифікація' ("Серія невдалих входів на '{0}' ×{1}" -f $g.TargetUser, $g.Attempts) ("{0} → {1} (лок.); IP={2}; WS={3}; {4}; {5}" -f $g.FirstLocal, $g.LastLocal, $g.SourceIP, $g.Workstation, $g.LogonType, $g.Statuses) 'auth'
    }
    foreach ($c in @($D.Correlation | Where-Object { $_.Candidate -ne '(не знайдено)' })) { Add-Flag 'Високо' 'Автентифікація' ("Кандидат-джерело спроб на '{0}': {1}" -f $c.TargetUser, $c.Candidate) $c.Evidence 'auth' }
    foreach ($r in @($D.OtherAuth | Where-Object { $_.EventId -eq 4740 })) { Add-Flag 'Середньо' 'Автентифікація' ("Блокування облікового запису: {0}" -f $r.Target) ("{0}; джерело виклику: {1}" -f $r.TimeLocal, $r.Workstation) 'auth' }
    foreach ($r in @($D.OtherAuth | Where-Object { $_.EventId -in 4720, 4732 })) { Add-Flag 'Високо' 'Облікові записи' ("{0}: {1}" -f $r.Meaning, $r.Target) ("{0}; хто: {1}" -f $r.TimeLocal, $r.Actor) 'auth' }
    foreach ($r in @($D.RdpSummary | Where-Object { $_.'Невдалі креденшали (140)' -ge 5 })) { Add-Flag 'Високо' 'RDP' ("Невдалі RDP-входи з {0} ×{1}" -f $r.SourceIP, $r.'Невдалі креденшали (140)') ("{0} → {1}" -f $r.FirstLocal, $r.LastLocal) 'rdp' }
    foreach ($r in @($D.SvcEvents | Where-Object { $_.EventId -in 7045, 4697 })) {
        $sev = 'Середньо'; if ($r.Match -or (Get-PathClass (Get-ExeFromCmd $r.Binary)) -in @('Нестандартний', 'Користувацький/тимчасовий')) { $sev = 'Високо' }
        Add-Flag $sev 'Служби' ("Встановлено службу '{0}' ({1})" -f $r.Service, $r.EventId) ("{0}; {1}; {2}; ким: {3}; зараз: {4}" -f $r.TimeLocal, $r.Binary, $r.Account, $r.InstalledBy, $r.StateNow) 'services'
    }
    foreach ($r in @($D.Services | Where-Object { $_.Flags -match 'Розташування|IOC|Підпис' })) { Add-Flag 'Середньо' 'Служби' ("Підозріла поточна служба: {0}" -f $r.Name) ("{0} — {1}" -f $r.Binary, $r.Flags) 'services' }
    foreach ($t in @($D.Tasks)) {
        $sev = 'Інфо'; if ($t.Flags -match 'IOC|Дія:|Прихована|Маскування') { $sev = 'Високо' }
        if ($sev -ne 'Інфо' -or $t.Flags -match 'Стороння') { Add-Flag $sev 'Задачі' ("Задача '{0}{1}' (автор: {2})" -f $t.TaskPath, $t.TaskName, $t.Author) ("{0}; дії: {1}; ост. запуск: {2}; {3}" -f $t.State, $t.Actions, $t.LastRunUtc, $t.Flags) 'tasks' }
    }
    foreach ($r in @($D.TaskEvents | Where-Object { $_.EventId -eq 4698 })) { $sev = 'Середньо'; if ($r.Match) { $sev = 'Високо' }; Add-Flag $sev 'Задачі' ("Створено задачу {0}" -f $r.TaskName) ("{0}; {1}; {2}" -f $r.TimeLocal, $r.Actor, $r.Command) 'tasks' }
    $fwManual = @($D.FwEvents | Where-Object { $_.Category -notlike 'Windows*' -and $_.EventId -in 2004, 2097, 2006, 2052, 2005, 2099, 4946, 4947, 4948 })
    foreach ($r in $fwManual) { $sev = 'Середньо'; if ($r.Match) { $sev = 'Високо' }; Add-Flag $sev 'Firewall' ("{0}: {1}" -f $r.Meaning, $r.RuleName) ("{0}; порти {1}/{2}; {3}; ким: {4}" -f $r.TimeLocal, $r.LocalPorts, $r.RemotePorts, $r.ModifyingApp, $r.ModifiedBy) 'firewall' }
    foreach ($r in @($D.FwRules | Where-Object { $_.Flags })) { Add-Flag 'Середньо' 'Firewall' ("Активне правило: {0}" -f $r.DisplayName) ("{0} {1} {2}/{3} {4} — {5}" -f $r.Direction, $r.Action, $r.Protocol, $r.LocalPort, $r.Program, $r.Flags) 'firewall' }
    foreach ($s in @($D.FwBySource | Where-Object { $_.Heuristic -and -not $_.Own })) { $sev = 'Середньо'; if ($s.Heuristic -match 'IOC') { $sev = 'Високо' }; Add-Flag $sev 'Мережа' ("pfirewall.log: {0}" -f $s.SourceIP) ("{0}; ALLOW {1} / DROP {2}; порти {3}; {4} → {5}" -f $s.Heuristic, $s.Allow, $s.Drop, $s.DstPorts, $s.FirstLocal, $s.LastLocal) 'firewall' }
    foreach ($x in @($D.MpExclusions)) { Add-Flag 'Високо' 'Defender' ("Виняток Defender ({0})" -f $x.Type) ("{0} [{1}]" -f $x.Value, $x.PathClass) 'defender' }
    $rtp = @($D.MpStatusRows | Where-Object { $_.Setting -eq 'RealTimeProtectionEnabled' -and $_.Value -eq 'False' })
    if ($rtp.Count) { Add-Flag 'Критично' 'Defender' 'Real-time protection ВИМКНЕНО' 'Get-MpComputerStatus' 'defender' }
    foreach ($r in @($D.MpEvents | Where-Object { $_.EventId -in 5001, 1116, 1117, 1006 })) { Add-Flag 'Високо' 'Defender' ("{0}" -f $r.Meaning) ("{0}; {1}" -f $r.TimeLocal, $r.Details) 'defender' }
    foreach ($r in @($D.MpEvents | Where-Object { $_.EventId -eq 5007 -and $_.Exclusion })) { Add-Flag 'Високо' 'Defender' 'Додано/змінено виняток Defender (5007)' ("{0}; {1}" -f $r.TimeLocal, $r.Details) 'defender' }
    foreach ($k in @($D.KmsReg | Where-Object { $_.Name -match '^KeyManagementServiceName$' })) { Add-Flag 'Середньо' 'Ліцензування' ("KMS-клієнт налаштовано на хост {0}" -f $k.Value) $k.Key 'kms' }
    foreach ($l in @($D.Licensing | Where-Object { $_.EstLastKmsActivationUtc })) { Add-Flag 'Інфо' 'Ліцензування' ("KMS-активація: {0}" -f $l.Name) ("{0}; залишок {1} дн.; орієнтовний час останньої активації/продовження: {2}" -f $l.LicenseStatus, $l.GraceDaysLeft, $l.EstLastKmsActivationUtc) 'kms' }
    foreach ($f in @($D.KnownFiles | Where-Object { $_.Exists -and $_.Note -ne 'Директорія' -and $_.Origin -eq 'Відомий шлях' })) { Add-Flag 'Високо' 'Файли' ("IOC-файл присутній: {0}" -f $f.Path) ("SHA256 {0}; створено {1}" -f $f.SHA256, $f.CreatedUtc) 'files' }
    $wh = @($D.WideHigh)
    if ($wh.Count) { Add-Flag 'Середньо' 'Файли' ("Файли за масками поза системними каталогами: {0}" -f $wh.Count) ((@($wh | Select-Object -First 6 | ForEach-Object { $_.Path }) -join '; ')) 'files' }
    foreach ($l in @($D.Lnk | Where-Object { $_.Match })) { Add-Flag 'Середньо' 'Файли' ("LNK на IOC-об'єкт ({0})" -f $l.Profile) ("{0} → {1}; створено {2}" -f $l.Lnk, $l.Target, $l.LnkCreatedUtc) 'files' }
    foreach ($b in @($D.Bam | Where-Object { $_.Match })) { Add-Flag 'Середньо' 'Виконання' ("BAM: запуск {0}" -f $b.Executable) ("{0}; {1}" -f $b.User, $b.LastRunUtc) 'files' }
    foreach ($r in @($D.Recycle | Where-Object { $_.Match })) { Add-Flag 'Середньо' 'Файли' ("Видалено в кошик: {0}" -f $r.OriginalPath) ("{0}; {1}" -f $r.DeletedUtc, $r.Owner) 'files' }
    foreach ($z in @($D.Zone | Where-Object { $_.Match })) { Add-Flag 'Середньо' 'Файли' ("Завантажено з інтернету: {0}" -f $z.File) ("Zone {0}; {1}" -f $z.ZoneId, $z.HostUrl) 'files' }
    if (@($D.Hints).Count) { Add-Flag 'Середньо' 'Браузер/Timeline' ("Згадки IOC в історії/Timeline: {0}" -f @($D.Hints).Count) ((@($D.Hints | Select-Object -First 4 | ForEach-Object { $_.Hint }) -join ' | ')) 'files' }
    if (@($D.PsHist).Count) { Add-Flag 'Середньо' 'PowerShell' ("Підозрілі команди в PS history: {0}" -f @($D.PsHist).Count) ((@($D.PsHist | Select-Object -First 3 | ForEach-Object { $_.Command }) -join ' | ')) 'files' }
    $execKw = @($D.Exec | Where-Object { $_.Reason -match 'IOC|Підозрілі' })
    if ($execKw.Count) { Add-Flag 'Високо' 'Виконання' ("Запуски з IOC/підозрілими аргументами: {0}" -f $execKw.Count) ((@($execKw | Select-Object -First 4 | ForEach-Object { "{0} {1}" -f $_.TimeLocal, $_.CommandLine }) -join ' | ')) 'exec' }
    if (@($D.Ps4104).Count) { Add-Flag 'Високо' 'PowerShell' ("Підозрілі script blocks (4104): {0}" -f @($D.Ps4104).Count) '' 'exec' }
    foreach ($p in @($D.Procs | Where-Object { $_.Flags })) { Add-Flag 'Середньо' 'Процеси' ("Процес {0} (PID {1})" -f $p.Name, $p.PID) ("{0} — {1}" -f $p.Path, $p.Flags) 'volatile' }
    foreach ($c in @($D.Tcp | Where-Object { $_.State -eq 'Established' -and $_.RemoteIsPublic -and $_.Signature -and $_.Signature -ne 'Valid' })) { Add-Flag 'Високо' 'Мережа' ("Непідписаний процес має зовнішнє з'єднання: {0}" -f $c.Process) ("{0}:{1} ← {2}" -f $c.RemoteAddress, $c.RemotePort, $c.ProcessPath) 'volatile' }
    foreach ($a in @($D.Autoruns | Where-Object { $_.Match -or $_.PathClass -in @('Нестандартний', 'Користувацький/тимчасовий', 'НЕСТАНДАРТНЕ значення') })) { Add-Flag 'Середньо' 'Персистентність' ("{0}: {1}" -f $a.Type, $a.Name) $a.Command 'persist' }
    foreach ($w in @($D.WmiPersist | Where-Object { -not $_.LikelyBenign })) { Add-Flag 'Високо' 'Персистентність' ("WMI-підписка {0}: {1}" -f $w.Class, $w.Name) $w.Details 'persist' }
    foreach ($l in @($D.LogHealth | Where-Object { $_.Severity -in 'Високо', 'Середньо' })) { Add-Flag $l.Severity 'Журнали' ("Журнал {0}: {1} MB, історія {2} дн." -f $l.Log, $l.MaxMB, $l.HistoryDays) $l.Advice 'system' }
    foreach ($h in @($D.Hardening | Where-Object { $_.Status -eq 'Ризик' -and $_.Severity -in 'Високо', 'Середньо' })) {
        Add-Flag $h.Severity 'Конфігурація' ("{0}: {1}" -f $h.Check, $h.Current) ("Рекомендовано: {0}. {1}. Виправлення: {2}" -f $h.Recommended, $h.Why, $h.Fix) 'hardening'
    }
    foreach ($h in @($D.AdConfig | Where-Object { $_.Status -eq 'Ризик' -and $_.Severity -in 'Високо', 'Середньо' })) {
        Add-Flag $h.Severity 'Active Directory' ("{0}: {1}" -f $h.Check, $h.Current) ("Рекомендовано: {0}. {1}. Виправлення: {2}" -f $h.Recommended, $h.Why, $h.Fix) 'ad'
    }
    foreach ($f in @($D.AdFindings | Where-Object { $_.Severity -in 'Критично', 'Високо', 'Середньо' })) {
        Add-Flag $f.Severity 'Active Directory' ("{0}: {1}" -f $f.Technique, $f.Who) ("{0} под.; {1}" -f $f.Count, $f.Evidence) 'ad'
    }
    $adGap = @($D.AdAudit | Where-Object { $_.OK -eq $false })
    if ($adGap.Count) { Add-Flag 'Середньо' 'Active Directory' ("Аудит AD неповний: {0} підкатегор." -f $adGap.Count) ((@($adGap | ForEach-Object { "{0} ({1})" -f $_.Subcategory, $_.Detects }) -join '; ') + ' — відсутність подій не доводить відсутність атаки') 'ad' }
    $badAud = @($D.AuditSettings | Where-Object { $_.OK -eq $false })
    if ($badAud.Count) { Add-Flag 'Середньо' 'Аудит' ("Налаштування аудиту нижче рекомендованих: {0}" -f $badAud.Count) ((@($badAud | ForEach-Object { $_.Setting }) -join '; ')) 'system' }
    if ($D.PrefetchState -like '0*') { Add-Flag 'Інфо' 'Методологія' 'Prefetch вимкнено' 'Відсутність .pf — очікувана, не доказ відсутності запуску' 'integrity' }
    if ($D.LastAccess -like 'УВІМКНЕНО*') { Add-Flag 'Інфо' 'Методологія' 'NTFS last-access увімкнено' 'Accessed може змінитися при читанні — див. розділ цілісності' 'integrity' }
    # Урізана вибірка = частина вікна не проаналізована: початок атаки міг випасти — це не «Інфо»
    foreach ($n in @($Notes | Where-Object { $_ -like 'УВАГА*' })) { Add-Flag 'Середньо' 'Повнота даних' 'Вибірку журналу урізано лімітом -MaxEvents' $n 'integrity' }
}

# ════════════════════════════════════ 7. TIMELINE (UTC, NIST 5.3) ════════════════════════════════════
Invoke-Step "7.1 Єдиний timeline з усіх джерел" {
    foreach ($r in @($D.Ev4625)) { Add-TL $r.TimeUtc 'Security' '4625' ("Невдалий вхід → {0} ({1}); {2}; IP={3}; WS={4}" -f $r.TargetUser, $r.LogonTypeText, $r.Status, $r.SourceIP, $r.Workstation) $r.TargetUser 'detail' }
    foreach ($g in @($D.BruteForce)) { Add-TL $g.FirstUtc 'Аналіз' ("Серія 4625 ×{0}" -f $g.Attempts) ("Серія невдалих входів на {0}: {1} спроб до {2} (лок.); IP={3}; WS={4}; {5}" -f $g.TargetUser, $g.Attempts, $g.LastLocal, $g.SourceIP, $g.Workstation, $g.Statuses) $g.TargetUser 'bad' }
    foreach ($r in @($D.Ev4624)) { Add-TL $r.TimeUtc 'Security' '4624' ("Успішний вхід {0} [{1}] IP={2} WS={3} LogonId={4}" -f $r.TargetUser, $r.LogonType, $r.SourceIP, $r.Workstation, $r.LogonId) $r.TargetUser '' }
    foreach ($r in @($D.OtherAuth)) { $m = ''; if ($r.EventId -in 4740, 4720, 4732) { $m = 'warn' }; Add-TL $r.TimeUtc 'Security' ([string]$r.EventId) ("{0}: {1} {2}" -f $r.Meaning, $r.Target, $r.Status) $r.Actor $m }
    foreach ($r in @($D.LogCleared)) { Add-TL $r.TimeUtc $r.Log ([string]$r.EventId) $r.Details '' 'bad' }
    foreach ($r in @($D.Rdp)) { $m = ''; if ($r.EventId -eq 140 -or (Test-IocIP $r.SourceIP)) { $m = 'warn' }; Add-TL $r.TimeUtc ("RDP/{0}" -f $r.Log) ([string]$r.EventId) ("{0}; user={1}; IP={2}" -f $r.Meaning, $r.User, $r.SourceIP) $r.User $m }
    foreach ($r in @($D.SvcEvents)) { $m = ''; if ($r.EventId -ne 7040) { $m = 'warn' }; if ($r.Match) { $m = 'bad' }; Add-TL $r.TimeUtc 'Служби' ([string]$r.EventId) ("{0} → {1} ({2}, {3})" -f $r.Service, $r.Binary, $r.StartType, $r.Account) $r.InstalledBy $m }
    foreach ($r in @($D.TaskEvents)) { $m = ''; if ($r.Match) { $m = 'bad' } elseif ($r.EventId -eq 4698) { $m = 'warn' }; Add-TL $r.TimeUtc 'Задачі' ([string]$r.EventId) ("{0}: {1} {2}" -f $r.Meaning, $r.TaskName, $r.Command) $r.Actor $m }
    foreach ($r in @($D.FwEvents)) { $m = ''; if ($r.Match) { $m = 'bad' } elseif ($r.Category -notlike 'Windows*') { $m = 'warn' }; Add-TL $r.TimeUtc 'Firewall' ([string]$r.EventId) ("{0}: {1} ({2}/{3}) {4}" -f $r.Meaning, $r.RuleName, $r.LocalPorts, $r.RemotePorts, $r.ModifyingApp) $r.ModifiedBy $m }
    foreach ($r in @($D.MpEvents)) { $m = 'warn'; if ($r.EventId -in 5001, 1116, 1117) { $m = 'bad' }; Add-TL $r.TimeUtc 'Defender' ([string]$r.EventId) ("{0}: {1}" -f $r.Meaning, $r.Details) '' $m }
    foreach ($r in @($D.Exec)) { $m = ''; if ($r.Reason -match 'IOC|Підозрілі') { $m = 'bad' }; Add-TL $r.TimeUtc $r.Source 'Запуск' ("{0}  ← {1}" -f $r.CommandLine, $r.Parent) $r.User $m }
    foreach ($r in @($D.SysmonMisc)) { Add-TL $r.TimeUtc 'Sysmon' $r.EventId ("{0}: {1} ({2})" -f $r.Reason, $r.Target, $r.Image) $r.User 'warn' }
    foreach ($r in @($D.Ps4104)) { Add-TL $r.TimeUtc 'PowerShell' '4104' $r.Snippet '' 'warn' }
    foreach ($r in @($D.AdEvents | Where-Object { $_.Severity -ne 'Інфо' })) { Add-TL $r.TimeUtc 'Active Directory' ([string]$r.EventId) ("{0}: {1} {2} {3}" -f $r.Technique, $r.Target, $r.SourceIP, $r.Details) $r.Actor $(if ($r.Severity -in 'Критично', 'Високо') { 'bad' } else { 'warn' }) }
    foreach ($f in @(@($D.KnownFiles) + @($D.WideHigh) | Where-Object { $_.Exists })) {
        Add-TL $f.CreatedUtc 'Файл' 'Created' ("Створено: {0}" -f $f.Path) '' 'warn'
        if ($f.ModifiedUtc -and $f.ModifiedUtc -ne $f.CreatedUtc) { Add-TL $f.ModifiedUtc 'Файл' 'Modified' ("Змінено (може бути успадковано з архіву): {0}" -f $f.Path) '' '' }
    }
    foreach ($l in @($D.Lnk | Where-Object { $_.Match })) { Add-TL $l.LnkCreatedUtc 'LNK' 'Created' ("Відкрито через Провідник: {0} → {1}" -f $l.Lnk, $l.Target) $l.Profile 'warn' }
    foreach ($b in @($D.Bam | Where-Object { $_.Match })) { Add-TL $b.LastRunUtc 'BAM' 'LastRun' $b.Executable $b.User 'warn' }
    foreach ($r in @($D.Recycle | Where-Object { $_.Match })) { Add-TL $r.DeletedUtc 'Кошик' 'Deleted' $r.OriginalPath $r.Owner 'warn' }
    foreach ($z in @($D.Zone | Where-Object { $_.Match })) { Add-TL $z.CreatedUtc 'Zone.Identifier' 'Download' ("{0} ← {1}" -f $z.File, $z.HostUrl) '' 'warn' }
    foreach ($t in @($D.Tasks)) {
        $m = ''; if ($t.Flags -match 'IOC|Дія:') { $m = 'bad' }
        Add-TL $t.RegisteredUtc 'Задача (стан)' 'Registered' ("{0}{1} (автор {2}): {3}" -f $t.TaskPath, $t.TaskName, $t.Author, $t.Actions) $t.RunAs $m
        Add-TL $t.LastRunUtc 'Задача (стан)' 'LastRun' ("{0}{1} → результат {2}" -f $t.TaskPath, $t.TaskName, $t.LastResult) $t.RunAs $m
    }
    foreach ($s in @($D.FwBySource | Where-Object { $_.Heuristic -and -not $_.Own })) {
        Add-TL $s.FirstUtc 'pfirewall.log' 'Перша активність' ("{0}: {1}" -f $s.SourceIP, $s.Heuristic) $s.SourceIP 'warn'
        Add-TL $s.LastUtc 'pfirewall.log' 'Остання активність' ("{0}: всього {1} (ALLOW {2} / DROP {3})" -f $s.SourceIP, $s.Total, $s.Allow, $s.Drop) $s.SourceIP 'warn'
    }
    foreach ($p in @($D.Procs | Where-Object { $_.Flags })) { Add-TL $p.StartUtc 'Процес (стан)' 'Start' ("{0} (PID {1}) — {2}" -f $p.Path, $p.PID, $p.Flags) $p.Owner 'warn' }
    foreach ($l in @($D.Licensing | Where-Object { $_.EstLastKmsActivationUtc })) { Add-TL $l.EstLastKmsActivationUtc 'Ліцензування (оцінка)' 'KMS' ("Орієнтовна остання KMS-активація/продовження: {0}" -f $l.Name) '' 'warn' }
    $D.TimelineSorted = Arr ($Timeline | Sort-Object TimeUtc)
    Save-Csv $D.TimelineSorted 'timeline_full.csv'
}

# ════════════════════════════════════ 8. ЗВІТ (HTML) ════════════════════════════════════
function HT {
    param($Rows, [string[]]$Cols, [scriptblock]$RowClass = $null, [string]$Csv = '', [string]$Empty = 'Нічого не знайдено за заданими критеріями.')
    $arr = Arr $Rows
    if ($arr.Count -eq 0) { return "<p class='empty'>$(E $Empty)</p>" }
    if (-not $Cols) { $Cols = @($arr[0].PSObject.Properties | ForEach-Object { $_.Name }) }
    $id = 't' + [guid]::NewGuid().ToString('N').Substring(0, 10)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='tw'><div class='tbar'><input class='flt' placeholder='Фільтр…' oninput=""flt(this,'$id')""><span class='cnt'>$($arr.Count) рядк.")
    if ($Csv) { [void]$sb.Append(" · CSV: <code>$(E $Csv)</code>") }
    [void]$sb.Append("</span></div><div class='scroll'><table id='$id'><thead><tr>")
    foreach ($c in $Cols) { [void]$sb.Append("<th onclick='srt(this)'>$(E $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    $n = 0
    foreach ($r in $arr) {
        if ($n -ge $HtmlMaxRows) { break }
        $cls = ''
        if ($RowClass) { try { $cls = [string](& $RowClass $r) } catch {} }
        if ($cls) { [void]$sb.Append("<tr class='$cls'>") } else { [void]$sb.Append('<tr>') }
        foreach ($c in $Cols) {
            $v = $r.$c
            if ($v -is [array]) { $v = ($v -join '; ') }
            $s = [string]$v
            if ($s.Length -gt 1500) { $s = $s.Substring(0, 1500) + '…' }
            [void]$sb.Append("<td>$(E $s)</td>")
        }
        [void]$sb.Append('</tr>'); $n++
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($arr.Count -gt $HtmlMaxRows) { [void]$sb.Append("<p class='muted'>Показано перші $HtmlMaxRows з $($arr.Count) — повні дані в CSV.</p>") }
    [void]$sb.Append('</div>')
    return $sb.ToString()
}
function KV { param($Obj) if ($null -eq $Obj) { return "<p class='empty'>Немає даних.</p>" }; $sb = New-Object System.Text.StringBuilder; [void]$sb.Append("<table class='kv'>"); foreach ($p in $Obj.PSObject.Properties) { [void]$sb.Append("<tr><td>$(E $p.Name)</td><td>$(E $p.Value)</td></tr>") }; [void]$sb.Append('</table>'); return $sb.ToString() }
function Pre { param([string]$t) return "<pre>$(E $t)</pre>" }
function H3  { param([string]$t, [string]$note = '') $x = "<h3>$(E $t)</h3>"; if ($note) { $x += "<p class='muted'>$(E $note)</p>" }; return $x }
function Sec {
    param([string]$Id, [string]$Title, [string]$Body, [switch]$Open, [int]$Count = -1)
    $o = ''; if ($Open) { $o = ' open' }
    $badge = ''; if ($Count -ge 0) { $badge = "<span class='pill'>$Count</span>" }
    return "<section id='$Id'><details$o><summary><h2>$(E $Title)</h2>$badge</summary><div class='sbody'>$Body</div></details></section>"
}
$rcFlag  = { param($r) if ($r.Flags -match 'IOC') { 'bad' } elseif ($r.Flags) { 'warn' } }
$rcMatch = { param($r) if ($r.Match -eq $true) { 'bad' } }
$rcIoc   = { param($r) if ($r.IocIP -eq $true -or $r.IocHash -eq $true) { 'bad' } }

Invoke-Step "8. Формування HTML-звіту" {
    $sevOrder = @{ 'Критично' = 0; 'Високо' = 1; 'Середньо' = 2; 'Інфо' = 3 }
    $FlagsSorted = @($Flags | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Area)
    Save-Csv $FlagsSorted 'findings_auto.csv'
    Save-Csv $Integrity 'integrity_copies.csv'
    Save-Csv $StepLog 'collection_steps.csv'
    Save-Text ((@($Notes) -join [Environment]::NewLine)) 'collection_notes.txt'
    $cntSev = @{}; foreach ($k in $sevOrder.Keys) { $cntSev[$k] = @($FlagsSorted | Where-Object { $_.Severity -eq $k }).Count }

    # ── Прапорці ──
    $fl = New-Object System.Text.StringBuilder
    if ($FlagsSorted.Count -eq 0) { [void]$fl.Append("<p class='empty'>Автоматичних прапорців не виявлено.</p>") }
    else {
        [void]$fl.Append("<div class='tw'><div class='tbar'><input class='flt' placeholder='Фільтр…' oninput=""flt(this,'tflags')""></div><div class='scroll'><table id='tflags'><thead><tr><th>Рівень</th><th>Область</th><th>Знахідка</th><th>Доказ / контекст</th><th></th></tr></thead><tbody>")
        foreach ($f in $FlagsSorted) {
            [void]$fl.Append(("<tr><td><span class='sev s{0}'>{1}</span></td><td>{2}</td><td>{3}</td><td>{4}</td><td><a href='#{5}'>→</a></td></tr>" -f $sevOrder[$f.Severity], (E $f.Severity), (E $f.Area), (E $f.Finding), (E $f.Evidence), $f.Anchor))
        }
        [void]$fl.Append('</tbody></table></div></div>')
    }

    $verified = @($Integrity | Where-Object { $_.Status -like 'VERIFIED*' }).Count
    $cards = @(
        @('c', $cntSev['Критично'], 'Критичні прапорці'), @('h', $cntSev['Високо'], 'Високі прапорці'), @('m', $cntSev['Середньо'], 'Середні прапорці'),
        @('', @($D.Ev4625).Count, 'Невдалих входів (4625)'), @('', @($D.BruteForce | Where-Object { $_.Attempts -ge 10 }).Count, 'Серій brute-force (≥10)'),
        @('', @($D.SvcEvents | Where-Object { $_.EventId -ne 7040 }).Count, 'Встановлень служб'), @('', @($D.TaskEvents | Where-Object { $_.EventId -eq 4698 }).Count, 'Створено задач'),
        @('', @($D.FwEvents).Count, 'Змін правил firewall'), @('', @($D.IocHits).Count, 'IOC-збігів'),
        @('', @($D.WideHigh).Count, 'Цікавих файлів за масками'), @('', ("{0}/{1}" -f $verified, $Integrity.Count), 'Копій VERIFIED')
    )
    $cardsHtml = "<div class='cards'>" + ((@($cards | ForEach-Object { "<div class='card $($_[0])'><div class='n'>$(E $_[1])</div><div class='l'>$(E $_[2])</div></div>" })) -join '') + '</div>'

    # ── NIST-відповідність ──
    $nist = @(
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Спочатку волатильні дані (5.1.2)'; 'Як реалізовано' = 'Етап 1 (процеси, мережа, сесії, ARP, DNS, SMB) виконується до всіх інших'; 'Статус' = '✔' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Hash до і після копіювання (3.1.2, 4.2.1)'; 'Як реалізовано' = 'Copy-Evidence: hash джерела ДО → копія → hash копії → hash джерела ПІСЛЯ; таблиця нижче'; 'Статус' = '✔' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Аналіз на копіях (4.2.3)'; 'Як реалізовано' = 'Браузерні БД, Timeline, PS history, pfirewall.log аналізуються з копій; інші файли — лише читання (hash/метадані)'; 'Статус' = '✔ частково' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Write blocker на оригіналі (4.2.3)'; 'Як реалізовано' = 'Неможливо на живій системі. Компенсація: MAC-часи фіксуються ДО читання і перевіряються ПІСЛЯ; політика NTFS last-access задокументована'; 'Статус' = '✘ (компенсовано)' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Bit-stream образ'; 'Як реалізовано' = 'Поза межами скрипта. Для юридичного рівня — снапшот/образ VM до запуску'; 'Статус' = '✘ (рекомендація)' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Chain of custody (1, 3.1, чек-лист п.4)'; 'Як реалізовано' = 'chain_of_custody.log (онлайн) + .csv: кожна дія — seq, UTC, оператор, об''єкт, результат'; 'Статус' = '✔' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Фіксація інструмента'; 'Як реалізовано' = 'SHA256 скрипта + копія скрипта в 00_tool'; 'Статус' = '✔' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Час системи / таймзона (5.1.2)'; 'Як реалізовано' = 'Усі мітки в UTC і локальному часі; TZ і джерело NTP зафіксовані'; 'Статус' = '✔' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Кореляція кількох джерел (5.3, 8.3)'; 'Як реалізовано' = 'Єдиний timeline; кореляція 4625 ↔ pfirewall.log ↔ RDP'; 'Статус' = '✔' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Обережність з атрибуцією по IP (6.4.4)'; 'Як реалізовано' = 'IP подаються як "кандидати", атрибуція особи не робиться'; 'Статус' = '✔' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Документування рішень, що змінюють систему (3.1.1)'; 'Як реалізовано' = 'Скрипт нічого не змінює; -CollectHives (VSS) — явне рішення, фіксується в custody'; 'Статус' = '✔' }
        [pscustomobject]@{ 'Вимога NIST SP 800-86' = 'Цілісність результатів'; 'Як реалізовано' = 'manifest.csv (SHA256 кожного файлу) + hash маніфесту + ZIP із hash'; 'Статус' = '✔' }
    )
    $atime = @(@($D.KnownFiles) + @($D.WideHigh) | Where-Object { $_.AtimeChanged -eq $true })

    $S = New-Object System.Text.StringBuilder
    [void]$S.Append((Sec 'summary' '1. Огляд і автоматичні прапорці' ($cardsHtml + "<p class='muted'>Прапорці — підказки для аналітика, сформовані правилами скрипта. Висновки робить аналітик після перевірки кількох незалежних джерел (NIST 8.3).</p>" + $fl.ToString()) -Open -Count $FlagsSorted.Count))

    $b = (KV $D.SysInfo) + (H3 'Відповідність NIST SP 800-86') + (HT $nist) +
         (H3 'Верифікація копій доказів (hash до / копія / після)') + (HT $Integrity -Csv 'integrity_copies.csv' -RowClass { param($r) if ($r.Status -like 'VERIFIED*') { 'good' } elseif ($r.Status -like 'УВАГА*' -or $r.Status -like 'НЕ*') { 'bad' } else { 'info' } }) +
         (H3 'Файли, у яких змінився LastAccessTime після читання' 'Очікувано, якщо NTFS last-access увімкнено. Значення ДО читання збережено.') + (HT $atime -Cols @('Path', 'AccessedUtc_Before', 'AccessedUtc_After')) +
         (H3 'Обмеження та примітки збору') + $(if ($Notes.Count) { '<ul>' + ((@($Notes) | ForEach-Object { "<li>$(E $_)</li>" }) -join '') + '</ul>' } else { "<p class='empty'>Немає.</p>" }) +
         (H3 'Кроки збору') + (HT $StepLog -RowClass { param($r) if ($r.Status -ne 'OK') { 'bad' } })
    [void]$S.Append((Sec 'integrity' '2. Цілісність, методологія, обмеження (NIST)' $b))

    $b = (H3 'Процеси' 'Підсвічено: непідписані поза системними каталогами, нестандартні шляхи, IOC.') + (HT ($D.Procs | Sort-Object @{ Expression = { -not $_.Flags } }, Name) -Cols @('PID', 'PPID', 'ParentName', 'Name', 'Owner', 'StartUtc', 'Path', 'CommandLine', 'Signature', 'Location', 'SHA256', 'Flags') -RowClass $rcFlag -Csv '01_volatile\processes.csv') +
         (H3 "TCP-з'єднання") + (HT $D.Tcp -Cols @('State', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'PID', 'Process', 'Signature', 'RemoteIsPublic', 'IocIP', 'CreatedLocal') -RowClass $rcIoc -Csv '01_volatile\tcp_connections.csv') +
         (H3 'Сесії') + (Pre $D.SessionsText) +
         (H3 'ARP/NDP-сусіди' 'MAC-адреса допомагає ідентифікувати хост у тому ж L2-сегменті (напр. кандидата-джерело атаки).') + (HT $D.Arp -RowClass $rcIoc -Csv '01_volatile\arp_ndp_neighbors.csv') +
         (H3 'DNS-кеш (збіги з IOC підсвічено)') + (HT $D.Dns -RowClass $rcMatch -Csv '01_volatile\dns_cache.csv') +
         (H3 'UDP-точки') + (HT $D.Udp -Csv '01_volatile\udp_endpoints.csv') +
         (H3 'IP-адреси / маршрути') + (HT $D.IpAddr) + (HT $D.Routes) +
         (H3 'SMB') + (HT $D.SmbSess -Empty 'Немає SMB-сесій.') + (HT $D.SmbOpen -Empty 'Немає відкритих файлів.') + (HT $D.SmbShares)
    [void]$S.Append((Sec 'volatile' '3. Волатильні дані' $b -Count @($D.Procs).Count))

    $b = (H3 'Журнали подій: розмір, заповненість, глибина історії' 'Якщо вікно розслідування старше найстарішої події — частина доказів уже перезаписана: "не знайдено" ≠ "не було".') +
         (HT $D.LogHealth -Csv '02_system\eventlog_health.csv' -RowClass { param($r) if ($r.Severity -eq 'Високо') { 'bad' } elseif ($r.Severity -eq 'Середньо') { 'warn' } elseif ($r.Severity -eq 'OK') { 'good' } }) +
         (H3 'Налаштування аудиту та логування' 'Колонка Fix — готова команда/політика для виправлення.') +
         (HT $D.AuditSettings -Csv '02_system\audit_settings_check.csv' -RowClass { param($r) if ($r.OK -eq $false) { 'warn' } elseif ($r.OK -eq $true) { 'good' } }) +
         (H3 'Профілі користувачів') + (HT $D.Profiles) + (H3 'Локальні облікові записи') + (HT $D.LocalUsers) + (H3 'Адміністратори') + (HT $D.LocalAdmins) +
         (H3 'Політика облікових записів (net accounts)') + (Pre $D.NetAccounts) + (H3 'Audit policy (auditpol)') + (Pre $D.AuditPol)
    [void]$S.Append((Sec 'system' '4. Система, журнали, аудит, облікові записи' $b -Count @($D.LogHealth | Where-Object { $_.Severity -in 'Високо','Середньо' }).Count))
    $b = (H3 'Аудит конфігурації безпеки' 'Не «що сталося», а «наскільки хост вразливий». Колонка Fix — команда або політика для виправлення; Why — чим це загрожує.') +
         (HT $D.Hardening -Cols @('Status', 'Severity', 'Area', 'Check', 'Current', 'Recommended', 'Fix', 'Why') -Csv '02_system\security_config_audit.csv' -RowClass { param($r) if ($r.Status -eq 'Ризик' -and $r.Severity -eq 'Високо') { 'bad' } elseif ($r.Status -eq 'Ризик') { 'warn' } elseif ($r.Status -eq 'OK') { 'good' } }) +
         (H3 'Оригінальні журнали (.evtx)' 'Повний експорт (wevtutil epl) з SHA256 — для переаналізу Hayabusa / Chainsaw / EvtxECmd.') +
         (HT $D.EvtxExport -Csv '03_eventlogs\evtx_export.csv' -Empty 'Експорт .evtx не виконувався (-NoEvtx) або журнали відсутні.' -RowClass { param($r) if ($r.Status -like 'ПОМИЛКА*') { 'bad' } elseif ($r.Status -eq 'OK') { 'good' } })
    [void]$S.Append((Sec 'hardening' '4.1 Налаштування безпеки та оригінальні журнали' $b -Count @($D.Hardening | Where-Object { $_.Status -eq 'Ризик' }).Count))

    $b = (H3 'Зведення brute-force (4625)' 'Кількість — за локальним журналом Security (не лічильник rule.firedtimes Wazuh).') + (HT $D.BruteForce -Csv '03_eventlogs\bruteforce_summary.csv' -RowClass { param($r) if ($r.Attempts -ge 10) { 'bad' } }) +
         (H3 'Кореляція джерела: 4625 ↔ pfirewall.log ↔ RDP (±15 хв)' 'NIST 6.4.4: IP-адреса — кандидат, не доказ ідентичності.') + (HT $D.Correlation -Csv '03_eventlogs\bruteforce_source_correlation.csv' -RowClass $rcIoc) +
         (H3 'Очищення журналів') + (HT $D.LogCleared -Empty 'Подій очищення журналів не знайдено.' -RowClass { 'bad' }) +
         (H3 'Інші події автентифікації (4648/4740/4776, зміни облікових записів)') + (HT $D.OtherAuth -Csv '03_eventlogs\security_auth_other.csv' -RowClass { param($r) if ($r.EventId -in 4740, 4720, 4732) { 'warn' } }) +
         (H3 'Успішні входи користувачів (4624, типи 2/3/7/10/11)') + (HT $D.Ev4624 -Csv '03_eventlogs\security_4624_user_logons.csv' -RowClass { param($r) if ($r.LogonType -like '10*') { 'info' } }) +
         (H3 'Невдалі входи (4625) — сирі події') + (HT $D.Ev4625 -Csv '03_eventlogs\security_4625_failed_logons.csv')
    [void]$S.Append((Sec 'auth' '5. Автентифікація / brute-force' $b -Count @($D.Ev4625).Count))
    $rcSev = { param($r) if ($r.Severity -in 'Критично', 'Високо') { 'bad' } elseif ($r.Severity -eq 'Середньо') { 'warn' } }
    if ($D.IsDC) {
        $b = (H3 'Покриття аудиту для виявлення атак на AD' 'Якщо підкатегорія не аудитується — відповідних подій не буде навіть під час атаки.') +
             (HT $D.AdAudit -Csv '03_eventlogs\ad_audit_coverage.csv' -RowClass { param($r) if ($r.OK -eq $false) { 'bad' } elseif ($r.OK -eq $true) { 'good' } }) +
             (H3 'Ознаки атак (зведення)' 'Kerberoasting, AS-REP roasting, password spraying, DCSync, привілейовані групи, userAccountControl, ACL/RBCD/Shadow Credentials/GPO.') +
             (HT $D.AdFindings -Csv '03_eventlogs\ad_attack_findings.csv' -RowClass $rcSev -Empty 'Ознак атак на AD за вікно не знайдено (див. покриття аудиту вище).') +
             (H3 'Події-докази') + (HT $D.AdEvents -Csv '03_eventlogs\ad_attack_events.csv' -RowClass $rcSev -Empty 'Подій немає.') +
             (H3 'Конфігурація домену' 'LDAP, лише читання. Колонка Fix — що зробити; Why — чим це загрожує.') +
             (HT $D.AdConfig -Cols @('Status', 'Severity', 'Check', 'Current', 'Recommended', 'Fix', 'Why') -Csv '02_system\ad_config.csv' -RowClass { param($r) if ($r.Status -eq 'Ризик' -and $r.Severity -eq 'Високо') { 'bad' } elseif ($r.Status -eq 'Ризик') { 'warn' } elseif ($r.Status -eq 'OK') { 'good' } }) +
             (H3 'Ризикові та привілейовані облікові записи') + (HT $D.AdObjects -Csv '02_system\ad_risky_accounts.csv' -Empty 'Немає.')
    } else { $b = "<p class='empty'>Хост не є контролером домену — аудит Active Directory не виконувався.</p>" }
    [void]$S.Append((Sec 'ad' '5.1 Active Directory' $b -Count (@($D.AdFindings | Where-Object { $_.Severity -in 'Критично', 'Високо' }).Count + @($D.AdConfig | Where-Object { $_.Status -eq 'Ризик' }).Count)))

    $b = (H3 'Зведення за IP-джерелом') + (HT $D.RdpSummary -RowClass $rcIoc -Csv '03_eventlogs\rdp_by_source.csv') + (H3 'RDP-події') + (HT $D.Rdp -Csv '03_eventlogs\rdp_events.csv' -RowClass { param($r) if ($r.EventId -eq 140) { 'warn' } })
    [void]$S.Append((Sec 'rdp' '6. RDP' $b -Count @($D.Rdp).Count))

    $b = (H3 'Встановлення / зміни служб за вікно') + (HT $D.SvcEvents -Csv '03_eventlogs\service_install_events.csv' -RowClass { param($r) if ($r.Match) { 'bad' } elseif ($r.EventId -ne 7040) { 'warn' } }) +
         (H3 'Поточні служби з прапорцями (підпис / розташування / IOC)') + (HT ($D.Services | Where-Object { $_.Flags }) -Cols @('Name', 'DisplayName', 'State', 'StartMode', 'Account', 'Binary', 'Signature', 'Signer', 'Location', 'SHA256', 'Flags') -RowClass $rcFlag -Csv '02_system\services_flagged.csv') +
         (H3 'Auto, але не запущені') + (HT ($D.Services | Where-Object { $_.AutoNotRunning }) -Cols @('Name', 'DisplayName', 'State', 'Binary', 'Signature', 'Location'))
    [void]$S.Append((Sec 'services' '7. Служби' $b -Count @($D.SvcEvents).Count))

    $b = (H3 'Сторонні / підозрілі задачі (поточний стан)' 'Поле Author — безпосередньо з XML задачі (первинне джерело).') + (HT $D.Tasks -RowClass $rcFlag -Csv '02_system\scheduled_tasks_nonms_or_suspicious.csv') +
         (H3 'Події задач за вікно') + (HT $D.TaskEvents -Csv '03_eventlogs\task_events.csv' -RowClass { param($r) if ($r.Match) { 'bad' } elseif ($r.EventId -eq 4698) { 'warn' } })
    [void]$S.Append((Sec 'tasks' '8. Задачі планувальника' $b -Count @($D.Tasks).Count))

    $b = (H3 'Run / Winlogon / IFEO / Startup') + (HT $D.Autoruns -Csv '02_system\autoruns.csv' -RowClass { param($r) if ($r.Match -or $r.PathClass -in @('Нестандартний', 'Користувацький/тимчасовий', 'НЕСТАНДАРТНЕ значення')) { 'warn' } }) +
         (H3 'WMI-підписки (root\subscription)') + (HT $D.WmiPersist -Empty 'WMI-підписок не знайдено.' -RowClass { param($r) if (-not $r.LikelyBenign) { 'bad' } })
    [void]$S.Append((Sec 'persist' '9. Персистентність' $b -Count @($D.Autoruns).Count))

    $b = (H3 'Профілі та логування') + (HT $D.FwProfiles) +
         (H3 'Зміни правил за вікно' "Категорія 'Windows / служба' — зміни від svchost/mpssvc (як правило, автоматичні).") + (HT $D.FwEvents -Csv '03_eventlogs\firewall_rule_change_events.csv' -RowClass { param($r) if ($r.Match) { 'bad' } elseif ($r.Category -notlike 'Windows*') { 'warn' } }) +
         (H3 ("pfirewall.log: джерела ({0} записів у вікні)" -f $D.FwLinesInWindow) 'Спершу — джерела з евристиками (ICMP-розвідка, RDP/SMB, DROP, сканування, IOC).') + (HT $D.FwBySource -Csv '04_firewall\fw_log_by_source.csv' -RowClass { param($r) if ($r.Heuristic -match 'IOC') { 'bad' } elseif ($r.Heuristic) { 'warn' } }) +
         (H3 'pfirewall.log: порти') + (HT $D.FwByPort -Csv '04_firewall\fw_log_by_port.csv') +
         (H3 'pfirewall.log: сирі записи з IOC IP') + (HT $D.FwIocRaw -Csv '04_firewall\fw_log_ioc_raw.csv') +
         (H3 'Активні правила з прапорцями') + (HT ($D.FwRules | Where-Object { $_.Flags }) -RowClass $rcFlag -Empty 'Немає.') +
         (H3 'Усі активні правила') + (HT $D.FwRules -Csv '04_firewall\fw_rules_enabled.csv')
    [void]$S.Append((Sec 'firewall' '10. Firewall' $b -Count @($D.FwEvents).Count))

    $b = (H3 'Стан захисту') + (HT $D.MpStatusRows -RowClass { param($r) if ($r.Setting -eq 'RealTimeProtectionEnabled' -and $r.Value -eq 'False') { 'bad' } }) +
         (H3 'Винятки') + (HT $D.MpExclusions -Empty 'Винятків не знайдено.' -RowClass { 'bad' }) + (H3 'Події Defender') + (HT $D.MpEvents -Csv '03_eventlogs\defender_events.csv' -RowClass { param($r) if ($r.EventId -in 5001, 1116, 1117 -or $r.Exclusion) { 'bad' } else { 'warn' } })
    [void]$S.Append((Sec 'defender' '11. Microsoft Defender' $b -Count @($D.MpExclusions).Count))

    $b = (H3 'Продукти з ключем' 'EstLastKmsActivationUtc — оцінка: KMS-активація дійсна 180 діб, час = зараз − (180 діб − залишок).') + (HT $D.Licensing -Csv '02_system\licensing_products.csv') +
         (H3 'Налаштування KMS у реєстрі') + (HT $D.KmsReg -Empty 'KMS-хост у реєстрі не задано.')
    [void]$S.Append((Sec 'kms' '12. Ліцензування / KMS' $b -Count @($D.Licensing).Count))

    $b = (H3 'Запуски LOLBin / з IOC (Sysmon 1, 4688)') + (HT $D.Exec -Csv '03_eventlogs\process_exec_lolbin_ioc.csv' -RowClass { param($r) if ($r.Reason -match 'IOC|Підозрілі') { 'bad' } }) +
         (H3 'Sysmon 11/13/3 за IOC') + (HT $D.SysmonMisc -Csv '03_eventlogs\sysmon_file_reg_net_ioc.csv') + (H3 'PowerShell 4104') + (HT $D.Ps4104 -Csv '03_eventlogs\powershell_4104_suspicious.csv')
    [void]$S.Append((Sec 'exec' '13. Виконання процесів і скриптів' $b -Count @($D.Exec).Count))

    $b = (H3 'IOC-збіги') + (HT $D.IocHits -Csv 'ioc_hits.csv' -RowClass { 'bad' } -Empty 'IOC-збігів не знайдено.')
    [void]$S.Append((Sec 'ioc' '14. IOC-збіги' $b -Count @($D.IocHits).Count))

    $b = (H3 'Відомі шляхи IOC') + (HT $D.KnownFiles -Cols @('Origin', 'Path', 'Exists', 'SizeBytes', 'CreatedUtc', 'ModifiedUtc', 'AccessedUtc_Before', 'AtimeChanged', 'SHA256', 'Signature', 'Signer', 'ZoneId', 'HostUrl', 'IocHash', 'Note') -RowClass { param($r) if ($r.IocHash) { 'bad' } elseif ($r.Exists) { 'warn' } } -Csv '05_artifacts\known_paths.csv') +
         (H3 ("Цікаві збіги за масками ({0} файлів переглянуто)" -f $D.WideScanned) 'Виконувані/архіви/конфіги поза системними каталогами — з hash і Zone.Identifier.') + (HT $D.WideHigh -Cols @('Path', 'SizeBytes', 'CreatedUtc', 'ModifiedUtc', 'SHA256', 'Signature', 'ZoneId', 'HostUrl', 'PathClass', 'IocHash') -RowClass $rcIoc -Csv '05_artifacts\pattern_hits_interesting.csv') +
         (H3 'Папки за масками') + (HT $D.WideDirs) +
         (H3 'LNK (Recent/Desktop)') + (HT $D.Lnk -RowClass $rcMatch -Csv '05_artifacts\lnk_recent_desktop.csv') +
         (H3 'BAM/DAM') + (HT $D.Bam -RowClass $rcMatch -Csv '05_artifacts\bam_dam.csv' -Empty 'Записів BAM/DAM немає (див. примітки).') +
         (H3 ("Prefetch — {0}; усього .pf: {1}" -f $D.PrefetchState, $D.PrefetchTotal)) + (HT $D.Prefetch -Empty 'Збігів у Prefetch немає.') +
         (H3 'Кошик ($I)') + (HT $D.Recycle -RowClass $rcMatch -Csv '05_artifacts\recycle_bin.csv' -Empty 'Кошик порожній.') +
         (H3 'Zone.Identifier (Mark of the Web)') + (HT $D.Zone -RowClass $rcMatch -Csv '05_artifacts\zone_identifier.csv') +
         (H3 'Підказки з копій історії браузерів / Windows Timeline' 'Пошук рядків (URL/шляхи з ключовими словами) без SQLite — без часових міток.') + (HT $D.Hints -Csv '05_artifacts\evidence_string_hints.csv') +
         (H3 'PowerShell history — підозрілі команди') + (HT $D.PsHist -Csv '05_artifacts\powershell_history_hits.csv') +
         (H3 'Збіги низького інтересу (ймовірний шум)') + (HT $D.WideLow -Csv '05_artifacts\pattern_hits_low_interest.csv')
    [void]$S.Append((Sec 'files' '15. Файлові артефакти' $b -Count (@($D.KnownFiles).Count + @($D.WideHigh).Count)))

    $tlView = @($D.TimelineSorted | Where-Object { $_.Mark -ne 'detail' })
    $b = "<p class='muted'>Окремі події 4625 згорнуто в серії (повний перелік — timeline_full.csv). Файлові мітки часу можуть бути поза вікном журналів — це контекст (напр. дата першої появи файлу).</p>" +
         (HT $tlView -Cols @('TimeUtc', 'TimeLocal', 'Source', 'Event', 'Summary', 'Actor') -RowClass { param($r) $r.Mark } -Csv 'timeline_full.csv')
    [void]$S.Append((Sec 'timeline' '16. Timeline (UTC)' $b -Open -Count $tlView.Count))

    Add-Custody 'REPORT_BUILD' 'report.html' 'OK' ''
    [void]$S.Append((Sec 'custody' '17. Chain of custody' ((HT $Custody -Csv 'chain_of_custody.csv')) -Count $Custody.Count))

    $css = @'
*{box-sizing:border-box}body{margin:0;font-family:"Segoe UI",Roboto,Arial,sans-serif;background:#f4f6f9;color:#1b1f24;font-size:14px}
header{background:linear-gradient(135deg,#14264a,#2f5496);color:#fff;padding:22px 28px}header h1{margin:0 0 4px;font-size:23px}header .sub{opacity:.85}
.meta{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}.meta div{background:rgba(255,255,255,.12);padding:6px 12px;border-radius:8px;font-size:12.5px}
.meta b{display:block;font-size:10.5px;opacity:.75;text-transform:uppercase;letter-spacing:.04em}
.layout{display:flex;align-items:flex-start}nav{position:sticky;top:0;width:240px;min-width:240px;height:100vh;overflow:auto;background:#fff;border-right:1px solid #e1e5eb;padding:14px 10px}
nav a{display:block;padding:6px 10px;color:#1f3864;text-decoration:none;border-radius:6px;font-size:13px}nav a:hover{background:#eef2f8}
main{flex:1;padding:18px 26px 60px;min-width:0}.banner{background:#fff7e6;border-left:5px solid #b45309;padding:12px 16px;border-radius:6px;margin:0 0 16px;line-height:1.5}
.cards{display:-webkit-flex;display:flex;-webkit-flex-wrap:wrap;flex-wrap:wrap;margin:6px -5px 14px}
.card{-webkit-flex:1 1 150px;flex:1 1 150px;margin:5px;min-width:150px;background:#fff;border-radius:10px;padding:12px 14px;box-shadow:0 1px 3px rgba(0,0,0,.07);border-top:4px solid #2f5496}
.card .n{font-size:23px;font-weight:700;color:#1f3864}.card .l{font-size:12px;color:#5b6470}.card.c{border-top-color:#7f0000}.card.h{border-top-color:#c62828}.card.m{border-top-color:#b45309}
section{margin:14px 0}details{background:#fff;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
summary{cursor:pointer;padding:12px 16px;list-style:none;display:flex;align-items:center;gap:8px}summary::-webkit-details-marker{display:none}
summary h2{display:inline;font-size:17px;color:#1f3864;margin:0}summary:before{content:"▸";color:#2f5496}details[open]>summary:before{content:"▾"}
.sbody{padding:4px 16px 16px}h3{color:#2f5496;font-size:14.5px;margin:20px 0 6px;border-bottom:1px solid #e1e5eb;padding-bottom:4px}
.tw{margin:6px 0 10px}.tbar{display:flex;gap:10px;align-items:center;margin-bottom:4px}.flt{padding:5px 9px;border:1px solid #cfd6e0;border-radius:6px;width:260px;font-size:12.5px}
.cnt{color:#6b7480;font-size:12px}.scroll{overflow:auto;max-height:560px;border:1px solid #e1e5eb;border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:12.5px;background:#fff}th{position:sticky;top:0;background:#1f3864;color:#fff;text-align:left;padding:7px 9px;font-weight:600;cursor:pointer;white-space:nowrap}
td{padding:6px 9px;border-bottom:1px solid #e1e5eb;vertical-align:top;word-break:break-word;max-width:560px}tr:nth-child(even) td{background:#fafbfd}
tr.bad td{background:#fde8e8}tr.warn td{background:#fff4e0}tr.good td{background:#eef8ee}tr.info td{background:#eef3fb}
.sev{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}.s0{background:#7f0000}.s1{background:#c62828}.s2{background:#b45309}.s3{background:#2f5496}
pre{background:#0f1720;color:#dfe6ee;padding:12px;border-radius:8px;overflow:auto;max-height:420px;font-size:12px;white-space:pre-wrap}
.empty{color:#7a838f;font-style:italic}.muted{color:#6b7480;font-size:12px;margin:4px 0}.kv td:first-child{font-weight:600;color:#44505e;width:300px;background:#f7f9fc}
code{background:#eef1f5;padding:1px 5px;border-radius:4px;font-size:11.5px}.pill{display:inline-block;background:#eef2f8;color:#1f3864;border-radius:999px;padding:1px 9px;font-size:11px}
footer{color:#7a838f;font-size:12px;text-align:center;padding:20px}@media print{nav{display:none}.scroll{max-height:none}}
'@
    $js = @'
function flt(inp,id){var q=inp.value.toLowerCase();var rows=document.getElementById(id).tBodies[0].rows;for(var i=0;i<rows.length;i++){rows[i].style.display=rows[i].innerText.toLowerCase().indexOf(q)>-1?'':'none';}}
function srt(th){var t=th.closest('table'),i=Array.prototype.indexOf.call(th.parentNode.children,th),b=t.tBodies[0],r=Array.prototype.slice.call(b.rows);var d=th.getAttribute('data-d')==='a'?'d':'a';th.setAttribute('data-d',d);
r.sort(function(x,y){var a=x.cells[i].innerText,c=y.cells[i].innerText,na=parseFloat(a),nc=parseFloat(c);var v=(/^-?[\d.]+$/.test(a)&&/^-?[\d.]+$/.test(c))?na-nc:a.localeCompare(c);return d==='a'?v:-v;});r.forEach(function(x){b.appendChild(x);});}
'@
    $navItems = @(@('summary', 'Огляд і прапорці'), @('integrity', 'Цілісність / NIST'), @('volatile', 'Волатильні дані'), @('system', 'Система'), @('hardening', 'Налаштування безпеки'), @('auth', 'Автентифікація'), @('ad', 'Active Directory'),
                  @('rdp', 'RDP'), @('services', 'Служби'), @('tasks', 'Задачі'), @('persist', 'Персистентність'), @('firewall', 'Firewall'), @('defender', 'Defender'),
                  @('kms', 'Ліцензування / KMS'), @('exec', 'Виконання'), @('ioc', 'IOC-збіги'), @('files', 'Файлові артефакти'), @('timeline', 'Timeline'), @('custody', 'Chain of custody'))
    $nav = (@($navItems | ForEach-Object { "<a href='#$($_[0])'>$(E $_[1])</a>" }) -join '')
    $banner = "<div class='banner'><b>Live response (NIST SP 800-86).</b> Дані зібрано з працюючої системи без write blocker. Скрипт нічого не змінює й не видаляє; MAC-часи фіксуються до читання, копії доказів верифіковано hash до/після. " +
              "NTFS last-access: <b>$(E $D.LastAccess)</b>. Prefetch: <b>$(E $D.PrefetchState)</b>. Для доказів юридичного рівня використовуйте образ/снапшот VM.</div>"
    $html = "<!DOCTYPE html><html lang='uk'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>SOC Live Response — $(E $CaseId) — $(E $HostName)</title><style>$css</style></head><body>" +
            "<header><h1>SOC Live Response — $(E $CaseId)</h1><div class='sub'>$(E $ToolName) v$ToolVersion · збір і первинний аналіз доказів відповідно до NIST SP 800-86</div><div class='meta'>" +
            "<div><b>Хост</b>$(E $HostName)</div><div><b>Оператор</b>$(E $Operator)</div><div><b>Вікно журналів (UTC)</b>$(E (U $Since)) → $(E (U $Until))</div>" +
            "<div><b>Старт збору (UTC)</b>$(E (U $RunStart))</div><div><b>SHA256 інструмента</b>$(E $D.ToolSHA256)</div><div><b>Критично / Високо</b>$($cntSev['Критично']) / $($cntSev['Високо'])</div></div></header>" +
            "<div class='layout'><nav>$nav</nav><main>$banner$($S.ToString())<footer>Згенеровано $(E (U (Get-Date))) · цілісність усіх файлів справи — manifest.csv / manifest.csv.sha256</footer></main></div><script>$js</script></body></html>"
    $D.ReportPath = Join-Path $CaseDir 'report.html'
    [IO.File]::WriteAllText($D.ReportPath, $html, (New-Object Text.UTF8Encoding($true)))
}

# ════════════════════════════════════ 9. CHAIN OF CUSTODY, МАНІФЕСТ, АРХІВ ════════════════════════════════════
Add-Custody 'FINISH_COLLECTION' $CaseDir 'OK' 'Далі — маніфест SHA256; після нього файли справи не змінюються'
$Custody | Export-Csv -LiteralPath (Join-Path $CaseDir 'chain_of_custody.csv') -NoTypeInformation -Encoding UTF8

Write-Host ("[{0}] 9. Маніфест SHA256 усіх файлів справи" -f (Get-Date -Format 'HH:mm:ss')) -ForegroundColor Cyan
$manPath = Join-Path $CaseDir 'manifest.csv'
$man = foreach ($f in @(Get-ChildItem -LiteralPath $CaseDir -Recurse -File -Force | Where-Object { $_.FullName -ne $manPath })) {
    [pscustomobject]@{ RelativePath = $f.FullName.Substring($CaseDir.Length + 1); SizeBytes = $f.Length; SHA256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash; ModifiedUtc = (U $f.LastWriteTimeUtc) }
}
$man | Export-Csv -LiteralPath $manPath -NoTypeInformation -Encoding UTF8
$manHash = (Get-FileHash -LiteralPath $manPath -Algorithm SHA256).Hash
[IO.File]::WriteAllText((Join-Path $CaseDir 'manifest.csv.sha256'), "$manHash  manifest.csv`r`n", (New-Object Text.UTF8Encoding($false)))

$zipPath = ''; $zipHash = ''
if (-not $NoZip) {
    Write-Host ("[{0}] 10. Архів справи" -f (Get-Date -Format 'HH:mm:ss')) -ForegroundColor Cyan
    try {
        $zipPath = "$CaseDir.zip"
        Compress-Archive -LiteralPath $CaseDir -DestinationPath $zipPath -CompressionLevel Optimal -Force -ErrorAction Stop
        $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
        [IO.File]::WriteAllText("$zipPath.sha256", "$zipHash  $(Split-Path $zipPath -Leaf)`r`n", (New-Object Text.UTF8Encoding($false)))
    } catch { Write-Host "    ! ZIP не створено: $($_.Exception.Message)" -ForegroundColor Yellow; $zipPath = '' }
}

$sevOrder2 = @{ 'Критично' = 0; 'Високо' = 1; 'Середньо' = 2; 'Інфо' = 3 }
Write-Host ""
Write-Host "═══════════════════════════ ГОТОВО ═══════════════════════════" -ForegroundColor Green
Write-Host ("Звіт:        {0}" -f $D.ReportPath)
Write-Host ("Папка:       {0}" -f $CaseDir)
Write-Host ("Маніфест:    SHA256 {0}" -f $manHash)
if ($zipPath) { Write-Host ("Архів:       {0}" -f $zipPath); Write-Host ("             SHA256 {0}" -f $zipHash) }
Write-Host ("Прапорці:    Критично {0} | Високо {1} | Середньо {2} | Інфо {3}" -f @($Flags | Where-Object { $_.Severity -eq 'Критично' }).Count, @($Flags | Where-Object { $_.Severity -eq 'Високо' }).Count, @($Flags | Where-Object { $_.Severity -eq 'Середньо' }).Count, @($Flags | Where-Object { $_.Severity -eq 'Інфо' }).Count)
$errs = @($StepLog | Where-Object { $_.Status -ne 'OK' })
if ($errs.Count) { Write-Host ("Кроки з помилками: {0} (див. розділ 'Цілісність' у звіті)" -f $errs.Count) -ForegroundColor Yellow }
Write-Host "Зафіксуйте SHA256 маніфесту/архіву в тікеті — це точка контролю цілісності (chain of custody)." -ForegroundColor Gray
