<#
.SYNOPSIS
    Unit-тести soc-collect.ps1 без зовнішніх модулів (Pester не потрібен).
    Функції беруться з самого скрипта через AST — скрипт при цьому НЕ запускається.
    Працює у Windows PowerShell 5.1 і PowerShell 7 (Windows / Linux). Код виходу: 0 — усі тести пройдено, 1 — є помилки.
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\tests\run-tests.ps1
#>
param([string]$Script = (Join-Path (Split-Path -Parent $PSScriptRoot) 'soc-collect.ps1'))

$ErrorActionPreference = 'Stop'
$script:Fail = 0; $script:Pass = 0
function Assert-True {
    param([string]$Name, $Condition)
    if ($Condition) { $script:Pass++ } else { $script:Fail++; Write-Host "FAIL  $Name" -ForegroundColor Red }
}
function Test-Group { param([string]$Name) Write-Host "--- $Name" -ForegroundColor Cyan }

$Script = (Resolve-Path $Script).Path
$srcText = [IO.File]::ReadAllText($Script).Replace("`r`n", "`n")
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Script, [ref]$tokens, [ref]$errors)

Test-Group 'Синтаксис'
Assert-True 'скрипт парситься без помилок' ($errors.Count -eq 0)

# Усі функції скрипта (включно з вкладеними у кроки) — у поточну область видимості
$fnAsts = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
foreach ($f in $fnAsts) { . ([scriptblock]::Create($f.Extent.Text)) }

# Верхньорівневі присвоєння, потрібні функціям
$wantVars = 'Lolbins', 'TaskInterpreters', 'KnownFolderGuids', 'AdReplGuids', 'AdUacCodes', 'AdPrivGroupRx', 'NtStatus', 'LogonTypes'
foreach ($a in @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] })) {
    $left = $a.Left
    if ($left -is [System.Management.Automation.Language.VariableExpressionAst] -and $wantVars -contains $left.VariablePath.UserPath) { . ([scriptblock]::Create($a.Extent.Text)) }
}
function Get-SourceText {   # фрагмент скрипта між двома маркерами
    param([string]$StartMarker, [string]$EndMarker)
    $i = $srcText.IndexOf($StartMarker); if ($i -lt 0) { throw "Маркер не знайдено: $StartMarker" }
    $j = $srcText.IndexOf($EndMarker, $i + 1); if ($j -lt 0) { throw "Маркер не знайдено: $EndMarker" }
    return $srcText.Substring($i, $j - $i)
}
function Invoke-SourceBlock { param([string]$StartMarker, [string]$EndMarker) return [scriptblock]::Create((Get-SourceText $StartMarker $EndMarker)) }

$origSystemRoot = $env:SystemRoot
if (-not $env:SystemRoot) { $env:SystemRoot = 'C:\Windows' }
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("soc-tests-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    Test-Group 'Імена функцій не збігаються з вбудованими алиасами'
    $aliasNames = @(Get-Alias | ForEach-Object { $_.Name })
    # алиаси Windows PowerShell 5.1, яких немає в pwsh на Linux
    $aliasNames += 'ft', 'fl', 'fw', 'gwmi', 'iwmi', 'rwmi', 'swmi', 'sc', 'sort', 'kill', 'ps', 'cat', 'ls', 'cp', 'mv', 'rm', 'curl', 'wget', 'diff', 'man', 'mount', 'tee', 'write', 'type', 'start', 'sleep', 'h', 'r'
    foreach ($n in @($fnAsts | ForEach-Object { $_.Name } | Select-Object -Unique)) { Assert-True "функція '$n' не є алиасом" (-not ($aliasNames -contains $n)) }

    Test-Group 'IOC IP: межі адреси'
    $IocIPs = @('192.168.77.51', 'fe80::1a2b:3c4d:5e6f:7a8b', '10.9.0.20')
    . (Invoke-SourceBlock '# IOC IP: множина' '$Keywords = @(')
    Assert-True 'точний IP у тексті'       (Test-IocIP 'connect to 10.9.0.20:445')
    Assert-True 'не 110.9.0.20'            (-not (Test-IocIP '110.9.0.20'))
    Assert-True 'не 10.9.0.200'            (-not (Test-IocIP '10.9.0.200'))
    Assert-True 'не 10.9.0.20.1'           (-not (Test-IocIP '10.9.0.20.1'))
    Assert-True 'кінець речення'           (Test-IocIP 'host 10.9.0.20.')
    Assert-True 'IPv6 із zone id'          (Test-IocIP 'fe80::1a2b:AB57:7f11:5b01%12')
    Assert-True 'не довша IPv6'            (-not (Test-IocIP 'fe80::1a2b:3c4d:5e6f:7a8b:1'))
    Assert-True 'Eq: [IPv6%zone]'          (Test-IocIPEq '[FE80::105:ab57:7f11:5b01%3]')
    Assert-True 'Eq: точний IPv4'          (Test-IocIPEq '192.168.77.51')
    Assert-True 'Eq: не 192.168.77.5'      (-not (Test-IocIPEq '192.168.77.5'))
    Assert-True 'Split-ListParam "a, b,c"' ((Split-ListParam @('a, b,c')).Count -eq 3)

    Test-Group 'Задачі під \Microsoft\'
    $BinCache = @{}; $Keywords = @('KMS', 'SECOPatcher'); $IocSha256 = @(); $D = @{ ProfileRoots = @() }
    $sys32 = $env:SystemRoot.TrimEnd('\') + '\System32'   # рядок, не шлях: на Linux диска C: немає
    Assert-True 'штатна (rundll32, автор $(@...))' (-not (Get-MsTaskSuspicion ($sys32 + '\rundll32.exe') 'rundll32.exe x.dll,Run' '$(@%SystemRoot%\system32\x.dll,-1)'))
    Assert-True 'powershell -enc'          ((Get-MsTaskSuspicion 'powershell.exe' 'powershell.exe -enc AAAA' 'Microsoft Corporation') -match 'Підозрілі')
    Assert-True 'інтерпретатор + чужий автор' ((Get-MsTaskSuspicion 'cmd.exe' 'cmd.exe /c x' 'DESKTOP\bob') -match 'інтерпретатор')
    Assert-True 'дія з профілю користувача' ((Get-MsTaskSuspicion 'C:\Users\bob\AppData\x.exe' 'x.exe' 'Microsoft') -match 'дія')
    Assert-True 'actor SYSTEM — штатно'    (-not (Get-MsTaskSuspicion '' '' 'Microsoft' 'NT AUTHORITY\SYSTEM'))
    Assert-True 'actor PC$ — штатно'       (-not (Get-MsTaskSuspicion '' '' 'Microsoft' 'WORKGROUP\PC1$'))
    Assert-True 'actor користувач'         ((Get-MsTaskSuspicion '' '' 'Microsoft' 'DESKTOP\bob') -match 'користувачем')

    Test-Group 'Resolve-BareExe / Get-ExeFromCmd'
    $fakeRoot = Join-Path $tmp 'win'; $fakeSys = Join-Path $fakeRoot 'System32'
    New-Item -ItemType Directory -Force -Path $fakeSys | Out-Null
    $scExe = Join-Path $fakeSys 'sc.exe'; Set-Content -LiteralPath $scExe -Value 'x'
    $saveRoot = $env:SystemRoot; $env:SystemRoot = $fakeRoot
    try {
        Assert-True 'sc.exe -> System32'   ((Resolve-BareExe 'sc.exe') -eq $scExe)
        Assert-True 'sc -> sc.exe'         ((Resolve-BareExe 'sc') -eq $scExe)
        Assert-True 'невідоме — без змін'  ((Resolve-BareExe 'BthUdTask.exe') -eq 'BthUdTask.exe')
        Assert-True 'шлях — без змін'      ((Resolve-BareExe 'C:\x\sc.exe') -eq 'C:\x\sc.exe')
        Assert-True 'команда з голим імʼям' ((Get-ExeFromCmd 'sc.exe config upnphost start= auto') -eq $scExe)
        Assert-True 'команда в лапках'     ((Get-ExeFromCmd '"C:\P F\a.exe" -x') -eq 'C:\P F\a.exe')
    } finally { $env:SystemRoot = $saveRoot }

    Test-Group 'Hash файлів, відкритих іншим процесом'
    $lf = Join-Path $tmp 'locked.log'; Set-Content -LiteralPath $lf -Value 'hello'
    $w = [IO.File]::Open($lf, 'Open', 'ReadWrite', 'Read'); try { $h1 = Get-SharedHash $lf } finally { $w.Close() }
    Assert-True 'Get-SharedHash = Get-FileHash' ($h1 -eq (Get-FileHash -LiteralPath $lf).Hash)
    $w = [IO.File]::Open($lf, 'Open', 'ReadWrite', 'ReadWrite'); try { $h2 = Get-SourceHash $lf } finally { $w.Close() }
    Assert-True 'Get-SourceHash під записом' ($h2 -eq (Get-FileHash -LiteralPath $lf).Hash)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    Assert-True 'дедуп шляхів без урахування регістру' (@('C:\Windows\system32\x.log', 'C:\Windows\System32\x.log' | Where-Object { $seen.Add($_) }).Count -eq 1)

    Test-Group 'Get-StringHints: читання блоками'
    $db = Join-Path $tmp 'db.bin'
    $rnd = New-Object byte[] (4MB - 37); (New-Object Random 1).NextBytes($rnd)
    $u16 = [Text.Encoding]::Unicode.GetBytes('https://evil.example/KMSAuto.rar ')
    $u8 = [Text.Encoding]::UTF8.GetBytes(' C:\Windows\KMSAutoS\KMSSS.exe ')
    $fs = [IO.File]::Create($db); try { $fs.Write($rnd, 0, $rnd.Length); $fs.WriteByte(0); $fs.Write($u16, 0, $u16.Length); $fs.Write($rnd, 0, 4MB - 37); $fs.Write($u8, 0, $u8.Length) } finally { $fs.Close() }
    $hints = (@(Get-StringHints $db) -join '|')
    Assert-True 'UTF-16 через межу блоку' ($hints -match 'evil\.example/KMSAuto\.rar')
    Assert-True 'UTF-8 у другому блоці'   ($hints -match 'KMSSS\.exe')

    Test-Group 'auditpol /r (EN / RU / UA, 6 і 7 колонок)'
    $en = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value', 'DC01,System,Kerberos Service Ticket Operations,{0CCE9240-69AE-11D9-BED3-505054503030},Success and Failure,,3')
    $ru7 = @('Имя компьютера,Цель политики,Подкатегория,GUID подкатегории,Параметр включения,Параметр исключения,Значение параметра', 'DC01,Система,Операции с билетами службы Kerberos,{0CCE9240-69AE-11D9-BED3-505054503030},Успех,,1')
    $ru6 = @('Имя компьютера,цель политики,подкатегория,GUID подкатегории,параметр включения,параметр исключения', 'DC01,Система,Операции с билетами службы Kerberos,{0CCE9240-69AE-11D9-BED3-505054503030},Успех и сбой,')
    $ru6no = @('Имя компьютера,цель политики,подкатегория,GUID подкатегории,параметр включения,параметр исключения', 'DC01,Система,Доступ к службе каталогов,{0CCE923B-69AE-11D9-BED3-505054503030},Без аудита,')
    Assert-True 'EN = 3'                  ((ConvertFrom-AuditpolCsv $en).Value -eq 3)
    Assert-True 'RU 7 колонок = 1'        ((ConvertFrom-AuditpolCsv $ru7).Value -eq 1)
    Assert-True 'RU 6 колонок «Успех и сбой» = 3' ((ConvertFrom-AuditpolCsv $ru6).Value -eq 3)
    Assert-True 'RU «Без аудита» = 0'     ((ConvertFrom-AuditpolCsv $ru6no).Value -eq 0)
    Assert-True 'UA «Без аудиту» = 0'     ((ConvertFrom-AuditpolCsv @('a,b,c,d,e,f', 'x,y,z,w,Без аудиту,')).Value -eq 0)
    Assert-True 'помилка auditpol -> невідомо' ($null -eq (ConvertFrom-AuditpolCsv @('Ошибка 0x00000057 произошла:', 'Параметр задан неверно.')).Value)
    Assert-True 'порожньо -> невідомо'    ($null -eq (ConvertFrom-AuditpolCsv @()).Value)

    Test-Group 'Сліди запуску: ROT13, UserAssist, ShimCache (синтетичні байти)'
    Assert-True 'ROT13'                   ((ConvertFrom-Rot13 'P:\Jvaqbjf\abgrcnq.rkr') -eq 'C:\Windows\notepad.exe')
    Assert-True 'ROT13 двічі = оригінал'  ((ConvertFrom-Rot13 (ConvertFrom-Rot13 'Evil_Test.EXE 123')) -eq 'Evil_Test.EXE 123')
    Assert-True 'KNOWNFOLDER System32'    ((Resolve-KnownFolderPath '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe') -eq '%SystemRoot%\System32\cmd.exe')
    Assert-True 'KNOWNFOLDER невідомий — без змін' ((Resolve-KnownFolderPath '{00000000-0000-0000-0000-000000000000}\x.exe') -eq '{00000000-0000-0000-0000-000000000000}\x.exe')
    $when = [DateTime]::new(2026, 9, 20, 10, 30, 0, [DateTimeKind]::Utc)
    $ua72 = New-Object byte[] 72
    [BitConverter]::GetBytes([int32]7).CopyTo($ua72, 4); [BitConverter]::GetBytes([int32]3).CopyTo($ua72, 8)
    [BitConverter]::GetBytes([uint32]65000).CopyTo($ua72, 12); [BitConverter]::GetBytes($when.ToFileTimeUtc()).CopyTo($ua72, 60)
    $u = ConvertFrom-UserAssistData $ua72
    Assert-True 'UserAssist 72 байти: запуски' ($u.RunCount -eq 7 -and $u.FocusCount -eq 3 -and $u.FocusSeconds -eq 65)
    Assert-True 'UserAssist 72 байти: час'     ($u.LastRunUtc -eq $when)
    $ua16 = New-Object byte[] 16
    [BitConverter]::GetBytes([int32]9).CopyTo($ua16, 4); [BitConverter]::GetBytes($when.ToFileTimeUtc()).CopyTo($ua16, 8)
    $u = ConvertFrom-UserAssistData $ua16
    Assert-True 'UserAssist 16 байт (XP): лічильник −5' ($u.RunCount -eq 4 -and $u.LastRunUtc -eq $when)
    Assert-True 'UserAssist порожнє значення' ($null -eq (ConvertFrom-UserAssistData @()).LastRunUtc)
    function New-ShimEntry { param([string]$Path, [datetime]$Mod)
        $pb = [Text.Encoding]::Unicode.GetBytes($Path); $data = [byte[]](1, 2, 3)
        $body = New-Object System.Collections.Generic.List[byte]
        $body.AddRange([BitConverter]::GetBytes([uint16]$pb.Length)); $body.AddRange($pb); $body.AddRange([BitConverter]::GetBytes($Mod.ToFileTimeUtc()))
        $body.AddRange([BitConverter]::GetBytes([uint32]$data.Length)); $body.AddRange($data)
        $e = New-Object System.Collections.Generic.List[byte]
        $e.AddRange([Text.Encoding]::ASCII.GetBytes('10ts')); $e.AddRange([BitConverter]::GetBytes([uint32]0x12345678)); $e.AddRange([BitConverter]::GetBytes([uint32]$body.Count)); $e.AddRange($body)
        return ,$e.ToArray() }
    foreach ($hdr in 0x30, 0x34) {
        $blob = New-Object System.Collections.Generic.List[byte]
        $h = New-Object byte[] $hdr; [BitConverter]::GetBytes([int32]$hdr).CopyTo($h, 0); $blob.AddRange($h)
        $blob.AddRange((New-ShimEntry 'C:\Users\bob\Downloads\evil_test.exe' $when)); $blob.AddRange((New-ShimEntry 'C:\Windows\System32\notepad.exe' $when.AddDays(-30)))
        $sc = @(ConvertFrom-ShimCache $blob.ToArray())
        Assert-True "ShimCache (заголовок 0x$('{0:X}' -f $hdr)): 2 записи" ($sc.Count -eq 2)
        Assert-True "ShimCache (заголовок 0x$('{0:X}' -f $hdr)): шлях і дата" ($sc[0].Path -eq 'C:\Users\bob\Downloads\evil_test.exe' -and $sc[0].LastModifiedUtc -eq $when -and $sc[1].Order -eq 1)
    }
    $bad = New-Object byte[] 128; [BitConverter]::GetBytes([int32]0x80).CopyTo($bad, 0)
    Assert-True 'ShimCache: невідомий формат -> 0 записів' (@(ConvertFrom-ShimCache $bad).Count -eq 0)
    $trunc = $blob.ToArray()[0..($blob.Count - 20)]
    Assert-True 'ShimCache: обрізані дані -> без винятку, 1 запис' (@(ConvertFrom-ShimCache ([byte[]]$trunc)).Count -eq 1)

    $onWin = ($PSVersionTable.PSEdition -ne 'Core') -or $IsWindows
    if ($onWin) {
        Test-Group 'Сліди запуску на цій Windows (реальні дані)'
        $raw = $null; try { $raw = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop).AppCompatCache } catch {}
        if ($raw) {
            $real = @(ConvertFrom-ShimCache ([byte[]]$raw))
            Assert-True ("ShimCache цієї системи розібрано ({0} записів)" -f $real.Count) ($real.Count -gt 0)
            Assert-True 'ShimCache: шляхи схожі на шляхи' (@($real | Where-Object { $_.Path -match '^(?i)([a-z]:\\|\\\\|SYSVOL\\|\\\?\?\\)' }).Count -ge [math]::Floor($real.Count * 0.8))
        }
        $cnt = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' -ErrorAction SilentlyContinue)
        $okUa = $true
        foreach ($g in $cnt) { $k = Get-Item -LiteralPath (Join-Path $g.PSPath 'Count') -ErrorAction SilentlyContinue; if (-not $k) { continue }
            foreach ($vn in $k.GetValueNames()) { try { $null = ConvertFrom-UserAssistData ($k.GetValue($vn)) } catch { $okUa = $false } } }
        Assert-True 'UserAssist поточного користувача читається без помилок' $okUa
        $now = Get-Date
        $e24 = Get-LogEvents24h 'System' $now
        $cnt24 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $now.AddHours(-24); EndTime = $now } -ErrorAction SilentlyContinue).Count
        Assert-True ("Get-LogEvents24h System = {0}, прямий підрахунок = {1}" -f $e24, $cnt24) ($null -ne $e24 -and [string]$e24 -notlike '≈*' -and [math]::Abs([int64]$e24 - $cnt24) -le 2)
    }

    Test-Group 'FILETIME'
    Assert-True '2024'                    ((ConvertFrom-AdFileTime 133700000000000000).Year -eq 2024)
    Assert-True '0 -> null'               ($null -eq (ConvertFrom-AdFileTime 0))
    Assert-True 'MaxValue -> null'        ($null -eq (ConvertFrom-AdFileTime ([int64]::MaxValue)))

    Test-Group 'Ознаки атак на AD (Get-AdAttackRow)'
    $dom = 'DC=company,DC=local'
    $r = Get-AdAttackRow 4769 @{ ServiceName = 'svc_sql'; TargetUserName = 'bob@COMPANY.LOCAL'; TicketEncryptionType = '0x17'; IpAddress = '::ffff:10.23.2.50' } $dom
    Assert-True '4769 сервісний обл. запис' ($r -and $r.Technique -like 'Kerberoasting*' -and $r.SourceIP -eq '10.23.2.50')
    Assert-True '4769 PC$ — пропуск'     (-not (Get-AdAttackRow 4769 @{ ServiceName = 'PC01$'; TicketEncryptionType = '0x17' } $dom))
    Assert-True '4769 krbtgt — пропуск'  (-not (Get-AdAttackRow 4769 @{ ServiceName = 'krbtgt'; TicketEncryptionType = '0x17' } $dom))
    Assert-True '4768 AS-REP = Високо'   ((Get-AdAttackRow 4768 @{ TargetUserName = 'nopre'; PreAuthType = '0'; IpAddress = '10.1.1.1' } $dom).Severity -eq 'Високо')
    $r = Get-AdAttackRow 4662 @{ SubjectUserName = 'mimi'; SubjectDomainName = 'COMPANY'; Properties = '%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}'; ObjectName = '%{abc}' } $dom
    Assert-True '4662 DCSync = Критично' ($r.Severity -eq 'Критично' -and $r.Details -match 'Get-Changes-All')
    Assert-True '4662 DC$ — пропуск'     (-not (Get-AdAttackRow 4662 @{ SubjectUserName = 'DC01$'; Properties = '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}' } $dom))
    Assert-True '4662 MSOL_ = Високо'    ((Get-AdAttackRow 4662 @{ SubjectUserName = 'MSOL_ab12'; Properties = '{1131F6AA-9C07-11D1-F79F-00C04FC2DCD2}' } $dom).Severity -eq 'Високо')
    Assert-True '4662 інше право — пропуск' (-not (Get-AdAttackRow 4662 @{ SubjectUserName = 'bob'; Properties = '{bf967a86-0de6-11d0-a285-00aa003049e2}' } $dom))
    Assert-True '4728 Domain Admins'     ((Get-AdAttackRow 4728 @{ TargetSid = 'S-1-5-21-1-2-3-512'; TargetUserName = 'Domain Admins'; MemberName = 'CN=evil,CN=Users'; SubjectUserName = 'adm'; SubjectDomainName = 'C' } $dom).Severity -eq 'Високо')
    Assert-True '4728 звичайна група — пропуск' (-not (Get-AdAttackRow 4728 @{ TargetSid = 'S-1-5-21-1-2-3-1105'; TargetUserName = 'HR' } $dom))
    Assert-True '4733 Backup Operators'  ((Get-AdAttackRow 4733 @{ TargetSid = 'S-1-5-32-551'; TargetUserName = 'Backup Operators' } $dom).Severity -eq 'Середньо')
    Assert-True '4756 DnsAdmins за назвою' ($null -ne (Get-AdAttackRow 4756 @{ TargetSid = 'S-1-5-21-1-2-3-1101'; TargetUserName = 'DnsAdmins' } $dom))
    Assert-True '4738 без preauth'       ((Get-AdAttackRow 4738 @{ UserAccountControl = "`r`n`t`t%%2096"; TargetUserName = 'x' } $dom).Severity -eq 'Високо')
    Assert-True '4738 штатна зміна'      (-not (Get-AdAttackRow 4738 @{ UserAccountControl = "`r`n`t`t%%2080"; TargetUserName = 'x' } $dom))
    Assert-True '4742 делегування'       ((Get-AdAttackRow 4742 @{ UserAccountControl = '%%2093'; TargetUserName = 'SRV$' } $dom).Details -match 'неконтрольоване')
    Assert-True '5136 Shadow Credentials' ((Get-AdAttackRow 5136 @{ AttributeLDAPDisplayName = 'msDS-KeyCredentialLink'; OperationType = '%%14674'; ObjectDN = 'CN=DC01,OU=Domain Controllers,DC=company,DC=local'; ObjectClass = 'computer' } $dom).Technique -match 'Shadow')
    Assert-True '5136 видалення — пропуск' (-not (Get-AdAttackRow 5136 @{ AttributeLDAPDisplayName = 'msDS-KeyCredentialLink'; OperationType = '%%14675' } $dom))
    Assert-True '5136 SPN компʼютера — пропуск' (-not (Get-AdAttackRow 5136 @{ AttributeLDAPDisplayName = 'servicePrincipalName'; OperationType = '%%14674'; ObjectClass = 'computer' } $dom))
    Assert-True '5136 SPN користувача'   ((Get-AdAttackRow 5136 @{ AttributeLDAPDisplayName = 'servicePrincipalName'; OperationType = '%%14674'; ObjectClass = 'user'; ObjectDN = 'CN=bob' } $dom).Severity -eq 'Середньо')
    Assert-True '5136 AdminSDHolder'     ((Get-AdAttackRow 5136 @{ AttributeLDAPDisplayName = 'nTSecurityDescriptor'; OperationType = '%%14674'; ObjectDN = 'CN=AdminSDHolder,CN=System,DC=company,DC=local' } $dom).Technique -match 'AdminSDHolder')
    Assert-True '5136 ACL кореня домену' ((Get-AdAttackRow 5136 @{ AttributeLDAPDisplayName = 'nTSecurityDescriptor'; OperationType = '%%14674'; ObjectDN = 'DC=company,DC=local' } $dom).Technique -match 'кореня')
    Assert-True '5136 інший ACL — пропуск' (-not (Get-AdAttackRow 5136 @{ AttributeLDAPDisplayName = 'nTSecurityDescriptor'; OperationType = '%%14674'; ObjectDN = 'CN=bob,DC=company,DC=local' } $dom))
    Assert-True 'інший EventID — пропуск' (-not (Get-AdAttackRow 4624 @{} $dom))

    Test-Group 'Тестові IOC за замовчуванням'
    $defExpr = [scriptblock]::Create(($srcText -split "`n" | Where-Object { $_ -match '^\$UsingDefaultIoc = ' } | Select-Object -First 1))
    $ScriptBound = @{ CaseId = 'x'; Hours = 24 }
    . $defExpr; Assert-True 'без IOC-параметрів -> тестові' ($UsingDefaultIoc -eq $true)
    $ScriptBound = @{ CaseId = 'x'; IocIPs = @('1.2.3.4') }
    . $defExpr; Assert-True 'з -IocIPs -> свої' ($UsingDefaultIoc -eq $false)
    $downgrade = [scriptblock]::Create((Get-SourceText ('    if ($UsingDefaultIoc) {' + "`n" + '        $maskTitles') "`n    }`n") + "`n    }")
    $Flags = New-Object System.Collections.Generic.List[object]
    $Flags.Add([pscustomobject]@{ Severity = 'Середньо'; Finding = 'Активне правило: mDNS'; Evidence = 'Inbound Allow UDP/5353 svchost — Збіг з маскою IOC' })
    $Flags.Add([pscustomobject]@{ Severity = 'Середньо'; Finding = 'Активне правило: X'; Evidence = 'x — Збіг з маскою IOC; Програма в нестандартному шляху' })
    $Flags.Add([pscustomobject]@{ Severity = 'Середньо'; Finding = "LNK на IOC-об'єкт (bob)"; Evidence = 'a → b' })
    $Flags.Add([pscustomobject]@{ Severity = 'Високо'; Finding = 'IOC IP 1.2.3.4'; Evidence = 'x' })
    $Flags.Add([pscustomobject]@{ Severity = 'Середньо'; Finding = 'LLMNR: Увімкнено'; Evidence = 'Рекомендовано…' })
    $UsingDefaultIoc = $true; . $downgrade
    Assert-True 'лише маска -> Інфо'     ($Flags[0].Severity -eq 'Інфо' -and $Flags[0].Finding -like '`[тестова маска`]*')
    Assert-True 'маска + шлях — лишається' ($Flags[1].Severity -eq 'Середньо')
    Assert-True 'LNK за маскою -> Інфо'  ($Flags[2].Severity -eq 'Інфо')
    Assert-True 'IOC IP не чіпаємо'      ($Flags[3].Severity -eq 'Високо')
    Assert-True 'LLMNR не чіпаємо'       ($Flags[4].Severity -eq 'Середньо')
    $Flags.Add([pscustomobject]@{ Severity = 'Середньо'; Finding = 'Активне правило: Y'; Evidence = 'z — Збіг з маскою IOC' })
    $UsingDefaultIoc = $false; . $downgrade
    Assert-True 'свої IOC — без змін'    ($Flags[5].Severity -eq 'Середньо')

    Test-Group 'Крок 2.9 (налаштування безпеки) виконується і дає коректні статуси'
    $step29 = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].CommandElements.Count -ge 3 -and $args[0].CommandElements[0].Extent.Text -eq 'Invoke-Step' -and $args[0].CommandElements[1].Extent.Text -like '"2.9 *' }, $true) | Select-Object -First 1
    Assert-True 'крок 2.9 знайдено' ($null -ne $step29)
    function Save-Csv { param($Rows, $Rel) }   # у тестах нічого не пишемо
    $onWindows = ($PSVersionTable.PSEdition -ne 'Core') -or $IsWindows
    if (-not $onWindows) { $env:SystemRoot = $tmp }   # на Linux диска C: немає — лише для перевірки логіки
    foreach ($role in 1, 2) {
        $D = @{ ProductType = $role; IsDC = ($role -eq 2); LocalUsers = @([pscustomobject]@{ SID = 'S-1-5-21-1-2-3-501'; Enabled = 'True' }); Services = @([pscustomobject]@{ Name = 'Spooler'; State = 'Running' })
                FwProfiles = @([pscustomobject]@{ Profile = 'Domain'; Enabled = 'False'; DefaultInbound = 'NotConfigured' }) }
        & ([scriptblock]::Create($step29.CommandElements[2].ScriptBlock.EndBlock.Extent.Text))
        $rows = @($D.Hardening)
        Assert-True "роль ${role}: ≥ 15 перевірок" ($rows.Count -ge 15)
        Assert-True "роль ${role}: статуси коректні" (@($rows | Where-Object { $_.Status -notin 'OK', 'Ризик', 'Н/д', 'Невідомо' }).Count -eq 0)
        Assert-True "роль ${role}: у ризиків є рівень" (@($rows | Where-Object { $_.Status -eq 'Ризик' -and -not $_.Severity }).Count -eq 0)
        Assert-True "роль ${role}: вимкнений firewall = Високо" (@($rows | Where-Object { $_.Check -like 'Профіль Domain' -and $_.Severity -eq 'Високо' }).Count -eq 1)
    }
    Assert-True 'DC: Spooler = ризик' (@($D.Hardening | Where-Object { $_.Check -like 'Print Spooler на контролері*' -and $_.Status -eq 'Ризик' }).Count -eq 1)
    Assert-True 'DC: LAPS = Н/д'      (@($D.Hardening | Where-Object { $_.Check -eq 'LAPS' -and $_.Status -eq 'Н/д' }).Count -eq 1)
}
finally {
    $env:SystemRoot = $origSystemRoot
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("Пройдено: {0}   Помилок: {1}" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail) { 'Red' } else { 'Green' })
if ($script:Fail) { exit 1 } else { exit 0 }
