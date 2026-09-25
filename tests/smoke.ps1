<#
.SYNOPSIS
    Smoke-прогін: повний запуск soc-collect.ps1 окремим процесом (як у реальній роботі) і перевірка результату.
    Падає, якщо скрипт завершився з помилкою, немає звіту/маніфесту або хоч один крок має статус ПОМИЛКА.
.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\tests\smoke.ps1 -OutRoot C:\SOC_Smoke
#>
param(
    [string]$OutRoot = (Join-Path ([IO.Path]::GetTempPath()) 'soc-smoke'),
    [string]$Exe = 'powershell.exe'
)
$script = Join-Path (Split-Path -Parent $PSScriptRoot) 'soc-collect.ps1'
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
$sw = [Diagnostics.Stopwatch]::StartNew()
# -CollectHives: перевіряє також копію кущів і розбір Amcache (reg load/unload робочої копії)
& $Exe -NoProfile -ExecutionPolicy Bypass -File $script -CaseId CI-SMOKE -Hours 1 -SkipWideSearch -NoEvtx -NoZip -CollectHives -OutRoot $OutRoot
$code = $LASTEXITCODE
Write-Host ("Код виходу: {0}; час: {1:N0} с" -f $code, $sw.Elapsed.TotalSeconds)
$fail = @()
if ($code -ne 0) { $fail += "код виходу $code" }
$case = Get-ChildItem -LiteralPath $OutRoot -Directory | Where-Object Name -like 'CI-SMOKE*' | Sort-Object LastWriteTime | Select-Object -Last 1
if (-not $case) { Write-Host 'FAIL  папку справи не створено' -ForegroundColor Red; exit 1 }
foreach ($f in 'report.html', 'manifest.csv', 'manifest.csv.sha256', 'collection_steps.csv', 'chain_of_custody.csv', 'findings_auto.csv') {
    if (-not (Test-Path -LiteralPath (Join-Path $case.FullName $f))) { $fail += "немає $f" }
}
$steps = @(Import-Csv -LiteralPath (Join-Path $case.FullName 'collection_steps.csv'))
$steps | Format-Table Step, Status, Seconds -AutoSize | Out-String -Width 220 | Write-Host
$err = @($steps | Where-Object { $_.Status -ne 'OK' })
foreach ($e in $err) { $fail += ("крок «{0}»: {1}" -f $e.Step, $e.Error) }
if ($steps.Count -lt 30) { $fail += "лише $($steps.Count) кроків" }
$visPath = Join-Path $case.FullName '02_system\event_visibility.csv'
$vis = @(); if (Test-Path -LiteralPath $visPath) { $vis = @(Import-Csv -LiteralPath $visPath) }
if ($vis.Count -lt 20) { $fail += "event_visibility.csv: лише $($vis.Count) категорій" }
$pePath = Join-Path $case.FullName '02_system\persistence_extended.csv'
$pe = @(); if ((Test-Path -LiteralPath $pePath) -and -not ((Get-Content -LiteralPath $pePath -TotalCount 1) -like '#*')) { $pe = @(Import-Csv -LiteralPath $pePath) }
if ($pe.Count -lt 3) { $fail += "persistence_extended.csv: лише $($pe.Count) рядків (очікувались хоча б LSA-пакети)" }
Write-Host '--- Розширена персистентність'
$pe | Format-Table Category, Name, Status, Severity, Signer -AutoSize | Out-String -Width 220 | Write-Host
Write-Host '--- Видимість за категоріями подій'
$vis | Format-Table Category, EventIds, Status, Events24h -AutoSize | Out-String -Width 220 | Write-Host
Write-Host '--- Сліди запуску (кількість рядків)'
foreach ($f in 'userassist.csv', 'runmru.csv', 'shimcache.csv', 'amcache_files.csv') {
    $pth = Join-Path $case.FullName "05_artifacts\$f"
    # файл-заглушка без даних починається з '#'; @(...).Count — бо в PS 5.1 у PSObject.Properties немає .Count
    $n = 0; if ((Test-Path -LiteralPath $pth) -and -not ((Get-Content -LiteralPath $pth -TotalCount 1) -like '#*')) { $n = @(Import-Csv -LiteralPath $pth).Count }
    Write-Host ("  {0,-20} {1}" -f $f, $n)
}
$mounted = @(Get-ChildItem 'Registry::HKEY_LOCAL_MACHINE' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'SOC_Amcache_*' })
if ($mounted.Count) { $fail += "куш Amcache лишився змонтованим: $($mounted.PSChildName -join ', ')" }
Write-Host '--- Примітки збору'; Get-Content -LiteralPath (Join-Path $case.FullName 'collection_notes.txt') | Write-Host
if ($fail.Count) { foreach ($f in $fail) { Write-Host "FAIL  $f" -ForegroundColor Red }; exit 1 }
Write-Host ("OK: {0} кроків без помилок" -f $steps.Count) -ForegroundColor Green
exit 0
