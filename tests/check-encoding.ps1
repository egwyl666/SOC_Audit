<#
.SYNOPSIS
    Усі *.ps1 у репозиторії мають бути UTF-8 з BOM і з переносами CRLF.
    Без BOM Windows PowerShell 5.1 читає кирилицю як ANSI і ламає скрипт.
#>
param([string]$Root = (Split-Path -Parent $PSScriptRoot))
$bad = 0
foreach ($f in @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.ps1' | Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })) {
    $b = [IO.File]::ReadAllBytes($f.FullName)
    $rel = $f.FullName.Substring($Root.Length).TrimStart('\', '/')
    if ($b.Length -lt 3 -or $b[0] -ne 0xEF -or $b[1] -ne 0xBB -or $b[2] -ne 0xBF) { Write-Host "FAIL  $rel — немає UTF-8 BOM" -ForegroundColor Red; $bad++; continue }
    $lfOnly = 0
    for ($i = 0; $i -lt $b.Length; $i++) { if ($b[$i] -eq 10 -and ($i -eq 0 -or $b[$i - 1] -ne 13)) { $lfOnly++ } }
    if ($lfOnly) { Write-Host "FAIL  $rel — $lfOnly рядків з LF без CR" -ForegroundColor Red; $bad++; continue }
    Write-Host "OK    $rel"
}
if ($bad) { exit 1 } else { exit 0 }
