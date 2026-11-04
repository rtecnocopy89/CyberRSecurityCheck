<#
.NOTES
    CyberRSecurityCheck - analisi di sicurezza per PC usati per l'home banking
    Maintainer : @rtecnocopy89
    GitHub     : https://github.com/rtecnocopy89/CyberRSecurityCheck
    Version    : #{VERSION}
    SHA256 dei sorgenti: #{SOURCEHASH}

.USAGE
    PowerShell come amministratore:
        irm https://raw.githubusercontent.com/rtecnocopy89/CyberRSecurityCheck/main/cyberrsecuritycheck.ps1 | iex
    Con parametri:
        & ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/rtecnocopy89/CyberRSecurityCheck/main/cyberrsecuritycheck.ps1))) -Console -Mode Completo
#>

param (
    [string]$Mode,
    [int]$MonitorMinutes,
    [switch]$Console,
    [switch]$Fast,
    [string]$OutputPath
)

# "irm | iex" esegue il blocco param come semplici dichiarazioni: niente ValidateSet, controlli manuali
$CRS_URL = 'https://raw.githubusercontent.com/rtecnocopy89/CyberRSecurityCheck/main/cyberrsecuritycheck.ps1'
$CRS_VERSION = '#{VERSION}'
if (-not $Mode) { $Mode = 'Completo' }
if ($Mode -notin 'Completo', 'Raccolta', 'ClipTest', 'Monitor') {
    Write-Host "Modalita' sconosciuta '$Mode': usare Completo, Raccolta, ClipTest o Monitor" -ForegroundColor Red
    return
}
if (-not $MonitorMinutes -or $MonitorMinutes -lt 1) { $MonitorMinutes = 30 }

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host 'CyberRSecurityCheck non puo'' essere eseguito: PowerShell e'' limitato dai criteri di sicurezza (Constrained Language Mode).' -ForegroundColor Red
    return
}

$crsIsWindows = ($env:OS -eq 'Windows_NT')
$crsIsAdmin = $false
try { $crsIsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }

# Argomenti per un eventuale riavvio (come amministratore o dall'interfaccia)
$crsArgs = @()
if ($Mode -ne 'Completo') { $crsArgs += "-Mode $Mode" }
if ($MonitorMinutes -ne 30) { $crsArgs += "-MonitorMinutes $MonitorMinutes" }
if ($Console) { $crsArgs += '-Console' }
if ($Fast) { $crsArgs += '-Fast' }
if ($OutputPath) { $crsArgs += "-OutputPath '$($OutputPath -replace "'", "''")'" }
$crsRelaunch = if ($PSCommandPath) {
    "& { & '$($PSCommandPath -replace "'", "''")' $($crsArgs -join ' ') }"
} else {
    "&([ScriptBlock]::Create((irm $CRS_URL))) $($crsArgs -join ' ')"
}

if ($crsIsWindows -and -not $crsIsAdmin -and $env:CRS_NO_ELEVATE -ne '1') {
    Write-Output 'CyberRSecurityCheck richiede i privilegi di amministratore: riavvio in corso...'
    $psCmd = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
    try {
        Start-Process $psCmd -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `"$crsRelaunch`"" -Verb RunAs
    } catch {
        Write-Host 'Riavvio come amministratore annullato. Proseguo senza privilegi: alcuni controlli saranno incompleti.' -ForegroundColor Yellow
        $crsIsAdmin = $null
    }
    # return e non break: break fuori da un ciclo interrompe anche lo script o il ciclo di chi ha lanciato il comando
    if ($null -ne $crsIsAdmin) { return }
}

# ---------------------------------------------------------------- componenti incorporati
function ConvertFrom-CrsBlob {
    param([string]$Blob)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($Blob -replace '\s', '')))
}
$crsEngine = ConvertFrom-CrsBlob @'
#{ENGINE}
'@
$crsGui = ConvertFrom-CrsBlob @'
#{GUI}
'@
$crsUi = ConvertFrom-CrsBlob @'
#{UI}
'@
$crsConfigDefault = ConvertFrom-CrsBlob @'
#{CONFIG}
'@

if ($env:CRS_SELFTEST -eq '1') {
    # usato dai test: verifica che i componenti si estraggano e si analizzino senza errori
    $ok = $true
    foreach ($pair in @(@('motore', $crsEngine), @('interfaccia', $crsGui))) {
        $t = $null; $e = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($pair[1], [ref]$t, [ref]$e)
        if ($e.Count -gt 0) { $ok = $false; Write-Output "ERRORE sintassi $($pair[0]): $($e[0].Message)" }
    }
    if ($crsUi -notmatch '__NONCE__') { $ok = $false; Write-Output 'ERRORE interfaccia: pagina non valida' }
    try { [void]($crsConfigDefault | ConvertFrom-Json) } catch { $ok = $false; Write-Output 'ERRORE config predefinita' }
    Write-Output ("SELFTEST {0} v{1} motore={2} gui={3} ui={4}" -f $(if ($ok) { 'OK' } else { 'FALLITO' }), $CRS_VERSION, $crsEngine.Length, $crsGui.Length, $crsUi.Length)
    return
}

# ---------------------------------------------------------------- dati e configurazione
if ($PSCommandPath) { $crsHome = Split-Path $PSCommandPath -Parent }
elseif ($env:LOCALAPPDATA) { $crsHome = Join-Path $env:LOCALAPPDATA 'CyberRSecurityCheck' }
else { $crsHome = Join-Path ([IO.Path]::GetTempPath()) 'CyberRSecurityCheck' }
if (-not (Test-Path -LiteralPath $crsHome)) { New-Item -ItemType Directory -Path $crsHome -Force | Out-Null }
$crsConfig = Join-Path $crsHome 'config.json'
if (-not (Test-Path -LiteralPath $crsConfig)) {
    try { [IO.File]::WriteAllText($crsConfig, $crsConfigDefault, (New-Object System.Text.UTF8Encoding($false))) } catch { }
}
if (-not $OutputPath) { $OutputPath = Join-Path $crsHome 'Report' }

Write-Host ''
Write-Host "  CyberRSecurityCheck v$CRS_VERSION" -ForegroundColor Cyan
Write-Host '  Analisi di sicurezza in sola lettura per PC usati per l''home banking' -ForegroundColor Gray
Write-Host "  Rapporti: $OutputPath" -ForegroundColor Gray
Write-Host ''

if ($Console -or -not $crsIsWindows) {
    $p = @{ Mode = $Mode; OutputPath = $OutputPath; ConfigPath = $crsConfig }
    if ($Mode -eq 'Monitor') { $p.MonitorMinutes = $MonitorMinutes }
    if ($Fast) { $p.SkipMemory = $true }
    & ([ScriptBlock]::Create($crsEngine)) @p
} else {
    Write-Host '  Interfaccia aperta in una finestra separata. Chiudere quella finestra per terminare.' -ForegroundColor Gray
    & ([ScriptBlock]::Create($crsGui)) -EngineText $crsEngine -UiHtml $crsUi -OutputPath $OutputPath -ConfigPath $crsConfig -RelaunchCommand $crsRelaunch
}
