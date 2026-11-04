<#
.SYNOPSIS
    Crea cyberrsecuritycheck.ps1, il file unico servito con "irm ... | iex".

.DESCRIPTION
    Unisce il lanciatore (src\start.ps1), il motore (src\CyberRSecurityCheck.ps1), l'interfaccia
    (src\CyberRSecurityCheck-GUI.ps1 + ui\index.html) e la configurazione predefinita
    (config\config.json). Motore, interfaccia e configurazione vengono incorporati in Base64, cosi'
    il file risultante e' ASCII puro: "irm | iex" rifiuta il BOM e Windows PowerShell 5.1 legge i file
    senza BOM con la codepage ANSI. La compilazione si interrompe se qualcosa non e' valido.

.EXAMPLE
    .\Compile.ps1           # crea cyberrsecuritycheck.ps1 e cyberrsecuritycheck.ps1.sha256
    .\Compile.ps1 -Test     # crea il file ed esegue i test automatici
    .\Compile.ps1 -Run      # crea il file e lo avvia
#>
param (
    [switch]$Run,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$outName = 'cyberrsecuritycheck.ps1'
$outFile = Join-Path $root $outName

function Read-Source {
    param([string[]]$Parts)
    $p = $root
    foreach ($x in $Parts) { $p = Join-Path $p $x }
    if (-not (Test-Path -LiteralPath $p)) { throw "File sorgente mancante: $p" }
    return [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF).Replace("`r`n", "`n")
}

function Test-PsSyntax {
    param([string]$Name, [string]$Code)
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($Code, [ref]$t, [ref]$e)
    if ($e.Count -gt 0) { throw ("Errore di sintassi in {0} riga {1}: {2}" -f $Name, $e[0].Extent.StartLineNumber, $e[0].Message) }
}

function ConvertTo-Blob {
    param([string]$Text)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
    $lines = New-Object 'System.Collections.Generic.List[string]'
    for ($i = 0; $i -lt $b64.Length; $i += 120) { $lines.Add($b64.Substring($i, [math]::Min(120, $b64.Length - $i))) }
    return ($lines -join "`n")
}

Write-Host 'Lettura dei sorgenti...' -ForegroundColor Cyan
$start = Read-Source @('src', 'start.ps1')
$engine = Read-Source @('src', 'CyberRSecurityCheck.ps1')
$gui = Read-Source @('src', 'CyberRSecurityCheck-GUI.ps1')
$ui = Read-Source @('ui', 'index.html')
$config = Read-Source @('config', 'config.json')

Write-Host 'Controllo dei sorgenti...' -ForegroundColor Cyan
Test-PsSyntax 'src\start.ps1' $start
Test-PsSyntax 'src\CyberRSecurityCheck.ps1' $engine
Test-PsSyntax 'src\CyberRSecurityCheck-GUI.ps1' $gui
try { [void]($config | ConvertFrom-Json) } catch { throw "config\config.json non e' un JSON valido: $($_.Exception.Message)" }
if ($ui -notmatch '__NONCE__') { throw 'ui\index.html: manca il segnaposto __NONCE__ dello script' }
foreach ($pair in @(@('src\start.ps1', $start), @('src\CyberRSecurityCheck.ps1', $engine), @('src\CyberRSecurityCheck-GUI.ps1', $gui))) {
    $bad = [regex]::Match($pair[1], '[^\x00-\x7F]')
    if ($bad.Success) {
        $line = ($pair[1].Substring(0, $bad.Index) -split "`n").Count
        throw ("Carattere non ASCII in {0} riga {1}: nel codice PowerShell usare [char] (es. `"Modalit`$([char]0x00E0)`")" -f $pair[0], $line)
    }
}
$m = [regex]::Match($engine, "\`$script:Version = '([^']+)'")
if (-not $m.Success) { throw 'Versione non trovata nel motore ($script:Version)' }
$version = $m.Groups[1].Value

$sha = [Security.Cryptography.SHA256]::Create()
$srcHash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($start + $engine + $gui + $ui + $config)) | ForEach-Object { $_.ToString('x2') })

Write-Host "Creazione di $outName v$version..." -ForegroundColor Cyan
$out = $start.Replace('#{VERSION}', $version).Replace('#{SOURCEHASH}', $srcHash)
$out = $out.Replace('#{ENGINE}', (ConvertTo-Blob $engine)).Replace('#{GUI}', (ConvertTo-Blob $gui)).Replace('#{UI}', (ConvertTo-Blob $ui)).Replace('#{CONFIG}', (ConvertTo-Blob $config))
if ($out -match '#\{(VERSION|SOURCEHASH|ENGINE|GUI|UI|CONFIG)\}') { throw 'Segnaposto non sostituito nel file unico' }
if ([regex]::IsMatch($out, '[^\x00-\x7F]')) { throw 'Il file unico contiene caratteri non ASCII' }
Test-PsSyntax $outName $out
$out = $out.Replace("`n", "`r`n")

if ((Test-Path -LiteralPath $outFile) -and (Get-Item -LiteralPath $outFile).IsReadOnly) { Remove-Item -LiteralPath $outFile -Force }
[IO.File]::WriteAllText($outFile, $out, (New-Object System.Text.ASCIIEncoding))
$hash = (Get-FileHash -LiteralPath $outFile -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $root "$outName.sha256"), "$hash  $outName`n", (New-Object System.Text.ASCIIEncoding))

Write-Host ''
Write-Host "  $outName creato ($([math]::Round((Get-Item -LiteralPath $outFile).Length / 1KB)) KB, v$version)" -ForegroundColor Green
Write-Host "  SHA256: $hash" -ForegroundColor Green
Write-Host ''

if ($Test) {
    $psExe = (Get-Process -Id $PID).Path
    & $psExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path (Join-Path $root 'tests') 'Test-CyberRSecurityCheck.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Test falliti' }
}
if ($Run) { & $outFile }
