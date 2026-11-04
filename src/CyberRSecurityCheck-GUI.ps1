<#
.SYNOPSIS
    CyberRSecurityCheck - interfaccia grafica.

.DESCRIPTION
    Avvia un piccolo server locale (solo localhost, codice di accesso casuale a ogni avvio) e apre
    l'interfaccia in una finestra Edge/Chrome in modalita' app con un PROFILO TEMPORANEO PULITO e le
    ESTENSIONI DISATTIVATE: su un PC sospetto, un'estensione malevola non puo' leggere o alterare
    i risultati mostrati. L'analisi vera e propria e' eseguita da CyberRSecurityCheck.ps1 in un
    thread separato, cosi' la finestra resta reattiva.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File .\CyberRSecurityCheck-GUI.ps1
#>
[CmdletBinding()]
param(
    [switch]$NoBrowser,          # solo per test: non apre il browser, stampa l'indirizzo
    [int]$Port = 0,
    [string]$Token = '',
    [int]$IdleTimeout = 0,       # secondi senza richieste dall'interfaccia prima di chiudersi
    [string]$OutputPath = '',
    [string]$ConfigPath = '',
    # Usati dal file unico (irm | iex): motore e pagina incorporati, comando per riavviarsi come admin
    [string]$EngineText = '',
    [string]$UiHtml = '',
    [string]$RelaunchCommand = ''
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$engine = ''
$uiFile = ''
if ($here) {
    $engine = Join-Path $here 'CyberRSecurityCheck.ps1'
    $uiFile = Join-Path (Join-Path (Split-Path $here -Parent) 'ui') 'index.html'
}
if (-not $EngineText -and $engine -and -not (Test-Path -LiteralPath $engine)) { Write-Host "File mancante: $engine" -ForegroundColor Red; exit 1 }
if (-not $UiHtml -and $uiFile -and -not (Test-Path -LiteralPath $uiFile)) { Write-Host "File mancante: $uiFile" -ForegroundColor Red; exit 1 }
$version = '2.0.0'
try {
    $src = $EngineText
    if (-not $src) { $src = [IO.File]::ReadAllText($engine) }
    $m = [regex]::Match($src, "\`$script:Version = '([^']+)'"); if ($m.Success) { $version = $m.Groups[1].Value }
} catch { }
if (-not $OutputPath) { $OutputPath = Join-Path (Split-Path $here -Parent) 'Report' }
if ($IdleTimeout -le 0) { if ($NoBrowser) { $IdleTimeout = 900 } else { $IdleTimeout = 25 } }

$isAdmin = $false
try { $isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }


# ---------------------------------------------------------------- sicurezza della sessione
if (-not $Token) {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes); $rng.Dispose()
    $Token = -join ($bytes | ForEach-Object { $_.ToString('x2') })
}
if (-not $Port) {
    $tl = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $tl.Start(); $Port = ([Net.IPEndPoint]$tl.LocalEndpoint).Port; $tl.Stop()
}
$prefix = "http://localhost:$Port/"
$origin = "http://localhost:$Port"

function Test-TokenEqual {
    # confronto a tempo costante
    param([string]$A, [string]$B)
    if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
    $d = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $d = $d -bor ([int][char]$A[$i] -bxor [int][char]$B[$i]) }
    return ($d -eq 0)
}

# ---------------------------------------------------------------- stato
$state = @{
    Phase = 'idle'; Sync = $null; PS = $null; Handle = $null; RS = $null; Started = $null
    Mode = ''; LastActivity = (Get-Date).AddSeconds(30); Quit = $false; Browser = $null; BrowserProc = $null; ProfileDir = ''
}

function Start-Run {
    param([string]$Mode, [int]$Minutes, [bool]$Fast)
    if ($state.Phase -eq 'running') { return $false }
    Stop-Run
    $sync = [hashtable]::Synchronized(@{
            Log = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList))
            Step = 0; Total = 1; Name = ''; Percent = 0; Done = $false; Cancel = $false; Result = $null; Error = $null; LastAlert = $null; Alerts = 0
        })
    $own = New-Object 'System.Collections.Generic.List[int]'
    $own.Add($PID)
    if ($state.BrowserProc) { try { $own.Add($state.BrowserProc.Id) } catch { } }
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    if ($EngineText) { [void]$ps.AddScript($EngineText) } else { [void]$ps.AddCommand($engine) }
    [void]$ps.AddParameter('Mode', $Mode).AddParameter('NoOpen', $true).AddParameter('ProgressSync', $sync).AddParameter('ExcludePids', $own.ToArray()).AddParameter('OutputPath', $OutputPath)
    if ($Mode -eq 'Monitor') { [void]$ps.AddParameter('MonitorMinutes', [math]::Max(1, [math]::Min(240, $Minutes))) }
    if ($Fast) { [void]$ps.AddParameter('SkipMemory', $true) }
    if ($ConfigPath) { [void]$ps.AddParameter('ConfigPath', $ConfigPath) }
    $state.Sync = $sync; $state.PS = $ps; $state.RS = $rs; $state.Mode = $Mode
    $state.Handle = $ps.BeginInvoke()
    $state.Started = Get-Date
    $state.Phase = 'running'
    return $true
}

function Stop-Run {
    if ($state.PS) {
        try { if (-not $state.Handle.IsCompleted) { $state.PS.Stop() } } catch { }
        try { $state.PS.Dispose() } catch { }
        try { $state.RS.Close(); $state.RS.Dispose() } catch { }
    }
    $state.PS = $null; $state.RS = $null; $state.Handle = $null
}

function Update-Phase {
    if ($state.Phase -ne 'running') { return }
    $s = $state.Sync
    if ($s['Done'] -or ($state.Handle -and $state.Handle.IsCompleted)) {
        if (-not $s['Result']) {
            $msg = $s['Error']
            if (-not $msg -and $state.PS -and $state.PS.Streams.Error.Count -gt 0) { $msg = [string]$state.PS.Streams.Error[0] }
            if (-not $msg) { $msg = 'Analisi terminata senza risultati.' }
            $s['Error'] = $msg
            $state.Phase = 'error'
        } else { $state.Phase = 'done' }
    }
}

function Get-StatusObject {
    param([int]$Since)
    Update-Phase
    $s = $state.Sync
    $log = New-Object 'System.Collections.Generic.List[object]'
    $count = 0
    if ($s) {
        $count = $s.Log.Count
        if ($Since -lt 0 -or $Since -gt $count) { $Since = 0 }
        for ($i = $Since; $i -lt $count; $i++) {
            $e = $s.Log[$i]
            $log.Add(@{ t = [string]$e.Ora; m = [string]$e.Testo; c = [string]$e.Colore })
        }
    }
    $el = 0
    if ($state.Started) { $el = [int]((Get-Date) - $state.Started).TotalSeconds }
    $o = @{ phase = $state.Phase; mode = $state.Mode; logIndex = $count; log = $log.ToArray(); elapsed = $el; startedAt = [bool]$state.Started }
    if ($s) {
        $o.step = [int]$s['Step']; $o.total = [int]$s['Total']; $o.name = [string]$s['Name']; $o.percent = [int]$s['Percent']
        $o.alerts = [int]$s['Alerts']; $o.lastAlert = [string]$s['LastAlert']; $o.error = [string]$s['Error']
    }
    return $o
}

function Get-ResultObject {
    Update-Phase
    $s = $state.Sync
    if (-not $s) { return @{ error = 'Nessuna analisi eseguita.' } }
    $r = $s['Result']
    if (-not $r) { return @{ error = [string]$s['Error'] } }
    $f = New-Object 'System.Collections.Generic.List[object]'
    foreach ($x in @($r.Findings)) { $f.Add(@{ sev = [string]$x.Gravita; area = [string]$x.Categoria; title = [string]$x.Titolo; detail = [string]$x.Dettaglio; advice = [string]$x.Consiglio }) }
    $h = New-Object 'System.Collections.Generic.List[object]'
    foreach ($x in @($r.Hardening)) { $h.Add(@{ state = [string]$x.Stato; area = [string]$x.Area; check = [string]$x.Controllo; value = [string]$x.Valore; advice = [string]$x.Consiglio }) }
    $secs = @($r.Sections)
    $ok = @($secs | Where-Object { $_.Stato -eq 'OK' }).Count
    $sum = $r.Summary
    return @{
        summary = @{ score = [int]$sum.Punteggio; verdict = [string]$sum.Giudizio; message = [string]$sum.Messaggio; alta = [int]$sum.Alta; media = [int]$sum.Media; critici = [int]$sum.Critici; incomplete = [bool]$sum.Incompleta }
        findings = $f.ToArray(); hardening = $h.ToArray(); sectionsOk = $ok; sectionsTotal = $secs.Count
        html = [string]$r.Html; outDir = [string]$r.OutDir; zip = [string]$r.Zip
    }
}

# ---------------------------------------------------------------- browser in modalita' app isolata
function Find-AppBrowser {
    $c = @()
    foreach ($b in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA)) {
        if (-not $b) { continue }
        $c += Join-Path $b 'Microsoft\Edge\Application\msedge.exe'
    }
    foreach ($b in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
        if (-not $b) { continue }
        $c += Join-Path $b 'Google\Chrome\Application\chrome.exe'
    }
    foreach ($p in $c) {
        if (Test-Path -LiteralPath $p) {
            try { if ((Get-AuthenticodeSignature -LiteralPath $p).Status -eq 'Valid') { return $p } } catch { return $p }
        }
    }
    return $null
}

function Open-AppWindow {
    param([string]$Url)
    if (-not $state.Browser) { return $false }
    $argList = @(
        "--app=$Url", "--user-data-dir=`"$($state.ProfileDir)`"", '--no-first-run', '--no-default-browser-check',
        '--disable-extensions', '--disable-sync', '--disable-background-networking', '--disable-component-update',
        '--disable-features=Translate,msEdgeSidebarV2,EdgeCollections,msUndersideButton', '--window-size=1240,880'
    )
    $p = Start-Process -FilePath $state.Browser -ArgumentList $argList -PassThru
    if (-not $state.BrowserProc) { $state.BrowserProc = $p }
    return $true
}

function Open-Target {
    param([string]$What)
    $r = $null
    if ($state.Sync) { $r = $state.Sync['Result'] }
    switch ($What) {
        'report' {
            if ($r -and (Test-Path -LiteralPath $r.Html)) {
                $u = ([Uri]$r.Html).AbsoluteUri
                if (-not (Open-AppWindow $u)) { Start-Process $r.Html }
            }
        }
        'folder' { if ($r -and (Test-Path -LiteralPath $r.OutDir)) { Start-Process explorer.exe -ArgumentList "`"$($r.OutDir)`"" } }
        'base' {
            if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
            Start-Process explorer.exe -ArgumentList "`"$OutputPath`""
        }
    }
}

# ---------------------------------------------------------------- HTTP
function Send-Bytes {
    param($Ctx, [byte[]]$Bytes, [string]$Type, [int]$Code = 200, [hashtable]$Extra = @{})
    $res = $Ctx.Response
    $res.StatusCode = $Code
    $res.ContentType = $Type
    $res.Headers['Cache-Control'] = 'no-store'
    $res.Headers['X-Content-Type-Options'] = 'nosniff'
    $res.Headers['Referrer-Policy'] = 'no-referrer'
    $res.Headers['X-Frame-Options'] = 'DENY'
    foreach ($k in $Extra.Keys) { $res.Headers[$k] = $Extra[$k] }
    $res.ContentLength64 = $Bytes.Length
    $res.OutputStream.Write($Bytes, 0, $Bytes.Length)
    $res.OutputStream.Close()
}

function Send-Json {
    param($Ctx, $Obj, [int]$Code = 200)
    $json = ConvertTo-Json -InputObject $Obj -Depth 6 -Compress
    Send-Bytes $Ctx ([Text.Encoding]::UTF8.GetBytes($json)) 'application/json; charset=utf-8' $Code
}

function Read-Body {
    param($Req)
    if (-not $Req.HasEntityBody) { return $null }
    $sr = New-Object IO.StreamReader($Req.InputStream, [Text.Encoding]::UTF8)
    try { $t = $sr.ReadToEnd() } finally { $sr.Dispose() }
    if ($t.Length -gt 10000) { return $null }
    try { return ($t | ConvertFrom-Json) } catch { return $null }
}

function Invoke-Request {
    param($Ctx)
    $req = $Ctx.Request
    $path = $req.Url.AbsolutePath
    # protezione da DNS rebinding: accetta solo Host localhost:porta
    if ($req.Headers['Host'] -ne "localhost:$Port") { Send-Json $Ctx @{ error = 'host' } 403; return }
    if ($path -eq '/' -or $path -eq '/index.html') {
        $nonceBytes = New-Object byte[] 16
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($nonceBytes); $rng.Dispose()
        $nonce = [Convert]::ToBase64String($nonceBytes)
        $page = $UiHtml
        if (-not $page) { $page = [IO.File]::ReadAllText($uiFile) }
        $html = $page.Replace('__NONCE__', $nonce)
        $csp = "default-src 'none'; script-src 'nonce-$nonce'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        Send-Bytes $Ctx ([Text.Encoding]::UTF8.GetBytes($html)) 'text/html; charset=utf-8' 200 @{ 'Content-Security-Policy' = $csp }
        return
    }
    if (-not $path.StartsWith('/api/')) { Send-Json $Ctx @{ error = 'not found' } 404; return }
    if (-not (Test-TokenEqual $req.Headers['X-Token'] $Token)) { Send-Json $Ctx @{ error = 'token' } 403; return }
    $o = $req.Headers['Origin']
    if ($req.HttpMethod -eq 'POST' -and $o -and $o -ne $origin) { Send-Json $Ctx @{ error = 'origin' } 403; return }
    $state.LastActivity = Get-Date
    switch ("$($req.HttpMethod) $path") {
        'GET /api/ping' { Send-Json $Ctx @{ ok = $true } }
        'GET /api/info' { Update-Phase; Send-Json $Ctx @{ app = 'CyberRSecurityCheck'; version = $version; pc = [Environment]::MachineName; user = "$env:USERDOMAIN\$env:USERNAME"; isAdmin = $isAdmin; phase = $state.Phase } }
        'GET /api/status' {
            $since = 0
            [void][int]::TryParse([string]$req.QueryString['since'], [ref]$since)
            Send-Json $Ctx (Get-StatusObject $since)
        }
        'GET /api/result' { Send-Json $Ctx (Get-ResultObject) }
        'POST /api/start' {
            $b = Read-Body $req
            $mode = [string]$b.mode
            if ($mode -notin @('Completo', 'ClipTest', 'Monitor', 'Raccolta')) { Send-Json $Ctx @{ error = 'mode' } 400; return }
            $min = 30
            try { $min = [int]$b.minutes } catch { }
            $ok = Start-Run $mode $min ([bool]$b.fast)
            if ($ok) { Send-Json $Ctx @{ ok = $true } } else { Send-Json $Ctx @{ error = 'analisi gia'' in corso' } 409 }
        }
        'POST /api/cancel' { if ($state.Sync) { $state.Sync['Cancel'] = $true }; Send-Json $Ctx @{ ok = $true } }
        'POST /api/open' { $b = Read-Body $req; Open-Target ([string]$b.what); Send-Json $Ctx @{ ok = $true } }
        'POST /api/elevate' {
            Send-Json $Ctx @{ ok = $true }
            try {
                $a = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
                if ($RelaunchCommand) { $a = "-NoProfile -ExecutionPolicy Bypass -Command `"$RelaunchCommand`"" }
                Start-Process powershell.exe -Verb RunAs -ArgumentList $a | Out-Null
                $state.Quit = $true
            } catch { }
        }
        'POST /api/exit' { Send-Json $Ctx @{ ok = $true }; if ($state.Phase -ne 'running') { $state.Quit = $true } }
        default { Send-Json $Ctx @{ error = 'not found' } 404 }
    }
}

# ---------------------------------------------------------------- avvio
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)
try { $listener.Start() } catch { Write-Host "Impossibile avviare l'interfaccia su $prefix : $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
$url = "$prefix#$Token"

if ($NoBrowser) {
    Write-Host "CyberRSecurityCheck GUI in ascolto: $url"
} else {
    $state.Browser = Find-AppBrowser
    $state.ProfileDir = Join-Path ([IO.Path]::GetTempPath()) ('CyberRSecUI_' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    if (-not (Open-AppWindow $url)) {
        Write-Host 'Edge/Chrome non trovati: apro il browser predefinito (le estensioni restano attive).' -ForegroundColor Yellow
        Start-Process $url
    }
}

try {
    while (-not $state.Quit) {
        $task = $listener.GetContextAsync()
        while (-not $task.AsyncWaitHandle.WaitOne(400)) {
            Update-Phase
            $idle = ((Get-Date) - $state.LastActivity).TotalSeconds
            if ($state.Phase -ne 'running' -and $idle -gt $IdleTimeout) { $state.Quit = $true; break }
            if ($state.Quit) { break }
        }
        if ($state.Quit) { break }
        $ctx = $null
        try { $ctx = $task.GetAwaiter().GetResult() } catch { continue }
        try { Invoke-Request $ctx } catch {
            try { Send-Json $ctx @{ error = $_.Exception.Message } 500 } catch { }
        }
    }
} finally {
    if ($state.Phase -eq 'running' -and $state.Sync) {
        # finestra chiusa durante l'analisi: si lascia terminare e salvare il rapporto
        $state.Sync['Cancel'] = ($state.Mode -eq 'Monitor')
        $t0 = Get-Date
        while (-not $state.Handle.IsCompleted -and ((Get-Date) - $t0).TotalMinutes -lt 30) { Start-Sleep -Milliseconds 500 }
    }
    try { $listener.Stop(); $listener.Close() } catch { }
    Stop-Run
    if ($state.BrowserProc) {
        try { if (-not $state.BrowserProc.HasExited) { [void]$state.BrowserProc.CloseMainWindow(); [void]$state.BrowserProc.WaitForExit(4000) } } catch { }
    }
    if ($state.ProfileDir -and (Test-Path -LiteralPath $state.ProfileDir)) {
        Start-Sleep -Milliseconds 800
        try { Remove-Item -LiteralPath $state.ProfileDir -Recurse -Force -ErrorAction Stop } catch { }
    }
}
