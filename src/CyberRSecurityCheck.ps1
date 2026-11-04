<#
.SYNOPSIS
    CyberRSecurityCheck - analisi di sicurezza di un PC Windows usato per l'home banking.

.DESCRIPTION
    Cerca le cause tipiche delle frodi sui bonifici (IBAN sostituito, credenziali rubate):
    estensioni del browser, codice iniettato nel browser (man-in-the-browser, es. Ramnit/drIBAN),
    clipper, controllo remoto, ClickFix, proxy/DNS/certificati, ARP spoofing, persistenza,
    e verifica la configurazione di sicurezza del PC con un punteggio finale.

    E' IN SOLA LETTURA: non cancella e non modifica nulla (il test appunti scrive un IBAN di prova
    e poi ripristina il contenuto). Produce REPORT.html, risultati.json, CSV di dettaglio,
    SHA256SUMS.txt (integrita' delle prove) e uno ZIP.

    Modalita' (-Mode): Completo (predefinita), Raccolta, ClipTest, Monitor.
    Interfaccia grafica: CyberRSecurityCheck-GUI.ps1 (o Avvia-CyberRSecurityCheck.bat).
    Compatibile con Windows PowerShell 5.1 e PowerShell 7. Eseguire come amministratore.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\CyberRSecurityCheck.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\CyberRSecurityCheck.ps1 -Mode Monitor -MonitorMinutes 30
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\CyberRSecurityCheck.ps1 -OutputPath \\SERVER\Report
#>
[CmdletBinding()]
param(
    [ValidateSet('Completo', 'Raccolta', 'ClipTest', 'Monitor')]
    [string]$Mode = 'Completo',

    # Cartella in cui creare il report (anche una share di rete, per raccogliere i report di piu' PC)
    [string]$OutputPath = '',

    # Domini/parole chiave dell'home banking da sorvegliare (estensioni, hosts, DNS)
    [string[]]$BankDomains = @('relaxbanking.it', 'bcccampaniacentro.it', 'bcc.it', 'iccreabanca.it', 'inbank.it', 'cse.it'),

    # File di configurazione (domini banca, elementi autorizzati). Predefinito: config.json accanto allo script
    [string]$ConfigPath = '',

    [int]$MonitorMinutes = 60,
    [int]$RecentDays = 30,
    [switch]$NoZip,
    [switch]$NoOpen,
    [switch]$SkipModules,
    [switch]$SkipMemory,

    # Usati dall'interfaccia grafica: avanzamento/risultati condivisi e processi propri da escludere
    [hashtable]$ProgressSync = $null,
    [int[]]$ExcludePids = @()
)

$script:BoundParams = $PSBoundParameters
Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$script:AppName = 'CyberRSecurityCheck'
$script:Version = '2.0.0'
$script:Sync = $ProgressSync
$script:Hardening = @()
$script:DomainJoined = $null
$script:LocalProxyActive = $false
$script:OwnPids = @($ExcludePids) + @($PID)
$script:Result = $null

# ----------------------------------------------------------------------------------------------
#  Stato globale
# ----------------------------------------------------------------------------------------------
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:Sections = New-Object 'System.Collections.Generic.List[object]'
$script:SigCache = @{}
$script:SectionData = @{}
$script:Config = $null
$script:StepNo = 0
$script:StepTotal = 0
$script:JsSer = $null
$script:OutDir = $null
$script:IsWin = ($env:OS -eq 'Windows_NT')
$script:IsAdmin = $false
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $script:IsAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $script:IsAdmin = $false }
if ($PSVersionTable.PSVersion.Major -ge 6) { $script:CsvEnc = 'utf8BOM' } else { $script:CsvEnc = 'UTF8' }

$script:BrowserExe = @('chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe', 'iexplore.exe')
$script:RemoteToolRegex = '(?i)anydesk|teamviewer|rustdesk|ultravnc|tightvnc|realvnc|tvnserver|winvnc|vncserver|screenconnect|connectwise|splashtop|atera|netsupport|client32\.exe|remcos|ammyy|supremo|dwservice|dwagent|meshagent|logmein|gotoassist|getgo|zoho ?assist|zohoassist|parsec|remoting_host|chrome remote desktop|action1|tacticalrmm|simplehelp|syncro|aeroadmin|litemanager|radmin|remoteutilities|rutserv|rfusclient|ninjarmm|n-able|kaseya|bomgar|beyondtrust|islonline|showmypc|fixme\.it|iperius ?remote'
$script:ScriptHostRegex = '(?i)\b(wscript|cscript|mshta|regsvr32|rundll32)(\.exe)?\b|powershell(\.exe)?\s.*(-e(nc|ncodedcommand)?\s|-w(indowstyle)?\s+h|hidden|iex\b|invoke-expression|downloadstring|frombase64string|-nop\b)'
$script:DangerPerms = @('debugger', 'proxy', 'webRequestBlocking', 'nativeMessaging', 'management', 'clipboardRead', 'clipboardWrite', 'cookies', 'scripting', 'declarativeNetRequestWithHostAccess', 'webRequest', 'tabs', 'history', 'downloads')
$script:ChromeLocation = @{
    1 = 'Store/interna'; 2 = 'Esterna (preferenze)'; 3 = 'Esterna (registro)'; 4 = 'NON IMPACCHETTATA (caricata da cartella)'
    5 = 'Componente'; 6 = 'Esterna (download)'; 7 = 'Policy (download)'; 8 = 'RIGA DI COMANDO (--load-extension)'
    9 = 'Policy'; 10 = 'Componente esterno'
}

# ----------------------------------------------------------------------------------------------
#  Funzioni di supporto (pure, testabili)
# ----------------------------------------------------------------------------------------------
function Get-DefaultConfig {
    return [ordered]@{
        BankDomains          = @('relaxbanking.it', 'bcccampaniacentro.it', 'bcc.it', 'iccreabanca.it', 'inbank.it', 'cse.it')
        RecentDays           = 30
        DnsCompare           = $true
        AllowExtensionIds    = @()
        AllowRemoteTools     = @()
        AllowCertThumbprints = @()
        AllowPaths           = @()
    }
}

function Import-CyberConfig {
    param([string]$Path)
    $cfg = Get-DefaultConfig
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $j = Read-JsonFile $Path
        if ($null -eq $j) {
            Write-Host "ATTENZIONE: $Path non e' un JSON valido, uso le impostazioni predefinite." -ForegroundColor Yellow
        } else {
            foreach ($k in @($j.Keys)) { if (-not ([string]$k).StartsWith('_')) { $cfg[[string]$k] = $j[$k] } }
        }
    }
    foreach ($k in @('BankDomains', 'AllowExtensionIds', 'AllowRemoteTools', 'AllowCertThumbprints', 'AllowPaths')) {
        $cfg[$k] = @(ConvertTo-StrArray $cfg[$k] | Where-Object { $_ })
    }
    return $cfg
}

function Test-Allowed {
    # true se l'elemento e' stato dichiarato autorizzato in config.json
    param([string]$Key, [string]$KeyType)
    if (-not $Key -or $null -eq $script:Config) { return $false }
    switch ($KeyType) {
        'ext' { return @($script:Config['AllowExtensionIds'] | Where-Object { $_ -ieq $Key }).Count -gt 0 }
        'cert' { return @($script:Config['AllowCertThumbprints'] | Where-Object { $_.Replace(' ', '') -ieq $Key }).Count -gt 0 }
        'remote' { return @($script:Config['AllowRemoteTools'] | Where-Object { $Key.ToLowerInvariant().Contains($_.ToLowerInvariant()) }).Count -gt 0 }
        'path' { return @($script:Config['AllowPaths'] | Where-Object { $Key.ToLowerInvariant().StartsWith($_.ToLowerInvariant()) }).Count -gt 0 }
    }
    return $false
}

function Add-Finding {
    param(
        [ValidateSet('ALTA', 'MEDIA', 'BASSA')][string]$Severity,
        [string]$Category, [string]$Title, [string]$Detail = '', [string]$Advice = '',
        [string]$Key = '', [ValidateSet('', 'ext', 'cert', 'remote', 'path')][string]$KeyType = ''
    )
    foreach ($ex in $script:Findings) {
        if ($ex.Titolo -eq $Title -and $ex.Dettaglio -eq $Detail) { return }
    }
    if ($Key -and $KeyType -and (Test-Allowed $Key $KeyType)) {
        $Severity = 'BASSA'
        $Title = '[AUTORIZZATO] ' + $Title
        $Advice = "Segnato come autorizzato in config.json. Toglierlo dall'elenco se non e' piu' necessario."
    }
    $script:Findings.Add([pscustomobject]@{
            Gravita = $Severity; Categoria = $Category; Titolo = $Title; Dettaglio = $Detail; Consiglio = $Advice
        })
}

function Write-Msg {
    # Scrive in console e, se presente, nel registro dell'interfaccia grafica
    param([string]$Text, [string]$Color = 'Gray')
    try { Write-Host $Text -ForegroundColor $Color } catch { }
    if ($script:Sync -and $script:Sync.ContainsKey('Log')) {
        try { [void]$script:Sync.Log.Add([pscustomobject]@{ Ora = (Get-Date).ToString('HH:mm:ss'); Testo = $Text; Colore = $Color }) } catch { }
    }
}

function Get-SevLabel {
    # Etichette mostrate all'utente: ALTA = problema confermato, MEDIA = da controllare, BASSA = dettaglio tecnico
    param([string]$Severity)
    switch ($Severity) { 'ALTA' { return 'CONFERMATO' } 'MEDIA' { return 'DA CONTROLLARE' } default { return 'DETTAGLIO' } }
}

function Test-DomainJoined {
    if ($null -ne $script:DomainJoined) { return $script:DomainJoined }
    $script:DomainJoined = $false
    try { $script:DomainJoined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }
    return $script:DomainJoined
}

function Test-PrivateIp {
    param([string]$Ip)
    return ($Ip -match '^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)' -or $Ip -match '^(::1|fe80:|fc|fd)')
}

function Test-Cancel {
    return [bool]($script:Sync -and $script:Sync['Cancel'])
}

function Set-Progress {
    param([int]$Step, [int]$Total, [string]$Name, [int]$Percent = -1)
    if ($Percent -lt 0) { $Percent = [int](100 * [math]::Max(0, $Step - 1) / [math]::Max(1, $Total)) }
    if ($script:Sync) {
        $script:Sync['Step'] = $Step; $script:Sync['Total'] = $Total; $script:Sync['Name'] = $Name; $script:Sync['Percent'] = $Percent
    } else {
        try { Write-Progress -Activity "$($script:AppName) - analisi in corso" -Status ("Passo {0} di {1}: {2}" -f $Step, $Total, $Name) -PercentComplete $Percent } catch { }
    }
}

function Join-Parts {
    param([string]$Base, [string[]]$Parts)
    $p = $Base
    foreach ($x in $Parts) { $p = Join-Path $p $x }
    return $p
}

function Test-IbanChecksum {
    param([string]$Iban)
    if (-not $Iban) { return $false }
    $s = ($Iban -replace '[\s-]', '').ToUpperInvariant()
    if ($s -notmatch '^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$') { return $false }
    if ($s.StartsWith('IT') -and $s.Length -ne 27) { return $false }
    $r = $s.Substring(4) + $s.Substring(0, 4)
    $rem = 0
    foreach ($ch in $r.ToCharArray()) {
        if ($ch -ge 'A' -and $ch -le 'Z') { $v = [string]([int][char]$ch - 55) } else { $v = [string]$ch }
        foreach ($d in $v.ToCharArray()) { $rem = ($rem * 10 + [int][string]$d) % 97 }
    }
    return ($rem -eq 1)
}

function Find-Ibans {
    # Restituisce gli IBAN (normalizzati, senza spazi) trovati in un testo
    param([string]$Text)
    $out = New-Object 'System.Collections.Generic.List[string]'
    if (-not $Text) { return @() }
    $ms = [regex]::Matches($Text.ToUpperInvariant(), '\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}\b')
    foreach ($m in $ms) {
        $n = $m.Value -replace '[\s-]', ''
        # prova anche a togliere caratteri finali in eccesso (es. testo attaccato)
        $found = $null
        for ($len = $n.Length; $len -ge 15; $len--) {
            $c = $n.Substring(0, $len)
            if (Test-IbanChecksum $c) { $found = $c; break }
        }
        if ($found -and -not $out.Contains($found)) { $out.Add($found) }
    }
    return $out.ToArray()
}

function Get-ExePathFromCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|wsf|com|scr|hta|msi|cpl))(?=\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

function Get-PathRisk {
    # 2 = cartella scrivibile dall'utente tipica del malware, 1 = cartella utente, 0 = altro
    param([string]$Path)
    if (-not $Path) { return 0 }
    $p = $Path.ToLowerInvariant().Replace('/', '\')
    if ($p -match '\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\appdata\\roaming\\|\\programdata\\|\\\$recycle\.bin\\|\\appdata\\locallow\\|\\appdata\\local\\[^\\]+\.(exe|dll|scr)$') { return 2 }
    if ($p -match '\\downloads\\|\\desktop\\|\\documents\\|\\appdata\\local\\|\\onedrive') { return 1 }
    return 0
}

function ConvertFrom-ChromeTime {
    param($Value)
    try {
        $v = [int64]([string]$Value)
        if ($v -le 0) { return '' }
        return [DateTime]::FromFileTimeUtc($v * 10).ToLocalTime().ToString('yyyy-MM-dd HH:mm')
    } catch { return '' }
}

function Read-JsonFile {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
        $txt = [IO.File]::ReadAllText($Path)
        if ([string]::IsNullOrWhiteSpace($txt)) { return $null }
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            return ($txt | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
        }
        if (-not $script:JsSer) {
            Add-Type -AssemblyName System.Web.Extensions
            $script:JsSer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $script:JsSer.MaxJsonLength = [int]::MaxValue
            $script:JsSer.RecursionLimit = 1000
        }
        return $script:JsSer.DeserializeObject($txt)
    } catch {
        Write-Verbose "JSON non leggibile: $Path - $($_.Exception.Message)"
        return $null
    }
}

function Test-DKey {
    param($Dict, [string]$Key)
    if ($null -eq $Dict -or -not ($Dict -is [System.Collections.IDictionary])) { return $false }
    if ($Dict.PSObject.Methods['ContainsKey']) { return [bool]$Dict.ContainsKey($Key) }
    return [bool]$Dict.Contains($Key)
}

function Get-DVal {
    param($Obj, [string]$Path)
    $cur = $Obj
    foreach ($k in $Path.Split('.')) {
        if (-not (Test-DKey $cur $k)) { return $null }
        $cur = $cur[$k]
    }
    return $cur
}

function ConvertTo-StrArray {
    param($Value)
    $o = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Value) { return $o.ToArray() }
    if ($Value -is [string]) { $o.Add($Value); return $o.ToArray() }
    foreach ($x in $Value) {
        if ($null -eq $x) { continue }
        if ($x -is [string]) { $o.Add($x) }
        elseif ($x -is [System.Collections.IDictionary]) {
            # es. permessi opzionali/oggetti: prendi i valori stringa
            foreach ($k in $x.Keys) { if ($x[$k] -is [string]) { $o.Add([string]$x[$k]) } }
        } else { $o.Add([string]$x) }
    }
    return $o.ToArray()
}

function Test-BroadHost {
    param([string]$Pattern)
    if (-not $Pattern) { return $false }
    return ($Pattern -match '^(<all_urls>|\*://\*/.*|https?://\*/.*|file:///.*|\*://\*|https?://\*)$')
}

function Test-BankHost {
    param([string]$Pattern, [string[]]$BankDomains)
    if (-not $Pattern) { return $false }
    foreach ($d in $BankDomains) {
        $k = ($d -replace '^\*?\.', '')
        if ($k -and $Pattern.ToLowerInvariant().Contains($k.ToLowerInvariant())) { return $true }
    }
    return $false
}

function Get-ExtensionRisk {
    param(
        [int]$LocationCode, [string[]]$Hosts, [string[]]$ContentMatches, [string[]]$Perms,
        [bool]$FromStore, [string[]]$BankDomains
    )
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    $sev = ''
    $allHosts = @($Hosts) + @($ContentMatches)
    $broad = @($allHosts | Where-Object { Test-BroadHost $_ }).Count -gt 0
    $bank = @($allHosts | Where-Object { Test-BankHost $_ $BankDomains }).Count -gt 0
    $danger = @($Perms | Where-Object { $script:DangerPerms -contains $_ })

    if ($LocationCode -in 5, 10) { return [pscustomobject]@{ Severity = ''; Reasons = 'componente del browser' } }
    $offStore = ($LocationCode -in 4, 8) -or ((-not $FromStore) -and ($LocationCode -notin 7, 9))
    if ($LocationCode -in 4, 8) { $reasons.Add('installata fuori dallo store (' + $script:ChromeLocation[$LocationCode] + ')') }
    elseif ($offStore) { $reasons.Add('non proviene dallo store ufficiale') }
    if ($bank) { $reasons.Add('ha accesso esplicito al sito della banca') }
    if ($broad) { $reasons.Add('puo'' leggere e modificare tutti i siti, compresa la banca') }
    if ($LocationCode -in 2, 3, 6) { $reasons.Add('installata da un altro programma (' + $script:ChromeLocation[$LocationCode] + ')') }
    if ($LocationCode -in 7, 9) { $reasons.Add('imposta da criterio/policy') }
    if ($danger.Count -gt 0) { $reasons.Add('permessi sensibili: ' + ($danger -join ', ')) }
    # CONFERMATO: combinazioni che un'estensione legittima installata normalmente non ha
    if (($LocationCode -in 4, 8) -and ($broad -or $bank)) { $sev = 'ALTA' }
    elseif ($bank -and $offStore) { $sev = 'ALTA' }
    elseif ($broad -and $offStore) { $sev = 'ALTA' }
    # DA CONTROLLARE: fatti certi ma con spiegazioni legittime possibili
    elseif ($LocationCode -in 4, 8) { $sev = 'MEDIA' }
    elseif ($bank) { $sev = 'MEDIA' }
    elseif ($broad -and $LocationCode -in 2, 3, 6) { $sev = 'MEDIA' }
    # DETTAGLIO: estensioni dello store con accesso a tutti i siti (adblock, gestori password...)
    elseif ($broad) { $sev = 'BASSA' }
    return [pscustomobject]@{ Severity = $sev; Reasons = ($reasons -join '; ') }
}

function Resolve-ExtName {
    param($Manifest, [string]$ExtDir)
    $n = [string](Get-DVal $Manifest 'name')
    if ($n -match '^__MSG_(.+)__$' -and $ExtDir) {
        $key = $Matches[1]
        $cands = @()
        $dl = [string](Get-DVal $Manifest 'default_locale')
        if ($dl) { $cands += $dl }
        $cands += @('it', 'en', 'en_US')
        foreach ($l in $cands) {
            $m = Read-JsonFile (Join-Parts $ExtDir @('_locales', $l, 'messages.json'))
            if ($null -eq $m) { continue }
            foreach ($kk in @($m.Keys)) {
                if ($kk -ieq $key) {
                    $msg = Get-DVal $m[$kk] 'message'
                    if ($msg) { return [string]$msg }
                }
            }
        }
    }
    return $n
}

function Get-SigInfo {
    param([string]$Path)
    if (-not $Path) { return [pscustomobject]@{ Status = 'N/D'; Signer = '' } }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $r = $null
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $r = [pscustomobject]@{ Status = 'FileNonTrovato'; Signer = '' }
    } elseif (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        $r = [pscustomobject]@{ Status = 'N/D'; Signer = '' }
    } else {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $signer = ''
            if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject }
            $r = [pscustomobject]@{ Status = [string]$s.Status; Signer = $signer }
        } catch { $r = [pscustomobject]@{ Status = 'Errore'; Signer = '' } }
    }
    $script:SigCache[$Path] = $r
    return $r
}

function Get-BinaryRisk {
    # '' | 'BASSA' | 'MEDIA' | 'ALTA'
    param([string]$Path, $Sig)
    if (-not $Path) { return '' }
    if ($null -eq $Sig) { $Sig = Get-SigInfo $Path }
    if ($Sig.Status -eq 'HashMismatch') { return 'ALTA' }
    $unsigned = $Sig.Status -in @('NotSigned', 'NotTrusted', 'UnknownError', 'NotSupportedFileFormat')
    if (-not $unsigned) { return '' }
    $pr = Get-PathRisk $Path
    if ($pr -eq 2) { return 'ALTA' }
    if ($pr -eq 1) { return 'MEDIA' }
    return 'BASSA'
}

function Get-FileSha256 {
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return '' }
}

function Get-HostsEntries {
    param([string]$Path, [string[]]$BankDomains)
    $res = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Test-Path -LiteralPath $Path)) { return $res.ToArray() }
    $n = 0
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $n++
        $l = ($line -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        $parts = $l -split '\s+'
        if ($parts.Count -lt 2) { continue }
        $ip = $parts[0]
        foreach ($h in $parts[1..($parts.Count - 1)]) {
            $isLocal = ($h -ieq 'localhost') -or ($h -ieq 'localhost.localdomain')
            $res.Add([pscustomobject]@{
                    Riga = $n; IP = $ip; Host = $h; Banca = [bool](Test-BankHost $h $BankDomains); Localhost = $isLocal
                })
        }
    }
    return $res.ToArray()
}

function Get-UserProfileDirs {
    $list = New-Object 'System.Collections.Generic.List[string]'
    if ($script:IsWin -and $script:IsAdmin) {
        $root = $null
        try { $root = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop).ProfilesDirectory) } catch { }
        if (-not $root) { $root = Join-Path $env:SystemDrive 'Users' }
        foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
            if ($d.Name -in @('Public', 'Default', 'Default User', 'All Users', 'defaultuser0')) { continue }
            if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            $list.Add($d.FullName)
        }
    }
    $me = $env:USERPROFILE
    if (-not $me) { $me = $HOME }
    if ($me -and -not $list.Contains($me)) { $list.Add($me) }
    return $list.ToArray()
}

function Get-UserHives {
    # HKCU di tutti gli utenti caricati (con admin), altrimenti solo HKCU
    $o = New-Object 'System.Collections.Generic.List[object]'
    if (-not $script:IsWin) { return $o.ToArray() }
    $o.Add([pscustomobject]@{ Name = $env:USERNAME; Root = 'HKCU:' })
    if ($script:IsAdmin) {
        $mySid = ''
        try { $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { }
        foreach ($k in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
            $sid = $k.PSChildName
            if ($sid -notmatch '^S-1-5-21-[\d-]+$' -or $sid -eq $mySid) { continue }
            $nm = $sid
            try { $nm = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
            $o.Add([pscustomobject]@{ Name = $nm; Root = "Registry::HKEY_USERS\$sid" })
        }
    }
    return $o.ToArray()
}

function Invoke-Section {
    param([string]$Name, [string]$CsvName, [scriptblock]$Script)
    $script:StepNo++
    Set-Progress $script:StepNo $script:StepTotal $Name
    if (Test-Cancel) {
        $script:Sections.Add([pscustomobject]@{ Sezione = $Name; Stato = 'Annullato'; Righe = 0; Secondi = 0; File = ''; Errore = '' })
        return
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'; $err = ''; $rows = 0; $file = ''
    $before = $script:Findings.Count
    try {
        $data = @(& $Script | ForEach-Object { $_ })
        $rows = $data.Count
        if ($CsvName) { $script:SectionData[$CsvName] = $data }
        if ($CsvName -and $rows -gt 0 -and $script:OutDir) {
            $file = "$CsvName.csv"
            $data | Export-Csv -LiteralPath (Join-Path $script:OutDir $file) -NoTypeInformation -Delimiter ';' -Encoding $script:CsvEnc
        }
    } catch {
        $status = 'Non disponibile'; $err = $_.Exception.Message
    }
    $new = @($script:Findings | Select-Object -Skip $before)
    $na = @($new | Where-Object { $_.Gravita -eq 'ALTA' }).Count
    $nm = @($new | Where-Object { $_.Gravita -eq 'MEDIA' }).Count
    $tag = ('[{0,2}/{1}]' -f $script:StepNo, $script:StepTotal)
    if ($status -ne 'OK') { Write-Msg ("{0} {1}: non disponibile ({2})" -f $tag, $Name, $err) 'DarkYellow' }
    elseif ($na) { Write-Msg ("{0} {1}: {2} problemi GRAVI, {3} da verificare" -f $tag, $Name, $na, $nm) 'Red' }
    elseif ($nm) { Write-Msg ("{0} {1}: {2} elementi da verificare" -f $tag, $Name, $nm) 'Yellow' }
    else { Write-Msg ("{0} {1}: OK ({2} elementi controllati, {3:N1} s)" -f $tag, $Name, $rows, $sw.Elapsed.TotalSeconds) 'Green' }
    $script:Sections.Add([pscustomobject]@{
            Sezione = $Name; Stato = $status; Righe = $rows; Secondi = [math]::Round($sw.Elapsed.TotalSeconds, 1); File = $file; Errore = $err
        })
}

# ----------------------------------------------------------------------------------------------
#  Funzioni native (memoria dei processi, nomi dispositivo)
# ----------------------------------------------------------------------------------------------
$script:NativeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace CyberRSecNative {
    public class MemHit {
        public int Pid;
        public long Address;
        public long Size;
        public uint Protect;
        public string Kind;
    }

    public static class Mem {
        [StructLayout(LayoutKind.Sequential)]
        public struct MBI {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
        [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern uint QueryDosDevice(string dev, StringBuilder target, int max);

        const uint PROCESS_QUERY_INFORMATION = 0x400;
        const uint PROCESS_VM_READ = 0x10;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_PRIVATE = 0x20000;

        // Analizza le regioni di memoria PRIVATE ed ESEGUIBILI di un processo cercando un eseguibile (MZ/PE)
        // caricato senza passare dal disco: tipico dei malware che si iniettano nel browser (man-in-the-browser).
        public static List<MemHit> Scan(int pid, out string error) {
            List<MemHit> hits = new List<MemHit>();
            error = null;
            IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (h == IntPtr.Zero) { error = "accesso negato"; return hits; }
            try {
                long addr = 0;
                long max = IntPtr.Size == 8 ? 0x7FFFFFFEFFFFL : 0x7FFEFFFFL;
                IntPtr sz = (IntPtr)Marshal.SizeOf(typeof(MBI));
                byte[] buf = new byte[1024];
                int guard = 0;
                while (addr < max && guard++ < 500000) {
                    MBI m;
                    if (VirtualQueryEx(h, (IntPtr)addr, out m, sz) == IntPtr.Zero) break;
                    long rsize = m.RegionSize.ToInt64();
                    if (rsize <= 0) break;
                    bool exec = (m.Protect & 0xF0) != 0;
                    bool noAccess = (m.Protect & 0x01) != 0 || (m.Protect & 0x100) != 0;
                    if (m.State == MEM_COMMIT && m.Type == MEM_PRIVATE && exec && !noAccess) {
                        IntPtr read;
                        if (ReadProcessMemory(h, m.BaseAddress, buf, (IntPtr)buf.Length, out read) && read.ToInt64() >= 64) {
                            if (buf[0] == 0x4D && buf[1] == 0x5A) {
                                int e = BitConverter.ToInt32(buf, 0x3C);
                                MemHit hit = new MemHit();
                                hit.Pid = pid; hit.Address = m.BaseAddress.ToInt64(); hit.Size = rsize; hit.Protect = m.Protect;
                                if (e > 0 && e < buf.Length - 4 && buf[e] == 0x50 && buf[e + 1] == 0x45 && buf[e + 2] == 0 && buf[e + 3] == 0)
                                    hit.Kind = "eseguibile completo (MZ+PE) in memoria privata eseguibile";
                                else
                                    hit.Kind = "intestazione MZ in memoria privata eseguibile";
                                hits.Add(hit);
                            }
                        }
                    }
                    long next = m.BaseAddress.ToInt64() + rsize;
                    if (next <= addr) break;
                    addr = next;
                }
            } finally { CloseHandle(h); }
            return hits;
        }

        public static string DosDevice(string drive) {
            StringBuilder sb = new StringBuilder(1024);
            return QueryDosDevice(drive, sb, 1024) > 0 ? sb.ToString() : null;
        }
    }
}
'@

function Initialize-CyberNative {
    if ('CyberRSecNative.Mem' -as [type]) { return $true }
    try { Add-Type -TypeDefinition $script:NativeSource -Language CSharp -ErrorAction Stop; return $true } catch { Write-Verbose $_.Exception.Message; return $false }
}

function Get-DeviceMap {
    # \Device\HarddiskVolume3 -> C:
    $map = @{}
    if (-not (Initialize-CyberNative)) { return $map }
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        if ($d.Name -notmatch '^[A-Za-z]:') { continue }
        $letter = $d.Name.Substring(0, 2)
        try { $t = [CyberRSecNative.Mem]::DosDevice($letter); if ($t) { $map[$t] = $letter } } catch { }
    }
    return $map
}

function Convert-DevicePath {
    param([string]$Path, [hashtable]$Map)
    if (-not $Path) { return '' }
    $m = [regex]::Match($Path, '^(\\Device\\[^\\]+)(\\.*)$')
    if ($m.Success -and $Map -and $Map.ContainsKey($m.Groups[1].Value)) { return $Map[$m.Groups[1].Value] + $m.Groups[2].Value }
    return $Path
}

# ----------------------------------------------------------------------------------------------
#  Classificatori (funzioni pure, testate)
# ----------------------------------------------------------------------------------------------
function Get-RunCommandRisk {
    # Comandi digitati/incollati in Esegui (Win+R) o nella barra di Esplora file: tecniche ClickFix / FileFix.
    # CONFERMATO solo se il comando scarica ed esegue codice: digitare "powershell" o "cmd" da soli non conta.
    param([string]$Command)
    if (-not $Command) { return '' }
    $c = $Command -replace '\\1$', ''
    $download = '(?i)https?://|\bcurl\b|\bwget\b|\biwr\b|\birm\b|invoke-(webrequest|restmethod)|downloadstring|downloadfile|net\.webclient|bitsadmin|start-bitstransfer|certutil.*-urlcache|\bfinger\b'
    $exec = '(?i)powershell|pwsh|mshta|\biex\b|invoke-expression|cmd(\.exe)?\s*/[ck]|msiexec|rundll32|regsvr32|wscript|cscript|\|\s*(cmd|sh|iex)\b|frombase64'
    if ($c -match $download -and $c -match $exec) { return 'ALTA' }
    if ($c -match '(?i)(powershell|pwsh).*\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{40,}') { return 'ALTA' }
    if ($c -match '(?i)mshta(\.exe)?\s+\S+') { return 'ALTA' }
    return ''
}

function Get-PsHistoryRisk {
    param([string]$Line)
    if (-not $Line) { return '' }
    if ($Line -match '(?i)cyberrsecuritycheck') { return '' }
    if ($Line -match '(?i)add-mppreference\s.*-exclusion|set-mppreference\s.*-disable(realtime|behavior|ioav|scriptscanning)') { return 'MEDIA' }
    $dl = '(?i)downloadstring|downloadfile|\biwr\b|invoke-webrequest|\birm\b|invoke-restmethod|net\.webclient|start-bitstransfer'
    $ex = '(?i)\biex\b|invoke-expression|\|\s*(iex|invoke-expression)|start-process|&\s*\$|frombase64string|reflection\.assembly.*load'
    if ($Line -match $dl -and $Line -match $ex) { return 'MEDIA' }
    return ''
}

function Test-RamnitHtml {
    # Ramnit infetta i file .htm/.html aggiungendo in coda un VBScript che scrive "svchost.exe"
    param([string]$Text)
    if (-not $Text) { return $false }
    return ($Text -match '(?i)DropFileName\s*=\s*"svchost\.exe"' -or $Text -match '(?i)WriteData\s*=\s*"4D5A')
}

function Get-ArpAnomalies {
    # Righe: IP, MAC. Restituisce i MAC usati da piu' IP (possibile ARP spoofing se include il gateway)
    param($Rows, [string[]]$Gateways)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $groups = @($Rows | Where-Object {
            $_.MAC -and $_.MAC -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E-.*|33-33-.*)$' -and
            $_.IP -notmatch '^(22[4-9]|23\d|255)\.|\.255$'
        } | Group-Object MAC | Where-Object { $_.Count -gt 1 })
    foreach ($g in $groups) {
        $ips = @($g.Group | ForEach-Object { $_.IP })
        $gw = @($ips | Where-Object { $Gateways -contains $_ }).Count -gt 0
        $out.Add([pscustomobject]@{ MAC = $g.Name; IP = ($ips -join ', '); Gateway = $gw })
    }
    return $out.ToArray()
}

function Get-SecurityScore {
    param([int]$Alta, [int]$Media, [int]$Critici, [int]$Attenzione)
    $s = 100 - [math]::Min(70, 20 * $Alta) - [math]::Min(25, 3 * $Media) - [math]::Min(15, 4 * $Critici) - [math]::Min(10, 1 * $Attenzione)
    if ($s -lt 0) { $s = 0 }
    if ($Alta -gt 0 -and $s -gt 49) { $s = 49 }
    $v = 'Buono'
    if ($s -lt 85) { $v = 'Da migliorare' }
    if ($s -lt 60) { $v = 'A rischio' }
    if ($s -lt 30) { $v = 'Critico' }
    return [pscustomobject]@{ Punteggio = [int]$s; Giudizio = $v }
}

# ----------------------------------------------------------------------------------------------
#  Nuovi controlli
# ----------------------------------------------------------------------------------------------
function Add-HardeningRow {
    param($Rows, [string]$Area, [string]$Check, [ValidateSet('OK', 'ATTENZIONE', 'CRITICO', 'INFO', 'N.D.')][string]$State, [string]$Value, [string]$Advice, [string]$FindingSeverity = '')
    $Rows.Add([pscustomobject]@{ Area = $Area; Controllo = $Check; Stato = $State; Valore = $Value; Consiglio = $Advice })
    if ($FindingSeverity) { Add-Finding $FindingSeverity 'Configurazione' "$Check : $Value" $Area $Advice }
}

function Get-RegValue {
    param([string]$Key, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Get-HardeningChecks {
    param([string[]]$UserDirs)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if (-not $script:IsWin) { throw 'Controlli disponibili solo su Windows' }

    # Sistema operativo
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $build = [int]$os.BuildNumber
        $caption = [string]$os.Caption
        $st = 'OK'; $adv = ''
        if ($caption -match 'Windows 10') { $st = 'CRITICO'; $adv = 'Windows 10 non riceve piu'' aggiornamenti di sicurezza gratuiti dal 14/10/2025: passare a Windows 11 o attivare gli ESU.' }
        elseif ($caption -match 'Windows 11' -and $build -lt 26100) { $st = 'ATTENZIONE'; $adv = 'Versione di Windows 11 vecchia: per Home/Pro non e'' piu'' supportata. Aggiornare alla 24H2 o successiva.' }
        Add-HardeningRow $rows 'Sistema' 'Versione di Windows supportata' $st "$caption build $build" $adv
    } catch { }
    try {
        $hf = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
        if ($hf.Count -gt 0) {
            $last = [datetime]$hf[0].InstalledOn
            $days = [int]((Get-Date) - $last).TotalDays
            $st = 'OK'
            if ($days -gt 120) { $st = 'CRITICO' } elseif ($days -gt 45) { $st = 'ATTENZIONE' }
            Add-HardeningRow $rows 'Sistema' 'Aggiornamenti Windows recenti' $st ("ultimo aggiornamento {0:dd/MM/yyyy} ({1} giorni fa)" -f $last, $days) 'Installare gli aggiornamenti: molti malware sfruttano falle gia'' corrette.'
        }
    } catch { }

    # UAC
    $uk = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua = Get-RegValue $uk 'EnableLUA'
    if ($null -ne $lua) {
        if ($lua -eq 0) { Add-HardeningRow $rows 'Account' 'Controllo account utente (UAC) attivo' 'CRITICO' 'UAC disattivato' 'Riattivare UAC: senza, qualsiasi programma ottiene i privilegi di amministratore.' }
        else {
            $cp = Get-RegValue $uk 'ConsentPromptBehaviorAdmin'
            if ($cp -eq 0) { Add-HardeningRow $rows 'Account' 'Controllo account utente (UAC) attivo' 'CRITICO' 'UAC attivo ma senza richiesta di conferma' 'Impostare UAC almeno al livello predefinito.' }
            else { Add-HardeningRow $rows 'Account' 'Controllo account utente (UAC) attivo' 'OK' "attivo (livello $cp)" '' }
        }
    }
    # Account Guest
    try {
        $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID -like '*-501' }
        if ($g) { if ($g.Enabled) { Add-HardeningRow $rows 'Account' 'Account Guest disattivato' 'CRITICO' 'Guest attivo' 'Disattivare l''account Guest.' } else { Add-HardeningRow $rows 'Account' 'Account Guest disattivato' 'OK' 'disattivato' '' } }
    } catch { }

    # Firewall
    try {
        foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            if ($p.Enabled) { Add-HardeningRow $rows 'Rete' "Firewall attivo (profilo $($p.Name))" 'OK' 'attivo' '' }
            else { Add-HardeningRow $rows 'Rete' "Firewall attivo (profilo $($p.Name))" 'CRITICO' 'DISATTIVATO' 'Riattivare Windows Firewall (o verificare che un firewall di terze parti lo sostituisca).' }
        }
    } catch { }
    # SMBv1
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smb.EnableSMB1Protocol) { Add-HardeningRow $rows 'Rete' 'Protocollo SMBv1 disattivato' 'CRITICO' 'SMBv1 attivo' 'Disattivare SMBv1: protocollo obsoleto usato da ransomware (es. WannaCry).' }
        else { Add-HardeningRow $rows 'Rete' 'Protocollo SMBv1 disattivato' 'OK' 'disattivato' '' }
    } catch { }
    # RDP + NLA
    $deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($deny -eq 0) {
        $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        if ($nla -ne 1) { Add-HardeningRow $rows 'Rete' 'Desktop remoto protetto (NLA)' 'CRITICO' 'RDP attivo senza NLA' 'Disattivare RDP o almeno attivare l''autenticazione a livello di rete (NLA).' }
        else { Add-HardeningRow $rows 'Rete' 'Desktop remoto protetto (NLA)' 'ATTENZIONE' 'RDP attivo con NLA' 'Se non serve, disattivare il Desktop remoto sul PC dei bonifici.' }
    } elseif ($null -ne $deny) { Add-HardeningRow $rows 'Rete' 'Desktop remoto disattivato' 'OK' 'disattivato' '' }

    # Credenziali
    $wd = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    if ($wd -eq 1) { Add-HardeningRow $rows 'Credenziali' 'WDigest disattivato (password non in chiaro in memoria)' 'CRITICO' 'UseLogonCredential = 1' 'Impostazione usata dagli attaccanti per leggere le password in chiaro: riportarla a 0 e cambiare le password.' 'MEDIA' }
    else { Add-HardeningRow $rows 'Credenziali' 'WDigest disattivato (password non in chiaro in memoria)' 'OK' 'disattivato' '' }
    $ppl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    if ($ppl -in 1, 2) { Add-HardeningRow $rows 'Credenziali' 'Protezione LSA (RunAsPPL)' 'OK' 'attiva' '' }
    else { Add-HardeningRow $rows 'Credenziali' 'Protezione LSA (RunAsPPL)' 'ATTENZIONE' 'non attiva' 'Consigliato attivarla: rende piu'' difficile rubare le credenziali di Windows dalla memoria.' }

    # Antivirus
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $other = @()
            try { $other = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Where-Object { $_.displayName -notmatch 'Defender' }) } catch { }
            if ($mp.RealTimeProtectionEnabled) { Add-HardeningRow $rows 'Antivirus' 'Protezione antivirus in tempo reale' 'OK' 'Microsoft Defender attivo' '' }
            elseif ($other.Count -gt 0) { Add-HardeningRow $rows 'Antivirus' 'Protezione antivirus in tempo reale' 'OK' ('antivirus: ' + (($other | ForEach-Object { $_.displayName }) -join ', ')) '' }
            else { Add-HardeningRow $rows 'Antivirus' 'Protezione antivirus in tempo reale' 'CRITICO' 'nessun antivirus attivo' 'Riattivare Microsoft Defender: molti malware lo disattivano.' }
            if ($mp.IsTamperProtected) { Add-HardeningRow $rows 'Antivirus' 'Protezione anti-manomissione' 'OK' 'attiva' '' } elseif ($mp.RealTimeProtectionEnabled) { Add-HardeningRow $rows 'Antivirus' 'Protezione anti-manomissione' 'ATTENZIONE' 'non attiva' 'Attivarla in Sicurezza di Windows: impedisce ai malware di disattivare Defender.' }
            $pref = Get-MpPreference -ErrorAction SilentlyContinue
            if ($pref -and $mp.RealTimeProtectionEnabled) {
                if ($pref.PUAProtection -eq 1) { Add-HardeningRow $rows 'Antivirus' 'Blocco app potenzialmente indesiderate (PUA)' 'OK' 'attivo' '' } else { Add-HardeningRow $rows 'Antivirus' 'Blocco app potenzialmente indesiderate (PUA)' 'ATTENZIONE' 'non attivo' 'Attivare il blocco PUA (Set-MpPreference -PUAProtection Enabled).' }
            }
        } catch { }
    }
    # SmartScreen
    $ss = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
    $ssPol = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
    if ($ss -eq 'Off' -or $ssPol -eq 0) { Add-HardeningRow $rows 'Antivirus' 'SmartScreen attivo' 'CRITICO' 'disattivato' 'Riattivare SmartScreen: blocca file e siti malevoli noti.' }
    else { Add-HardeningRow $rows 'Antivirus' 'SmartScreen attivo' 'OK' 'attivo' '' }

    # Disco e avvio
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            if ([string]$bl.ProtectionStatus -eq 'On') { Add-HardeningRow $rows 'Dati' 'Cifratura del disco (BitLocker)' 'OK' 'attiva' '' }
            else { Add-HardeningRow $rows 'Dati' 'Cifratura del disco (BitLocker)' 'ATTENZIONE' 'non attiva' 'Consigliata sui portatili: protegge i dati in caso di furto.' }
        } catch { }
    }
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) { Add-HardeningRow $rows 'Sistema' 'Avvio protetto (Secure Boot)' 'OK' 'attivo' '' } else { Add-HardeningRow $rows 'Sistema' 'Avvio protetto (Secure Boot)' 'ATTENZIONE' 'non attivo' 'Attivarlo nel BIOS/UEFI: protegge da bootkit.' }
    } catch { }

    # Script e macro
    $wsh = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled'
    if ($wsh -eq 0) { Add-HardeningRow $rows 'Script' 'Windows Script Host (VBS/JS) disattivato' 'OK' 'disattivato' '' }
    else { Add-HardeningRow $rows 'Script' 'Windows Script Host (VBS/JS) disattivato' 'INFO' 'attivo' 'Sul PC dei bonifici si puo'' disattivare: blocca molti allegati malevoli .vbs/.js.' }
    $sbl = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    if ($sbl -eq 1) { Add-HardeningRow $rows 'Script' 'Registrazione script PowerShell' 'OK' 'attiva' '' }
    else { Add-HardeningRow $rows 'Script' 'Registrazione script PowerShell' 'INFO' 'non attiva' 'Attivarla (criteri di gruppo) aiuta molto le indagini future.' }
    foreach ($h in (Get-UserHives)) {
        foreach ($ver in @('16.0', '15.0')) {
            foreach ($app in @('Word', 'Excel')) {
                $k = "$($h.Root)\Software\Microsoft\Office\$ver\$app\Security"
                $vw = Get-RegValue $k 'VBAWarnings'
                if ($null -eq $vw) { continue }
                if ($vw -eq 1) { Add-HardeningRow $rows 'Script' "Macro Office $app ($($h.Name))" 'CRITICO' 'TUTTE le macro abilitate' 'Impostare "Disattiva macro con notifica": le macro sono il primo vettore di infezione via email/PEC.' }
                else { Add-HardeningRow $rows 'Script' "Macro Office $app ($($h.Name))" 'OK' "livello $vw" '' }
            }
        }
    }
    $ar = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    if ($ar -eq 255) { Add-HardeningRow $rows 'Sistema' 'Esecuzione automatica da USB disattivata' 'OK' 'disattivata' '' }
    else { Add-HardeningRow $rows 'Sistema' 'Esecuzione automatica da USB disattivata' 'INFO' 'predefinita' 'Consigliato disattivare l''AutoRun di tutte le unita''.' }

    # Password salvate nei browser (bersaglio degli infostealer)
    foreach ($ud in $UserDirs) {
        foreach ($b in $script:ChromiumBrowsers) {
            foreach ($prof in (Get-ChromiumProfiles (Join-Parts $ud $b.Parts))) {
                $ld = Join-Path $prof 'Login Data'
                if (Test-Path -LiteralPath $ld) {
                    $len = (Get-Item -LiteralPath $ld).Length
                    if ($len -gt 40KB) { Add-HardeningRow $rows 'Credenziali' "Password salvate in $($b.Name) ($(Split-Path $ud -Leaf)/$(Split-Path $prof -Leaf))" 'ATTENZIONE' ("archivio password {0:N0} KB" -f ($len / 1KB)) 'Non salvare nel browser le credenziali della banca: un infostealer le copia in pochi secondi. Usare un gestore password dedicato.' }
                }
            }
        }
        $ffp = Join-Parts $ud @('AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
        foreach ($p in @(Get-ChildItem -LiteralPath $ffp -Directory -ErrorAction SilentlyContinue)) {
            $lj = Join-Path $p.FullName 'logins.json'
            if ((Test-Path -LiteralPath $lj) -and (Get-Item -LiteralPath $lj).Length -gt 2KB) { Add-HardeningRow $rows 'Credenziali' "Password salvate in Firefox ($(Split-Path $ud -Leaf))" 'ATTENZIONE' 'presenti' 'Non salvare nel browser le credenziali della banca. Impostare almeno una password principale.' }
        }
    }
    return $rows.ToArray()
}

function Get-ExecutionHistory {
    # BAM (Background Activity Moderator): percorso completo e ultima esecuzione dei programmi per utente
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $map = Get-DeviceMap
    $roots = @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')
    foreach ($r in $roots) {
        foreach ($k in @(Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue)) {
            $sid = $k.PSChildName
            $user = $sid
            try { $user = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
            foreach ($vn in @($k.GetValueNames())) {
                if ($vn -notlike '\Device\*') { continue }
                $data = $k.GetValue($vn)
                $when = ''
                if ($data -is [byte[]] -and $data.Length -ge 8) {
                    try { $when = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($data, 0)).ToLocalTime() } catch { }
                }
                $path = Convert-DevicePath $vn $map
                $exists = Test-Path -LiteralPath $path
                $sig = [pscustomobject]@{ Status = 'FileNonTrovato'; Signer = '' }
                if ($exists) { $sig = Get-SigInfo $path }
                $risk = ''
                if ($exists) { $risk = Get-BinaryRisk $path $sig }
                elseif ((Get-PathRisk $path) -eq 2) { $risk = 'MEDIA' }
                $rows.Add([pscustomobject]@{ Utente = $user; Programma = $path; UltimaEsecuzione = $when; Esiste = $exists; Firma = $sig.Status; Rischio = $risk })
                if ($risk -eq 'ALTA') {
                    Add-Finding 'BASSA' 'Cronologia esecuzione' "Eseguito programma non firmato da cartella utente: $([IO.Path]::GetFileName($path))" "$path | ultima esecuzione $when | utente $user" 'Cercare lo SHA256 del file su VirusTotal e verificare se l''esecuzione coincide con i bonifici fraudolenti.' -Key $path -KeyType path
                } elseif ($risk -eq 'MEDIA' -and -not $exists) {
                    Add-Finding 'BASSA' 'Cronologia esecuzione' "Programma eseguito da cartella utente e poi CANCELLATO: $([IO.Path]::GetFileName($path))" "$path | ultima esecuzione $when | utente $user" 'I malware spesso si cancellano dopo l''installazione. Confrontare la data con i bonifici fraudolenti.' -Key $path -KeyType path
                }
            }
        }
    }
    return $rows.ToArray()
}

function Get-TypedCommands {
    # ClickFix / FileFix: comandi incollati in Esegui (Win+R) e nella barra degli indirizzi di Esplora file
    param([string[]]$UserDirs)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($h in (Get-UserHives)) {
        foreach ($sub in @('RunMRU', 'TypedPaths')) {
            $k = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\$sub"
            $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            foreach ($vn in @($item.GetValueNames())) {
                if ($vn -eq 'MRUList') { continue }
                $cmd = ([string]$item.GetValue($vn)) -replace '\\1$', ''
                $risk = Get-RunCommandRisk $cmd
                $src = 'Esegui (Win+R)'
                if ($sub -eq 'TypedPaths') { $src = 'Barra di Esplora file' }
                $rows.Add([pscustomobject]@{ Utente = $h.Name; Origine = $src; Comando = $cmd; Rischio = $risk })
                if ($risk) {
                    Add-Finding $risk 'ClickFix' "Comando sospetto incollato in $src ($($h.Name))" $cmd 'Tecnica "ClickFix": un sito o una email (anche PEC) convince l''utente a incollare un comando che installa il malware. Chiedere all''utente quando e perche'' l''ha eseguito; analizzare cosa scarica.'
                }
            }
        }
    }
    foreach ($ud in $UserDirs) {
        $hf = Join-Parts $ud @('AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt')
        if (-not (Test-Path -LiteralPath $hf)) { continue }
        if ($script:OutDir) { Copy-Item -LiteralPath $hf -Destination (Join-Path $script:OutDir ('cronologia_powershell_' + (Split-Path $ud -Leaf) + '.txt')) -ErrorAction SilentlyContinue }
        $n = 0
        foreach ($line in @(Get-Content -LiteralPath $hf -ErrorAction SilentlyContinue)) {
            $n++
            $risk = Get-PsHistoryRisk $line
            if (-not $risk) { continue }
            $rows.Add([pscustomobject]@{ Utente = (Split-Path $ud -Leaf); Origine = "Cronologia PowerShell riga $n"; Comando = $line; Rischio = $risk })
            Add-Finding $risk 'ClickFix' "Comando PowerShell sospetto nella cronologia di $(Split-Path $ud -Leaf)" $line 'Verificare se l''ha eseguito un tecnico. Se no, e'' un forte indizio di infezione (download ed esecuzione di codice).'
        }
    }
    return $rows.ToArray()
}

function Get-KnownIocs {
    # Indicatori noti di Ramnit/drIBAN (sostituzione IBAN nei bonifici aziendali) e di altri malware bancari
    param([string[]]$UserDirs)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $paths = @()
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $pf) { continue }
        $paths += Join-Parts $pf @('Microsoft', 'DesktopLayer.exe')
        $paths += Join-Parts $pf @('Microsoft', 'WaterMark.exe')
    }
    foreach ($ud in $UserDirs) { $paths += Join-Parts $ud @('AppData', 'Local', 'Temp', 'svchost.exe') }
    if ($env:windir) { $paths += Join-Parts $env:windir @('Temp', 'svchost.exe') }
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p) {
            $h = Get-FileSha256 $p
            $rows.Add([pscustomobject]@{ Tipo = 'File noto'; Oggetto = $p; Dettaglio = "SHA256 $h" })
            Add-Finding 'ALTA' 'Indicatori noti' "File tipico del trojan Ramnit: $p" "SHA256 $h" 'Ramnit e'' il malware usato nelle frodi drIBAN che sostituiscono l''IBAN nei bonifici. Isolare il PC e fare analisi approfondita.'
        }
    }
    # File HTML infettati da Ramnit
    $dirs = @()
    foreach ($ud in $UserDirs) { foreach ($s in @('Desktop', 'Documents', 'Downloads', 'OneDrive')) { $dirs += Join-Path $ud $s } }
    $count = 0
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -Depth 6 -File -Include *.htm, *.html -ErrorAction SilentlyContinue)) {
            $count++
            if ($count -gt 3000) { break }
            if ($f.Length -gt 5MB -or $f.Length -lt 100) { continue }
            try {
                $fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
                try {
                    $len = [int][math]::Min(8192, $fs.Length)
                    [void]$fs.Seek(-$len, 'End')
                    $buf = New-Object byte[] $len
                    [void]$fs.Read($buf, 0, $len)
                    $tail = [Text.Encoding]::ASCII.GetString($buf)
                } finally { $fs.Dispose() }
                if (Test-RamnitHtml $tail) {
                    $rows.Add([pscustomobject]@{ Tipo = 'HTML infetto'; Oggetto = $f.FullName; Dettaglio = 'VBScript Ramnit in coda al file' })
                    Add-Finding 'ALTA' 'Indicatori noti' "File HTML infettato da Ramnit: $($f.Name)" $f.FullName 'Ramnit infetta i file .html: aprirli nel browser reinfetta il PC. Indica un''infezione Ramnit attiva o passata.'
                }
            } catch { }
        }
    }
    $rows.Add([pscustomobject]@{ Tipo = 'Riepilogo'; Oggetto = 'File HTML controllati'; Dettaglio = [string][math]::Min($count, 3000) })
    return $rows.ToArray()
}

function Get-MemoryInjection {
    # Cerca eseguibili caricati direttamente in memoria (senza file su disco) dentro i processi
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if (-not $script:IsWin) { throw 'Disponibile solo su Windows' }
    if (-not (Initialize-CyberNative)) { throw 'Impossibile compilare il modulo di analisi memoria' }
    $key = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 'iexplore', 'explorer', 'svchost', 'rundll32', 'dllhost', 'regsvr32', 'msiexec', 'notepad')
    $scanned = 0; $denied = 0
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $PID })) {
        $err = $null
        $hits = $null
        try { $hits = [CyberRSecNative.Mem]::Scan($p.Id, [ref]$err) } catch { continue }
        if ($err) { $denied++; continue }
        $scanned++
        foreach ($hh in $hits) {
            $path = ''
            try { $path = $p.Path } catch { }
            $pn = $p.ProcessName.ToLowerInvariant()
            $sev = 'BASSA'
            if (@('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 'iexplore') -contains $pn) { $sev = 'ALTA' }
            elseif ($key -contains $pn) { $sev = 'MEDIA' }
            if ($script:OwnPids -contains [int]$p.Id) { continue }
            $rows.Add([pscustomobject]@{ Processo = $p.ProcessName; PID = $p.Id; Percorso = $path; Indirizzo = ('0x{0:X}' -f $hh.Address); Dimensione = $hh.Size; Protezione = ('0x{0:X}' -f $hh.Protect); Tipo = $hh.Kind })
            Add-Finding $sev 'Iniezione in memoria' "Codice eseguibile iniettato in $($p.ProcessName) (PID $($p.Id))" ("{0} all'indirizzo 0x{1:X} ({2:N0} byte). {3}" -f $hh.Kind, $hh.Address, $hh.Size, $path) "Tipico dei trojan bancari che modificano le pagine della banca dentro il browser (es. Ramnit/drIBAN). Alcuni software di protezione legittimi fanno lo stesso: se il processo e' un antivirus, verificare. Altrimenti NON usare il PC per bonifici, fare un dump della memoria (es. con WinPmem o procdump) e analisi forense."
        }
    }
    $rows.Add([pscustomobject]@{ Processo = '(riepilogo)'; PID = ''; Percorso = "processi analizzati: $scanned, non accessibili: $denied"; Indirizzo = ''; Dimensione = ''; Protezione = ''; Tipo = '' })
    if ($denied -gt 10 -and -not $script:IsAdmin) {
        Add-Finding 'BASSA' 'Iniezione in memoria' "$denied processi non analizzabili senza privilegi di amministratore" '' 'Rilanciare come amministratore per analizzare tutti i processi.'
    }
    return $rows.ToArray()
}

function Get-LanReport {
    # Rete locale: tabella ARP (possibile ARP spoofing = attacco man-in-the-middle sulla LAN), regole firewall, BITS
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $gws = @()
    try { $gws = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | ForEach-Object { $_.NextHop } | Where-Object { $_ -and $_ -ne '0.0.0.0' } | Select-Object -Unique) } catch { }
    $arp = @()
    try {
        $arp = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.State -in @('Reachable', 'Stale', 'Permanent', 'Delay', 'Probe') } |
                ForEach-Object { [pscustomobject]@{ IP = $_.IPAddress; MAC = ([string]$_.LinkLayerAddress).ToUpperInvariant(); Interfaccia = $_.InterfaceAlias; Stato = [string]$_.State } })
    } catch { }
    foreach ($a in $arp) {
        $gwFlag = ''
        if ($gws -contains $a.IP) { $gwFlag = 'gateway' }
        $rows.Add([pscustomobject]@{ Tipo = 'ARP'; Oggetto = $a.IP; Valore = $a.MAC; Note = ("{0} {1} {2}" -f $a.Interfaccia, $a.Stato, $gwFlag).Trim() })
    }
    foreach ($an in (Get-ArpAnomalies $arp $gws)) {
        if ($an.Gateway) {
            Add-Finding 'MEDIA' 'Rete locale' "Il MAC del router ($($an.MAC)) risulta usato anche da altri IP della rete" "IP con lo stesso MAC: $($an.IP)" 'Fatto certo, ma con due spiegazioni: un ripetitore Wi-Fi (normale) oppure un dispositivo che intercetta il traffico (ARP spoofing). Se il PC e'' collegato via cavo direttamente al router, e'' un attacco: verificare il MAC sull''etichetta del router.'
        } else {
            Add-Finding 'BASSA' 'Rete locale' "Piu' IP con lo stesso MAC ($($an.MAC))" $an.IP 'Spesso normale (dispositivo con piu'' indirizzi). Verificare se sconosciuto.'
        }
    }
    foreach ($g in $gws) { $rows.Add([pscustomobject]@{ Tipo = 'Gateway'; Oggetto = $g; Valore = (@($arp | Where-Object { $_.IP -eq $g } | ForEach-Object { $_.MAC }) -join ','); Note = '' }) }

    # Regole firewall in ingresso che permettono programmi in cartelle utente
    try {
        $rules = @{}
        foreach ($r in @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)) { $rules[$r.Name] = $r }
        foreach ($af in @(Get-NetFirewallApplicationFilter -All -ErrorAction Stop)) {
            if (-not $rules.ContainsKey($af.InstanceID)) { continue }
            $prog = [Environment]::ExpandEnvironmentVariables([string]$af.Program)
            if (-not $prog -or $prog -eq 'Any' -or $prog -eq 'System') { continue }
            if ((Get-PathRisk $prog) -lt 1) { continue }
            $sig = Get-SigInfo $prog
            $rows.Add([pscustomobject]@{ Tipo = 'Regola firewall'; Oggetto = $rules[$af.InstanceID].DisplayName; Valore = $prog; Note = "firma $($sig.Status)" })
            if ($sig.Status -ne 'Valid') {
                Add-Finding 'BASSA' 'Rete locale' "Il firewall accetta connessioni in ingresso verso un programma in cartella utente" "$($rules[$af.InstanceID].DisplayName): $prog (firma $($sig.Status))" 'I RAT aprono il firewall per farsi controllare da remoto. Verificare il programma.' -Key $prog -KeyType path
            }
        }
    } catch { }

    # Download in background (BITS), usati da loader come sLoad
    if (Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue) {
        try {
            foreach ($j in @(Get-BitsTransfer -AllUsers -ErrorAction Stop)) {
                $urls = @($j.FileList | ForEach-Object { $_.RemoteName })
                $rows.Add([pscustomobject]@{ Tipo = 'BITS'; Oggetto = $j.DisplayName; Valore = ($urls -join ' '); Note = "$($j.OwnerAccount) $($j.JobState)" })
                $bad = @($urls | Where-Object { $_ -notmatch '(?i)\.(microsoft|windowsupdate|msftconnecttest|office|live|bing|google|gvt1|mozilla|adobe)\.(com|net)/' })
                if ($bad.Count -gt 0) {
                    Add-Finding 'BASSA' 'Rete locale' "Download in background (BITS) verso un sito non comune: $($j.DisplayName)" (($bad -join ' ') + " | utente $($j.OwnerAccount)") 'I loader (es. sLoad, usato nelle frodi IBAN) usano BITS per scaricare il malware. Verificare l''indirizzo.'
                }
            }
        } catch { }
    }
    return $rows.ToArray()
}

# ----------------------------------------------------------------------------------------------
#  Raccolta: browser
# ----------------------------------------------------------------------------------------------
$script:ChromiumBrowsers = @(
    @{ Name = 'Chrome'; Parts = @('AppData', 'Local', 'Google', 'Chrome', 'User Data') },
    @{ Name = 'Edge'; Parts = @('AppData', 'Local', 'Microsoft', 'Edge', 'User Data') },
    @{ Name = 'Brave'; Parts = @('AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data') },
    @{ Name = 'Vivaldi'; Parts = @('AppData', 'Local', 'Vivaldi', 'User Data') },
    @{ Name = 'Chromium'; Parts = @('AppData', 'Local', 'Chromium', 'User Data') },
    @{ Name = 'Opera'; Parts = @('AppData', 'Roaming', 'Opera Software', 'Opera Stable') },
    @{ Name = 'Opera GX'; Parts = @('AppData', 'Roaming', 'Opera Software', 'Opera GX Stable') }
)

function Get-ChromiumProfiles {
    param([string]$UserDataDir)
    $o = New-Object 'System.Collections.Generic.List[string]'
    if (-not (Test-Path -LiteralPath $UserDataDir)) { return $o.ToArray() }
    if (Test-Path -LiteralPath (Join-Path $UserDataDir 'Preferences')) { $o.Add($UserDataDir) }
    foreach ($d in @(Get-ChildItem -LiteralPath $UserDataDir -Directory -Force -ErrorAction SilentlyContinue)) {
        if ((Test-Path -LiteralPath (Join-Path $d.FullName 'Preferences')) -or (Test-Path -LiteralPath (Join-Path $d.FullName 'Extensions'))) {
            $o.Add($d.FullName)
        }
    }
    return $o.ToArray()
}

function Get-ChromiumExtensions {
    param([string[]]$UserDirs, [string[]]$BankDomains)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ud in $UserDirs) {
        foreach ($b in $script:ChromiumBrowsers) {
            $udd = Join-Parts $ud $b.Parts
            foreach ($prof in (Get-ChromiumProfiles $udd)) {
                $settings = @{}
                $devMode = $false
                foreach ($pf in @('Secure Preferences', 'Preferences')) {
                    $j = Read-JsonFile (Join-Path $prof $pf)
                    if ($null -eq $j) { continue }
                    if ((Get-DVal $j 'extensions.ui.developer_mode') -eq $true) { $devMode = $true }
                    $s = Get-DVal $j 'extensions.settings'
                    if ($s -is [System.Collections.IDictionary]) {
                        foreach ($k in @($s.Keys)) { if (-not $settings.ContainsKey($k)) { $settings[$k] = $s[$k] } }
                    }
                }
                $extRoot = Join-Path $prof 'Extensions'
                $ids = New-Object 'System.Collections.Generic.HashSet[string]'
                foreach ($k in $settings.Keys) { [void]$ids.Add($k) }
                foreach ($d in @(Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue)) { [void]$ids.Add($d.Name) }

                if ($devMode) {
                    Add-Finding 'BASSA' 'Browser' "$($b.Name): modalita' sviluppatore estensioni attiva" "Profilo: $prof" 'Permette di caricare estensioni da cartella: disattivarla se nessuno la usa.'
                }

                foreach ($id in $ids) {
                    $s = $null
                    if ($settings.ContainsKey($id)) { $s = $settings[$id] }
                    $loc = 0
                    try { $loc = [int](Get-DVal $s 'location') } catch { }
                    $extDir = ''
                    $manifest = $null
                    $sp = [string](Get-DVal $s 'path')
                    if ($sp -and ([IO.Path]::IsPathRooted($sp))) { $extDir = $sp }
                    elseif (Test-Path -LiteralPath (Join-Path $extRoot $id)) {
                        $vd = @(Get-ChildItem -LiteralPath (Join-Path $extRoot $id) -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
                        if ($vd.Count -gt 0) { $extDir = $vd[0].FullName }
                    }
                    if ($extDir) { $manifest = Read-JsonFile (Join-Path $extDir 'manifest.json') }
                    if ($null -eq $manifest) { $manifest = Get-DVal $s 'manifest' }
                    if ($null -eq $manifest -and $null -eq $s) { continue }
                    if ($loc -eq 0 -and $extDir -and $extDir.StartsWith($extRoot)) { $loc = 1 }

                    $name = Resolve-ExtName $manifest $extDir
                    if (-not $name) { $name = '(senza nome)' }
                    $ver = [string](Get-DVal $manifest 'version')
                    $perms = ConvertTo-StrArray (Get-DVal $manifest 'permissions')
                    $hostPerms = ConvertTo-StrArray (Get-DVal $manifest 'host_permissions')
                    # in MV2 gli host stanno dentro "permissions"
                    $hosts = @($hostPerms) + @($perms | Where-Object { $_ -match '://|<all_urls>' })
                    $perms = @($perms | Where-Object { $_ -notmatch '://|<all_urls>' })
                    $cm = New-Object 'System.Collections.Generic.List[string]'
                    $cs = Get-DVal $manifest 'content_scripts'
                    if ($cs) { foreach ($c in $cs) { foreach ($mm in (ConvertTo-StrArray (Get-DVal $c 'matches'))) { $cm.Add($mm) } } }
                    $upd = [string](Get-DVal $manifest 'update_url')
                    $fromStore = ($upd -match 'clients2\.google\.com|edge\.microsoft\.com|extensionwebstorebase|clients2\.googleusercontent\.com') -or ((Get-DVal $s 'from_webstore') -eq $true)
                    $state = Get-DVal $s 'state'
                    $disabled = Get-DVal $s 'disable_reasons'
                    $enabled = $true
                    if ($null -ne $state -and [int64]$state -eq 0) { $enabled = $false }
                    if ($null -ne $disabled) {
                        if ($disabled -is [System.Collections.IEnumerable] -and $disabled -isnot [string]) { if (@($disabled).Count -gt 0) { $enabled = $false } }
                        elseif ([int64]$disabled -ne 0) { $enabled = $false }
                    }

                    $risk = Get-ExtensionRisk -LocationCode $loc -Hosts $hosts -ContentMatches $cm.ToArray() -Perms $perms -FromStore $fromStore -BankDomains $BankDomains
                    $locTxt = $script:ChromeLocation[$loc]
                    if (-not $locTxt) { $locTxt = "sconosciuta ($loc)" }
                    $row = [pscustomobject]@{
                        Utente = (Split-Path $ud -Leaf); Browser = $b.Name; Profilo = (Split-Path $prof -Leaf)
                        Id = $id; Nome = $name; Versione = $ver; Attiva = $enabled; Provenienza = $locTxt
                        DalloStore = $fromStore; Installata = (ConvertFrom-ChromeTime (Get-DVal $s 'install_time'))
                        Permessi = ($perms -join ' '); Host = (@($hosts) -join ' '); ContentScripts = ($cm -join ' ')
                        UpdateUrl = $upd; Cartella = $extDir; Rischio = $risk.Severity; Motivi = $risk.Reasons
                    }
                    $rows.Add($row)
                    if ($risk.Severity -in @('ALTA', 'MEDIA')) {
                        $stato = 'attiva'
                        if (-not $enabled) { $stato = 'disattivata' }
                        Add-Finding $risk.Severity 'Estensioni browser' "$($b.Name): estensione '$name' ($stato)" ("Utente {0}, profilo {1}, ID {2}. {3}. Cartella: {4}" -f $row.Utente, $row.Profilo, $id, $risk.Reasons, $extDir) "Se non la riconoscete, rimuovetela e cercate l'ID su Google/VirusTotal. Le estensioni sono la causa piu' frequente di IBAN modificati nella pagina della banca. Se e' legittima, aggiungere l'ID in AllowExtensionIds di config.json." -Key $id -KeyType ext
                    }
                }
            }
        }
    }
    $wide = @($rows | Where-Object { $_.Rischio -eq 'BASSA' -and $_.Attiva })
    if ($wide.Count -gt 0) {
        Add-Finding 'BASSA' 'Estensioni browser' "$($wide.Count) estensioni dello store possono leggere e modificare tutte le pagine (compresa la banca)" (($wide | ForEach-Object { "$($_.Browser): $($_.Nome)" } | Select-Object -Unique) -join '; ') 'Sul PC dei bonifici tenere solo le estensioni indispensabili.'
    }
    return $rows.ToArray()
}

function Get-FirefoxExtensions {
    param([string[]]$UserDirs, [string[]]$BankDomains)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ud in $UserDirs) {
        $pr = Join-Parts $ud @('AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
        foreach ($p in @(Get-ChildItem -LiteralPath $pr -Directory -ErrorAction SilentlyContinue)) {
            # prefs.js: firme disattivate / proxy
            $prefs = Join-Path $p.FullName 'prefs.js'
            if (Test-Path -LiteralPath $prefs) {
                $pt = [IO.File]::ReadAllText($prefs)
                if ($pt -match 'xpinstall\.signatures\.required",\s*false') {
                    Add-Finding 'BASSA' 'Browser' 'Firefox: impostazione per disattivare la firma delle estensioni presente' "Profilo $($p.FullName)" 'Nelle versioni ufficiali di Firefox non ha effetto; insieme a estensioni non firmate indica manomissione.'
                }
                $m = [regex]::Match($pt, 'network\.proxy\.type",\s*(\d)')
                if ($m.Success -and $m.Groups[1].Value -in @('1', '2')) {
                    $px = [regex]::Match($pt, 'network\.proxy\.(http|autoconfig_url)",\s*"([^"]+)"').Groups[2].Value
                    Add-Finding 'MEDIA' 'Rete/Proxy' 'Firefox: proxy configurato' "Profilo $($p.FullName): $px" 'Verificare che il proxy sia quello aziendale.'
                }
            }
            if (Test-Path -LiteralPath (Join-Path $p.FullName 'user.js')) {
                Add-Finding 'BASSA' 'Browser' 'Firefox: presente user.js (impostazioni forzate)' (Join-Path $p.FullName 'user.js') 'Aprirlo e verificare cosa imposta (proxy, certificati, firme).'
            }
            $j = Read-JsonFile (Join-Path $p.FullName 'extensions.json')
            $addons = Get-DVal $j 'addons'
            if (-not $addons) { continue }
            foreach ($a in $addons) {
                $type = [string](Get-DVal $a 'type')
                if ($type -and $type -notin @('extension', 'webextension')) { continue }
                $loc = [string](Get-DVal $a 'location')
                if ($loc -in @('app-builtin', 'app-system-defaults', 'app-system-addons')) { continue }
                $origins = ConvertTo-StrArray (Get-DVal $a 'userPermissions.origins')
                $perms = ConvertTo-StrArray (Get-DVal $a 'userPermissions.permissions')
                $signed = Get-DVal $a 'signedState'
                $name = [string](Get-DVal $a 'defaultLocale.name')
                $active = [bool](Get-DVal $a 'active')
                $broad = @($origins | Where-Object { Test-BroadHost $_ }).Count -gt 0
                $bank = @($origins | Where-Object { Test-BankHost $_ $BankDomains }).Count -gt 0
                $sev = ''; $why = @()
                $unsigned = ($null -ne $signed -and [int]$signed -le 0)
                if ($unsigned) { $why += 'non firmata da Mozilla' }
                if ($loc -ne 'app-profile') { $why += "installata da '$loc'" }
                if ($bank) { $why += 'accesso esplicito al sito della banca' }
                if ($broad) { $why += 'accesso a tutti i siti' }
                if ($unsigned -and ($broad -or $bank) -and $active) { $sev = 'ALTA' }
                elseif ($unsigned -or $bank) { $sev = 'MEDIA' }
                elseif ($broad) { $sev = 'BASSA' }
                $inst = ''
                try { $inst = ([DateTime]'1970-01-01').AddMilliseconds([double](Get-DVal $a 'installDate')).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } catch { }
                $rows.Add([pscustomobject]@{
                        Utente = (Split-Path $ud -Leaf); Browser = 'Firefox'; Profilo = $p.Name; Id = [string](Get-DVal $a 'id'); Nome = $name
                        Versione = [string](Get-DVal $a 'version'); Attiva = $active; Provenienza = $loc; Firmata = $signed
                        Installata = $inst; Permessi = ($perms -join ' '); Host = ($origins -join ' ')
                        Sorgente = [string](Get-DVal $a 'sourceURI'); Rischio = $sev; Motivi = ($why -join '; ')
                    })
                if ($sev -in @('ALTA', 'MEDIA')) { Add-Finding $sev 'Estensioni browser' "Firefox: estensione '$name'" ("Utente {0}, ID {1}. {2}" -f (Split-Path $ud -Leaf), (Get-DVal $a 'id'), ($why -join '; ')) 'Se non la riconoscete, rimuovetela.' -Key ([string](Get-DVal $a 'id')) -KeyType ext }
            }
        }
    }
    return $rows.ToArray()
}

function Get-BrowserPolicies {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $roots = @(
        'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKCU:\SOFTWARE\Policies\Google\Chrome',
        'HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
        'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave', 'HKCU:\SOFTWARE\Policies\BraveSoftware\Brave',
        'HKLM:\SOFTWARE\Policies\Mozilla\Firefox', 'HKCU:\SOFTWARE\Policies\Mozilla\Firefox',
        'HKLM:\SOFTWARE\Google\Chrome\Extensions', 'HKLM:\SOFTWARE\WOW6432Node\Google\Chrome\Extensions',
        'HKLM:\SOFTWARE\Microsoft\Edge\Extensions', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions',
        'HKCU:\SOFTWARE\Google\Chrome\Extensions', 'HKCU:\SOFTWARE\Microsoft\Edge\Extensions'
    )
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        $keys = @(Get-Item $r -ErrorAction SilentlyContinue) + @(Get-ChildItem $r -Recurse -ErrorAction SilentlyContinue)
        foreach ($k in $keys) {
            foreach ($vn in @($k.GetValueNames())) {
                $v = $k.GetValue($vn)
                $rows.Add([pscustomobject]@{ Chiave = $k.Name; Valore = $vn; Dato = [string]($v -join ' ') })
            }
        }
    }
    foreach ($row in $rows) {
        $kn = $row.Chiave; $d = $row.Dato
        if ($kn -match 'ExtensionInstallForcelist') {
            $fsev = 'MEDIA'
            if (-not (Test-DomainJoined)) { $fsev = 'ALTA' }
            Add-Finding $fsev 'Policy browser' 'Estensione installata FORZATAMENTE tramite policy' "$kn = $d" "Le policy forzano l'estensione e impediscono di rimuoverla. Se non e' una policy aziendale nota, e' un forte indizio di malware."
        } elseif ($kn -match '\\Extensions(\\|$)' -and $kn -notmatch 'Policies') {
            Add-Finding 'BASSA' 'Policy browser' 'Estensione registrata da un programma esterno (registro)' "$kn $($row.Valore) = $d" "Verificare quale programma l'ha registrata."
        } elseif ($row.Valore -match '^(ProxyServer|ProxyPacUrl|ProxyMode|ProxySettings)$') {
            Add-Finding 'MEDIA' 'Policy browser' 'Proxy imposto al browser tramite policy' "$kn $($row.Valore) = $d" 'Tutto il traffico del browser passa da quel proxy: verificare che sia quello aziendale.'
        } elseif ($row.Valore -match '^(CommandLineFlagSecurityWarningsEnabled|DeveloperToolsAvailability|ExtensionInstallSources|ExtensionInstallAllowlist|ExtensionSettings|RemoteDebuggingAllowed|Certificates|ImportEnterpriseRoots)$' -or $kn -match 'ExtensionInstallSources|ExtensionSettings|Certificates') {
            Add-Finding 'BASSA' 'Policy browser' "Policy browser sensibile: $($row.Valore)" "$kn = $d" 'Verificare che sia stata impostata dall''IT.'
        }
    }
    return $rows.ToArray()
}

function Get-BrowserShortcuts {
    param([string[]]$UserDirs)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $sh = $null
    try { $sh = New-Object -ComObject WScript.Shell } catch { throw 'COM WScript.Shell non disponibile' }
    $dirs = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ud in $UserDirs) {
        foreach ($p in @(@('Desktop'), @('OneDrive', 'Desktop'), @('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu'),
                @('AppData', 'Roaming', 'Microsoft', 'Internet Explorer', 'Quick Launch'))) { $dirs.Add((Join-Parts $ud $p)) }
    }
    if ($env:PUBLIC) { $dirs.Add((Join-Path $env:PUBLIC 'Desktop')) }
    if ($env:ProgramData) { $dirs.Add((Join-Parts $env:ProgramData @('Microsoft', 'Windows', 'Start Menu'))) }
    foreach ($d in $dirs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Filter *.lnk -Recurse -Force -ErrorAction SilentlyContinue)) {
            try { $l = $sh.CreateShortcut($f.FullName) } catch { continue }
            $t = [string]$l.TargetPath; $a = [string]$l.Arguments
            $isBrowser = ($script:BrowserExe -contains ([IO.Path]::GetFileName($t).ToLowerInvariant())) -or ($f.Name -match '(?i)chrome|edge|firefox|brave|opera|banca|bcc|relax')
            if (-not $isBrowser) { continue }
            $rows.Add([pscustomobject]@{ Collegamento = $f.FullName; Destinazione = $t; Argomenti = $a; Modificato = $f.LastWriteTime })
            if ($a -match '(?i)--load-extension|--remote-debugging|--proxy-server|--proxy-pac-url|--disable-web-security|--host-resolver-rules|--headless|--disable-extensions-except') {
                Add-Finding 'ALTA' 'Browser' "Collegamento del browser con parametri sospetti: $($f.Name)" "$($f.FullName) -> $t $a" "Malware bancari modificano i collegamenti per caricare estensioni nascoste o un proxy. Ricreare il collegamento e cercare la cartella indicata."
            }
            if ($t -and ($script:BrowserExe -contains ([IO.Path]::GetFileName($t).ToLowerInvariant())) -and (Test-Path -LiteralPath $t) -and (Get-SigInfo $t).Status -ne 'Valid') {
                Add-Finding 'ALTA' 'Browser' "Il collegamento '$($f.Name)' avvia un browser senza firma valida" "$t" 'L''eseguibile del browser avviato dal collegamento NON ha una firma digitale valida: browser falso o manomesso.'
            }
        }
    }
    return $rows.ToArray()
}

function Get-BrowserBinaries {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $cands = @()
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
        if (-not $pf) { continue }
        $cands += Join-Parts $pf @('Google', 'Chrome', 'Application', 'chrome.exe')
        $cands += Join-Parts $pf @('Microsoft', 'Edge', 'Application', 'msedge.exe')
        $cands += Join-Parts $pf @('Mozilla Firefox', 'firefox.exe')
        $cands += Join-Parts $pf @('BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe')
    }
    foreach ($c in $cands) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        $s = Get-SigInfo $c
        $rows.Add([pscustomobject]@{ File = $c; Firma = $s.Status; Firmatario = $s.Signer; Versione = (Get-Item -LiteralPath $c).VersionInfo.ProductVersion; SHA256 = (Get-FileSha256 $c) })
        if ($s.Status -in @('HashMismatch', 'NotSigned')) {
            Add-Finding 'ALTA' 'Browser' "Eseguibile del browser con firma non valida: $c" "Stato firma: $($s.Status)" 'Reinstallare il browser da sito ufficiale e analizzare il file.'
        }
    }
    return $rows.ToArray()
}

# ----------------------------------------------------------------------------------------------
#  Raccolta: processi, moduli, avvio automatico
# ----------------------------------------------------------------------------------------------
function Get-ProcessReport {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $byPid = @{}
    foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    foreach ($p in $procs) {
        $path = [string]$p.ExecutablePath
        $cmd = [string]$p.CommandLine
        $sig = Get-SigInfo $path
        $parent = ''
        if ($byPid.ContainsKey([int]$p.ParentProcessId)) { $parent = $byPid[[int]$p.ParentProcessId].Name }
        $risk = Get-BinaryRisk $path $sig
        $rows.Add([pscustomobject]@{
                PID = $p.ProcessId; Nome = $p.Name; Padre = $parent; PPID = $p.ParentProcessId; Percorso = $path; RigaComando = $cmd
                Firma = $sig.Status; Firmatario = $sig.Signer; Avviato = $p.CreationDate; Rischio = $risk
            })
        $nm = ([string]$p.Name).ToLowerInvariant()
        $isOwnUi = ($script:OwnPids -contains [int]$p.ProcessId) -or ($cmd -match 'CyberRSecUI_')
        if (-not $isOwnUi -and $script:BrowserExe -contains $nm -and $cmd -match '(?i)--load-extension|--remote-debugging-port|--remote-debugging-address|--remote-allow-origins|-remote-debugging-port|--window-position=-\\d{3,}|-start-debugger-server') {
            Add-Finding 'ALTA' 'Processi' "Browser avviato con parametri sospetti ($($p.Name) PID $($p.ProcessId))" $cmd "--load-extension carica un'estensione nascosta; --remote-debugging-port, --headless o una finestra fuori schermo (--window-position=-2400) sono usati dagli infostealer (es. Phemedrone, Lumma, StealC) per rubare cookie e sessioni della banca. Padre: $parent"
        }
        if (-not $isOwnUi -and $script:BrowserExe -contains $nm -and $cmd -match '(?i)--proxy-server|--proxy-pac-url|--disable-web-security|--host-resolver-rules|--headless') {
            Add-Finding 'MEDIA' 'Processi' "Browser in esecuzione con proxy/opzioni di sicurezza modificate ($($p.Name) PID $($p.ProcessId))" $cmd "Verificare quale programma ha avviato il browser in questo modo. Padre: $parent"
        }
        if ($risk -eq 'ALTA') {
            Add-Finding 'MEDIA' 'Processi' "Programma senza firma digitale in esecuzione da una cartella utente: $($p.Name) (PID $($p.ProcessId))" "$path | firma: $($sig.Status) | padre: $parent | SHA256: $(Get-FileSha256 $path)" 'Cercare lo SHA256 su VirusTotal. Se sconosciuto, raccogliere il file prima di cancellarlo.' -Key $path -KeyType path
        }
        if ($script:BrowserExe -contains $nm -and $cmd -match '(?i)--profile-directory=' -and $parent -and $parent -notmatch '(?i)^(explorer|chrome|msedge|brave|opera|vivaldi|launcher|browser_broker|sihost|runtimebroker|svchost|chrome_proxy|msedge_proxy|elevation_service|setup|outlook|teams|ms-teams|olk|winword|excel)\.exe$') {
            Add-Finding 'BASSA' 'Processi' "Browser avviato da un programma insolito: $parent -> $($p.Name)" $cmd 'Gli infostealer riavviano il browser con il profilo dell''utente per rubarne i dati. Verificare il programma padre.'
        }
        if ($nm -in @('powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe') -and $cmd -match $script:ScriptHostRegex -and $p.ProcessId -ne $PID -and $cmd -notmatch '(?i)CyberRSecurityCheck') {
            $psev = 'BASSA'
            if ($cmd -match '(?i)(iex|invoke-expression).*(downloadstring|iwr|irm|invoke-webrequest|net\.webclient)|(downloadstring|iwr|irm|invoke-webrequest|net\.webclient).*(iex|invoke-expression)|mshta(\.exe)?\s+https?:') { $psev = 'MEDIA' }
            Add-Finding $psev 'Processi' "Script in esecuzione con parametri sospetti: $($p.Name) PID $($p.ProcessId)" $cmd 'Verificare cosa esegue e chi lo ha avviato.'
        }
        if ($script:BrowserExe -contains $nm -and $path -and $sig.Status -in @('NotSigned', 'HashMismatch')) {
            Add-Finding 'ALTA' 'Processi' "Browser in esecuzione senza firma digitale valida: $path" "PID $($p.ProcessId) firma $($sig.Status)" 'Un vero Chrome/Edge/Firefox e'' sempre firmato: questo e'' un browser falso o manomesso.'
        }
    }
    return $rows.ToArray()
}

function Get-BrowserModules {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    $winDir = ([string]$env:windir).ToLowerInvariant()
    foreach ($p in @(Get-Process -Name chrome, msedge, firefox, brave, opera, vivaldi -ErrorAction SilentlyContinue)) {
        $mods = $null
        try { $mods = $p.Modules } catch { continue }
        foreach ($m in $mods) {
            $f = [string]$m.FileName
            if (-not $f -or $seen.ContainsKey($f)) { continue }
            $seen[$f] = $true
            if ($winDir -and $f.ToLowerInvariant().StartsWith($winDir)) { continue }
            $sig = Get-SigInfo $f
            $rows.Add([pscustomobject]@{ Browser = $p.ProcessName; PID = $p.Id; Modulo = $f; Firma = $sig.Status; Firmatario = $sig.Signer; Azienda = $m.Company })
            if ($sig.Status -ne 'Valid') {
                $sev = 'BASSA'
                if ((Get-PathRisk $f) -eq 1) { $sev = 'MEDIA' }
                if ((Get-PathRisk $f) -eq 2 -or $sig.Status -eq 'HashMismatch') { $sev = 'ALTA' }
                Add-Finding $sev 'Iniezione nel browser' "DLL non firmata caricata in $($p.ProcessName): $([IO.Path]::GetFileName($f))" "$f | firma $($sig.Status) | SHA256 $(Get-FileSha256 $f)" "Una DLL estranea dentro il browser puo' modificare le pagine della banca (man-in-the-browser). Verificare su VirusTotal." -Key $f -KeyType path
            }
        }
    }
    return $rows.ToArray()
}

function Add-AutorunRow {
    param($Rows, [string]$Type, [string]$Location, [string]$Name, [string]$Command, [string]$Extra = '')
    $exe = Get-ExePathFromCommand $Command
    $sig = Get-SigInfo $exe
    $bin = Get-BinaryRisk $exe $sig
    $risk = ''
    # CONFERMATO: avvio automatico che scarica ed esegue codice o esegue PowerShell codificato/nascosto
    if ($Command -match '(?i)powershell|pwsh' -and $Command -match '(?i)(-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{40,})|((iex|invoke-expression).*(http|downloadstring|iwr|irm))|((http|downloadstring|iwr|irm).*(iex|invoke-expression))|frombase64string') { $risk = 'ALTA' }
    elseif ($Command -match '(?i)mshta(\.exe)?\s+(https?:|javascript:|vbscript:)') { $risk = 'ALTA' }
    # DA CONTROLLARE: eseguibile senza firma in AppData/Temp/ProgramData/Public, o script in quelle cartelle
    elseif ($bin -eq 'ALTA') { $risk = 'MEDIA' }
    elseif ($Command -match '(?i)\.(vbs|vbe|js|jse|hta|wsf)\b' -and (Get-PathRisk $Command) -eq 2) { $risk = 'MEDIA' }
    elseif ($bin -eq 'MEDIA') { $risk = 'BASSA' }
    $Rows.Add([pscustomobject]@{ Tipo = $Type; Posizione = $Location; Nome = $Name; Comando = $Command; Eseguibile = $exe; Firma = $sig.Status; Firmatario = $sig.Signer; Rischio = $risk; Note = $Extra })
    if ($risk) {
        $t = "$Type senza firma digitale da cartella utente: $Name"
        if ($risk -eq 'ALTA') { $t = "$Type che scarica o esegue codice nascosto: $Name" }
        Add-Finding $risk 'Avvio automatico' $t "$Location | $Command | firma $($sig.Status)" 'Verificare il file (SHA256 su VirusTotal). Se malevolo: isolare il PC, salvare le prove, poi rimuovere. Se legittimo, aggiungere la cartella in AllowPaths di config.json.' -Key $exe -KeyType path
    }
}

function Get-Autoruns {
    param([string[]]$UserDirs)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $runSub = @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    $roots = @([pscustomobject]@{ Name = 'HKLM'; Root = 'HKLM:' }) + @(Get-UserHives)
    foreach ($r in $roots) {
        foreach ($s in $runSub) {
            $k = "$($r.Root)\$s"
            if (-not (Test-Path $k)) { continue }
            $item = Get-Item $k -ErrorAction SilentlyContinue
            foreach ($vn in @($item.GetValueNames())) {
                if (-not $vn) { continue }
                Add-AutorunRow $rows 'Registro Run' "$($r.Name)\$s" $vn ([string]$item.GetValue($vn))
            }
        }
    }
    # Winlogon
    try {
        $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
        $rows.Add([pscustomobject]@{ Tipo = 'Winlogon'; Posizione = 'HKLM Winlogon'; Nome = 'Shell'; Comando = $wl.Shell; Eseguibile = ''; Firma = ''; Firmatario = ''; Rischio = ''; Note = '' })
        $rows.Add([pscustomobject]@{ Tipo = 'Winlogon'; Posizione = 'HKLM Winlogon'; Nome = 'Userinit'; Comando = $wl.Userinit; Eseguibile = ''; Firma = ''; Firmatario = ''; Rischio = ''; Note = '' })
        if ($wl.Shell -and $wl.Shell.Trim() -notmatch '^(?i)explorer\.exe,?$') { Add-Finding 'ALTA' 'Avvio automatico' 'Winlogon Shell modificato' $wl.Shell 'Deve essere solo explorer.exe.' }
        if ($wl.Userinit -and $wl.Userinit.Trim().TrimEnd(',') -notmatch '^(?i)(c:\\windows\\system32\\)?userinit\.exe$') { Add-Finding 'ALTA' 'Avvio automatico' 'Winlogon Userinit modificato' $wl.Userinit 'Deve essere solo C:\Windows\system32\userinit.exe,' }
    } catch { }
    # AppInit_DLLs
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        try {
            $v = (Get-ItemProperty $k -ErrorAction Stop).AppInit_DLLs
            if ($v -and $v.Trim()) {
                $rows.Add([pscustomobject]@{ Tipo = 'AppInit_DLLs'; Posizione = $k; Nome = 'AppInit_DLLs'; Comando = $v; Eseguibile = ''; Firma = ''; Firmatario = ''; Rischio = 'ALTA'; Note = '' })
                $asev = 'MEDIA'
                foreach ($dll in @($v -split '[,\s]+' | Where-Object { $_ })) { if ((Get-SigInfo $dll).Status -ne 'Valid') { $asev = 'ALTA' } }
                Add-Finding $asev 'Avvio automatico' 'AppInit_DLLs impostato (DLL caricata in ogni programma)' "$k = $v" 'Tecnica classica di iniezione: analizzare la DLL indicata.'
            }
        } catch { }
    }
    # IFEO debugger
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($k in @(Get-ChildItem $ifeo -ErrorAction SilentlyContinue)) {
        $dbg = $k.GetValue('Debugger')
        if ($dbg) {
            $sev = 'BASSA'
            if ($script:BrowserExe -contains $k.PSChildName.ToLowerInvariant()) { $sev = 'ALTA' }
            elseif ($k.PSChildName -match '(?i)^(sethc|utilman|osk|narrator|magnify|displayswitch|atbroker|msmpeng|mpcmdrun|taskmgr)\.exe$') { $sev = 'ALTA' }
            $rows.Add([pscustomobject]@{ Tipo = 'IFEO Debugger'; Posizione = $k.Name; Nome = $k.PSChildName; Comando = $dbg; Eseguibile = ''; Firma = ''; Firmatario = ''; Rischio = $sev; Note = '' })
            Add-Finding $sev 'Avvio automatico' "IFEO Debugger su $($k.PSChildName)" $dbg "Quando si avvia $($k.PSChildName) parte invece il programma indicato."
        }
    }
    # Esecuzione automatica: cartelle Startup
    $sdirs = @()
    foreach ($ud in $UserDirs) { $sdirs += Join-Parts $ud @('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup') }
    if ($env:ProgramData) { $sdirs += Join-Parts $env:ProgramData @('Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp') }
    $sh = $null
    try { $sh = New-Object -ComObject WScript.Shell } catch { }
    foreach ($d in $sdirs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.Name -ieq 'desktop.ini') { continue }
            $cmd = $f.FullName
            if ($f.Extension -ieq '.lnk' -and $sh) { try { $l = $sh.CreateShortcut($f.FullName); $cmd = ('"{0}" {1}' -f $l.TargetPath, $l.Arguments).Trim() } catch { } }
            Add-AutorunRow $rows 'Cartella Esecuzione automatica' $d $f.Name $cmd
        }
    }
    # Operazioni pianificate
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            foreach ($a in @($t.Actions)) {
                $exe = [string]$a.Execute
                if (-not $exe) { continue }
                $cmd = ('"{0}" {1}' -f $exe, $a.Arguments).Trim()
                $isMs = $t.TaskPath -like '\Microsoft\*'
                $exePath = Get-ExePathFromCommand $cmd
                if ($isMs -and (Get-PathRisk $exePath) -lt 1 -and $cmd -notmatch $script:ScriptHostRegex) { continue }
                $note = "Stato: $($t.State); Autore: $($t.Author)"
                Add-AutorunRow $rows 'Operazione pianificata' $t.TaskPath $t.TaskName $cmd $note
                if ($isMs -and (Get-PathRisk $exePath) -eq 2 -and (Get-SigInfo $exePath).Status -ne 'Valid') {
                    Add-Finding 'ALTA' 'Avvio automatico' "Operazione pianificata camuffata da Microsoft: $($t.TaskPath)$($t.TaskName)" $cmd 'Le attivita'' Microsoft non eseguono file da AppData/Temp.'
                }
            }
        }
    }
    # Servizi
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $pn = [string]$s.PathName
        if (-not $pn) { continue }
        $exe = Get-ExePathFromCommand $pn
        if ($exe -match '(?i)\\windows\\system32\\svchost\.exe$') { continue }
        Add-AutorunRow $rows 'Servizio' "$($s.StartMode) / $($s.State) / $($s.StartName)" "$($s.Name) ($($s.DisplayName))" $pn
    }
    # Sottoscrizioni WMI (persistenza fileless)
    try {
        foreach ($c in @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop)) {
            $cmd = [string]$c.CommandLineTemplate
            if (-not $cmd) { $cmd = [string]$c.ScriptText }
            $cls = $c.CimClass.CimClassName
            $rows.Add([pscustomobject]@{ Tipo = 'WMI Consumer'; Posizione = 'root\subscription'; Nome = $c.Name; Comando = $cmd; Eseguibile = ''; Firma = ''; Firmatario = ''; Rischio = ''; Note = $cls })
            if ($cls -in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer') -and $c.Name -notmatch '^(SCM Event Log Consumer|BVTConsumer)$') {
                $wsev = 'MEDIA'
                if ($cls -eq 'ActiveScriptEventConsumer' -or $cmd -match '(?i)powershell|mshta|wscript|cscript|cmd(\.exe)?\s*/c|https?:') { $wsev = 'ALTA' }
                Add-Finding $wsev 'Avvio automatico' "Persistenza WMI: $($c.Name) ($cls)" $cmd 'Tecnica fileless usata da malware avanzati: analizzare e rimuovere.'
            }
        }
    } catch { }
    return $rows.ToArray()
}

# ----------------------------------------------------------------------------------------------
#  Raccolta: accesso remoto, rete, certificati
# ----------------------------------------------------------------------------------------------
function Get-RemoteAccess {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        if (("{0} {1}" -f $p.Name, $p.ExecutablePath) -match $script:RemoteToolRegex) {
            $rows.Add([pscustomobject]@{ Tipo = 'Processo'; Nome = $p.Name; Dettaglio = $p.ExecutablePath; Note = "PID $($p.ProcessId)" })
        }
    }
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        if (("{0} {1} {2}" -f $s.Name, $s.DisplayName, $s.PathName) -match $script:RemoteToolRegex) {
            $rows.Add([pscustomobject]@{ Tipo = 'Servizio'; Nome = $s.DisplayName; Dettaglio = $s.PathName; Note = "$($s.State) / $($s.StartMode)" })
        }
    }
    foreach ($sw in @(Get-InstalledSoftwareRaw)) {
        if (("{0} {1}" -f $sw.Nome, $sw.Editore) -match $script:RemoteToolRegex) {
            $rows.Add([pscustomobject]@{ Tipo = 'Installato'; Nome = $sw.Nome; Dettaglio = $sw.Editore; Note = "installato $($sw.DataInstallazione)" })
        }
    }
    # Log connessioni in ingresso AnyDesk / TeamViewer
    $logs = @()
    foreach ($ud in (Get-UserProfileDirs)) { $logs += Join-Parts $ud @('AppData', 'Roaming', 'AnyDesk', 'ad.trace') }
    if ($env:ProgramData) { $logs += Join-Parts $env:ProgramData @('AnyDesk', 'ad_svc.trace'); $logs += Join-Parts $env:ProgramData @('AnyDesk', 'connection_trace.txt') }
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) { if ($pf) { $logs += Join-Parts $pf @('TeamViewer', 'Connections_incoming.txt') } }
    foreach ($l in $logs) {
        if (-not (Test-Path -LiteralPath $l)) { continue }
        $lines = @(Get-Content -LiteralPath $l -ErrorAction SilentlyContinue | Where-Object { $_ -match '(?i)incoming|Incoming session|Logged in from|remote_id|external address|\t' } | Select-Object -Last 200)
        foreach ($ln in $lines) { $rows.Add([pscustomobject]@{ Tipo = 'Log connessioni'; Nome = (Split-Path $l -Leaf); Dettaglio = $ln.Trim(); Note = $l }) }
        if ($script:OutDir) { try { Copy-Item -LiteralPath $l -Destination (Join-Path $script:OutDir ('log_' + (Split-Path (Split-Path $l -Parent) -Leaf) + '_' + (Split-Path $l -Leaf))) -ErrorAction SilentlyContinue } catch { } }
    }
    Add-RemoteToolFindings $rows.ToArray()
    # RDP
    try {
        $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections
        $rows.Add([pscustomobject]@{ Tipo = 'RDP'; Nome = 'Desktop remoto'; Dettaglio = "fDenyTSConnections=$deny"; Note = '' })
        # lo stato RDP e' valutato in 'Configurazione di sicurezza'
    } catch { }
    return $rows.ToArray()
}

function Add-RemoteToolFindings {
    # Una sola segnalazione per programma: processo, servizio e voce installata dello stesso strumento vanno insieme
    param([object[]]$Rows)
    $tools = [ordered]@{}
    foreach ($r in @($Rows | Where-Object { $_.Tipo -ne 'Log connessioni' -and $_.Tipo -ne 'RDP' })) {
        $tool = [regex]::Match(("{0} {1}" -f $r.Nome, $r.Dettaglio), $script:RemoteToolRegex).Value.ToLowerInvariant()
        if (-not $tool) { $tool = ([string]$r.Nome).ToLowerInvariant() }
        if (-not $tools.Contains($tool)) { $tools[$tool] = New-Object 'System.Collections.Generic.List[object]' }
        $tools[$tool].Add($r)
    }
    foreach ($tool in @($tools.Keys)) {
        $items = $tools[$tool].ToArray()
        $display = $null
        foreach ($t in @('Installato', 'Servizio', 'Processo')) {
            if (-not $display) { $display = @($items | Where-Object { $_.Tipo -eq $t } | Select-Object -ExpandProperty Nome -First 1) | Select-Object -First 1 }
        }
        if (-not $display) { $display = [string]$items[0].Nome }
        $parts = @()
        foreach ($t in @('Installato', 'Servizio', 'Processo')) {
            $n = @($items | Where-Object { $_.Tipo -eq $t } | Select-Object -ExpandProperty Nome -Unique)
            if ($n.Count -gt 0) {
                $lbl = switch ($t) { 'Installato' { 'programma installato' } 'Servizio' { 'servizio' } default { 'processo in esecuzione' } }
                $parts += ('{0} ({1})' -f $lbl, ($n -join ', '))
            }
        }
        $key = ((@($items | Select-Object -ExpandProperty Nome -Unique) + $tool) -join ' | ')
        Add-Finding 'MEDIA' 'Accesso remoto' "Programma di controllo remoto presente sul PC: $display" ("Trovato come: {0}. Vedi accesso_remoto.csv e i log copiati nel report." -f ($parts -join '; ')) "Verificare che sia autorizzato e chi si collega. Con il controllo remoto un truffatore puo' modificare il bonifico mentre il cliente lavora. Controllare nei log le connessioni in ingresso nelle date dei bonifici fraudolenti. Se e' lo strumento del vostro tecnico, aggiungerlo in AllowRemoteTools di config.json." -Key $key -KeyType remote
    }
}

function Get-NetworkReport {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $procs = @{}
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $procs[[int]$p.ProcessId] = $p }
    foreach ($c in @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -in @('Established', 'Listen', 'SynSent') })) {
        $p = $procs[[int]$c.OwningProcess]
        $pn = ''; $pp = ''
        if ($p) { $pn = $p.Name; $pp = $p.ExecutablePath }
        $rows.Add([pscustomobject]@{ Stato = [string]$c.State; Locale = "$($c.LocalAddress):$($c.LocalPort)"; Remoto = "$($c.RemoteAddress):$($c.RemotePort)"; PID = $c.OwningProcess; Processo = $pn; Percorso = $pp })
        if ($c.State -eq 'Established' -and $c.RemoteAddress -in @('127.0.0.1', '::1') -and $c.RemotePort -in @(9222, 9229) -and $script:BrowserExe -notcontains ([string]$pn).ToLowerInvariant()) {
            Add-Finding 'ALTA' 'Rete' "Il programma $pn e' collegato alla porta di debug del browser ($($c.RemotePort))" "$pp PID $($c.OwningProcess)" 'Tecnica degli infostealer per leggere cookie e pagine della banca dal browser. Analizzare subito il programma.' -Key $pp -KeyType path
        }
        if ($c.State -eq 'Listen' -and $script:BrowserExe -contains ([string]$pn).ToLowerInvariant() -and $c.LocalPort -ge 9222 -and $c.LocalPort -le 9230 -and $script:OwnPids -notcontains [int]$c.OwningProcess) {
            Add-Finding 'ALTA' 'Rete' "Il browser $pn e' in ascolto sulla porta $($c.LocalPort)" "PID $($c.OwningProcess)" 'Tipico del debug remoto (--remote-debugging-port): un altro programma puo'' leggere e modificare le pagine.'
        }
    }
    return $rows.ToArray()
}

function Get-ProxyHostsDns {
    param([string[]]$BankDomains)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    # hosts
    $hp = Join-Parts $env:SystemRoot @('System32', 'drivers', 'etc', 'hosts')
    foreach ($e in (Get-HostsEntries $hp $BankDomains)) {
        $rows.Add([pscustomobject]@{ Tipo = 'hosts'; Nome = $e.Host; Valore = $e.IP; Note = "riga $($e.Riga)" })
        if ($e.Banca) { Add-Finding 'ALTA' 'Rete/DNS' "File hosts reindirizza il dominio della banca: $($e.Host) -> $($e.IP)" $hp 'Il PC viene mandato su un sito falso. Pulire il file hosts e cercare il malware che lo ha modificato.' }
        elseif (-not $e.Localhost) { Add-Finding 'BASSA' 'Rete/DNS' "Voce personalizzata nel file hosts: $($e.Host) -> $($e.IP)" $hp 'Verificare che sia voluta.' }
    }
    if ($script:OutDir -and (Test-Path -LiteralPath $hp)) { Copy-Item -LiteralPath $hp -Destination (Join-Path $script:OutDir 'hosts.txt') -ErrorAction SilentlyContinue }
    # proxy WinINET per utente
    foreach ($h in (Get-UserHives)) {
        $k = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        try { $is = Get-ItemProperty $k -ErrorAction Stop } catch { continue }
        $rows.Add([pscustomobject]@{ Tipo = 'Proxy utente'; Nome = $h.Name; Valore = "ProxyEnable=$($is.ProxyEnable) ProxyServer=$($is.ProxyServer) AutoConfigURL=$($is.AutoConfigURL)"; Note = $k })
        if ($is.ProxyEnable -eq 1 -and $is.ProxyServer) {
            $sev = 'MEDIA'
            if ($is.ProxyServer -match '(?i)127\.0\.0\.1|localhost|\[::1\]') { $sev = 'MEDIA'; $script:LocalProxyActive = $true }
            Add-Finding $sev 'Rete/Proxy' "Proxy di sistema attivo per $($h.Name): $($is.ProxyServer)" $k 'Un proxy locale (127.0.0.1) intercetta e puo'' modificare il traffico verso la banca. Verificare quale programma ascolta su quella porta (connessioni.csv).'
        }
        if ($is.AutoConfigURL) {
            $pacSev = 'MEDIA'
            $pacHost = ([regex]::Match([string]$is.AutoConfigURL, '^[a-z]+://([^/:]+)', 'IgnoreCase')).Groups[1].Value
            if ($is.AutoConfigURL -match '(?i)^file:|127\.0\.0\.1|localhost' -or ($pacHost -match '^\d+\.\d+\.\d+\.\d+$' -and -not (Test-PrivateIp $pacHost))) { $pacSev = 'ALTA' }
            Add-Finding $pacSev 'Rete/Proxy' "Script PAC (configurazione proxy automatica) per $($h.Name)" $is.AutoConfigURL 'Tecnica usata dai trojan bancari per dirottare solo i siti delle banche. Scaricare e leggere il file PAC.'
        }
    }
    # WinHTTP
    try {
        $wh = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -ErrorAction Stop).WinHttpSettings
        if ($wh -and $wh.Length -gt 12) {
            $flags = $wh[8]
            $txt = (& netsh winhttp show proxy 2>$null) -join ' '
            $rows.Add([pscustomobject]@{ Tipo = 'Proxy WinHTTP'; Nome = 'sistema'; Valore = $txt.Trim(); Note = "flag=$flags" })
            if ($flags -band 2) { Add-Finding 'BASSA' 'Rete/Proxy' 'Proxy WinHTTP di sistema configurato' $txt.Trim() 'Verificare che sia il proxy aziendale.' }
        }
    } catch { }
    # DNS configurati
    if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
        foreach ($d in @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses })) {
            $rows.Add([pscustomobject]@{ Tipo = 'Server DNS'; Nome = $d.InterfaceAlias; Valore = ($d.ServerAddresses -join ', '); Note = '' })
        }
    }
    # confronto risoluzione dominio banca: DNS del PC vs DNS pubblici
    $dnsOn = $true
    if ($script:Config -and $script:Config['DnsCompare'] -eq $false) { $dnsOn = $false }
    if ($dnsOn -and (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        foreach ($dom in $BankDomains) {
            foreach ($q in @($dom, "www.$dom")) {
                $loc = @(Resolve-DnsName -Name $q -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
                if ($loc.Count -eq 0) { continue }
                $pub = @()
                foreach ($srv in @('1.1.1.1', '8.8.8.8', '9.9.9.9')) {
                    $pub += @(Resolve-DnsName -Name $q -Type A -DnsOnly -Server $srv -QuickTimeout -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
                }
                $pub = @($pub | Select-Object -Unique)
                $common = @($loc | Where-Object { $pub -contains $_ })
                $rows.Add([pscustomobject]@{ Tipo = 'Risoluzione DNS'; Nome = $q; Valore = "PC: $($loc -join ', ') | pubblici: $($pub -join ', ')"; Note = '' })
                $privLoc = @($loc | Where-Object { Test-PrivateIp $_ })
                if ($privLoc.Count -gt 0 -and @($pub | Where-Object { Test-PrivateIp $_ }).Count -eq 0) {
                    Add-Finding 'ALTA' 'Rete/DNS' "Il dominio della banca $q viene risolto verso un indirizzo della rete locale" "PC: $($loc -join ', ') / DNS pubblici: $($pub -join ', ')" 'Dirottamento DNS certo (router, DNS aziendale o PC manomesso): il browser viene mandato su un server diverso da quello della banca. Verificare i DNS del router e del PC.'
                } elseif ($pub.Count -gt 0 -and $common.Count -eq 0) {
                    Add-Finding 'BASSA' 'Rete/DNS' "Il dominio $q risolve su IP diversi rispetto ai DNS pubblici" "PC: $($loc -join ', ') / pubblici: $($pub -join ', ')" 'Puo'' essere normale (CDN), ma se gli IP del PC non appartengono alla banca c''e'' un dirottamento DNS (router o PC). Verificare il proprietario degli IP (whois).'
                }
            }
        }
    }
    # DNS cache
    if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
        foreach ($c in @(Get-DnsClientCache -ErrorAction SilentlyContinue)) {
            $rows.Add([pscustomobject]@{ Tipo = 'Cache DNS'; Nome = $c.Entry; Valore = $c.Data; Note = '' })
        }
    }
    return $rows.ToArray()
}

function Get-RootCertificates {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $known = '(?i)microsoft|digicert|sectigo|comodo|usertrust|globalsign|entrust|isrg|let.s encrypt|amazon|google trust|gts root|baltimore|verisign|thawte|geotrust|quovadis|identrust|starfield|go ?daddy|certum|actalis|infocert|aruba|namirial|intesi|poste|buypass|swisssign|t-telesec|telesec|deutsche telekom|d-trust|telia|izenpe|certigna|harica|hellenic|ssl\.com|trustwave|securetrust|secure trust|aaa certificate|symantec|network solutions|hongkong post|certainly|atos|emsign|firmaprofesional|accv|e-szigno|netlock|twca|chunghwa|secom|gdca|cfca|microsec|tubitak|staat der nederlanden|autoridad|class 3 public|cybertrust|equifax|addtrust|dst root|xramp|wisekey|oiste|affirmtrust|certplus|keynectis|opentrust|sk id|e-tugra|anf |camerfirma|acraiz|government|trustcor|vtrus|ssl corp|naver|cisco|apple|asseco|unizeto|qualified|nemlog|digidentity|pkioverheid|ecommerce|trust services|globaltrust|bjca|telekom|kisa|certsign|eca root|ica |e-commerce|atrust|a-trust|halcom|rsa|thawte|sonera|camerfirma|d-trust|izenpe|ac raiz|copyright \(c\) 1997 microsoft|root agency'
    $avRegex = '(?i)avast|avg|kaspersky|eset|bitdefender|fortinet|fortigate|sophos|norton|mcafee|trend ?micro|zscaler|netskope|palo alto|check ?point|watchguard|cisco umbrella|f-secure|malwarebytes|webroot|panda|g data'
    $mitmRegex = '(?i)mitmproxy|fiddler|do_not_trust|charles proxy|burp|portswigger|superfish|privdog|komodia|proxyman|httpdebugger|http toolkit|telerik|owasp|zap root'
    $stores = @('Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root', 'Cert:\LocalMachine\AuthRoot')
    $lmThumbs = @{}
    foreach ($st in $stores) {
        foreach ($c in @(Get-ChildItem $st -ErrorAction SilentlyContinue)) {
            if ($st -like '*LocalMachine*') { $lmThumbs[$c.Thumbprint] = $true }
            $rows.Add([pscustomobject]@{ Archivio = $st; Soggetto = $c.Subject; Emittente = $c.Issuer; Thumbprint = $c.Thumbprint; Dal = $c.NotBefore; Al = $c.NotAfter; Nome = $c.FriendlyName })
        }
    }
    foreach ($r in $rows) {
        $txt = "$($r.Soggetto) $($r.Nome)"
        if ($txt -match $mitmRegex) {
            $msev = 'MEDIA'
            if ($script:LocalProxyActive) { $msev = 'ALTA' }
            Add-Finding $msev 'Certificati' "Certificato radice di uno strumento di intercettazione HTTPS: $($r.Soggetto)" "$($r.Archivio) $($r.Thumbprint)" -Key $r.Thumbprint -KeyType cert -Advice "Permette di leggere e modificare il traffico HTTPS verso la banca. Rimuoverlo se nessuno lo ha installato volutamente."
        } elseif ($txt -match $avRegex) {
            Add-Finding 'BASSA' 'Certificati' "Certificato radice dell'antivirus/firewall (ispezione HTTPS): $($r.Soggetto)" "$($r.Archivio)" 'Normale se l''antivirus fa scansione HTTPS.'
        } elseif ($r.Archivio -eq 'Cert:\CurrentUser\Root' -and -not $lmThumbs.ContainsKey($r.Thumbprint)) {
            Add-Finding 'BASSA' 'Certificati' "Certificato radice installato solo per l'utente: $($r.Soggetto)" "$($r.Thumbprint), valido dal $($r.Dal)" 'Un malware senza privilegi installa qui il proprio certificato per intercettare HTTPS. Verificare. Se legittimo, aggiungere il thumbprint in AllowCertThumbprints.' -Key $r.Thumbprint -KeyType cert
        } elseif ($r.Archivio -ne 'Cert:\LocalMachine\AuthRoot' -and $txt -notmatch $known -and $r.Dal -is [datetime] -and $r.Dal -ge (Get-Date).AddYears(-3)) {
            Add-Finding 'BASSA' 'Certificati' "Certificato radice recente non riconosciuto: $($r.Soggetto)" "$($r.Archivio) $($r.Thumbprint), valido dal $($r.Dal)" 'Verificare se appartiene a un software aziendale noto; altrimenti rimuoverlo. Se legittimo, aggiungere il thumbprint in AllowCertThumbprints.' -Key $r.Thumbprint -KeyType cert
        }
    }
    return $rows.ToArray()
}

# ----------------------------------------------------------------------------------------------
#  Raccolta: software, antivirus, eventi, utenti, file recenti
# ----------------------------------------------------------------------------------------------
function Get-InstalledSoftwareRaw {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($h in (Get-UserHives)) { $paths += "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    foreach ($p in $paths) {
        foreach ($k in @(Get-ChildItem $p -ErrorAction SilentlyContinue)) {
            $dn = $k.GetValue('DisplayName')
            if (-not $dn) { continue }
            $rows.Add([pscustomobject]@{
                    Nome = [string]$dn; Versione = [string]$k.GetValue('DisplayVersion'); Editore = [string]$k.GetValue('Publisher')
                    DataInstallazione = [string]$k.GetValue('InstallDate'); Cartella = [string]$k.GetValue('InstallLocation'); Chiave = $k.Name
                })
        }
    }
    return $rows.ToArray()
}

function Get-InstalledSoftware {
    param([int]$Days)
    $rows = @(Get-InstalledSoftwareRaw)
    $limit = (Get-Date).AddDays(-$Days).ToString('yyyyMMdd')
    $recent = @($rows | Where-Object { $_.DataInstallazione -match '^\d{8}$' -and $_.DataInstallazione -ge $limit })
    if ($recent.Count -gt 0) {
        Add-Finding 'BASSA' 'Software' "$($recent.Count) programmi installati negli ultimi $Days giorni" (($recent | ForEach-Object { "$($_.Nome) [$($_.DataInstallazione)]" }) -join '; ') 'Controllare che siano tutti voluti, soprattutto quelli installati poco prima dei bonifici fraudolenti.'
    }
    return $rows
}

function Get-DefenderReport {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($av in @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)) {
            $rows.Add([pscustomobject]@{ Tipo = 'Antivirus registrato'; Nome = $av.displayName; Valore = $av.pathToSignedProductExe; Data = $av.timestamp })
        }
    } catch { }
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return $rows.ToArray() }
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        foreach ($pn in @('AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'IsTamperProtected', 'AntivirusSignatureLastUpdated', 'QuickScanEndTime', 'FullScanEndTime')) {
            $rows.Add([pscustomobject]@{ Tipo = 'Stato Defender'; Nome = $pn; Valore = [string]$st.$pn; Data = '' })
        }
        $thirdParty = @($rows | Where-Object { $_.Tipo -eq 'Antivirus registrato' -and $_.Nome -notmatch 'Defender' }).Count -gt 0
        if (-not $st.RealTimeProtectionEnabled -and -not $thirdParty) { $script:NoAntivirus = $true }
        if ($st.AntivirusSignatureLastUpdated -and $st.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-7) -and -not $thirdParty) { Add-Finding 'BASSA' 'Antivirus' 'Firme Defender non aggiornate da oltre 7 giorni' ([string]$st.AntivirusSignatureLastUpdated) 'Aggiornare e lanciare una scansione completa.' }
    } catch { }
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        foreach ($pair in @(@('ExclusionPath', $pref.ExclusionPath), @('ExclusionProcess', $pref.ExclusionProcess), @('ExclusionExtension', $pref.ExclusionExtension), @('ExclusionIpAddress', $pref.ExclusionIpAddress))) {
            foreach ($v in @($pair[1])) {
                if (-not $v -or $v -match 'N/A') { continue }
                $rows.Add([pscustomobject]@{ Tipo = 'Esclusione Defender'; Nome = $pair[0]; Valore = $v; Data = '' })
                $sev = 'BASSA'
                if ((Get-PathRisk ([string]$v + '\')) -eq 2 -or $v -match '(?i)\\Users\\?$|^\.?(exe|dll|ps1|js|vbs)$') { $sev = 'MEDIA' }
                if ($v -match '^(?i)[a-z]:\\?$|^(?i)[a-z]:\\Users\\?$' -or ($pair[0] -eq 'ExclusionExtension' -and $v -match '^(?i)\.?(exe|dll)$')) { $sev = 'ALTA' }
                Add-Finding $sev 'Antivirus' "Esclusione antivirus: $($pair[0]) = $v" '' 'I malware aggiungono esclusioni per non essere rilevati. Rimuovere quelle non volute.'
            }
        }
    } catch { }
    try {
        $threats = @{}
        foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) { $threats[[string]$t.ThreatID] = $t.ThreatName }
        foreach ($d in @(Get-MpThreatDetection -ErrorAction Stop)) {
            $nm = $threats[[string]$d.ThreatID]
            $res = ($d.Resources -join ' | ')
            $rows.Add([pscustomobject]@{ Tipo = 'Rilevamento'; Nome = $nm; Valore = $res; Data = $d.InitialDetectionTime })
            $dsev = 'ALTA'
            try { if ([datetime]$d.InitialDetectionTime -lt (Get-Date).AddDays(-90)) { $dsev = 'MEDIA' } } catch { }
            Add-Finding $dsev 'Antivirus' "Defender ha rilevato: $nm" "$($d.InitialDetectionTime) - $res" 'Anche se risulta rimosso, potrebbe aver lasciato altri componenti. Verificare la data rispetto ai bonifici fraudolenti.'
        }
    } catch { }
    return $rows.ToArray()
}

function Get-EventXmlData {
    param($Evt)
    $h = @{}
    try {
        $x = [xml]$Evt.ToXml()
        foreach ($d in $x.Event.EventData.Data) { $h[[string]$d.Name] = [string]$d.'#text' }
        if ($x.Event.UserData) {
            foreach ($n in $x.Event.UserData.FirstChild.ChildNodes) { $h[[string]$n.Name] = [string]$n.InnerText }
        }
    } catch { }
    return $h
}

function Get-SecurityEvents {
    param([int]$Days)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) { throw 'Get-WinEvent non disponibile' }
    $ms = [int64]$Days * 86400000
    $queries = @(
        @{ Log = 'Security'; Desc = 'Accesso RDP (4624 tipo 10)'; X = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='LogonType']='10']]" },
        @{ Log = 'Security'; Desc = 'Accesso di rete con password in chiaro/NTLM da remoto (4624 tipo 3)'; X = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='LogonType']='3'] and EventData[Data[@Name='AuthenticationPackageName']='NTLM']]" },
        @{ Log = 'Security'; Desc = 'Accesso fallito (4625)'; X = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]]" },
        @{ Log = 'Security'; Desc = 'Utente creato (4720)'; X = "*[System[(EventID=4720) and TimeCreated[timediff(@SystemTime) <= $ms]]]" },
        @{ Log = 'Security'; Desc = 'Aggiunta a gruppo admin (4732)'; X = "*[System[(EventID=4732) and TimeCreated[timediff(@SystemTime) <= $ms]]]" },
        @{ Log = 'Security'; Desc = 'Registro Security cancellato (1102)'; X = "*[System[(EventID=1102)]]" },
        @{ Log = 'System'; Desc = 'Servizio installato (7045)'; X = "*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= $ms]]]" },
        @{ Log = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Desc = 'Sessione RDP (21/25)'; X = "*[System[(EventID=21 or EventID=25) and TimeCreated[timediff(@SystemTime) <= $ms]]]" },
        @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Desc = 'Defender rilevamento (1116/1117)'; X = "*[System[(EventID=1116 or EventID=1117 or EventID=5001) and TimeCreated[timediff(@SystemTime) <= $ms]]]" },
        @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Desc = 'Script PowerShell sospetto (4104 avviso)'; X = "*[System[(EventID=4104) and (Level=3) and TimeCreated[timediff(@SystemTime) <= $ms]]]" }
    )
    $rdpCount = 0; $failed = @{}; $rdpExt = @{}
    foreach ($q in $queries) {
        $evs = @()
        try { $evs = @(Get-WinEvent -LogName $q.Log -FilterXPath $q.X -MaxEvents 500 -ErrorAction Stop) } catch { continue }
        foreach ($e in $evs) {
            $d = Get-EventXmlData $e
            $who = @($d['TargetUserName'], $d['User'], $d['SubjectUserName']) | Where-Object { $_ } | Select-Object -First 1
            $from = @($d['IpAddress'], $d['Address'], $d['WorkstationName']) | Where-Object { $_ -and $_ -ne '-' } | Select-Object -First 1
            $det = ''
            if ($e.Id -eq 7045) { $det = "$($d['ServiceName']) -> $($d['ImagePath'])" }
            elseif ($e.Id -eq 4104) { $det = ([string]$d['ScriptBlockText']); if ($det.Length -gt 500) { $det = $det.Substring(0, 500) + '...' } }
            elseif ($e.Id -in 1116, 1117) { $det = "$($d['Threat Name']) $($d['Path'])" }
            $rows.Add([pscustomobject]@{ Data = $e.TimeCreated; Registro = $q.Log; ID = $e.Id; Descrizione = $q.Desc; Utente = $who; Origine = $from; Dettaglio = $det })
            if ($e.Id -eq 4624 -and $q.Desc -like '*RDP*') { $rdpCount++; if ($from -and -not (Test-PrivateIp $from)) { $rdpExt[$from] = 1 + [int]$rdpExt[$from] } }
            if ($e.Id -eq 4625 -and $from) { $failed[$from] = 1 + [int]$failed[$from] }
            if ($e.Id -eq 7045) {
                $exe = Get-ExePathFromCommand $d['ImagePath']
                $r = Get-BinaryRisk $exe $null
                $ssev = ''
                if ($d['ImagePath'] -match '(?i)(%COMSPEC%|cmd(\.exe)?).*/c.*(powershell|echo|\\\\\.\\pipe)|powershell.*(-e(nc)?\s+[a-z0-9+/=]{40,}|frombase64|downloadstring|iex)') { $ssev = 'ALTA' }
                elseif ($r -eq 'ALTA') { $ssev = 'MEDIA' }
                if ($ssev) { Add-Finding $ssev 'Eventi' "Servizio sospetto installato il $($e.TimeCreated): $($d['ServiceName'])" $d['ImagePath'] 'Verificare il programma.' }
            }
            if ($e.Id -eq 1102) { Add-Finding 'MEDIA' 'Eventi' "Registro di sicurezza cancellato il $($e.TimeCreated)" "Utente: $who" 'Fatto certo: qualcuno ha cancellato il registro degli accessi. Verificare chi e perche''.' }
            if ($e.Id -eq 4720) { Add-Finding 'BASSA' 'Eventi' "Creato utente locale il $($e.TimeCreated): $($d['TargetUserName'])" "da $($d['SubjectUserName'])" 'Verificare che sia stato creato volutamente.' }
        }
    }
    if ($rdpCount -gt 0) { Add-Finding 'BASSA' 'Accesso remoto' "$rdpCount accessi RDP negli ultimi $Days giorni" 'Vedi eventi.csv (utente e IP di provenienza)' 'Confrontare date e ore con quelle dei bonifici fraudolenti.' }
    foreach ($ip in $rdpExt.Keys) { Add-Finding 'ALTA' 'Accesso remoto' "Accesso al PC con Desktop remoto da Internet (IP pubblico $ip)" "$($rdpExt[$ip]) accessi riusciti negli ultimi $Days giorni - dettagli in eventi.csv" 'Qualcuno da Internet ha effettuato l''accesso al PC. Se non e'' un accesso autorizzato (VPN/tecnico), il PC e'' controllato da remoto: cambiare subito le password e chiudere RDP verso Internet.' }
    foreach ($ip in $failed.Keys) { if ($failed[$ip] -ge 20) { $fs = 'BASSA'; if (-not (Test-PrivateIp $ip)) { $fs = 'MEDIA' }; Add-Finding $fs 'Eventi' "$($failed[$ip]) tentativi di accesso falliti da $ip" '' 'Tentativi di indovinare la password: se l''IP e'' pubblico il PC e'' raggiungibile da Internet.' } }
    return $rows.ToArray()
}

function Get-LocalAccounts {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) { throw 'Get-LocalUser non disponibile' }
    $admins = @()
    try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch {
        try {
            $grp = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            $admins = @(& net localgroup $grp 2>$null | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch '^(The command|Esecuzione comando|Comando)' })
        } catch { }
    }
    foreach ($u in @(Get-LocalUser)) {
        $isAdm = @($admins | Where-Object { $_ -match ('(^|\\)' + [regex]::Escape($u.Name) + '$') }).Count -gt 0
        $rows.Add([pscustomobject]@{ Utente = $u.Name; Attivo = $u.Enabled; Amministratore = $isAdm; UltimoAccesso = $u.LastLogon; PasswordImpostata = $u.PasswordLastSet; Descrizione = $u.Description })
    }
    foreach ($a in $admins) { if (-not @($rows | Where-Object { $a -match ('(^|\\)' + [regex]::Escape($_.Utente) + '$') }).Count) { $rows.Add([pscustomobject]@{ Utente = $a; Attivo = ''; Amministratore = $true; UltimoAccesso = ''; PasswordImpostata = ''; Descrizione = '(dominio o account non locale)' }) } }
    if (@($admins | Where-Object { $_ -match ('(^|\\)' + [regex]::Escape($env:USERNAME) + '$') }).Count) {
        Add-Finding 'BASSA' 'Account' "L'utente $env:USERNAME e' amministratore del PC" '' 'Per i bonifici usare un utente standard (non amministratore): limita molto cosa puo'' installare un malware.'
    }
    return $rows.ToArray()
}

function Get-RecentFiles {
    param([string[]]$UserDirs, [int]$Days)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $limit = (Get-Date).AddDays(-$Days)
    $ext = @('.exe', '.dll', '.scr', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.hta', '.bat', '.cmd', '.wsf', '.jar', '.msi', '.lnk', '.pif', '.cpl')
    $targets = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ud in $UserDirs) {
        $targets.Add(@((Join-Parts $ud @('AppData', 'Roaming')), 4))
        $targets.Add(@((Join-Parts $ud @('AppData', 'Local', 'Temp')), 3))
        $targets.Add(@((Join-Parts $ud @('AppData', 'Local')), 1))
        $targets.Add(@((Join-Parts $ud @('AppData', 'LocalLow')), 3))
        $targets.Add(@((Join-Path $ud 'Downloads'), 2))
    }
    if ($env:ProgramData) { $targets.Add(@($env:ProgramData, 2)) }
    if ($env:PUBLIC) { $targets.Add(@($env:PUBLIC, 3)) }
    if ($env:windir) { $targets.Add(@((Join-Path $env:windir 'Temp'), 2)) }
    $count = 0
    foreach ($t in $targets) {
        if ($count -ge 1500) { break }
        if (-not (Test-Path -LiteralPath $t[0])) { continue }
        $files = @(Get-ChildItem -LiteralPath $t[0] -File -Recurse -Depth $t[1] -Force -ErrorAction SilentlyContinue |
                Where-Object { ($ext -contains $_.Extension.ToLowerInvariant()) -and ($_.CreationTime -ge $limit -or $_.LastWriteTime -ge $limit) -and $_.FullName -notmatch '(?i)\\(Google\\Chrome|Microsoft\\Edge|Mozilla\\Firefox|BraveSoftware)\\(User Data|Profiles)\\|\\Microsoft\\Windows\\(Recent|INetCache|Explorer)\\|\\Packages\\|\\assembly\\' })
        foreach ($f in $files) {
            $count++
            if ($count -gt 1500) { break }
            $sig = [pscustomobject]@{ Status = ''; Signer = '' }
            if ($f.Extension -in @('.exe', '.dll', '.scr', '.msi', '.ps1', '.cpl')) { $sig = Get-SigInfo $f.FullName }
            $risk = ''
            if ($f.Extension -in @('.exe', '.scr', '.pif', '.cpl') -and $sig.Status -ne 'Valid' -and (Get-PathRisk $f.FullName) -eq 2) { $risk = 'ALTA' }
            elseif ($f.Extension -in @('.vbs', '.vbe', '.js', '.jse', '.hta', '.wsf', '.jar') -and (Get-PathRisk $f.FullName) -eq 2) { $risk = 'MEDIA' }
            elseif ($f.Extension -eq '.dll' -and $sig.Status -ne 'Valid' -and (Get-PathRisk $f.FullName) -eq 2) { $risk = 'MEDIA' }
            $hash = ''
            if ($risk -or $f.Length -lt 50MB) { $hash = Get-FileSha256 $f.FullName }
            $rows.Add([pscustomobject]@{ File = $f.FullName; Dimensione = $f.Length; Creato = $f.CreationTime; Modificato = $f.LastWriteTime; Firma = $sig.Status; Firmatario = $sig.Signer; SHA256 = $hash; Rischio = $risk })
            if ($risk) {
                Add-Finding 'BASSA' 'File recenti' "File eseguibile/script recente non firmato: $($f.Name)" "$($f.FullName) | creato $($f.CreationTime) | SHA256 $hash" 'Cercare lo SHA256 su VirusTotal. Confrontare la data di creazione con i bonifici fraudolenti.' -Key $f.FullName -KeyType path
            }
        }
    }
    return $rows.ToArray()
}

function Get-SystemInfo {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $rows.Add([pscustomobject]@{ Voce = 'Computer'; Valore = [Environment]::MachineName })
    $rows.Add([pscustomobject]@{ Voce = 'Utente'; Valore = "$env:USERDOMAIN\$env:USERNAME" })
    $rows.Add([pscustomobject]@{ Voce = 'Amministratore'; Valore = $script:IsAdmin })
    $rows.Add([pscustomobject]@{ Voce = 'PowerShell'; Valore = $PSVersionTable.PSVersion.ToString() })
    $rows.Add([pscustomobject]@{ Voce = 'Data analisi'; Valore = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') })
    $rows.Add([pscustomobject]@{ Voce = 'Versione script'; Valore = $script:Version })
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $rows.Add([pscustomobject]@{ Voce = 'Sistema'; Valore = "$($os.Caption) $($os.Version) build $($os.BuildNumber)" })
        $rows.Add([pscustomobject]@{ Voce = 'Installato il'; Valore = $os.InstallDate })
        $rows.Add([pscustomobject]@{ Voce = 'Ultimo avvio'; Valore = $os.LastBootUpTime })
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $rows.Add([pscustomobject]@{ Voce = 'Dominio/Gruppo'; Valore = $cs.Domain })
        $rows.Add([pscustomobject]@{ Voce = 'Modello'; Valore = "$($cs.Manufacturer) $($cs.Model)" })
    } catch { }
    try {
        foreach ($a in @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4Address })) {
            $rows.Add([pscustomobject]@{ Voce = "Rete $($a.InterfaceAlias)"; Valore = "IP $($a.IPv4Address.IPAddress) GW $($a.IPv4DefaultGateway.NextHop) DNS $($a.DNSServer.ServerAddresses -join ',')" })
        }
    } catch { }
    if (-not $script:IsAdmin) {
        Add-Finding 'BASSA' 'Analisi' 'Analisi eseguita SENZA privilegi di amministratore' '' 'Rilanciare come amministratore: mancano eventi, altri utenti, esclusioni antivirus e moduli dei browser.'
    }
    return $rows.ToArray()
}

# ----------------------------------------------------------------------------------------------
#  Test clipboard e monitor in tempo reale
# ----------------------------------------------------------------------------------------------
function Initialize-Native {
    if ('CyberRSecClip.U32' -as [type]) { return $true }
    try {
        Add-Type -Namespace CyberRSecClip -Name U32 -MemberDefinition @'
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
[DllImport("user32.dll")] public static extern IntPtr GetClipboardOwner();
[DllImport("user32.dll")] public static extern uint GetClipboardSequenceNumber();
[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder s, int n);
'@ -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Get-WindowProcessInfo {
    param([IntPtr]$Hwnd)
    $o = [pscustomobject]@{ PID = 0; Processo = ''; Percorso = ''; Titolo = '' }
    if ($Hwnd -eq [IntPtr]::Zero) { return $o }
    try {
        [uint32]$procId = 0
        [void][CyberRSecClip.U32]::GetWindowThreadProcessId($Hwnd, [ref]$procId)
        $o.PID = $procId
        $sb = New-Object System.Text.StringBuilder 256
        [void][CyberRSecClip.U32]::GetWindowText($Hwnd, $sb, 256)
        $o.Titolo = $sb.ToString()
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p) { $o.Processo = $p.ProcessName; try { $o.Percorso = $p.Path } catch { } }
    } catch { }
    return $o
}

function Get-ClipText {
    for ($i = 0; $i -lt 5; $i++) {
        try { $t = Get-Clipboard -Raw -ErrorAction Stop; if ($null -eq $t) { return '' }; return [string]$t } catch { Start-Sleep -Milliseconds 50 }
    }
    return $null
}

function Invoke-ClipboardTest {
    Write-Msg ''
    Write-Msg '=== TEST CLIPPER (sostituzione IBAN negli appunti) ===' 'Cyan'
    if (-not $script:IsWin) { throw 'Test disponibile solo su Windows' }
    $nativeOk = Initialize-Native
    $orig = Get-ClipText
    $tests = @('IT60X0542811101000000123456', 'IT60 X054 2811 1010 0000 0123 456', 'DE89370400440532013000', 'Beneficiario: Mario Rossi IBAN IT60X0542811101000000123456 causale fattura 12')
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $hit = $false
    foreach ($t in $tests) {
        Set-Clipboard -Value $t
        $changed = $false; $now = $t; $owner = $null
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt 8) {
            Start-Sleep -Milliseconds 200
            $now = Get-ClipText
            if ($null -ne $now -and $now.Trim() -ne $t.Trim()) {
                $changed = $true
                if ($nativeOk) { $owner = Get-WindowProcessInfo ([CyberRSecClip.U32]::GetClipboardOwner()) }
                break
            }
        }
        $ownTxt = ''
        if ($owner) { $ownTxt = "$($owner.Processo) (PID $($owner.PID)) $($owner.Percorso)" }
        $rows.Add([pscustomobject]@{ Scritto = $t; Letto = $now; Modificato = $changed; DopoSecondi = [math]::Round($sw.Elapsed.TotalSeconds, 1); ProcessoProprietario = $ownTxt })
        $newIbans = @(Find-Ibans $now)
        $origIbans = @(Find-Ibans $t)
        $swapped = $changed -and $newIbans.Count -gt 0 -and @($newIbans | Where-Object { $origIbans -notcontains $_ }).Count -gt 0
        if ($changed -and -not $swapped) {
            Write-Msg "  Appunti modificati da un altro programma (senza IBAN diverso): $ownTxt" 'DarkYellow'
            Add-Finding 'BASSA' 'Clipper' 'Gli appunti sono stati modificati da un altro programma durante il test' "Scritto: $t | Letto: $now | $ownTxt" 'Probabile gestore appunti o sincronizzazione: non e'' una sostituzione di IBAN.'
        } elseif ($swapped) {
            $hit = $true
            Write-Msg "  !!! APPUNTI MODIFICATI: '$t' -> '$now'  processo: $ownTxt" 'Red'
            Add-Finding 'ALTA' 'Clipper' 'CLIPPER RILEVATO: un programma sostituisce l''IBAN negli appunti' "Scritto: $t | Diventato: $now | dopo $([math]::Round($sw.Elapsed.TotalSeconds,1)) s | Processo che ha scritto negli appunti: $ownTxt" 'Il PC e'' infetto. Isolarlo dalla rete, non fare bonifici, salvare le prove (questo report + il file del processo indicato) e consegnarle con la denuncia.'
        } else {
            Write-Msg "  OK nessuna modifica: $t" 'Green'
        }
    }
    if ($null -ne $orig) { try { if ($orig -eq '') { Set-Clipboard -Value ' ' } else { Set-Clipboard -Value $orig } } catch { } }
    if (-not $hit) {
        Add-Finding 'BASSA' 'Clipper' 'Test clipboard negativo (nessuna sostituzione in 8 secondi)' '' 'Se l''IBAN cambia comunque sul sito, la modifica avviene dentro il browser (estensione/iniezione) e non negli appunti. Usare la modalita'' Monitor durante il bonifico.'
    }
    if ($script:OutDir) { $rows | Export-Csv -LiteralPath (Join-Path $script:OutDir 'test_clipboard.csv') -NoTypeInformation -Delimiter ';' -Encoding $script:CsvEnc }
    $script:Sections.Add([pscustomobject]@{ Sezione = 'Test clipboard'; Stato = 'OK'; Righe = $rows.Count; Secondi = 0; File = 'test_clipboard.csv'; Errore = '' })
    return $hit
}

function Get-ProxySnapshot {
    $s = ''
    try { $i = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop; $s = "ProxyEnable=$($i.ProxyEnable) ProxyServer=$($i.ProxyServer) AutoConfigURL=$($i.AutoConfigURL)" } catch { }
    return $s
}

function Invoke-Monitor {
    param([int]$Minutes)
    if (-not $script:IsWin) { throw 'Monitor disponibile solo su Windows' }
    if (-not (Initialize-Native)) { throw 'Impossibile caricare le funzioni di sistema (user32)' }
    $log = Join-Path $script:OutDir 'monitor_log.csv'
    Write-Msg ''
    Write-Msg "=== MONITOR ATTIVO per $Minutes minuti (Ctrl+C o 'Interrompi' per terminare) ===" 'Cyan'
    Write-Msg 'Ora fate eseguire il bonifico al cliente come al solito. Lo script registra:' 'Cyan'
    Write-Msg ' - ogni modifica degli appunti, con il PROCESSO che li ha modificati e gli IBAN contenuti' 'Cyan'
    Write-Msg ' - ogni nuovo processo avviato, modifiche a file hosts e proxy' 'Cyan'
    Write-Msg "Log: $log" 'Cyan'
    Write-Msg ''

    $hp = Join-Parts $env:SystemRoot @('System32', 'drivers', 'etc', 'hosts')
    $hostsHash = Get-FileSha256 $hp
    $proxy = Get-ProxySnapshot
    $known = @{}
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $known[[int]$p.ProcessId] = $true }
    $seq = [CyberRSecClip.U32]::GetClipboardSequenceNumber()
    $lastText = Get-ClipText
    $lastIbans = Find-Ibans $lastText
    $lastTime = Get-Date
    $end = (Get-Date).AddMinutes($Minutes)
    $tick = 0
    $alerts = 0

    $write = {
        param($Evento, $Gravita, $Dettaglio, $Processo, $Percorso, $Ibans)
        $r = [pscustomobject]@{ Ora = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'); Evento = $Evento; Gravita = $Gravita; Dettaglio = $Dettaglio; Processo = $Processo; Percorso = $Percorso; IBAN = $Ibans }
        $r | Export-Csv -LiteralPath $log -NoTypeInformation -Delimiter ';' -Encoding $script:CsvEnc -Append
        $col = 'Gray'
        if ($Gravita -eq 'ALTA') { $col = 'Red' } elseif ($Gravita -eq 'MEDIA') { $col = 'Yellow' }
        Write-Msg ('{0} [{1}] {2} {3} {4}' -f $r.Ora.Substring(11), $Evento, $Dettaglio, $Processo, $Ibans) $col
        if ($Gravita -eq 'ALTA' -and $script:Sync) { $script:Sync['LastAlert'] = ('{0} - {1} {2}' -f $r.Ora.Substring(11), $Evento, $Dettaglio) }
    }

    try {
        $startTime = Get-Date
        while ((Get-Date) -lt $end) {
            if (Test-Cancel) { Write-Msg 'Monitor interrotto dall''utente.' 'Cyan'; break }
            Start-Sleep -Milliseconds 150
            $tick++
            if ($tick % 7 -eq 0) {
                $el = ((Get-Date) - $startTime).TotalSeconds
                $left = [int](($end - (Get-Date)).TotalSeconds)
                Set-Progress 1 1 ("Monitor attivo - {0:mm\:ss} rimanenti - allarmi: {1}" -f [timespan]::FromSeconds([math]::Max(0, $left)), $alerts) ([int](100 * $el / ($Minutes * 60)))
                if ($script:Sync) { $script:Sync['Alerts'] = $alerts }
            }
            $s = [CyberRSecClip.U32]::GetClipboardSequenceNumber()
            if ($s -ne $seq) {
                $seq = $s
                $owner = Get-WindowProcessInfo ([CyberRSecClip.U32]::GetClipboardOwner())
                $fg = Get-WindowProcessInfo ([CyberRSecClip.U32]::GetForegroundWindow())
                $txt = Get-ClipText
                $ibans = Find-Ibans $txt
                $ownerTxt = "$($owner.Processo) PID $($owner.PID)"
                $sev = 'BASSA'; $ev = 'Appunti modificati'
                $det = "finestra attiva: $($fg.Processo) '$($fg.Titolo)'"
                $elapsed = ((Get-Date) - $lastTime).TotalSeconds
                $replaced = @($lastIbans).Count -gt 0 -and @($ibans).Count -gt 0 -and (@($ibans | Where-Object { $lastIbans -notcontains $_ }).Count -gt 0)
                if ($replaced -and $elapsed -lt 5) {
                    $sev = 'ALTA'; $ev = 'IBAN SOSTITUITO NEGLI APPUNTI'
                    $det = "da $($lastIbans -join ',') a $($ibans -join ',') in $([math]::Round($elapsed,2)) s; finestra attiva: $($fg.Processo)"
                } elseif (@($ibans).Count -gt 0) {
                    $sev = 'MEDIA'; $ev = 'IBAN copiato'
                }
                if ($owner.PID -and $owner.Percorso -and (Get-BinaryRisk $owner.Percorso $null) -in @('ALTA', 'MEDIA')) {
                    if ($sev -ne 'ALTA') { $sev = 'MEDIA' }
                    $det += ' | il processo che ha scritto gli appunti NON e'' firmato'
                }
                & $write $ev $sev $det $ownerTxt $owner.Percorso ($ibans -join ',')
                if ($sev -eq 'ALTA') {
                    $alerts++
                    try { [console]::Beep(1200, 400); [console]::Beep(800, 400) } catch { }
                    Add-Finding 'ALTA' 'Monitor' $ev "$det | processo appunti: $ownerTxt $($owner.Percorso)" 'Salvare il file del processo indicato e il log; isolare il PC.'
                }
                $lastText = $txt; $lastIbans = $ibans; $lastTime = Get-Date
            }
            if ($tick % 20 -eq 0) {
                # ogni ~3 secondi: nuovi processi, hosts, proxy
                foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
                    $procId = [int]$p.ProcessId
                    if ($known.ContainsKey($procId)) { continue }
                    $known[$procId] = $true
                    $path = [string]$p.ExecutablePath
                    $r = Get-BinaryRisk $path $null
                    $sev = 'BASSA'
                    if ($r -eq 'ALTA') { $sev = 'MEDIA' }
                    $cmd = [string]$p.CommandLine
                    if ($script:BrowserExe -contains ([string]$p.Name).ToLowerInvariant() -and $cmd -match '(?i)--load-extension|--remote-debugging|--proxy-server|--headless|--window-position=-') { $sev = 'ALTA' }
                    if ($cmd.Length -gt 300) { $cmd = $cmd.Substring(0, 300) + '...' }
                    & $write 'Nuovo processo' $sev $cmd $p.Name $path ''
                    if ($sev -eq 'ALTA') { $alerts++; Add-Finding 'ALTA' 'Monitor' "Durante il monitor e' stato avviato un browser con debug remoto o estensione nascosta: $($p.Name)" "$path $cmd" 'Analizzare chi lo ha avviato.' }
                    elseif ($sev -eq 'MEDIA' -and $r -eq 'ALTA') { Add-Finding 'MEDIA' 'Monitor' "Durante il monitor e' stato avviato un programma senza firma da cartella utente: $($p.Name)" "$path $cmd" 'Verificare il file.' }
                }
                $hh = Get-FileSha256 $hp
                if ($hh -ne $hostsHash) {
                    $hostsHash = $hh
                    $hsev = 'MEDIA'
                    if (@(Get-HostsEntries $hp $BankDomains | Where-Object { $_.Banca }).Count -gt 0) { $hsev = 'ALTA'; $alerts++ }
                    & $write 'File hosts MODIFICATO' $hsev $hp '' '' ''
                    Add-Finding $hsev 'Monitor' 'File hosts modificato durante il monitor' $hp 'Controllare il contenuto (copia nel rapporto).'
                }
                $px = Get-ProxySnapshot
                if ($px -ne $proxy) { $proxy = $px; & $write 'Proxy MODIFICATO' 'MEDIA' $px '' '' ''; Add-Finding 'MEDIA' 'Monitor' 'Impostazioni proxy modificate durante il monitor' $px 'Un programma ha cambiato il proxy (anche una VPN puo'' farlo).' }
            }
        }
    } finally {
        Write-Msg ''
        Write-Msg "Monitor terminato. Allarmi: $alerts. Log: $log" 'Cyan'
        if ($alerts -eq 0) {
            Add-Finding 'BASSA' 'Monitor' 'Nessuna anomalia rilevata durante il monitor' 'Appunti, processi, hosts e proxy non hanno mostrato modifiche sospette.' "Se l'IBAN e' cambiato lo stesso nella pagina, la modifica avviene dentro il browser: controllare la sezione Estensioni e Iniezione nel browser, e provare il bonifico da un altro browser/profilo pulito."
        }
        $script:Sections.Add([pscustomobject]@{ Sezione = 'Monitor'; Stato = 'OK'; Righe = $alerts; Secondi = 0; File = 'monitor_log.csv'; Errore = '' })
    }
}

# ----------------------------------------------------------------------------------------------
#  Report HTML
# ----------------------------------------------------------------------------------------------
function ConvertTo-HtmlText { param($s) return [System.Net.WebUtility]::HtmlEncode([string]$s) }

function Get-RunSummary {
    $nA = @($script:Findings | Where-Object { $_.Gravita -eq 'ALTA' }).Count
    $nM = @($script:Findings | Where-Object { $_.Gravita -eq 'MEDIA' }).Count
    $nB = @($script:Findings | Where-Object { $_.Gravita -eq 'BASSA' }).Count
    $hC = @($script:Hardening | Where-Object { $_.Stato -eq 'CRITICO' }).Count
    $hA = @($script:Hardening | Where-Object { $_.Stato -eq 'ATTENZIONE' }).Count
    $hO = @($script:Hardening | Where-Object { $_.Stato -eq 'OK' }).Count
    $sc = Get-SecurityScore -Alta $nA -Media $nM -Critici $hC -Attenzione $hA
    $msg = 'Nessun indizio di compromissione trovato con i controlli eseguiti.'
    if ($nA -gt 0) { $msg = "$nA problemi CONFERMATI: considerare il PC compromesso. Non fare bonifici da questo PC." }
    elseif ($nM -gt 0) { $msg = "Nessun problema confermato. $nM elementi da controllare (fatti certi che possono avere una spiegazione legittima)." }
    elseif ($hC -gt 0) { $msg = "Nessun indizio di compromissione, ma $hC impostazioni di sicurezza da correggere." }
    $secTot = $script:Sections.Count
    $secOk = @($script:Sections.ToArray() | Where-Object { $_.Stato -eq 'OK' }).Count
    $giud = $sc.Giudizio
    $incompleta = ($secTot -ge 5 -and $secOk -lt [math]::Ceiling($secTot * 0.8))
    if ($incompleta) {
        if ($nA -eq 0) { $giud = 'Analisi incompleta' }
        $why = 'rilanciare come amministratore'
        if ($script:IsAdmin) { $why = 'vedere "Controlli eseguiti" nel rapporto' }
        $msg += " Attenzione: $($secTot - $secOk) controlli su $secTot non sono stati eseguiti ($why), quindi il risultato non e' completo."
    }
    return [pscustomobject]@{ Alta = $nA; Media = $nM; Bassa = $nB; Critici = $hC; Attenzione = $hA; ControlliOk = $hO; Punteggio = $sc.Punteggio; Giudizio = $giud; Messaggio = $msg; Incompleta = $incompleta; SezioniOk = $secOk; SezioniTotali = $secTot }
}

function Write-HtmlReport {
    param([string]$Path)
    $sum = Get-RunSummary
    $order = @{ 'ALTA' = 0; 'MEDIA' = 1; 'BASSA' = 2 }
    $f = @($script:Findings | Sort-Object @{ Expression = { $order[$_.Gravita] } }, Categoria, Titolo)
    $hOrder = @{ 'CRITICO' = 0; 'ATTENZIONE' = 1; 'INFO' = 2; 'N.D.' = 3; 'OK' = 4 }
    $hard = @($script:Hardening | Sort-Object @{ Expression = { $hOrder[$_.Stato] } }, Area, Controllo)
    $col = '#1f8a4c'
    if ($sum.Punteggio -lt 85) { $col = '#c27c0e' }
    if ($sum.Punteggio -lt 60) { $col = '#d9480f' }
    if ($sum.Punteggio -lt 30) { $col = '#c92a2a' }
    if ($sum.Incompleta -and $sum.Alta -eq 0) { $col = '#7b8494' }
    $dash = [math]::Round(339.3 * $sum.Punteggio / 100, 1)
    $pc = ConvertTo-HtmlText ([Environment]::MachineName)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberRSecurityCheck - $pc</title>
<style>
:root{--bg:#f4f6fa;--card:#fff;--tx:#18202e;--mu:#5b6578;--bd:#e1e5ec;--hd:#0f1e36;--alta:#c92a2a;--media:#c27c0e;--bassa:#3b6fb6;--ok:#1f8a4c;--th:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#0e131b;--card:#161d28;--tx:#e6ebf2;--mu:#9aa6b8;--bd:#283244;--hd:#0a1424;--th:#1d2633}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 "Segoe UI",system-ui,Arial,sans-serif;background:var(--bg);color:var(--tx)}
header{background:var(--hd);color:#fff;padding:18px 0}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px}
header .wrap{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
header h1{font-size:20px;margin:0;letter-spacing:.3px}header .sub{color:#b8c4d8;font-size:13px}
main{padding:20px 0 40px}
.grid{display:grid;grid-template-columns:240px 1fr;gap:16px}
@media (max-width:760px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:18px}
.score{text-align:center}.score .v{font-size:18px;font-weight:700;margin-top:6px}
.msg{font-size:16px;font-weight:600;margin:0 0 14px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.tile{border:1px solid var(--bd);border-radius:10px;padding:10px 12px}.tile b{display:block;font-size:24px;line-height:1.2}
.tile span{color:var(--mu);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
h2{font-size:16px;margin:28px 0 10px}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.bar button{border:1px solid var(--bd);background:var(--card);color:var(--tx);border-radius:16px;padding:5px 12px;cursor:pointer;font:inherit}
.bar button.on{background:var(--hd);color:#fff;border-color:var(--hd)}
.bar input{flex:1;min-width:180px;padding:6px 10px;border:1px solid var(--bd);border-radius:8px;background:var(--card);color:var(--tx);font:inherit}
.tbl{overflow-x:auto;border:1px solid var(--bd);border-radius:10px;background:var(--card)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:top}
th{background:var(--th);font-weight:600;font-size:13px}tr:last-child td{border-bottom:0}
td.det{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px;color:var(--mu);word-break:break-word}
.pill{display:inline-block;font-weight:700;padding:2px 9px;border-radius:10px;color:#fff;font-size:11px;white-space:nowrap}
.ALTA,.CRITICO{background:var(--alta)}.MEDIA,.ATTENZIONE{background:var(--media)}.BASSA,.INFO{background:var(--bassa)}.OK{background:var(--ok)}.ND{background:#7b8494}
.guide li{margin:5px 0}footer{color:var(--mu);font-size:12px;margin-top:24px}
@media print{.bar{display:none}header{background:#fff;color:#000}body{background:#fff}}
</style></head><body>
<header><div class="wrap">
<svg width="34" height="38" viewBox="0 0 34 38" aria-hidden="true"><path d="M17 1 32 7v11c0 9.5-6.4 16.4-15 19C8.4 34.4 2 27.5 2 18V7z" fill="#2f7de1"/><path d="m10 19 5 5 9-10" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
<div><h1>CyberRSecurityCheck &middot; Rapporto di sicurezza</h1>
<div class="sub">PC <b>$pc</b> &middot; $((Get-Date).ToString('dd/MM/yyyy HH:mm')) &middot; utente $(ConvertTo-HtmlText "$env:USERDOMAIN\$env:USERNAME") &middot; amministratore: $(if ($script:IsAdmin) { 's&igrave;' } else { 'no' }) &middot; v$($script:Version)</div></div>
</div></header>
<main class="wrap">
<div class="grid">
<div class="card score">
<svg width="150" height="150" viewBox="0 0 120 120"><circle cx="60" cy="60" r="54" fill="none" stroke="var(--bd)" stroke-width="10"/>
<circle cx="60" cy="60" r="54" fill="none" stroke="$col" stroke-width="10" stroke-linecap="round" stroke-dasharray="$dash 339.3" transform="rotate(-90 60 60)"/>
<text x="60" y="66" text-anchor="middle" font-size="30" font-weight="700" fill="$col">$($sum.Punteggio)</text><text x="60" y="84" text-anchor="middle" font-size="10" fill="var(--mu)">su 100</text></svg>
<div class="v" style="color:$col">$(ConvertTo-HtmlText $sum.Giudizio)</div></div>
<div class="card"><p class="msg">$(ConvertTo-HtmlText $sum.Messaggio)</p>
<div class="tiles">
<div class="tile"><b style="color:var(--alta)">$($sum.Alta)</b><span>Problemi confermati</span></div>
<div class="tile"><b style="color:var(--media)">$($sum.Media)</b><span>Da controllare</span></div>
<div class="tile"><b style="color:var(--media)">$($sum.Critici)</b><span>Impostazioni da correggere</span></div>
<div class="tile"><b>$($sum.SezioniOk)/$($sum.SezioniTotali)</b><span>Controlli eseguiti</span></div>
</div></div></div>
<h2>Risultati</h2>
<div class="bar" id="fb"><button class="on" data-f="AM">Confermati e da controllare ($($sum.Alta + $sum.Media))</button><button data-f="ALTA">Confermati ($($sum.Alta))</button><button data-f="MEDIA">Da controllare ($($sum.Media))</button><button data-f="BASSA">Dettagli tecnici ($($sum.Bassa))</button><button data-f="">Tutti ($($f.Count))</button><input id="q" placeholder="Cerca (es. AnyDesk, estensione, IBAN)..."></div>
<div class="tbl"><table id="ft"><thead><tr><th>Esito</th><th>Area</th><th>Cosa</th><th>Dettaglio</th><th>Cosa fare</th></tr></thead><tbody>
"@)
    if ($f.Count -eq 0) { [void]$sb.Append('<tr><td colspan="5">Nessun problema trovato.</td></tr>') }
    foreach ($x in $f) {
        [void]$sb.AppendFormat('<tr data-s="{0}"><td><span class="pill {0}">' + (Get-SevLabel $x.Gravita) + '</span></td><td>{1}</td><td>{2}</td><td class="det">{3}</td><td>{4}</td></tr>', $x.Gravita, (ConvertTo-HtmlText $x.Categoria), (ConvertTo-HtmlText $x.Titolo), (ConvertTo-HtmlText $x.Dettaglio), (ConvertTo-HtmlText $x.Consiglio))
    }
    [void]$sb.Append('</tbody></table></div><h2>Configurazione di sicurezza</h2><div class="tbl"><table><thead><tr><th>Stato</th><th>Area</th><th>Controllo</th><th>Valore</th><th>Consiglio</th></tr></thead><tbody>')
    if ($hard.Count -eq 0) { [void]$sb.Append('<tr><td colspan="5">Controlli non disponibili.</td></tr>') }
    foreach ($h in $hard) {
        $cls = $h.Stato; if ($cls -eq 'N.D.') { $cls = 'ND' }
        [void]$sb.AppendFormat('<tr><td><span class="pill {0}">{1}</span></td><td>{2}</td><td>{3}</td><td class="det">{4}</td><td>{5}</td></tr>', $cls, (ConvertTo-HtmlText $h.Stato), (ConvertTo-HtmlText $h.Area), (ConvertTo-HtmlText $h.Controllo), (ConvertTo-HtmlText $h.Valore), (ConvertTo-HtmlText $h.Consiglio))
    }
    [void]$sb.Append('</tbody></table></div><h2>Controlli eseguiti</h2><div class="tbl"><table><thead><tr><th>Controllo</th><th>Stato</th><th>Elementi</th><th>Secondi</th><th>Dettaglio</th><th>Note</th></tr></thead><tbody>')
    foreach ($s in $script:Sections) {
        $link = ''
        if ($s.File) { $link = '<a href="' + (ConvertTo-HtmlText $s.File) + '">' + (ConvertTo-HtmlText $s.File) + '</a>' }
        [void]$sb.AppendFormat('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td class="det">{5}</td></tr>', (ConvertTo-HtmlText $s.Sezione), (ConvertTo-HtmlText $s.Stato), $s.Righe, $s.Secondi, $link, (ConvertTo-HtmlText $s.Errore))
    }
    [void]$sb.Append(@"
</tbody></table></div>
<h2>Come leggere il rapporto</h2>
<div class="card guide"><ul>
<li><b>CONFERMATO</b>: indicatore certo di compromissione o manomissione. Non fare bonifici da questo PC, scollegarlo dalla rete, <b>non cancellare nulla</b> e conservare lo ZIP del rapporto (con SHA256SUMS.txt) come prova per la denuncia.</li>
<li><b>DA CONTROLLARE</b>: fatto certo ma con possibili spiegazioni legittime (es. il programma di assistenza del tecnico, un gestore password) ma potrebbe modificare la pagina della banca. Gli elementi verificati si segnano in <i>config.json</i> e non daranno pi&ugrave; allarme.</li>
<li>Se l'IBAN cambia <b>solo nella pagina della banca</b>, oltre una certa cifra, la causa tipica &egrave; un trojan man-in-the-browser (es. Ramnit con il kit drIBAN) o un'estensione del browser: guardare le aree <i>Iniezione in memoria</i>, <i>Iniezione nel browser</i>, <i>Estensioni browser</i>, <i>Indicatori noti</i>.</li>
<li>Chiedere alla banca IP, dispositivo e orario dell'operazione fraudolenta e confrontarli con eventi.csv, accesso_remoto.csv e cronologia_esecuzione.csv.</li>
<li>Gli SHA256 nei file CSV si cercano su virustotal.com senza caricare i file.</li>
<li>Nessuno strumento trova tutto: se il rapporto &egrave; pulito ma il problema continua, servono una scansione offline (Microsoft Defender Offline) e un'analisi forense della memoria.</li>
</ul></div>
<footer>Generato da CyberRSecurityCheck v$($script:Version). Analisi in sola lettura. Impronte dei file in SHA256SUMS.txt.</footer>
</main>
<script>
(function(){var f='AM',b=document.querySelectorAll('#fb button'),q=document.getElementById('q'),r=document.querySelectorAll('#ft tbody tr[data-s]');
function a(){var t=q.value.toLowerCase();for(var i=0;i<r.length;i++){var x=r[i],s=x.getAttribute('data-s'),ok=(!f||s===f||(f==='AM'&&(s==='ALTA'||s==='MEDIA')))&&(!t||x.textContent.toLowerCase().indexOf(t)>=0);x.style.display=ok?'':'none';}}
for(var i=0;i<b.length;i++){b[i].addEventListener('click',function(){for(var j=0;j<b.length;j++)b[j].className='';this.className='on';f=this.getAttribute('data-f');a();});}
q.addEventListener('input',a);a();})();
</script>
</body></html>
"@)
    [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
}

# ----------------------------------------------------------------------------------------------
#  Storico: istantanea e confronto con l'analisi precedente dello stesso PC
# ----------------------------------------------------------------------------------------------
function Get-Snapshot {
    param([hashtable]$Data)
    $snap = [ordered]@{}
    $map = [ordered]@{
        'Estensioni'      = @(@('estensioni_chromium', { '{0}|{1}|{2}|{3}' -f $_.Browser, $_.Utente, $_.Id, $_.Nome }), @('estensioni_firefox', { '{0}|{1}|{2}|{3}' -f $_.Browser, $_.Utente, $_.Id, $_.Nome }))
        'AvvioAutomatico' = @(, @('avvio_automatico', { '{0}|{1}|{2}' -f $_.Tipo, $_.Nome, $_.Comando }))
        'Certificati'     = @(, @('certificati', { '{0}|{1}|{2}' -f $_.Archivio, $_.Thumbprint, $_.Soggetto }))
        'AccessoRemoto'   = @(, @('accesso_remoto', { if ($_.Tipo -in @('Processo', 'Servizio', 'Installato', 'RDP')) { '{0}|{1}|{2}' -f $_.Tipo, $_.Nome, $_.Dettaglio } }))
        'ProxyHosts'      = @(, @('proxy_hosts_dns', { if ($_.Tipo -in @('hosts', 'Proxy utente', 'Proxy WinHTTP', 'Server DNS')) { '{0}|{1}|{2}' -f $_.Tipo, $_.Nome, $_.Valore } }))
        'Policy'          = @(, @('policy_browser', { '{0}|{1}|{2}' -f $_.Chiave, $_.Valore, $_.Dato }))
        'Software'        = @(, @('software', { '{0}|{1}' -f $_.Nome, $_.Editore }))
    }
    foreach ($cat in $map.Keys) {
        $items = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($pair in $map[$cat]) {
            if (-not $Data.ContainsKey($pair[0])) { continue }
            foreach ($row in @($Data[$pair[0]])) {

                $v = [string](ForEach-Object -InputObject $row -Process $pair[1])
                if ($v) { [void]$items.Add($v) }
            }
        }
        $snap[$cat] = @($items | Sort-Object)
    }
    return $snap
}

function Compare-Snapshot {
    # Restituisce le differenze tra due istantanee: NUOVO = presente ora e non prima, RIMOSSO = il contrario
    param($Previous, $Current)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($cat in @($Current.Keys)) {
        $prev = @(ConvertTo-StrArray (Get-DVal $Previous $cat))
        if (-not (Test-DKey $Previous $cat)) { continue }   # categoria non presente nel vecchio formato
        $cur = @(ConvertTo-StrArray $Current[$cat])
        $ps = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($x in $prev) { [void]$ps.Add($x) }
        $cs = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($x in $cur) { [void]$cs.Add($x) }
        foreach ($x in $cur) { if (-not $ps.Contains($x)) { $out.Add([pscustomobject]@{ Categoria = $cat; Cambio = 'NUOVO'; Elemento = $x }) } }
        foreach ($x in $prev) { if (-not $cs.Contains($x)) { $out.Add([pscustomobject]@{ Categoria = $cat; Cambio = 'RIMOSSO'; Elemento = $x }) } }
    }
    return $out.ToArray()
}

function Find-PreviousSnapshot {
    param([string]$BaseDir, [string]$CurrentDir)
    $pattern = 'CyberRSecurityCheck_{0}_*' -f [Environment]::MachineName
    $dirs = @(Get-ChildItem -LiteralPath $BaseDir -Directory -Filter $pattern -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne $CurrentDir -and (Test-Path -LiteralPath (Join-Path $_.FullName 'snapshot.json')) } |
            Sort-Object Name -Descending)
    if ($dirs.Count -eq 0) { return $null }
    return $dirs[0].FullName
}

function Invoke-CyberHistory {
    $snap = Get-Snapshot $script:SectionData
    $meta = [ordered]@{ Computer = [Environment]::MachineName; Data = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Versione = $script:Version }
    $doc = [ordered]@{ _info = $meta }
    foreach ($k in $snap.Keys) { $doc[$k] = $snap[$k] }
    ($doc | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath (Join-Path $script:OutDir 'snapshot.json') -Encoding UTF8

    $base = Split-Path $script:OutDir -Parent
    $prevDir = Find-PreviousSnapshot $base $script:OutDir
    if (-not $prevDir) {
        Add-Finding 'BASSA' 'Storico' 'Prima analisi salvata per questo PC' "Cartella: $base" 'Le prossime analisi eseguite nella stessa cartella mostreranno automaticamente cosa e'' cambiato (nuove estensioni, programmi in avvio automatico, certificati, accessi remoti).'
        return @()
    }
    $prev = Read-JsonFile (Join-Path $prevDir 'snapshot.json')
    $when = [string](Get-DVal $prev '_info.Data')
    $diff = @(Compare-Snapshot $prev $snap)
    $nuovi = @($diff | Where-Object { $_.Cambio -eq 'NUOVO' -and $_.Categoria -ne 'Software' })
    $sw = @($diff | Where-Object { $_.Cambio -eq 'NUOVO' -and $_.Categoria -eq 'Software' })
    $rim = @($diff | Where-Object { $_.Cambio -eq 'RIMOSSO' })
    foreach ($d in ($nuovi | Select-Object -First 40)) {
        $nsev = 'BASSA'
        if ($d.Categoria -in @('Estensioni', 'AccessoRemoto', 'ProxyHosts')) { $nsev = 'MEDIA' }
        Add-Finding $nsev 'Novita' "NUOVO dall'analisi del $($when): $($d.Categoria)" $d.Elemento 'Elemento comparso dopo l''ultimo controllo: verificare chi lo ha aggiunto e quando.'
    }
    if ($nuovi.Count -gt 40) { Add-Finding 'BASSA' 'Novita' "Altri $($nuovi.Count - 40) elementi nuovi" 'Vedi confronto_precedente.csv' '' }
    if ($sw.Count -gt 0) { Add-Finding 'BASSA' 'Novita' "$($sw.Count) programmi nuovi dall'analisi del $when" (($sw | ForEach-Object { $_.Elemento.Split('|')[0] }) -join '; ') 'Verificare che siano voluti.' }
    if ($rim.Count -gt 0) { Add-Finding 'BASSA' 'Novita' "$($rim.Count) elementi rimossi dall'analisi del $when" 'Vedi confronto_precedente.csv' '' }
    if ($diff.Count -eq 0) { Add-Finding 'BASSA' 'Novita' "Nessuna differenza rispetto all'analisi del $when" $prevDir '' }
    $script:Sections.Add([pscustomobject]@{ Sezione = "Confronto con analisi del $when"; Stato = 'OK'; Righe = $diff.Count; Secondi = 0; File = $(if ($diff.Count) { 'confronto_precedente.csv' } else { '' }); Errore = '' })
    if ($diff.Count -gt 0) { $diff | Export-Csv -LiteralPath (Join-Path $script:OutDir 'confronto_precedente.csv') -NoTypeInformation -Delimiter ';' -Encoding $script:CsvEnc }
    return $diff
}

function Write-IntegrityManifest {
    # Catena di custodia: SHA256 di ogni file del report e dello script usato
    param([string]$Dir)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('# SHA256 dei file di questo report - generato da CyberRSecurityCheck v' + $script:Version + ' il ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    $lines.Add('# Computer: ' + [Environment]::MachineName + '  Utente: ' + $env:USERNAME)
    if ($PSCommandPath) { $lines.Add('# Script: ' + (Get-FileSha256 $PSCommandPath) + '  ' + (Split-Path $PSCommandPath -Leaf)) }
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Sort-Object Name)) {
        $lines.Add((Get-FileSha256 $f.FullName) + '  ' + $f.Name)
    }
    [IO.File]::WriteAllLines((Join-Path $Dir 'SHA256SUMS.txt'), $lines.ToArray())
}

# ----------------------------------------------------------------------------------------------
#  Main
# ----------------------------------------------------------------------------------------------
function Initialize-Output {
    $base = $OutputPath
    if (-not $base) {
        if ($PSScriptRoot) { $base = Join-Path (Split-Path $PSScriptRoot -Parent) 'Report' }
        elseif ($env:LOCALAPPDATA) { $base = Join-Path $env:LOCALAPPDATA 'CyberRSecurityCheck\Report' }
        else { $base = Join-Path (Get-Location).Path 'Report' }
    }
    if (-not (Test-Path -LiteralPath $base)) { New-Item -ItemType Directory -Path $base -Force | Out-Null }
    $name = 'CyberRSecurityCheck_{0}_{1}' -f [Environment]::MachineName, (Get-Date -Format 'yyyyMMdd_HHmmss')
    $script:OutDir = Join-Path $base $name
    New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
    return $script:OutDir
}

function Get-CollectPlan {
    $plan = New-Object 'System.Collections.Generic.List[object]'
    $plan.Add(@('Informazioni di sistema', 'sistema', { Get-SystemInfo }))
    $plan.Add(@('Configurazione di sicurezza', 'configurazione', { Get-HardeningChecks -UserDirs $ud }))
    $plan.Add(@('Estensioni Chrome/Edge/Brave/Opera', 'estensioni_chromium', { Get-ChromiumExtensions -UserDirs $ud -BankDomains $BankDomains }))
    $plan.Add(@('Estensioni Firefox', 'estensioni_firefox', { Get-FirefoxExtensions -UserDirs $ud -BankDomains $BankDomains }))
    $plan.Add(@('Policy dei browser', 'policy_browser', { Get-BrowserPolicies }))
    $plan.Add(@('Collegamenti dei browser', 'collegamenti_browser', { Get-BrowserShortcuts -UserDirs $ud }))
    $plan.Add(@('Integrita'' dei browser', 'eseguibili_browser', { Get-BrowserBinaries }))
    $plan.Add(@('Processi in esecuzione', 'processi', { Get-ProcessReport }))
    if (-not $SkipModules) { $plan.Add(@('DLL caricate nei browser', 'moduli_browser', { Get-BrowserModules })) }
    if (-not $SkipMemory) { $plan.Add(@('Codice iniettato in memoria', 'memoria', { Get-MemoryInjection })) }
    $plan.Add(@('Avvio automatico e persistenza', 'avvio_automatico', { Get-Autoruns -UserDirs $ud }))
    $plan.Add(@('Cronologia di esecuzione programmi', 'cronologia_esecuzione', { Get-ExecutionHistory }))
    $plan.Add(@('Comandi incollati (ClickFix) e PowerShell', 'comandi', { Get-TypedCommands -UserDirs $ud }))
    $plan.Add(@('Indicatori noti (Ramnit/drIBAN)', 'indicatori', { Get-KnownIocs -UserDirs $ud }))
    $plan.Add(@('Controllo remoto', 'accesso_remoto', { Get-RemoteAccess }))
    $plan.Add(@('Connessioni di rete', 'connessioni', { Get-NetworkReport }))
    $plan.Add(@('Proxy, hosts e DNS', 'proxy_hosts_dns', { Get-ProxyHostsDns -BankDomains $BankDomains }))
    $plan.Add(@('Rete locale, firewall e BITS', 'rete_locale', { Get-LanReport }))
    $plan.Add(@('Certificati radice', 'certificati', { Get-RootCertificates }))
    $plan.Add(@('Software installato', 'software', { Get-InstalledSoftware -Days 60 }))
    $plan.Add(@('Antivirus', 'antivirus', { Get-DefenderReport }))
    $plan.Add(@('Eventi di sicurezza', 'eventi', { Get-SecurityEvents -Days $RecentDays }))
    $plan.Add(@('Account locali', 'account', { Get-LocalAccounts }))
    $plan.Add(@('File eseguibili recenti', 'file_recenti', { Get-RecentFiles -UserDirs $ud -Days $RecentDays }))
    return $plan.ToArray()
}

function Invoke-Collect {
    param([switch]$WithClipTest)
    $ud = Get-UserProfileDirs
    $plan = Get-CollectPlan
    $script:StepNo = 0
    $script:StepTotal = $plan.Count + 1
    if ($WithClipTest) { $script:StepTotal++ }
    foreach ($x in $plan) { Invoke-Section $x[0] $x[1] $x[2] }
    if ($script:SectionData.ContainsKey('configurazione')) { $script:Hardening = @($script:SectionData['configurazione']) }
    $script:StepNo++
    Set-Progress $script:StepNo $script:StepTotal 'Confronto con l''analisi precedente'
    if (-not (Test-Cancel)) {
        try { [void](Invoke-CyberHistory) } catch { Write-Msg "Confronto con l'analisi precedente non eseguito: $($_.Exception.Message)" 'DarkYellow' }
    }
    if ($WithClipTest -and -not (Test-Cancel)) {
        $script:StepNo++
        Set-Progress $script:StepNo $script:StepTotal 'Test appunti (sostituzione IBAN)'
        try { [void](Invoke-ClipboardTest) } catch { Write-Msg "Test appunti non eseguito: $($_.Exception.Message)" 'DarkYellow' }
    }
    if (Test-Cancel) { Add-Finding 'BASSA' 'Analisi' 'Analisi interrotta dall''utente' 'Alcuni controlli non sono stati eseguiti.' 'Ripetere l''analisi completa.' }
}

function Write-ResultJson {
    param([string]$Path, $Summary)
    $doc = [ordered]@{
        App = $script:AppName; Versione = $script:Version; Computer = [Environment]::MachineName
        Utente = "$env:USERDOMAIN\$env:USERNAME"; Data = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss'); Amministratore = $script:IsAdmin; Modalita = $Mode
        Punteggio = $Summary.Punteggio; Giudizio = $Summary.Giudizio; Messaggio = $Summary.Messaggio
        Conteggi = [ordered]@{ Alta = $Summary.Alta; Media = $Summary.Media; Bassa = $Summary.Bassa; ImpostazioniCritiche = $Summary.Critici; ImpostazioniAttenzione = $Summary.Attenzione }
        Risultati = $script:Findings.ToArray(); Configurazione = @($script:Hardening); Controlli = $script:Sections.ToArray()
    }
    [IO.File]::WriteAllText($Path, ($doc | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
}

function Show-FinalScreen {
    param($Summary, [string]$Html, [string]$Zip)
    try { Write-Progress -Activity "$($script:AppName)" -Completed } catch { }
    $col = 'Green'
    if ($Summary.Punteggio -lt 85) { $col = 'Yellow' }
    if ($Summary.Alta -gt 0 -or $Summary.Punteggio -lt 60) { $col = 'Red' }
    $line = '=' * 70
    Write-Msg ''
    Write-Msg $line 'White'
    Write-Msg ("  RISULTATO FINALE   Punteggio di sicurezza: {0}/100  ({1})" -f $Summary.Punteggio, $Summary.Giudizio) $col
    Write-Msg $line 'White'
    Write-Msg ("  Problemi confermati: {0}    Da controllare: {1}    Impostazioni da correggere: {2}    Controlli eseguiti: {3}/{4}" -f $Summary.Alta, $Summary.Media, $Summary.Critici, $Summary.SezioniOk, $Summary.SezioniTotali) 'White'
    Write-Msg ''
    Write-Msg ('  ' + $Summary.Messaggio) $col
    $top = @($script:Findings | Where-Object { $_.Gravita -eq 'ALTA' } | Select-Object -First 12) + @($script:Findings | Where-Object { $_.Gravita -eq 'MEDIA' } | Select-Object -First 8)
    if ($top.Count -gt 0) {
        Write-Msg ''
        Write-Msg '  Principali elementi trovati:' 'White'
        foreach ($x in $top) {
            $c = 'Yellow'; $lab = 'DA CONTROLLARE'
            if ($x.Gravita -eq 'ALTA') { $c = 'Red'; $lab = 'CONFERMATO    ' }
            $t = $x.Titolo
            if ($t.Length -gt 90) { $t = $t.Substring(0, 87) + '...' }
            Write-Msg ("   [{0}] {1}" -f $lab, $t) $c
        }
    }
    Write-Msg ''
    if ($Summary.Alta -gt 0) {
        Write-Msg '  COSA FARE ORA:' 'Red'
        Write-Msg '   1. Non fare bonifici da questo PC finche'' i problemi confermati non sono risolti.' 'Red'
        Write-Msg '   2. Non cancellare nulla: conservare lo ZIP del rapporto (vale come prova).' 'Red'
        Write-Msg '   3. Scollegare il PC dalla rete, cambiare le password da un dispositivo pulito, avvisare la banca.' 'Red'
    } elseif ($Summary.Media -gt 0) {
        Write-Msg '  COSA FARE ORA: controllare i punti "da controllare" nel rapporto. Quelli legittimi si segnano in config.json.' 'Yellow'
    } else {
        Write-Msg '  Se l''IBAN cambia ancora, usare la modalita'' Monitor durante il bonifico.' 'Green'
    }
    Write-Msg ''
    Write-Msg "  Rapporto: $Html" 'Gray'
    if ($Zip) { Write-Msg "  Archivio da conservare: $Zip" 'Gray' }
    Write-Msg $line 'White'
}

function Complete-Report {
    $html = Join-Path $script:OutDir 'REPORT.html'
    $sum = Get-RunSummary
    if ($script:Findings.Count -gt 0) {
        $script:Findings | Export-Csv -LiteralPath (Join-Path $script:OutDir 'risultati.csv') -NoTypeInformation -Delimiter ';' -Encoding $script:CsvEnc
    }
    try { Write-ResultJson (Join-Path $script:OutDir 'risultati.json') $sum } catch { Write-Msg "risultati.json non creato: $($_.Exception.Message)" 'DarkYellow' }
    Write-HtmlReport $html
    try { Write-IntegrityManifest $script:OutDir } catch { }
    $zip = ''
    if (-not $NoZip) {
        try {
            $zip = $script:OutDir + '.zip'
            Compress-Archive -Path (Join-Path $script:OutDir '*') -DestinationPath $zip -Force -ErrorAction Stop
        } catch { $zip = '' }
    }
    Show-FinalScreen $sum $html $zip
    $script:Result = [pscustomobject]@{ Summary = $sum; Html = $html; OutDir = $script:OutDir; Zip = $zip; Findings = $script:Findings.ToArray(); Hardening = @($script:Hardening); Sections = $script:Sections.ToArray() }
    if ($script:Sync) { $script:Sync['Result'] = $script:Result }
    if (-not $NoOpen -and -not $script:Sync -and $script:IsWin -and [Environment]::UserInteractive) { try { Start-Process $html } catch { } }
}

function Start-CyberRSecurityCheck {
    $cfgPath = $ConfigPath
    if (-not $cfgPath -and $PSScriptRoot) { $cfgPath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'config') 'config.json' }
    $script:Config = Import-CyberConfig $cfgPath
    if (-not $script:BoundParams.ContainsKey('BankDomains')) { $script:BankDomains = $script:Config['BankDomains'] }
    if (-not $script:BoundParams.ContainsKey('RecentDays') -and $script:Config['RecentDays']) { $script:RecentDays = [int]$script:Config['RecentDays'] }
    $line = '=' * 70
    Write-Msg ''
    Write-Msg $line 'White'
    Write-Msg "  CYBERRSECURITYCHECK v$($script:Version)  -  analisi di sicurezza in sola lettura" 'White'
    Write-Msg $line 'White'
    Write-Msg ("  Computer: {0}   Modalita': {1}   Amministratore: {2}" -f [Environment]::MachineName, $Mode, $(if ($script:IsAdmin) { 'si' } else { 'NO' }))
    Write-Msg ("  Domini banca sorvegliati: {0}" -f ($script:BankDomains -join ', '))
    $nAllow = @($script:Config['AllowExtensionIds']).Count + @($script:Config['AllowRemoteTools']).Count + @($script:Config['AllowCertThumbprints']).Count + @($script:Config['AllowPaths']).Count
    if ($cfgPath -and (Test-Path -LiteralPath $cfgPath)) { Write-Msg "  Configurazione: $cfgPath ($nAllow elementi autorizzati)" } else { Write-Msg '  Configurazione: predefinita' }
    if (-not $script:IsAdmin) { Write-Msg '  ATTENZIONE: senza privilegi di amministratore alcuni controlli saranno incompleti.' 'Yellow' }
    Write-Msg ''
    [void](Initialize-Output)
    $transcript = $false
    if (-not $script:Sync) { try { Start-Transcript -LiteralPath (Join-Path $script:OutDir 'log_esecuzione.txt') -ErrorAction Stop | Out-Null; $transcript = $true } catch { } }
    try {
        switch ($Mode) {
            'Completo' { Invoke-Collect -WithClipTest }
            'Raccolta' { Invoke-Collect }
            'ClipTest' { $script:StepTotal = 1; $script:StepNo = 1; Set-Progress 1 1 'Test appunti (sostituzione IBAN)'; [void](Invoke-ClipboardTest) }
            'Monitor' { Invoke-Monitor -Minutes $MonitorMinutes }
        }
    } catch {
        Write-Msg "Errore imprevisto: $($_.Exception.Message)" 'Red'
        Add-Finding 'BASSA' 'Analisi' 'Errore imprevisto durante l''analisi' $_.Exception.Message 'Inviare log_esecuzione.txt a chi mantiene lo strumento.'
        if ($script:Sync) { $script:Sync['Error'] = $_.Exception.Message }
    } finally {
        if ($transcript) { try { Stop-Transcript | Out-Null } catch { } }
        if ($script:Sync -and $script:Sync.ContainsKey('Log')) {
            try { ($script:Sync.Log | ForEach-Object { '{0} {1}' -f $_.Ora, $_.Testo }) | Set-Content -LiteralPath (Join-Path $script:OutDir 'log_esecuzione.txt') -Encoding UTF8 } catch { }
        }
        Complete-Report
        if ($script:Sync) { $script:Sync['Done'] = $true }
    }
}

if ($MyInvocation.InvocationName -ne '.') { Start-CyberRSecurityCheck }
