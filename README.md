<div align="center">

# CyberRSecurityCheck

**Analisi di sicurezza per i PC Windows usati per l'home banking: trova le cause delle frodi sui bonifici (IBAN sostituito, credenziali rubate) e segnala come problemi solo gli indicatori certi.**

</div>

## Avvio rapido

Apri **PowerShell come Amministratore** ed esegui:

```powershell
irm https://raw.githubusercontent.com/rtecnocopy89/CyberRSecurityCheck/main/cyberrsecuritycheck.ps1 | iex
```

> Se PowerShell non è elevato, CyberRSecurityCheck si riavvia da solo come Amministratore.

Per usare una versione precisa (consigliato sui PC dei clienti), avvia il file della release con tag e confronta l'impronta con quella pubblicata nella release:

```powershell
irm https://raw.githubusercontent.com/rtecnocopy89/CyberRSecurityCheck/v2.0.0/cyberrsecuritycheck.ps1 | iex
```

Con parametri:

```powershell
& ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/rtecnocopy89/CyberRSecurityCheck/main/cyberrsecuritycheck.ps1))) -Console -Mode Completo
```

| Parametro | Effetto |
|---|---|
| `-Mode Completo` | analisi completa + test degli appunti (predefinito) |
| `-Mode Raccolta` | analisi completa senza test degli appunti |
| `-Mode ClipTest` | solo test "clipper" (sostituzione dell'IBAN negli appunti) |
| `-Mode Monitor -MonitorMinutes 30` | sorveglia il PC mentre il cliente esegue il bonifico |
| `-Console` | senza interfaccia grafica, risultato a video in console |
| `-Fast` | salta la scansione della memoria |
| `-OutputPath <cartella>` | dove salvare i rapporti (anche una cartella di rete) |

Offline o da chiavetta USB: copia la cartella e fai doppio clic su `Avvia-CyberRSecurityCheck.bat` (oppure `Avvia-Console.bat`).

## Solo segnalazioni certe

| Esito | Significato |
|---|---|
| **CONFERMATO** | indicatore specifico di attacco o manomissione: IBAN sostituito negli appunti, codice eseguibile iniettato nella memoria del browser, estensione installata fuori dallo store con accesso al sito della banca, file del trojan Ramnit, comando "ClickFix" che scarica ed esegue codice, browser con debug remoto, accessi RDP da Internet, rilevamenti dell'antivirus, file hosts che dirotta la banca |
| **DA CONTROLLARE** | fatto certo e pertinente che può avere una spiegazione legittima (es. *AnyDesk è installato*) |
| **DA CORREGGERE** | impostazioni di sicurezza sbagliate (firewall spento, Windows non più supportato, macro abilitate...) |
| **DETTAGLIO** | tutto il resto: nascosto per impostazione predefinita |

Se più del 20% dei controlli non può essere eseguito (es. senza privilegi di amministratore) il giudizio è **Analisi incompleta**: lo strumento non dichiara mai "tutto a posto" senza aver controllato.

## Cosa controlla

- **Browser** — estensioni di Chrome, Edge, Brave, Opera, Vivaldi e Firefox (provenienza, accesso al sito della banca), policy imposte, collegamenti modificati, integrità degli eseguibili, DLL caricate nel browser.
- **Man-in-the-browser** — codice eseguibile iniettato in memoria nei processi (la tecnica dei trojan come Ramnit con il kit drIBAN, che sostituiscono l'IBAN solo nei bonifici sopra una certa cifra) e indicatori noti di Ramnit.
- **Infostealer** — browser avviati con debug remoto, finestre fuori schermo, programmi collegati alla porta di debug.
- **Sistema** — processi, avvio automatico (registro, attività pianificate, servizi, WMI, Winlogon, AppInit, IFEO), cronologia di esecuzione (BAM), comandi incollati in Esegui (ClickFix/FileFix), cronologia PowerShell, file eseguibili recenti, account, eventi di sicurezza, antivirus ed esclusioni.
- **Rete** — programmi di controllo remoto con i log delle connessioni, connessioni attive, proxy e PAC, file hosts, DNS confrontati con DNS pubblici, tabella ARP del router, firewall, download BITS, certificati di intercettazione HTTPS.
- **Configurazione** — versione di Windows e aggiornamenti, UAC, firewall, SMBv1, RDP/NLA, WDigest, LSA, antivirus, SmartScreen, BitLocker, Secure Boot, macro Office, password salvate nei browser. Punteggio finale da 0 a 100.
- **Test attivi** — test degli appunti (clipper) e **Monitor** durante il bonifico: registra ogni modifica degli appunti con il programma responsabile, i nuovi processi e le modifiche a proxy e hosts.

## Sicurezza dello strumento

- **Sola lettura**: non cancella e non modifica nulla (il test degli appunti ripristina il contenuto originale).
- **Nessun dato inviato in Internet**, tranne il confronto DNS (disattivabile con `"DnsCompare": false`).
- L'interfaccia si apre in una finestra Edge/Chrome con **profilo temporaneo ed estensioni disattivate**: un'estensione malevola sul PC non può leggere o alterare i risultati.
- Server dell'interfaccia solo su `localhost`, con codice di accesso casuale a ogni avvio, controllo di Host e Origin e Content-Security-Policy con nonce.
- Ogni rapporto contiene `SHA256SUMS.txt` con le impronte dei file e viene archiviato in uno ZIP da conservare come prova.

## Rapporti e dati

Lanciato con `irm | iex`, CyberRSecurityCheck salva i dati in `%LOCALAPPDATA%\CyberRSecurityCheck`: `config.json` e la cartella `Report`. Lanciato da file, li salva accanto al file. Ogni analisi crea `Report\CyberRSecurityCheck_<PC>_<data>` con `REPORT.html`, `risultati.json`, `risultati.csv`, un CSV per ogni controllo, `snapshot.json` (confronto con l'analisi successiva), i log di AnyDesk/TeamViewer e della cronologia PowerShell, `SHA256SUMS.txt` e lo ZIP.

### Uso nel tempo

- Ripetendo l'analisi sullo stesso PC, il rapporto indica come **NUOVO** ciò che è comparso dall'ultima volta.
- Gli elementi verificati e legittimi si inseriscono in `config.json` (`AllowExtensionIds`, `AllowRemoteTools`, `AllowCertThumbprints`, `AllowPaths`) e non verranno più segnalati.
- I domini della banca da sorvegliare sono in `BankDomains`.

## Compilazione dai sorgenti

```powershell
git clone https://github.com/rtecnocopy89/CyberRSecurityCheck
cd CyberRSecurityCheck
.\Compile.ps1          # crea cyberrsecuritycheck.ps1 e cyberrsecuritycheck.ps1.sha256
.\Compile.ps1 -Test    # crea il file ed esegue i test automatici
.\Compile.ps1 -Run     # crea il file e lo avvia
```

| Percorso | Contenuto |
|---|---|
| `src/start.ps1` | lanciatore: parametri, riavvio come amministratore, estrazione dei componenti |
| `src/CyberRSecurityCheck.ps1` | motore di analisi (usabile anche da solo) |
| `src/CyberRSecurityCheck-GUI.ps1` | interfaccia: server locale e finestra app isolata |
| `ui/index.html` | grafica dell'interfaccia |
| `config/config.json` | configurazione predefinita |
| `tests/Test-CyberRSecurityCheck.ps1` | test automatici (devono essere tutti PASS) |

Il file `cyberrsecuritycheck.ps1` generato è ASCII puro, così funziona sia con `irm | iex` sia come file locale in Windows PowerShell 5.1 e PowerShell 7. Nel codice PowerShell i caratteri accentati vanno scritti con `[char]` (es. `"Modalit$([char]0x00E0)"`): la compilazione si interrompe se trova caratteri non ASCII.

## Limiti

Nessuno strumento automatico trova tutto: un rootkit può nascondersi. Se il rapporto è pulito ma il problema continua, servono una scansione offline (Microsoft Defender Offline) e i log della banca (IP, dispositivo e orario delle operazioni fraudolente).

## Crediti e Licenza

Distribuito sotto **Licenza MIT** (vedi [`LICENSE`](LICENSE)). Alcuni elementi grafici dell'interfaccia derivano da [Uiverse.io](https://uiverse.io) (MIT).
