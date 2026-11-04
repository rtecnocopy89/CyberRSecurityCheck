# CyberRSecurityCheck - note per Claude Code

Strumento PowerShell di Rosario (rtecnocopy89) per analizzare i PC Windows dei clienti usati per l'home
banking. Nato da un caso reale: cliente di BCC Campania Centro (home banking Relax Banking, relaxbanking.it)
a cui, durante bonifici sopra una certa cifra, l'IBAN del beneficiario veniva sostituito "a runtime" nella
pagina; la banca segnalava periodicamente credenziali rubate. Le scansioni di rete e antivirus non
trovavano nulla. Lo schema corrisponde a un man-in-the-browser tipo Ramnit + kit drIBAN (Cleafy).

Il progetto si avvia come WinRUtil (repo rtecnocopy89/WinRUtil, stesso autore):
`irm https://raw.githubusercontent.com/rtecnocopy89/CyberRSecurityCheck/main/cyberrsecuritycheck.ps1 | iex`

## Regola piu' importante: solo segnalazioni certe
Richiesta esplicita di Rosario: il programma non deve mai segnalare cose inutili, solo cose certe.
- `ALTA`  -> mostrato come **CONFERMATO**: solo indicatori specifici di attacco/manomissione che un software
  legittimo non produce (IBAN sostituito nel test appunti, PE iniettato in memoria privata eseguibile del
  browser, estensione fuori store con accesso al sito banca o a tutti i siti, file/HTML Ramnit, RunMRU con
  download+esecuzione, browser con --remote-debugging/--load-extension, RDP riuscito da IP pubblico,
  rilevamenti Defender recenti, hosts che dirotta il dominio banca, DNS banca risolto su IP privato).
- `MEDIA` -> **DA CONTROLLARE**: fatti certi e pertinenti con possibile spiegazione legittima, scritti come
  fatti ("AnyDesk e' installato"), non come ipotesi.
- `BASSA` -> **DETTAGLIO**: tutto il resto, nascosto per impostazione predefinita.
- Configurazione sbagliata (firewall spento...) -> righe `CRITICO` in "Configurazione", non tra i problemi.
- Se meno dell'80% dei controlli riesce, giudizio "Analisi incompleta": mai dire "tutto a posto" senza aver controllato.
- Prima di alzare una regola ad ALTA chiedersi: "un PC pulito puo' produrre questo?" Se si', non e' ALTA.
- Add-Finding deduplica titolo+dettaglio; le estensioni dello store con accesso a tutti i siti sono aggregate in un'unica riga BASSA.

## Struttura
- `src/start.ps1` lanciatore del file unico: param senza ValidateSet (irm|iex esegue il param block come
  semplici variabili), controllo Constrained Language, auto-elevazione come WinRUtil, estrazione dei blob
  Base64, dati in `%LOCALAPPDATA%\CyberRSecurityCheck` (o accanto al file se avviato da file).
  Variabili d'ambiente di test: `CRS_SELFTEST=1` (verifica componenti ed esce), `CRS_NO_ELEVATE=1`.
- `src/CyberRSecurityCheck.ps1` motore (24 controlli via Get-CollectPlan, Invoke-Section, Add-Finding,
  report HTML/JSON/CSV, SHA256SUMS, ZIP, confronto con snapshot precedente, ClipTest, Monitor).
  Parametri usati dalla GUI: `-ProgressSync` (hashtable sincronizzata), `-ExcludePids`.
- `src/CyberRSecurityCheck-GUI.ps1` server HttpListener solo `localhost:<porta casuale>`, token casuale nel
  frammento URL e header `X-Token`, controllo Host/Origin, CSP con nonce. Apre Edge/Chrome `--app` con
  profilo temporaneo `CyberRSecUI_*` ed estensioni disattivate (un'estensione malevola non deve poter alterare
  i risultati). Il motore gira in un runspace STA (AddScript con il testo incorporato, o AddCommand da file).
- `ui/index.html` interfaccia (tema scuro; pulsanti Uiverse "perfect-penguin" e barra "wise-moose" scelti
  da Rosario, opzioni B e C). Niente risorse esterne, niente commenti di attribuzione nel codice.
- `config/config.json` BankDomains, RecentDays, DnsCompare, Allow* (elementi autorizzati -> BASSA).
- `Compile.ps1` produce `cyberrsecuritycheck.ps1` (ASCII puro, senza BOM, CRLF) + `.sha256`.
- `tests/Test-CyberRSecurityCheck.ps1` 103 test, inclusa la simulazione `Get-Content | iex` del file unico.

## Convenzioni
- Compatibilita': Windows PowerShell 5.1 e PowerShell 7. Niente `??`, `?.`, ternario, `-Parallel`.
- Codice PowerShell solo ASCII: accenti con `[char]` o scritti come `e'`; la compilazione si ferma sui non ASCII.
- Trappola nota: `@($list)` su una `System.Collections.Generic.List` dentro un hashtable letterale o certe
  assegnazioni da' "Argument types do not match": usare `.ToArray()` o `.Count`.
- `$ud` nei blocchi di Get-CollectPlan e' risolto per scope dinamico da Invoke-Collect (l'avviso
  PSUseDeclaredVarsMoreThanAssignments e' un falso positivo).
- Messaggi all'utente in italiano, chiari, con "cosa fare".
- Lo strumento e' in sola lettura: nessuna modifica al sistema (il test appunti ripristina il contenuto).

## Flusso di lavoro
1. Modificare i sorgenti in `src/`, `ui/`, `config/`.
2. `.\Compile.ps1 -Test` -> devono passare tutti i test.
3. Committare anche `cyberrsecuritycheck.ps1` e `.sha256` (sono i file serviti con irm | iex).
4. Per le release: tag `vX.Y.Z`, impronta SHA256 nelle note di rilascio; aggiornare `$script:Version` e CHANGELOG.md.

## Stato e prossimi passi
- Finora testato solo su Linux con PowerShell 7 (pwsh): MAI eseguito su Windows reale. Primo compito:
  su questo PC eseguire `.\Compile.ps1 -Test` con Windows PowerShell 5.1 E con pwsh, poi un'analisi
  completa reale (GUI e `-Console`) come amministratore, e correggere cio' che non funziona su Windows
  (CIM, registro, eventi, Add-Type del modulo memoria con csc di .NET Framework, clipboard STA, Edge --app,
  HttpListener su localhost senza URL ACL).
- Verificare i falsi positivi su un PC pulito: un PC sano deve risultare con 0 CONFERMATI.
- Creare il repository GitHub pubblico `rtecnocopy89/CyberRSecurityCheck`, push del branch `main`, tag `v2.0.0`.
- Idee future: verifica firma/hash del file unico prima dell'esecuzione, export PDF del rapporto,
  stessa estetica di WinRUtil se Rosario lo chiede.
