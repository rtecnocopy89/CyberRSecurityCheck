# Novità

## 2.0.0
- Avvio con `irm ... | iex` da un unico file ASCII (`cyberrsecuritycheck.ps1`), riavvio automatico come amministratore, dati in `%LOCALAPPDATA%\CyberRSecurityCheck`.
- Interfaccia grafica con barra di avanzamento, registro in tempo reale e schermata dei risultati con punteggio; finestra isolata senza estensioni.
- Solo segnalazioni certe: esiti CONFERMATO / DA CONTROLLARE / DA CORREGGERE / DETTAGLIO; "Analisi incompleta" se mancano troppi controlli.
- Nuovi controlli: codice iniettato in memoria, indicatori Ramnit/drIBAN, ClickFix/FileFix, debug remoto dei browser (infostealer), ARP, BAM, BITS, configurazione di sicurezza.
- Programmi di controllo remoto: una sola segnalazione per programma, con l'elenco dei componenti trovati (installato, servizio, processo).
- Riavvio come amministratore: il lanciatore termina con `return`, così non interrompe lo script o il ciclo da cui è stato avviato.
- Provato su Windows 11 con Windows PowerShell 5.1 e PowerShell 7.6: test automatici, analisi reale da console e da interfaccia, avvio come `irm | iex` con riavvio automatico come amministratore.

## 1.1.0
- Configurazione con elementi autorizzati, confronto con l'analisi precedente, `SHA256SUMS.txt`.

## 1.0.0
- Prima versione (script di analisi per i bonifici).
