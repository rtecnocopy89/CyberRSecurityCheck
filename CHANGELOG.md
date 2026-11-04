# Novità

## 2.0.0
- Avvio con `irm ... | iex` da un unico file ASCII (`cyberrsecuritycheck.ps1`), riavvio automatico come amministratore, dati in `%LOCALAPPDATA%\CyberRSecurityCheck`.
- Interfaccia grafica con barra di avanzamento, registro in tempo reale e schermata dei risultati con punteggio; finestra isolata senza estensioni.
- Solo segnalazioni certe: esiti CONFERMATO / DA CONTROLLARE / DA CORREGGERE / DETTAGLIO; "Analisi incompleta" se mancano troppi controlli.
- Nuovi controlli: codice iniettato in memoria, indicatori Ramnit/drIBAN, ClickFix/FileFix, debug remoto dei browser (infostealer), ARP, BAM, BITS, configurazione di sicurezza.

## 1.1.0
- Configurazione con elementi autorizzati, confronto con l'analisi precedente, `SHA256SUMS.txt`.

## 1.0.0
- Prima versione (script di analisi per i bonifici).
