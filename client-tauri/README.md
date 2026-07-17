# Client desktop (Tauri)

App desktop del client P2P. **UI in HTML/JS**, **rete in Rust** (riusa il
protocollo `p2p_holepunch::proto`). Login via browser (device-code flow),
segnalazione TCP e UDP hole punching, esattamente come il client CLI ma con
un'interfaccia grafica ed eventi in tempo reale.

```
client-tauri/
  src/               # frontend statico (nessun bundler, nessun npm)
    index.html
    main.js
  src-tauri/
    Cargo.toml       # dipende da ../.. (solo `proto`, default-features = false)
    tauri.conf.json
    src/lib.rs       # comandi: get_state, login_start, login_wait, connect, logout
    src/main.rs
    capabilities/    # permessi Tauri v2
    icons/
```

## Prerequisiti

- Rust (già installato).
- macOS: gli strumenti da riga di comando di Xcode (`xcode-select --install`).
  La webview usa **WKWebView** di sistema: niente Chromium da scaricare.
- (Solo per creare gli installer) la CLI di Tauri:
  `cargo install tauri-cli --version '^2'`.

## Avvio in sviluppo

Il server deve essere in esecuzione e devi esserti registrato nel backoffice.

```bash
cd client-tauri/src-tauri

# Se il server gira sulle porte di default:
cargo run

# In locale, con il backoffice sulla 8091 (per il conflitto sulla 8080):
P2P_SERVER=127.0.0.1 P2P_HTTP_PORT=8091 cargo run
```

Si apre la finestra dell'app. Al primo avvio:

1. Inserisci il **nome del dispositivo** e premi *Accedi via browser* → si apre
   il browser sulla pagina di approvazione del backoffice.
2. Approva: l'app riceve l'identità e passa alla schermata principale.
3. Premi **Connetti**. Poi nel backoffice (**Dispositivi**) seleziona questo
   dispositivo e un altro e premi **Collega**.
4. Nel log dell'app comparirà `✅ Connessione P2P diretta stabilita`.

## Variabili d'ambiente

Come il client CLI: `P2P_SERVER`, `P2P_HTTP_PORT` (default 8080),
`P2P_TCP_PORT` (47100), `P2P_UDP_PORT` (47101). La config viene salvata in
`~/.p2p-holepunch/config.json` (stessa del client CLI).

## Creare gli installer (.app / .dmg / .exe / .deb)

```bash
cd client-tauri/src-tauri
cargo tauri build
# output in target/release/bundle/
```

> Per distribuirlo senza avvisi di sicurezza va **firmato**: notarizzazione
> Apple su macOS, certificato di code signing su Windows. Senza firma funziona
> comunque, ma al primo avvio l'utente vede l'avviso del sistema.

## Note

- **Due client sulla stessa macchina** condividono la stessa config
  (`~/.p2p-holepunch/config.json`). Per provare due peer in locale, usa un client
  Tauri e uno CLI con `HOME` diverso, oppure due `HOME` separate.
- Il client Tauri e il client CLI sono **intercambiabili**: stesso protocollo,
  stesso server. Puoi collegare un Tauri con un CLI senza problemi.
- Non serve `npm`: il frontend è statico e usa `withGlobalTauri`
  (`window.__TAURI__`). `cargo run` incorpora `src/` a compile time.
