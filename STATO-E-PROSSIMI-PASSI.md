# Stato lavori e prossimi passi (aggiornato: 2026-07-22)

## 🚀 NOVITÀ 2026-07-22 — RELAY stile DERP (il "funziona ovunque")

Implementato il **relay sul server** (droplet), la strada definitiva già indicata
sotto: quando il collegamento diretto non passa (CGNAT, NAT simmetrico, niente
port forwarding), i datagrammi WireGuard **cifrati** rimbalzano dal server, che ha
IP pubblico. È il meccanismo con cui Tailscale "funziona sempre".

**Come funziona:**
- Il relay riusa la **stessa porta UDP 47101** dell'apprendimento endpoint → il
  mapping NAT è identico a quello del keepalive, quindi **funziona anche sotto NAT
  simmetrico** (niente hole punching necessario).
- Framing binario `[0x72]['r'][len][device_id][wireguard…]`; il server riscrive
  l'id `destinatario → mittente` così il ricevente sa da chi arriva (le sessioni
  WireGuard sono indicizzate per **identità**, non per indirizzo).
- Nuovo tipo `Endpoint::{Direct, Relay}` nel data plane: invio/ricezione uguali su
  entrambi i percorsi. TUN a **MTU 1280** per evitare frammentazione nel doppio
  incapsulamento.

**Default cambiato:** `client --use-exit "<nome>"` ora passa dal **relay**
(funziona ovunque, zero config sul router). `--exit-endpoint IP:porta` resta per
il percorso **diretto** (LAN o port forwarding, più veloce).

**Collaudo:** unit test del framing/instradamento + un test d'integrazione che fa
l'**handshake WireGuard completo attraverso il relay** su socket reali (senza
TUN/root). Tutti verdi (`cargo test --features vpn`). Le parti TUN/root non sono
testabili in dev: vanno provate sull'hardware (vedi sotto).

### ⚠️ DA FARE PER ATTIVARLO (deploy)
1. **Ricompilare e ridistribuire il server** sul droplet (contiene il relay):
   `pm2 deploy production` (vedi memoria `prod-deploy`). Verificare che la
   **47101/udp** sia aperta (dovrebbe già esserlo).
2. **Ricompilare i client** (`--features vpn`) e reinstallarli: binario Mac in
   `dist/`, binario Pi via `deploy/raspberry/cross-build.sh` → reinstallare sul Pi
   (⚠️ sempre: `p2p-client --help | grep -i relay` per confermare il binario nuovo).
3. **Test dall'hotspot**: `sudo … p2p-client-macos-arm64 --use-exit "raspberry-casa"`
   (SENZA `--exit-endpoint`) → `curl ifconfig.me` deve mostrare l'IP di casa.
   Non serve più toccare il router.

### Idea futura (non urgente)
Auto-upgrade a diretto: partire dal relay (garantito) e passare al diretto se
l'hole punching col peer riesce (come fa Tailscale). Ora è relay-o-diretto scelto
all'avvio in base a `--exit-endpoint`.

---

# (Storico) Stato al 2026-07-21, fine giornata

## 🎯 Obiettivo
VPN reale: dal **Mac** (ovunque nel mondo) far uscire tutto il traffico
attraverso il **Raspberry Pi** che sta a casa (exit node), così da avere l'IP di
casa da qualsiasi rete.

---

## ✅ COSA FUNZIONA (dimostrato oggi)

Il tunnel **funziona end-to-end** quando Mac e Pi si raggiungono direttamente.
Provato con successo sulla **LAN di casa** puntando all'IP locale del Pi:

- **Pi (exit):** `sudo env HOME="$HOME" P2P_BIND_PORT=47820 /usr/local/bin/p2p-client --exit-node`
  → log: `sessione WireGuard avviata con client 192.168.1.2:...`
- **Mac (client):** `sudo --preserve-env=HOME ./dist/p2p-client-macos-arm64 --use-exit "raspberry-casa" --exit-endpoint 192.168.1.10:47820`
  → log: `handshake OK → attivo il full tunnel` + `[route] ✅ VPN attiva`

Handshake WireGuard, cifratura, routing automatico (default via TUN + DNS) e
ripristino su Ctrl-C: **tutto ok**.

## ❌ COSA NON FUNZIONA ANCORA
Dall'**hotspot del telefono** (uso remoto reale): il tunnel si blocca perché i
pacchetti diretti non attraversano il NAT.
- L'hotspot usa **CGNAT (NAT simmetrico)**: hole punching diretto impossibile.
- Anche sulla stessa rete l'hole punching falliva: il router **non fa hairpinning**
  (mandare al proprio IP pubblico dall'interno non torna indietro).
- La soluzione trovata: **endpoint diretto** verso il Pi (`--exit-endpoint`), che
  bypassa l'hole punching. In LAN funziona. Da remoto serve che il Pi sia
  **raggiungibile dall'esterno** → port forwarding sul router.

**Ultimo test (hotspot):** `curl ifconfig.me` mostrava ancora l'IP dell'hotspot
(`87.241.148.51`), non quello di casa → il traffico non passava. Motivo da
confermare (vedi TODO #1): regola port forwarding, IP di casa cambiato, o **CGNAT
lato casa**.

---

## 📋 DA FARE DOMANI (in ordine)

### 1. Capire perché da hotspot non passa
Serve il **log del client** dall'hotspot (fin dove arriva) + verifiche:
- **Router → pagina Stato/WAN → guardare l'IP WAN:**
  - se è `46.36.123.220` (o comunque un IP pubblico "vero") → port forwarding
    deve funzionare, è un problema di regola.
  - se è `10.x` / `100.64–100.127.x` / `192.168.x` → **CGNAT lato casa**: il port
    forwarding NON può funzionare → serve il relay (vedi #3).
- Verificare che la **regola port forwarding** sia attiva:
  UDP, WAN port `47820`, LAN host `192.168.1.10`, LAN port `47820`, origine "any".
- Verificare che l'**IP pubblico di casa** non sia cambiato (è dinamico): si legge
  nel log del client alla riga `[Mesh] Peer 'raspberry-casa' @ X.X.X.X:47820`.
  Usare quella X nel `--exit-endpoint`.

### 2. Se l'IP pubblico di casa è dinamico
Impostare un **DDNS** (es. DuckDNS/No-IP) sul router o sul Pi, così `--exit-endpoint`
può usare un nome fisso invece dell'IP.

### 3. Se casa è dietro CGNAT (port forwarding impossibile)
Implementare un **relay stile DERP** sul droplet (`abc.edoardocasella.it`,
`188.166.36.30`): quando l'hole punching diretto fallisce, il traffico cifrato
passa dal droplet. È la soluzione "alla Tailscale", funziona ovunque senza toccare
il router. Lavoro medio-grande, lato server + client.

### 4. Rendere permanente e comodo (dopo che il remoto funziona)
- **Porta fissa sul Pi**: già impostata via drop-in systemd
  `/etc/systemd/system/p2p-vpn.service.d/port.conf` con `P2P_BIND_PORT=47820`.
  (Da verificare che sia attiva: `journalctl -u p2p-vpn -n 15 | grep "Socket UDP"`
  deve dire `0.0.0.0:47820`.)
- **Integrare `--exit-endpoint` nell'app GUI** (campo o automatico), così si fa
  tutto dall'app senza terminale.
- **Baking di `P2P_BIND_PORT` in `--install-service`** (ora va messo a mano).

### 5. Pulizia
- Nel backoffice ci sono **4 dispositivi "dispositivo"** (uno per ogni login
  rifatto): cancellare gli **offline** doppioni, tenerne uno.
- Sfarfallio mesh (peer offline/online ogni ~3s): capire se dipende ancora da
  processi multipli o dall'instabilità della rete. Non blocca il tunnel diretto.

---

## 🔑 DATI UTILI

| Cosa | Valore |
|------|--------|
| IP LAN del Pi | `192.168.1.10` |
| IP pubblico di casa (visto dal server) | `46.36.123.220` (⚠️ forse dinamico) |
| Porta UDP fissa scelta | `47820` (la 51820 era occupata da WireGuard/Tailscale sul Pi) |
| Nome exit node | `raspberry-casa` (device_id `2afdb670...`) |
| Server / control plane | `abc.edoardocasella.it` (droplet `188.166.36.30`) |
| Segnalazione TCP / hole punch UDP | 47100 / 47101 |
| Il Pi ha anche Tailscale | IP `100.119.159.117` (non usato dal nostro sistema) |

## 📦 BINARI PRONTI (in `dist/`)
- `P2P VPN.app` + `P2P-VPN-macos-arm64.dmg` — app grafica Mac (Apple Silicon).
- `p2p-client-macos-arm64` — CLI Mac.
- `p2p-client-linux-arm64` — CLI Raspberry Pi (aarch64, glibc ≥ 2.31).

⚠️ **Se si ricompila il CLI, va reinstallato sul Pi** (oggi ci ha fatto perdere
tempo un binario vecchio sul Pi: controllare sempre con
`/usr/local/bin/p2p-client --help | grep BIND_PORT`).

## 🧪 COMANDI DI TEST RAPIDI

Pi (exit, porta fissa, manuale):
```bash
sudo systemctl stop p2p-vpn; sudo pkill -9 -x p2p-client
sudo env HOME="$HOME" P2P_BIND_PORT=47820 /usr/local/bin/p2p-client --exit-node
# deve dire: Socket UDP locale su 0.0.0.0:47820
```

Mac (client, endpoint diretto):
```bash
cd "/Users/sebastianocasella/Desktop/Tools/VPN tailscale"
sudo sh -c "LC_ALL=C pkill -9 -f 'use-exit'"        # pulizia processi
sudo --preserve-env=HOME ./dist/p2p-client-macos-arm64 --use-exit "raspberry-casa" --exit-endpoint <IP>:47820
# LAN:    <IP> = 192.168.1.10   (funziona)
# remoto: <IP> = IP pubblico di casa (da far funzionare col port forwarding)
curl -s https://ifconfig.me ; echo    # deve mostrare l'IP di casa
```

Spegnere la VPN: `Ctrl-C` (ripristina rotte e DNS).

---

## 🛠️ MODIFICHE FATTE OGGI AL CODICE (non committate)
- `src/route.rs` (NUOVO): routing automatico full-tunnel macOS/Linux + ripristino.
- `src/vpn.rs`: kick handshake all'avvio; exit prova **tutte** le chiavi note
  (gestisce mismatch d'indirizzo); log diagnostici; buffer handshake.
- `src/bin/client.rs`: `--list-exits`, `--install-service`/`--uninstall-service`
  (systemd), `--exit-endpoint` + `P2P_EXIT_ENDPOINT`, `P2P_BIND_PORT`, vip preso
  dal server o derivato, SIGTERM/SIGINT → ripristino, log PING ridotti.
- `client-tauri/`: app come pannello di controllo (login + selettore exit +
  interruttore VPN On/Off) che pilota il CLI via prompt admin; fix locale
  (`LC_ALL=C`), stop robusto, anti-accavallamento processi.
- `Cargo.toml`: OpenSSL vendored per target non-macOS (cross-compilazione).
- `deploy/raspberry/`: install.sh, cross-build.sh (cargo-zigbuild), p2p-vpn.service, README.
- Toolchain cross: installati `cargo-zigbuild` + `zig 0.14.1` (in `~/.local` +
  symlink in `~/.cargo/bin/zig`) per compilare il binario ARM dal Mac.

⚠️ **Effetto collaterale**: durante il setup, `brew autoremove` ha rimosso
`node`, `mongosh`, `aspell`, ecc. Se servono: `brew install node mongosh`.

## 💡 NOTA STRATEGICA
Il **relay sul droplet** (#3) risolverebbe TUTTO in un colpo (hotspot, CGNAT,
niente port forwarding, niente DDNS) ed è la strada "definitiva". Il port
forwarding è più veloce ma fragile (IP dinamico, e inutile se casa è in CGNAT).
Domani, in base all'IP WAN del router, si decide quale strada prendere.
