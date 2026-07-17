# p2p-holepunch (Fase 2 — control plane)

Sistema in Rust ispirato a Tailscale: un **control plane** con IP pubblico
(backoffice web + login + segnalazione) e un **client** che, dietro NAT, si
autentica via browser e stabilisce una connessione **P2P diretta** con un altro
dispositivo dello stesso account tramite **UDP hole punching**.

Rispetto alla Fase 1 sono stati aggiunti:

- **Backoffice web** (login/registrazione) per vedere e collegare i dispositivi;
- **Login del client via browser** (device-code flow, come `tailscale up`):
  il client apre il browser, tu approvi, il dispositivo resta legato all'account;
- **Account e persistenza** (SQLite): utenti, dispositivi, sessioni.

## Struttura

```
Cargo.toml
src/
  lib.rs         # dichiarazione moduli + re-export protocollo
  proto.rs       # protocollo condiviso (messaggi JSON TCP/UDP)
  db.rs          # storage SQLite: utenti, device, sessioni, device-auth
  web.rs         # backoffice web (axum): login, /devices, mesh, exit node
  vpn.rs         # data plane VPN (feature `vpn`): TUN + forwarding (exit node)
  bin/server.rs  # control plane: HTTP + segnalazione TCP + UDP (sulla VPS)
  bin/client.rs  # client CLI per i dispositivi (login via browser + hole punch)
client-tauri/    # client desktop (Tauri): stessa logica, UI in HTML/JS
EXIT-NODE.md     # runbook del data plane VPN (exit node)
```

La libreria è divisa per feature: il control plane (axum + SQLite) sta dietro la
feature `server` (attiva di default); il data plane VPN (TUN) dietro la feature
`vpn`. I client usano la libreria con `default-features = false` e ottengono
**solo il modulo `proto`**, senza tirarsi dietro SQLite/axum.

## Due varianti di client (intercambiabili)

Stesso protocollo, stesso server: puoi anche collegare un client CLI con uno Tauri.

- **CLI** (`src/bin/client.rs`) — da terminale, un singolo binario nativo.
- **Desktop / Tauri** (`client-tauri/`) — app con finestra, UI in HTML/JS e rete
  in Rust. Vedi [`client-tauri/README.md`](client-tauri/README.md).

Tre servizi sullo stesso processo `server`:

| Servizio | Porta di default | Ruolo |
|----------|------------------|-------|
| HTTP     | `8080`           | backoffice web + API del device-code flow |
| TCP      | `47100`          | segnalazione (il client si autentica con la `auth_key`) |
| UDP      | `47101`          | apprende l'endpoint UDP pubblico per l'hole punching |

## Compilazione

```bash
cargo build --release
# binari in target/release/server  e  target/release/client
```

## Come funziona (flusso "alla Tailscale")

1. Ti registri/accedi al **backoffice** (`http://<server>:8080`).
2. Su un dispositivo avvii il **client**: apre il browser sulla pagina di
   approvazione. Approvi → il dispositivo riceve un'identità persistente
   (`device_id` + `auth_key`) salvata in `~/.p2p-holepunch/config.json`.
3. Ripeti su ogni dispositivo che vuoi aggiungere all'account.
4. **Mesh automatica:** appena un dispositivo è online e pubblica il suo
   endpoint UDP, il server lo collega **tutti-con-tutti** agli altri dispositivi
   online dell'account (hole punching). Non serve alcuna azione manuale.
5. **Exit node (opzionale):** nel backoffice puoi marcare uno o più dispositivi
   come *disponibili a fare da exit node*. Questa disponibilità viene comunicata
   agli altri, che potranno poi sceglierne uno dal client.

> ⚠️ L'exit node oggi è al livello di **coordinamento**: il server marca e
> annuncia quali dispositivi sono disponibili come uscita. Il **routing vero del
> traffico** attraverso l'exit node (interfaccia TUN + forwarding) è il passo
> successivo e non è ancora implementato.

## Test in locale (una sola macchina)

```bash
# 1) Server (control plane)
cargo run --bin server
# Backoffice su http://127.0.0.1:8080

# 2) Apri il browser su http://127.0.0.1:8080 e REGISTRATI.

# 3) Primo client (apre il browser per l'approvazione)
cargo run --bin client -- "laptop"

# 4) Altri client (quanti vuoi)
cargo run --bin client -- "telefono"
cargo run --bin client -- "nas-casa"

# I dispositivi si collegano da soli (mesh). In ogni terminale comparirà,
# per ciascun peer:
#    [Mesh] Peer '...' @ ... → hole punching
#    ✅ Connessione P2P diretta stabilita ...
#
# (Facoltativo) Nel backoffice -> Dispositivi puoi marcare un dispositivo come
# exit node: comparirà come "[disponibile come exit node]" nei log degli altri.
```

> Nota: sulla stessa macchina i client condividono `~/.p2p-holepunch/config.json`.
> Per provarne più d'uno in locale usa `HOME` diverse, es.
> `HOME=/tmp/h1 P2P_HTTP_PORT=8091 cargo run --bin client`.

> In locale non c'è NAT, quindi il "buco" è banale: serve a validare tutta la
> catena (login, account, segnalazione) prima di andare sulla VPS.
>
> Le porte di default sono **8080/tcp** (backoffice), **47100/tcp**
> (segnalazione) e **47101/udp**. Se la 8080 è occupata, avvia con
> `HTTP_PORT=8091 PUBLIC_URL=http://127.0.0.1:8091 cargo run --bin server` e il
> client con `P2P_HTTP_PORT=8091`.

### Variabili d'ambiente

**Server:** `DB_PATH` (default `data.db`), `HTTP_PORT` (default `8080`),
`PUBLIC_URL` (default `http://127.0.0.1:<HTTP_PORT>`, usato nei link del
device-code flow — in produzione mettere l'URL pubblico).

**Client:** `P2P_SERVER` (IP/host del server), `P2P_HTTP_PORT`, `P2P_TCP_PORT`,
`P2P_UDP_PORT`. In alternativa modifica le costanti in cima a `src/bin/client.rs`.

Comandi utili del client:

```bash
client               # login (se serve) + attesa collegamento
client "Nome device" # imposta il nome del dispositivo al primo login
client --reset       # cancella la config locale (rifà il login)
```

## Deploy sulla VPS DigitalOcean

1. Configura il client con l'IP pubblico del droplet: costante `SERVER_IP` in
   `src/bin/client.rs` oppure `P2P_SERVER=<ip>` a runtime.
2. Ricompila il client per i tuoi dispositivi.
3. Apri le porte nel firewall (es. `ufw`):
   ```bash
   sudo ufw allow 8080/tcp    # backoffice web
   sudo ufw allow 47100/tcp   # segnalazione
   sudo ufw allow 47101/udp   # hole punching
   ```
4. Avvia il server (dietro `systemd` / `tmux`), impostando l'URL pubblico:
   ```bash
   PUBLIC_URL=http://<ip-o-dominio>:8080 ./server
   ```
5. Registrati dal backoffice, poi avvia il client su ogni dispositivo.

> In produzione metti il backoffice **dietro HTTPS** (reverse proxy nginx/caddy):
> le password e i cookie di sessione viaggiano in chiaro sulla 8080. Vedi sotto.

## Limiti noti (prossime fasi)

- **HTTP in chiaro:** il backoffice non fa TLS. In produzione va messo dietro un
  reverse proxy HTTPS (caddy/nginx) e `PUBLIC_URL=https://...`.
- **Exit node — routing da validare:** il tunnel è **cifrato con WireGuard**
  (crypto verificata da unit test) e il control plane assegna IP virtuali
  (IPAM); l'instradamento reale del traffico richiede però la **TUN** (privilegi
  root) e va provato sul campo. Vedi [`EXIT-NODE.md`](EXIT-NODE.md).
- **NAT simmetrico:** può rimappare le porte in modo imprevedibile; in quel caso
  l'hole punching diretto fallisce e serve un **relay** via server (tipo DERP).
- **Nessuna cifratura del traffico P2P** né keep-alive del buco NAT dopo il
  collegamento: base didattica, non ancora una VPN sicura end-to-end.
