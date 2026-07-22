# Guida: Raspberry come exit node + Mac come client VPN

Guida operativa in italiano per usare un **Raspberry Pi** (es. Pi 500) da **exit
node** e far uscire tutto il traffico del **Mac** attraverso di esso, da qualsiasi
parte del mondo (VPN reale, tunnel cifrato WireGuard). Il riferimento tecnico
completo (in inglese) resta [`EXIT-NODE.md`](./EXIT-NODE.md).

---

## Stato attuale (2026-07-21)

Cosa funziona GIÀ:
- Control plane in produzione su `https://abc.edoardocasella.it` (droplet
  DigitalOcean `188.166.36.30`, nginx + pm2). Vedi memoria `prod-deploy`.
- App desktop Tauri (`.dmg`/`.app`) con login via browser e mesh P2P.
- **Client CLI con VPN reale**: tunnel cifrato WireGuard + **routing automatico
  full-tunnel** (aggiunge/ripristina le rotte da solo) — vedi sotto.
- **Pacchetto Raspberry** (`deploy/raspberry/`): build, install, avvio automatico.

### Novità rispetto alla versione precedente
- Il routing "full tunnel" **non è più manuale**: il client CLI, appena
  l'handshake WireGuard è confermato, dirotta tutto il traffico nel tunnel,
  pinna l'IP dell'exit al gateway attuale e imposta un DNS pubblico. Su `Ctrl-C`
  **ripristina tutto** (niente più rischio di restare tagliati fuori).
- Nuovo comando **`--list-exits`** per vedere gli exit node online.
- Nuovo comando **`--install-service`** ("connetti all'avvio") per far partire il
  client come exit node a ogni boot del Raspberry (systemd).

### ⚠️ Da sapere
- **L'app GUI Tauri NON fa il tunnel**: il selettore exit node invia solo il
  messaggio di controllo `UseExitNode`. Il data plane reale (TUN + WireGuard +
  routing) vive **nel client CLI compilato con `--features vpn`** e richiede
  **root** su entrambe le estremità. Sul Mac quindi la VPN si accende dal CLI.
- Testato: framing, demux e crittografia WireGuard (unit test). L'instradamento
  end-to-end verso Internet va verificato sul campo (serve TUN + root reali).

---

## Perché il Raspberry come exit node

- È **Linux** → auto-config dell'exit supportata (`ip_forward` + `iptables
  MASQUERADE`), fatta dal binario stesso.
- Sta **a casa tua** → usarlo come exit ti dà l'IP di casa ovunque tu sia.
- Può stare **sempre acceso** e riconnettersi al boot (servizio systemd).

---

## Passi

### A. Sul Raspberry (una volta)

Vedi il dettaglio in [`deploy/raspberry/README.md`](./deploy/raspberry/README.md).
In sintesi:

```bash
# sul Pi, dalla radice del repo
./deploy/raspberry/install.sh            # dipendenze + build (--features vpn) + install

p2p-client "raspberry-casa"              # LOGIN: approva il link nel browser, poi Ctrl-C
# backoffice → Devices → Rendi exit node su "raspberry-casa"

sudo p2p-client --install-service --exit-node   # CONNETTI ALL'AVVIO come exit node
```

Verifica: `systemctl status p2p-vpn` · Log: `journalctl -u p2p-vpn -f`.

### B. Sul Mac (client VPN)

```bash
cargo build --release --features vpn --bin client

./target/release/client --list-exits             # vedi gli exit node online
sudo ./target/release/client --use-exit "raspberry-casa"
```

Il client fa **tutto da solo**: crea il TUN, completa l'handshake, poi instrada
tutto il traffico nel tunnel. Premi `Ctrl-C` per spegnere la VPN e ripristinare
il routing originale.

- `--no-route`: crea solo l'interfaccia TUN e lascia il routing a te (test di una
  singola subnet, debug).

### C. Verifica

```bash
curl -s https://ifconfig.me
# deve mostrare l'IP pubblico di casa tua (quello del Raspberry) = VPN funzionante
```

---

## Come funziona il routing automatico (`src/route.rs`)

Quando l'handshake è confermato, sul client:
1. salva gateway di default, interfaccia WAN e DNS attuali;
2. **pinna** l'IP pubblico dell'exit al gateway attuale (rotta host) → i pacchetti
   WireGuard verso l'exit non entrano nel tunnel (niente loop);
3. instrada `0.0.0.0/1` + `128.0.0.0/1` dentro il TUN (coprono l'intero default
   senza cancellare la rotta di default originale);
4. imposta DNS pubblico (1.1.1.1 / 8.8.8.8);
5. su `Ctrl-C` o disconnessione, **ripristina** rotte e DNS.

Supporta macOS (`route`/`networksetup`) e Linux (`ip`/`resolv.conf`).

---

## Insidie / checklist
- [ ] **Firewall droplet**: TCP 47100 + UDP 47101 aperti (segnalazione + hole
      punching; l'UDP porta i pacchetti WireGuard cifrati).
- [ ] **Root**: il tunnel (TUN) e il routing richiedono `sudo` su Mac e Pi.
- [ ] **NAT del Raspberry**: se il Pi è dietro NAT simmetrico e l'hole punching
      diretto fallisce serve un relay (DERP-style), non ancora presente.
- [ ] **Solo IPv4**.
- [ ] **Ripristino**: se il client viene killato brutalmente (`kill -9`) le rotte
      restano; ripristina riavviando la rete o con `route delete`/`ip route del`.

---

## Idee per il futuro
1. Far accendere la VPN direttamente dalla **GUI Tauri** (serve un helper
   privilegiato per il TUN/route su macOS).
2. Relay DERP-style per i NAT simmetrici.
3. Push DNS/rotte dal control plane (vera tailnet).

Riferimenti: `src/route.rs` (routing), `src/vpn.rs` (data plane),
`src/bin/client.rs` (flag CLI), `deploy/raspberry/` (pacchetto Pi),
`EXIT-NODE.md` (doc tecnica completa).
