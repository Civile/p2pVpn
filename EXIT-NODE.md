# Exit node — data plane VPN (feature `vpn`)

Questo documento descrive come far instradare **davvero** il traffico di un
dispositivo attraverso un altro marcato come *exit node*, usando il data plane
implementato in `src/vpn.rs` (feature `vpn`).

> ⚠️ **Stato onesto.** Il data plane è implementato e **compila**. Sono coperti
> da **unit test** (`cargo test --features vpn`): framing/demux, IPAM,
> parsing IPv4 e — soprattutto — l'**handshake WireGuard con roundtrip cifrato**
> (due sessioni `Tunn` che si scambiano un pacchetto cifrato che si decifra
> correttamente). L'instradamento reale del traffico verso Internet, invece,
> **non è stato verificato**: aprire la TUN richiede privilegi **root** (senza,
> fallisce con `Operation not permitted`) e l'uscita va su un host adatto
> (tipicamente **Linux**). Consideralo un **prototipo con crittografia
> verificata ma da validare end-to-end sul campo**.
>
> ✅ **Cifratura.** Il tunnel usa **WireGuard** (boringtun): ogni coppia
> client↔exit fa un handshake Noise e cifra i pacchetti (ChaCha20-Poly1305). Le
> chiavi X25519 sono generate dal client al primo avvio e distribuite via mesh.

## Come funziona

Subnet virtuale `10.7.0.0/24`:

- **Exit node** → TUN `10.7.0.1`, con IP forwarding + NAT masquerade verso
  Internet. Riceve i pacchetti dei client sul socket UDP già "bucato" dalla
  mesh, li scrive sulla propria TUN (il kernel li instrada e NATta), e rispedisce
  le risposte al client giusto (mappa *IP virtuale → endpoint UDP*, appresa dal
  traffico).
- **Client** → TUN `10.7.0.x` (IP derivato dal `device_id`). I pacchetti locali
  entrano nella TUN, vengono incapsulati (un magic byte) e spediti all'exit node
  sul socket bucato.

Il socket UDP è **lo stesso** della mesh: i datagrammi VPN sono distinti dai PING
di hole punching tramite il magic byte, e il ricevitore del client li smista al
tunnel (demux in `spawn_receiver`).

## Compilazione

```bash
# Client + data plane
cargo build --release --features vpn --bin client
```

## Uso

Prerequisiti: aver già fatto login dei dispositivi (device-code flow) e aver
marcato l'exit node come tale nel backoffice (**Dispositivi → Rendi exit node**).

### 1. Sull'exit node (idealmente una VPS Linux)

```bash
sudo ./client --exit-node
```

All'avvio prova a configurare da sé, su Linux:

```
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.7.0.0/24 -j MASQUERADE
```

Se preferisci farlo a mano (o sei su un kernel con firewall gestito), esegui gli
stessi comandi prima di avviare. Su **macOS** l'auto-config non è supportata; usa
`pf`:

```
sysctl -w net.inet.ip.forwarding=1
echo 'nat on en0 from 10.7.0.0/24 to any -> (en0)' | sudo pfctl -f - -e
```

### 2. Sul client che vuole uscire dall'exit node

```bash
sudo ./client --use-exit "nome-exit-node"
```

Il client, appena l'exit node è online nella mesh, invia `UseExitNode`, riceve
conferma dal server e avvia il tunnel verso l'endpoint bucato dell'exit.

### 3. Routing del traffico (manuale, per ora)

Portare la TUN "su" con un indirizzo aggiunge automaticamente la rotta della
subnet `10.7.0.0/24`. Per instradare **tutto** il traffico servono, sul client,
le classiche rotte VPN (Linux), da adattare:

```bash
# Tieni raggiungibile l'exit node per la sua strada normale
sudo ip route add <IP_PUBBLICO_EXIT>/32 via <GATEWAY_ATTUALE>
# Manda tutto il resto nella TUN (0/1 + 128/1 = default senza sovrascriverlo)
sudo ip route add 0.0.0.0/1 dev tun0
sudo ip route add 128.0.0.0/1 dev tun0
```

Queste rotte **non** vengono impostate in automatico di proposito: manipolare la
default route è delicato e va fatto con cognizione (rischio di tagliarsi fuori
dalla rete). Per un test più sicuro, instrada nella TUN solo una subnet specifica
invece di tutto.

## Verifica consigliata (sul campo)

1. Due host Linux (o un client Linux + una VPS Linux come exit).
2. Avvia server, logga i dispositivi, marca l'exit.
3. `sudo ./client --exit-node` sull'uscita, `sudo ./client --use-exit <nome>` sul
   client, poi le rotte del punto 3.
4. Dal client: `curl -s https://ifconfig.me` → deve mostrare **l'IP pubblico
   dell'exit node**. Quello è l'exit node "che funziona".

## Cosa è già implementato

- **Cifratura WireGuard** (boringtun) end-to-end tra client ed exit node.
- **IPAM**: il server assegna IP virtuali stabili e distinti (`10.7.0.x`),
  salvati nel dispositivo e distribuiti via mesh.
- **Selezione dell'exit node dal client**: CLI (`--use-exit <nome>`) e app Tauri
  (menu a tendina degli exit disponibili).

## Limiti noti di questo taglio

- **Instradamento non verificato**: la TUN richiede root; il routing full-tunnel
  è manuale (comandi sopra) e va provato su un host reale.
- **Solo IPv4**. Nessun push automatico di DNS.
- **NAT simmetrico** lato mesh: se l'hole punching diretto fallisce, serve un
  relay (tipo DERP), non ancora presente.
