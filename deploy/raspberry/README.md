# Client P2P VPN su Raspberry Pi (500) — exit node con avvio automatico

Questa cartella impacchetta tutto il necessario per far girare il client sul
**Raspberry Pi 500** (Raspberry Pi OS / Debian 64-bit, CPU `aarch64`), farlo da
**exit node** e connetterlo **automaticamente a ogni avvio**.

Risultato finale: dal Mac, ovunque nel mondo, scegli il Raspberry come exit node
e tutto il traffico esce da casa attraverso di esso (VPN reale, tunnel cifrato
WireGuard).

---

## Via consigliata: build nativa sul Pi

Il Pi 500 è abbastanza potente da compilare da solo (qualche minuto). È la via
più affidabile (niente toolchain di cross-compilazione da gestire).

Sul Raspberry (via SSH o direttamente):

```bash
# 1. porta il sorgente sul Pi (git clone del repo, oppure scp/rsync della cartella)
git clone <URL-del-repo> p2p-vpn && cd p2p-vpn
#    (in alternativa: rsync -av /percorso/locale/ pi@raspberry:~/p2p-vpn/)

# 2. build + install del binario (installa anche le dipendenze)
./deploy/raspberry/install.sh
```

Lo script:
- installa `build-essential`, `pkg-config`, `libssl-dev`, `iptables`, `rustup`;
- compila `client` con `--features vpn` (data plane: TUN + WireGuard);
- installa il binario in `/usr/local/bin/p2p-client`;
- stampa i passi finali (login → marca exit node → avvio automatico).

Poi, una volta sola:

```bash
# LOGIN (apre/mostra un link da approvare su https://abc.edoardocasella.it)
p2p-client "raspberry-casa"      # approva dal browser, poi Ctrl-C

# Nel backoffice: Devices → Rendi exit node su "raspberry-casa"

# CONNETTI ALL'AVVIO come exit node (servizio systemd)
sudo p2p-client --install-service --exit-node
```

Verifica e log:

```bash
systemctl status p2p-vpn
journalctl -u p2p-vpn -f
```

Disattivare l'avvio automatico:

```bash
sudo p2p-client --uninstall-service
```

---

## Via alternativa: cross-compilazione dal Mac (con zig, senza Docker)

Se non vuoi compilare sul Pi, dal Mac puoi cross-compilare con **cargo-zigbuild**
(zig fa da cross-compiler C + linker per glibc — niente Docker):

```bash
rustup target add aarch64-unknown-linux-gnu
cargo install cargo-zigbuild
brew install zig            # oppure scarica il binario da ziglang.org

./deploy/raspberry/cross-build.sh
# produce target/aarch64-unknown-linux-gnu/release/client (glibc 2.31)
scp target/aarch64-unknown-linux-gnu/release/client pi@raspberry:/tmp/p2p-client
ssh pi@raspberry 'sudo install -m0755 /tmp/p2p-client /usr/local/bin/p2p-client'
```

Poi sul Pi esegui login + `--install-service --exit-node` come sopra.

> Il binario è compilato per glibc 2.31, compatibile con Raspberry Pi OS bullseye
> e bookworm. Il binario già pronto è anche in `dist/p2p-client-linux-arm64`.

---

## Dal Mac: usare il Raspberry come exit node (VPN reale)

Compila il client sul Mac con il data plane e scegli l'exit node:

```bash
cargo build --release --features vpn --bin client

# elenca gli exit node online
./target/release/client --list-exits

# instrada TUTTO il traffico attraverso il Raspberry (serve sudo per il TUN/routing)
sudo ./target/release/client --use-exit "raspberry-casa"
```

Il client, appena l'handshake WireGuard è confermato, dirotta automaticamente
tutto il traffico nel tunnel (aggiunge le rotte, pinna l'IP del Raspberry al
gateway attuale, imposta un DNS pubblico) e **ripristina tutto** quando premi
`Ctrl-C`. Con `--no-route` crea solo l'interfaccia TUN e lascia il routing a te.

Verifica che l'uscita sia quella del Raspberry (IP pubblico di casa):

```bash
curl -s https://ifconfig.me
```

---

## File in questa cartella

| File | Cosa fa |
|------|---------|
| `install.sh` | Build nativa sul Pi + installazione del binario. |
| `cross-build.sh` | Cross-compilazione aarch64 dal Mac (Docker + `cross`). |
| `p2p-vpn.service` | Unit systemd di riferimento (di norma generata da `--install-service`). |
