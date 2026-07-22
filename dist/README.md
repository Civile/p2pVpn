# P2P VPN — pacchetti pronti

## Mac — app grafica (consigliata)

| File | Cosa fare |
|------|-----------|
| `P2P-VPN-macos-arm64.dmg` | Doppio click → trascina **P2P VPN** in Applicazioni |
| `P2P VPN.app` | La stessa app, già pronta (puoi lanciarla direttamente) |

Dentro l'app fai tutto:
1. **Accedi** (si apre il browser, approvi il dispositivo — stesso account del Raspberry).
2. Scegli l'**exit node** dal menù a tendina (es. `raspberry-casa`).
3. Premi **Attiva VPN** → inserisci la password del Mac quando richiesto.
   Tutto il traffico esce dall'exit node. Premi **Disattiva VPN** per spegnere.

> ⚠️ **Prima apertura (Gatekeeper).** L'app non è firmata da un account Apple
> Developer. Se macOS dice "impossibile aprire perché lo sviluppatore non può
> essere verificato": **click destro sull'app → Apri → Apri**. Va fatto una volta sola.
> (Da riga di comando: `xattr -dr com.apple.quarantine "P2P VPN.app"`.)

> ⚠️ **La password all'On/Off** è necessaria: macOS la richiede per creare
> l'interfaccia di rete e instradare il traffico. È il comportamento previsto.

L'app usa internamente l'eseguibile `p2p-client` (già incluso). Se preferisci la
riga di comando, trovi comunque il binario qui sotto.

## Mac — riga di comando (alternativa)

| File | Piattaforma |
|------|-------------|
| `p2p-client-macos-arm64` | macOS Apple Silicon |

```bash
sudo ./p2p-client-macos-arm64 --use-exit "raspberry-casa"   # Ctrl-C per spegnere
```

## Raspberry Pi 500 — exit node (riga di comando)

| File | Piattaforma |
|------|-------------|
| `p2p-client-linux-arm64` | Linux aarch64 (glibc ≥ 2.31 → Pi OS bullseye/bookworm) |

```bash
sudo install -m0755 p2p-client-linux-arm64 /usr/local/bin/p2p-client
p2p-client "raspberry-casa"                     # login, poi marca "exit node" nel backoffice
sudo p2p-client --install-service --exit-node   # connetti all'avvio (systemd)
```

Verifica exit node: `systemctl status p2p-vpn` · `journalctl -u p2p-vpn -f`.

---

Verifica che la VPN funzioni (dal Mac, mentre è attiva):
```bash
curl -s https://ifconfig.me     # deve mostrare l'IP del Raspberry (casa tua)
```
