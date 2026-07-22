#!/usr/bin/env bash
#
# Installa il client P2P VPN su un Raspberry Pi (Debian / Raspberry Pi OS 64-bit,
# es. Raspberry Pi 500 = aarch64). Da eseguire SUL Raspberry: compila nativamente
# il binario con il data plane (`--features vpn`), lo installa in
# /usr/local/bin/p2p-client e stampa i passi per login + "connetti all'avvio".
#
# Uso:
#   ./deploy/raspberry/install.sh            # build + install
#   ./deploy/raspberry/install.sh --login    # ... e poi avvia subito il login
#
set -euo pipefail

# Radice del repo (due livelli sopra questo script).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_NAME="p2p-client"
DEST="/usr/local/bin/$BIN_NAME"
SERVICE_HINT="p2p-vpn"   # nome del servizio systemd creato da --install-service

echo "==> Repo: $REPO_ROOT"
echo "==> Architettura: $(uname -m)  ·  $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-sconosciuta}")"

# --- 1) Dipendenze di sistema -----------------------------------------------
# build-essential + pkg-config + libssl-dev servono a native-tls (login HTTPS);
# iptables serve all'exit node per il NAT masquerade.
if command -v apt-get >/dev/null 2>&1; then
  echo "==> Installo le dipendenze di sistema (sudo apt-get)…"
  sudo apt-get update -y
  sudo apt-get install -y build-essential pkg-config libssl-dev iptables curl ca-certificates
else
  echo "!! apt-get non trovato: installa a mano build-essential, pkg-config, libssl-dev, iptables."
fi

# --- 2) Toolchain Rust ------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  echo "==> Rust non presente: installo rustup…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi
echo "==> $(cargo --version)"

# --- 3) Build del client con il data plane VPN ------------------------------
echo "==> Compilo il client (release, --features vpn). Sul Pi può richiedere qualche minuto…"
cd "$REPO_ROOT"
cargo build --release --features vpn --bin client

# --- 4) Installazione del binario -------------------------------------------
echo "==> Installo il binario in $DEST (sudo)…"
sudo install -m 0755 "$REPO_ROOT/target/release/client" "$DEST"
echo "==> Installato: $($DEST --help | head -1)"

cat <<EOF

============================================================================
 ✅ Client installato come:  $BIN_NAME
============================================================================

Passi successivi (una volta sola):

  1) LOGIN del dispositivo (interattivo, apre/mostra un link da approvare nel
     backoffice https://abc.edoardocasella.it):

       $BIN_NAME "raspberry-casa"

     Approva il dispositivo dal browser, poi Ctrl-C.

  2) Marca il dispositivo come EXIT NODE nel backoffice
     (Devices → Rendi exit node).

  3) CONNETTI ALL'AVVIO come exit node (servizio systemd, parte a ogni boot):

       sudo $BIN_NAME --install-service --exit-node

     Verifica:   systemctl status $SERVICE_HINT
     Log dal vivo: journalctl -u $SERVICE_HINT -f

  Per disattivare l'avvio automatico:  sudo $BIN_NAME --uninstall-service

Dal tuo Mac, per uscire da Internet attraverso questo Raspberry:

       sudo $BIN_NAME --use-exit "raspberry-casa"      # (build con --features vpn)

============================================================================
EOF

if [[ "${1:-}" == "--login" ]]; then
  echo "==> Avvio il login adesso…"
  exec "$DEST" "raspberry-casa"
fi
