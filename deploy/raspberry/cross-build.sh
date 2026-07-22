#!/usr/bin/env bash
#
# Cross-compila il client per Raspberry Pi 500 (aarch64 Linux, glibc) da macOS,
# SENZA compilare sul Pi e SENZA Docker. Usa cargo-zigbuild: zig fa da
# cross-compiler C (per ring/openssl vendored) e da linker per glibc.
#
#   - Raspberry Pi 500 → CPU ARM Cortex-A76 a 64 bit → target
#     `aarch64-unknown-linux-gnu` (Raspberry Pi OS / Debian a 64 bit).
#   - Miriamo a glibc 2.31 → compatibile con Pi OS bullseye (2.31) e bookworm (2.36).
#
# Prerequisiti (una volta sola):
#   rustup target add aarch64-unknown-linux-gnu
#   cargo install cargo-zigbuild
#   # zig: `brew install zig` OPPURE scarica il binario ufficiale da ziglang.org
#   # (brew può voler ricompilare LLVM: più veloce il tarball precompilato)
#
# Uso (dalla radice del repo):
#   ./deploy/raspberry/cross-build.sh
# Output: target/aarch64-unknown-linux-gnu/release/client
#
set -euo pipefail
TARGET="aarch64-unknown-linux-gnu.2.31"
OUT="target/aarch64-unknown-linux-gnu/release/client"

command -v zig >/dev/null 2>&1 || { echo "!! 'zig' non trovato sul PATH. Installa zig (ziglang.org) e riprova." >&2; exit 1; }
command -v cargo-zigbuild >/dev/null 2>&1 || { echo "==> installo cargo-zigbuild…"; cargo install cargo-zigbuild; }
rustup target list --installed | grep -q '^aarch64-unknown-linux-gnu$' || rustup target add aarch64-unknown-linux-gnu

echo "==> Cross-compilo per $TARGET (--features vpn) con zig $(zig version)…"
cargo zigbuild --release --target "$TARGET" --features vpn --bin client

echo "==> Fatto: $OUT"
file "$OUT" 2>/dev/null || true
echo
echo "Verifica glibc (max deve essere <= 2.31):"
strings "$OUT" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -u | tail -5 || true
echo
echo "Copia sul Raspberry e installa il servizio:"
echo "  scp $OUT pi@raspberry:/tmp/p2p-client"
echo "  ssh pi@raspberry 'sudo install -m0755 /tmp/p2p-client /usr/local/bin/p2p-client'"
echo "  ssh pi@raspberry 'sudo p2p-client --install-service --exit-node'   # dopo il login"
