# p2p-holepunch

A Tailscale-inspired system in Rust: a **control plane** with a public IP
(web backoffice + login + signaling) and a **client** that, behind NAT,
authenticates via the browser and establishes a **direct P2P connection** with
another device on the same account through **UDP hole punching**.

Features:

- **Web backoffice** (login/registration) to see and connect your devices;
- **Browser-based client login** (device-code flow, like `tailscale up`): the
  client opens the browser, you approve, and the device stays bound to the account;
- **Accounts and persistence** (SQLite): users, devices, sessions;
- **Automatic full mesh**: online devices are connected all-to-all via hole punching;
- **Exit node** (VPN data plane, feature `vpn`): route your traffic through
  another device over an encrypted **WireGuard** tunnel.

## Layout

```
Cargo.toml
src/
  lib.rs         # module declarations + protocol re-export
  proto.rs       # shared protocol (TCP/UDP JSON messages)
  db.rs          # SQLite storage: users, devices, sessions, device-auth
  web.rs         # web backoffice (axum): login, /devices, mesh, exit node
  vpn.rs         # VPN data plane (feature `vpn`): TUN + WireGuard forwarding
  bin/server.rs  # control plane: HTTP + TCP signaling + UDP (runs on the VPS)
  bin/client.rs  # CLI client for devices (browser login + hole punch)
client-tauri/    # desktop client (Tauri): same logic, UI in HTML/JS
EXIT-NODE.md     # runbook for the VPN data plane (exit node)
```

The library is split by feature: the control plane (axum + SQLite) is behind the
`server` feature (on by default); the VPN data plane (TUN) is behind the `vpn`
feature. Clients depend on the library with `default-features = false` and get
**only the `proto` module**, without pulling in SQLite/axum.

## Two interchangeable clients

Same protocol, same server — you can even connect a CLI client to a Tauri one.

- **CLI** (`src/bin/client.rs`) — terminal, a single native binary.
- **Desktop / Tauri** (`client-tauri/`) — windowed app, UI in HTML/JS and
  networking in Rust. See [`client-tauri/README.md`](client-tauri/README.md).

Three services in the same `server` process:

| Service | Default port | Role |
|---------|--------------|------|
| HTTP    | `8080`       | web backoffice + device-code flow API |
| TCP     | `47100`      | signaling (the client authenticates with its `auth_key`) |
| UDP     | `47101`      | learns the public UDP endpoint for hole punching |

## Build

```bash
cargo build --release
# binaries in target/release/server  and  target/release/client
```

## How it works (the "Tailscale-like" flow)

1. Register/sign in to the **backoffice** (`http://<server>:8080`).
2. On a device, start the **client**: it opens the browser on the approval page.
   Approve → the device gets a persistent identity (`device_id` + `auth_key`),
   saved to `~/.p2p-holepunch/config.json`.
3. Repeat on every device you want to add to the account.
4. **Automatic mesh:** as soon as a device is online and publishes its UDP
   endpoint, the server connects it **all-to-all** with the account's other
   online devices (hole punching). No manual action needed.
5. **Exit node (optional):** in the backoffice you can mark one or more devices
   as *available as an exit node*. This availability is advertised to the
   others, which can then select one from the client.

> ⚠️ The VPN tunnel is **WireGuard-encrypted** (crypto verified by unit tests)
> and the control plane assigns virtual IPs (IPAM); actually routing traffic,
> however, requires the **TUN** interface (root privileges) and must be tested on
> a real host. See [`EXIT-NODE.md`](EXIT-NODE.md).

## Local test (single machine)

```bash
# 1) Server (control plane)
cargo run --bin server
# Backoffice on http://127.0.0.1:8080

# 2) Open http://127.0.0.1:8080 in the browser and REGISTER.

# 3) First client (opens the browser to approve)
cargo run --bin client -- "laptop"

# 4) More clients (as many as you want)
cargo run --bin client -- "phone"
cargo run --bin client -- "home-nas"

# The devices connect on their own (mesh). Each client terminal shows, per peer:
#    [Mesh] Peer '...' @ ... → hole punching
#    ✅ Connessione P2P diretta stabilita ...
#
# (Optional) In the backoffice -> Devices you can mark a device as an exit node:
# it shows up as "[disponibile come exit node]" in the other clients' logs.
```

> Note: on the same machine clients share `~/.p2p-holepunch/config.json`. To run
> more than one locally, use different `HOME`s, e.g.
> `HOME=/tmp/h1 P2P_HTTP_PORT=8091 cargo run --bin client`.

> Locally there is no NAT, so the "hole" is trivial: it just validates the whole
> chain (login, accounts, signaling) before going to the VPS.
>
> Default ports are **8080/tcp** (backoffice), **47100/tcp** (signaling) and
> **47101/udp**. If 8080 is taken, start with
> `HTTP_PORT=8091 PUBLIC_URL=http://127.0.0.1:8091 cargo run --bin server` and the
> client with `P2P_HTTP_PORT=8091`.

### Environment variables

**Server:** `DB_PATH` (default `data.db`), `HTTP_PORT` (default `8080`),
`PUBLIC_URL` (default `http://127.0.0.1:<HTTP_PORT>`, used in the device-code
flow links — in production set the public URL).

**Client:** `P2P_SERVER` (server IP/host), `P2P_HTTP_PORT`, `P2P_TCP_PORT`,
`P2P_UDP_PORT`. Alternatively edit the constants at the top of `src/bin/client.rs`.

Handy client commands:

```bash
client                 # login (if needed) + wait for connection
client "Device name"   # set the device name at first login
client --use-exit NAME # route traffic through exit node NAME (needs feature vpn)
client --exit-node     # act as an exit node for the others (needs feature vpn)
client --reset         # delete the local config (re-run the login)
```

## Deploy on a DigitalOcean VPS

1. Point the client at the droplet's public IP: constant `SERVER_IP` in
   `src/bin/client.rs`, or `P2P_SERVER=<ip>` at runtime.
2. Rebuild the client for your devices.
3. Open the firewall ports (e.g. `ufw`):
   ```bash
   sudo ufw allow 8080/tcp    # web backoffice
   sudo ufw allow 47100/tcp   # signaling
   sudo ufw allow 47101/udp   # hole punching
   ```
4. Start the server (under `systemd` / `tmux`), setting the public URL:
   ```bash
   PUBLIC_URL=http://<ip-or-domain>:8080 ./server
   ```
5. Register in the backoffice, then start the client on each device.

> In production put the backoffice **behind HTTPS** (nginx/caddy reverse proxy):
> passwords and session cookies travel in clear text on 8080.

## Known limitations (next steps)

- **Plain HTTP:** the backoffice does not do TLS. In production put it behind an
  HTTPS reverse proxy (nginx/caddy) with `PUBLIC_URL=https://...`.
- **Exit node — routing to validate:** the tunnel is **WireGuard-encrypted**
  (crypto verified by unit tests) and the control plane assigns virtual IPs
  (IPAM); actually routing traffic requires the **TUN** interface (root) and must
  be tested on a real host. See [`EXIT-NODE.md`](EXIT-NODE.md).
- **Symmetric NAT:** it can remap ports unpredictably; in that case direct hole
  punching fails and a server **relay** (DERP-style) is needed — not present yet.
- **Mesh demo traffic:** outside the exit-node tunnel, the mesh currently just
  exchanges PING datagrams to prove the direct path; it is not an encrypted
  general-purpose data channel yet.
```
