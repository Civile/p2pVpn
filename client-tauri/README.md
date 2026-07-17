# Desktop client (Tauri)

Desktop app for the P2P client. **UI in HTML/JS**, **networking in Rust** (reuses
the `p2p_holepunch::proto` protocol). Browser login (device-code flow), TCP
signaling and UDP hole punching — exactly like the CLI client but with a GUI and
real-time events.

```
client-tauri/
  src/               # static frontend (no bundler, no npm)
    index.html
    main.js
  src-tauri/
    Cargo.toml       # depends on ../.. (only `proto`, default-features = false)
    tauri.conf.json
    src/lib.rs       # commands: get_state, login_start, login_wait, connect, logout, list_exits, use_exit
    src/main.rs
    capabilities/    # Tauri v2 permissions
    icons/
```

## Prerequisites

- Rust (already installed).
- macOS: the Xcode command line tools (`xcode-select --install`). The webview
  uses the system **WKWebView**: no Chromium to download.
- (Only to build installers) the Tauri CLI:
  `cargo install tauri-cli --version '^2'`.

## Running in development

The server must be running and you must have registered in the backoffice.

```bash
cd client-tauri/src-tauri

# If the server runs on the default ports:
cargo run

# Locally, with the backoffice on 8091 (because 8080 is taken):
P2P_SERVER=127.0.0.1 P2P_HTTP_PORT=8091 cargo run
```

The app window opens. On first run:

1. Enter the **device name** and press *Accedi via browser* → the browser opens
   on the backoffice approval page.
2. Approve: the app receives the identity and moves to the main screen.
3. Press **Connetti**. The device joins the account's mesh automatically and
   connects to the other online devices (hole punching).
4. The app log shows `✅ Connessione P2P diretta stabilita` for each peer.
5. If an exit node is available, pick it from the dropdown and press *Usa exit node*.

## Environment variables

Like the CLI client: `P2P_SERVER`, `P2P_HTTP_PORT` (default 8080), `P2P_TCP_PORT`
(47100), `P2P_UDP_PORT` (47101). The config is saved to
`~/.p2p-holepunch/config.json` (same as the CLI client).

## Building installers (.app / .dmg / .exe / .deb)

```bash
cd client-tauri/src-tauri
cargo tauri build
# output in target/release/bundle/
```

> To distribute it without security warnings it must be **signed**: Apple
> notarization on macOS, a code-signing certificate on Windows. It still runs
> unsigned, but the user sees the OS warning on first launch.

## Notes

- **Two clients on the same machine** share the same config
  (`~/.p2p-holepunch/config.json`). To test two peers locally, use one Tauri
  client and one CLI client with a different `HOME`, or two separate `HOME`s.
- The Tauri client and the CLI client are **interchangeable**: same protocol,
  same server. You can connect a Tauri one to a CLI one without issues.
- No `npm` needed: the frontend is static and uses `withGlobalTauri`
  (`window.__TAURI__`). `cargo run` embeds `src/` at compile time.
```
