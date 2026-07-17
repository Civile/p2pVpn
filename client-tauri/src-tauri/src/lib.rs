//! Core Rust del client desktop (Tauri v2).
//!
//! Il frontend (HTML/JS) chiama i comandi qui sotto via `invoke` e riceve gli
//! aggiornamenti tramite gli eventi `log` e `status`. Tutta la rete
//! (device-code login, segnalazione TCP, hole punching UDP) vive qui, riusando
//! il protocollo condiviso `p2p_holepunch::proto`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::async_runtime::JoinHandle;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::time::{interval, sleep};

use p2p_holepunch::{ClientMessage, ServerMessage, UdpMessage};

/// Canale verso il writer TCP (per inviare messaggi dopo la connessione).
static OUTBOUND: Mutex<Option<UnboundedSender<ClientMessage>>> = Mutex::new(None);
/// Exit node disponibili appresi dalla mesh: (nome, device_id).
static EXIT_PEERS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

// Default sovrascrivibili via variabili d'ambiente (come il client CLI).
const DEFAULT_SERVER: &str = "127.0.0.1";
const HTTP_PORT: u16 = 8080;
const TCP_PORT: u16 = 47100;
const UDP_PORT: u16 = 47101;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
fn port(key: &str, default: u16) -> u16 {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}
fn server_host() -> String {
    env_or("P2P_SERVER", DEFAULT_SERVER)
}

/// Identità persistente del dispositivo (stessa posizione del client CLI).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    device_id: String,
    auth_key: String,
    name: String,
}

fn config_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".p2p-holepunch").join("config.json")
}
fn load_config() -> Option<Config> {
    serde_json::from_str(&std::fs::read_to_string(config_path()).ok()?).ok()
}
fn save_config(cfg: &Config) -> std::io::Result<()> {
    let path = config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(cfg)?)
}

// -------------------------------------------------------------- comandi ---

#[derive(Serialize)]
struct StateInfo {
    logged_in: bool,
    name: Option<String>,
}

/// Stato all'avvio: c'è già una config salvata?
#[tauri::command]
fn get_state() -> StateInfo {
    match load_config() {
        Some(c) => StateInfo { logged_in: true, name: Some(c.name) },
        None => StateInfo { logged_in: false, name: None },
    }
}

/// Rimuove l'identità locale (rifà il login al prossimo accesso).
#[tauri::command]
fn logout() -> Result<(), String> {
    let _ = std::fs::remove_file(config_path());
    Ok(())
}

#[derive(Serialize)]
struct StartInfo {
    code: String,
    url: String,
}

/// Passo 1 del login: chiede un codice al server e apre il browser.
#[tauri::command]
async fn login_start(name: String) -> Result<StartInfo, String> {
    let http = format!("{}:{}", server_host(), port("P2P_HTTP_PORT", HTTP_PORT));
    let name = if name.trim().is_empty() { "dispositivo".to_string() } else { name };
    let body = serde_json::json!({ "name": name }).to_string();
    let resp = http_request(&http, "POST", "/api/device/start", Some(&body))
        .await
        .map_err(|e| format!("connessione al server fallita: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&resp).map_err(|e| format!("risposta non valida: {e} — {resp}"))?;
    let code = v["code"].as_str().ok_or("manca 'code'")?.to_string();
    let url = v["verification_url"].as_str().ok_or("manca 'verification_url'")?.to_string();
    open_browser(&url);
    Ok(StartInfo { code, url })
}

/// Passo 2 del login: attende (polling) che l'utente approvi dal browser,
/// poi salva la config e ritorna il nome del dispositivo.
#[tauri::command]
async fn login_wait(code: String) -> Result<String, String> {
    let http = format!("{}:{}", server_host(), port("P2P_HTTP_PORT", HTTP_PORT));
    let path = format!("/api/device/poll?code={code}");
    loop {
        sleep(Duration::from_secs(2)).await;
        let resp = match http_request(&http, "GET", &path, None).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(&resp) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(err) = v["error"].as_str() {
            return Err(format!("codice rifiutato dal server: {err}"));
        }
        if v["approved"].as_bool() == Some(true) {
            let cfg = Config {
                device_id: v["device_id"].as_str().unwrap_or_default().to_string(),
                auth_key: v["auth_key"].as_str().unwrap_or_default().to_string(),
                name: v["name"].as_str().unwrap_or("dispositivo").to_string(),
            };
            save_config(&cfg).map_err(|e| e.to_string())?;
            return Ok(cfg.name);
        }
    }
}

/// Avvia la segnalazione in background. Gli aggiornamenti arrivano al frontend
/// via eventi `log`/`status`. Ritorna subito.
#[tauri::command]
async fn connect(app: AppHandle) -> Result<(), String> {
    let cfg = load_config().ok_or("dispositivo non autenticato")?;
    tauri::async_runtime::spawn(async move {
        if let Err(e) = run_signaling(app.clone(), cfg).await {
            let _ = app.emit("log", format!("Errore: {e}"));
            let _ = app.emit("status", "error");
        }
    });
    Ok(())
}

/// Elenco dei nomi degli exit node disponibili (per il selettore in UI).
#[tauri::command]
fn list_exits() -> Vec<String> {
    EXIT_PEERS.lock().unwrap().iter().map(|(n, _)| n.clone()).collect()
}

/// Sceglie (o annulla, con `name` vuoto) l'exit node attraverso cui uscire.
#[tauri::command]
fn use_exit(name: String) -> Result<(), String> {
    let exit_device_id = if name.is_empty() {
        None
    } else {
        let id = EXIT_PEERS
            .lock()
            .unwrap()
            .iter()
            .find(|(n, _)| n == &name)
            .map(|(_, id)| id.clone());
        match id {
            Some(id) => Some(id),
            None => return Err("exit node non trovato".into()),
        }
    };
    let tx = OUTBOUND.lock().unwrap().clone();
    match tx {
        Some(tx) => tx
            .send(ClientMessage::UseExitNode { exit_device_id })
            .map_err(|_| "non connesso".to_string()),
        None => Err("non connesso: premi prima Connetti".to_string()),
    }
}

// --------------------------------------------------------- rete / logica ---

async fn run_signaling(app: AppHandle, cfg: Config) -> Result<(), String> {
    let host = server_host();
    let server_tcp = resolve(&host, port("P2P_TCP_PORT", TCP_PORT)).await.map_err(|e| e.to_string())?;
    let server_udp = resolve(&host, port("P2P_UDP_PORT", UDP_PORT)).await.map_err(|e| e.to_string())?;

    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?);
    let _ = app.emit("status", "connecting");
    let _ = app.emit("log", format!("Socket UDP locale su {}", udp.local_addr().unwrap()));

    EXIT_PEERS.lock().unwrap().clear();

    // TCP + autenticazione con auth_key.
    let tcp = TcpStream::connect(server_tcp).await.map_err(|e| e.to_string())?;
    let (read_half, mut write_half) = tcp.into_split();
    let mut lines = BufReader::new(read_half).lines();

    // Writer task: invia i ClientMessage (Register, UseExitNode…) sul canale TCP.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ClientMessage>();
    *OUTBOUND.lock().unwrap() = Some(out_tx.clone());
    tauri::async_runtime::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let mut d = serde_json::to_vec(&msg).unwrap_or_default();
            d.push(b'\n');
            if write_half.write_all(&d).await.is_err() {
                break;
            }
        }
    });
    let _ = out_tx.send(ClientMessage::Register { auth_key: cfg.auth_key.clone(), wg_public: None });
    let _ = app.emit("log", "Autenticazione inviata.".to_string());

    // Keepalive UDP: pubblica e mantiene fresco il nostro endpoint (per la mesh).
    {
        let udp = udp.clone();
        let device_id = cfg.device_id.clone();
        tauri::async_runtime::spawn(async move {
            let payload = serde_json::to_vec(&UdpMessage::UdpRegister { device_id }).unwrap();
            loop {
                let _ = udp.send_to(&payload, server_udp).await;
                sleep(Duration::from_secs(3)).await;
            }
        });
    }

    // Ricevitore unico dei pacchetti da tutti i peer.
    spawn_receiver(app.clone(), udp.clone(), server_udp);

    let _ = app.emit("log", "In attesa dei peer dell'account (mesh)…".to_string());

    // Un sender per ogni peer della mesh, indicizzato per device_id.
    let mut senders: HashMap<String, (SocketAddr, JoinHandle<()>)> = HashMap::new();
    loop {
        let line = match lines.next_line().await.map_err(|e| e.to_string())? {
            Some(l) => l,
            None => return Err("il server ha chiuso la connessione".to_string()),
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ServerMessage>(&line).map_err(|e| e.to_string())? {
            ServerMessage::Registered { info, .. } => {
                let _ = app.emit("status", "registered");
                let _ = app.emit("log", info);
            }
            ServerMessage::Waiting => {
                let _ = app.emit("log", "Registrato. In attesa di peer…".to_string());
            }
            ServerMessage::Error { message } => return Err(message),
            ServerMessage::PeerInfo { peer_id, peer_name, peer_addr, is_exit_node, .. } => {
                if senders.get(&peer_id).map(|(a, _)| *a) != Some(peer_addr) {
                    if let Some((_, old)) = senders.remove(&peer_id) {
                        old.abort();
                    }
                    let _ = app.emit("status", "punching");
                    let tag = if is_exit_node { " [exit node]" } else { "" };
                    let _ = app.emit(
                        "log",
                        format!("Peer '{peer_name}'{tag} @ {peer_addr} → hole punching"),
                    );
                    let handle = spawn_sender(udp.clone(), peer_addr);
                    senders.insert(peer_id.clone(), (peer_addr, handle));
                }
                // Aggiorna l'elenco degli exit node disponibili per il selettore.
                if is_exit_node {
                    let mut list = EXIT_PEERS.lock().unwrap();
                    if !list.iter().any(|(_, id)| id == &peer_id) {
                        list.push((peer_name.clone(), peer_id.clone()));
                    }
                    let names: Vec<String> = list.iter().map(|(n, _)| n.clone()).collect();
                    drop(list);
                    let _ = app.emit("exit_nodes", names);
                }
            }
            ServerMessage::PeerGone { peer_id } => {
                if let Some((addr, h)) = senders.remove(&peer_id) {
                    h.abort();
                    let _ = app.emit("log", format!("Peer '{peer_id}' offline ({addr})"));
                }
            }
            ServerMessage::ExitNodeSet { ok, message, .. } => {
                let _ = app.emit("log", format!("[exit node] {message}"));
                let _ = ok;
            }
        }
    }
}

/// Invia PING periodici verso un peer (apre il NAT locale).
fn spawn_sender(udp: Arc<UdpSocket>, peer_addr: SocketAddr) -> JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let mut ticker = interval(Duration::from_millis(500));
        let mut n: u64 = 0;
        loop {
            ticker.tick().await;
            n += 1;
            let msg = format!("PING #{n} (hole-punch)");
            if udp.send_to(msg.as_bytes(), peer_addr).await.is_err() {
                break;
            }
        }
    })
}

/// Ricevitore unico del socket UDP: emette gli eventi dei pacchetti dai peer,
/// ignorando quelli del server. Segnala il primo contatto con ogni peer.
fn spawn_receiver(app: AppHandle, udp: Arc<UdpSocket>, server_udp: SocketAddr) -> JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut established: HashSet<IpAddr> = HashSet::new();
        loop {
            let (n, src) = match udp.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if src == server_udp {
                continue;
            }
            let text = String::from_utf8_lossy(&buf[..n]);
            if established.insert(src.ip()) {
                let _ = app.emit("status", "connected");
                let _ = app.emit("log", format!("✅ Connessione P2P diretta stabilita con {src}!"));
            }
            let _ = app.emit("log", format!("<< da {src}: {}", text.trim()));
        }
    })
}

// ----------------------------------------------------------- utilità ---

async fn resolve(host: &str, p: u16) -> std::io::Result<SocketAddr> {
    tokio::net::lookup_host((host, p))
        .await?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "host non risolto"))
}

/// HTTP/1.1 in chiaro verso il backoffice (nessun TLS: solo il nostro server).
async fn http_request(
    host_port: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(host_port).await?;
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw);
    Ok(match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => text.into_owned(),
    })
}

/// Apre l'URL nel browser di sistema (best effort).
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let cmd: (&str, Vec<&str>) = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let cmd: (&str, Vec<&str>) = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let cmd: (&str, Vec<&str>) = ("xdg-open", vec![url]);

    let _ = std::process::Command::new(cmd.0).args(cmd.1).spawn();
}

// ------------------------------------------------------------- avvio ---

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_state,
            logout,
            login_start,
            login_wait,
            connect,
            list_exits,
            use_exit
        ])
        .run(tauri::generate_context!())
        .expect("errore nell'avvio dell'app Tauri");
}
