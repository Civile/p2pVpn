//! Core Rust del client desktop (Tauri v2) — pannello di controllo VPN.
//!
//! La GUI **non** fa da sola il data plane: pilota l'eseguibile CLI
//! (`p2p-client`, bundlato nell'app come resource), che è l'unico a creare il
//! tunnel cifrato e a instradare il traffico. Motivo: il server tiene **una
//! sola** connessione per identità, quindi non possiamo avere GUI e tunnel
//! connessi insieme — la GUI apre una connessione alla volta, tramite la CLI.
//!
//! Flusso:
//! - **Login**: device-code via browser (come prima), salva l'identità condivisa.
//! - **Elenco exit**: `p2p-client --list-exits` (connessione breve, poi esce).
//! - **VPN On**: lancia `sudo p2p-client --use-exit <nome>` con un prompt di
//!   amministratore (macOS lo impone per creare il TUN e cambiare il routing).
//! - **VPN Off**: manda SIGINT alla CLI, che ripristina il routing ed esce.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

// Percorsi dei file di lavoro del tunnel (log/PID e script per il prompt admin).
const LOG_PATH: &str = "/tmp/p2p-vpn.log";
const PID_PATH: &str = "/tmp/p2p-vpn.pid";
const START_SCRIPT: &str = "/tmp/p2p-vpn-start.sh";
const STOP_SCRIPT: &str = "/tmp/p2p-vpn-stop.sh";

// Default sovrascrivibili via variabili d'ambiente (come il client CLI).
const DEFAULT_SERVER: &str = "abc.edoardocasella.it";
const HTTP_PORT: u16 = 443;

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

// -------------------------------------------------------------- login ---

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

// --------------------------------------------------------- controllo VPN ---

/// Percorso dell'eseguibile CLI `p2p-client`: prima come resource bundlata
/// nell'app, poi override via env, poi installazione di sistema.
fn cli_path(app: &AppHandle) -> PathBuf {
    use tauri::Manager;
    if let Ok(p) = app.path().resolve("bin/p2p-client", tauri::path::BaseDirectory::Resource) {
        if p.exists() {
            ensure_executable(&p);
            return p;
        }
    }
    if let Ok(p) = std::env::var("P2P_CLI") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return pb;
        }
    }
    let common = PathBuf::from("/usr/local/bin/p2p-client");
    if common.exists() {
        return common;
    }
    PathBuf::from("p2p-client")
}

/// Elenca gli exit node disponibili eseguendo `p2p-client --list-exits`.
/// Richiede di essere già loggati (la GUI lo garantisce mostrando prima il login).
#[tauri::command]
async fn vpn_list_exits(app: AppHandle) -> Result<Vec<String>, String> {
    let cli = cli_path(&app).to_string_lossy().to_string();
    let home = std::env::var("HOME").unwrap_or_default();
    tauri::async_runtime::spawn_blocking(move || {
        let out = std::process::Command::new(&cli)
            .arg("--list-exits")
            .env("HOME", &home)
            .output()
            .map_err(|e| format!("impossibile eseguire il client ({cli}): {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Righe tipo "  • raspberry-casa   (id: abc123)".
        let exits: Vec<String> = text
            .lines()
            .filter_map(|l| {
                let rest = l.trim_start().strip_prefix("• ")?;
                let name = rest.split("   (id:").next().unwrap_or(rest).trim();
                (!name.is_empty()).then(|| name.to_string())
            })
            .collect();
        Ok(exits)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Escapa una stringa per inserirla tra apici singoli in uno script sh.
fn sh_squote(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Garantisce il bit di esecuzione sul binario (le resource Tauri talvolta lo
/// perdono nella copia). Best effort, solo su Unix.
fn ensure_executable(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perm = meta.permissions();
            if perm.mode() & 0o111 == 0 {
                perm.set_mode(perm.mode() | 0o755);
                let _ = std::fs::set_permissions(path, perm);
            }
        }
    }
}

/// Accende la VPN: lancia `p2p-client --use-exit <name>` come root (prompt di
/// amministratore), in background, salvando log e PID. Ritorna il PID.
#[tauri::command]
async fn vpn_start(app: AppHandle, name: String) -> Result<u32, String> {
    if name.trim().is_empty() {
        return Err("scegli prima un exit node".into());
    }
    let cli = cli_path(&app).to_string_lossy().to_string();
    let home = std::env::var("HOME").unwrap_or_default();
    // Script eseguito come root: HOME=<utente> per ritrovare l'identità del
    // login, avvia il tunnel in background e salva il PID.
    // `LC_ALL=C` evita l'errore "illegal byte sequence" di pkill/grep su macOS.
    // Prima di avviare, uccide ogni istanza precedente: evita più processi con la
    // stessa identità che si scalzano a vicenda sul server (endpoint instabile).
    let script = format!(
        "#!/bin/sh\nexport LC_ALL=C\npkill -9 -f 'p2p-client --use-exit' 2>/dev/null || true\nsleep 1\nrm -f {pid}\nHOME='{home}' '{cli}' --use-exit '{name}' > {log} 2>&1 &\necho $! > {pid}\n",
        home = sh_squote(&home),
        cli = sh_squote(&cli),
        name = sh_squote(&name),
        log = LOG_PATH,
        pid = PID_PATH,
    );
    tauri::async_runtime::spawn_blocking(move || {
        let _ = std::fs::remove_file(PID_PATH);
        std::fs::write(START_SCRIPT, script).map_err(|e| e.to_string())?;
        let out = std::process::Command::new("osascript")
            .args([
                "-e",
                &format!("do shell script \"/bin/sh {START_SCRIPT}\" with administrator privileges"),
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            // -128 = l'utente ha annullato il prompt password.
            if err.contains("-128") {
                return Err("operazione annullata".into());
            }
            return Err(format!("avvio VPN fallito: {}", err.trim()));
        }
        std::fs::read_to_string(PID_PATH)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .ok_or_else(|| "VPN avviata ma PID non disponibile".to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Spegne la VPN: manda SIGINT alla CLI (che ripristina il routing ed esce).
/// Usa il PID salvato e, come rete di sicurezza, `pkill` sul pattern del comando
/// (così funziona anche se il PID è stantìo).
#[tauri::command]
async fn vpn_stop() -> Result<(), String> {
    let pid = std::fs::read_to_string(PID_PATH)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    // Se non c'è né PID né processo attivo, non serve chiedere la password.
    if pid.is_none() && !any_vpn_process() {
        let _ = std::fs::remove_file(PID_PATH);
        return Ok(());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let kill_pid = pid
            .map(|p| format!("kill {p} 2>/dev/null || true\n"))
            .unwrap_or_default();
        // Usiamo SIGTERM (non SIGINT): un processo avviato in background dalla
        // shell ha SIGINT impostato su IGNORE, quindi `kill -INT` non lo tocca.
        // La CLI gestisce SIGTERM (ripristina il routing ed esce). Dopo 2s, come
        // ultima spiaggia, SIGKILL. `LC_ALL=C` evita l'errore di locale di pkill.
        // Il pidfile è di root: lo rimuoviamo qui dentro (come root).
        let script = format!(
            "#!/bin/sh\nexport LC_ALL=C\n{kill_pid}pkill -f 'p2p-client --use-exit' 2>/dev/null || true\nsleep 2\npkill -9 -f 'p2p-client --use-exit' 2>/dev/null || true\nrm -f {PID_PATH}\nexit 0\n"
        );
        std::fs::write(STOP_SCRIPT, script).map_err(|e| e.to_string())?;
        let out = std::process::Command::new("osascript")
            .args([
                "-e",
                &format!("do shell script \"/bin/sh {STOP_SCRIPT}\" with administrator privileges"),
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            if err.contains("-128") {
                return Err("operazione annullata".into());
            }
            return Err(format!("stop VPN fallito: {}", err.trim()));
        }
        let _ = std::fs::remove_file(PID_PATH);
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// `true` se esiste un processo del tunnel VPN in esecuzione (fallback per lo stato).
fn any_vpn_process() -> bool {
    std::process::Command::new("pgrep")
        .args(["-f", "p2p-client --use-exit"])
        .env("LC_ALL", "C")
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

#[derive(Serialize)]
struct VpnStatus {
    running: bool,
    log: String,
}

/// Stato del tunnel: la CLI è ancora viva? + ultime righe di log per la UI.
#[tauri::command]
async fn vpn_status() -> VpnStatus {
    tauri::async_runtime::spawn_blocking(|| {
        let pid = std::fs::read_to_string(PID_PATH)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        let running = pid.map(process_alive).unwrap_or(false) || any_vpn_process();
        VpnStatus { running, log: tail_file(LOG_PATH, 60) }
    })
    .await
    .unwrap_or(VpnStatus { running: false, log: String::new() })
}

/// `true` se il processo con quel PID è ancora attivo (anche se è di root).
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string()])
        .env("LC_ALL", "C")
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).lines().count() > 1)
        .unwrap_or(false)
}

/// Ultime `n` righe di un file di testo (best effort).
fn tail_file(path: &str, n: usize) -> String {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

// ----------------------------------------------------------- utilità ---

/// HTTP/1.1 verso il backoffice. Se la porta è 443 usa TLS (produzione dietro
/// nginx/HTTPS), altrimenti va in chiaro (dev locale). Usato solo al login.
async fn http_request(
    host_port: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> std::io::Result<String> {
    let body = body.unwrap_or("");
    // Host header e SNI senza la porta.
    let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let tcp = TcpStream::connect(host_port).await?;
    let raw = if host_port.ends_with(":443") {
        let connector = tokio_native_tls::native_tls::TlsConnector::new()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let mut stream = tokio_native_tls::TlsConnector::from(connector)
            .connect(host, tcp)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        stream.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        raw
    } else {
        let mut stream = tcp;
        stream.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        raw
    };
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
            vpn_list_exits,
            vpn_start,
            vpn_stop,
            vpn_status
        ])
        .run(tauri::generate_context!())
        .expect("errore nell'avvio dell'app Tauri");
}
