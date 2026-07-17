//! # Client P2P con login via browser + UDP hole punching
//!
//! Flusso "alla Tailscale":
//!
//! 1. **Primo avvio (login):** il client chiede al server un codice, apre il
//!    **browser** su una pagina del backoffice, tu ti autentichi e approvi.
//!    Il client, facendo polling, riceve la sua identità persistente
//!    (`device_id` + `auth_key`) e la salva in `~/.p2p-holepunch/config.json`.
//! 2. **Avvii successivi:** riusa la `auth_key` salvata, senza browser.
//! 3. **Segnalazione:** si connette in TCP e si autentica con la `auth_key`;
//!    pubblica via UDP il proprio endpoint pubblico.
//! 4. **Collegamento:** quando dal backoffice colleghi questo dispositivo a un
//!    altro, il server invia `PeerInfo` e parte l'**UDP hole punching** diretto.
//!
//! Uso:
//!   client                 # login (se serve) + attesa collegamento
//!   client "Nome device"   # come sopra, impostando il nome del dispositivo
//!   client --reset         # cancella la config locale (rifà il login)

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep};

use p2p_holepunch::{ClientMessage, ServerMessage, UdpMessage};

// ============================================================================
//  CONFIGURAZIONE — >>> INSERISCI QUI L'IP DEL TUO SERVER <<<
// ============================================================================
// In test locale lascia "127.0.0.1". In produzione: l'IP pubblico del droplet.
// Tutto sovrascrivibile a runtime via variabili d'ambiente:
//   P2P_SERVER, P2P_HTTP_PORT, P2P_TCP_PORT, P2P_UDP_PORT.
const SERVER_IP: &str = "127.0.0.1";
const HTTP_PORT: u16 = 8080; // backoffice web (device-code flow)
const TCP_PORT: u16 = 47100; // segnalazione
const UDP_PORT: u16 = 47101; // hole punching
// ============================================================================

/// Legge una porta da env con fallback al default compilato.
fn port(env: &str, default: u16) -> u16 {
    std::env::var(env).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

/// Identità persistente del dispositivo, salvata su disco dopo il login.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    device_id: String,
    auth_key: String,
    name: String,
    /// IP virtuale (IPAM) assegnato dal server, es. `10.7.0.2`.
    #[serde(default)]
    vip: Option<String>,
    /// Chiavi WireGuard (base64), generate al primo avvio con la feature `vpn`.
    #[serde(default)]
    wg_private: Option<String>,
    #[serde(default)]
    wg_public: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let server_ip = std::env::var("P2P_SERVER").unwrap_or_else(|_| SERVER_IP.to_string());

    if args.iter().any(|a| a == "--reset") {
        let path = config_path();
        let _ = std::fs::remove_file(&path);
        println!("[Client] Config rimossa: {}", path.display());
        return Ok(());
    }

    // Parsing argomenti:
    //   [nome]              nome del dispositivo (al primo login)
    //   --use-exit <nome>   instrada il traffico attraverso l'exit node <nome>
    //   --exit-node         fai da exit node per gli altri dispositivi
    let be_exit = args.iter().any(|a| a == "--exit-node");
    let mut desired_exit: Option<String> = None;
    let mut device_name: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--use-exit" => desired_exit = it.next().cloned(),
            s if s.starts_with("--") => {}
            s if device_name.is_none() => device_name = Some(s.to_string()),
            _ => {}
        }
    }
    if be_exit {
        println!("[Client] Modalità EXIT NODE attiva (il data plane richiede la feature `vpn` e privilegi root).");
    }
    if let Some(ref e) = desired_exit {
        println!("[Client] Instraderò il traffico tramite l'exit node '{e}' quando sarà online.");
    }

    // 1) Carica la config; se manca, esegui il login via browser.
    #[cfg_attr(not(feature = "vpn"), allow(unused_mut))]
    let mut cfg = match load_config() {
        Some(c) => {
            println!("[Client] Dispositivo '{}' (device_id={})", c.name, c.device_id);
            c
        }
        None => {
            let name = device_name.unwrap_or_else(default_device_name);
            login_flow(&server_ip, &name).await?
        }
    };

    // Chiavi WireGuard: generate una volta e salvate (solo con la feature `vpn`).
    #[cfg(feature = "vpn")]
    if cfg.wg_private.is_none() {
        let (sk, pk) = p2p_holepunch::vpn::crypto::gen_keypair();
        cfg.wg_private = Some(p2p_holepunch::vpn::crypto::sk_to_b64(&sk));
        cfg.wg_public = Some(p2p_holepunch::vpn::crypto::pk_to_b64(&pk));
        let _ = save_config(&cfg);
        println!("[Client] Chiave WireGuard generata.");
    }

    // Chiave pubblica da pubblicare al server (solo con `vpn`).
    #[cfg(feature = "vpn")]
    let my_wg_public = cfg.wg_public.clone();
    #[cfg(not(feature = "vpn"))]
    let my_wg_public: Option<String> = None;

    // 2) Endpoint del server.
    let server_tcp: SocketAddr = resolve(&server_ip, port("P2P_TCP_PORT", TCP_PORT)).await?;
    let server_udp: SocketAddr = resolve(&server_ip, port("P2P_UDP_PORT", UDP_PORT)).await?;

    // 3) Un unico socket UDP, riusato per server e per peer (mapping NAT coerente).
    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    println!("[Client] Socket UDP locale su {}", udp.local_addr()?);

    // 4) Connessione TCP di segnalazione + autenticazione con auth_key.
    let tcp = TcpStream::connect(server_tcp).await?;
    let (read_half, mut write_half) = tcp.into_split();
    let mut lines = BufReader::new(read_half).lines();
    send_tcp(
        &mut write_half,
        &ClientMessage::Register { auth_key: cfg.auth_key.clone(), wg_public: my_wg_public },
    )
    .await?;
    println!("[Client] Autenticazione inviata (device '{}')", cfg.name);

    // 5) Keepalive UDP: pubblica e mantiene fresco il nostro endpoint pubblico.
    //    Serve alla mesh: il server ci annuncia ai peer quando conosce il nostro
    //    endpoint, e ci ri-annuncia se cambia (NAT).
    {
        let udp = udp.clone();
        let device_id = cfg.device_id.clone();
        tokio::spawn(async move {
            let payload = serde_json::to_vec(&UdpMessage::UdpRegister { device_id }).unwrap();
            loop {
                let _ = udp.send_to(&payload, server_udp).await;
                sleep(Duration::from_secs(3)).await;
            }
        });
    }

    // 6) Ricevitore unico: gestisce i pacchetti in arrivo da TUTTI i peer.
    spawn_receiver(udp.clone(), server_udp);

    // 6b) Se siamo un exit node, avvia il data plane lato uscita (feature `vpn`).
    #[cfg(feature = "vpn")]
    if be_exit {
        let vip = cfg.vip.as_deref().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
        match (cfg.wg_private.clone(), vip) {
            (Some(sk), Some(vip)) => p2p_holepunch::vpn::spawn_exit_node(udp.clone(), sk, vip),
            _ => eprintln!("[Client] Exit node: manca chiave WG o vip (rifai il login del client)."),
        }
    }

    // 7) Mesh: per ogni PeerInfo apriamo (o aggiorniamo) l'hole punching verso
    //    quel peer. I PeerInfo arrivano in continuazione, man mano che altri
    //    dispositivi dell'account entrano; PeerGone quando escono.
    println!("[Client] In attesa dei peer dell'account (mesh)...");
    let mut senders: HashMap<String, (SocketAddr, JoinHandle<()>)> = HashMap::new();
    // Stato della scelta exit node: (device_id, endpoint, chiave pubblica WG).
    let mut exit_requested = false;
    let mut exit_peer: Option<(String, SocketAddr, Option<String>)> = None;
    loop {
        let line = match lines.next_line().await? {
            Some(l) => l,
            None => {
                eprintln!("[Client] Il server ha chiuso la connessione TCP.");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ServerMessage>(&line)? {
            ServerMessage::Registered { info, .. } => println!("[Client] {info}"),
            ServerMessage::Waiting => println!("[Client] Registrato. In attesa di peer..."),
            ServerMessage::Error { message } => {
                eprintln!("[Client] Errore server: {message}");
                eprintln!("[Client] Suggerimento: `client --reset` e riesegui il login.");
                break;
            }
            ServerMessage::PeerInfo { peer_id, peer_name, peer_addr, is_exit_node, peer_vip: _, peer_wg_public } => {
                // Nuovo peer o endpoint cambiato → (ri)avvia il sender verso di lui.
                if senders.get(&peer_id).map(|(a, _)| *a) != Some(peer_addr) {
                    if let Some((_, old)) = senders.remove(&peer_id) {
                        old.abort();
                    }
                    let tag = if is_exit_node { " [disponibile come exit node]" } else { "" };
                    println!("[Mesh] Peer '{peer_name}' ({peer_id}) @ {peer_addr}{tag} → hole punching");
                    let handle = spawn_sender(udp.clone(), peer_addr);
                    senders.insert(peer_id.clone(), (peer_addr, handle));
                }
                // Se facciamo da exit node, registra la chiave pubblica del peer.
                #[cfg(feature = "vpn")]
                if be_exit {
                    if let Some(pk) = &peer_wg_public {
                        p2p_holepunch::vpn::exit_add_peer(peer_addr, pk.clone());
                    }
                }
                // Se è l'exit node che vogliamo usare, richiedilo (una sola volta).
                if !exit_requested {
                    if let Some(ref want) = desired_exit {
                        if is_exit_node && (&peer_name == want || &peer_id == want) {
                            exit_peer = Some((peer_id.clone(), peer_addr, peer_wg_public.clone()));
                            let _ = send_tcp(
                                &mut write_half,
                                &ClientMessage::UseExitNode { exit_device_id: Some(peer_id.clone()) },
                            )
                            .await;
                            exit_requested = true;
                            println!("[Exit] Richiesto '{peer_name}' come exit node (endpoint {peer_addr}).");
                        }
                    }
                }
                let _ = &peer_wg_public;
            }
            ServerMessage::PeerGone { peer_id } => {
                if let Some((addr, h)) = senders.remove(&peer_id) {
                    h.abort();
                    println!("[Mesh] Peer '{peer_id}' offline ({addr})");
                }
            }
            ServerMessage::ExitNodeSet { ok, message, .. } => {
                if ok {
                    println!("[Exit] {message}");
                    #[cfg(feature = "vpn")]
                    if let Some((_, addr, pk)) = &exit_peer {
                        let vip = cfg.vip.as_deref().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
                        match (pk.clone(), cfg.wg_private.clone(), vip) {
                            (Some(pk), Some(sk), Some(vip)) => {
                                println!("[Exit] (vpn) avvio tunnel CIFRATO verso {addr} (richiede root/TUN)…");
                                p2p_holepunch::vpn::spawn_client_tunnel(udp.clone(), *addr, sk, pk, vip);
                            }
                            _ => eprintln!("[Exit] (vpn) mancano chiave WG del peer, chiave privata o vip."),
                        }
                    }
                } else {
                    eprintln!("[Exit] Scelta exit node rifiutata: {message}");
                }
            }
        }
    }
    // Senza la feature `vpn`, `exit_peer` serve solo a livello di segnalazione.
    #[cfg(not(feature = "vpn"))]
    let _ = &exit_peer;
    Ok(())
}

/// Avvia un task che invia PING periodici verso `peer_addr` (apre il NAT locale).
fn spawn_sender(udp: Arc<UdpSocket>, peer_addr: SocketAddr) -> JoinHandle<()> {
    tokio::spawn(async move {
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

/// Avvia il ricevitore unico del socket UDP: stampa i pacchetti dai peer,
/// ignorando quelli del server (es. l'ack UDP). Segnala la prima volta che
/// arriva traffico da un dato peer (buco NAT aperto).
fn spawn_receiver(udp: Arc<UdpSocket>, server_udp: SocketAddr) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut established: HashSet<IpAddr> = HashSet::new();
        loop {
            let (n, src) = match udp.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if src == server_udp {
                continue; // ack/echo del server: non è traffico peer
            }
            // Con la feature `vpn`, i datagrammi VPN vanno al tunnel, non a video.
            #[cfg(feature = "vpn")]
            if p2p_holepunch::vpn::is_vpn(&buf[..n]) {
                if let Some(pkt) = p2p_holepunch::vpn::decap(&buf[..n]) {
                    p2p_holepunch::vpn::deliver_inbound(src, pkt.to_vec());
                }
                continue;
            }
            let text = String::from_utf8_lossy(&buf[..n]);
            if established.insert(src.ip()) {
                println!("[Punch] ✅ Connessione P2P diretta stabilita con {src}!");
            }
            println!("[Punch] << da {src}: {}", text.trim());
        }
    })
}

// ---------------------------------------------------------- login via web ---

/// Esegue il device-code flow: chiede un codice, apre il browser, fa polling
/// finché l'utente non approva, salva la config e la ritorna.
async fn login_flow(server_ip: &str, name: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let http = format!("{server_ip}:{}", port("P2P_HTTP_PORT", HTTP_PORT));
    println!("[Login] Avvio autorizzazione per il dispositivo '{name}'...");

    // 1) Avvia la richiesta.
    let body = serde_json::json!({ "name": name }).to_string();
    let resp = http_request(&http, "POST", "/api/device/start", Some(&body)).await?;
    let start: serde_json::Value = serde_json::from_str(&resp)
        .map_err(|e| format!("risposta /api/device/start non valida: {e} — {resp}"))?;
    let code = start["code"].as_str().ok_or("manca 'code'")?.to_string();
    let url = start["verification_url"].as_str().ok_or("manca 'verification_url'")?.to_string();

    // 2) Apri il browser (best effort) e mostra comunque il link.
    println!("\n  👉 Apri questo link nel browser e approva il dispositivo:\n     {url}\n");
    open_browser(&url);

    // 3) Polling finché non approvato.
    let poll_path = format!("/api/device/poll?code={code}");
    loop {
        sleep(Duration::from_secs(2)).await;
        let resp = match http_request(&http, "GET", &poll_path, None).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[Login] polling fallito ({e}), riprovo...");
                continue;
            }
        };
        let v: serde_json::Value = match serde_json::from_str(&resp) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v["error"].is_string() {
            return Err(format!("il server ha rifiutato il codice: {}", v["error"]).into());
        }
        if v["approved"].as_bool() == Some(true) {
            let cfg = Config {
                device_id: v["device_id"].as_str().unwrap_or_default().to_string(),
                auth_key: v["auth_key"].as_str().unwrap_or_default().to_string(),
                name: v["name"].as_str().unwrap_or(name).to_string(),
                vip: v["vip"].as_str().map(|s| s.to_string()),
                wg_private: None,
                wg_public: None,
            };
            save_config(&cfg)?;
            println!("\n[Login] ✅ Dispositivo autorizzato e salvato in {}", config_path().display());
            return Ok(cfg);
        }
        print!(".");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
}

/// Apre l'URL nel browser di sistema (best effort, ignora gli errori).
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let cmd: (&str, Vec<&str>) = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let cmd: (&str, Vec<&str>) = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let cmd: (&str, Vec<&str>) = ("xdg-open", vec![url]);

    let _ = std::process::Command::new(cmd.0).args(cmd.1).spawn();
}

// ------------------------------------------------------- HTTP minimale ---

/// Esegue una richiesta HTTP/1.1 in chiaro verso il backoffice e ritorna il
/// corpo della risposta come stringa. (Solo verso il nostro server, niente TLS.)
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
    // Il corpo è ciò che segue la riga vuota che chiude gli header.
    Ok(match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => text.into_owned(),
    })
}

// --------------------------------------------------------------- config ---

fn config_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".p2p-holepunch").join("config.json")
}

fn load_config() -> Option<Config> {
    let data = std::fs::read_to_string(config_path()).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_config(cfg: &Config) -> std::io::Result<()> {
    let path = config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(cfg)?)
}

fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "dispositivo".to_string())
}

// ----------------------------------------------------------- segnalazione ---

async fn resolve(ip: &str, port: u16) -> std::io::Result<SocketAddr> {
    use tokio::net::lookup_host;
    lookup_host((ip, port))
        .await?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "host non risolto"))
}

/// Serializza e invia un `ClientMessage` sul canale TCP (JSON + newline).
async fn send_tcp<W>(writer: &mut W, msg: &ClientMessage) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut data = serde_json::to_vec(msg).expect("serializzazione ClientMessage");
    data.push(b'\n');
    writer.write_all(&data).await
}

